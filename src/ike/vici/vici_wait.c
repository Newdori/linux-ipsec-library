#include "vici_internal.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define VICI_COMPATIBILITY_POLL_MS 250U

bool IsViciWaitCancelled(int32_t iCancelFd)
{
    struct pollfd Descriptor = {0};
    int32_t iResult;

    if (iCancelFd < 0) {
        return false;
    }
    Descriptor.fd = iCancelFd;
    Descriptor.events = POLLIN;
    do {
        iResult = (int32_t)poll(&Descriptor, 1U, 0);
    } while ((iResult < 0) && (EINTR == errno));
    return (0 != iResult);
}

static void SignalViciWaits(IpsecContext_t *pContext)
{
    ViciWaiter_t *pWaiter;
    const uint8_t ucSignal = 1U;
    ssize_t lResult;

    for (pWaiter = pContext->Command.pWaiters; NULL != pWaiter; pWaiter = pWaiter->pNext) {
        do {
            lResult = send(pWaiter->aiCancelSockets[1], &ucSignal, sizeof(ucSignal),
                           MSG_NOSIGNAL);
        } while ((lResult < 0) && (EINTR == errno));
        /* EAGAIN means a previous cancellation is still queued/readable. */
    }
    (void)pthread_cond_broadcast(&pContext->Command.Condition);
}

IpsecError_t CancelIpsecWaits(IpsecContext_t *pContext)
{
    if (NULL == pContext) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (0 != pthread_mutex_lock(&pContext->Command.Mutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    SignalViciWaits(pContext);
    (void)pthread_mutex_unlock(&pContext->Command.Mutex);
    return IPSEC_OK;
}

void CloseViciWaits(IpsecContext_t *pContext)
{
    (void)pthread_mutex_lock(&pContext->Command.Mutex);
    pContext->Command.bClosing = true;
    SignalViciWaits(pContext);
    while ((NULL != pContext->Command.pWaiters) || pContext->Command.bActive) {
        (void)pthread_cond_wait(&pContext->Command.Condition, &pContext->Command.Mutex);
    }
    (void)pthread_mutex_unlock(&pContext->Command.Mutex);
}

IpsecError_t BeginViciWait(
    IpsecContext_t *pContext,
    ViciWaiter_t *pWaiter,
    uint64_t ullDeadlineMs)
{
    IpsecError_t eError = IPSEC_OK;

    memset(pWaiter, 0, sizeof(*pWaiter));
    pWaiter->EventContext.Vici.iSocket = -1;
    pWaiter->aiCancelSockets[0] = -1;
    pWaiter->aiCancelSockets[1] = -1;
    if (0 != socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK,
                        0, pWaiter->aiCancelSockets)) {
        return IPSEC_ERR_VICI_TRANSPORT;
    }
    if (0 != pthread_mutex_lock(&pContext->Command.Mutex)) {
        eError = IPSEC_ERR_INTERNAL;
    }
    else {
        if (pContext->Command.bClosing) {
            eError = IPSEC_ERR_CANCELLED;
        }
        else {
            memcpy(pWaiter->EventContext.Vici.acSocketPath,
                   pContext->Vici.acSocketPath, sizeof(pContext->Vici.acSocketPath));
            pWaiter->EventContext.Vici.uiConnectTimeoutMs =
                pContext->Vici.uiConnectTimeoutMs;
            pWaiter->EventContext.Vici.uiCommandTimeoutMs =
                pContext->Vici.uiCommandTimeoutMs;
            pWaiter->EventContext.Vici.iTransportCancelFd =
                pWaiter->aiCancelSockets[0];
            pWaiter->ullDeadlineMs = ullDeadlineMs;
            pWaiter->pNext = pContext->Command.pWaiters;
            pContext->Command.pWaiters = pWaiter;
        }
        (void)pthread_mutex_unlock(&pContext->Command.Mutex);
    }
    if (IPSEC_OK != eError) {
        (void)close(pWaiter->aiCancelSockets[0]);
        (void)close(pWaiter->aiCancelSockets[1]);
    }
    return eError;
}

void EndViciWait(IpsecContext_t *pContext, ViciWaiter_t *pWaiter)
{
    ViciWaiter_t **ppCurrent;

    DisconnectViciTransport(&pWaiter->EventContext);
    (void)pthread_mutex_lock(&pContext->Command.Mutex);
    for (ppCurrent = &pContext->Command.pWaiters; NULL != *ppCurrent;
         ppCurrent = &(*ppCurrent)->pNext) {
        if (*ppCurrent == pWaiter) {
            *ppCurrent = pWaiter->pNext;
            break;
        }
    }
    (void)close(pWaiter->aiCancelSockets[0]);
    (void)close(pWaiter->aiCancelSockets[1]);
    (void)pthread_cond_broadcast(&pContext->Command.Condition);
    (void)pthread_mutex_unlock(&pContext->Command.Mutex);
    /* The caller must not touch pContext after releasing its wait entry. */
}

static void SetViciWaitFrameDeadline(ViciWaiter_t *pWaiter)
{
    uint64_t ullLimitMs = GetIpsecMonotonicMilliseconds() +
                          pWaiter->EventContext.Vici.uiCommandTimeoutMs;

    pWaiter->EventContext.Vici.ullCommandDeadlineMs =
        (ullLimitMs < pWaiter->ullDeadlineMs) ? ullLimitMs : pWaiter->ullDeadlineMs;
}

static IpsecError_t ValidateViciSaEvent(const ViciPacketView_t *pView)
{
    static const char *const apcNames[] = {
        "ike-updown", "ike-rekey", "child-updown", "child-rekey"
    };
    uint32_t uiIndex;

    if (VICI_PACKET_EVENT != pView->eType) {
        return IPSEC_ERR_VICI_PROTOCOL;
    }
    for (uiIndex = 0U; uiIndex < (sizeof(apcNames) / sizeof(apcNames[0])); uiIndex++) {
        if ((strlen(apcNames[uiIndex]) == pView->ucNameLength) &&
            (0 == memcmp(apcNames[uiIndex], pView->pucName, pView->ucNameLength))) {
            return ParseViciMessage(pView->pucMessage, pView->uiMessageLength,
                                    NULL, NULL);
        }
    }
    return IPSEC_ERR_VICI_PROTOCOL;
}

static IpsecError_t RegisterViciSaEvent(ViciWaiter_t *pWaiter, const char *pcName)
{
    ViciBuffer_t Request = {0};
    ViciBuffer_t Response = {0};
    ViciPacketView_t View;
    IpsecError_t eError;

    eError = BuildViciNamedPacket(VICI_PACKET_EVENT_REGISTER, pcName, NULL, &Request);
    SetViciWaitFrameDeadline(pWaiter);
    if (IPSEC_OK == eError) {
        eError = SendViciTransportPacket(&pWaiter->EventContext, &Request);
    }
    while (IPSEC_OK == eError) {
        eError = ReceiveViciTransportPacket(&pWaiter->EventContext, &Response);
        if (IPSEC_OK == eError) {
            eError = DecodeViciPacket(Response.pucData, Response.uiLength, &View);
        }
        if (IPSEC_OK == eError) {
            if (VICI_PACKET_EVENT_CONFIRM == View.eType) {
                break;
            }
            else if (VICI_PACKET_EVENT_UNKNOWN == View.eType) {
                eError = IPSEC_ERR_NOT_SUPPORTED;
            }
            else {
                /* A previous subscription may emit before this confirmation.
                 * The snapshot AFTER all registrations covers these events. */
                eError = ValidateViciSaEvent(&View);
            }
        }
        DestroyViciBuffer(&Response);
    }
    DestroyViciBuffer(&Response);
    DestroyViciBuffer(&Request);
    return eError;
}

IpsecError_t SubscribeViciSaEvents(ViciWaiter_t *pWaiter, bool bChild)
{
    IpsecError_t eError;

    SetViciWaitFrameDeadline(pWaiter);
    eError = ConnectViciTransport(&pWaiter->EventContext);
    if (IPSEC_OK == eError) {
        eError = RegisterViciSaEvent(pWaiter, bChild ? "child-updown" : "ike-updown");
    }
    if (IPSEC_OK == eError) {
        eError = RegisterViciSaEvent(pWaiter, bChild ? "child-rekey" : "ike-rekey");
    }
    if (IPSEC_ERR_NOT_SUPPORTED == eError) {
        /* Compatibility polling is only selected after explicit EVENT_UNKNOWN. */
        DisconnectViciTransport(&pWaiter->EventContext);
        pWaiter->bPolling = true;
        eError = IPSEC_OK;
    }
    else if (IPSEC_OK != eError) {
        DisconnectViciTransport(&pWaiter->EventContext);
    }
    return eError;
}

IpsecError_t PauseViciWait(ViciWaiter_t *pWaiter)
{
    struct pollfd Descriptor = {0};
    uint64_t ullNowMs;
    uint64_t ullLimitMs = GetIpsecMonotonicMilliseconds() + VICI_COMPATIBILITY_POLL_MS;
    int32_t iResult;

    if (ullLimitMs > pWaiter->ullDeadlineMs) {
        ullLimitMs = pWaiter->ullDeadlineMs;
    }
    Descriptor.fd = pWaiter->aiCancelSockets[0];
    Descriptor.events = POLLIN;
    do {
        ullNowMs = GetIpsecMonotonicMilliseconds();
        if (ullNowMs >= ullLimitMs) {
            return IPSEC_OK;
        }
        iResult = (int32_t)poll(&Descriptor, 1U, (int32_t)(ullLimitMs - ullNowMs));
    } while ((iResult < 0) && (EINTR == errno));
    if (iResult > 0) {
        return IPSEC_ERR_CANCELLED;
    }
    return (0 == iResult) ? IPSEC_OK : IPSEC_ERR_VICI_TRANSPORT;
}

IpsecError_t ReceiveViciSaChange(ViciWaiter_t *pWaiter)
{
    ViciBuffer_t Packet = {0};
    ViciPacketView_t View;
    IpsecError_t eError;

    if (pWaiter->bPolling) {
        return PauseViciWait(pWaiter);
    }
    /* Idle event channels have the WAIT deadline, not a command timeout.
     * Once bytes arrive, bound completion of a partial frame separately. */
    eError = WaitViciTransportReadable(&pWaiter->EventContext, pWaiter->ullDeadlineMs);
    if (IPSEC_OK == eError) {
        SetViciWaitFrameDeadline(pWaiter);
        eError = ReceiveViciTransportPacket(&pWaiter->EventContext, &Packet);
    }
    if (IPSEC_OK == eError) {
        eError = DecodeViciPacket(Packet.pucData, Packet.uiLength, &View);
    }
    if (IPSEC_OK == eError) {
        eError = ValidateViciSaEvent(&View);
    }
    DestroyViciBuffer(&Packet);
    if (IPSEC_OK != eError) {
        DisconnectViciTransport(&pWaiter->EventContext);
    }
    return eError;
}
