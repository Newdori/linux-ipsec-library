#include "vici_internal.h"

#include <string.h>
#include <errno.h>
#include <time.h>

typedef struct ViciResultParserContext {
    ViciCommandResult_t *pResult;
} ViciResultParserContext_t;

static bool MatchViciText(
    const uint8_t *pucText,
    uint32_t uiTextLength,
    const char *pcExpected)
{
    size_t zExpectedLength;
    bool bMatches;

    if ((NULL == pucText) || (NULL == pcExpected)) {
        bMatches = false;
    }
    else {
        zExpectedLength = strlen(pcExpected);
        bMatches = (zExpectedLength == uiTextLength) &&
                   (0 == memcmp(pucText, pcExpected, uiTextLength));
    }
    return bMatches;
}

static IpsecError_t ParseViciResultElement(
    const ViciElement_t *pElement,
    void *pvUserData)
{
    ViciResultParserContext_t *pContext =
        (ViciResultParserContext_t *)pvUserData;
    IpsecError_t eError = IPSEC_OK;
    uint32_t uiIndex;
    uint32_t uiLength;

    if ((0U == pElement->uiDepth) && (VICI_ELEMENT_KEY_VALUE == pElement->eType) &&
        MatchViciText(pElement->pucName, pElement->ucNameLength, "success")) {
        if (pContext->pResult->bSuccessPresent) {
            return IPSEC_ERR_VICI_PROTOCOL;
        }
        pContext->pResult->bSuccessPresent = true;
        if (MatchViciText(pElement->pucValue, pElement->usValueLength, "yes")) {
            pContext->pResult->bSuccess = true;
        }
        else if (MatchViciText(pElement->pucValue, pElement->usValueLength, "no")) {
            pContext->pResult->bSuccess = false;
        }
        else {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
    }
    else if ((0U == pElement->uiDepth) && (VICI_ELEMENT_KEY_VALUE == pElement->eType) &&
             MatchViciText(pElement->pucName, pElement->ucNameLength, "errmsg")) {
        uiLength = pElement->usValueLength;
        if (uiLength >= sizeof(pContext->pResult->acErrorMessage)) {
            uiLength = sizeof(pContext->pResult->acErrorMessage) - 1U;
        }
        for (uiIndex = 0U; uiIndex < uiLength; uiIndex++) {
            uint8_t ucValue = pElement->pucValue[uiIndex];
            pContext->pResult->acErrorMessage[uiIndex] =
                ((ucValue < 32U) || (127U == ucValue)) ? ' ' : (char)ucValue;
        }
        pContext->pResult->acErrorMessage[uiLength] = '\0';
    }
    else {
        /* Ignore unrelated command fields. */
    }

    return eError;
}

IpsecError_t ParseViciCommandResult(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    ViciCommandResult_t *pResult)
{
    ViciResultParserContext_t ParserContext;
    IpsecError_t eError;

    if (NULL == pResult) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pResult, 0, sizeof(*pResult));
        ParserContext.pResult = pResult;
        eError = ParseViciMessage(pucMessage, uiMessageLength,
                                  ParseViciResultElement, &ParserContext);
    }

    return eError;
}

static IpsecError_t ExchangeViciRegistration(
    IpsecContext_t *pContext,
    const char *pcEventName,
    bool bRegister)
{
    ViciBuffer_t Packet = {0};
    ViciBuffer_t Response = {0};
    ViciPacketView_t View;
    ViciPacketType_t eExpectedType;
    IpsecError_t eError;

    eError = BuildViciNamedPacket(bRegister ? VICI_PACKET_EVENT_REGISTER :
                                  VICI_PACKET_EVENT_UNREGISTER,
                                  pcEventName, NULL, &Packet);
    if (IPSEC_OK == eError) {
        eError = SendViciTransportPacket(pContext, &Packet);
    }
    else {
        /* Preserve packet error. */
    }
    if (IPSEC_OK == eError) {
        eError = ReceiveViciTransportPacket(pContext, &Response);
    }
    else {
        /* Preserve transport error. */
    }
    if (IPSEC_OK == eError) {
        eError = DecodeViciPacket(Response.pucData, Response.uiLength, &View);
    }
    else {
        /* Preserve receive error. */
    }
    if (IPSEC_OK == eError) {
        eExpectedType = VICI_PACKET_EVENT_CONFIRM;
        if (eExpectedType != View.eType) {
            eError = (VICI_PACKET_EVENT_UNKNOWN == View.eType) ?
                     IPSEC_ERR_NOT_SUPPORTED : IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            /* Event registration confirmed. */
        }
    }
    else {
        /* Preserve packet decode error. */
    }

    DestroyViciBuffer(&Response);
    DestroyViciBuffer(&Packet);
    return eError;
}

static IpsecError_t ReceiveViciCommandStream(
    IpsecContext_t *pContext,
    const char *pcEventName,
    ViciMessageCallback_t pEventCallback,
    ViciMessageCallback_t pResponseCallback,
    void *pvUserData,
    ViciCommandResult_t *pResult,
    bool *pbOutcomeKnown)
{
    ViciBuffer_t Packet = {0};
    ViciPacketView_t View;
    IpsecError_t eError = IPSEC_OK;
    bool bComplete = false;

    while (!bComplete && (IPSEC_OK == eError)) {
        eError = ReceiveViciTransportPacket(pContext, &Packet);
        if (IPSEC_OK == eError) {
            eError = DecodeViciPacket(Packet.pucData, Packet.uiLength, &View);
        }
        else {
            /* Preserve receive error. */
        }

        if ((IPSEC_OK == eError) && (VICI_PACKET_EVENT == View.eType)) {
            if ((NULL != pcEventName) &&
                MatchViciText(View.pucName, View.ucNameLength, pcEventName)) {
                if (NULL != pEventCallback) {
                    eError = pEventCallback(View.pucMessage,
                                            View.uiMessageLength,
                                            pvUserData);
                }
                else {
                    /* Registered event is intentionally ignored. */
                }
            }
            else {
                /* Ignore unrelated event data on this connection. */
            }
        }
        else if ((IPSEC_OK == eError) &&
                 (VICI_PACKET_COMMAND_RESPONSE == View.eType)) {
            eError = ParseViciCommandResult(View.pucMessage,
                                            View.uiMessageLength, pResult);
            if ((IPSEC_OK == eError) && (NULL != pResponseCallback)) {
                eError = pResponseCallback(View.pucMessage,
                                           View.uiMessageLength,
                                           pvUserData);
            }
            else {
                /* No custom response parser or existing error. */
            }
            bComplete = true;
            *pbOutcomeKnown = (IPSEC_OK == eError);
        }
        else if ((IPSEC_OK == eError) &&
                 (VICI_PACKET_COMMAND_UNKNOWN == View.eType)) {
            *pbOutcomeKnown = true;
            eError = IPSEC_ERR_NOT_SUPPORTED;
        }
        else if (IPSEC_OK == eError) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            /* Preserve existing error. */
        }

        DestroyViciBuffer(&Packet);
    }

    return eError;
}

static bool RequireViciSuccessField(const char *pcCommand)
{
    static const char *const apcMutations[] = {
        "load-conn", "unload-conn", "load-shared", "unload-shared",
        "clear-creds", "initiate", "terminate", "rekey"
    };
    uint32_t uiIndex;

    for (uiIndex = 0U; uiIndex < (sizeof(apcMutations) / sizeof(apcMutations[0])); uiIndex++) {
        if (0 == strcmp(pcCommand, apcMutations[uiIndex])) {
            return true;
        }
    }
    return false;
}

static IpsecError_t AcquireViciCommand(
    IpsecContext_t *pContext,
    uint64_t ullDeadlineMs,
    int32_t iCancelFd)
{
    struct timespec Deadline;
    int32_t iResult = 0;
    IpsecError_t eError = IPSEC_OK;

    Deadline.tv_sec = (time_t)(ullDeadlineMs / 1000U);
    Deadline.tv_nsec = (int64_t)((ullDeadlineMs % 1000U) * 1000000U);
    if (0 != pthread_mutex_lock(&pContext->Command.Mutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    while (pContext->Command.bActive && !pContext->Command.bClosing &&
           !IsViciWaitCancelled(iCancelFd) && (0 == iResult)) {
        iResult = pthread_cond_timedwait(&pContext->Command.Condition,
                                        &pContext->Command.Mutex, &Deadline);
    }
    if (pContext->Command.bClosing || IsViciWaitCancelled(iCancelFd)) {
        eError = IPSEC_ERR_CANCELLED;
    }
    else if ((ETIMEDOUT == iResult) ||
             (GetIpsecMonotonicMilliseconds() >= ullDeadlineMs)) {
        eError = IPSEC_ERR_VICI_TIMEOUT;
    }
    else if (0 != iResult) {
        eError = IPSEC_ERR_INTERNAL;
    }
    else {
        pContext->Command.bActive = true;
    }
    (void)pthread_mutex_unlock(&pContext->Command.Mutex);
    return eError;
}

IpsecError_t ExecuteViciCommandUntil(
    IpsecContext_t *pContext,
    const char *pcCommand,
    const ViciBuffer_t *pRequest,
    const char *pcEventName,
    ViciMessageCallback_t pEventCallback,
    ViciMessageCallback_t pResponseCallback,
    void *pvUserData,
    ViciCommandResult_t *pResult,
    uint64_t ullDeadlineMs,
    int32_t iCancelFd)
{
    ViciBuffer_t Packet = {0};
    ViciCommandResult_t LocalResult;
    IpsecDiagnostic_t Diagnostic = {0};
    uint64_t ullNowMs;
    uint64_t ullCommandLimit;
    bool bAcquired = false;
    bool bRegistered = false;
    bool bSendAttempted = false;
    bool bResponseValid = false;
    bool bSensitive;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pcCommand)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (NULL == pResult) {
        pResult = &LocalResult;
    }
    memset(pResult, 0, sizeof(*pResult));
    Diagnostic.uiStructSize = sizeof(Diagnostic);
    Diagnostic.eStage = IPSEC_STAGE_QUEUE;
    (void)CopyIpsecString(Diagnostic.acCommand, sizeof(Diagnostic.acCommand),
                         (const uint8_t *)pcCommand, strlen(pcCommand));
    bSensitive = (NULL != pRequest) && pRequest->bSensitive;
    ullNowMs = GetIpsecMonotonicMilliseconds();
    if ((0U == ullNowMs) ||
        (ullNowMs > (UINT64_MAX - pContext->Vici.uiCommandTimeoutMs))) {
        return IPSEC_ERR_INTERNAL;
    }
    ullCommandLimit = ullNowMs + pContext->Vici.uiCommandTimeoutMs;
    if ((0U == ullDeadlineMs) || (ullDeadlineMs > ullCommandLimit)) {
        ullDeadlineMs = ullCommandLimit;
    }
    eError = AcquireViciCommand(pContext, ullDeadlineMs, iCancelFd);
    if (IPSEC_OK == eError) {
        bAcquired = true;
        pContext->Vici.ullCommandDeadlineMs = ullDeadlineMs;
        pContext->Vici.iTransportCancelFd = iCancelFd;
        Diagnostic.eStage = IPSEC_STAGE_CONNECT;
        errno = 0;
        eError = ConnectViciTransport(pContext);
    }
    if ((IPSEC_OK == eError) && (NULL != pcEventName)) {
        Diagnostic.eStage = IPSEC_STAGE_REGISTER;
        errno = 0;
        eError = ExchangeViciRegistration(pContext, pcEventName, true);
        bRegistered = (IPSEC_OK == eError);
    }
    if (IPSEC_OK == eError) {
        Diagnostic.eStage = IPSEC_STAGE_ENCODE;
        errno = 0;
        eError = BuildViciNamedPacket(VICI_PACKET_COMMAND_REQUEST,
                                      pcCommand, pRequest, &Packet);
    }
    if (IPSEC_OK == eError) {
        Diagnostic.eStage = IPSEC_STAGE_SEND;
        bSendAttempted = true;
        errno = 0;
        eError = SendViciTransportPacket(pContext, &Packet);
    }
    if (IPSEC_OK == eError) {
        Diagnostic.eStage = IPSEC_STAGE_RECEIVE;
        errno = 0;
        eError = ReceiveViciCommandStream(pContext, pcEventName,
                                         pEventCallback, pResponseCallback,
                                         pvUserData, pResult, &bResponseValid);
        if ((IPSEC_OK == eError) && RequireViciSuccessField(pcCommand) &&
            !pResult->bSuccessPresent) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
            bResponseValid = false;
        }
    }
    /* A parser/callback error may leave stream events and a response unread.
     * Never send unregister or a new command on a stream of unknown position.
     * Reconnect on the NEXT call; never replay a possibly executed mutation.
     */
    if (bAcquired && (IPSEC_OK != eError)) {
        Diagnostic.iSystemError = (IPSEC_ERR_VICI_CONNECT == eError ||
                                   IPSEC_ERR_VICI_TRANSPORT == eError ||
                                   IPSEC_ERR_PERMISSION == eError) ? errno : 0;
        DisconnectViciTransport(pContext);
    }
    else if (bRegistered) {
        Diagnostic.eStage = IPSEC_STAGE_UNREGISTER;
        errno = 0;
        eError = ExchangeViciRegistration(pContext, pcEventName, false);
        if (IPSEC_OK != eError) {
            Diagnostic.iSystemError = (IPSEC_ERR_VICI_TRANSPORT == eError) ? errno : 0;
            DisconnectViciTransport(pContext);
        }
    }

    /* Daemon replies can echo input. Never expose an echoed PSK in diagnostics
     * or logger callbacks, even if a malicious/buggy daemon returns one.
     */
    if (bSensitive) {
        SecureZeroIpsec(pResult->acErrorMessage, sizeof(pResult->acErrorMessage));
    }
    if ((IPSEC_OK == eError) && pResult->bSuccessPresent && !pResult->bSuccess) {
        Diagnostic.eStage = IPSEC_STAGE_DAEMON;
        eError = IPSEC_ERR_VICI_COMMAND;
    }
    if (IPSEC_OK == eError) {
        Diagnostic.eStage = IPSEC_STAGE_NONE;
    }
    Diagnostic.eError = eError;
    Diagnostic.bOutcomeUnknown = bSendAttempted && !bResponseValid;
    if (IPSEC_OK != eError) {
        const char *pcMessage = ('\0' != pResult->acErrorMessage[0]) ?
            pResult->acErrorMessage : GetIpsecErrorString(eError);
        (void)CopyIpsecString(Diagnostic.acMessage, sizeof(Diagnostic.acMessage),
                             (const uint8_t *)pcMessage, strlen(pcMessage));
    }
    DestroyViciBuffer(&Packet);
    if (bAcquired) {
        pContext->Vici.ullCommandDeadlineMs = 0U;
        pContext->Vici.iTransportCancelFd = -1;
    }
    (void)pthread_mutex_lock(&pContext->Command.Mutex);
    pContext->Diagnostic.Last = Diagnostic;
    if (bAcquired) {
        pContext->Command.bActive = false;
        (void)pthread_cond_broadcast(&pContext->Command.Condition);
    }
    (void)pthread_mutex_unlock(&pContext->Command.Mutex);

    if (IPSEC_ERR_VICI_COMMAND == eError) {
        LogIpsec(pContext, IPSEC_LOG_ERROR, "VICI command %s failed: %s",
                 pcCommand, Diagnostic.acMessage);
    }
    return eError;
}

IpsecError_t ExecuteViciCommand(
    IpsecContext_t *pContext,
    const char *pcCommand,
    const ViciBuffer_t *pRequest,
    const char *pcEventName,
    ViciMessageCallback_t pEventCallback,
    ViciMessageCallback_t pResponseCallback,
    void *pvUserData,
    ViciCommandResult_t *pResult)
{
    return ExecuteViciCommandUntil(pContext, pcCommand, pRequest, pcEventName,
                                   pEventCallback, pResponseCallback, pvUserData,
                                   pResult, 0U, -1);
}
