#include "plain_internal.h"

#include <stdlib.h>
#include <string.h>

static IpsecError_t InitializeApplicationPlainPath(IpsecContext_t *pContext)
{
    IpsecPlainApplicationState_t *pState;
    IpsecError_t eError;
    if (!pContext->Datapath.bInitialized ||
        (0U == pContext->Datapath.Config.usPlainQueueNumber)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (pContext->Datapath.Config.bManagePlainNetfilterRule &&
        (IPSEC_DATAPATH_KERNEL_LIBIPSEC != pContext->Datapath.eActiveType)) {
        return IPSEC_ERR_NOT_SUPPORTED;
    }
    pState = (IpsecPlainApplicationState_t *)calloc(1U, sizeof(*pState));
    if (NULL == pState) {
        return IPSEC_ERR_NO_MEMORY;
    }
    pState->iQueueSocket = -1;
    pState->iRuleSocket = -1;
    pState->usQueueNumber = pContext->Datapath.Config.usPlainQueueNumber;
    if (IPSEC_DATAPATH_KERNEL_LIBIPSEC == pContext->Datapath.eActiveType) {
        pState->uiExpectedInterfaceIndex = pContext->Datapath.uiInterfaceIndex;
    }
    pContext->PlainPath.pApplicationState = pState;
    eError = OpenIpsecPlainQueue(pContext, pState);
    if ((IPSEC_OK == eError) &&
        pContext->Datapath.Config.bManagePlainNetfilterRule) {
        if (0 != pthread_mutex_init(&pState->PeerMutex, NULL)) {
            eError = IPSEC_ERR_INTERNAL;
        }
        else {
            pState->bPeerMutexInitialized = true;
            eError = InitializeIpsecPlainRules(pContext, pState);
        }
    }
    return eError;
}

static IpsecError_t ReceiveApplicationPlainPacket(IpsecContext_t *pContext,
    IpsecPlainPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    if (NULL == pPacket->pucData) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    return ReceiveIpsecPlainQueuePacket(
        pContext->PlainPath.pApplicationState, pPacket, uiTimeoutMs);
}

static IpsecError_t GetApplicationPlainPathStatus(IpsecContext_t *pContext,
    IpsecPlainPathStatusInternal_t *pStatus)
{
    const IpsecPlainApplicationState_t *pState = pContext->PlainPath.pApplicationState;
    if ((NULL == pState) || (pState->iQueueSocket < 0) || !pState->bQueueBound) {
        return IPSEC_ERR_PLAIN_PATH_UNAVAILABLE;
    }
    pStatus->bReady = pContext->PlainPath.bInitialized;
    pStatus->usQueueNumber = pState->usQueueNumber;
    pStatus->uiInterfaceIndex = pState->uiExpectedInterfaceIndex;
    if ((0U != pState->uiExpectedInterfaceIndex) &&
        ('\0' != pContext->Datapath.acInterfaceName[0])) {
        memcpy(pStatus->acInterfaceName, pContext->Datapath.acInterfaceName,
               sizeof(pStatus->acInterfaceName));
    }
    return IPSEC_OK;
}

static void DeinitializeApplicationPlainPath(IpsecContext_t *pContext)
{
    if (NULL != pContext->PlainPath.pApplicationState) {
        DeinitializeIpsecPlainRules(
            pContext, pContext->PlainPath.pApplicationState);
        CloseIpsecPlainQueue(pContext->PlainPath.pApplicationState);
        free(pContext->PlainPath.pApplicationState);
        pContext->PlainPath.pApplicationState = NULL;
    }
}

const IpsecPlainPathOps_t *GetApplicationPlainPathOps(void)
{
    static const IpsecPlainPathOps_t Ops = {
        InitializeApplicationPlainPath, ReceiveApplicationPlainPacket,
        GetApplicationPlainPathStatus, DeinitializeApplicationPlainPath
    };
    return &Ops;
}
