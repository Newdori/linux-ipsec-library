#include "plain_internal.h"

#include <stdlib.h>
#include <string.h>

static IpsecError_t InitializeApplicationPlainPath(IpsecContext_t *pContext)
{
    IpsecPlainApplicationState_t *pState;
    IpsecError_t eError;
    if (!pContext->bDatapathInitialized ||
        (0U == pContext->DatapathConfig.usPlainQueueNumber)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (pContext->DatapathConfig.bManagePlainNetfilterRule &&
        (IPSEC_DATAPATH_KERNEL_LIBIPSEC != pContext->eActiveDatapath)) {
        return IPSEC_ERR_NOT_SUPPORTED;
    }
    pState = (IpsecPlainApplicationState_t *)calloc(1U, sizeof(*pState));
    if (NULL == pState) {
        return IPSEC_ERR_NO_MEMORY;
    }
    pState->iQueueSocket = -1;
    pState->iRuleSocket = -1;
    pState->usQueueNumber = pContext->DatapathConfig.usPlainQueueNumber;
    if (IPSEC_DATAPATH_KERNEL_LIBIPSEC == pContext->eActiveDatapath) {
        pState->uiExpectedInterfaceIndex = pContext->uiDatapathInterfaceIndex;
    }
    pContext->pPlainApplicationState = pState;
    eError = OpenIpsecPlainQueue(pContext, pState);
    if ((IPSEC_OK == eError) &&
        pContext->DatapathConfig.bManagePlainNetfilterRule) {
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
        pContext->pPlainApplicationState, pPacket, uiTimeoutMs);
}

static IpsecError_t GetApplicationPlainPathStatus(IpsecContext_t *pContext,
    IpsecPlainPathStatusInternal_t *pStatus)
{
    const IpsecPlainApplicationState_t *pState = pContext->pPlainApplicationState;
    if ((NULL == pState) || (pState->iQueueSocket < 0) || !pState->bQueueBound) {
        return IPSEC_ERR_PLAIN_PATH_UNAVAILABLE;
    }
    pStatus->bReady = pContext->bPlainPathInitialized;
    pStatus->usQueueNumber = pState->usQueueNumber;
    pStatus->uiInterfaceIndex = pState->uiExpectedInterfaceIndex;
    if ((0U != pState->uiExpectedInterfaceIndex) &&
        ('\0' != pContext->acDatapathInterfaceName[0])) {
        memcpy(pStatus->acInterfaceName, pContext->acDatapathInterfaceName,
               sizeof(pStatus->acInterfaceName));
    }
    return IPSEC_OK;
}

static void DeinitializeApplicationPlainPath(IpsecContext_t *pContext)
{
    if (NULL != pContext->pPlainApplicationState) {
        DeinitializeIpsecPlainRules(
            pContext, pContext->pPlainApplicationState);
        CloseIpsecPlainQueue(pContext->pPlainApplicationState);
        free(pContext->pPlainApplicationState);
        pContext->pPlainApplicationState = NULL;
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
