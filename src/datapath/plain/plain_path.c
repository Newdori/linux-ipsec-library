#include "plain_path_ops.h"

#include <string.h>

IpsecError_t InitializeIpsecPlainPath(IpsecContext_t *pContext)
{
    IpsecError_t eError;
    if (IPSEC_PACKET_PATH_SYSTEM == pContext->DatapathConfig.ePlainPacketPath) {
        pContext->pPlainPathOps = GetSystemPlainPathOps();
    }
    else if (IPSEC_PACKET_PATH_APPLICATION == pContext->DatapathConfig.ePlainPacketPath) {
        pContext->pPlainPathOps = GetApplicationPlainPathOps();
    }
    else {
        return IPSEC_ERR_INVALID_PACKET_PATH;
    }
    eError = pContext->pPlainPathOps->pInitialize(pContext);
    if (IPSEC_OK == eError) {
        pContext->bPlainPathInitialized = true;
    }
    else {
        pContext->pPlainPathOps->pDeinitialize(pContext);
        pContext->pPlainPathOps = NULL;
    }
    return eError;
}

void DeinitializeIpsecPlainPath(IpsecContext_t *pContext)
{
    if (NULL != pContext->pPlainPathOps) {
        pContext->pPlainPathOps->pDeinitialize(pContext);
    }
    pContext->pPlainPathOps = NULL;
    pContext->bPlainPathInitialized = false;
}

IpsecError_t GetIpsecPlainPathStatusInternal(IpsecContext_t *pContext,
    IpsecPlainPathStatusInternal_t *pStatus)
{
    if ((NULL == pContext) || (NULL == pStatus)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pStatus, 0, sizeof(*pStatus));
    if (NULL == pContext->pPlainPathOps) {
        return IPSEC_ERR_PLAIN_PATH_UNAVAILABLE;
    }
    return pContext->pPlainPathOps->pGetStatus(pContext, pStatus);
}

IpsecError_t ReceiveIpsecPlainPacket(IpsecContext_t *pContext,
    IpsecPlainPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    if ((NULL == pContext) || (NULL == pPacket) ||
        (sizeof(*pPacket) != pPacket->uiStructSize)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pPacket->zLength = 0U;
    pPacket->eFamily = IPSEC_ADDRESS_FAMILY_UNSPECIFIED;
    if (!pContext->bPlainPathInitialized || (NULL == pContext->pPlainPathOps)) {
        return IPSEC_ERR_PLAIN_PATH_UNAVAILABLE;
    }
    return pContext->pPlainPathOps->pReceivePacket(pContext, pPacket, uiTimeoutMs);
}
