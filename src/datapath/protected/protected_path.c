#include "protected_path_ops.h"

#include <string.h>

IpsecError_t InitializeIpsecProtectedPath(IpsecContext_t *pContext)
{
    IpsecError_t eError;
    if (IPSEC_PACKET_PATH_SYSTEM == pContext->DatapathConfig.eProtectedPacketPath) {
        pContext->pProtectedPathOps = GetSystemProtectedPathOps();
    }
    else if (IPSEC_PACKET_PATH_APPLICATION == pContext->DatapathConfig.eProtectedPacketPath) {
        pContext->pProtectedPathOps = GetApplicationProtectedPathOps();
    }
    else {
        return IPSEC_ERR_INVALID_PACKET_PATH;
    }
    eError = pContext->pProtectedPathOps->pInitialize(pContext);
    if (IPSEC_OK == eError) {
        pContext->bProtectedPathInitialized = true;
    }
    else {
        /* Also clean a partially initialized implementation. */
        pContext->pProtectedPathOps->pDeinitialize(pContext);
        pContext->pProtectedPathOps = NULL;
    }
    return eError;
}

void DeinitializeIpsecProtectedPath(IpsecContext_t *pContext)
{
    if (NULL != pContext->pProtectedPathOps) {
        pContext->pProtectedPathOps->pDeinitialize(pContext);
    }
    pContext->pProtectedPathOps = NULL;
    pContext->bProtectedPathInitialized = false;
}

IpsecError_t GetIpsecProtectedPathStatusInternal(IpsecContext_t *pContext,
    IpsecProtectedPathStatusInternal_t *pStatus)
{
    if ((NULL == pContext) || (NULL == pStatus)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pStatus, 0, sizeof(*pStatus));
    if (NULL == pContext->pProtectedPathOps) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    return pContext->pProtectedPathOps->pGetStatus(pContext, pStatus);
}

IpsecError_t ReceiveIpsecProtectedPacket(IpsecContext_t *pContext,
    IpsecProtectedPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    if ((NULL == pContext) || (NULL == pPacket) ||
        (sizeof(*pPacket) != pPacket->uiStructSize)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pPacket->zLength = 0U;
    if (!pContext->bProtectedPathInitialized || (NULL == pContext->pProtectedPathOps)) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    return pContext->pProtectedPathOps->pReceivePacket(pContext, pPacket, uiTimeoutMs);
}

IpsecError_t SubmitIpsecProtectedPacket(IpsecContext_t *pContext,
    const IpsecProtectedPacket_t *pPacket)
{
    if ((NULL == pContext) || (NULL == pPacket) ||
        (sizeof(*pPacket) != pPacket->uiStructSize)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (!pContext->bProtectedPathInitialized || (NULL == pContext->pProtectedPathOps)) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    return pContext->pProtectedPathOps->pSubmitPacket(pContext, pPacket);
}
