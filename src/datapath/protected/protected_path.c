#include "protected_path_ops.h"

#include <string.h>

IpsecError_t InitializeIpsecProtectedPath(IpsecContext_t *pContext)
{
    IpsecError_t eError;
    if (IPSEC_PACKET_PATH_SYSTEM == pContext->Datapath.Config.eProtectedPacketPath) {
        pContext->ProtectedPath.pOps = GetSystemProtectedPathOps();
    }
    else if (IPSEC_PACKET_PATH_APPLICATION == pContext->Datapath.Config.eProtectedPacketPath) {
        pContext->ProtectedPath.pOps = GetApplicationProtectedPathOps();
    }
    else {
        return IPSEC_ERR_INVALID_PACKET_PATH;
    }
    eError = pContext->ProtectedPath.pOps->pInitialize(pContext);
    if (IPSEC_OK == eError) {
        pContext->ProtectedPath.bInitialized = true;
    }
    else {
        /* Also clean a partially initialized implementation. */
        pContext->ProtectedPath.pOps->pDeinitialize(pContext);
        pContext->ProtectedPath.pOps = NULL;
    }
    return eError;
}

void DeinitializeIpsecProtectedPath(IpsecContext_t *pContext)
{
    if (NULL != pContext->ProtectedPath.pOps) {
        pContext->ProtectedPath.pOps->pDeinitialize(pContext);
    }
    pContext->ProtectedPath.pOps = NULL;
    pContext->ProtectedPath.bInitialized = false;
}

IpsecError_t GetIpsecProtectedPathStatusInternal(IpsecContext_t *pContext,
    IpsecProtectedPathStatusInternal_t *pStatus)
{
    if ((NULL == pContext) || (NULL == pStatus)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pStatus, 0, sizeof(*pStatus));
    if (NULL == pContext->ProtectedPath.pOps) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    return pContext->ProtectedPath.pOps->pGetStatus(pContext, pStatus);
}

IpsecError_t ReceiveIpsecProtectedPacket(IpsecContext_t *pContext,
    IpsecProtectedPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    if ((NULL == pContext) || (NULL == pPacket) ||
        (sizeof(*pPacket) != pPacket->uiStructSize)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pPacket->zLength = 0U;
    if (!pContext->ProtectedPath.bInitialized || (NULL == pContext->ProtectedPath.pOps)) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    return pContext->ProtectedPath.pOps->pReceivePacket(pContext, pPacket, uiTimeoutMs);
}

IpsecError_t SubmitIpsecProtectedPacket(IpsecContext_t *pContext,
    const IpsecProtectedPacket_t *pPacket)
{
    if ((NULL == pContext) || (NULL == pPacket) ||
        (sizeof(*pPacket) != pPacket->uiStructSize)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (!pContext->ProtectedPath.bInitialized || (NULL == pContext->ProtectedPath.pOps)) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    return pContext->ProtectedPath.pOps->pSubmitPacket(pContext, pPacket);
}
