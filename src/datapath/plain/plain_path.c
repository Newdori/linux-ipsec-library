#include "plain_path_ops.h"

#include <string.h>

IpsecError_t InitializeIpsecPlainPath(IpsecContext_t *pContext)
{
    IpsecError_t eError;
    if (IPSEC_PACKET_PATH_SYSTEM == pContext->Datapath.Config.ePlainPacketPath) {
        pContext->PlainPath.pOps = GetSystemPlainPathOps();
    }
    else if (IPSEC_PACKET_PATH_APPLICATION == pContext->Datapath.Config.ePlainPacketPath) {
        pContext->PlainPath.pOps = GetApplicationPlainPathOps();
    }
    else {
        return IPSEC_ERR_INVALID_PACKET_PATH;
    }
    eError = pContext->PlainPath.pOps->pInitialize(pContext);
    if (IPSEC_OK == eError) {
        pContext->PlainPath.bInitialized = true;
    }
    else {
        pContext->PlainPath.pOps->pDeinitialize(pContext);
        pContext->PlainPath.pOps = NULL;
    }
    return eError;
}

void DeinitializeIpsecPlainPath(IpsecContext_t *pContext)
{
    if (NULL != pContext->PlainPath.pOps) {
        pContext->PlainPath.pOps->pDeinitialize(pContext);
    }
    pContext->PlainPath.pOps = NULL;
    pContext->PlainPath.bInitialized = false;
}

IpsecError_t GetIpsecPlainPathStatusInternal(IpsecContext_t *pContext,
    IpsecPlainPathStatusInternal_t *pStatus)
{
    if ((NULL == pContext) || (NULL == pStatus)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pStatus, 0, sizeof(*pStatus));
    if (NULL == pContext->PlainPath.pOps) {
        return IPSEC_ERR_PLAIN_PATH_UNAVAILABLE;
    }
    return pContext->PlainPath.pOps->pGetStatus(pContext, pStatus);
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
    if (!pContext->PlainPath.bInitialized || (NULL == pContext->PlainPath.pOps)) {
        return IPSEC_ERR_PLAIN_PATH_UNAVAILABLE;
    }
    return pContext->PlainPath.pOps->pReceivePacket(pContext, pPacket, uiTimeoutMs);
}
