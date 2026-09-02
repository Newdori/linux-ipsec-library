#include "plain_path_ops.h"

static IpsecError_t InitializeSystemPlainPath(IpsecContext_t *pContext)
{
    (void)pContext;
    return IPSEC_OK;
}

static IpsecError_t ReceiveSystemPlainPacket(IpsecContext_t *pContext,
    IpsecPlainPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    (void)pContext;
    (void)pPacket;
    (void)uiTimeoutMs;
    return IPSEC_ERR_PACKET_PATH_MISMATCH;
}

static IpsecError_t GetSystemPlainPathStatus(IpsecContext_t *pContext,
    IpsecPlainPathStatusInternal_t *pStatus)
{
    pStatus->bReady = pContext->bPlainPathInitialized;
    return IPSEC_OK;
}

static void DeinitializeSystemPlainPath(IpsecContext_t *pContext)
{
    (void)pContext;
}

const IpsecPlainPathOps_t *GetSystemPlainPathOps(void)
{
    static const IpsecPlainPathOps_t Ops = {
        InitializeSystemPlainPath, ReceiveSystemPlainPacket,
        GetSystemPlainPathStatus, DeinitializeSystemPlainPath
    };
    return &Ops;
}
