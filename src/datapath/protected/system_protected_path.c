#include "protected_path_ops.h"

static IpsecError_t InitializeSystemProtectedPath(IpsecContext_t *pContext)
{
    (void)pContext;
    return IPSEC_OK; /* No packet socket, TUN, route or forwarding worker. */
}

static IpsecError_t ReceiveSystemProtectedPacket(IpsecContext_t *pContext,
    IpsecProtectedPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    (void)pContext;
    (void)pPacket;
    (void)uiTimeoutMs;
    return IPSEC_ERR_PACKET_PATH_MISMATCH;
}

static IpsecError_t SubmitSystemProtectedPacket(IpsecContext_t *pContext,
    const IpsecProtectedPacket_t *pPacket)
{
    (void)pContext;
    (void)pPacket;
    return IPSEC_ERR_PACKET_PATH_MISMATCH;
}

static IpsecError_t GetSystemProtectedPathStatus(IpsecContext_t *pContext,
    IpsecProtectedPathStatusInternal_t *pStatus)
{
    pStatus->bReady = pContext->ProtectedPath.bInitialized;
    return IPSEC_OK;
}

static void DeinitializeSystemProtectedPath(IpsecContext_t *pContext)
{
    (void)pContext;
}

const IpsecProtectedPathOps_t *GetSystemProtectedPathOps(void)
{
    static const IpsecProtectedPathOps_t Ops = {
        InitializeSystemProtectedPath, ReceiveSystemProtectedPacket,
        SubmitSystemProtectedPacket, GetSystemProtectedPathStatus,
        DeinitializeSystemProtectedPath
    };
    return &Ops;
}
