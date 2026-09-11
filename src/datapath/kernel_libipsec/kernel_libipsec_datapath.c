#include "kernel_libipsec_internal.h"

#include <string.h>

static IpsecError_t ProbeKernelLibipsec(IpsecContext_t *pContext,
                                        IpsecDatapathStatus_t *pStatus)
{
    IpsecError_t eError = ReadIpsecBackendPlugins(pContext, pStatus);
    pStatus->eType = IPSEC_DATAPATH_KERNEL_LIBIPSEC;
    if (IPSEC_OK != eError) {
        return eError;
    }
    if (!pStatus->bKernelLibipsecLoaded || !pStatus->bKernelNetlinkLoaded) {
        return IPSEC_ERR_DATAPATH_UNAVAILABLE;
    }
    return InspectKernelLibipsecDatapath(pContext, pStatus);
}

static IpsecError_t InitializeKernelLibipsec(IpsecContext_t *pContext)
{
    (void)pContext; /* Probe selected an existing TUN; never attach to its fd. */
    return IPSEC_OK;
}

static IpsecError_t GetKernelLibipsecStatus(IpsecContext_t *pContext,
                                            IpsecDatapathStatus_t *pStatus)
{
    IpsecError_t eError = ProbeKernelLibipsec(pContext, pStatus);
    if ((IPSEC_OK == eError) &&
        (pContext->Datapath.uiInterfaceIndex != pStatus->uiTunInterfaceIndex)) {
        pStatus->bReady = false;
        eError = IPSEC_ERR_DATAPATH_UNAVAILABLE;
    }
    return eError;
}

static IpsecError_t GetKernelLibipsecStatistics(IpsecContext_t *pContext,
                                               IpsecTrafficStatistics_t *pStatistics)
{
    (void)pContext;
    pStatistics->bCountersValid = false;
    return IPSEC_ERR_NOT_SUPPORTED;
}

static void DeinitializeKernelLibipsec(IpsecContext_t *pContext)
{
    (void)pContext; /* No charon-owned resources are destroyed. */
}

const IpsecDatapathOps_t *GetKernelLibipsecDatapathOps(void)
{
    static const IpsecDatapathOps_t Ops = {
        IPSEC_DATAPATH_KERNEL_LIBIPSEC, ProbeKernelLibipsec,
        InitializeKernelLibipsec, GetKernelLibipsecStatus,
        GetKernelLibipsecStatistics, DeinitializeKernelLibipsec
    };
    return &Ops;
}
