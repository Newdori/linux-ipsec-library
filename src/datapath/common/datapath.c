#include "datapath_internal.h"

#include <string.h>

IpsecError_t GetIpsecDatapathStatus(
    IpsecContext_t *pContext,
    IpsecDatapathStatus_t *pStatus)
{
    IpsecDaemonStatus_t DaemonStatus = {0};
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pStatus)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pStatus, 0, sizeof(*pStatus));
        eError = GetIpsecDaemonStatus(pContext, &DaemonStatus);
    }
    if (IPSEC_OK == eError) {
        pStatus->bKernelNetlinkLoaded =
            DaemonStatus.bKernelNetlinkLoaded;
        pStatus->bKernelLibipsecLoaded =
            DaemonStatus.bKernelLibipsecLoaded;

        if (pStatus->bKernelLibipsecLoaded) {
            pStatus->eType = IPSEC_DATAPATH_KERNEL_LIBIPSEC;
            eError = InspectKernelLibipsecDatapath(pStatus);
        }
        else if (pStatus->bKernelNetlinkLoaded) {
            pStatus->eType = IPSEC_DATAPATH_KERNEL_XFRM;
            pStatus->bReady = true;
        }
        else {
            pStatus->eType = IPSEC_DATAPATH_UNKNOWN;
            pStatus->bReady = false;
        }
    }
    else {
        /* Preserve the VICI status error. */
    }
    return eError;
}
