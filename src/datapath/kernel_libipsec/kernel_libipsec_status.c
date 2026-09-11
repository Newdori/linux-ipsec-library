#include "kernel_libipsec_internal.h"

#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

IpsecError_t InspectKernelLibipsecDatapath(IpsecContext_t *pContext,
                                          IpsecDatapathStatus_t *pStatus)
{
    IpsecTunCandidates_t *pCandidates = (IpsecTunCandidates_t *)calloc(1U, sizeof(*pCandidates));
    IpsecRouteList_t Routes = {0};
    struct ifinfomsg Request = {0};
    IpsecError_t eError;
    uint32_t uiIndex;
    uint32_t uiRoute;
    const char *pcName = pContext->Datapath.acInterfaceName;
    if (NULL == pCandidates) {
        return IPSEC_ERR_NO_MEMORY;
    }
    if ('\0' == pcName[0]) {
        pcName = pContext->Datapath.Config.acKernelLibipsecTunName;
    }
    Request.ifi_family = AF_UNSPEC;
    eError = ExecuteNetlinkDump(NETLINK_ROUTE, RTM_GETLINK, &Request,
        sizeof(Request), ParseIpsecTunMessage, pCandidates);
    if (IPSEC_OK == eError) {
        eError = GetIpsecRoutes(&Routes);
    }
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < pCandidates->uiCount; uiIndex++) {
            for (uiRoute = 0U; uiRoute < Routes.uiCount; uiRoute++) {
                if (pCandidates->aItems[uiIndex].uiIndex == Routes.pItems[uiRoute].uiInterfaceIndex) {
                    pCandidates->aItems[uiIndex].uiRouteCount++;
                }
            }
        }
        eError = SelectIpsecTun(pCandidates, pcName,
            pContext->Datapath.Config.acProtectedInterfaceName, pStatus);
    }
    FreeIpsecRouteList(&Routes);
    free(pCandidates);
    return eError;
}
