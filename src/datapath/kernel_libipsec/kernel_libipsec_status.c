#include "kernel_libipsec_internal.h"

#include <string.h>

static IpsecError_t InspectKernelLibipsecInterface(
    IpsecDatapathStatus_t *pStatus)
{
    IpsecInterfaceList_t List = {0};
    IpsecError_t eError;
    uint32_t uiIndex;

    eError = GetIpsecInterfaces(&List);
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecInterfaceInfo_t *pItem = &List.pItems[uiIndex];

            if (0 == strcmp(KERNEL_LIBIPSEC_TUN_INTERFACE, pItem->acName)) {
                pStatus->bTunInterfacePresent = true;
                pStatus->bTunInterfaceUp = pItem->bUp;
                pStatus->uiTunInterfaceIndex = pItem->uiIndex;
                eError = CopyIpsecString(
                    pStatus->acTunInterfaceName,
                    sizeof(pStatus->acTunInterfaceName),
                    (const uint8_t *)pItem->acName,
                    strlen(pItem->acName));
                break;
            }
            else {
                /* Continue searching for the kernel-libipsec TUN device. */
            }
        }
    }
    else {
        /* Preserve the NETLINK_ROUTE query error. */
    }
    FreeIpsecInterfaceList(&List);
    return eError;
}

static IpsecError_t CountKernelLibipsecRoutes(
    IpsecDatapathStatus_t *pStatus)
{
    IpsecRouteList_t List = {0};
    IpsecError_t eError;
    uint32_t uiIndex;

    eError = GetIpsecRoutes(&List);
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            const IpsecRouteInfo_t *pItem = &List.pItems[uiIndex];

            if ((0U != pStatus->uiTunInterfaceIndex) &&
                (pStatus->uiTunInterfaceIndex == pItem->uiInterfaceIndex)) {
                pStatus->uiTunRouteCount++;
            }
            else {
                /* The route belongs to another network interface. */
            }
        }
    }
    else {
        /* Preserve the NETLINK_ROUTE query error. */
    }
    FreeIpsecRouteList(&List);
    return eError;
}

IpsecError_t InspectKernelLibipsecDatapath(
    IpsecDatapathStatus_t *pStatus)
{
    IpsecError_t eError;

    if (NULL == pStatus) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = InspectKernelLibipsecInterface(pStatus);
    }
    if ((IPSEC_OK == eError) && pStatus->bTunInterfacePresent) {
        eError = CountKernelLibipsecRoutes(pStatus);
    }
    else {
        /* A missing TUN device is reported as a non-ready status. */
    }
    if (IPSEC_OK == eError) {
        pStatus->bReady = pStatus->bTunInterfacePresent &&
                          pStatus->bTunInterfaceUp;
    }
    else {
        /* Preserve the route or interface query error. */
    }
    return eError;
}
