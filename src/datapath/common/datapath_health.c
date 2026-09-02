#include "datapath_ops.h"

#include <string.h>

IpsecError_t GetIpsecDatapathStatusEx(IpsecContext_t *pContext,
                                      IpsecDatapathStatusEx_t *pStatus)
{
    IpsecPacketPathStatus_t Paths = {.uiStructSize = sizeof(Paths)};
    IpsecChildSaList_t Children = {0};
    IpsecIkeSaList_t Ikes = {0};
    IpsecError_t eError;
    uint32_t uiIndex;
    if ((NULL == pContext) || (NULL == pStatus) ||
        (sizeof(*pStatus) != pStatus->uiStructSize)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pStatus, 0, sizeof(*pStatus));
    pStatus->uiStructSize = sizeof(*pStatus);
    pStatus->eProtectedPacketPath =
        pContext->DatapathConfig.eProtectedPacketPath;
    pStatus->ePlainPacketPath = pContext->DatapathConfig.ePlainPacketPath;
    eError = GetIpsecDatapathStatus(pContext, &pStatus->Backend);
    if (IPSEC_OK == eError) {
        pStatus->bBackendReady = pStatus->Backend.bReady;
        eError = GetIpsecPacketPathStatus(pContext, &Paths);
    }
    if (IPSEC_OK == eError) {
        pStatus->bProtectedPathReady = Paths.bProtectedPathReady;
        pStatus->bPlainPathReady = Paths.bPlainPathReady;
        pStatus->uiProtectedInterfaceIndex = Paths.uiProtectedInterfaceIndex;
        memcpy(pStatus->acProtectedInterfaceName, Paths.acProtectedInterfaceName,
               sizeof(pStatus->acProtectedInterfaceName));
        pStatus->uiPlainInterfaceIndex = Paths.uiPlainInterfaceIndex;
        memcpy(pStatus->acPlainInterfaceName, Paths.acPlainInterfaceName,
               sizeof(pStatus->acPlainInterfaceName));
        pStatus->usPlainQueueNumber = Paths.usPlainQueueNumber;
        eError = GetIpsecChildSas(pContext, &Children);
    }
    if ((IPSEC_OK == eError) && (IPSEC_PACKET_PATH_APPLICATION == pStatus->eProtectedPacketPath)) {
        eError = GetIpsecIkeSas(pContext, &Ikes);
    }
    for (uiIndex = 0U; (IPSEC_OK == eError) && (uiIndex < Children.uiCount); uiIndex++) {
        const IpsecChildSaInfo_t *pChild = &Children.pItems[uiIndex];
        bool bInScope = IPSEC_PACKET_PATH_SYSTEM == pStatus->eProtectedPacketPath;
        uint32_t uiIke;
        for (uiIke = 0U; !bInScope && (uiIke < Ikes.uiCount); uiIke++) {
            const IpsecIkeSaInfo_t *pIke = &Ikes.pItems[uiIke];
            bInScope = !pChild->bUdpEncapsulation &&
                (0 == strcmp(pIke->acName, pChild->acIkeName)) &&
                (0 == strcmp(pIke->acLocalAddress, pContext->DatapathConfig.acProtectedLocalAddress)) &&
                (0 == strcmp(pIke->acRemoteAddress, pContext->DatapathConfig.acProtectedRemoteAddress));
        }
        if (bInScope && (0 == strcmp(pChild->acState, "INSTALLED"))) {
            pStatus->uiInstalledChildCount++;
        }
    }
    pStatus->bTrafficReady = (IPSEC_OK == eError) && pStatus->bBackendReady &&
        pStatus->bProtectedPathReady && pStatus->bPlainPathReady &&
        (pStatus->uiInstalledChildCount > 0U) &&
        ((IPSEC_DATAPATH_KERNEL_LIBIPSEC != pStatus->Backend.eType) ||
         (pStatus->Backend.uiTunRouteCount > 0U));
    FreeIpsecChildSaList(&Children);
    FreeIpsecIkeSaList(&Ikes);
    return eError;
}
