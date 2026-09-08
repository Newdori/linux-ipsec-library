#include "datapath_ops.h"
#include "../protected/protected_path_ops.h"

#include <string.h>

static bool ValidateDatapathName(const char *pcName, size_t zCapacity)
{
    size_t zLength = strnlen(pcName, zCapacity);
    size_t zIndex;
    if ((zLength == zCapacity) || (0 == strcmp(pcName, ".")) ||
        (0 == strcmp(pcName, ".."))) {
        return false;
    }
    for (zIndex = 0U; zIndex < zLength; zIndex++) {
        uint8_t ucValue = (uint8_t)pcName[zIndex];
        if ((ucValue <= 0x20U) || (ucValue >= 0x7fU) ||
            ('/' == ucValue) || (':' == ucValue) || ('%' == ucValue)) {
            return false;
        }
    }
    return true;
}

IpsecError_t ConfigureIpsecDatapath(IpsecContext_t *pContext,
                                    const IpsecDatapathConfig_t *pConfig)
{
    IpsecDatapathConfig_t Config = {0};
    Config.uiStructSize = sizeof(Config);
    if (NULL != pConfig) {
        if (sizeof(*pConfig) != pConfig->uiStructSize) {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
        Config = *pConfig;
    }
    if ((IPSEC_DATAPATH_PREFER_AUTO != Config.ePreference) &&
        (IPSEC_DATAPATH_PREFER_XFRM != Config.ePreference) &&
        (IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC != Config.ePreference)) {
        return IPSEC_ERR_INVALID_DATAPATH;
    }
    if ((IPSEC_PACKET_PATH_SYSTEM != Config.eProtectedPacketPath) &&
        (IPSEC_PACKET_PATH_APPLICATION != Config.eProtectedPacketPath)) {
        return IPSEC_ERR_INVALID_PACKET_PATH;
    }
    if ((IPSEC_PACKET_PATH_SYSTEM != Config.ePlainPacketPath) &&
        (IPSEC_PACKET_PATH_APPLICATION != Config.ePlainPacketPath)) {
        return IPSEC_ERR_INVALID_PACKET_PATH;
    }
    if ((IPSEC_PACKET_PATH_APPLICATION == Config.ePlainPacketPath) &&
        (0U == Config.usPlainQueueNumber)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if ((IPSEC_PLAIN_NETFILTER_INPUT != Config.ePlainNetfilterHook) &&
        (IPSEC_PLAIN_NETFILTER_FORWARD != Config.ePlainNetfilterHook)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (!ValidateDatapathName(Config.acKernelLibipsecTunName,
                             sizeof(Config.acKernelLibipsecTunName)) ||
        !ValidateDatapathName(Config.acProtectedInterfaceName,
                             sizeof(Config.acProtectedInterfaceName)) ||
        !ValidateDatapathName(Config.acProtectedEgressInterfaceName,
                             sizeof(Config.acProtectedEgressInterfaceName)) ||
        (NULL == memchr(Config.acProtectedLocalAddress, '\0', sizeof(Config.acProtectedLocalAddress))) ||
        (NULL == memchr(Config.acProtectedRemoteAddress, '\0', sizeof(Config.acProtectedRemoteAddress)))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pContext->DatapathConfig = Config;
    return IPSEC_OK;
}

IpsecError_t ReadIpsecBackendPlugins(IpsecContext_t *pContext,
                                     IpsecDatapathStatus_t *pStatus)
{
    IpsecDaemonStatus_t Daemon = {0};
    IpsecError_t eError = GetIpsecDaemonStatus(pContext, &Daemon);
    if (IPSEC_OK == eError) {
        pStatus->bKernelLibipsecLoaded = Daemon.bKernelLibipsecLoaded;
        pStatus->bKernelNetlinkLoaded = Daemon.bKernelNetlinkLoaded;
    }
    return eError;
}

IpsecError_t SelectIpsecDatapath(IpsecContext_t *pContext,
    const IpsecDatapathOps_t *pLibipsec, const IpsecDatapathOps_t *pXfrm)
{
    IpsecDatapathStatus_t Status = {0};
    IpsecError_t eError = IPSEC_ERR_DATAPATH_UNAVAILABLE;
    const IpsecDatapathOps_t *pSelected = NULL;
    IpsecDatapathPreference_t ePreference = pContext->DatapathConfig.ePreference;

    if (IPSEC_DATAPATH_PREFER_XFRM != ePreference) {
        eError = pLibipsec->pProbe(pContext, &Status);
        if (IPSEC_OK == eError) {
            pSelected = pLibipsec;
        }
    }
    if ((NULL == pSelected) &&
        (IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC != ePreference)) {
        IpsecError_t ePrevious = eError;
        memset(&Status, 0, sizeof(Status));
        eError = pXfrm->pProbe(pContext, &Status);
        if (IPSEC_OK == eError) {
            pSelected = pXfrm;
        }
        else if ((IPSEC_ERR_BACKEND_MISMATCH == eError) &&
                 (IPSEC_DATAPATH_PREFER_AUTO == ePreference)) {
            /* A loaded but broken libipsec backend cannot be changed by IPC. */
            eError = ePrevious;
        }
    }
    if (NULL != pSelected) {
        pContext->pDatapathOps = pSelected;
        pContext->eActiveDatapath = pSelected->eType;
        pContext->uiDatapathInterfaceIndex = Status.uiTunInterfaceIndex;
        if (strlen(Status.acTunInterfaceName) >= sizeof(pContext->acDatapathInterfaceName)) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            memcpy(pContext->acDatapathInterfaceName, Status.acTunInterfaceName,
                   strlen(Status.acTunInterfaceName) + 1U);
            eError = pSelected->pInitialize(pContext);
        }
        if (IPSEC_OK == eError) {
            pContext->bDatapathInitialized = true;
        }
        else {
            pSelected->pDeinitialize(pContext);
            pContext->pDatapathOps = NULL;
            pContext->eActiveDatapath = IPSEC_DATAPATH_UNKNOWN;
        }
    }
    pContext->eDatapathError = eError;
    return eError;
}

IpsecError_t InitializeIpsecDatapath(IpsecContext_t *pContext)
{
    return SelectIpsecDatapath(pContext, GetKernelLibipsecDatapathOps(),
                              GetXfrmDatapathOps());
}

void DeinitializeIpsecDatapath(IpsecContext_t *pContext)
{
    if (pContext->bDatapathInitialized) {
        pContext->pDatapathOps->pDeinitialize(pContext);
        pContext->bDatapathInitialized = false;
    }
    pContext->pDatapathOps = NULL;
    pContext->eActiveDatapath = IPSEC_DATAPATH_UNKNOWN;
}

IpsecError_t GetIpsecDatapathStatus(IpsecContext_t *pContext,
                                    IpsecDatapathStatus_t *pStatus)
{
    if ((NULL == pContext) || (NULL == pStatus)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pStatus, 0, sizeof(*pStatus));
    if (NULL == pContext->pDatapathOps) {
        return (IPSEC_OK != pContext->eDatapathError) ?
            pContext->eDatapathError : IPSEC_ERR_DATAPATH_UNAVAILABLE;
    }
    return pContext->pDatapathOps->pGetStatus(pContext, pStatus);
}

IpsecError_t RequireIpsecXfrmBackend(IpsecContext_t *pContext)
{
    IpsecDatapathStatus_t Status;
    IpsecError_t eError = GetIpsecDatapathStatus(pContext, &Status);
    if ((IPSEC_OK == eError) && (IPSEC_DATAPATH_KERNEL_XFRM != Status.eType)) {
        eError = IPSEC_ERR_BACKEND_MISMATCH;
    }
    return eError;
}

IpsecError_t GetIpsecTrafficStatistics(IpsecContext_t *pContext,
                                       IpsecTrafficStatistics_t *pStatistics)
{
    IpsecDatapathStatus_t Status;
    IpsecError_t eError;
    if ((NULL == pContext) || (NULL == pStatistics) ||
        (sizeof(*pStatistics) != pStatistics->uiStructSize)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pStatistics, 0, sizeof(*pStatistics));
    pStatistics->uiStructSize = sizeof(*pStatistics);
    eError = GetIpsecDatapathStatus(pContext, &Status);
    if (IPSEC_OK == eError) {
        eError = pContext->pDatapathOps->pGetStatistics(pContext, pStatistics);
    }
    return eError;
}

IpsecError_t GetIpsecBackendXfrmStatistics(IpsecContext_t *pContext,
                                          IpsecXfrmStatistics_t *pStatistics)
{
    IpsecError_t eError;
    if (NULL == pStatistics) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pStatistics, 0, sizeof(*pStatistics));
    eError = RequireIpsecXfrmBackend(pContext);
    if (IPSEC_OK == eError) {
        eError = GetIpsecXfrmStatistics(pStatistics);
    }
    return eError;
}
