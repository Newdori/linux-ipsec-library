#include "app_internal.h"

#include <arpa/inet.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

bool IsNativeAppDatapathKey(const char *pcKey)
{
    return (NULL != pcKey) &&
        ((0 == strcmp("datapath_backend", pcKey)) ||
         (0 == strcmp("protected_packet_path", pcKey)) ||
         (0 == strcmp("plain_packet_path", pcKey)) ||
         (0 == strcmp("kernel_libipsec_tun", pcKey)) ||
         (0 == strncmp("protected_", pcKey, 10U)) ||
         (0 == strcmp("plain_queue_number", pcKey)));
}

IpsecError_t SetNativeAppDatapathSetting(
    NativeAppConfig_t *pConfig, const char *pcKey, const char *pcValue)
{
    IpsecDatapathConfig_t *pDatapath;
    char *pcDestination = NULL;
    size_t zCapacity = 0U;
    size_t zLength;
    uint32_t uiPriority;

    if ((NULL == pConfig) || (NULL == pcKey) || (NULL == pcValue)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pDatapath = &pConfig->Datapath;
    if (0 == strcmp("datapath_backend", pcKey)) {
        if (0 == strcmp("auto", pcValue)) {
            pDatapath->ePreference = IPSEC_DATAPATH_PREFER_AUTO;
        }
        else if (0 == strcmp("xfrm", pcValue)) {
            pDatapath->ePreference = IPSEC_DATAPATH_PREFER_XFRM;
        }
        else if (0 == strcmp("kernel-libipsec", pcValue)) {
            pDatapath->ePreference = IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC;
        }
        else {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
    }
    else if ((0 == strcmp("protected_packet_path", pcKey)) ||
             (0 == strcmp("plain_packet_path", pcKey))) {
        IpsecPacketPathMode_t ePath;
        if (0 == strcmp("system", pcValue)) {
            ePath = IPSEC_PACKET_PATH_SYSTEM;
        }
        else if (0 == strcmp("application", pcValue)) {
            ePath = IPSEC_PACKET_PATH_APPLICATION;
        }
        else {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
        if (0 == strcmp("protected_packet_path", pcKey)) {
            pDatapath->eProtectedPacketPath = ePath;
        }
        else {
            pDatapath->ePlainPacketPath = ePath;
        }
    }
    else if (0 == strcmp("protected_filter_priority", pcKey)) {
        if (!ParseNativeAppNumber(pcValue, &uiPriority) ||
            (uiPriority >= UINT16_MAX)) {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
        pDatapath->usProtectedFilterPriority = (uint16_t)uiPriority;
    }
    else if (0 == strcmp("plain_queue_number", pcKey)) {
        if (!ParseNativeAppNumber(pcValue, &uiPriority) ||
            (0U == uiPriority) || (uiPriority > UINT16_MAX)) {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
        pDatapath->usPlainQueueNumber = (uint16_t)uiPriority;
    }
    else {
        if (0 == strcmp("kernel_libipsec_tun", pcKey)) {
            pcDestination = pDatapath->acKernelLibipsecTunName;
            zCapacity = sizeof(pDatapath->acKernelLibipsecTunName);
        }
        else if (0 == strcmp("protected_interface", pcKey)) {
            pcDestination = pDatapath->acProtectedInterfaceName;
            zCapacity = sizeof(pDatapath->acProtectedInterfaceName);
        }
        else if (0 == strcmp("protected_egress_interface", pcKey)) {
            pcDestination = pDatapath->acProtectedEgressInterfaceName;
            zCapacity = sizeof(pDatapath->acProtectedEgressInterfaceName);
        }
        else if (0 == strcmp("protected_local_ip", pcKey)) {
            pcDestination = pDatapath->acProtectedLocalAddress;
            zCapacity = sizeof(pDatapath->acProtectedLocalAddress);
        }
        else if (0 == strcmp("protected_remote_ip", pcKey)) {
            pcDestination = pDatapath->acProtectedRemoteAddress;
            zCapacity = sizeof(pDatapath->acProtectedRemoteAddress);
        }
        else {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
        zLength = strnlen(pcValue, zCapacity);
        if (zLength >= zCapacity) {
            return IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        (void)memcpy(pcDestination, pcValue, zLength + 1U);
    }
    return IPSEC_OK;
}

static bool IsNativeAppInterfaceNameValid(const char *pcName, bool bOptional)
{
    size_t zIndex;
    size_t zLength = strnlen(pcName, IPSEC_DATAPATH_NAME_LENGTH);
    if ((zLength >= IPSEC_DATAPATH_NAME_LENGTH) ||
        ((!bOptional) && (0U == zLength)) ||
        (0 == strcmp(".", pcName)) || (0 == strcmp("..", pcName))) {
        return false;
    }
    for (zIndex = 0U; zIndex < zLength; zIndex++) {
        char cValue = pcName[zIndex];
        if (!(((cValue >= 'a') && (cValue <= 'z')) ||
              ((cValue >= 'A') && (cValue <= 'Z')) ||
              ((cValue >= '0') && (cValue <= '9')) ||
              ('_' == cValue) || ('-' == cValue) || ('.' == cValue))) {
            return false;
        }
    }
    return true;
}

IpsecError_t ValidateNativeAppDatapathConfig(const NativeAppConfig_t *pConfig)
{
    const IpsecDatapathConfig_t *pDatapath;
    struct in_addr Local;
    struct in_addr Remote;
    if (NULL == pConfig) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pDatapath = &pConfig->Datapath;
    if ((sizeof(*pDatapath) != pDatapath->uiStructSize) ||
        ((IPSEC_DATAPATH_PREFER_AUTO != pDatapath->ePreference) &&
         (IPSEC_DATAPATH_PREFER_XFRM != pDatapath->ePreference) &&
         (IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC != pDatapath->ePreference)) ||
        !IsNativeAppInterfaceNameValid(pDatapath->acKernelLibipsecTunName, true) ||
        ((IPSEC_PACKET_PATH_SYSTEM != pDatapath->eProtectedPacketPath) &&
         (IPSEC_PACKET_PATH_APPLICATION != pDatapath->eProtectedPacketPath)) ||
        ((IPSEC_PACKET_PATH_SYSTEM != pDatapath->ePlainPacketPath) &&
         (IPSEC_PACKET_PATH_APPLICATION != pDatapath->ePlainPacketPath))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (IPSEC_PACKET_PATH_APPLICATION == pDatapath->eProtectedPacketPath) {
        if (!IsNativeAppInterfaceNameValid(pDatapath->acProtectedInterfaceName, false) ||
            !IsNativeAppInterfaceNameValid(pDatapath->acProtectedEgressInterfaceName, false) ||
            (0 == strcmp(pDatapath->acProtectedInterfaceName,
                         pDatapath->acKernelLibipsecTunName)) ||
            (0 == strcmp(pDatapath->acProtectedInterfaceName,
                         pDatapath->acProtectedEgressInterfaceName)) ||
            (0 == strcmp(pDatapath->acProtectedEgressInterfaceName,
                         pDatapath->acKernelLibipsecTunName)) ||
            (UINT16_MAX == pDatapath->usProtectedFilterPriority) ||
            (1 != inet_pton(AF_INET, pDatapath->acProtectedLocalAddress, &Local)) ||
            (1 != inet_pton(AF_INET, pDatapath->acProtectedRemoteAddress, &Remote)) ||
            (Local.s_addr == Remote.s_addr) ||
            (0 == Local.s_addr) || (0 == Remote.s_addr) ||
            (ntohl(Local.s_addr) >= 0xe0000000U) ||
            (ntohl(Remote.s_addr) >= 0xe0000000U) ||
            (0 != strcmp(pConfig->acLocalAddress, pDatapath->acProtectedLocalAddress)) ||
            (('\0' != pConfig->acRemoteAddress[0]) &&
             (0 != strcmp(pConfig->acRemoteAddress,
                           pDatapath->acProtectedRemoteAddress)))) {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
    }
    else {
        /* Protected SYSTEM does not use dedicated TUN/filter settings. */
    }
    if ((IPSEC_PACKET_PATH_APPLICATION == pDatapath->ePlainPacketPath) &&
        (0U == pDatapath->usPlainQueueNumber)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if ((IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC == pDatapath->ePreference) &&
        (IPSEC_MODE_TUNNEL != pConfig->eMode)) {
        return IPSEC_ERR_NOT_SUPPORTED;
    }
    return IPSEC_OK;
}

bool AreNativeAppContextSettingsEqual(
    const NativeAppConfig_t *pLeft, const NativeAppConfig_t *pRight)
{
    const IpsecDatapathConfig_t *pA;
    const IpsecDatapathConfig_t *pB;
    if ((NULL == pLeft) || (NULL == pRight)) {
        return false;
    }
    pA = &pLeft->Datapath;
    pB = &pRight->Datapath;
    /* Compare fields, not struct padding. No peer-local identity is included. */
    return (0 == strcmp(pLeft->acViciSocket, pRight->acViciSocket)) &&
        (pLeft->uiTimeoutMs == pRight->uiTimeoutMs) &&
        (pA->ePreference == pB->ePreference) &&
        (pA->eProtectedPacketPath == pB->eProtectedPacketPath) &&
        (pA->ePlainPacketPath == pB->ePlainPacketPath) &&
        (pA->usProtectedFilterPriority == pB->usProtectedFilterPriority) &&
        (pA->usPlainQueueNumber == pB->usPlainQueueNumber) &&
        (0 == strcmp(pA->acKernelLibipsecTunName, pB->acKernelLibipsecTunName)) &&
        (0 == strcmp(pA->acProtectedInterfaceName, pB->acProtectedInterfaceName)) &&
        (0 == strcmp(pA->acProtectedEgressInterfaceName, pB->acProtectedEgressInterfaceName)) &&
        (0 == strcmp(pA->acProtectedLocalAddress, pB->acProtectedLocalAddress)) &&
        (0 == strcmp(pA->acProtectedRemoteAddress, pB->acProtectedRemoteAddress));
}

void ShowNativeAppDatapathConfig(const NativeAppConfig_t *pConfig)
{
    const IpsecDatapathConfig_t *pDatapath = &pConfig->Datapath;
    const char *pcBackend = "auto";
    if (IPSEC_DATAPATH_PREFER_XFRM == pDatapath->ePreference) {
        pcBackend = "xfrm";
    }
    else if (IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC == pDatapath->ePreference) {
        pcBackend = "kernel-libipsec";
    }
    (void)printf("[CONTEXT CONFIGURATION - restart required to change]\n"
        "  Backend          : %s (required; auto selects, not fallback)\n"
        "  Protected Path   : %s\n"
        "  Plain Path       : %s\n"
        "  Charon TUN       : %s\n"
        "  Protected TUN    : %s\n"
        "  Protected Egress : %s\n"
        "  Protected Local  : %s\n"
        "  Protected Remote : %s\n"
        "  TC Priority      : %" PRIu16 " (+1 reserved)\n"
        "  Plain NFQUEUE    : %" PRIu16 "\n",
        pcBackend,
        (IPSEC_PACKET_PATH_APPLICATION == pDatapath->eProtectedPacketPath) ?
            "application" : "system",
        (IPSEC_PACKET_PATH_APPLICATION == pDatapath->ePlainPacketPath) ?
            "application" : "system",
        ('\0' == pDatapath->acKernelLibipsecTunName[0]) ? "<discover>" :
            pDatapath->acKernelLibipsecTunName,
        pDatapath->acProtectedInterfaceName, pDatapath->acProtectedEgressInterfaceName,
        pDatapath->acProtectedLocalAddress, pDatapath->acProtectedRemoteAddress,
        (0U == pDatapath->usProtectedFilterPriority) ? (uint16_t)32000U :
            pDatapath->usProtectedFilterPriority,
        pDatapath->usPlainQueueNumber);
}
