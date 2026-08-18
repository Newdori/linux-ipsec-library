#include "network_internal.h"

#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static IpsecError_t AppendInterface(
    IpsecInterfaceList_t *pList,
    IpsecInterfaceInfo_t **ppInfo)
{
    IpsecInterfaceInfo_t *pNewItems;
    uint32_t uiNewCount;
    size_t zAllocationSize;
    IpsecError_t eError;

    if (UINT32_MAX == pList->uiCount) {
        eError = IPSEC_ERR_NO_MEMORY;
    }
    else {
        uiNewCount = pList->uiCount + 1U;
        if (!CalculateIpsecArraySize(uiNewCount, sizeof(*pNewItems),
                                    &zAllocationSize)) {
            eError = IPSEC_ERR_NO_MEMORY;
        }
        else {
            pNewItems = (IpsecInterfaceInfo_t *)realloc(
                pList->pItems, zAllocationSize);
            if (NULL == pNewItems) {
                eError = IPSEC_ERR_NO_MEMORY;
            }
            else {
                pList->pItems = pNewItems;
                pList->uiCount = uiNewCount;
                *ppInfo = &pNewItems[uiNewCount - 1U];
                memset(*ppInfo, 0, sizeof(**ppInfo));
                eError = IPSEC_OK;
            }
        }
    }
    return eError;
}

static IpsecError_t FormatInterfaceMacAddress(
    const uint8_t *pucAddress,
    size_t zAddressLength,
    char *pcDestination,
    size_t zDestinationLength)
{
    size_t zIndex;
    size_t zUsed = 0U;
    int32_t iLength;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pucAddress) || (0U == zAddressLength) ||
        (NULL == pcDestination) || (0U == zDestinationLength)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        pcDestination[0] = '\0';
        for (zIndex = 0U;
             (zIndex < zAddressLength) && (IPSEC_OK == eError);
             zIndex++) {
            iLength = (int32_t)snprintf(
                pcDestination + zUsed, zDestinationLength - zUsed,
                (0U == zIndex) ? "%02x" : ":%02x", pucAddress[zIndex]);
            if ((0 > iLength) ||
                ((size_t)iLength >= (zDestinationLength - zUsed))) {
                eError = IPSEC_ERR_BUFFER_TOO_SMALL;
            }
            else {
                zUsed += (size_t)iLength;
            }
        }
    }
    return eError;
}

static IpsecError_t ParseInterfaceAttribute(
    const struct rtattr *pAttribute,
    IpsecInterfaceInfo_t *pInfo,
    bool *pbCarrierPresent)
{
    const uint8_t *pucPayload = (const uint8_t *)RTA_DATA(pAttribute);
    size_t zPayloadLength = (size_t)RTA_PAYLOAD(pAttribute);
    const uint8_t *pucEnd;
    uint32_t uiValue;
    IpsecError_t eError = IPSEC_OK;

    switch (pAttribute->rta_type) {
    case IFLA_IFNAME:
        pucEnd = (const uint8_t *)memchr(pucPayload, '\0', zPayloadLength);
        if (NULL == pucEnd) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            eError = CopyIpsecString(pInfo->acName, sizeof(pInfo->acName),
                                     pucPayload,
                                     (size_t)(pucEnd - pucPayload));
        }
        break;
    case IFLA_MTU:
        if (sizeof(uiValue) != zPayloadLength) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            memcpy(&uiValue, pucPayload, sizeof(uiValue));
            pInfo->uiMtu = uiValue;
        }
        break;
    case IFLA_ADDRESS:
        eError = FormatInterfaceMacAddress(
            pucPayload, zPayloadLength, pInfo->acMacAddress,
            sizeof(pInfo->acMacAddress));
        break;
    case IFLA_CARRIER:
        if (sizeof(uint8_t) != zPayloadLength) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            pInfo->bCarrier = 0U != pucPayload[0];
            *pbCarrierPresent = true;
        }
        break;
    default:
        /* Unknown link attributes are forward-compatible. */
        break;
    }
    return eError;
}

IpsecError_t ParseInterfaceMessage(
    const struct nlmsghdr *pHeader,
    void *pvUserData)
{
    IpsecInterfaceList_t *pList = (IpsecInterfaceList_t *)pvUserData;
    const struct ifinfomsg *pKernelInfo;
    IpsecInterfaceInfo_t *pInfo = NULL;
    struct rtattr *pAttribute;
    int32_t iAttributeLength;
    bool bCarrierPresent = false;
    IpsecError_t eError;

    if ((NULL == pHeader) || (NULL == pList) ||
        (RTM_NEWLINK != pHeader->nlmsg_type) ||
        (NLMSG_PAYLOAD(pHeader, 0) < sizeof(*pKernelInfo))) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        pKernelInfo = (const struct ifinfomsg *)NLMSG_DATA(pHeader);
        eError = AppendInterface(pList, &pInfo);
    }

    if (IPSEC_OK == eError) {
        pInfo->uiIndex = (uint32_t)pKernelInfo->ifi_index;
        pInfo->uiFlags = pKernelInfo->ifi_flags;
        pInfo->bUp = 0U != (pKernelInfo->ifi_flags & IFF_UP);
        pInfo->bRunning = 0U != (pKernelInfo->ifi_flags & IFF_RUNNING);

        iAttributeLength = (int32_t)pHeader->nlmsg_len -
                           (int32_t)NLMSG_LENGTH(sizeof(*pKernelInfo));
        pAttribute = IFLA_RTA(pKernelInfo);
        while (RTA_OK(pAttribute, iAttributeLength) &&
               (IPSEC_OK == eError)) {
            eError = ParseInterfaceAttribute(pAttribute, pInfo,
                                             &bCarrierPresent);
            pAttribute = RTA_NEXT(pAttribute, iAttributeLength);
        }
        if ((IPSEC_OK == eError) && (0 != iAttributeLength)) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            /* Attribute stream is complete or already invalid. */
        }
        if ((IPSEC_OK == eError) && !bCarrierPresent) {
            pInfo->bCarrier = pInfo->bRunning;
        }
        else {
            /* Use explicit carrier or preserve error. */
        }
    }
    else {
        /* Preserve header/allocation error. */
    }
    return eError;
}

IpsecError_t GetIpsecInterfaces(IpsecInterfaceList_t *pList)
{
    struct ifinfomsg Request;
    IpsecError_t eError;

    if (NULL == pList) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pList, 0, sizeof(*pList));
        memset(&Request, 0, sizeof(Request));
        Request.ifi_family = AF_UNSPEC;
        eError = ExecuteNetlinkDump(NETLINK_ROUTE, RTM_GETLINK,
                                    &Request, sizeof(Request),
                                    ParseInterfaceMessage, pList);
    }
    if (IPSEC_OK != eError) {
        FreeIpsecInterfaceList(pList);
    }
    else {
        /* Return interfaces. */
    }
    return eError;
}

void FreeIpsecInterfaceList(IpsecInterfaceList_t *pList)
{
    if (NULL != pList) {
        free(pList->pItems);
        memset(pList, 0, sizeof(*pList));
    }
    else {
        /* NULL free is safe. */
    }
}
