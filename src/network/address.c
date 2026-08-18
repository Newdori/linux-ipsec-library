#include "network_internal.h"

#include <arpa/inet.h>
#include <linux/if_addr.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>

static IpsecAddressFamily_t MapRouteAddressFamily(uint8_t ucFamily)
{
    IpsecAddressFamily_t eFamily;

    if (AF_INET == ucFamily) {
        eFamily = IPSEC_ADDRESS_FAMILY_IPV4;
    }
    else if (AF_INET6 == ucFamily) {
        eFamily = IPSEC_ADDRESS_FAMILY_IPV6;
    }
    else {
        eFamily = IPSEC_ADDRESS_FAMILY_UNSPECIFIED;
    }
    return eFamily;
}

static IpsecError_t AppendAddress(
    IpsecAddressList_t *pList,
    IpsecAddressInfo_t **ppInfo)
{
    IpsecAddressInfo_t *pNewItems;
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
            pNewItems = (IpsecAddressInfo_t *)realloc(
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

IpsecError_t ParseAddressMessage(
    const struct nlmsghdr *pHeader,
    void *pvUserData)
{
    IpsecAddressList_t *pList = (IpsecAddressList_t *)pvUserData;
    const struct ifaddrmsg *pKernelInfo;
    IpsecAddressInfo_t *pInfo = NULL;
    struct rtattr *pAttribute;
    const void *pvAddress = NULL;
    const void *pvFallbackAddress = NULL;
    size_t zAddressLength = 0U;
    size_t zFallbackLength = 0U;
    size_t zExpectedLength;
    int32_t iAttributeLength;
    IpsecError_t eError;

    if ((NULL == pHeader) || (NULL == pList) ||
        (RTM_NEWADDR != pHeader->nlmsg_type) ||
        (NLMSG_PAYLOAD(pHeader, 0) < sizeof(*pKernelInfo))) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        pKernelInfo = (const struct ifaddrmsg *)NLMSG_DATA(pHeader);
        if (!((AF_INET == pKernelInfo->ifa_family) ||
              (AF_INET6 == pKernelInfo->ifa_family))) {
            return IPSEC_OK;
        }
        else {
            eError = AppendAddress(pList, &pInfo);
        }
    }

    if (IPSEC_OK == eError) {
        pInfo->uiInterfaceIndex = pKernelInfo->ifa_index;
        pInfo->eFamily = MapRouteAddressFamily(pKernelInfo->ifa_family);
        pInfo->ucPrefixLength = pKernelInfo->ifa_prefixlen;
        pInfo->ucScope = pKernelInfo->ifa_scope;
        if (NULL == if_indextoname(pKernelInfo->ifa_index,
                                   pInfo->acInterfaceName)) {
            pInfo->acInterfaceName[0] = '\0';
        }
        else {
            /* Interface name resolved. */
        }

        iAttributeLength = IFA_PAYLOAD(pHeader);
        pAttribute = IFA_RTA(pKernelInfo);
        while (RTA_OK(pAttribute, iAttributeLength)) {
            if (IFA_LOCAL == pAttribute->rta_type) {
                pvAddress = RTA_DATA(pAttribute);
                zAddressLength = (size_t)RTA_PAYLOAD(pAttribute);
            }
            else if (IFA_ADDRESS == pAttribute->rta_type) {
                pvFallbackAddress = RTA_DATA(pAttribute);
                zFallbackLength = (size_t)RTA_PAYLOAD(pAttribute);
            }
            else {
                /* Ignore optional address attributes. */
            }
            pAttribute = RTA_NEXT(pAttribute, iAttributeLength);
        }
        if (0 != iAttributeLength) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            /* Attribute stream is complete. */
        }
    }
    else {
        /* Preserve header/allocation error. */
    }

    if ((IPSEC_OK == eError) && (NULL == pvAddress)) {
        pvAddress = pvFallbackAddress;
        zAddressLength = zFallbackLength;
    }
    else {
        /* Prefer IFA_LOCAL when present. */
    }
    if (IPSEC_OK == eError) {
        zExpectedLength = (AF_INET == pKernelInfo->ifa_family) ?
                          sizeof(struct in_addr) : sizeof(struct in6_addr);
        if ((NULL == pvAddress) || (zExpectedLength != zAddressLength) ||
            (NULL == inet_ntop(pKernelInfo->ifa_family, pvAddress,
                               pInfo->acAddress,
                               sizeof(pInfo->acAddress)))) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            /* Address converted. */
        }
    }
    else {
        /* Preserve attribute error. */
    }
    return eError;
}

IpsecError_t GetIpsecAddresses(IpsecAddressList_t *pList)
{
    struct ifaddrmsg Request;
    IpsecError_t eError;

    if (NULL == pList) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pList, 0, sizeof(*pList));
        memset(&Request, 0, sizeof(Request));
        Request.ifa_family = AF_UNSPEC;
        eError = ExecuteNetlinkDump(NETLINK_ROUTE, RTM_GETADDR,
                                    &Request, sizeof(Request),
                                    ParseAddressMessage, pList);
    }
    if (IPSEC_OK != eError) {
        FreeIpsecAddressList(pList);
    }
    else {
        /* Return addresses. */
    }
    return eError;
}

void FreeIpsecAddressList(IpsecAddressList_t *pList)
{
    if (NULL != pList) {
        free(pList->pItems);
        memset(pList, 0, sizeof(*pList));
    }
    else {
        /* NULL free is safe. */
    }
}
