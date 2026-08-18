#include "network_internal.h"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <stdlib.h>
#include <string.h>

typedef struct RouteAttributeValues {
    const void *pvDestination;
    size_t zDestinationLength;
    const void *pvGateway;
    size_t zGatewayLength;
    const void *pvSource;
    size_t zSourceLength;
    uint32_t uiInterfaceIndex;
    uint32_t uiMetric;
    uint32_t uiTable;
} RouteAttributeValues_t;

static IpsecAddressFamily_t MapRouteFamily(uint8_t ucFamily)
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

static IpsecError_t AppendRoute(
    IpsecRouteList_t *pList,
    IpsecRouteInfo_t **ppInfo)
{
    IpsecRouteInfo_t *pNewItems;
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
            pNewItems = (IpsecRouteInfo_t *)realloc(
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

static IpsecError_t ReadRouteUint32(
    const struct rtattr *pAttribute,
    uint32_t *puiValue)
{
    IpsecError_t eError;

    if (sizeof(*puiValue) != (size_t)RTA_PAYLOAD(pAttribute)) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        memcpy(puiValue, RTA_DATA(pAttribute), sizeof(*puiValue));
        eError = IPSEC_OK;
    }
    return eError;
}

static IpsecError_t ParseRouteMultipath(
    const struct rtattr *pAttribute,
    RouteAttributeValues_t *pValues)
{
    struct rtnexthop *pNextHop;
    struct rtattr *pNestedAttribute;
    int32_t iRemainingLength = RTA_PAYLOAD(pAttribute);
    int32_t iNestedLength;
    IpsecError_t eError = IPSEC_OK;

    pNextHop = (struct rtnexthop *)RTA_DATA(pAttribute);
    if (!RTNH_OK(pNextHop, iRemainingLength)) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        pValues->uiInterfaceIndex = (uint32_t)pNextHop->rtnh_ifindex;
        iNestedLength = (int32_t)pNextHop->rtnh_len -
                        (int32_t)sizeof(*pNextHop);
        pNestedAttribute = RTNH_DATA(pNextHop);
        while (RTA_OK(pNestedAttribute, iNestedLength)) {
            if (RTA_GATEWAY == pNestedAttribute->rta_type) {
                pValues->pvGateway = RTA_DATA(pNestedAttribute);
                pValues->zGatewayLength =
                    (size_t)RTA_PAYLOAD(pNestedAttribute);
            }
            else {
                /* Ignore optional next-hop attributes. */
            }
            pNestedAttribute = RTA_NEXT(pNestedAttribute, iNestedLength);
        }
        if (0 != iNestedLength) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            /* First next hop was decoded. */
        }
    }
    return eError;
}

static IpsecError_t ParseRouteAttributes(
    const struct rtmsg *pKernelInfo,
    const struct nlmsghdr *pHeader,
    RouteAttributeValues_t *pValues)
{
    struct rtattr *pAttribute;
    int32_t iAttributeLength = RTM_PAYLOAD(pHeader);
    IpsecError_t eError = IPSEC_OK;

    memset(pValues, 0, sizeof(*pValues));
    pValues->uiTable = pKernelInfo->rtm_table;
    pAttribute = RTM_RTA(pKernelInfo);
    while (RTA_OK(pAttribute, iAttributeLength) &&
           (IPSEC_OK == eError)) {
        switch (pAttribute->rta_type) {
        case RTA_DST:
            pValues->pvDestination = RTA_DATA(pAttribute);
            pValues->zDestinationLength =
                (size_t)RTA_PAYLOAD(pAttribute);
            break;
        case RTA_GATEWAY:
            pValues->pvGateway = RTA_DATA(pAttribute);
            pValues->zGatewayLength = (size_t)RTA_PAYLOAD(pAttribute);
            break;
        case RTA_PREFSRC:
            pValues->pvSource = RTA_DATA(pAttribute);
            pValues->zSourceLength = (size_t)RTA_PAYLOAD(pAttribute);
            break;
        case RTA_OIF:
            eError = ReadRouteUint32(pAttribute,
                                     &pValues->uiInterfaceIndex);
            break;
        case RTA_PRIORITY:
            eError = ReadRouteUint32(pAttribute, &pValues->uiMetric);
            break;
        case RTA_TABLE:
            eError = ReadRouteUint32(pAttribute, &pValues->uiTable);
            break;
        case RTA_MULTIPATH:
            if (0U == pValues->uiInterfaceIndex) {
                eError = ParseRouteMultipath(pAttribute, pValues);
            }
            else {
                /* Prefer explicit outer interface. */
            }
            break;
        default:
            /* Unknown route attributes are forward-compatible. */
            break;
        }
        pAttribute = RTA_NEXT(pAttribute, iAttributeLength);
    }
    if ((IPSEC_OK == eError) && (0 != iAttributeLength)) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        /* Attribute stream is complete or already invalid. */
    }
    return eError;
}

static IpsecError_t ConvertRouteAddress(
    uint8_t ucFamily,
    const void *pvAddress,
    size_t zAddressLength,
    bool bDefault,
    char *pcDestination,
    size_t zDestinationLength)
{
    size_t zExpectedLength;
    const char *pcDefault;
    IpsecError_t eError;

    zExpectedLength = (AF_INET == ucFamily) ?
                      sizeof(struct in_addr) : sizeof(struct in6_addr);
    pcDefault = (AF_INET == ucFamily) ? "0.0.0.0" : "::";

    if ((NULL == pvAddress) && bDefault) {
        eError = CopyIpsecString(pcDestination, zDestinationLength,
                                 (const uint8_t *)pcDefault,
                                 strlen(pcDefault));
    }
    else if (NULL == pvAddress) {
        pcDestination[0] = '\0';
        eError = IPSEC_OK;
    }
    else if ((zExpectedLength != zAddressLength) ||
             (NULL == inet_ntop(ucFamily, pvAddress, pcDestination,
                                (socklen_t)zDestinationLength))) {
        pcDestination[0] = '\0';
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        eError = IPSEC_OK;
    }
    return eError;
}

IpsecError_t ParseRouteMessage(
    const struct nlmsghdr *pHeader,
    void *pvUserData)
{
    IpsecRouteList_t *pList = (IpsecRouteList_t *)pvUserData;
    const struct rtmsg *pKernelInfo;
    IpsecRouteInfo_t *pInfo = NULL;
    RouteAttributeValues_t Values;
    IpsecError_t eError;

    if ((NULL == pHeader) || (NULL == pList) ||
        (RTM_NEWROUTE != pHeader->nlmsg_type) ||
        (NLMSG_PAYLOAD(pHeader, 0) < sizeof(*pKernelInfo))) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        pKernelInfo = (const struct rtmsg *)NLMSG_DATA(pHeader);
        if (!((AF_INET == pKernelInfo->rtm_family) ||
              (AF_INET6 == pKernelInfo->rtm_family))) {
            return IPSEC_OK;
        }
        else {
            eError = AppendRoute(pList, &pInfo);
        }
    }

    if (IPSEC_OK == eError) {
        eError = ParseRouteAttributes(pKernelInfo, pHeader, &Values);
    }
    else {
        /* Preserve header/allocation error. */
    }
    if (IPSEC_OK == eError) {
        pInfo->eFamily = MapRouteFamily(pKernelInfo->rtm_family);
        pInfo->ucPrefixLength = pKernelInfo->rtm_dst_len;
        pInfo->uiInterfaceIndex = Values.uiInterfaceIndex;
        pInfo->uiMetric = Values.uiMetric;
        pInfo->uiTable = Values.uiTable;
        pInfo->ucProtocol = pKernelInfo->rtm_protocol;
        pInfo->ucScope = pKernelInfo->rtm_scope;
        eError = ConvertRouteAddress(
            pKernelInfo->rtm_family, Values.pvDestination,
            Values.zDestinationLength, true, pInfo->acDestination,
            sizeof(pInfo->acDestination));
    }
    else {
        /* Preserve attribute error. */
    }
    if (IPSEC_OK == eError) {
        eError = ConvertRouteAddress(
            pKernelInfo->rtm_family, Values.pvGateway,
            Values.zGatewayLength, false, pInfo->acGateway,
            sizeof(pInfo->acGateway));
    }
    else {
        /* Preserve destination error. */
    }
    if (IPSEC_OK == eError) {
        eError = ConvertRouteAddress(
            pKernelInfo->rtm_family, Values.pvSource,
            Values.zSourceLength, false, pInfo->acSource,
            sizeof(pInfo->acSource));
    }
    else {
        /* Preserve gateway error. */
    }
    if (IPSEC_OK == eError) {
        if ((0U != pInfo->uiInterfaceIndex) &&
            (NULL == if_indextoname(pInfo->uiInterfaceIndex,
                                    pInfo->acInterfaceName))) {
            pInfo->acInterfaceName[0] = '\0';
        }
        else {
            /* Interface is absent or resolved. */
        }
    }
    else {
        /* Preserve source error. */
    }
    return eError;
}

IpsecError_t GetIpsecRoutes(IpsecRouteList_t *pList)
{
    struct rtmsg Request;
    IpsecError_t eError;

    if (NULL == pList) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pList, 0, sizeof(*pList));
        memset(&Request, 0, sizeof(Request));
        Request.rtm_family = AF_UNSPEC;
        eError = ExecuteNetlinkDump(NETLINK_ROUTE, RTM_GETROUTE,
                                    &Request, sizeof(Request),
                                    ParseRouteMessage, pList);
    }
    if (IPSEC_OK != eError) {
        FreeIpsecRouteList(pList);
    }
    else {
        /* Return routes. */
    }
    return eError;
}

void FreeIpsecRouteList(IpsecRouteList_t *pList)
{
    if (NULL != pList) {
        free(pList->pItems);
        memset(pList, 0, sizeof(*pList));
    }
    else {
        /* NULL free is safe. */
    }
}
