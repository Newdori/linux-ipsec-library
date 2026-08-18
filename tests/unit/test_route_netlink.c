#include "network_internal.h"

#include <arpa/inet.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/if_link.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_ROUTE_BUFFER_LENGTH 2048U

typedef union TestRouteBuffer {
    max_align_t Alignment;
    uint8_t aucData[TEST_ROUTE_BUFFER_LENGTH];
} TestRouteBuffer_t;

static int32_t ReportFailure(const char *pcMessage)
{
    (void)fprintf(stderr, "FAIL: %s\n", pcMessage);
    return 1;
}

static bool AddTestAttribute(
    struct nlmsghdr *pHeader,
    size_t zCapacity,
    uint16_t usType,
    const void *pvData,
    size_t zDataLength)
{
    struct rtattr *pAttribute;
    size_t zOffset = NLMSG_ALIGN(pHeader->nlmsg_len);
    size_t zAttributeLength = RTA_LENGTH(zDataLength);
    size_t zAlignedLength = RTA_ALIGN(zAttributeLength);
    bool bAdded;

    if ((NULL == pvData) || (zCapacity < zOffset) ||
        ((zCapacity - zOffset) < zAlignedLength) ||
        (UINT16_MAX < zAttributeLength)) {
        bAdded = false;
    }
    else {
        pAttribute = (struct rtattr *)((uint8_t *)pHeader + zOffset);
        memset(pAttribute, 0, zAlignedLength);
        pAttribute->rta_type = usType;
        pAttribute->rta_len = (uint16_t)zAttributeLength;
        memcpy(RTA_DATA(pAttribute), pvData, zDataLength);
        pHeader->nlmsg_len = (uint32_t)(zOffset + zAlignedLength);
        bAdded = true;
    }
    return bAdded;
}

static int32_t TestInterfaceMessage(void)
{
    static const char acName[] = "eth-test";
    static const uint8_t aucMac[] = {0x02U, 0x00U, 0x00U,
                                     0x00U, 0x00U, 0x01U};
    TestRouteBuffer_t Buffer;
    struct nlmsghdr *pHeader = (struct nlmsghdr *)Buffer.aucData;
    struct ifinfomsg *pKernelInfo;
    uint32_t uiMtu = 1500U;
    uint8_t ucCarrier = 1U;
    IpsecInterfaceList_t List = {0};
    IpsecError_t eError;

    memset(&Buffer, 0, sizeof(Buffer));
    pHeader->nlmsg_type = RTM_NEWLINK;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pKernelInfo));
    pKernelInfo = (struct ifinfomsg *)NLMSG_DATA(pHeader);
    pKernelInfo->ifi_index = 7;
    pKernelInfo->ifi_flags = IFF_UP | IFF_RUNNING;
    if (!AddTestAttribute(pHeader, sizeof(Buffer.aucData), IFLA_IFNAME,
                          acName, sizeof(acName)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), IFLA_MTU,
                          &uiMtu, sizeof(uiMtu)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), IFLA_ADDRESS,
                          aucMac, sizeof(aucMac)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), IFLA_CARRIER,
                          &ucCarrier, sizeof(ucCarrier))) {
        return ReportFailure("interface attribute construction");
    }
    else {
        /* Attributes encoded. */
    }

    eError = ParseInterfaceMessage(pHeader, &List);
    if ((IPSEC_OK != eError) || (1U != List.uiCount) ||
        (7U != List.pItems[0].uiIndex) || !List.pItems[0].bUp ||
        !List.pItems[0].bRunning || !List.pItems[0].bCarrier ||
        (1500U != List.pItems[0].uiMtu) ||
        (0 != strcmp("eth-test", List.pItems[0].acName)) ||
        (0 != strcmp("02:00:00:00:00:01",
                     List.pItems[0].acMacAddress))) {
        FreeIpsecInterfaceList(&List);
        return ReportFailure("interface message parse");
    }
    else {
        FreeIpsecInterfaceList(&List);
        return 0;
    }
}

static int32_t TestAddressMessage(void)
{
    TestRouteBuffer_t Buffer;
    struct nlmsghdr *pHeader = (struct nlmsghdr *)Buffer.aucData;
    struct ifaddrmsg *pKernelInfo;
    struct in_addr Address;
    IpsecAddressList_t List = {0};
    IpsecError_t eError;

    memset(&Buffer, 0, sizeof(Buffer));
    pHeader->nlmsg_type = RTM_NEWADDR;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pKernelInfo));
    pKernelInfo = (struct ifaddrmsg *)NLMSG_DATA(pHeader);
    pKernelInfo->ifa_family = AF_INET;
    pKernelInfo->ifa_prefixlen = 24U;
    pKernelInfo->ifa_index = 7U;
    if ((1 != inet_pton(AF_INET, "192.0.2.10", &Address)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), IFA_LOCAL,
                          &Address, sizeof(Address))) {
        return ReportFailure("address attribute construction");
    }
    else {
        /* Address encoded. */
    }

    eError = ParseAddressMessage(pHeader, &List);
    if ((IPSEC_OK != eError) || (1U != List.uiCount) ||
        (IPSEC_ADDRESS_FAMILY_IPV4 != List.pItems[0].eFamily) ||
        (24U != List.pItems[0].ucPrefixLength) ||
        (0 != strcmp("192.0.2.10", List.pItems[0].acAddress))) {
        FreeIpsecAddressList(&List);
        return ReportFailure("address message parse");
    }
    else {
        FreeIpsecAddressList(&List);
        return 0;
    }
}

static int32_t TestRouteMessage(void)
{
    TestRouteBuffer_t Buffer;
    struct nlmsghdr *pHeader = (struct nlmsghdr *)Buffer.aucData;
    struct rtmsg *pKernelInfo;
    struct in_addr Destination;
    struct in_addr Gateway;
    struct in_addr Source;
    uint32_t uiInterfaceIndex = 7U;
    uint32_t uiMetric = 100U;
    uint32_t uiTable = 254U;
    IpsecRouteList_t List = {0};
    IpsecError_t eError;

    memset(&Buffer, 0, sizeof(Buffer));
    pHeader->nlmsg_type = RTM_NEWROUTE;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pKernelInfo));
    pKernelInfo = (struct rtmsg *)NLMSG_DATA(pHeader);
    pKernelInfo->rtm_family = AF_INET;
    pKernelInfo->rtm_dst_len = 24U;
    pKernelInfo->rtm_protocol = RTPROT_STATIC;
    pKernelInfo->rtm_scope = RT_SCOPE_UNIVERSE;
    pKernelInfo->rtm_table = RT_TABLE_MAIN;
    if ((1 != inet_pton(AF_INET, "203.0.113.0", &Destination)) ||
        (1 != inet_pton(AF_INET, "192.0.2.1", &Gateway)) ||
        (1 != inet_pton(AF_INET, "192.0.2.10", &Source)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), RTA_DST,
                          &Destination, sizeof(Destination)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), RTA_GATEWAY,
                          &Gateway, sizeof(Gateway)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), RTA_PREFSRC,
                          &Source, sizeof(Source)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), RTA_OIF,
                          &uiInterfaceIndex, sizeof(uiInterfaceIndex)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), RTA_PRIORITY,
                          &uiMetric, sizeof(uiMetric)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), RTA_TABLE,
                          &uiTable, sizeof(uiTable))) {
        return ReportFailure("route attribute construction");
    }
    else {
        /* Route encoded. */
    }

    eError = ParseRouteMessage(pHeader, &List);
    if ((IPSEC_OK != eError) || (1U != List.uiCount) ||
        (24U != List.pItems[0].ucPrefixLength) ||
        (100U != List.pItems[0].uiMetric) ||
        (254U != List.pItems[0].uiTable) ||
        (0 != strcmp("203.0.113.0", List.pItems[0].acDestination)) ||
        (0 != strcmp("192.0.2.1", List.pItems[0].acGateway)) ||
        (0 != strcmp("192.0.2.10", List.pItems[0].acSource))) {
        FreeIpsecRouteList(&List);
        return ReportFailure("route message parse");
    }
    else {
        FreeIpsecRouteList(&List);
        return 0;
    }
}

static int32_t TestMalformedRouteAttribute(void)
{
    TestRouteBuffer_t Buffer;
    struct nlmsghdr *pHeader = (struct nlmsghdr *)Buffer.aucData;
    struct rtmsg *pKernelInfo;
    uint16_t usShortInterfaceIndex = 7U;
    IpsecRouteList_t List = {0};
    IpsecError_t eError;

    memset(&Buffer, 0, sizeof(Buffer));
    pHeader->nlmsg_type = RTM_NEWROUTE;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pKernelInfo));
    pKernelInfo = (struct rtmsg *)NLMSG_DATA(pHeader);
    pKernelInfo->rtm_family = AF_INET;
    if (!AddTestAttribute(pHeader, sizeof(Buffer.aucData), RTA_OIF,
                          &usShortInterfaceIndex,
                          sizeof(usShortInterfaceIndex))) {
        return ReportFailure("malformed route construction");
    }
    else {
        /* Malformed attribute encoded. */
    }

    eError = ParseRouteMessage(pHeader, &List);
    FreeIpsecRouteList(&List);
    if (IPSEC_ERR_NETLINK_PARSE != eError) {
        return ReportFailure("short route attribute accepted");
    }
    else {
        return 0;
    }
}

int main(void)
{
    int32_t iResult;

    iResult = TestInterfaceMessage();
    if (0 == iResult) {
        iResult = TestAddressMessage();
    }
    else {
        /* Preserve first failure. */
    }
    if (0 == iResult) {
        iResult = TestRouteMessage();
    }
    else {
        /* Preserve first failure. */
    }
    if (0 == iResult) {
        iResult = TestMalformedRouteAttribute();
    }
    else {
        /* Preserve first failure. */
    }
    return iResult;
}
