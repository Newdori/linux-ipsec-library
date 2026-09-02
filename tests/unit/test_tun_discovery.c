#include "../../src/datapath/kernel_libipsec/kernel_libipsec_internal.h"

#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); exit(1); \
} } while (0)

typedef union TestTunMessage {
    max_align_t Alignment;
    uint8_t aucData[512];
} TestTunMessage_t;

static size_t AppendTestAttribute(struct nlmsghdr *pHeader, uint16_t usType,
                                   const void *pvData, size_t zLength)
{
    size_t zOffset = NLMSG_ALIGN(pHeader->nlmsg_len);
    struct rtattr *pAttribute = (struct rtattr *)((uint8_t *)pHeader + zOffset);
    CHECK(zOffset + RTA_SPACE(zLength) <= 512U);
    pAttribute->rta_type = usType;
    pAttribute->rta_len = (uint16_t)RTA_LENGTH(zLength);
    if (zLength > 0U) {
        memcpy(RTA_DATA(pAttribute), pvData, zLength);
    }
    pHeader->nlmsg_len = (uint32_t)(zOffset + RTA_SPACE(zLength));
    return zOffset;
}

static void BuildTestTun(TestTunMessage_t *pMessage, uint8_t ucType)
{
    struct nlmsghdr *pHeader = (struct nlmsghdr *)pMessage->aucData;
    struct ifinfomsg *pLink;
    size_t zInfo;
    size_t zData;
    memset(pMessage, 0, sizeof(*pMessage));
    pHeader->nlmsg_type = RTM_NEWLINK;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pLink));
    pLink = (struct ifinfomsg *)NLMSG_DATA(pHeader);
    pLink->ifi_index = 42;
    pLink->ifi_flags = IFF_UP;
    (void)AppendTestAttribute(pHeader, IFLA_IFNAME, "custom-tun", 11U);
    zInfo = AppendTestAttribute(pHeader, IFLA_LINKINFO | NLA_F_NESTED, NULL, 0U);
    (void)AppendTestAttribute(pHeader, IFLA_INFO_KIND, "tun", 4U);
    zData = AppendTestAttribute(pHeader, IFLA_INFO_DATA | NLA_F_NESTED, NULL, 0U);
    (void)AppendTestAttribute(pHeader, IFLA_TUN_TYPE, &ucType, 1U);
    ((struct rtattr *)(pMessage->aucData + zData))->rta_len = (uint16_t)(pHeader->nlmsg_len - zData);
    ((struct rtattr *)(pMessage->aucData + zInfo))->rta_len = (uint16_t)(pHeader->nlmsg_len - zInfo);
}

int main(void)
{
    TestTunMessage_t Message;
    struct nlmsghdr *pHeader = (struct nlmsghdr *)Message.aucData;
    IpsecTunCandidates_t Candidates = {0};
    IpsecDatapathStatus_t Status = {0};
    CHECK(IPSEC_ERR_INTERFACE_NOT_FOUND == SelectIpsecTun(&Candidates, "", "", &Status));
    BuildTestTun(&Message, IFF_TUN);
    CHECK(IPSEC_OK == ParseIpsecTunMessage(pHeader, &Candidates));
    CHECK(IPSEC_OK == SelectIpsecTun(&Candidates, "", "", &Status));
    CHECK(42U == Status.uiTunInterfaceIndex);
    CHECK(0 == strcmp(Status.acTunInterfaceName, "custom-tun"));
    CHECK(IPSEC_OK == SelectIpsecTun(&Candidates, "custom-tun", "", &Status));
    CHECK(IPSEC_ERR_INTERFACE_NOT_FOUND == SelectIpsecTun(&Candidates, "missing", "", &Status));
    CHECK(IPSEC_ERR_RESOURCE_CONFLICT == SelectIpsecTun(&Candidates, "custom-tun", "custom-tun", &Status));
    Candidates.aItems[0].bUp = false;
    CHECK(IPSEC_ERR_DATAPATH_UNAVAILABLE == SelectIpsecTun(&Candidates, "custom-tun", "", &Status));
    Candidates.aItems[0].bUp = true;
    Candidates.aItems[1] = Candidates.aItems[0];
    memcpy(Candidates.aItems[1].acName, "other-tun", 10U);
    Candidates.aItems[1].uiIndex = 43U;
    Candidates.uiCount = 2U;
    CHECK(IPSEC_ERR_INTERFACE_AMBIGUOUS == SelectIpsecTun(&Candidates, "", "", &Status));
    CHECK(IPSEC_OK == SelectIpsecTun(&Candidates, "custom-tun", "", &Status));
    CHECK(IPSEC_OK == SelectIpsecTun(&Candidates, "", "other-tun", &Status));
    Candidates.uiCount = 0U;
    BuildTestTun(&Message, IFF_TAP);
    CHECK(IPSEC_OK == ParseIpsecTunMessage(pHeader, &Candidates));
    CHECK(!Candidates.aItems[0].bTun);
    CHECK(IPSEC_ERR_INTERFACE_NOT_FOUND == SelectIpsecTun(&Candidates, "", "", &Status));
    BuildTestTun(&Message, IFF_TUN);
    pHeader->nlmsg_len--;
    CHECK(IPSEC_ERR_NETLINK_PARSE == ParseIpsecTunMessage(pHeader, &Candidates));
    pHeader->nlmsg_len = NLMSG_HDRLEN;
    CHECK(IPSEC_ERR_NETLINK_PARSE == ParseIpsecTunMessage(pHeader, &Candidates));
    (void)puts("PASS: explicit/automatic TUN, missing/down/TAP/multiple candidates, nested Netlink bounds");
    return 0;
}
