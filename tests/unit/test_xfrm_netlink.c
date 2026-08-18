#include "xfrm_internal.h"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define TEST_NETLINK_BUFFER_LENGTH 2048U

typedef union TestNetlinkBuffer {
    max_align_t Alignment;
    uint8_t aucData[TEST_NETLINK_BUFFER_LENGTH];
} TestNetlinkBuffer_t;

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

static int32_t TestXfrmStateMessage(void)
{
    TestNetlinkBuffer_t Buffer;
    struct nlmsghdr *pHeader = (struct nlmsghdr *)Buffer.aucData;
    struct xfrm_usersa_info *pKernelInfo;
    struct xfrm_algo Algorithm;
    IpsecXfrmStateList_t List = {0};
    IpsecError_t eError;

    memset(&Buffer, 0, sizeof(Buffer));
    pHeader->nlmsg_type = XFRM_MSG_NEWSA;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pKernelInfo));
    pKernelInfo = (struct xfrm_usersa_info *)NLMSG_DATA(pHeader);
    pKernelInfo->family = AF_INET;
    pKernelInfo->id.proto = IPPROTO_ESP;
    pKernelInfo->id.spi = htonl(UINT32_C(0x10203040));
    pKernelInfo->reqid = 17U;
    pKernelInfo->mode = XFRM_MODE_TUNNEL;
    pKernelInfo->flags = XFRM_STATE_ESN;
    pKernelInfo->replay_window = 32U;
    pKernelInfo->curlft.packets = 123U;
    pKernelInfo->curlft.bytes = 4567U;
    if ((1 != inet_pton(AF_INET, "192.0.2.1", &pKernelInfo->saddr)) ||
        (1 != inet_pton(AF_INET, "198.51.100.2",
                        &pKernelInfo->id.daddr))) {
        return ReportFailure("test IPv4 conversion");
    }
    else {
        /* Test addresses encoded. */
    }

    memset(&Algorithm, 0, sizeof(Algorithm));
    (void)snprintf(Algorithm.alg_name, sizeof(Algorithm.alg_name), "%s",
                   "cbc(aes)");
    Algorithm.alg_key_len = 128U;
    if (!AddTestAttribute(pHeader, sizeof(Buffer.aucData), XFRMA_ALG_CRYPT,
                          &Algorithm, sizeof(Algorithm))) {
        return ReportFailure("state algorithm attribute construction");
    }
    else {
        /* Attribute added. */
    }

    eError = ParseXfrmStateMessage(pHeader, &List);
    if ((IPSEC_OK != eError) || (1U != List.uiCount) ||
        (UINT32_C(0x10203040) != List.pItems[0].uiSpi) ||
        (17U != List.pItems[0].uiReqid) ||
        (IPSEC_MODE_TUNNEL != List.pItems[0].eMode) ||
        !List.pItems[0].bEsn ||
        (0 != strcmp("192.0.2.1", List.pItems[0].acSource)) ||
        (0 != strcmp("198.51.100.2", List.pItems[0].acDestination)) ||
        (0 != strcmp("cbc(aes)",
                     List.pItems[0].acEncryptionAlgorithm))) {
        FreeIpsecXfrmStateList(&List);
        return ReportFailure("XFRM state message parse");
    }
    else {
        FreeIpsecXfrmStateList(&List);
        return 0;
    }
}

static int32_t TestXfrmPolicyMessage(void)
{
    TestNetlinkBuffer_t Buffer;
    struct nlmsghdr *pHeader = (struct nlmsghdr *)Buffer.aucData;
    struct xfrm_userpolicy_info *pKernelInfo;
    struct xfrm_user_tmpl Template;
    IpsecXfrmPolicyList_t List = {0};
    IpsecError_t eError;

    memset(&Buffer, 0, sizeof(Buffer));
    pHeader->nlmsg_type = XFRM_MSG_NEWPOLICY;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pKernelInfo));
    pKernelInfo = (struct xfrm_userpolicy_info *)NLMSG_DATA(pHeader);
    pKernelInfo->sel.family = AF_INET;
    pKernelInfo->sel.prefixlen_s = 24U;
    pKernelInfo->sel.prefixlen_d = 24U;
    pKernelInfo->dir = XFRM_POLICY_OUT;
    pKernelInfo->priority = 2200U;
    pKernelInfo->index = 8U;
    if ((1 != inet_pton(AF_INET, "10.10.1.0",
                        &pKernelInfo->sel.saddr)) ||
        (1 != inet_pton(AF_INET, "10.20.1.0",
                        &pKernelInfo->sel.daddr))) {
        return ReportFailure("policy selector construction");
    }
    else {
        /* Selectors encoded. */
    }

    memset(&Template, 0, sizeof(Template));
    Template.family = AF_INET;
    Template.id.proto = IPPROTO_ESP;
    Template.reqid = 17U;
    Template.mode = XFRM_MODE_TUNNEL;
    if ((1 != inet_pton(AF_INET, "192.0.2.1", &Template.saddr)) ||
        (1 != inet_pton(AF_INET, "198.51.100.2",
                        &Template.id.daddr)) ||
        !AddTestAttribute(pHeader, sizeof(Buffer.aucData), XFRMA_TMPL,
                          &Template, sizeof(Template))) {
        return ReportFailure("policy template construction");
    }
    else {
        /* Template encoded. */
    }

    eError = ParseXfrmPolicyMessage(pHeader, &List);
    if ((IPSEC_OK != eError) || (1U != List.uiCount) ||
        (IPSEC_XFRM_DIRECTION_OUT != List.pItems[0].eDirection) ||
        (17U != List.pItems[0].uiReqid) ||
        (IPSEC_MODE_TUNNEL != List.pItems[0].eMode) ||
        (0 != strcmp("10.10.1.0", List.pItems[0].acSourceSelector)) ||
        (0 != strcmp("192.0.2.1", List.pItems[0].acTemplateSource)) ||
        (0 != strcmp("198.51.100.2",
                     List.pItems[0].acTemplateDestination))) {
        FreeIpsecXfrmPolicyList(&List);
        return ReportFailure("XFRM policy message parse");
    }
    else {
        FreeIpsecXfrmPolicyList(&List);
        return 0;
    }
}

static int32_t TestMalformedXfrmMessage(void)
{
    struct nlmsghdr Header;
    IpsecXfrmStateList_t List = {0};

    memset(&Header, 0, sizeof(Header));
    Header.nlmsg_type = XFRM_MSG_NEWSA;
    Header.nlmsg_len = sizeof(Header);
    if (IPSEC_ERR_NETLINK_PARSE !=
        ParseXfrmStateMessage(&Header, &List)) {
        FreeIpsecXfrmStateList(&List);
        return ReportFailure("truncated XFRM message accepted");
    }
    else {
        return 0;
    }
}

int main(void)
{
    int32_t iResult;

    iResult = TestXfrmStateMessage();
    if (0 == iResult) {
        iResult = TestXfrmPolicyMessage();
    }
    else {
        /* Preserve first failure. */
    }
    if (0 == iResult) {
        iResult = TestMalformedXfrmMessage();
    }
    else {
        /* Preserve first failure. */
    }
    return iResult;
}
