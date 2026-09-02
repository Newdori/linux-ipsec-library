#include "plain_internal.h"

#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4U
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(Length) (((Length) + NLA_ALIGNTO - 1U) & ~(NLA_ALIGNTO - 1U))
#endif

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); exit(1); \
} } while (0)

typedef union TestPlainQueueMessage {
    struct nlmsghdr Alignment;
    uint8_t aucData[512];
} TestPlainQueueMessage_t;

static void AppendTestAttribute(struct nlmsghdr *pHeader, uint16_t usType,
    const void *pvData, size_t zLength)
{
    struct nlattr Attribute = {0};
    size_t zOffset = NLMSG_ALIGN(pHeader->nlmsg_len);
    size_t zAttributeLength = sizeof(Attribute) + zLength;
    Attribute.nla_type = usType;
    Attribute.nla_len = (uint16_t)zAttributeLength;
    memcpy((uint8_t *)pHeader + zOffset, &Attribute, sizeof(Attribute));
    memcpy((uint8_t *)pHeader + zOffset + sizeof(Attribute), pvData, zLength);
    pHeader->nlmsg_len = (uint32_t)(zOffset + NLA_ALIGN(zAttributeLength));
}

static struct nlmsghdr *BuildTestPlainMessage(TestPlainQueueMessage_t *pMessage,
    uint8_t ucFamily, uint32_t uiPacketId, uint32_t uiInputIndex,
    const uint8_t *pucPayload, size_t zPayloadLength)
{
    struct nlmsghdr *pHeader;
    struct nfgenmsg *pGeneral;
    struct nfqnl_msg_packet_hdr PacketHeader = {0};
    uint32_t uiNetworkInputIndex = htonl(uiInputIndex);
    uint32_t uiCapturedLength = htonl((uint32_t)zPayloadLength);
    memset(pMessage, 0, sizeof(*pMessage));
    pHeader = (struct nlmsghdr *)pMessage->aucData;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pGeneral));
    pHeader->nlmsg_type =
        (uint16_t)((NFNL_SUBSYS_QUEUE << 8U) | NFQNL_MSG_PACKET);
    pGeneral = (struct nfgenmsg *)NLMSG_DATA(pHeader);
    pGeneral->nfgen_family = ucFamily;
    pGeneral->version = NFNETLINK_V0;
    PacketHeader.packet_id = htonl(uiPacketId);
    AppendTestAttribute(pHeader, NFQA_PACKET_HDR,
        &PacketHeader, sizeof(PacketHeader));
    AppendTestAttribute(pHeader, NFQA_IFINDEX_INDEV,
        &uiNetworkInputIndex, sizeof(uiNetworkInputIndex));
    AppendTestAttribute(pHeader, NFQA_CAP_LEN,
        &uiCapturedLength, sizeof(uiCapturedLength));
    AppendTestAttribute(pHeader, NFQA_PAYLOAD, pucPayload, zPayloadLength);
    return pHeader;
}

static void VerifyValidAndBufferCases(void)
{
    TestPlainQueueMessage_t Message;
    uint8_t aucPayload[20] = {0x45U, 0U, 0U, 20U};
    uint8_t aucOutput[20] = {0};
    IpsecPlainPacket_t Packet = {.uiStructSize = sizeof(Packet),
        .pucData = aucOutput, .zCapacity = sizeof(aucOutput)};
    struct nlmsghdr *pHeader = BuildTestPlainMessage(
        &Message, AF_INET, 0U, 19U, aucPayload, sizeof(aucPayload));
    uint32_t uiPacketId = UINT32_MAX;
    bool bPacketId = false;
    CHECK(IPSEC_OK == ParseIpsecPlainQueueMessage(pHeader,
        pHeader->nlmsg_len, 19U, &Packet, &uiPacketId, &bPacketId));
    CHECK(bPacketId && (0U == uiPacketId));
    CHECK((sizeof(aucPayload) == Packet.zLength) &&
        (0 == memcmp(aucPayload, aucOutput, sizeof(aucPayload))));
    CHECK((IPSEC_ADDRESS_FAMILY_IPV4 == Packet.eFamily) &&
        (IPSEC_PACKET_DIRECTION_INBOUND == Packet.eDirection));
    Packet.zCapacity = sizeof(aucOutput) - 1U;
    CHECK(IPSEC_ERR_BUFFER_TOO_SMALL == ParseIpsecPlainQueueMessage(pHeader,
        pHeader->nlmsg_len, 19U, &Packet, &uiPacketId, &bPacketId));
    Packet.zCapacity = sizeof(aucOutput);
    CHECK(IPSEC_ERR_PACKET_INVALID == ParseIpsecPlainQueueMessage(pHeader,
        pHeader->nlmsg_len, 20U, &Packet, &uiPacketId, &bPacketId));
}

static void VerifyAddressFamilyAndMalformedCases(void)
{
    TestPlainQueueMessage_t Message;
    uint8_t aucIpv4[20] = {0x45U, 0U, 0U, 20U};
    uint8_t aucIpv6[20] = {0x60U};
    uint8_t aucOutput[20] = {0};
    IpsecPlainPacket_t Packet = {.uiStructSize = sizeof(Packet),
        .pucData = aucOutput, .zCapacity = sizeof(aucOutput)};
    struct nlmsghdr *pHeader;
    uint32_t uiPacketId;
    bool bPacketId;
    pHeader = BuildTestPlainMessage(
        &Message, AF_INET6, 7U, 19U, aucIpv4, sizeof(aucIpv4));
    CHECK(IPSEC_ERR_ADDRESS_FAMILY == ParseIpsecPlainQueueMessage(pHeader,
        pHeader->nlmsg_len, 0U, &Packet, &uiPacketId, &bPacketId));
    pHeader = BuildTestPlainMessage(
        &Message, AF_INET, 7U, 19U, aucIpv6, sizeof(aucIpv6));
    CHECK(IPSEC_ERR_ADDRESS_FAMILY == ParseIpsecPlainQueueMessage(pHeader,
        pHeader->nlmsg_len, 0U, &Packet, &uiPacketId, &bPacketId));
    pHeader = BuildTestPlainMessage(
        &Message, AF_INET, 7U, 19U, aucIpv4, sizeof(aucIpv4));
    pHeader->nlmsg_len--;
    CHECK(IPSEC_ERR_NETLINK_PARSE == ParseIpsecPlainQueueMessage(pHeader,
        pHeader->nlmsg_len, 0U, &Packet, &uiPacketId, &bPacketId));
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == ParseIpsecPlainQueueMessage(pHeader,
        pHeader->nlmsg_len, 0U, &Packet, NULL, &bPacketId));
}

int main(void)
{
    VerifyValidAndBufferCases();
    VerifyAddressFamilyAndMalformedCases();
    (void)puts("PASS: post-decrypt NFQUEUE packet validation and IPv4 copy");
    return 0;
}
