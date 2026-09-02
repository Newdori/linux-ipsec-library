#include "plain_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4U
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(Length) (((Length) + NLA_ALIGNTO - 1U) & ~(NLA_ALIGNTO - 1U))
#endif
#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK 0x3fffU
#endif

#define IPSEC_PLAIN_CONTROL_CAPACITY 256U

typedef union IpsecPlainControlMessage {
    struct nlmsghdr Alignment;
    uint8_t aucData[IPSEC_PLAIN_CONTROL_CAPACITY];
} IpsecPlainControlMessage_t;

static IpsecError_t MapPlainQueueError(int32_t iSystemError,
    IpsecError_t eDefault)
{
    if ((EPERM == iSystemError) || (EACCES == iSystemError)) {
        return IPSEC_ERR_PERMISSION;
    }
    if ((EBUSY == iSystemError) || (EEXIST == iSystemError)) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    if ((ENOPROTOOPT == iSystemError) || (EPROTONOSUPPORT == iSystemError) ||
        (EAFNOSUPPORT == iSystemError)) {
        return IPSEC_ERR_NOT_SUPPORTED;
    }
    return eDefault;
}

static IpsecError_t AppendPlainQueueAttribute(struct nlmsghdr *pHeader,
    size_t zCapacity, uint16_t usType, const void *pvData, size_t zLength)
{
    struct nlattr Attribute;
    size_t zOffset = NLMSG_ALIGN(pHeader->nlmsg_len);
    size_t zAttributeLength;
    if ((zLength > UINT16_MAX - sizeof(Attribute)) ||
        (zOffset > zCapacity)) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    zAttributeLength = sizeof(Attribute) + zLength;
    if (NLA_ALIGN(zAttributeLength) > zCapacity - zOffset) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    Attribute.nla_type = usType;
    Attribute.nla_len = (uint16_t)zAttributeLength;
    memcpy((uint8_t *)pHeader + zOffset, &Attribute, sizeof(Attribute));
    if (zLength > 0U) {
        memcpy((uint8_t *)pHeader + zOffset + sizeof(Attribute), pvData, zLength);
    }
    if (NLA_ALIGN(zAttributeLength) > zAttributeLength) {
        memset((uint8_t *)pHeader + zOffset + zAttributeLength, 0,
               NLA_ALIGN(zAttributeLength) - zAttributeLength);
    }
    pHeader->nlmsg_len = (uint32_t)(zOffset + NLA_ALIGN(zAttributeLength));
    return IPSEC_OK;
}

static struct nlmsghdr *InitializePlainQueueControl(
    IpsecPlainControlMessage_t *pMessage, uint8_t ucOperation,
    uint16_t usQueueNumber, uint32_t uiSequence, uint16_t usFlags)
{
    struct nlmsghdr *pHeader;
    struct nfgenmsg *pGeneral;
    memset(pMessage, 0, sizeof(*pMessage));
    pHeader = (struct nlmsghdr *)pMessage->aucData;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pGeneral));
    pHeader->nlmsg_type = (uint16_t)((NFNL_SUBSYS_QUEUE << 8U) | ucOperation);
    pHeader->nlmsg_flags = usFlags;
    pHeader->nlmsg_seq = uiSequence;
    pGeneral = (struct nfgenmsg *)NLMSG_DATA(pHeader);
    pGeneral->nfgen_family = AF_INET;
    pGeneral->version = NFNETLINK_V0;
    pGeneral->res_id = htons(usQueueNumber);
    return pHeader;
}

static IpsecError_t ReceivePlainQueueAck(int32_t iSocket, uint32_t uiSequence)
{
    uint8_t aucBuffer[512];
    ssize_t lLength;
    struct nlmsghdr *pHeader;
    uint32_t uiRemaining;
    do {
        lLength = recv(iSocket, aucBuffer, sizeof(aucBuffer), 0);
    } while ((lLength < 0) && (EINTR == errno));
    if (lLength < 0) {
        return MapPlainQueueError(errno, IPSEC_ERR_PLAIN_PATH_UNAVAILABLE);
    }
    uiRemaining = (uint32_t)lLength;
    for (pHeader = (struct nlmsghdr *)aucBuffer;
         NLMSG_OK(pHeader, uiRemaining);
         pHeader = NLMSG_NEXT(pHeader, uiRemaining)) {
        if ((uiSequence == pHeader->nlmsg_seq) &&
            (NLMSG_ERROR == pHeader->nlmsg_type) &&
            (pHeader->nlmsg_len >= NLMSG_LENGTH(sizeof(struct nlmsgerr)))) {
            struct nlmsgerr Error;
            memcpy(&Error, NLMSG_DATA(pHeader), sizeof(Error));
            return (0 == Error.error) ? IPSEC_OK :
                MapPlainQueueError(-Error.error, IPSEC_ERR_PLAIN_PATH_UNAVAILABLE);
        }
    }
    return IPSEC_ERR_NETLINK_PARSE;
}

static IpsecError_t SendPlainQueueControl(IpsecPlainApplicationState_t *pState,
    struct nlmsghdr *pHeader)
{
    struct sockaddr_nl Address = {0};
    ssize_t lLength;
    Address.nl_family = AF_NETLINK;
    do {
        lLength = sendto(pState->iQueueSocket, pHeader, pHeader->nlmsg_len, 0,
            (const struct sockaddr *)&Address, sizeof(Address));
    } while ((lLength < 0) && (EINTR == errno));
    if ((lLength < 0) || ((size_t)lLength != pHeader->nlmsg_len)) {
        return MapPlainQueueError(errno, IPSEC_ERR_NETLINK_SEND);
    }
    return ReceivePlainQueueAck(pState->iQueueSocket, pHeader->nlmsg_seq);
}

static IpsecError_t BindPlainQueue(IpsecPlainApplicationState_t *pState)
{
    IpsecPlainControlMessage_t Message;
    struct nfqnl_msg_config_cmd Command = {0};
    struct nfqnl_msg_config_params Parameters = {0};
    struct nlmsghdr *pHeader;
    IpsecError_t eError;
    Command.command = NFQNL_CFG_CMD_BIND;
    Command.pf = htons(AF_INET);
    pHeader = InitializePlainQueueControl(&Message, NFQNL_MSG_CONFIG,
        pState->usQueueNumber, ++pState->uiSequence, NLM_F_REQUEST | NLM_F_ACK);
    eError = AppendPlainQueueAttribute(pHeader, sizeof(Message),
        NFQA_CFG_CMD, &Command, sizeof(Command));
    if (IPSEC_OK == eError) {
        eError = SendPlainQueueControl(pState, pHeader);
    }
    if (IPSEC_OK == eError) {
        pState->bQueueBound = true;
        Parameters.copy_range = htonl(IPSEC_PROTECTED_PACKET_CAPACITY);
        Parameters.copy_mode = NFQNL_COPY_PACKET;
        pHeader = InitializePlainQueueControl(&Message, NFQNL_MSG_CONFIG,
            pState->usQueueNumber, ++pState->uiSequence,
            NLM_F_REQUEST | NLM_F_ACK);
        eError = AppendPlainQueueAttribute(pHeader, sizeof(Message),
            NFQA_CFG_PARAMS, &Parameters, sizeof(Parameters));
    }
    if (IPSEC_OK == eError) {
        eError = SendPlainQueueControl(pState, pHeader);
    }
    return eError;
}

IpsecError_t OpenIpsecPlainQueue(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState)
{
    struct sockaddr_nl Address = {0};
    struct timeval Timeout = {0};
    int32_t iFlags;
    int32_t iReceiveSize = (int32_t)(4U * IPSEC_PLAIN_NETLINK_CAPACITY);
    IpsecError_t eError = IPSEC_OK;
    pState->zReceiveCapacity = IPSEC_PLAIN_NETLINK_CAPACITY;
    pState->pucReceiveBuffer = (uint8_t *)malloc(pState->zReceiveCapacity);
    if (NULL == pState->pucReceiveBuffer) {
        return IPSEC_ERR_NO_MEMORY;
    }
    pState->iQueueSocket = (int32_t)socket(AF_NETLINK,
        SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (pState->iQueueSocket < 0) {
        eError = MapPlainQueueError(errno, IPSEC_ERR_PLAIN_PATH_UNAVAILABLE);
    }
    Address.nl_family = AF_NETLINK;
    Timeout.tv_sec = (time_t)(pContext->uiCommandTimeoutMs / 1000U);
    Timeout.tv_usec = (suseconds_t)
        ((pContext->uiCommandTimeoutMs % 1000U) * 1000U);
    if ((IPSEC_OK == eError) &&
        (0 != bind(pState->iQueueSocket, (const struct sockaddr *)&Address,
                   sizeof(Address)))) {
        eError = MapPlainQueueError(errno, IPSEC_ERR_PLAIN_PATH_UNAVAILABLE);
    }
    if ((IPSEC_OK == eError) &&
        ((0 != setsockopt(pState->iQueueSocket, SOL_SOCKET, SO_RCVTIMEO,
                          &Timeout, sizeof(Timeout))) ||
         (0 != setsockopt(pState->iQueueSocket, SOL_SOCKET, SO_SNDTIMEO,
                          &Timeout, sizeof(Timeout))))) {
        eError = MapPlainQueueError(errno, IPSEC_ERR_PLAIN_PATH_UNAVAILABLE);
    }
    if (IPSEC_OK == eError) {
        (void)setsockopt(pState->iQueueSocket, SOL_SOCKET, SO_RCVBUF,
                         &iReceiveSize, sizeof(iReceiveSize));
        eError = BindPlainQueue(pState);
    }
    if (IPSEC_OK == eError) {
        iFlags = fcntl(pState->iQueueSocket, F_GETFL, 0);
        if ((iFlags < 0) ||
            (0 != fcntl(pState->iQueueSocket, F_SETFL, iFlags | O_NONBLOCK))) {
            eError = MapPlainQueueError(errno, IPSEC_ERR_PLAIN_PATH_UNAVAILABLE);
        }
    }
    if (IPSEC_OK == eError) {
        LogIpsec(pContext, IPSEC_LOG_INFO,
            "plain APPLICATION path bound NFQUEUE %u; OS rule owns post-decrypt selection",
            (uint32_t)pState->usQueueNumber);
    }
    return eError;
}

void CloseIpsecPlainQueue(IpsecPlainApplicationState_t *pState)
{
    if (pState->iQueueSocket >= 0) {
        (void)close(pState->iQueueSocket);
        pState->iQueueSocket = -1;
    }
    free(pState->pucReceiveBuffer);
    pState->pucReceiveBuffer = NULL;
    pState->zReceiveCapacity = 0U;
    pState->bQueueBound = false;
}

static IpsecError_t ValidatePlainIpv4Packet(IpsecPlainPacket_t *pPacket,
    const uint8_t *pucPayload, size_t zPayloadLength)
{
    size_t zHeaderLength;
    size_t zTotalLength;
    if ((zPayloadLength < 20U) || (4U != (pucPayload[0] >> 4U))) {
        return (zPayloadLength > 0U) && (6U == (pucPayload[0] >> 4U)) ?
            IPSEC_ERR_ADDRESS_FAMILY : IPSEC_ERR_PACKET_INVALID;
    }
    zHeaderLength = (size_t)(pucPayload[0] & 0x0fU) * 4U;
    zTotalLength = ((size_t)pucPayload[2] << 8U) | pucPayload[3];
    if ((zHeaderLength < 20U) || (zHeaderLength > zPayloadLength) ||
        (zTotalLength != zPayloadLength)) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    if (pPacket->zCapacity < zPayloadLength) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(pPacket->pucData, pucPayload, zPayloadLength);
    pPacket->zLength = zPayloadLength;
    pPacket->eFamily = IPSEC_ADDRESS_FAMILY_IPV4;
    pPacket->eDirection = IPSEC_PACKET_DIRECTION_INBOUND;
    return IPSEC_OK;
}

IpsecError_t ParseIpsecPlainQueueMessage(const struct nlmsghdr *pHeader,
    size_t zMessageLength, uint32_t uiExpectedInterfaceIndex,
    IpsecPlainPacket_t *pPacket, uint32_t *puiPacketId, bool *pbPacketId)
{
    const struct nfgenmsg *pGeneral;
    const uint8_t *pucAttribute;
    const uint8_t *pucPayload = NULL;
    size_t zAttributeLength;
    size_t zPayloadLength = 0U;
    uint32_t uiInputIndex = 0U;
    uint32_t uiCapturedLength = 0U;
    bool bPacketId = false;
    IpsecError_t eError = IPSEC_OK;
    if ((NULL == puiPacketId) || (NULL == pbPacketId)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    *puiPacketId = 0U;
    *pbPacketId = false;
    if ((NULL == pHeader) || (NULL == pPacket) || (NULL == pPacket->pucData) ||
        (pHeader->nlmsg_len > zMessageLength) ||
        (pHeader->nlmsg_len < NLMSG_LENGTH(sizeof(*pGeneral))) ||
        (((NFNL_SUBSYS_QUEUE << 8U) | NFQNL_MSG_PACKET) != pHeader->nlmsg_type)) {
        return IPSEC_ERR_NETLINK_PARSE;
    }
    pGeneral = (const struct nfgenmsg *)NLMSG_DATA(pHeader);
    if (AF_INET6 == pGeneral->nfgen_family) {
        return IPSEC_ERR_ADDRESS_FAMILY;
    }
    if (AF_INET != pGeneral->nfgen_family) {
        return IPSEC_ERR_NETLINK_PARSE;
    }
    pucAttribute = (const uint8_t *)pGeneral + NLMSG_ALIGN(sizeof(*pGeneral));
    zAttributeLength = pHeader->nlmsg_len - NLMSG_LENGTH(sizeof(*pGeneral));
    while ((IPSEC_OK == eError) && (zAttributeLength > 0U)) {
        struct nlattr Attribute;
        size_t zStep;
        const uint8_t *pucValue;
        size_t zValueLength;
        if (zAttributeLength < sizeof(Attribute)) {
            eError = IPSEC_ERR_NETLINK_PARSE;
            break;
        }
        memcpy(&Attribute, pucAttribute, sizeof(Attribute));
        zStep = NLA_ALIGN(Attribute.nla_len);
        if ((Attribute.nla_len < sizeof(Attribute)) || (zStep > zAttributeLength)) {
            eError = IPSEC_ERR_NETLINK_PARSE;
            break;
        }
        pucValue = pucAttribute + sizeof(Attribute);
        zValueLength = Attribute.nla_len - sizeof(Attribute);
        switch (Attribute.nla_type & NLA_TYPE_MASK) {
        case NFQA_PACKET_HDR:
            if (sizeof(struct nfqnl_msg_packet_hdr) != zValueLength || bPacketId) {
                eError = IPSEC_ERR_NETLINK_PARSE;
            }
            else {
                struct nfqnl_msg_packet_hdr PacketHeader;
                memcpy(&PacketHeader, pucValue, sizeof(PacketHeader));
                *puiPacketId = ntohl(PacketHeader.packet_id);
                bPacketId = true;
                *pbPacketId = true;
            }
            break;
        case NFQA_IFINDEX_INDEV:
            if (sizeof(uiInputIndex) != zValueLength || (0U != uiInputIndex)) {
                eError = IPSEC_ERR_NETLINK_PARSE;
            }
            else {
                memcpy(&uiInputIndex, pucValue, sizeof(uiInputIndex));
                uiInputIndex = ntohl(uiInputIndex);
            }
            break;
        case NFQA_CAP_LEN:
            if (sizeof(uiCapturedLength) != zValueLength || (0U != uiCapturedLength)) {
                eError = IPSEC_ERR_NETLINK_PARSE;
            }
            else {
                memcpy(&uiCapturedLength, pucValue, sizeof(uiCapturedLength));
                uiCapturedLength = ntohl(uiCapturedLength);
            }
            break;
        case NFQA_PAYLOAD:
            if (NULL != pucPayload) {
                eError = IPSEC_ERR_NETLINK_PARSE;
            }
            else {
                pucPayload = pucValue;
                zPayloadLength = zValueLength;
            }
            break;
        default:
            break;
        }
        pucAttribute += zStep;
        zAttributeLength -= zStep;
    }
    if ((IPSEC_OK == eError) &&
        (!bPacketId || (NULL == pucPayload) ||
         ((0U != uiCapturedLength) && (uiCapturedLength != zPayloadLength)))) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    if ((IPSEC_OK == eError) && (0U != uiExpectedInterfaceIndex) &&
        (uiExpectedInterfaceIndex != uiInputIndex)) {
        eError = IPSEC_ERR_PACKET_INVALID;
    }
    if (IPSEC_OK == eError) {
        eError = ValidatePlainIpv4Packet(pPacket, pucPayload, zPayloadLength);
    }
    return eError;
}

static IpsecError_t SendPlainQueueDropVerdict(
    IpsecPlainApplicationState_t *pState, uint32_t uiPacketId)
{
    IpsecPlainControlMessage_t Message;
    struct nfqnl_msg_verdict_hdr Verdict = {0};
    struct nlmsghdr *pHeader;
    struct sockaddr_nl Address = {0};
    ssize_t lLength;
    IpsecError_t eError;
    Verdict.verdict = htonl(NF_DROP);
    Verdict.id = htonl(uiPacketId);
    pHeader = InitializePlainQueueControl(&Message, NFQNL_MSG_VERDICT,
        pState->usQueueNumber, ++pState->uiSequence, NLM_F_REQUEST);
    eError = AppendPlainQueueAttribute(pHeader, sizeof(Message),
        NFQA_VERDICT_HDR, &Verdict, sizeof(Verdict));
    if (IPSEC_OK != eError) {
        return eError;
    }
    Address.nl_family = AF_NETLINK;
    do {
        lLength = sendto(pState->iQueueSocket, pHeader, pHeader->nlmsg_len, 0,
            (const struct sockaddr *)&Address, sizeof(Address));
    } while ((lLength < 0) && (EINTR == errno));
    return ((lLength >= 0) && ((size_t)lLength == pHeader->nlmsg_len)) ?
        IPSEC_OK : MapPlainQueueError(errno, IPSEC_ERR_PLAIN_RECEIVE);
}

static IpsecError_t WaitPlainQueuePacket(int32_t iSocket, uint32_t uiTimeoutMs)
{
    struct pollfd Descriptor = {0};
    int32_t iResult;
    Descriptor.fd = iSocket;
    Descriptor.events = POLLIN;
    do {
        iResult = (int32_t)poll(&Descriptor, 1U,
            (uiTimeoutMs > INT_MAX) ? INT_MAX : (int32_t)uiTimeoutMs);
    } while ((iResult < 0) && (EINTR == errno));
    if (0 == iResult) {
        return IPSEC_ERR_PACKET_TIMEOUT;
    }
    if ((iResult < 0) ||
        (0 != (Descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)))) {
        return IPSEC_ERR_PLAIN_RECEIVE;
    }
    return (0 != (Descriptor.revents & POLLIN)) ?
        IPSEC_OK : IPSEC_ERR_PLAIN_RECEIVE;
}

IpsecError_t ReceiveIpsecPlainQueuePacket(IpsecPlainApplicationState_t *pState,
    IpsecPlainPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    struct iovec Vector;
    struct msghdr Message = {0};
    ssize_t lLength;
    uint32_t uiPacketId = 0U;
    bool bPacketId = false;
    IpsecError_t eError = WaitPlainQueuePacket(pState->iQueueSocket, uiTimeoutMs);
    if (IPSEC_OK != eError) {
        return eError;
    }
    Vector.iov_base = pState->pucReceiveBuffer;
    Vector.iov_len = pState->zReceiveCapacity;
    Message.msg_iov = &Vector;
    Message.msg_iovlen = 1U;
    do {
        lLength = recvmsg(pState->iQueueSocket, &Message, MSG_TRUNC);
    } while ((lLength < 0) && (EINTR == errno));
    if ((lLength < 0) && ((EAGAIN == errno) || (EWOULDBLOCK == errno))) {
        return IPSEC_ERR_PACKET_TIMEOUT;
    }
    if ((lLength < 0) || ((size_t)lLength > pState->zReceiveCapacity) ||
        (0 != (Message.msg_flags & MSG_TRUNC))) {
        return IPSEC_ERR_PLAIN_RECEIVE;
    }
    eError = ParseIpsecPlainQueueMessage(
        (const struct nlmsghdr *)pState->pucReceiveBuffer, (size_t)lLength,
        pState->uiExpectedInterfaceIndex, pPacket, &uiPacketId, &bPacketId);
    if (bPacketId) {
        IpsecError_t eVerdict = SendPlainQueueDropVerdict(pState, uiPacketId);
        if ((IPSEC_OK == eError) && (IPSEC_OK != eVerdict)) {
            eError = eVerdict;
        }
    }
    if (IPSEC_OK != eError) {
        pPacket->zLength = 0U;
        pPacket->eFamily = IPSEC_ADDRESS_FAMILY_UNSPECIFIED;
    }
    return eError;
}
