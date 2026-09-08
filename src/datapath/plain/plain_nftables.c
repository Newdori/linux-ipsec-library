#include "plain_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <unistd.h>

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4U
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(Length) (((Length) + NLA_ALIGNTO - 1U) & ~(NLA_ALIGNTO - 1U))
#endif

#define IPSEC_PLAIN_NFT_MESSAGE_CAPACITY 4096U

typedef union IpsecPlainNftMessage {
    struct nlmsghdr Alignment;
    uint8_t aucData[IPSEC_PLAIN_NFT_MESSAGE_CAPACITY];
} IpsecPlainNftMessage_t;

static IpsecError_t MapPlainRuleError(int32_t iSystemError,
    IpsecError_t eDefault)
{
    if ((EPERM == iSystemError) || (EACCES == iSystemError)) {
        return IPSEC_ERR_PERMISSION;
    }
    if ((EEXIST == iSystemError) || (EBUSY == iSystemError)) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    if ((ENOPROTOOPT == iSystemError) || (EPROTONOSUPPORT == iSystemError) ||
        (EAFNOSUPPORT == iSystemError) || (EOPNOTSUPP == iSystemError)) {
        return IPSEC_ERR_NOT_SUPPORTED;
    }
    return eDefault;
}

static struct nlmsghdr *InitializePlainNftMessage(
    IpsecPlainNftMessage_t *pMessage, uint16_t usOperation,
    uint16_t usFlags, uint32_t uiSequence)
{
    struct nlmsghdr *pHeader;
    struct nfgenmsg *pGeneral;

    (void)memset(pMessage, 0, sizeof(*pMessage));
    pHeader = (struct nlmsghdr *)pMessage->aucData;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pGeneral));
    pHeader->nlmsg_type =
        (uint16_t)((NFNL_SUBSYS_NFTABLES << 8U) | usOperation);
    pHeader->nlmsg_flags = usFlags;
    pHeader->nlmsg_seq = uiSequence;
    pGeneral = (struct nfgenmsg *)NLMSG_DATA(pHeader);
    pGeneral->nfgen_family = NFPROTO_IPV4;
    pGeneral->version = NFNETLINK_V0;
    pGeneral->res_id = 0U;
    return pHeader;
}

static IpsecError_t AppendPlainNftAttribute(struct nlmsghdr *pHeader,
    size_t zCapacity, uint16_t usType, const void *pvData, size_t zLength,
    size_t *pzOffset)
{
    struct nlattr Attribute = {0};
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
    (void)memcpy((uint8_t *)pHeader + zOffset, &Attribute,
                 sizeof(Attribute));
    if ((0U < zLength) && (NULL != pvData)) {
        (void)memcpy((uint8_t *)pHeader + zOffset + sizeof(Attribute),
                     pvData, zLength);
    }
    if (NLA_ALIGN(zAttributeLength) > zAttributeLength) {
        (void)memset((uint8_t *)pHeader + zOffset + zAttributeLength, 0,
            NLA_ALIGN(zAttributeLength) - zAttributeLength);
    }
    pHeader->nlmsg_len =
        (uint32_t)(zOffset + NLA_ALIGN(zAttributeLength));
    if (NULL != pzOffset) {
        *pzOffset = zOffset;
    }
    return IPSEC_OK;
}

static void FinishPlainNftNest(struct nlmsghdr *pHeader, size_t zOffset)
{
    struct nlattr *pAttribute =
        (struct nlattr *)((uint8_t *)pHeader + zOffset);

    pAttribute->nla_len = (uint16_t)(pHeader->nlmsg_len - zOffset);
}

static IpsecError_t AppendPlainNftUint32(struct nlmsghdr *pHeader,
    size_t zCapacity, uint16_t usType, uint32_t uiValue)
{
    uint32_t uiNetworkValue = htonl(uiValue);

    return AppendPlainNftAttribute(pHeader, zCapacity, usType,
        &uiNetworkValue, sizeof(uiNetworkValue), NULL);
}

static IpsecError_t BeginPlainNftExpression(struct nlmsghdr *pHeader,
    size_t zCapacity, const char *pcName, size_t *pzElement,
    size_t *pzData)
{
    IpsecError_t eError;

    eError = AppendPlainNftAttribute(pHeader, zCapacity,
        (uint16_t)(NFTA_LIST_ELEM | NLA_F_NESTED), NULL, 0U, pzElement);
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAttribute(pHeader, zCapacity, NFTA_EXPR_NAME,
            pcName, strlen(pcName) + 1U, NULL);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAttribute(pHeader, zCapacity,
            (uint16_t)(NFTA_EXPR_DATA | NLA_F_NESTED), NULL, 0U, pzData);
    }
    return eError;
}

static void FinishPlainNftExpression(struct nlmsghdr *pHeader,
    size_t zElement, size_t zData)
{
    FinishPlainNftNest(pHeader, zData);
    FinishPlainNftNest(pHeader, zElement);
}

static IpsecError_t AppendPlainNftData(struct nlmsghdr *pHeader,
    size_t zCapacity, uint16_t usType, const void *pvData, size_t zLength)
{
    size_t zData;
    IpsecError_t eError = AppendPlainNftAttribute(pHeader, zCapacity,
        (uint16_t)(usType | NLA_F_NESTED), NULL, 0U, &zData);

    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAttribute(pHeader, zCapacity, NFTA_DATA_VALUE,
            pvData, zLength, NULL);
    }
    if (IPSEC_OK == eError) {
        FinishPlainNftNest(pHeader, zData);
    }
    return eError;
}

static IpsecError_t AppendPlainNftMetaInterface(struct nlmsghdr *pHeader,
    size_t zCapacity, uint32_t uiInterfaceIndex)
{
    /* NFT_META_IIF is stored in the nftables register as a native-endian
     * uint32_t. Unlike IPv4 payload fields, the comparison value must not be
     * converted to network byte order. */
    uint32_t uiNativeIndex = uiInterfaceIndex;
    size_t zElement;
    size_t zData;
    IpsecError_t eError = BeginPlainNftExpression(pHeader, zCapacity,
        "meta", &zElement, &zData);

    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_META_KEY, NFT_META_IIF);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_META_DREG, NFT_REG_1);
    }
    if (IPSEC_OK == eError) {
        FinishPlainNftExpression(pHeader, zElement, zData);
        eError = BeginPlainNftExpression(pHeader, zCapacity,
            "cmp", &zElement, &zData);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_CMP_SREG, NFT_REG_1);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_CMP_OP, NFT_CMP_EQ);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftData(pHeader, zCapacity, NFTA_CMP_DATA,
            &uiNativeIndex, sizeof(uiNativeIndex));
    }
    if (IPSEC_OK == eError) {
        FinishPlainNftExpression(pHeader, zElement, zData);
    }
    return eError;
}

static IpsecError_t AppendPlainNftBitwise(struct nlmsghdr *pHeader,
    size_t zCapacity, uint32_t uiMask)
{
    const uint32_t uiZero = 0U;
    size_t zElement;
    size_t zData;
    IpsecError_t eError = BeginPlainNftExpression(pHeader, zCapacity,
        "bitwise", &zElement, &zData);

    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_BITWISE_SREG, NFT_REG_1);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_BITWISE_DREG, NFT_REG_1);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_BITWISE_LEN, sizeof(uiMask));
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftData(pHeader, zCapacity, NFTA_BITWISE_MASK,
            &uiMask, sizeof(uiMask));
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftData(pHeader, zCapacity, NFTA_BITWISE_XOR,
            &uiZero, sizeof(uiZero));
    }
    if (IPSEC_OK == eError) {
        FinishPlainNftExpression(pHeader, zElement, zData);
    }
    return eError;
}

static IpsecError_t AppendPlainNftAddress(struct nlmsghdr *pHeader,
    size_t zCapacity, uint32_t uiOffset, uint32_t uiNetwork,
    uint32_t uiMask)
{
    size_t zElement;
    size_t zData;
    IpsecError_t eError = BeginPlainNftExpression(pHeader, zCapacity,
        "payload", &zElement, &zData);

    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_PAYLOAD_BASE, NFT_PAYLOAD_NETWORK_HEADER);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_PAYLOAD_OFFSET, uiOffset);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_PAYLOAD_LEN, sizeof(uiNetwork));
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_PAYLOAD_DREG, NFT_REG_1);
    }
    if (IPSEC_OK == eError) {
        FinishPlainNftExpression(pHeader, zElement, zData);
        if (UINT32_MAX != ntohl(uiMask)) {
            eError = AppendPlainNftBitwise(pHeader, zCapacity, uiMask);
        }
    }
    if (IPSEC_OK == eError) {
        eError = BeginPlainNftExpression(pHeader, zCapacity,
            "cmp", &zElement, &zData);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_CMP_SREG, NFT_REG_1);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, zCapacity,
            NFTA_CMP_OP, NFT_CMP_EQ);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftData(pHeader, zCapacity, NFTA_CMP_DATA,
            &uiNetwork, sizeof(uiNetwork));
    }
    if (IPSEC_OK == eError) {
        FinishPlainNftExpression(pHeader, zElement, zData);
    }
    return eError;
}

static IpsecError_t AppendPlainNftQueue(struct nlmsghdr *pHeader,
    size_t zCapacity, uint16_t usQueueNumber)
{
    uint16_t usNetworkQueue = htons(usQueueNumber);
    size_t zElement;
    size_t zData;
    IpsecError_t eError = BeginPlainNftExpression(pHeader, zCapacity,
        "queue", &zElement, &zData);

    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAttribute(pHeader, zCapacity, NFTA_QUEUE_NUM,
            &usNetworkQueue, sizeof(usNetworkQueue), NULL);
    }
    if (IPSEC_OK == eError) {
        FinishPlainNftExpression(pHeader, zElement, zData);
    }
    return eError;
}

IpsecError_t BuildIpsecPlainRuleRequest(
    const IpsecPlainApplicationState_t *pState,
    const IpsecPlainApplicationPeer_t *pPeer,
    uint8_t *pucBuffer, size_t zCapacity, size_t *pzLength)
{
    IpsecPlainNftMessage_t Message;
    struct nlmsghdr *pHeader;
    size_t zExpressions;
    IpsecError_t eError;

    if ((NULL == pState) || (NULL == pPeer) || (NULL == pucBuffer) ||
        (NULL == pzLength) || (zCapacity < sizeof(struct nlmsghdr))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    *pzLength = 0U;
    pHeader = InitializePlainNftMessage(&Message, NFT_MSG_NEWRULE,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_APPEND,
        0U);
    eError = AppendPlainNftAttribute(pHeader, sizeof(Message),
        NFTA_RULE_TABLE, pState->acRuleTableName,
        strlen(pState->acRuleTableName) + 1U, NULL);
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAttribute(pHeader, sizeof(Message),
            NFTA_RULE_CHAIN, pState->acRuleChainName,
            strlen(pState->acRuleChainName) + 1U, NULL);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAttribute(pHeader, sizeof(Message),
            (uint16_t)(NFTA_RULE_EXPRESSIONS | NLA_F_NESTED),
            NULL, 0U, &zExpressions);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftMetaInterface(pHeader, sizeof(Message),
            pState->uiExpectedInterfaceIndex);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAddress(pHeader, sizeof(Message), 12U,
            pPeer->uiRemoteNetwork, pPeer->uiRemoteMask);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAddress(pHeader, sizeof(Message), 16U,
            pPeer->uiLocalNetwork, pPeer->uiLocalMask);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftQueue(pHeader, sizeof(Message),
            pState->usQueueNumber);
    }
    if (IPSEC_OK == eError) {
        FinishPlainNftNest(pHeader, zExpressions);
        if (pHeader->nlmsg_len > zCapacity) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            (void)memcpy(pucBuffer, pHeader, pHeader->nlmsg_len);
            *pzLength = pHeader->nlmsg_len;
        }
    }
    return eError;
}

static void InitializePlainNftBatch(IpsecPlainNftMessage_t *pMessage,
    uint16_t usType, uint32_t uiSequence)
{
    struct nlmsghdr *pHeader;
    struct nfgenmsg *pGeneral;

    (void)memset(pMessage, 0, sizeof(*pMessage));
    pHeader = (struct nlmsghdr *)pMessage->aucData;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pGeneral));
    pHeader->nlmsg_type = usType;
    pHeader->nlmsg_flags = NLM_F_REQUEST;
    pHeader->nlmsg_seq = uiSequence;
    pGeneral = (struct nfgenmsg *)NLMSG_DATA(pHeader);
    pGeneral->nfgen_family = NFPROTO_UNSPEC;
    pGeneral->version = NFNETLINK_V0;
    pGeneral->res_id = htons(NFNL_SUBSYS_NFTABLES);
}

static IpsecError_t ReceivePlainNftAck(IpsecPlainApplicationState_t *pState,
    uint32_t uiSequence, bool bIgnoreMissing)
{
    uint8_t aucBuffer[1024];

    for (;;) {
        ssize_t lLength;
        struct nlmsghdr *pHeader;
        uint32_t uiRemaining;

        do {
            lLength = recv(pState->iRuleSocket, aucBuffer,
                sizeof(aucBuffer), 0);
        } while ((lLength < 0) && (EINTR == errno));
        if (lLength < 0) {
            return MapPlainRuleError(errno, IPSEC_ERR_NETLINK_RECV);
        }
        uiRemaining = (uint32_t)lLength;
        for (pHeader = (struct nlmsghdr *)aucBuffer;
             NLMSG_OK(pHeader, uiRemaining);
             pHeader = NLMSG_NEXT(pHeader, uiRemaining)) {
            if ((uiSequence == pHeader->nlmsg_seq) &&
                (NLMSG_ERROR == pHeader->nlmsg_type) &&
                (pHeader->nlmsg_len >=
                 NLMSG_LENGTH(sizeof(struct nlmsgerr)))) {
                struct nlmsgerr Error;
                int32_t iSystemError;

                (void)memcpy(&Error, NLMSG_DATA(pHeader), sizeof(Error));
                iSystemError = -Error.error;
                if ((0 == Error.error) ||
                    (bIgnoreMissing && (ENOENT == iSystemError))) {
                    return IPSEC_OK;
                }
                return MapPlainRuleError(iSystemError,
                    IPSEC_ERR_PLAIN_PATH_UNAVAILABLE);
            }
        }
    }
}

static IpsecError_t SendPlainNftOperation(
    IpsecPlainApplicationState_t *pState, struct nlmsghdr *pOperation,
    bool bIgnoreMissing)
{
    IpsecPlainNftMessage_t Begin;
    IpsecPlainNftMessage_t End;
    struct nlmsghdr *pBegin;
    struct nlmsghdr *pEnd;
    struct iovec aVectors[3];
    struct msghdr Message = {0};
    struct sockaddr_nl Address = {0};
    uint32_t uiOperationSequence;
    ssize_t lLength;
    size_t zExpected;

    InitializePlainNftBatch(&Begin, NFNL_MSG_BATCH_BEGIN,
        ++pState->uiRuleSequence);
    pBegin = (struct nlmsghdr *)Begin.aucData;
    uiOperationSequence = ++pState->uiRuleSequence;
    pOperation->nlmsg_seq = uiOperationSequence;
    InitializePlainNftBatch(&End, NFNL_MSG_BATCH_END,
        ++pState->uiRuleSequence);
    pEnd = (struct nlmsghdr *)End.aucData;
    aVectors[0].iov_base = pBegin;
    aVectors[0].iov_len = pBegin->nlmsg_len;
    aVectors[1].iov_base = pOperation;
    aVectors[1].iov_len = pOperation->nlmsg_len;
    aVectors[2].iov_base = pEnd;
    aVectors[2].iov_len = pEnd->nlmsg_len;
    Address.nl_family = AF_NETLINK;
    Message.msg_name = &Address;
    Message.msg_namelen = sizeof(Address);
    Message.msg_iov = aVectors;
    Message.msg_iovlen = sizeof(aVectors) / sizeof(aVectors[0]);
    zExpected = pBegin->nlmsg_len + pOperation->nlmsg_len + pEnd->nlmsg_len;
    do {
        lLength = sendmsg(pState->iRuleSocket, &Message, 0);
    } while ((lLength < 0) && (EINTR == errno));
    if ((lLength < 0) || ((size_t)lLength != zExpected)) {
        return MapPlainRuleError(errno, IPSEC_ERR_NETLINK_SEND);
    }
    return ReceivePlainNftAck(pState, uiOperationSequence, bIgnoreMissing);
}

static IpsecError_t BuildPlainNftTableRequest(
    const IpsecPlainApplicationState_t *pState, bool bRemove,
    IpsecPlainNftMessage_t *pMessage)
{
    struct nlmsghdr *pHeader = InitializePlainNftMessage(pMessage,
        bRemove ? NFT_MSG_DELTABLE : NFT_MSG_NEWTABLE,
        bRemove ? (NLM_F_REQUEST | NLM_F_ACK) :
            (NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL),
        0U);

    return AppendPlainNftAttribute(pHeader, sizeof(*pMessage),
        NFTA_TABLE_NAME, pState->acRuleTableName,
        strlen(pState->acRuleTableName) + 1U, NULL);
}

static IpsecError_t BuildPlainNftChainRequest(
    const IpsecContext_t *pContext,
    const IpsecPlainApplicationState_t *pState,
    IpsecPlainNftMessage_t *pMessage)
{
    struct nlmsghdr *pHeader = InitializePlainNftMessage(pMessage,
        NFT_MSG_NEWCHAIN,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL, 0U);
    uint32_t uiHook =
        (IPSEC_PLAIN_NETFILTER_FORWARD ==
         pContext->DatapathConfig.ePlainNetfilterHook) ?
        NF_INET_FORWARD : NF_INET_LOCAL_IN;
    size_t zHook;
    IpsecError_t eError;

    eError = AppendPlainNftAttribute(pHeader, sizeof(*pMessage),
        NFTA_CHAIN_TABLE, pState->acRuleTableName,
        strlen(pState->acRuleTableName) + 1U, NULL);
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAttribute(pHeader, sizeof(*pMessage),
            NFTA_CHAIN_NAME, pState->acRuleChainName,
            strlen(pState->acRuleChainName) + 1U, NULL);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAttribute(pHeader, sizeof(*pMessage),
            NFTA_CHAIN_TYPE, "filter", sizeof("filter"), NULL);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftAttribute(pHeader, sizeof(*pMessage),
            (uint16_t)(NFTA_CHAIN_HOOK | NLA_F_NESTED),
            NULL, 0U, &zHook);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, sizeof(*pMessage),
            NFTA_HOOK_HOOKNUM, uiHook);
    }
    if (IPSEC_OK == eError) {
        eError = AppendPlainNftUint32(pHeader, sizeof(*pMessage),
            NFTA_HOOK_PRIORITY, 0U);
    }
    if (IPSEC_OK == eError) {
        FinishPlainNftNest(pHeader, zHook);
    }
    return eError;
}

static IpsecError_t RemovePlainNftTable(
    IpsecPlainApplicationState_t *pState, bool bIgnoreMissing)
{
    IpsecPlainNftMessage_t Message;
    IpsecError_t eError = BuildPlainNftTableRequest(pState, true, &Message);

    if (IPSEC_OK == eError) {
        eError = SendPlainNftOperation(pState,
            (struct nlmsghdr *)Message.aucData, bIgnoreMissing);
    }
    if (IPSEC_OK == eError) {
        pState->bRuleTableOwned = false;
    }
    return eError;
}

static IpsecError_t CreatePlainNftTable(
    const IpsecContext_t *pContext, IpsecPlainApplicationState_t *pState)
{
    IpsecPlainNftMessage_t Message;
    IpsecError_t eError = BuildPlainNftTableRequest(pState, false, &Message);

    if (IPSEC_OK == eError) {
        eError = SendPlainNftOperation(pState,
            (struct nlmsghdr *)Message.aucData, false);
    }
    if (IPSEC_OK == eError) {
        pState->bRuleTableOwned = true;
        eError = BuildPlainNftChainRequest(pContext, pState, &Message);
    }
    if (IPSEC_OK == eError) {
        eError = SendPlainNftOperation(pState,
            (struct nlmsghdr *)Message.aucData, false);
    }
    return eError;
}

static IpsecError_t AddPlainNftPeerRule(
    IpsecPlainApplicationState_t *pState,
    const IpsecPlainApplicationPeer_t *pPeer)
{
    IpsecPlainNftMessage_t Message;
    size_t zLength = 0U;
    IpsecError_t eError = BuildIpsecPlainRuleRequest(pState, pPeer,
        Message.aucData, sizeof(Message), &zLength);

    if ((IPSEC_OK == eError) &&
        (zLength != ((struct nlmsghdr *)Message.aucData)->nlmsg_len)) {
        eError = IPSEC_ERR_INTERNAL;
    }
    if (IPSEC_OK == eError) {
        eError = SendPlainNftOperation(pState,
            (struct nlmsghdr *)Message.aucData, false);
    }
    return eError;
}

static IpsecError_t RebuildPlainNftRules(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState)
{
    uint32_t uiIndex;
    IpsecError_t eError = RemovePlainNftTable(pState, true);

    if (IPSEC_OK == eError) {
        eError = CreatePlainNftTable(pContext, pState);
    }
    for (uiIndex = 0U;
         (IPSEC_OK == eError) &&
         (uiIndex < IPSEC_PLAIN_APPLICATION_PEER_CAPACITY);
         uiIndex++) {
        if (pState->aPeers[uiIndex].bInUse) {
            eError = AddPlainNftPeerRule(pState, &pState->aPeers[uiIndex]);
        }
    }
    return eError;
}

static IpsecError_t ParsePlainNftSelector(const char *pcSelector,
    uint32_t *puiNetwork, uint32_t *puiMask)
{
    char acAddress[INET_ADDRSTRLEN];
    const char *pcSlash;
    char *pcEnd = NULL;
    size_t zLength;
    uint64_t ullPrefix = 32U;
    struct in_addr Address;
    uint32_t uiHostMask;

    if ((NULL == pcSelector) || (NULL == puiNetwork) || (NULL == puiMask)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pcSlash = strchr(pcSelector, '/');
    zLength = (NULL == pcSlash) ? strlen(pcSelector) :
        (size_t)(pcSlash - pcSelector);
    if ((0U == zLength) || (zLength >= sizeof(acAddress))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    (void)memcpy(acAddress, pcSelector, zLength);
    acAddress[zLength] = '\0';
    if (NULL != pcSlash) {
        errno = 0;
        ullPrefix = strtoull(pcSlash + 1, &pcEnd, 10);
        if ((0 != errno) || (pcEnd == pcSlash + 1) ||
            ('\0' != *pcEnd) || (32U < ullPrefix)) {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
    }
    if (1 != inet_pton(AF_INET, acAddress, &Address)) {
        return IPSEC_ERR_ADDRESS_FAMILY;
    }
    uiHostMask = (0U == ullPrefix) ? 0U :
        UINT32_MAX << (32U - (uint32_t)ullPrefix);
    *puiMask = htonl(uiHostMask);
    *puiNetwork = Address.s_addr & *puiMask;
    return IPSEC_OK;
}

static IpsecError_t ParsePlainNftPeer(const IpsecConnectionConfig_t *pConfig,
    IpsecPlainApplicationPeer_t *pPeer)
{
    IpsecError_t eError;

    if ((NULL == pConfig) || (NULL == pConfig->pcName) ||
        (1U != pConfig->LocalTrafficSelectors.uiCount) ||
        (1U != pConfig->RemoteTrafficSelectors.uiCount) ||
        (NULL == pConfig->LocalTrafficSelectors.ppcItems) ||
        (NULL == pConfig->RemoteTrafficSelectors.ppcItems) ||
        (NULL == pConfig->LocalTrafficSelectors.ppcItems[0]) ||
        (NULL == pConfig->RemoteTrafficSelectors.ppcItems[0])) {
        return IPSEC_ERR_NOT_SUPPORTED;
    }
    (void)memset(pPeer, 0, sizeof(*pPeer));
    if (strlen(pConfig->pcName) >= sizeof(pPeer->acConnectionName)) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    (void)memcpy(pPeer->acConnectionName, pConfig->pcName,
        strlen(pConfig->pcName) + 1U);
    eError = ParsePlainNftSelector(
        pConfig->LocalTrafficSelectors.ppcItems[0],
        &pPeer->uiLocalNetwork, &pPeer->uiLocalMask);
    if (IPSEC_OK == eError) {
        eError = ParsePlainNftSelector(
            pConfig->RemoteTrafficSelectors.ppcItems[0],
            &pPeer->uiRemoteNetwork, &pPeer->uiRemoteMask);
    }
    return eError;
}

IpsecError_t InitializeIpsecPlainRules(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState)
{
    struct sockaddr_nl Address = {0};
    struct timeval Timeout = {0};
    int32_t iLength;
    IpsecError_t eError = IPSEC_OK;

    if (!pContext->DatapathConfig.bManagePlainNetfilterRule) {
        return IPSEC_OK;
    }
    pState->bManageRule = true;
    pState->iRuleSocket = (int32_t)socket(AF_NETLINK,
        SOCK_RAW | SOCK_CLOEXEC, NETLINK_NETFILTER);
    if (pState->iRuleSocket < 0) {
        return MapPlainRuleError(errno, IPSEC_ERR_NETLINK_SOCKET);
    }
    Address.nl_family = AF_NETLINK;
    if (0 != bind(pState->iRuleSocket,
                  (const struct sockaddr *)&Address, sizeof(Address))) {
        eError = MapPlainRuleError(errno, IPSEC_ERR_PLAIN_PATH_UNAVAILABLE);
    }
    Timeout.tv_sec = (time_t)(pContext->uiCommandTimeoutMs / 1000U);
    Timeout.tv_usec = (suseconds_t)
        ((pContext->uiCommandTimeoutMs % 1000U) * 1000U);
    if ((IPSEC_OK == eError) &&
        ((0 != setsockopt(pState->iRuleSocket, SOL_SOCKET, SO_RCVTIMEO,
                          &Timeout, sizeof(Timeout))) ||
         (0 != setsockopt(pState->iRuleSocket, SOL_SOCKET, SO_SNDTIMEO,
                          &Timeout, sizeof(Timeout))))) {
        eError = MapPlainRuleError(errno, IPSEC_ERR_PLAIN_PATH_UNAVAILABLE);
    }
    iLength = snprintf(pState->acRuleTableName,
        sizeof(pState->acRuleTableName), "ipsecctrl_%u",
        (uint32_t)pState->usQueueNumber);
    if ((IPSEC_OK == eError) &&
        ((iLength < 0) || ((size_t)iLength >=
                           sizeof(pState->acRuleTableName)))) {
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    iLength = snprintf(pState->acRuleChainName,
        sizeof(pState->acRuleChainName), "plain_%s",
        (IPSEC_PLAIN_NETFILTER_FORWARD ==
         pContext->DatapathConfig.ePlainNetfilterHook) ? "forward" : "input");
    if ((IPSEC_OK == eError) &&
        ((iLength < 0) || ((size_t)iLength >=
                           sizeof(pState->acRuleChainName)))) {
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    if (IPSEC_OK == eError) {
        eError = RemovePlainNftTable(pState, true);
    }
    if (IPSEC_OK == eError) {
        eError = CreatePlainNftTable(pContext, pState);
    }
    if (IPSEC_OK == eError) {
        LogIpsec(pContext, IPSEC_LOG_INFO,
            "plain APPLICATION owns nftables %s/%s for NFQUEUE %u",
            pState->acRuleTableName, pState->acRuleChainName,
            (uint32_t)pState->usQueueNumber);
    }
    return eError;
}

void DeinitializeIpsecPlainRules(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState)
{
    if (pState->bManageRule && (pState->iRuleSocket >= 0) &&
        pState->bRuleTableOwned) {
        IpsecError_t eError = RemovePlainNftTable(pState, true);

        if (IPSEC_OK != eError) {
            LogIpsec(pContext, IPSEC_LOG_WARNING,
                "plain APPLICATION nftables cleanup failed: %s",
                GetIpsecErrorString(eError));
        }
    }
    if (pState->iRuleSocket >= 0) {
        (void)close(pState->iRuleSocket);
        pState->iRuleSocket = -1;
    }
    if (pState->bPeerMutexInitialized) {
        (void)pthread_mutex_destroy(&pState->PeerMutex);
        pState->bPeerMutexInitialized = false;
    }
    pState->bManageRule = false;
    pState->bRuleTableOwned = false;
}

IpsecError_t RegisterIpsecPlainPeerInternal(IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig, bool *pbAdded)
{
    IpsecPlainApplicationState_t *pState;
    IpsecPlainApplicationPeer_t Peer;
    uint32_t uiIndex;
    uint32_t uiFreeIndex = UINT32_MAX;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pbAdded)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    *pbAdded = false;
    if ((IPSEC_PACKET_PATH_APPLICATION !=
         pContext->DatapathConfig.ePlainPacketPath) ||
        !pContext->DatapathConfig.bManagePlainNetfilterRule) {
        return IPSEC_OK;
    }
    pState = pContext->pPlainApplicationState;
    if ((NULL == pState) || !pState->bPeerMutexInitialized ||
        !pState->bRuleTableOwned) {
        return IPSEC_ERR_PLAIN_PATH_UNAVAILABLE;
    }
    eError = ParsePlainNftPeer(pConfig, &Peer);
    if (IPSEC_OK != eError) {
        return eError;
    }
    if (0 != pthread_mutex_lock(&pState->PeerMutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    for (uiIndex = 0U;
         uiIndex < IPSEC_PLAIN_APPLICATION_PEER_CAPACITY;
         uiIndex++) {
        IpsecPlainApplicationPeer_t *pExisting = &pState->aPeers[uiIndex];

        if (!pExisting->bInUse && (UINT32_MAX == uiFreeIndex)) {
            uiFreeIndex = uiIndex;
        }
        else if (pExisting->bInUse &&
                 (0 == strcmp(pExisting->acConnectionName,
                              Peer.acConnectionName))) {
            eError = ((pExisting->uiLocalNetwork == Peer.uiLocalNetwork) &&
                      (pExisting->uiRemoteNetwork == Peer.uiRemoteNetwork) &&
                      (pExisting->uiLocalMask == Peer.uiLocalMask) &&
                      (pExisting->uiRemoteMask == Peer.uiRemoteMask)) ?
                IPSEC_OK : IPSEC_ERR_RESOURCE_CONFLICT;
            break;
        }
    }
    if ((IPSEC_ERR_BUFFER_TOO_SMALL == eError) &&
        (UINT32_MAX != uiFreeIndex)) {
        eError = AddPlainNftPeerRule(pState, &Peer);
        if (IPSEC_OK == eError) {
            pState->aPeers[uiFreeIndex] = Peer;
            pState->aPeers[uiFreeIndex].bInUse = true;
            pState->uiPeerCount++;
            *pbAdded = true;
        }
    }
    (void)pthread_mutex_unlock(&pState->PeerMutex);
    return eError;
}

IpsecError_t UnregisterIpsecPlainPeerInternal(IpsecContext_t *pContext,
    const char *pcConnectionName)
{
    IpsecPlainApplicationState_t *pState;
    uint32_t uiIndex;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pContext) || (NULL == pcConnectionName)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if ((IPSEC_PACKET_PATH_APPLICATION !=
         pContext->DatapathConfig.ePlainPacketPath) ||
        !pContext->DatapathConfig.bManagePlainNetfilterRule) {
        return IPSEC_OK;
    }
    pState = pContext->pPlainApplicationState;
    if ((NULL == pState) || !pState->bPeerMutexInitialized) {
        return IPSEC_ERR_PLAIN_PATH_UNAVAILABLE;
    }
    if (0 != pthread_mutex_lock(&pState->PeerMutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    for (uiIndex = 0U;
         uiIndex < IPSEC_PLAIN_APPLICATION_PEER_CAPACITY;
         uiIndex++) {
        IpsecPlainApplicationPeer_t *pPeer = &pState->aPeers[uiIndex];

        if (pPeer->bInUse &&
            (0 == strcmp(pPeer->acConnectionName, pcConnectionName))) {
            (void)memset(pPeer, 0, sizeof(*pPeer));
            pState->uiPeerCount--;
            eError = RebuildPlainNftRules(pContext, pState);
            break;
        }
    }
    (void)pthread_mutex_unlock(&pState->PeerMutex);
    return eError;
}
