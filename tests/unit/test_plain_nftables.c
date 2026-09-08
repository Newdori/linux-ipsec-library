#include "plain_internal.h"

#include <arpa/inet.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef NLA_ALIGNTO
#define NLA_ALIGNTO 4U
#endif
#ifndef NLA_ALIGN
#define NLA_ALIGN(Length) (((Length) + NLA_ALIGNTO - 1U) & ~(NLA_ALIGNTO - 1U))
#endif
#ifndef NLA_TYPE_MASK
#define NLA_TYPE_MASK 0x3fffU
#endif

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); exit(1); \
} } while (0)

static const struct nlattr *FindTestAttribute(const uint8_t *pucData,
    size_t zLength, uint16_t usType)
{
    while (zLength >= sizeof(struct nlattr)) {
        const struct nlattr *pAttribute =
            (const struct nlattr *)pucData;
        size_t zStep;

        if ((pAttribute->nla_len < sizeof(*pAttribute)) ||
            (pAttribute->nla_len > zLength)) {
            return NULL;
        }
        if (usType == (pAttribute->nla_type & NLA_TYPE_MASK)) {
            return pAttribute;
        }
        zStep = NLA_ALIGN(pAttribute->nla_len);
        if (zStep > zLength) {
            return NULL;
        }
        pucData += zStep;
        zLength -= zStep;
    }
    return NULL;
}

static const struct nlattr *FindTestInterfaceCompare(
    const struct nlmsghdr *pHeader)
{
    const struct nfgenmsg *pGeneral =
        (const struct nfgenmsg *)NLMSG_DATA(pHeader);
    const uint8_t *pucRuleData =
        (const uint8_t *)pGeneral + NLMSG_ALIGN(sizeof(*pGeneral));
    size_t zRuleLength =
        pHeader->nlmsg_len - NLMSG_LENGTH(sizeof(*pGeneral));
    const struct nlattr *pExpressions = FindTestAttribute(pucRuleData,
        zRuleLength, NFTA_RULE_EXPRESSIONS);
    const uint8_t *pucElement;
    size_t zElementLength;
    bool bMetaSeen = false;

    if (NULL == pExpressions) {
        return NULL;
    }
    pucElement = (const uint8_t *)pExpressions + sizeof(*pExpressions);
    zElementLength = pExpressions->nla_len - sizeof(*pExpressions);
    while (zElementLength >= sizeof(struct nlattr)) {
        const struct nlattr *pElement =
            (const struct nlattr *)pucElement;
        const uint8_t *pucExpression;
        size_t zExpressionLength;
        const struct nlattr *pName;
        const struct nlattr *pData;
        size_t zStep;

        if ((pElement->nla_len < sizeof(*pElement)) ||
            (pElement->nla_len > zElementLength)) {
            return NULL;
        }
        pucExpression = pucElement + sizeof(*pElement);
        zExpressionLength = pElement->nla_len - sizeof(*pElement);
        pName = FindTestAttribute(pucExpression, zExpressionLength,
            NFTA_EXPR_NAME);
        pData = FindTestAttribute(pucExpression, zExpressionLength,
            NFTA_EXPR_DATA);
        if ((NULL != pName) && (NULL != pData)) {
            const char *pcName =
                (const char *)pName + sizeof(*pName);

            if (0 == strcmp("meta", pcName)) {
                bMetaSeen = true;
            }
            else if (bMetaSeen && (0 == strcmp("cmp", pcName))) {
                const uint8_t *pucCompare =
                    (const uint8_t *)pData + sizeof(*pData);
                size_t zCompareLength = pData->nla_len - sizeof(*pData);
                const struct nlattr *pCompareData = FindTestAttribute(
                    pucCompare, zCompareLength, NFTA_CMP_DATA);

                if (NULL != pCompareData) {
                    return FindTestAttribute(
                        (const uint8_t *)pCompareData +
                            sizeof(*pCompareData),
                        pCompareData->nla_len - sizeof(*pCompareData),
                        NFTA_DATA_VALUE);
                }
                return NULL;
            }
            else {
                bMetaSeen = false;
            }
        }
        zStep = NLA_ALIGN(pElement->nla_len);
        if (zStep > zElementLength) {
            return NULL;
        }
        pucElement += zStep;
        zElementLength -= zStep;
    }
    return NULL;
}

static bool ContainsTestBytes(const uint8_t *pucData, size_t zLength,
    const void *pvExpected, size_t zExpectedLength)
{
    size_t zIndex;

    if ((0U == zExpectedLength) || (zExpectedLength > zLength)) {
        return false;
    }
    for (zIndex = 0U; zIndex <= zLength - zExpectedLength; zIndex++) {
        if (0 == memcmp(pucData + zIndex, pvExpected, zExpectedLength)) {
            return true;
        }
    }
    return false;
}

static void InitializeTestRule(IpsecPlainApplicationState_t *pState,
    IpsecPlainApplicationPeer_t *pPeer)
{
    struct in_addr Address;

    (void)memset(pState, 0, sizeof(*pState));
    (void)memset(pPeer, 0, sizeof(*pPeer));
    (void)memcpy(pState->acRuleTableName, "ipsecctrl_32002",
                 sizeof("ipsecctrl_32002"));
    (void)memcpy(pState->acRuleChainName, "plain_input",
                 sizeof("plain_input"));
    pState->uiExpectedInterfaceIndex = 10U;
    pState->usQueueNumber = 32002U;
    CHECK(1 == inet_pton(AF_INET, "172.16.20.1", &Address));
    pPeer->uiLocalNetwork = Address.s_addr;
    pPeer->uiLocalMask = htonl(UINT32_MAX);
    CHECK(1 == inet_pton(AF_INET, "172.16.10.0", &Address));
    pPeer->uiRemoteNetwork = Address.s_addr;
    pPeer->uiRemoteMask = htonl(0xffffff00U);
}

int main(void)
{
    IpsecPlainApplicationState_t State;
    IpsecPlainApplicationPeer_t Peer;
    uint8_t aucBuffer[4096];
    size_t zLength = 0U;
    const struct nlmsghdr *pHeader;
    const struct nlattr *pInterfaceCompare;
    const uint16_t usNetworkQueue = htons(32002U);
    uint32_t uiInterfaceCompare = 0U;

    InitializeTestRule(&State, &Peer);
    CHECK(IPSEC_OK == BuildIpsecPlainRuleRequest(
        &State, &Peer, aucBuffer, sizeof(aucBuffer), &zLength));
    pHeader = (const struct nlmsghdr *)aucBuffer;
    CHECK(zLength == pHeader->nlmsg_len);
    CHECK(((NFNL_SUBSYS_NFTABLES << 8U) | NFT_MSG_NEWRULE) ==
          pHeader->nlmsg_type);
    CHECK(0U != (pHeader->nlmsg_flags & NLM_F_CREATE));
    pInterfaceCompare = FindTestInterfaceCompare(pHeader);
    CHECK(NULL != pInterfaceCompare);
    CHECK(sizeof(*pInterfaceCompare) + sizeof(uiInterfaceCompare) ==
          pInterfaceCompare->nla_len);
    (void)memcpy(&uiInterfaceCompare,
        (const uint8_t *)pInterfaceCompare + sizeof(*pInterfaceCompare),
        sizeof(uiInterfaceCompare));
    CHECK(State.uiExpectedInterfaceIndex == uiInterfaceCompare);
    CHECK(ContainsTestBytes(aucBuffer, zLength,
        "ipsecctrl_32002", sizeof("ipsecctrl_32002")));
    CHECK(ContainsTestBytes(aucBuffer, zLength,
        "plain_input", sizeof("plain_input")));
    CHECK(ContainsTestBytes(aucBuffer, zLength,
        "bitwise", sizeof("bitwise")));
    CHECK(ContainsTestBytes(aucBuffer, zLength,
        &usNetworkQueue, sizeof(usNetworkQueue)));
    CHECK(IPSEC_ERR_BUFFER_TOO_SMALL == BuildIpsecPlainRuleRequest(
        &State, &Peer, aucBuffer, 32U, &zLength));
    CHECK(0U == zLength);
    (void)puts("PASS: library-owned nftables NFQUEUE rule encoding");
    return 0;
}
