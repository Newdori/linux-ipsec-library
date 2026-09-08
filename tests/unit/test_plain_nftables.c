#include "plain_internal.h"

#include <arpa/inet.h>
#include <linux/netfilter/nf_tables.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netlink.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); exit(1); \
} } while (0)

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
    const uint16_t usNetworkQueue = htons(32002U);

    InitializeTestRule(&State, &Peer);
    CHECK(IPSEC_OK == BuildIpsecPlainRuleRequest(
        &State, &Peer, aucBuffer, sizeof(aucBuffer), &zLength));
    pHeader = (const struct nlmsghdr *)aucBuffer;
    CHECK(zLength == pHeader->nlmsg_len);
    CHECK(((NFNL_SUBSYS_NFTABLES << 8U) | NFT_MSG_NEWRULE) ==
          pHeader->nlmsg_type);
    CHECK(0U != (pHeader->nlmsg_flags & NLM_F_CREATE));
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
