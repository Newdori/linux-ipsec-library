#include "application_protected_filter.h"

#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include <linux/pkt_sched.h>
#include <linux/tc_act/tc_gact.h>
#include <linux/tc_act/tc_mirred.h>
#include <string.h>

static uint32_t ReadProtectedApplicationAddress(uint32_t uiAddress)
{
    const uint8_t *pucBytes = (const uint8_t *)&uiAddress;
    return ((uint32_t)pucBytes[0] << 24U) | ((uint32_t)pucBytes[1] << 16U) |
           ((uint32_t)pucBytes[2] << 8U) | pucBytes[3];
}

uint16_t BuildIpsecProtectedApplicationProgram(const IpsecProtectedApplicationState_t *pState,
    bool bUdpDrop, struct sock_filter *pProgram)
{
    /* Original classic-BPF selectors, using the skb network-header offset
     * instead of assuming Ethernet's header length. No GPL plugin or libbpf.
     * One program redirects RAW ESP. The other drops non-IKE UDP in scope:
     * UDP/500 is reserved for IKE and zero non-ESP markers are preserved.
     * Nonzero ESP markers are dropped even on a NAT-remapped port. UDP fragments
     * in the selected outer pair are dropped because ports may be absent.
     */
    const uint32_t uiNet = (uint32_t)SKF_NET_OFF;
    struct sock_filter aRaw[] = {
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, uiNet),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40U, 0, 7),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, uiNet + 12U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ReadProtectedApplicationAddress(pState->uiLocalAddress), 0, 5),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, uiNet + 16U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ReadProtectedApplicationAddress(pState->uiRemoteAddress), 0, 3),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, uiNet + 9U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 50U, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET | BPF_K, 0U)
    };
    struct sock_filter aUdp[] = {
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, uiNet),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xf0U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40U, 0, 19),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, uiNet + 12U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ReadProtectedApplicationAddress(pState->uiLocalAddress), 0, 17),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, uiNet + 16U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ReadProtectedApplicationAddress(pState->uiRemoteAddress), 0, 15),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, uiNet + 9U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 17U, 0, 13),
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, uiNet + 6U),
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x3fffU, 10, 0),
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, uiNet),
        BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0x0fU),
        BPF_STMT(BPF_ALU | BPF_LSH | BPF_K, 2U),
        BPF_STMT(BPF_MISC | BPF_TAX, 0U),
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, uiNet + 2U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 500U, 5, 0),
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, uiNet + 4U),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 12U, 0, 2),
        BPF_STMT(BPF_LD | BPF_W | BPF_IND, uiNet + 8U),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0U, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, UINT32_MAX),
        BPF_STMT(BPF_RET | BPF_K, 0U)
    };
    size_t zSize = bUdpDrop ? sizeof(aUdp) : sizeof(aRaw);
    memcpy(pProgram, bUdpDrop ? aUdp : aRaw, zSize);
    return (uint16_t)(zSize / sizeof(*pProgram));
}

static IpsecError_t AppendProtectedApplicationAttribute(struct nlmsghdr *pHeader, uint16_t usType,
    const void *pvData, size_t zLength, size_t *pzOffset)
{
    struct rtattr Attribute;
    size_t zOffset = NLMSG_ALIGN(pHeader->nlmsg_len);
    size_t zSize = RTA_LENGTH(zLength);
    if ((zLength > UINT16_MAX - sizeof(Attribute)) ||
        (zOffset > IPSEC_PROTECTED_APPLICATION_NETLINK_CAPACITY) ||
        (RTA_ALIGN(zSize) > IPSEC_PROTECTED_APPLICATION_NETLINK_CAPACITY - zOffset)) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    Attribute.rta_type = usType;
    Attribute.rta_len = (uint16_t)zSize;
    memcpy((uint8_t *)pHeader + zOffset, &Attribute, sizeof(Attribute));
    if (zLength > 0U) {
        memcpy((uint8_t *)pHeader + zOffset + sizeof(Attribute), pvData, zLength);
    }
    pHeader->nlmsg_len = (uint32_t)(zOffset + RTA_ALIGN(zSize));
    if (NULL != pzOffset) {
        *pzOffset = zOffset;
    }
    return IPSEC_OK;
}

static void FinishProtectedApplicationNest(struct nlmsghdr *pHeader, size_t zOffset)
{
    struct rtattr *pAttribute = (struct rtattr *)((uint8_t *)pHeader + zOffset);
    pAttribute->rta_len = (uint16_t)(pHeader->nlmsg_len - zOffset);
}

static uint32_t GetProtectedApplicationFilterInfo(const IpsecProtectedApplicationState_t *pState, bool bUdpDrop)
{
    /* ETH_P_ALL in network byte order, independent of host architecture. */
    uint16_t usProtocol;
    const uint8_t aucProtocol[2] = {0U, ETH_P_ALL};
    memcpy(&usProtocol, aucProtocol, sizeof(usProtocol));
    return ((uint32_t)(pState->usPriority + (bUdpDrop ? 1U : 0U)) << 16U) | usProtocol;
}

static uint32_t GetProtectedApplicationFilterHandle(
    const IpsecProtectedApplicationState_t *pState)
{
    return (0U != pState->uiFilterHandle) ? pState->uiFilterHandle :
        pState->uiTunIndex;
}

IpsecError_t BuildIpsecProtectedApplicationFilterRequest(const IpsecProtectedApplicationState_t *pState,
    bool bUdpDrop, bool bRemove, IpsecProtectedApplicationMessage_t *pMessage)
{
    struct nlmsghdr *pHeader;
    struct tcmsg *pTc;
    struct sock_filter aProgram[IPSEC_PROTECTED_APPLICATION_FILTER_CAPACITY];
    struct tc_mirred Redirect = {0};
    struct tc_gact Drop = {0};
    uint16_t usCount = BuildIpsecProtectedApplicationProgram(pState, bUdpDrop, aProgram);
    uint32_t uiFlags = TCA_CLS_FLAGS_SKIP_HW;
    size_t zOptions = 0U;
    size_t zActions = 0U;
    size_t zAction = 0U;
    size_t zParameters = 0U;
    IpsecError_t eError;
    memset(pMessage, 0, sizeof(*pMessage));
    pHeader = (struct nlmsghdr *)pMessage->aucData;
    pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pTc));
    pHeader->nlmsg_type = bRemove ? RTM_DELTFILTER : RTM_NEWTFILTER;
    pHeader->nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    if (!bRemove) {
        pHeader->nlmsg_flags |= NLM_F_CREATE | NLM_F_EXCL;
    }
    pTc = (struct tcmsg *)NLMSG_DATA(pHeader);
    pTc->tcm_ifindex = (int32_t)pState->uiEgressIndex;
    pTc->tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    pTc->tcm_handle = GetProtectedApplicationFilterHandle(pState);
    pTc->tcm_info = GetProtectedApplicationFilterInfo(pState, bUdpDrop);
    if (bRemove) {
        return IPSEC_OK;
    }
    /* Every append is checked; failed construction never reaches Netlink. */
    eError = AppendProtectedApplicationAttribute(pHeader, TCA_KIND, "bpf", 4U, NULL);
#define APPEND_PROTECTED(Type, Data, Length, Offset) \
    do { if (IPSEC_OK == eError) { \
        eError = AppendProtectedApplicationAttribute(pHeader, Type, Data, Length, Offset); \
    } } while (0)
    APPEND_PROTECTED(TCA_OPTIONS, NULL, 0U, &zOptions);
    APPEND_PROTECTED(TCA_BPF_OPS_LEN, &usCount, sizeof(usCount), NULL);
    APPEND_PROTECTED(TCA_BPF_OPS, aProgram, usCount * sizeof(aProgram[0]), NULL);
    APPEND_PROTECTED(TCA_BPF_FLAGS_GEN, &uiFlags, sizeof(uiFlags), NULL);
    APPEND_PROTECTED(TCA_BPF_ACT, NULL, 0U, &zActions);
    APPEND_PROTECTED(1U, NULL, 0U, &zAction);
    APPEND_PROTECTED(TCA_ACT_KIND, bUdpDrop ? "gact" : "mirred", bUdpDrop ? 5U : 7U, NULL);
    APPEND_PROTECTED(TCA_ACT_OPTIONS, NULL, 0U, &zParameters);
    if (bUdpDrop) {
        Drop.action = TC_ACT_SHOT;
        APPEND_PROTECTED(TCA_GACT_PARMS, &Drop, sizeof(Drop), NULL);
    }
    else {
        Redirect.action = TC_ACT_STOLEN;
        Redirect.eaction = TCA_EGRESS_REDIR;
        Redirect.ifindex = pState->uiTunIndex;
        APPEND_PROTECTED(TCA_MIRRED_PARMS, &Redirect, sizeof(Redirect), NULL);
    }
#undef APPEND_PROTECTED
    if (IPSEC_OK == eError) {
        FinishProtectedApplicationNest(pHeader, zParameters);
        FinishProtectedApplicationNest(pHeader, zAction);
        FinishProtectedApplicationNest(pHeader, zActions);
        FinishProtectedApplicationNest(pHeader, zOptions);
    }
    return eError;
}

IpsecError_t FindIpsecProtectedApplicationAttribute(const uint8_t *pucData, size_t zLength,
    uint16_t usType, const uint8_t **ppucValue, size_t *pzLength)
{
    *ppucValue = NULL;
    *pzLength = 0U;
    while (zLength > 0U) {
        struct rtattr Attribute;
        size_t zStep;
        if (zLength < sizeof(Attribute)) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        memcpy(&Attribute, pucData, sizeof(Attribute));
        zStep = RTA_ALIGN(Attribute.rta_len);
        if ((Attribute.rta_len < sizeof(Attribute)) || (zStep > zLength)) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        if ((Attribute.rta_type & NLA_TYPE_MASK) == usType) {
            if (NULL != *ppucValue) {
                return IPSEC_ERR_NETLINK_PARSE;
            }
            *ppucValue = pucData + sizeof(Attribute);
            *pzLength = Attribute.rta_len - sizeof(Attribute);
        }
        pucData += zStep;
        zLength -= zStep;
    }
    return IPSEC_OK;
}

static IpsecError_t RequireProtectedApplicationAttribute(const uint8_t *pucData, size_t zLength,
    uint16_t usType, const uint8_t **ppucValue, size_t *pzLength)
{
    IpsecError_t eError = FindIpsecProtectedApplicationAttribute(pucData, zLength, usType, ppucValue, pzLength);
    if ((IPSEC_OK == eError) && (NULL == *ppucValue)) {
        eError = IPSEC_ERR_RESOURCE_CONFLICT;
    }
    return eError;
}

IpsecError_t InspectIpsecProtectedApplicationFilterMessage(const IpsecProtectedApplicationState_t *pState,
    const struct nlmsghdr *pHeader, bool bRequireEmpty, uint32_t *puiFilterMask)
{
    struct tcmsg Tc;
    const uint8_t *pucAttributes;
    const uint8_t *pucValue;
    size_t zAttributes;
    size_t zValue;
    uint32_t uiChain = 0U;
    uint32_t uiBit;
    bool bUdp;
    IpsecError_t eError;
    if ((RTM_NEWTFILTER != pHeader->nlmsg_type) ||
        (pHeader->nlmsg_len < NLMSG_LENGTH(sizeof(Tc)))) {
        return IPSEC_ERR_NETLINK_PARSE;
    }
    memcpy(&Tc, NLMSG_DATA(pHeader), sizeof(Tc));
    if ((Tc.tcm_ifindex != (int32_t)pState->uiEgressIndex) ||
        (TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS) != Tc.tcm_parent)) {
        return IPSEC_OK;
    }
    if ((0U != Tc.tcm_handle) &&
        (Tc.tcm_handle != GetProtectedApplicationFilterHandle(pState))) {
        return IPSEC_OK;
    }
    pucAttributes = (const uint8_t *)NLMSG_DATA(pHeader) + NLMSG_ALIGN(sizeof(Tc));
    zAttributes = pHeader->nlmsg_len - NLMSG_LENGTH(sizeof(Tc));
    eError = RequireProtectedApplicationAttribute(pucAttributes, zAttributes, TCA_KIND, &pucValue, &zValue);
    if ((IPSEC_OK != eError) || (4U != zValue) || (0 != memcmp(pucValue, "bpf", 4U))) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    eError = FindIpsecProtectedApplicationAttribute(pucAttributes, zAttributes, TCA_CHAIN, &pucValue, &zValue);
    if (IPSEC_OK != eError) {
        return eError;
    }
    if (NULL != pucValue) {
        if (sizeof(uiChain) != zValue) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        memcpy(&uiChain, pucValue, sizeof(uiChain));
    }
    if (0U != uiChain) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    if (0U == Tc.tcm_handle) {
        /* A dump includes a classifier header before its filter entries.
         * Validate its identity but never count it as an installed filter.
         */
        eError = FindIpsecProtectedApplicationAttribute(pucAttributes, zAttributes, TCA_OPTIONS, &pucValue, &zValue);
        return ((IPSEC_OK == eError) && (NULL == pucValue)) ?
            IPSEC_OK : IPSEC_ERR_RESOURCE_CONFLICT;
    }
    if (bRequireEmpty) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    bUdp = (Tc.tcm_info >> 16U) == (uint32_t)pState->usPriority + 1U;
    if (Tc.tcm_info != GetProtectedApplicationFilterInfo(pState, bUdp)) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    uiBit = bUdp ? 2U : 1U;
    if (0U != (*puiFilterMask & uiBit)) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    eError = ValidateIpsecProtectedApplicationFilter(pState, pHeader, bUdp);
    if (IPSEC_OK == eError) {
        *puiFilterMask |= uiBit;
    }
    return eError;
}

static IpsecError_t ValidateProtectedApplicationProgramFlags(const uint8_t *pucOptions,
    size_t zOptions, uint16_t usExpectedCount)
{
    const uint8_t *pucValue;
    size_t zValue;
    uint32_t uiFlags = 0U;
    uint16_t usCount;
    IpsecError_t eError = RequireProtectedApplicationAttribute(pucOptions, zOptions,
        TCA_BPF_OPS_LEN, &pucValue, &zValue);
    if ((IPSEC_OK != eError) || (sizeof(usCount) != zValue)) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    memcpy(&usCount, pucValue, sizeof(usCount));
    if (usCount != usExpectedCount) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    eError = FindIpsecProtectedApplicationAttribute(pucOptions, zOptions, TCA_BPF_FLAGS, &pucValue, &zValue);
    if (IPSEC_OK != eError) {
        return eError;
    }
    if (NULL != pucValue) {
        if (sizeof(uiFlags) != zValue) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        memcpy(&uiFlags, pucValue, sizeof(uiFlags));
    }
    if (0U != uiFlags) {
        return IPSEC_ERR_RESOURCE_CONFLICT; /* This BPF flag would bypass our action list. */
    }
    eError = RequireProtectedApplicationAttribute(pucOptions, zOptions, TCA_BPF_FLAGS_GEN, &pucValue, &zValue);
    if ((IPSEC_OK != eError) || (sizeof(uiFlags) != zValue)) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    memcpy(&uiFlags, pucValue, sizeof(uiFlags));
    return ((0U != (uiFlags & TCA_CLS_FLAGS_SKIP_HW)) &&
            (0U == (uiFlags & (TCA_CLS_FLAGS_SKIP_SW | TCA_CLS_FLAGS_IN_HW)))) ?
        IPSEC_OK : IPSEC_ERR_RESOURCE_CONFLICT;
}

IpsecError_t ValidateIpsecProtectedApplicationFilter(const IpsecProtectedApplicationState_t *pState,
    const struct nlmsghdr *pHeader, bool bUdpDrop)
{
    struct tcmsg Tc;
    struct sock_filter aProgram[IPSEC_PROTECTED_APPLICATION_FILTER_CAPACITY];
    uint16_t usCount = BuildIpsecProtectedApplicationProgram(pState, bUdpDrop, aProgram);
    const uint8_t *pucData;
    const uint8_t *pucValue;
    const uint8_t *pucOptions;
    size_t zLength;
    size_t zValue;
    size_t zOptions;
    IpsecError_t eError;
    if (pHeader->nlmsg_len < NLMSG_LENGTH(sizeof(Tc))) {
        return IPSEC_ERR_NETLINK_PARSE;
    }
    memcpy(&Tc, NLMSG_DATA(pHeader), sizeof(Tc));
    if (((uint32_t)Tc.tcm_ifindex != pState->uiEgressIndex) ||
        (Tc.tcm_handle != GetProtectedApplicationFilterHandle(pState)) ||
        (TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS) != Tc.tcm_parent) ||
        (Tc.tcm_info != GetProtectedApplicationFilterInfo(pState, bUdpDrop))) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    pucData = (const uint8_t *)NLMSG_DATA(pHeader) + NLMSG_ALIGN(sizeof(Tc));
    zLength = pHeader->nlmsg_len - NLMSG_LENGTH(sizeof(Tc));
    eError = RequireProtectedApplicationAttribute(pucData, zLength, TCA_KIND, &pucValue, &zValue);
    if ((IPSEC_OK != eError) || (4U != zValue) || (0 != memcmp(pucValue, "bpf", 4U))) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    eError = RequireProtectedApplicationAttribute(pucData, zLength, TCA_OPTIONS, &pucOptions, &zOptions);
    if (IPSEC_OK != eError) {
        return eError;
    }
    eError = ValidateProtectedApplicationProgramFlags(pucOptions, zOptions, usCount);
    if (IPSEC_OK != eError) {
        return eError;
    }
    eError = RequireProtectedApplicationAttribute(pucOptions, zOptions, TCA_BPF_OPS, &pucValue, &zValue);
    if ((IPSEC_OK != eError) || (zValue != usCount * sizeof(aProgram[0])) ||
        (0 != memcmp(pucValue, aProgram, zValue))) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    eError = RequireProtectedApplicationAttribute(pucOptions, zOptions, TCA_BPF_ACT, &pucData, &zLength);
    if (IPSEC_OK == eError) {
        eError = RequireProtectedApplicationAttribute(pucData, zLength, 1U, &pucValue, &zValue);
        if ((IPSEC_OK == eError) && (RTA_ALIGN(RTA_LENGTH(zValue)) != zLength)) {
            eError = IPSEC_ERR_RESOURCE_CONFLICT;
        }
    }
    if (IPSEC_OK == eError) {
        eError = RequireProtectedApplicationAttribute(pucValue, zValue, TCA_ACT_KIND, &pucData, &zLength);
        if ((IPSEC_OK == eError) && ((zLength != (bUdpDrop ? 5U : 7U)) ||
            (0 != memcmp(pucData, bUdpDrop ? "gact" : "mirred", zLength)))) {
            eError = IPSEC_ERR_RESOURCE_CONFLICT;
        }
    }
    if (IPSEC_OK == eError) {
        eError = RequireProtectedApplicationAttribute(pucValue, zValue, TCA_ACT_OPTIONS, &pucData, &zLength);
    }
    if (IPSEC_OK == eError) {
        eError = RequireProtectedApplicationAttribute(pucData, zLength,
            bUdpDrop ? TCA_GACT_PARMS : TCA_MIRRED_PARMS, &pucValue, &zValue);
    }
    if (IPSEC_OK == eError) {
        if (bUdpDrop && (sizeof(struct tc_gact) == zValue)) {
            struct tc_gact Drop;
            memcpy(&Drop, pucValue, sizeof(Drop));
            eError = (TC_ACT_SHOT == Drop.action) ? IPSEC_OK : IPSEC_ERR_RESOURCE_CONFLICT;
        }
        else if (!bUdpDrop && (sizeof(struct tc_mirred) == zValue)) {
            struct tc_mirred Redirect;
            memcpy(&Redirect, pucValue, sizeof(Redirect));
            eError = ((TC_ACT_STOLEN == Redirect.action) &&
                (TCA_EGRESS_REDIR == Redirect.eaction) &&
                (pState->uiTunIndex == Redirect.ifindex)) ? IPSEC_OK : IPSEC_ERR_RESOURCE_CONFLICT;
        }
        else {
            eError = IPSEC_ERR_RESOURCE_CONFLICT;
        }
    }
    return eError;
}
