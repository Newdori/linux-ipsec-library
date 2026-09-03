#include "../../src/datapath/protected/application_protected_filter.h"

#include <linux/pkt_cls.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); exit(1); \
} } while (0)

/* Independent interpreter for the limited classic-BPF instructions emitted
 * by the production encoder. This is not a substitute for a kernel verifier
 * or live TC redirect test; it checks selector/control-flow semantics.
 */
static uint32_t RunTestProgram(const struct sock_filter *pProgram, uint16_t usCount,
    const uint8_t *pucPacket, size_t zLength)
{
    uint32_t uiA = 0U;
    uint32_t uiX = 0U;
    uint32_t uiPc = 0U;
    while (uiPc < usCount) {
        const struct sock_filter *pInstruction = &pProgram[uiPc];
        uint32_t uiOffset;
        uint32_t uiBytes;
        uint32_t uiIndex;
        bool bCondition;
        switch (BPF_CLASS(pInstruction->code)) {
        case BPF_LD:
            CHECK((BPF_ABS == BPF_MODE(pInstruction->code)) ||
                  (BPF_IND == BPF_MODE(pInstruction->code)));
            uiOffset = pInstruction->k - (uint32_t)SKF_NET_OFF;
            if (BPF_IND == BPF_MODE(pInstruction->code)) {
                uiOffset += uiX;
            }
            uiBytes = (BPF_W == BPF_SIZE(pInstruction->code)) ? 4U :
                ((BPF_H == BPF_SIZE(pInstruction->code)) ? 2U : 1U);
            if ((uiOffset > zLength) || (uiBytes > zLength - uiOffset)) {
                return 0U; /* Kernel BPF out-of-bounds loads reject. */
            }
            uiA = 0U;
            for (uiIndex = 0U; uiIndex < uiBytes; uiIndex++) {
                uiA = (uiA << 8U) | pucPacket[uiOffset + uiIndex];
            }
            break;
        case BPF_ALU:
            if (BPF_AND == BPF_OP(pInstruction->code)) {
                uiA &= pInstruction->k;
            }
            else {
                CHECK(BPF_LSH == BPF_OP(pInstruction->code));
                CHECK(pInstruction->k < 32U);
                uiA <<= pInstruction->k;
            }
            break;
        case BPF_MISC:
            CHECK(BPF_TAX == BPF_MISCOP(pInstruction->code));
            uiX = uiA;
            break;
        case BPF_JMP:
            if (BPF_JEQ == BPF_OP(pInstruction->code)) {
                bCondition = uiA == pInstruction->k;
            }
            else if (BPF_JSET == BPF_OP(pInstruction->code)) {
                bCondition = 0U != (uiA & pInstruction->k);
            }
            else {
                CHECK(BPF_JGE == BPF_OP(pInstruction->code));
                bCondition = uiA >= pInstruction->k;
            }
            uiPc += bCondition ? pInstruction->jt : pInstruction->jf;
            CHECK(uiPc + 1U < usCount);
            break;
        case BPF_RET:
            return pInstruction->k;
        default:
            CHECK(false);
            break;
        }
        uiPc++;
    }
    CHECK(false);
    return 0U;
}

static void VerifySelectors(void)
{
    IpsecProtectedApplicationState_t State = {0};
    struct sock_filter aRaw[IPSEC_PROTECTED_APPLICATION_FILTER_CAPACITY];
    struct sock_filter aUdp[IPSEC_PROTECTED_APPLICATION_FILTER_CAPACITY];
    uint8_t aucPacket[64] = {0};
    const uint8_t aucLocal[4] = {192U, 0U, 2U, 1U};
    const uint8_t aucRemote[4] = {192U, 0U, 2U, 2U};
    uint16_t usRaw;
    uint16_t usUdp;
    uint32_t uiIndex;
    memcpy(&State.uiLocalAddress, aucLocal, 4U);
    memcpy(&State.uiRemoteAddress, aucRemote, 4U);
    usRaw = BuildIpsecProtectedApplicationProgram(&State, false, aRaw);
    usUdp = BuildIpsecProtectedApplicationProgram(&State, true, aUdp);
    CHECK((usRaw <= IPSEC_PROTECTED_APPLICATION_FILTER_CAPACITY) && (usUdp <= IPSEC_PROTECTED_APPLICATION_FILTER_CAPACITY));
    aucPacket[0] = 0x45U;
    aucPacket[9] = 50U;
    memcpy(aucPacket + 12U, aucLocal, 4U);
    memcpy(aucPacket + 16U, aucRemote, 4U);
    CHECK(0U != RunTestProgram(aRaw, usRaw, aucPacket, sizeof(aucPacket)));
    CHECK(0U == RunTestProgram(aUdp, usUdp, aucPacket, sizeof(aucPacket)));
    for (uiIndex = 0U; uiIndex < 20U; uiIndex++) {
        CHECK(0U == RunTestProgram(aRaw, usRaw, aucPacket, uiIndex));
    }
    aucPacket[19] = 3U;
    CHECK(0U == RunTestProgram(aRaw, usRaw, aucPacket, sizeof(aucPacket)));
    aucPacket[19] = 2U;
    aucPacket[9] = 17U;
    aucPacket[22] = 0x11U;
    aucPacket[23] = 0x94U; /* UDP destination port 4500. */
    aucPacket[25] = 20U;
    aucPacket[31] = 1U; /* Nonzero ESP SPI, not an IKE non-ESP marker. */
    CHECK(0U == RunTestProgram(aRaw, usRaw, aucPacket, sizeof(aucPacket)));
    CHECK(0U != RunTestProgram(aUdp, usUdp, aucPacket, sizeof(aucPacket)));
    aucPacket[22] = 0x23U;
    aucPacket[23] = 0x28U; /* Remapped UDP/9000 ESP must not bypass the sink. */
    CHECK(0U != RunTestProgram(aUdp, usUdp, aucPacket, sizeof(aucPacket)));
    aucPacket[22] = 0x11U;
    aucPacket[23] = 0x94U;
    aucPacket[31] = 0U;
    CHECK(0U == RunTestProgram(aUdp, usUdp, aucPacket, sizeof(aucPacket))); /* IKE. */
    aucPacket[23] = 0xf4U;
    aucPacket[22] = 1U; /* IKE/500 is not diverted. */
    CHECK(0U == RunTestProgram(aUdp, usUdp, aucPacket, sizeof(aucPacket)));
    aucPacket[6] = 0x20U;
    CHECK(0U != RunTestProgram(aUdp, usUdp, aucPacket, sizeof(aucPacket))); /* Fragment guard. */
    aucPacket[6] = 0U;
    aucPacket[0] = 0x46U; /* IPv4 options: UDP header starts at offset 24. */
    aucPacket[26] = 0x11U;
    aucPacket[27] = 0x94U;
    aucPacket[29] = 20U;
    aucPacket[35] = 1U;
    CHECK(0U != RunTestProgram(aUdp, usUdp, aucPacket, sizeof(aucPacket)));
    aucPacket[0] = 0x60U;
    CHECK(0U == RunTestProgram(aUdp, usUdp, aucPacket, sizeof(aucPacket)));
}

static void VerifyMessages(void)
{
    IpsecProtectedApplicationState_t State = {.uiTunIndex = 13U, .uiEgressIndex = 2U, .usPriority = 32000U};
    IpsecProtectedApplicationMessage_t Message;
    struct nlmsghdr *pHeader = (struct nlmsghdr *)Message.aucData;
    uint32_t uiIndex;
    uint32_t uiMask = 0U;
    for (uiIndex = 0U; uiIndex < 2U; uiIndex++) {
        bool bUdp = 0U != uiIndex;
        struct tcmsg *pTc;
        uint32_t uiMaskBefore = uiMask;
        const uint8_t *pucOptions;
        const uint8_t *pucValue;
        size_t zOptions;
        size_t zValue;
        uint32_t uiFlags;
        CHECK(IPSEC_OK == BuildIpsecProtectedApplicationFilterRequest(&State, bUdp, false, &Message));
        pTc = (struct tcmsg *)NLMSG_DATA(pHeader);
        pTc->tcm_handle = 0U;
        pHeader->nlmsg_len = NLMSG_LENGTH(sizeof(*pTc)) + RTA_LENGTH(4U); /* TCA_KIND only. */
        CHECK(IPSEC_OK == InspectIpsecProtectedApplicationFilterMessage(&State, pHeader, false, &uiMask));
        CHECK(uiMaskBefore == uiMask); /* Classifier header is not a real filter. */
        CHECK(IPSEC_OK == InspectIpsecProtectedApplicationFilterMessage(
            &State, pHeader, true, &uiMask));
        pTc->tcm_info += 1U << 20U;
        CHECK(IPSEC_OK == InspectIpsecProtectedApplicationFilterMessage(
            &State, pHeader, false, &uiMask));
        CHECK(IPSEC_OK == BuildIpsecProtectedApplicationFilterRequest(&State, bUdp, false, &Message));
        pTc->tcm_handle = State.uiTunIndex + 1U;
        CHECK(IPSEC_OK == InspectIpsecProtectedApplicationFilterMessage(
            &State, pHeader, false, &uiMask));
        CHECK(uiMaskBefore == uiMask);
        CHECK(IPSEC_OK == BuildIpsecProtectedApplicationFilterRequest(
            &State, bUdp, false, &Message));
        CHECK(IPSEC_OK == ValidateIpsecProtectedApplicationFilter(&State, pHeader, bUdp));
        CHECK(IPSEC_OK == InspectIpsecProtectedApplicationFilterMessage(&State, pHeader, false, &uiMask));
        CHECK(IPSEC_ERR_RESOURCE_CONFLICT == InspectIpsecProtectedApplicationFilterMessage(&State, pHeader, false, &uiMask));
        CHECK(IPSEC_OK != ValidateIpsecProtectedApplicationFilter(&State, pHeader, !bUdp));
        CHECK(IPSEC_OK == FindIpsecProtectedApplicationAttribute(Message.aucData + NLMSG_LENGTH(sizeof(*pTc)),
            pHeader->nlmsg_len - NLMSG_LENGTH(sizeof(*pTc)), TCA_OPTIONS, &pucOptions, &zOptions));
        CHECK(NULL != pucOptions);
        CHECK(IPSEC_OK == FindIpsecProtectedApplicationAttribute(pucOptions, zOptions,
            TCA_BPF_FLAGS_GEN, &pucValue, &zValue));
        CHECK((NULL != pucValue) && (sizeof(uiFlags) == zValue));
        uiFlags = TCA_CLS_FLAGS_SKIP_SW;
        memcpy((void *)pucValue, &uiFlags, sizeof(uiFlags));
        CHECK(IPSEC_ERR_RESOURCE_CONFLICT == ValidateIpsecProtectedApplicationFilter(&State, pHeader, bUdp));
        uiFlags = TCA_CLS_FLAGS_SKIP_HW | TCA_CLS_FLAGS_NOT_IN_HW;
        memcpy((void *)pucValue, &uiFlags, sizeof(uiFlags));
        CHECK(IPSEC_OK == ValidateIpsecProtectedApplicationFilter(&State, pHeader, bUdp));
        pHeader->nlmsg_len--;
        CHECK(IPSEC_OK != ValidateIpsecProtectedApplicationFilter(&State, pHeader, bUdp));
        CHECK(IPSEC_OK == BuildIpsecProtectedApplicationFilterRequest(&State, bUdp, true, &Message));
        CHECK(RTM_DELTFILTER == pHeader->nlmsg_type);
        CHECK(NLMSG_LENGTH(sizeof(struct tcmsg)) == pHeader->nlmsg_len);
    }
    CHECK(3U == uiMask);
    State.uiFilterHandle = 0x49500001U;
    CHECK(IPSEC_OK == BuildIpsecProtectedApplicationFilterRequest(
        &State, false, false, &Message));
    CHECK(0x49500001U == ((struct tcmsg *)NLMSG_DATA(pHeader))->tcm_handle);
    (void)puts("PASS: ESP redirect / UDP-ESP drop selectors, IKE exclusion, scoped filters and malformed Netlink");
}

int main(void)
{
    VerifySelectors();
    VerifyMessages();
    return 0;
}
