#include "vici_internal.h"

#include <stdio.h>
#include <string.h>

typedef struct ParserState {
    uint32_t uiElementCount;
    uint32_t uiMaximumDepth;
} ParserState_t;

static int32_t ReportFailure(const char *pcMessage)
{
    (void)fprintf(stderr, "FAIL: %s\n", pcMessage);
    return 1;
}

static IpsecError_t CountElement(
    const ViciElement_t *pElement,
    void *pvUserData)
{
    ParserState_t *pState = (ParserState_t *)pvUserData;

    pState->uiElementCount++;
    if (pState->uiMaximumDepth < pElement->uiDepth) {
        pState->uiMaximumDepth = pElement->uiDepth;
    }
    else {
        /* Keep current maximum. */
    }
    return IPSEC_OK;
}

static int32_t TestOfficialMessageExample(void)
{
    static const uint8_t aucExpected[] = {
        3U, 4U, 'k', 'e', 'y', '1', 0U, 6U,
        'v', 'a', 'l', 'u', 'e', '1',
        1U, 8U, 's', 'e', 'c', 't', 'i', 'o', 'n', '1',
        1U, 11U, 's', 'u', 'b', '-', 's', 'e', 'c', 't', 'i', 'o', 'n',
        3U, 4U, 'k', 'e', 'y', '2', 0U, 6U,
        'v', 'a', 'l', 'u', 'e', '2',
        2U,
        4U, 5U, 'l', 'i', 's', 't', '1',
        5U, 0U, 5U, 'i', 't', 'e', 'm', '1',
        5U, 0U, 5U, 'i', 't', 'e', 'm', '2',
        6U,
        2U
    };
    ViciBuffer_t Message = {0};
    ParserState_t State = {0};
    IpsecError_t eError;

    eError = InitializeViciBuffer(&Message, 128U, false);
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(&Message, "key1", "value1");
    }
    else {
        /* Preserve allocation error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionStart(&Message, "section1");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionStart(&Message, "sub-section");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(&Message, "key2", "value2");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionEnd(&Message);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListStart(&Message, "list1");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListItemString(&Message, "item1");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListItemString(&Message, "item2");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListEnd(&Message);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionEnd(&Message);
    }
    else {
        /* Preserve message error. */
    }

    if ((IPSEC_OK != eError) ||
        (sizeof(aucExpected) != Message.uiLength) ||
        (0 != memcmp(aucExpected, Message.pucData, sizeof(aucExpected)))) {
        DestroyViciBuffer(&Message);
        return ReportFailure("official VICI message encoding");
    }
    else {
        /* Encoded bytes match the 5.8.4 protocol example. */
    }

    eError = ParseViciMessage(Message.pucData, Message.uiLength,
                              CountElement, &State);
    DestroyViciBuffer(&Message);
    if ((IPSEC_OK != eError) || (10U != State.uiElementCount) ||
        (2U != State.uiMaximumDepth)) {
        return ReportFailure("official VICI message decoding");
    }
    else {
        return 0;
    }
}

static int32_t TestMalformedMessages(void)
{
    static const uint8_t aucUnbalanced[] = {
        1U, 1U, 'x'
    };
    static const uint8_t aucTruncatedValue[] = {
        3U, 1U, 'k', 0U, 4U, 'x'
    };
    static const uint8_t aucListKeyValue[] = {
        4U, 1U, 'l',
        3U, 1U, 'k', 0U, 1U, 'v',
        6U
    };

    if (IPSEC_ERR_VICI_PROTOCOL !=
        ParseViciMessage(aucUnbalanced, sizeof(aucUnbalanced),
                         NULL, NULL)) {
        return ReportFailure("unbalanced section accepted");
    }
    else if (IPSEC_ERR_VICI_PROTOCOL !=
             ParseViciMessage(aucTruncatedValue,
                              sizeof(aucTruncatedValue), NULL, NULL)) {
        return ReportFailure("truncated value accepted");
    }
    else if (IPSEC_ERR_VICI_PROTOCOL !=
             ParseViciMessage(aucListKeyValue,
                              sizeof(aucListKeyValue), NULL, NULL)) {
        return ReportFailure("key/value inside list accepted");
    }
    else {
        return 0;
    }
}

static int32_t TestPacketBoundary(void)
{
    static const uint8_t aucGoodPacket[] = {
        0U, 7U, 'v', 'e', 'r', 's', 'i', 'o', 'n'
    };
    static const uint8_t aucBadPacket[] = {
        0U, 8U, 'v', 'e', 'r'
    };
    ViciPacketView_t View;
    IpsecError_t eError;

    eError = DecodeViciPacket(aucGoodPacket, sizeof(aucGoodPacket), &View);
    if ((IPSEC_OK != eError) ||
        (VICI_PACKET_COMMAND_REQUEST != View.eType) ||
        (7U != View.ucNameLength) || (0U != View.uiMessageLength)) {
        return ReportFailure("valid named packet decode");
    }
    else if (IPSEC_ERR_VICI_PROTOCOL !=
             DecodeViciPacket(aucBadPacket, sizeof(aucBadPacket), &View)) {
        return ReportFailure("truncated named packet accepted");
    }
    else {
        return 0;
    }
}

static int32_t TestHumanReadableUptime(void)
{
    static const uint8_t aucMinutes[] = "18 minutes";
    static const uint8_t aucComposite[] = "1 hour, 2 minutes";
    static const uint8_t aucSubsecond[] = "less than a second";
    static const uint8_t aucUnknown[] = "18 fortnights";
    uint64_t ullSeconds = 99U;

    if ((IPSEC_OK != ParseIpsecDurationSeconds(
             aucMinutes, sizeof(aucMinutes) - 1U, &ullSeconds)) ||
        (1080U != ullSeconds)) {
        return ReportFailure("VICI uptime minutes");
    }
    else if ((IPSEC_OK != ParseIpsecDurationSeconds(
                  aucComposite, sizeof(aucComposite) - 1U, &ullSeconds)) ||
             (3720U != ullSeconds)) {
        return ReportFailure("VICI composite uptime");
    }
    else if ((IPSEC_OK != ParseIpsecDurationSeconds(
                  aucSubsecond, sizeof(aucSubsecond) - 1U, &ullSeconds)) ||
             (0U != ullSeconds)) {
        return ReportFailure("VICI subsecond uptime");
    }
    else if ((IPSEC_ERR_VICI_PROTOCOL != ParseIpsecDurationSeconds(
                  aucUnknown, sizeof(aucUnknown) - 1U, &ullSeconds)) ||
             (0U != ullSeconds)) {
        return ReportFailure("unknown VICI uptime unit");
    }
    else {
        return 0;
    }
}

int main(void)
{
    int32_t iResult;

    iResult = TestOfficialMessageExample();
    if (0 == iResult) {
        iResult = TestMalformedMessages();
    }
    else {
        /* Preserve first failure. */
    }
    if (0 == iResult) {
        iResult = TestPacketBoundary();
    }
    else {
        /* Preserve first failure. */
    }
    if (0 == iResult) {
        iResult = TestHumanReadableUptime();
    }
    else {
        /* Preserve first failure. */
    }

    return iResult;
}
