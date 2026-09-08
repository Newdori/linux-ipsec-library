#include "algorithm_packet.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); return 1; \
} } while (0)

static NativeAppPacketTestResult_t BuildTestPacketEvidence(void) {
    NativeAppPacketTestResult_t Result = {.bAttempted = true,
        .uiSent = 2U, .uiReceived = 2U,
        .uiExpectedInboundSpi = 0xc0000001U, .uiExpectedOutboundSpi = 0xc0000002U};
    uint32_t uiIndex;
    memcpy(Result.acStage, "complete", sizeof("complete"));
    for (uiIndex = 0U; uiIndex < NATIVE_APP_PACKET_EVIDENCE_CAPACITY; uiIndex++) {
        NativeAppPacketEvidence_t *pPacket = &Result.aPackets[uiIndex];
        pPacket->uiProbeSequence = uiIndex + 1U;
        pPacket->bOutbound = (0U == uiIndex % 2U);
        pPacket->uiEspLength = 220U;
        pPacket->uiEspSpi = pPacket->bOutbound ? Result.uiExpectedOutboundSpi : Result.uiExpectedInboundSpi;
        pPacket->uiEspSequence = uiIndex / 2U + 1U;
        pPacket->bEspValid = true;
        if (pPacket->bOutbound) {
            pPacket->bCaptureAttempted = true;
            pPacket->bEspCaptured = true;
            pPacket->bEspRelayed = true;
            pPacket->bPeerConfirmed = true;
        }
        else {
            pPacket->bEspRelayed = true;
            pPacket->bSubmitAttempted = true;
            pPacket->bEspSubmitted = true;
            pPacket->bPlainAttempted = true;
            pPacket->bPlainReceived = true;
            pPacket->bCompareAttempted = true;
            pPacket->bPayloadMatch = true;
            pPacket->uiPlainLength = 156U;
        }
    }
    return Result;
}

static int32_t VerifyTestProofFailures(const NativeAppPacketTestResult_t *pGood) {
    NativeAppPacketTestResult_t Bad = {.bAttempted = true, .uiSent = 2U, .uiReceived = 2U};
    uint32_t uiIndex;
    CHECK(!VerifyNativeAppPacketTestProof(NULL));
    CHECK(!VerifyNativeAppPacketTestProof(&Bad)); /* Counters alone are not proof. */
#define REJECT_CHANGE(Change) do { Bad = *pGood; Change; \
    CHECK(!VerifyNativeAppPacketTestProof(&Bad)); } while (0)
    REJECT_CHANGE(Bad.bAttempted = false);
    REJECT_CHANGE(Bad.eError = IPSEC_ERR_FILE_WRITE);
    REJECT_CHANGE(Bad.uiSent = 1U);
    REJECT_CHANGE(Bad.uiReceived = 1U);
    REJECT_CHANGE(Bad.uiExpectedInboundSpi = 0U);
    REJECT_CHANGE(Bad.uiExpectedOutboundSpi = 0U);
    for (uiIndex = 0U; uiIndex < NATIVE_APP_PACKET_EVIDENCE_CAPACITY; uiIndex++) {
        REJECT_CHANGE(Bad.aPackets[uiIndex].uiProbeSequence = 0U);
        REJECT_CHANGE(Bad.aPackets[uiIndex].eError = IPSEC_ERR_PACKET_TIMEOUT);
        REJECT_CHANGE(Bad.aPackets[uiIndex].uiEspLength = 0U);
        REJECT_CHANGE(Bad.aPackets[uiIndex].uiEspSpi ^= 1U);
        REJECT_CHANGE(Bad.aPackets[uiIndex].bEspValid = false);
        REJECT_CHANGE(Bad.aPackets[uiIndex].bOutbound = !Bad.aPackets[uiIndex].bOutbound);
        if (pGood->aPackets[uiIndex].bOutbound) {
            REJECT_CHANGE(Bad.aPackets[uiIndex].bCaptureAttempted = false);
            REJECT_CHANGE(Bad.aPackets[uiIndex].bEspCaptured = false);
            REJECT_CHANGE(Bad.aPackets[uiIndex].bPeerConfirmed = false);
        }
        else {
            REJECT_CHANGE(Bad.aPackets[uiIndex].bEspRelayed = false);
            REJECT_CHANGE(Bad.aPackets[uiIndex].bSubmitAttempted = false);
            REJECT_CHANGE(Bad.aPackets[uiIndex].bEspSubmitted = false);
            REJECT_CHANGE(Bad.aPackets[uiIndex].bPlainAttempted = false);
            REJECT_CHANGE(Bad.aPackets[uiIndex].bPlainReceived = false);
            REJECT_CHANGE(Bad.aPackets[uiIndex].bCompareAttempted = false);
            REJECT_CHANGE(Bad.aPackets[uiIndex].bPayloadMatch = false);
            REJECT_CHANGE(Bad.aPackets[uiIndex].uiPlainLength = 155U);
        }
    }
#undef REJECT_CHANGE
    return 0;
}

typedef IpsecError_t (*WriteTestEvidence_t)(FILE *, const NativeAppPacketTestResult_t *);

static int32_t VerifyTestFailureOwnership(void)
{
    NativeAppAlgorithmCaseResult_t Result = {0};
    Result.eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH;
    Result.PacketTest.bAttempted = true;
    Result.PacketTest.eError = IPSEC_ERR_PACKET_TIMEOUT;
    Result.PacketTest.eLocalError = IPSEC_ERR_PACKET_TIMEOUT;
    Result.bPeerCaseKnown = true; /* Initiator echoed the responder timeout. */
    Result.ePeerCaseResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH;
    Result.ePeerCaseError = IPSEC_ERR_PACKET_TIMEOUT;
    ApplyNativeAppPacketFailure(&Result);
    CHECK(IPSEC_ERR_PACKET_TIMEOUT == Result.eError);
    CHECK(IPSEC_ERR_PACKET_TIMEOUT == GetNativeAppAlgorithmCaseError(&Result));
    /* Initiator only received the responder error; it must not claim a
     * second local decryption failure. */
    Result.PacketTest.eLocalError = IPSEC_OK;
    Result.bPeerCaseKnown = false;
    ApplyNativeAppPacketFailure(&Result);
    CHECK(IPSEC_OK == Result.eError);
    CHECK(Result.bPeerCaseKnown);
    CHECK(IPSEC_ERR_PACKET_TIMEOUT == Result.ePeerCaseError);
    CHECK(IPSEC_ERR_PACKET_TIMEOUT == GetNativeAppAlgorithmCaseError(&Result));
    Result.eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_CLEANUP;
    Result.eError = IPSEC_ERR_RESOURCE_CONFLICT;
    ApplyNativeAppPacketFailure(&Result);
    CHECK(IPSEC_ERR_RESOURCE_CONFLICT == Result.eError);
    CHECK(IPSEC_ERR_RESOURCE_CONFLICT == GetNativeAppAlgorithmCaseError(&Result));
    Result.PacketTest.bAttempted = false; /* SYSTEM path is unchanged. */
    Result.eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH;
    ApplyNativeAppPacketFailure(&Result);
    CHECK(IPSEC_ERR_RESOURCE_CONFLICT == Result.eError);
    ApplyNativeAppPacketFailure(NULL);
    return 0;
}

static int32_t VerifyTestReport(WriteTestEvidence_t pWrite,
    const NativeAppPacketTestResult_t *pResult, const char *pcExpected) {
    char acText[8192];
    size_t zRead;
    /* Exclusive, per-test scratch in the build directory; never overwrite. */
    int32_t iFile = open("test_algorithm_packet_evidence.tmp", O_CREAT | O_EXCL | O_RDWR, 0600);
    FILE *pFile;
    CHECK(iFile >= 0);
    pFile = fdopen(iFile, "w+");
    if (NULL == pFile) {
        (void)close(iFile);
    }
    CHECK(NULL != pFile);
    CHECK(IPSEC_OK == pWrite(pFile, pResult));
    CHECK(0 == fflush(pFile));
    CHECK(0 == fseek(pFile, 0L, SEEK_SET));
    zRead = fread(acText, 1U, sizeof(acText) - 1U, pFile);
    CHECK((0U != zRead) && (0 == ferror(pFile)));
    acText[zRead] = '\0';
    CHECK(NULL != strstr(acText, pcExpected));
    CHECK(0 == fclose(pFile));
    CHECK(0 == remove("test_algorithm_packet_evidence.tmp"));
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == pWrite(NULL, pResult));
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == pWrite(stdout, NULL));
    return 0;
}

int main(int32_t iArgc, char **ppcArgv) {
    NativeAppPacketTestResult_t Good = BuildTestPacketEvidence();
    NativeAppPacketTestResult_t Empty = {0};
    NativeAppPacketTestResult_t Failed = {.bAttempted = true, .eError = IPSEC_ERR_PACKET_TYPE};
    CHECK(VerifyNativeAppPacketTestProof(&Good));
    CHECK(0 == VerifyTestFailureOwnership());
    CHECK(0 == VerifyTestProofFailures(&Good));
    CHECK(0 == VerifyTestReport(WriteNativeAppPacketEvidenceText, &Good,
        "application_checks ESP_CAPTURE=PASS(2/2) ESP_SUBMIT=PASS(2/2) PLAIN_DELIVERY=PASS(2/2) PAYLOAD_MATCH=PASS(2/2) proof=PASS error=none"));
    CHECK(0 == VerifyTestReport(WriteNativeAppPacketEvidenceText, &Empty, "proof=NOT_RUN error=none"));
    Failed.aPackets[0].bCaptureAttempted = true;
    CHECK(0 == VerifyTestReport(WriteNativeAppPacketEvidenceText, &Failed,
        "ESP_CAPTURE=FAIL(0/2) ESP_SUBMIT=NOT_RUN(0/2)"));
    CHECK(0 == VerifyTestReport(WriteNativeAppPacketEvidenceJson, &Good, "\"proof\":\"PASS\""));
    CHECK(0 == VerifyTestReport(WriteNativeAppPacketEvidenceJson, &Empty, "\"packets\":[]"));
    CHECK(0 == VerifyTestReport(WriteNativeAppPacketEvidenceJson, &Failed, "\"proof\":\"FAIL\""));
    CHECK(0 == VerifyTestReport(WriteNativeAppPacketEvidenceCsv, &Good,
        "1,outbound,220,0xc0000002,1,0,1,1,1,0,0,0,1,0"));
    Failed.eLocalError = IPSEC_ERR_PACKET_TIMEOUT;
    CHECK(0 == VerifyTestReport(WriteNativeAppPacketEvidenceJson, &Failed,
        "\"local_error\":\"packet operation timed out\""));
    memcpy(Good.acStage, "quote\"\\\n", sizeof("quote\"\\\n"));
    CHECK(0 == VerifyTestReport(WriteNativeAppPacketEvidenceJson, &Good, "quote\\\"\\\\\\u000a"));
    if ((2 == iArgc) && (0 == strcmp(ppcArgv[1], "--json"))) {
        CHECK(IPSEC_OK == WriteNativeAppPacketEvidenceJson(stdout, &Good));
    }
    else if ((2 == iArgc) && (0 == strcmp(ppcArgv[1], "--csv"))) {
        CHECK(IPSEC_OK == WriteNativeAppPacketEvidenceCsv(stdout, &Good));
    }
    else {
        (void)puts("algorithm packet evidence: PASS");
    }
    return 0;
}
