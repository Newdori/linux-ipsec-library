#include "algorithm_packet.h"

#include <inttypes.h>
#include <string.h>

bool ShouldStopNativeAppPacketFailure(const NativeAppAlgorithmCaseResult_t *pResult,
    bool bContinueOnDataPathError)
{
    return (NULL != pResult) && !bContinueOnDataPathError &&
        pResult->PacketTest.bAttempted &&
        (NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH == pResult->eResult);
}

IpsecError_t GetNativeAppAlgorithmCaseError(const NativeAppAlgorithmCaseResult_t *pResult)
{
    if (NULL == pResult) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (IPSEC_OK != pResult->eError) {
        return pResult->eError;
    }
    if (IPSEC_OK != pResult->eCleanupError) {
        return pResult->eCleanupError;
    }
    return pResult->bPeerCaseKnown ? pResult->ePeerCaseError : IPSEC_OK;
}

void ApplyNativeAppPacketFailure(NativeAppAlgorithmCaseResult_t *pResult)
{
    if ((NULL == pResult) || !pResult->PacketTest.bAttempted ||
        (IPSEC_OK == pResult->PacketTest.eError) ||
        (NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH != pResult->eResult)) {
        return;
    }
    /* ABORT may echo this host's original failure. Do not let a later peer
     * acknowledgement or successful cleanup turn that failure into none. */
    pResult->eError = pResult->PacketTest.eLocalError;
    if (IPSEC_OK == pResult->PacketTest.eLocalError) {
        pResult->bPeerCaseKnown = true;
        pResult->ePeerCaseResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH;
        pResult->ePeerCaseError = pResult->PacketTest.eError;
    }
}

typedef struct NativeAppPacketChecks {
    uint32_t auiAttempts[4];
    uint32_t auiSuccesses[4];
} NativeAppPacketChecks_t;

static NativeAppPacketChecks_t CollectNativeAppPacketChecks(
    const NativeAppPacketTestResult_t *pResult)
{
    NativeAppPacketChecks_t Checks = {0};
    uint32_t uiIndex;
    for (uiIndex = 0U; uiIndex < NATIVE_APP_PACKET_EVIDENCE_CAPACITY; uiIndex++) {
        const NativeAppPacketEvidence_t *pPacket = &pResult->aPackets[uiIndex];
        Checks.auiAttempts[0] += pPacket->bCaptureAttempted ? 1U : 0U;
        Checks.auiAttempts[1] += pPacket->bSubmitAttempted ? 1U : 0U;
        Checks.auiAttempts[2] += pPacket->bPlainAttempted ? 1U : 0U;
        Checks.auiAttempts[3] += pPacket->bCompareAttempted ? 1U : 0U;
        Checks.auiSuccesses[0] += (pPacket->bEspCaptured && pPacket->bEspValid) ? 1U : 0U;
        Checks.auiSuccesses[1] += pPacket->bEspSubmitted ? 1U : 0U;
        Checks.auiSuccesses[2] += pPacket->bPlainReceived ? 1U : 0U;
        Checks.auiSuccesses[3] += pPacket->bPayloadMatch ? 1U : 0U;
    }
    return Checks;
}

static const char *GetNativeAppPacketCheckStatus(uint32_t uiAttempts, uint32_t uiSuccesses)
{
    if (0U == uiAttempts) {
        return "NOT_RUN";
    }
    return (NATIVE_APP_PROBE_COUNT == uiSuccesses) ? "PASS" : "FAIL";
}

static const char *GetNativeAppPacketError(IpsecError_t eError)
{
    return (IPSEC_OK == eError) ? "none" : GetIpsecErrorString(eError);
}

static void WriteNativeAppPacketQuoted(FILE *pFile, const char *pcText)
{
    const uint8_t *pucCursor = (const uint8_t *)pcText;
    (void)fputc('"', pFile);
    while (0U != *pucCursor) {
        if (('"' == *pucCursor) || ('\\' == *pucCursor)) {
            (void)fputc('\\', pFile);
            (void)fputc(*pucCursor, pFile);
        }
        else if (*pucCursor < 32U) {
            (void)fprintf(pFile, "\\u%04x", (uint32_t)*pucCursor);
        }
        else {
            (void)fputc(*pucCursor, pFile);
        }
        pucCursor++;
    }
    (void)fputc('"', pFile);
}

IpsecError_t WriteNativeAppPacketEvidenceText(FILE *pFile,
    const NativeAppPacketTestResult_t *pResult)
{
    NativeAppPacketChecks_t Checks;
    static const char *const pacNames[4] = {
        "ESP_CAPTURE", "ESP_SUBMIT", "PLAIN_DELIVERY", "PAYLOAD_MATCH"
    };
    uint32_t uiIndex;
    if ((NULL == pFile) || (NULL == pResult)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    Checks = CollectNativeAppPacketChecks(pResult);
    (void)fputs("application_checks", pFile);
    for (uiIndex = 0U; uiIndex < 4U; uiIndex++) {
        (void)fprintf(pFile, " %s=%s(%" PRIu32 "/%u)", pacNames[uiIndex],
            GetNativeAppPacketCheckStatus(Checks.auiAttempts[uiIndex], Checks.auiSuccesses[uiIndex]),
            Checks.auiSuccesses[uiIndex], NATIVE_APP_PROBE_COUNT);
    }
    (void)fprintf(pFile, " proof=%s error=%s\n",
        !pResult->bAttempted ? "NOT_RUN" :
        (VerifyNativeAppPacketTestProof(pResult) ? "PASS" : "FAIL"),
        GetNativeAppPacketError(pResult->eError));
    return (0 == ferror(pFile)) ? IPSEC_OK : IPSEC_ERR_FILE_WRITE;
}

IpsecError_t WriteNativeAppPacketEvidenceJson(FILE *pFile,
    const NativeAppPacketTestResult_t *pResult)
{
    NativeAppPacketChecks_t Checks;
    static const char *const pacNames[4] = {
        "esp_capture", "esp_submit", "plain_delivery", "payload_match"
    };
    uint32_t uiIndex;
    bool bFirst = true;
    if ((NULL == pFile) || (NULL == pResult)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    Checks = CollectNativeAppPacketChecks(pResult);
    (void)fprintf(pFile, "{\"attempted\":%s,\"sent_verified\":%" PRIu32
        ",\"received_verified\":%" PRIu32 ",\"expected_spi_in\":%" PRIu32
        ",\"expected_spi_out\":%" PRIu32 ",\"stage\":",
        pResult->bAttempted ? "true" : "false", pResult->uiSent, pResult->uiReceived,
        pResult->uiExpectedInboundSpi, pResult->uiExpectedOutboundSpi);
    WriteNativeAppPacketQuoted(pFile, pResult->acStage);
    (void)fputs(",\"error\":", pFile);
    WriteNativeAppPacketQuoted(pFile, GetNativeAppPacketError(pResult->eError));
    (void)fputs(",\"local_error\":", pFile);
    WriteNativeAppPacketQuoted(pFile, GetNativeAppPacketError(pResult->eLocalError));
    (void)fprintf(pFile, ",\"proof\":\"%s\",\"checks\":{",
        !pResult->bAttempted ? "NOT_RUN" :
        (VerifyNativeAppPacketTestProof(pResult) ? "PASS" : "FAIL"));
    for (uiIndex = 0U; uiIndex < 4U; uiIndex++) {
        (void)fprintf(pFile, "%s\"%s\":{\"result\":\"%s\",\"attempts\":%" PRIu32
            ",\"successes\":%" PRIu32 ",\"expected\":%u}",
            (0U == uiIndex) ? "" : ",", pacNames[uiIndex],
            GetNativeAppPacketCheckStatus(Checks.auiAttempts[uiIndex], Checks.auiSuccesses[uiIndex]),
            Checks.auiAttempts[uiIndex], Checks.auiSuccesses[uiIndex], NATIVE_APP_PROBE_COUNT);
    }
    (void)fputs("},\"packets\":[", pFile);
    for (uiIndex = 0U; uiIndex < NATIVE_APP_PACKET_EVIDENCE_CAPACITY; uiIndex++) {
        const NativeAppPacketEvidence_t *pPacket = &pResult->aPackets[uiIndex];
        if (0U == pPacket->uiProbeSequence) {
            continue;
        }
        (void)fprintf(pFile, "%s{\"probe_sequence\":%" PRIu32 ",\"direction\":\"%s\","
            "\"esp_bytes\":%" PRIu32 ",\"spi\":%" PRIu32 ",\"esp_sequence\":%" PRIu32
            ",\"plain_bytes\":%" PRIu32 ",\"esp_captured\":%s,\"esp_relayed\":%s,"
            "\"esp_valid\":%s,\"esp_submitted\":%s,\"plain_received\":%s,"
            "\"payload_match\":%s,\"peer_confirmed\":%s,\"error\":",
            bFirst ? "" : ",", pPacket->uiProbeSequence,
            pPacket->bOutbound ? "outbound" : "inbound", pPacket->uiEspLength,
            pPacket->uiEspSpi, pPacket->uiEspSequence, pPacket->uiPlainLength,
            pPacket->bEspCaptured ? "true" : "false", pPacket->bEspRelayed ? "true" : "false",
            pPacket->bEspValid ? "true" : "false", pPacket->bEspSubmitted ? "true" : "false",
            pPacket->bPlainReceived ? "true" : "false", pPacket->bPayloadMatch ? "true" : "false",
            pPacket->bPeerConfirmed ? "true" : "false");
        WriteNativeAppPacketQuoted(pFile, GetNativeAppPacketError(pPacket->eError));
        (void)fputc('}', pFile);
        bFirst = false;
    }
    (void)fputs("]}", pFile);
    return (0 == ferror(pFile)) ? IPSEC_OK : IPSEC_ERR_FILE_WRITE;
}

IpsecError_t WriteNativeAppPacketEvidenceCsv(FILE *pFile,
    const NativeAppPacketTestResult_t *pResult)
{
    uint32_t uiIndex;
    if ((NULL == pFile) || (NULL == pResult)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    (void)fputs("probe_sequence,direction,esp_bytes,spi,esp_sequence,plain_bytes,"
        "esp_captured,esp_relayed,esp_valid,esp_submitted,plain_received,"
        "payload_match,peer_confirmed,error_code\n", pFile);
    for (uiIndex = 0U; uiIndex < NATIVE_APP_PACKET_EVIDENCE_CAPACITY; uiIndex++) {
        const NativeAppPacketEvidence_t *pPacket = &pResult->aPackets[uiIndex];
        if (0U == pPacket->uiProbeSequence) {
            continue;
        }
        (void)fprintf(pFile, "%" PRIu32 ",%s,%" PRIu32 ",0x%08" PRIx32
            ",%" PRIu32 ",%" PRIu32 ",%u,%u,%u,%u,%u,%u,%u,%" PRIu32 "\n",
            pPacket->uiProbeSequence, pPacket->bOutbound ? "outbound" : "inbound",
            pPacket->uiEspLength, pPacket->uiEspSpi, pPacket->uiEspSequence, pPacket->uiPlainLength,
            pPacket->bEspCaptured ? 1U : 0U, pPacket->bEspRelayed ? 1U : 0U,
            pPacket->bEspValid ? 1U : 0U, pPacket->bEspSubmitted ? 1U : 0U,
            pPacket->bPlainReceived ? 1U : 0U, pPacket->bPayloadMatch ? 1U : 0U,
            pPacket->bPeerConfirmed ? 1U : 0U, (uint32_t)pPacket->eError);
    }
    return (0 == ferror(pFile)) ? IPSEC_OK : IPSEC_ERR_FILE_WRITE;
}
