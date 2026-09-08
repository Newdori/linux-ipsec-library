#include "algorithm_packet.h"

#include <string.h>

static uint16_t ReadNativeAppTestUint16(const uint8_t *pucData)
{
    return (uint16_t)(((uint16_t)pucData[0] << 8U) | pucData[1]);
}

static uint32_t ReadNativeAppTestUint32(const uint8_t *pucData)
{
    return ((uint32_t)pucData[0] << 24U) | ((uint32_t)pucData[1] << 16U) |
        ((uint32_t)pucData[2] << 8U) | pucData[3];
}

IpsecError_t InspectNativeAppTestEsp(const uint8_t *pucData, size_t zLength,
    uint32_t uiExpectedSpi, NativeAppPacketEvidence_t *pEvidence)
{
    size_t zHeader;
    size_t zIndex;
    uint32_t uiChecksum = 0U;
    if ((NULL == pucData) || (NULL == pEvidence)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pEvidence->bEspValid = false;
    pEvidence->uiEspSpi = 0U;
    pEvidence->uiEspSequence = 0U;
    pEvidence->uiEspLength = (zLength <= UINT16_MAX) ? (uint32_t)zLength : 0U;
    if ((zLength < 29U) || (zLength > UINT16_MAX)) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    if ((4U != (pucData[0] >> 4U)) || (50U != pucData[9])) {
        return IPSEC_ERR_PACKET_TYPE;
    }
    zHeader = (size_t)(pucData[0] & 15U) * 4U;
    if ((zHeader < 20U) || (zHeader + 8U >= zLength) ||
        (ReadNativeAppTestUint16(pucData + 2U) != zLength) ||
        (0U != (ReadNativeAppTestUint16(pucData + 6U) & 0xbfffU))) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    for (zIndex = 0U; zIndex < zHeader; zIndex += 2U) {
        uiChecksum += ReadNativeAppTestUint16(pucData + zIndex);
    }
    while (uiChecksum > UINT16_MAX) {
        uiChecksum = (uiChecksum & UINT16_MAX) + (uiChecksum >> 16U);
    }
    pEvidence->uiEspSpi = ReadNativeAppTestUint32(pucData + zHeader);
    pEvidence->uiEspSequence = ReadNativeAppTestUint32(pucData + zHeader + 4U);
    if ((UINT16_MAX != uiChecksum) || (0U == uiExpectedSpi) ||
        (uiExpectedSpi != pEvidence->uiEspSpi)) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    pEvidence->bEspValid = true;
    /* SPI/framing is evidence of capture, not cryptographic verification.
     * Authentication and decryption remain entirely with charon. */
    return IPSEC_OK;
}

bool VerifyNativeAppPacketTestProof(const NativeAppPacketTestResult_t *pResult)
{
    uint32_t uiIndex;
    uint32_t uiOutbound = 0U;
    uint32_t uiInbound = 0U;
    if ((NULL == pResult) || !pResult->bAttempted || (IPSEC_OK != pResult->eError) ||
        (NATIVE_APP_PROBE_COUNT != pResult->uiSent) ||
        (NATIVE_APP_PROBE_COUNT != pResult->uiReceived)) {
        return false;
    }
    for (uiIndex = 0U; uiIndex < NATIVE_APP_PACKET_EVIDENCE_CAPACITY; uiIndex++) {
        const NativeAppPacketEvidence_t *pPacket = &pResult->aPackets[uiIndex];
        if ((uiIndex + 1U != pPacket->uiProbeSequence) ||
            (IPSEC_OK != pPacket->eError) || !pPacket->bEspValid ||
            (pPacket->uiEspLength < 29U)) {
            return false;
        }
        if (pPacket->bOutbound) {
            if (!pPacket->bCaptureAttempted || !pPacket->bEspCaptured ||
                !pPacket->bPeerConfirmed || (0U == pResult->uiExpectedOutboundSpi) ||
                (pResult->uiExpectedOutboundSpi != pPacket->uiEspSpi)) {
                return false;
            }
            uiOutbound++;
        }
        else {
            if (!pPacket->bEspRelayed || !pPacket->bSubmitAttempted ||
                !pPacket->bEspSubmitted || !pPacket->bPlainAttempted ||
                !pPacket->bPlainReceived || !pPacket->bCompareAttempted ||
                !pPacket->bPayloadMatch || (0U == pResult->uiExpectedInboundSpi) ||
                (pResult->uiExpectedInboundSpi != pPacket->uiEspSpi) ||
                (pPacket->uiPlainLength < NATIVE_APP_PROBE_LENGTH + 28U)) {
                return false;
            }
            uiInbound++;
        }
    }
    return (NATIVE_APP_PROBE_COUNT == uiOutbound) && (NATIVE_APP_PROBE_COUNT == uiInbound);
}

void EncodeNativeAppTestLength(uint8_t *pucHeader, uint32_t uiLength)
{
    pucHeader[0] = (uint8_t)(uiLength >> 24U);
    pucHeader[1] = (uint8_t)(uiLength >> 16U);
    pucHeader[2] = (uint8_t)(uiLength >> 8U);
    pucHeader[3] = (uint8_t)uiLength;
}

IpsecError_t DecodeNativeAppTestLength(const uint8_t *pucHeader,
    size_t zCapacity, size_t *pzLength)
{
    uint32_t uiLength;
    if ((NULL == pucHeader) || (NULL == pzLength)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    *pzLength = 0U;
    uiLength = ((uint32_t)pucHeader[0] << 24U) |
        ((uint32_t)pucHeader[1] << 16U) |
        ((uint32_t)pucHeader[2] << 8U) | pucHeader[3];
    if ((0U == uiLength) || (uiLength > NATIVE_APP_RELAY_CAPACITY) ||
        (uiLength > zCapacity)) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    *pzLength = uiLength;
    return IPSEC_OK;
}

void BuildNativeAppTestProbe(uint8_t *pucProbe, const uint8_t *pucNonce,
    const char *pcCaseId, uint32_t uiSequence)
{
    size_t zLength = strlen(pcCaseId);
    size_t zIndex;
    memset(pucProbe, 0, NATIVE_APP_PROBE_LENGTH);
    memcpy(pucProbe, "IPSEC-PROBE-1", 13U);
    memcpy(pucProbe + 16U, pucNonce, 16U);
    EncodeNativeAppTestLength(pucProbe + 32U, uiSequence);
    if (zLength >= NATIVE_APP_ALGORITHM_CASE_ID_LENGTH) {
        zLength = NATIVE_APP_ALGORITHM_CASE_ID_LENGTH - 1U;
    }
    memcpy(pucProbe + 36U, pcCaseId, zLength);
    for (zIndex = 100U; zIndex < NATIVE_APP_PROBE_LENGTH; zIndex++) {
        pucProbe[zIndex] = (uint8_t)(zIndex ^ uiSequence ^ pucNonce[zIndex % 16U]);
    }
}

IpsecError_t ValidateNativeAppTestPlain(const uint8_t *pucData, size_t zLength,
    const uint8_t *pucSource, const uint8_t *pucDestination,
    const uint8_t *pucProbe)
{
    size_t zHeader;
    size_t zIndex;
    uint32_t uiChecksum = 0U;
    if ((NULL == pucData) || (NULL == pucSource) ||
        (NULL == pucDestination) || (NULL == pucProbe) || (zLength < 28U)) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    zHeader = (size_t)(pucData[0] & 15U) * 4U;
    if ((4U != (pucData[0] >> 4U)) || (17U != pucData[9]) ||
        (zHeader < 20U) || (zHeader + 8U + NATIVE_APP_PROBE_LENGTH != zLength) ||
        (ReadNativeAppTestUint16(pucData + 2U) != zLength) ||
        (0U != (ReadNativeAppTestUint16(pucData + 6U) & 0xbfffU)) ||
        (0 != memcmp(pucData + 12U, pucSource, 4U)) ||
        (0 != memcmp(pucData + 16U, pucDestination, 4U))) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    for (zIndex = 0U; zIndex < zHeader; zIndex += 2U) {
        uiChecksum += ReadNativeAppTestUint16(pucData + zIndex);
    }
    while (uiChecksum > UINT16_MAX) {
        uiChecksum = (uiChecksum & UINT16_MAX) + (uiChecksum >> 16U);
    }
    if ((UINT16_MAX != uiChecksum) ||
        (NATIVE_APP_PROBE_PORT != ReadNativeAppTestUint16(pucData + zHeader)) ||
        (NATIVE_APP_PROBE_PORT != ReadNativeAppTestUint16(pucData + zHeader + 2U)) ||
        (8U + NATIVE_APP_PROBE_LENGTH !=
         ReadNativeAppTestUint16(pucData + zHeader + 4U)) ||
        (0 != memcmp(pucData + zHeader + 8U, pucProbe, NATIVE_APP_PROBE_LENGTH))) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    return IPSEC_OK;
}
