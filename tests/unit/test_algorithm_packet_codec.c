#include "algorithm_packet.h"

#include <stdio.h>
#include <string.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); return 1; \
} } while (0)

static void UpdateTestIpv4Checksum(uint8_t *pucPacket) {
    uint32_t uiSum = 0U;
    size_t zIndex;
    size_t zHeader = (size_t)(pucPacket[0] & 15U) * 4U;
    pucPacket[10] = 0U;
    pucPacket[11] = 0U;
    for (zIndex = 0U; zIndex < zHeader; zIndex += 2U) {
        uiSum += ((uint32_t)pucPacket[zIndex] << 8U) | pucPacket[zIndex + 1U];
    }
    while (uiSum > UINT16_MAX) {
        uiSum = (uiSum & UINT16_MAX) + (uiSum >> 16U);
    }
    uiSum = (~uiSum) & UINT16_MAX;
    pucPacket[10] = (uint8_t)(uiSum >> 8U);
    pucPacket[11] = (uint8_t)uiSum;
}

static int32_t VerifyTestEspInspection(void) {
    uint8_t aucEsp[40] = {
        0x45U, 0U, 0U, 40U, 0U, 0U, 0x40U, 0U, 64U, 50U,
        0U, 0U, 192U, 168U, 33U, 100U, 192U, 168U, 33U, 101U,
        0xc0U, 0U, 0U, 1U, 0U, 0U, 0U, 2U
    };
    NativeAppPacketEvidence_t Evidence = {0};
    size_t zIndex;
    UpdateTestIpv4Checksum(aucEsp);
    CHECK(IPSEC_OK == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 0xc0000001U, &Evidence));
    CHECK(Evidence.bEspValid && (40U == Evidence.uiEspLength));
    CHECK((0xc0000001U == Evidence.uiEspSpi) && (2U == Evidence.uiEspSequence));
    CHECK(IPSEC_ERR_PACKET_INVALID == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 1U, &Evidence));
    CHECK(!Evidence.bEspValid && (0xc0000001U == Evidence.uiEspSpi));
    CHECK(IPSEC_ERR_PACKET_INVALID == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 0U, &Evidence));
    for (zIndex = 0U; zIndex < sizeof(aucEsp); zIndex++) {
        CHECK(IPSEC_ERR_PACKET_INVALID == InspectNativeAppTestEsp(aucEsp, zIndex, 0xc0000001U, &Evidence));
    }
    CHECK(IPSEC_ERR_PACKET_INVALID == InspectNativeAppTestEsp(aucEsp, SIZE_MAX, 1U, &Evidence));
    CHECK(0U == Evidence.uiEspLength);
    aucEsp[9] = 17U;
    CHECK(IPSEC_ERR_PACKET_TYPE == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 0xc0000001U, &Evidence));
    aucEsp[9] = 50U;
    aucEsp[0] = 0x65U;
    CHECK(IPSEC_ERR_PACKET_TYPE == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 0xc0000001U, &Evidence));
    aucEsp[0] = 0x4fU;
    CHECK(IPSEC_ERR_PACKET_INVALID == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 0xc0000001U, &Evidence));
    aucEsp[0] = 0x44U;
    CHECK(IPSEC_ERR_PACKET_INVALID == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 0xc0000001U, &Evidence));
    aucEsp[0] = 0x45U;
    aucEsp[8] ^= 1U;
    CHECK(IPSEC_ERR_PACKET_INVALID == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 0xc0000001U, &Evidence));
    aucEsp[8] ^= 1U;
    aucEsp[6] = 0x20U;
    UpdateTestIpv4Checksum(aucEsp);
    CHECK(IPSEC_ERR_PACKET_INVALID == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 0xc0000001U, &Evidence));
    aucEsp[6] = 0U;
    aucEsp[7] = 1U;
    UpdateTestIpv4Checksum(aucEsp);
    CHECK(IPSEC_ERR_PACKET_INVALID == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 0xc0000001U, &Evidence));
    aucEsp[7] = 0U;
    aucEsp[27] = 0U; /* Low ESP sequence zero may occur with ESN; charon validates it. */
    UpdateTestIpv4Checksum(aucEsp);
    CHECK(IPSEC_OK == InspectNativeAppTestEsp(aucEsp, sizeof(aucEsp), 0xc0000001U, &Evidence));
    CHECK(0U == Evidence.uiEspSequence);
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == InspectNativeAppTestEsp(NULL, 40U, 1U, &Evidence));
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == InspectNativeAppTestEsp(aucEsp, 40U, 1U, NULL));
    return 0;
}

int main(void)
{
    uint8_t aucHeader[4];
    uint8_t aucNonce[16] = {1U, 2U, 3U};
    uint8_t aucProbe[NATIVE_APP_PROBE_LENGTH];
    uint8_t aucOther[NATIVE_APP_PROBE_LENGTH];
    uint8_t aucPacket[20U + 8U + NATIVE_APP_PROBE_LENGTH] = {
        0x45U, 0U, 0U, 156U, 0U, 0U, 0U, 0U, 64U, 17U,
        0U, 0U, 172U, 16U, 20U, 1U, 172U, 16U, 10U, 1U,
        0xbcU, 0x16U, 0xbcU, 0x16U, 0U, 136U, 0U, 0U
    };
    uint8_t aucSource[4] = {172U, 16U, 20U, 1U};
    uint8_t aucDestination[4] = {172U, 16U, 10U, 1U};
    uint32_t uiChecksum = 0U;
    size_t zLength;
    size_t zIndex;
    CHECK(0 == VerifyTestEspInspection());
    EncodeNativeAppTestLength(aucHeader, 1024U);
    CHECK(IPSEC_OK == DecodeNativeAppTestLength(aucHeader, 1024U, &zLength));
    CHECK(1024U == zLength);
    CHECK(IPSEC_ERR_PACKET_INVALID == DecodeNativeAppTestLength(aucHeader, 1023U, &zLength));
    CHECK(0U == zLength);
    EncodeNativeAppTestLength(aucHeader, 0U);
    CHECK(IPSEC_ERR_PACKET_INVALID == DecodeNativeAppTestLength(aucHeader, 4096U, &zLength));
    EncodeNativeAppTestLength(aucHeader, UINT32_MAX);
    CHECK(IPSEC_ERR_PACKET_INVALID == DecodeNativeAppTestLength(aucHeader, SIZE_MAX, &zLength));
    EncodeNativeAppTestLength(aucHeader, NATIVE_APP_RELAY_CAPACITY);
    CHECK(IPSEC_OK == DecodeNativeAppTestLength(aucHeader, SIZE_MAX, &zLength));
    BuildNativeAppTestProbe(aucProbe, aucNonce, "BASE-001", 1U);
    BuildNativeAppTestProbe(aucOther, aucNonce, "BASE-001", 2U);
    CHECK(0 != memcmp(aucProbe, aucOther, sizeof(aucProbe)));
    BuildNativeAppTestProbe(aucOther, aucNonce, "BASE-002", 1U);
    CHECK(0 != memcmp(aucProbe, aucOther, sizeof(aucProbe)));
    aucNonce[0]++;
    BuildNativeAppTestProbe(aucOther, aucNonce, "BASE-001", 1U);
    CHECK(0 != memcmp(aucProbe, aucOther, sizeof(aucProbe)));
    memcpy(aucPacket + 28U, aucProbe, sizeof(aucProbe));
    for (zIndex = 0U; zIndex < 20U; zIndex += 2U) {
        uiChecksum += ((uint32_t)aucPacket[zIndex] << 8U) | aucPacket[zIndex + 1U];
    }
    while (uiChecksum > UINT16_MAX) {
        uiChecksum = (uiChecksum & UINT16_MAX) + (uiChecksum >> 16U);
    }
    uiChecksum = (~uiChecksum) & UINT16_MAX;
    aucPacket[10] = (uint8_t)(uiChecksum >> 8U);
    aucPacket[11] = (uint8_t)uiChecksum;
    CHECK(IPSEC_OK == ValidateNativeAppTestPlain(aucPacket, sizeof(aucPacket),
        aucSource, aucDestination, aucProbe));
    for (zIndex = 0U; zIndex < sizeof(aucPacket); zIndex++) {
        CHECK(IPSEC_ERR_PACKET_INVALID == ValidateNativeAppTestPlain(aucPacket,
            zIndex, aucSource, aucDestination, aucProbe));
    }
    for (zIndex = 0U; zIndex < sizeof(aucPacket); zIndex++) {
        if ((26U == zIndex) || (27U == zIndex)) {
            continue; /* UDP checksum is backend/stack-validated, not the probe identity. */
        }
        aucPacket[zIndex] ^= 1U;
        CHECK(IPSEC_ERR_PACKET_INVALID == ValidateNativeAppTestPlain(aucPacket,
            sizeof(aucPacket), aucSource, aucDestination, aucProbe));
        aucPacket[zIndex] ^= 1U;
    }
    CHECK(IPSEC_ERR_PACKET_INVALID == ValidateNativeAppTestPlain(aucPacket,
        sizeof(aucPacket), aucDestination, aucSource, aucProbe));
    CHECK(IPSEC_ERR_PACKET_INVALID == ValidateNativeAppTestPlain(aucPacket,
        sizeof(aucPacket), aucSource, aucDestination, aucOther));
    (void)puts("algorithm packet codec: PASS");
    return 0;
}
