#include "application_protected_internal.h"

bool IsIpsecProtectedTunControlPacket(const uint8_t *pucData, size_t zLength)
{
    size_t zOffset = 40U;
    size_t zIndex;
    size_t zIcmpLength;
    uint32_t uiChecksum;
    uint8_t ucType;
    bool bUnspecified = true;
    bool bRouterAlert = false;

    if ((NULL == pucData) || (zLength < 48U) ||
        (zLength > IPSEC_PROTECTED_PACKET_CAPACITY) ||
        (6U != (pucData[0] >> 4U)) ||
        (zLength - 40U != (((size_t)pucData[4] << 8U) | pucData[5])) ||
        (0xffU != pucData[24]) || (2U != pucData[25])) {
        return false;
    }
    for (zIndex = 8U; zIndex < 24U; zIndex++) {
        bUnspecified = bUnspecified && (0U == pucData[zIndex]);
    }
    if (!bUnspecified && ((0xfeU != pucData[8]) ||
                          (0x80U != (pucData[9] & 0xc0U)))) {
        return false;
    }
    if (0U == pucData[6]) {
        /* Linux MLD uses a Hop-by-Hop Router Alert. Accept only padding and
         * Router Alert (MLD value 0), not arbitrary extension-header chains. */
        zOffset += ((size_t)pucData[41] + 1U) * 8U;
        if ((zOffset + 8U > zLength) || (58U != pucData[40])) {
            return false;
        }
        for (zIndex = 42U; zIndex < zOffset;) {
            uint8_t ucOption = pucData[zIndex++];
            size_t zOptionLength;
            if (0U == ucOption) {
                continue;
            }
            if (zIndex >= zOffset) {
                return false;
            }
            zOptionLength = pucData[zIndex++];
            if (zOptionLength > zOffset - zIndex) {
                return false;
            }
            if ((5U == ucOption) && (2U == zOptionLength) &&
                (0U == pucData[zIndex]) && (0U == pucData[zIndex + 1U])) {
                bRouterAlert = true;
            }
            else if (1U != ucOption) {
                return false;
            }
            zIndex += zOptionLength;
        }
    }
    else if (58U != pucData[6]) {
        return false; /* Includes ESP, UDP and fragmented IPv6. */
    }
    ucType = pucData[zOffset];
    zIcmpLength = zLength - zOffset;
    if (0U != pucData[zOffset + 1U]) {
        return false;
    }
    if ((133U == ucType) || (135U == ucType) || (136U == ucType)) {
        if ((40U != zOffset) || (255U != pucData[7]) ||
            (zIcmpLength < ((133U == ucType) ? 8U : 24U))) {
            return false;
        }
    }
    else if ((131U == ucType) || (132U == ucType) || (143U == ucType)) {
        if (!bRouterAlert || (1U != pucData[7]) ||
            (zIcmpLength < ((143U == ucType) ? 8U : 24U))) {
            return false;
        }
    }
    else {
        return false;
    }
    /* Verify the ICMPv6 pseudo-header checksum before classifying as control.
     * No payload is exposed or forwarded by this classifier. */
    uiChecksum = (uint32_t)zIcmpLength + 58U;
    for (zIndex = 8U; zIndex < 40U; zIndex += 2U) {
        uiChecksum += ((uint32_t)pucData[zIndex] << 8U) | pucData[zIndex + 1U];
    }
    for (zIndex = zOffset; zIndex < zLength; zIndex += 2U) {
        uiChecksum += (uint32_t)pucData[zIndex] << 8U;
        if (zIndex + 1U < zLength) {
            uiChecksum += pucData[zIndex + 1U];
        }
    }
    while (uiChecksum > UINT16_MAX) {
        uiChecksum = (uiChecksum & UINT16_MAX) + (uiChecksum >> 16U);
    }
    return UINT16_MAX == uiChecksum;
}

IpsecError_t ValidateIpsecProtectedPacket(const IpsecProtectedPacket_t *pPacket)
{
    const uint8_t *pucData;
    size_t zHeader;
    uint32_t uiChecksum = 0U;
    size_t zIndex;
    if ((NULL == pPacket) || (sizeof(*pPacket) != pPacket->uiStructSize) ||
        (NULL == pPacket->pucData) || (pPacket->zLength > pPacket->zCapacity) ||
        (pPacket->zLength > IPSEC_PROTECTED_PACKET_CAPACITY)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (IPSEC_PROTECTED_PACKET_RAW_ESP != pPacket->eType) {
        return IPSEC_ERR_PACKET_TYPE;
    }
    if (pPacket->zLength < 20U) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    pucData = pPacket->pucData;
    if ((4U != (pucData[0] >> 4U)) || (50U != pucData[9])) {
        return IPSEC_ERR_PACKET_TYPE;
    }
    zHeader = (size_t)(pucData[0] & 0x0fU) * 4U;
    if ((zHeader < 20U) || (zHeader + 8U >= pPacket->zLength) ||
        (pPacket->zLength != (((size_t)pucData[2] << 8U) | pucData[3]))) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    if ((0U != (pucData[6] & 0xbfU)) || (0U != pucData[7])) {
        /* Fragmentation and reserved flag are not part of this packet API. */
        return IPSEC_ERR_PACKET_TYPE;
    }
    for (zIndex = 0U; zIndex < zHeader; zIndex += 2U) {
        uiChecksum += ((uint32_t)pucData[zIndex] << 8U) | pucData[zIndex + 1U];
    }
    while (uiChecksum > UINT16_MAX) {
        uiChecksum = (uiChecksum & UINT16_MAX) + (uiChecksum >> 16U);
    }
    if ((UINT16_MAX != uiChecksum) ||
        (0U == (pucData[zHeader] | pucData[zHeader + 1U] |
                pucData[zHeader + 2U] | pucData[zHeader + 3U]))) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    /* Cipher-specific IV/tag lengths and replay/authentication belong to the
     * installed SA's backend, not this unauthenticated framing validator.
     */
    return IPSEC_OK;
}
