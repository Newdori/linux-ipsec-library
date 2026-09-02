#include "protected_path_ops.h"

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
