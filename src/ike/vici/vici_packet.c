#include "vici_internal.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

static IpsecError_t ReserveViciBuffer(
    ViciBuffer_t *pBuffer,
    uint32_t uiAdditionalLength)
{
    uint32_t uiRequiredLength;
    uint32_t uiNewCapacity;
    uint8_t *pucNewData;
    IpsecError_t eError = IPSEC_OK;

    if (NULL == pBuffer) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (uiAdditionalLength > (UINT32_MAX - pBuffer->uiLength)) {
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        uiRequiredLength = pBuffer->uiLength + uiAdditionalLength;
        if (VICI_MAX_SEGMENT_LENGTH < uiRequiredLength) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else if (pBuffer->uiCapacity >= uiRequiredLength) {
            /* Existing storage is sufficient. */
        }
        else {
            uiNewCapacity = (0U == pBuffer->uiCapacity) ? 64U : pBuffer->uiCapacity;
            while (uiNewCapacity < uiRequiredLength) {
                if (uiNewCapacity > (VICI_MAX_SEGMENT_LENGTH / 2U)) {
                    uiNewCapacity = VICI_MAX_SEGMENT_LENGTH;
                }
                else {
                    uiNewCapacity *= 2U;
                }
            }

            pucNewData = (uint8_t *)realloc(pBuffer->pucData, uiNewCapacity);
            if (NULL == pucNewData) {
                eError = IPSEC_ERR_NO_MEMORY;
            }
            else {
                pBuffer->pucData = pucNewData;
                pBuffer->uiCapacity = uiNewCapacity;
            }
        }
    }

    return eError;
}

IpsecError_t InitializeViciBuffer(
    ViciBuffer_t *pBuffer,
    uint32_t uiInitialCapacity,
    bool bSensitive)
{
    IpsecError_t eError;

    if ((NULL == pBuffer) || (VICI_MAX_SEGMENT_LENGTH < uiInitialCapacity)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pBuffer, 0, sizeof(*pBuffer));
        pBuffer->bSensitive = bSensitive;
        eError = ReserveViciBuffer(pBuffer, uiInitialCapacity);
    }

    return eError;
}

void DestroyViciBuffer(ViciBuffer_t *pBuffer)
{
    if (NULL != pBuffer) {
        if (pBuffer->bSensitive && (NULL != pBuffer->pucData)) {
            SecureZeroIpsec(pBuffer->pucData, pBuffer->uiCapacity);
        }
        else {
            /* Non-sensitive buffers do not require a wipe. */
        }
        free(pBuffer->pucData);
        memset(pBuffer, 0, sizeof(*pBuffer));
    }
    else {
        /* NULL destruction is safe. */
    }
}

IpsecError_t AppendViciBuffer(
    ViciBuffer_t *pBuffer,
    const void *pvData,
    uint32_t uiLength)
{
    IpsecError_t eError;

    if ((NULL == pBuffer) || ((NULL == pvData) && (0U != uiLength))) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ReserveViciBuffer(pBuffer, uiLength);
        if ((IPSEC_OK == eError) && (0U < uiLength)) {
            memcpy(pBuffer->pucData + pBuffer->uiLength, pvData, uiLength);
            pBuffer->uiLength += uiLength;
        }
        else {
            /* Preserve reserve result or append an empty value. */
        }
    }

    return eError;
}

static IpsecError_t AppendViciByte(ViciBuffer_t *pBuffer, uint8_t ucValue)
{
    return AppendViciBuffer(pBuffer, &ucValue, sizeof(ucValue));
}

static IpsecError_t AppendViciName(ViciBuffer_t *pBuffer, const char *pcName)
{
    size_t zLength;
    uint8_t ucLength;
    IpsecError_t eError;

    if (NULL == pcName) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        zLength = strnlen(pcName, (size_t)UINT8_MAX + 1U);
        if ((0U == zLength) || (UINT8_MAX < zLength)) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            ucLength = (uint8_t)zLength;
            eError = AppendViciByte(pBuffer, ucLength);
            if (IPSEC_OK == eError) {
                eError = AppendViciBuffer(pBuffer, pcName, ucLength);
            }
            else {
                /* Preserve buffer error. */
            }
        }
    }

    return eError;
}

IpsecError_t AddViciSectionStart(ViciBuffer_t *pBuffer, const char *pcName)
{
    IpsecError_t eError;

    eError = AppendViciByte(pBuffer, (uint8_t)VICI_ELEMENT_SECTION_START);
    if (IPSEC_OK == eError) {
        eError = AppendViciName(pBuffer, pcName);
    }
    else {
        /* Preserve buffer error. */
    }
    return eError;
}

IpsecError_t AddViciSectionEnd(ViciBuffer_t *pBuffer)
{
    return AppendViciByte(pBuffer, (uint8_t)VICI_ELEMENT_SECTION_END);
}

IpsecError_t AddViciKeyValue(
    ViciBuffer_t *pBuffer,
    const char *pcName,
    const void *pvValue,
    uint32_t uiValueLength)
{
    uint16_t usNetworkLength;
    IpsecError_t eError;

    if (((NULL == pvValue) && (0U != uiValueLength)) ||
        (UINT16_MAX < uiValueLength)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = AppendViciByte(pBuffer, (uint8_t)VICI_ELEMENT_KEY_VALUE);
        if (IPSEC_OK == eError) {
            eError = AppendViciName(pBuffer, pcName);
        }
        else {
            /* Preserve buffer error. */
        }
        if (IPSEC_OK == eError) {
            usNetworkLength = htons((uint16_t)uiValueLength);
            eError = AppendViciBuffer(pBuffer, &usNetworkLength,
                                      sizeof(usNetworkLength));
        }
        else {
            /* Preserve buffer error. */
        }
        if (IPSEC_OK == eError) {
            eError = AppendViciBuffer(pBuffer, pvValue, uiValueLength);
        }
        else {
            /* Preserve buffer error. */
        }
    }

    return eError;
}

IpsecError_t AddViciKeyValueString(
    ViciBuffer_t *pBuffer,
    const char *pcName,
    const char *pcValue)
{
    size_t zLength;
    IpsecError_t eError;

    if (NULL == pcValue) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        zLength = strnlen(pcValue, (size_t)UINT16_MAX + 1U);
        if (UINT16_MAX < zLength) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            eError = AddViciKeyValue(pBuffer, pcName, pcValue,
                                     (uint32_t)zLength);
        }
    }
    return eError;
}

IpsecError_t AddViciListStart(ViciBuffer_t *pBuffer, const char *pcName)
{
    IpsecError_t eError;

    eError = AppendViciByte(pBuffer, (uint8_t)VICI_ELEMENT_LIST_START);
    if (IPSEC_OK == eError) {
        eError = AppendViciName(pBuffer, pcName);
    }
    else {
        /* Preserve buffer error. */
    }
    return eError;
}

IpsecError_t AddViciListItem(
    ViciBuffer_t *pBuffer,
    const void *pvValue,
    uint32_t uiValueLength)
{
    uint16_t usNetworkLength;
    IpsecError_t eError;

    if (((NULL == pvValue) && (0U != uiValueLength)) ||
        (UINT16_MAX < uiValueLength)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = AppendViciByte(pBuffer, (uint8_t)VICI_ELEMENT_LIST_ITEM);
        if (IPSEC_OK == eError) {
            usNetworkLength = htons((uint16_t)uiValueLength);
            eError = AppendViciBuffer(pBuffer, &usNetworkLength,
                                      sizeof(usNetworkLength));
        }
        else {
            /* Preserve buffer error. */
        }
        if (IPSEC_OK == eError) {
            eError = AppendViciBuffer(pBuffer, pvValue, uiValueLength);
        }
        else {
            /* Preserve buffer error. */
        }
    }

    return eError;
}

IpsecError_t AddViciListItemString(ViciBuffer_t *pBuffer, const char *pcValue)
{
    size_t zLength;
    IpsecError_t eError;

    if (NULL == pcValue) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        zLength = strnlen(pcValue, (size_t)UINT16_MAX + 1U);
        if (UINT16_MAX < zLength) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            eError = AddViciListItem(pBuffer, pcValue, (uint32_t)zLength);
        }
    }
    return eError;
}

IpsecError_t AddViciListEnd(ViciBuffer_t *pBuffer)
{
    return AppendViciByte(pBuffer, (uint8_t)VICI_ELEMENT_LIST_END);
}

IpsecError_t BuildViciNamedPacket(
    ViciPacketType_t eType,
    const char *pcName,
    const ViciBuffer_t *pMessage,
    ViciBuffer_t *pPacket)
{
    IpsecError_t eError;
    bool bSensitive;

    if ((NULL == pcName) || (NULL == pPacket)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        bSensitive = (NULL != pMessage) && pMessage->bSensitive;
        eError = InitializeViciBuffer(pPacket, 64U, bSensitive);
        if (IPSEC_OK == eError) {
            eError = AppendViciByte(pPacket, (uint8_t)eType);
        }
        else {
            /* Preserve allocation error. */
        }
        if (IPSEC_OK == eError) {
            eError = AppendViciName(pPacket, pcName);
        }
        else {
            /* Preserve buffer error. */
        }
        if ((IPSEC_OK == eError) && (NULL != pMessage)) {
            eError = AppendViciBuffer(pPacket, pMessage->pucData,
                                      pMessage->uiLength);
        }
        else {
            /* Empty message or existing error. */
        }
        if (IPSEC_OK != eError) {
            DestroyViciBuffer(pPacket);
        }
        else {
            /* Packet completed. */
        }
    }

    return eError;
}

IpsecError_t DecodeViciPacket(
    const uint8_t *pucPacket,
    uint32_t uiPacketLength,
    ViciPacketView_t *pView)
{
    uint32_t uiOffset = 1U;
    bool bNamed;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pucPacket) || (NULL == pView) || (1U > uiPacketLength)) {
        eError = IPSEC_ERR_VICI_PROTOCOL;
    }
    else if ((uint8_t)VICI_PACKET_EVENT < pucPacket[0]) {
        eError = IPSEC_ERR_VICI_PROTOCOL;
    }
    else {
        memset(pView, 0, sizeof(*pView));
        pView->eType = (ViciPacketType_t)pucPacket[0];
        bNamed = (VICI_PACKET_COMMAND_REQUEST == pView->eType) ||
                 (VICI_PACKET_EVENT_REGISTER == pView->eType) ||
                 (VICI_PACKET_EVENT_UNREGISTER == pView->eType) ||
                 (VICI_PACKET_EVENT == pView->eType);

        if (bNamed) {
            if (uiOffset >= uiPacketLength) {
                eError = IPSEC_ERR_VICI_PROTOCOL;
            }
            else {
                pView->ucNameLength = pucPacket[uiOffset];
                uiOffset++;
                if ((0U == pView->ucNameLength) ||
                    (pView->ucNameLength > (uiPacketLength - uiOffset))) {
                    eError = IPSEC_ERR_VICI_PROTOCOL;
                }
                else {
                    pView->pucName = pucPacket + uiOffset;
                    uiOffset += pView->ucNameLength;
                }
            }
        }
        else {
            /* Unnamed packet. */
        }

        if (IPSEC_OK == eError) {
            pView->pucMessage = pucPacket + uiOffset;
            pView->uiMessageLength = uiPacketLength - uiOffset;
        }
        else {
            /* Preserve protocol error. */
        }
    }

    return eError;
}
