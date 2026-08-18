#include "vici_internal.h"

#include <arpa/inet.h>
#include <string.h>

static IpsecError_t ReadViciName(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    uint32_t *puiOffset,
    const uint8_t **ppucName,
    uint8_t *pucNameLength)
{
    uint8_t ucLength;
    IpsecError_t eError;

    if (*puiOffset >= uiMessageLength) {
        eError = IPSEC_ERR_VICI_PROTOCOL;
    }
    else {
        ucLength = pucMessage[*puiOffset];
        (*puiOffset)++;
        if ((0U == ucLength) || (ucLength > (uiMessageLength - *puiOffset))) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            *ppucName = pucMessage + *puiOffset;
            *pucNameLength = ucLength;
            *puiOffset += ucLength;
            eError = IPSEC_OK;
        }
    }

    return eError;
}

static IpsecError_t ReadViciValue(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    uint32_t *puiOffset,
    const uint8_t **ppucValue,
    uint16_t *pusValueLength)
{
    uint16_t usNetworkLength;
    uint16_t usLength;
    IpsecError_t eError;

    if ((sizeof(usNetworkLength) > (uiMessageLength - *puiOffset))) {
        eError = IPSEC_ERR_VICI_PROTOCOL;
    }
    else {
        memcpy(&usNetworkLength, pucMessage + *puiOffset,
               sizeof(usNetworkLength));
        *puiOffset += sizeof(usNetworkLength);
        usLength = ntohs(usNetworkLength);
        if (usLength > (uiMessageLength - *puiOffset)) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            *ppucValue = pucMessage + *puiOffset;
            *pusValueLength = usLength;
            *puiOffset += usLength;
            eError = IPSEC_OK;
        }
    }

    return eError;
}

IpsecError_t ParseViciMessage(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    ViciElementCallback_t pCallback,
    void *pvUserData)
{
    ViciElement_t Element;
    uint32_t uiOffset = 0U;
    uint32_t uiDepth = 0U;
    bool bListOpen = false;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pucMessage) && (0U != uiMessageLength)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        while ((uiOffset < uiMessageLength) && (IPSEC_OK == eError)) {
            memset(&Element, 0, sizeof(Element));
            Element.eType = (ViciElementType_t)pucMessage[uiOffset];
            uiOffset++;
            Element.uiDepth = uiDepth;

            switch (Element.eType) {
            case VICI_ELEMENT_SECTION_START:
                if (bListOpen || (VICI_MAX_SECTION_DEPTH <= uiDepth)) {
                    eError = IPSEC_ERR_VICI_PROTOCOL;
                }
                else {
                    eError = ReadViciName(pucMessage, uiMessageLength, &uiOffset,
                                          &Element.pucName, &Element.ucNameLength);
                    if (IPSEC_OK == eError) {
                        uiDepth++;
                        Element.uiDepth = uiDepth;
                    }
                    else {
                        /* Preserve parser error. */
                    }
                }
                break;
            case VICI_ELEMENT_SECTION_END:
                if (bListOpen || (0U == uiDepth)) {
                    eError = IPSEC_ERR_VICI_PROTOCOL;
                }
                else {
                    Element.uiDepth = uiDepth;
                    uiDepth--;
                }
                break;
            case VICI_ELEMENT_KEY_VALUE:
                if (bListOpen) {
                    eError = IPSEC_ERR_VICI_PROTOCOL;
                }
                else {
                    eError = ReadViciName(pucMessage, uiMessageLength, &uiOffset,
                                          &Element.pucName, &Element.ucNameLength);
                    if (IPSEC_OK == eError) {
                        eError = ReadViciValue(pucMessage, uiMessageLength, &uiOffset,
                                               &Element.pucValue,
                                               &Element.usValueLength);
                    }
                    else {
                        /* Preserve parser error. */
                    }
                }
                break;
            case VICI_ELEMENT_LIST_START:
                if (bListOpen) {
                    eError = IPSEC_ERR_VICI_PROTOCOL;
                }
                else {
                    eError = ReadViciName(pucMessage, uiMessageLength, &uiOffset,
                                          &Element.pucName, &Element.ucNameLength);
                    if (IPSEC_OK == eError) {
                        bListOpen = true;
                    }
                    else {
                        /* Preserve parser error. */
                    }
                }
                break;
            case VICI_ELEMENT_LIST_ITEM:
                if (!bListOpen) {
                    eError = IPSEC_ERR_VICI_PROTOCOL;
                }
                else {
                    eError = ReadViciValue(pucMessage, uiMessageLength, &uiOffset,
                                           &Element.pucValue,
                                           &Element.usValueLength);
                }
                break;
            case VICI_ELEMENT_LIST_END:
                if (!bListOpen) {
                    eError = IPSEC_ERR_VICI_PROTOCOL;
                }
                else {
                    bListOpen = false;
                }
                break;
            default:
                eError = IPSEC_ERR_VICI_PROTOCOL;
                break;
            }

            if ((IPSEC_OK == eError) && (NULL != pCallback)) {
                eError = pCallback(&Element, pvUserData);
            }
            else {
                /* Continue parsing without a callback or preserve error. */
            }
        }

        if ((IPSEC_OK == eError) && (bListOpen || (0U != uiDepth))) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            /* Message is balanced or already invalid. */
        }
    }

    return eError;
}
