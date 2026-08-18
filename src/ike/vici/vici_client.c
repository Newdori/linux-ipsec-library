#include "vici_internal.h"

#include <string.h>

typedef struct ViciResultParserContext {
    ViciCommandResult_t *pResult;
} ViciResultParserContext_t;

static bool MatchViciText(
    const uint8_t *pucText,
    uint32_t uiTextLength,
    const char *pcExpected)
{
    size_t zExpectedLength;
    bool bMatches;

    if ((NULL == pucText) || (NULL == pcExpected)) {
        bMatches = false;
    }
    else {
        zExpectedLength = strlen(pcExpected);
        bMatches = (zExpectedLength == uiTextLength) &&
                   (0 == memcmp(pucText, pcExpected, uiTextLength));
    }
    return bMatches;
}

static IpsecError_t ParseViciResultElement(
    const ViciElement_t *pElement,
    void *pvUserData)
{
    ViciResultParserContext_t *pContext =
        (ViciResultParserContext_t *)pvUserData;
    IpsecError_t eError = IPSEC_OK;

    if ((VICI_ELEMENT_KEY_VALUE == pElement->eType) &&
        MatchViciText(pElement->pucName, pElement->ucNameLength, "success")) {
        pContext->pResult->bSuccessPresent = true;
        if (MatchViciText(pElement->pucValue, pElement->usValueLength, "yes")) {
            pContext->pResult->bSuccess = true;
        }
        else if (MatchViciText(pElement->pucValue, pElement->usValueLength, "no")) {
            pContext->pResult->bSuccess = false;
        }
        else {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
    }
    else if ((VICI_ELEMENT_KEY_VALUE == pElement->eType) &&
             MatchViciText(pElement->pucName, pElement->ucNameLength, "errmsg")) {
        eError = CopyIpsecString(pContext->pResult->acErrorMessage,
                                 sizeof(pContext->pResult->acErrorMessage),
                                 pElement->pucValue,
                                 pElement->usValueLength);
        if (IPSEC_ERR_BUFFER_TOO_SMALL == eError) {
            eError = IPSEC_OK;
        }
        else {
            /* Preserve parser result. */
        }
    }
    else {
        /* Ignore unrelated command fields. */
    }

    return eError;
}

IpsecError_t ParseViciCommandResult(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    ViciCommandResult_t *pResult)
{
    ViciResultParserContext_t ParserContext;
    IpsecError_t eError;

    if (NULL == pResult) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pResult, 0, sizeof(*pResult));
        ParserContext.pResult = pResult;
        eError = ParseViciMessage(pucMessage, uiMessageLength,
                                  ParseViciResultElement, &ParserContext);
    }

    return eError;
}

static IpsecError_t ExchangeViciRegistration(
    IpsecContext_t *pContext,
    const char *pcEventName,
    bool bRegister)
{
    ViciBuffer_t Packet = {0};
    ViciBuffer_t Response = {0};
    ViciPacketView_t View;
    ViciPacketType_t eExpectedType;
    IpsecError_t eError;

    eError = BuildViciNamedPacket(bRegister ? VICI_PACKET_EVENT_REGISTER :
                                  VICI_PACKET_EVENT_UNREGISTER,
                                  pcEventName, NULL, &Packet);
    if (IPSEC_OK == eError) {
        eError = SendViciTransportPacket(pContext, &Packet);
    }
    else {
        /* Preserve packet error. */
    }
    if (IPSEC_OK == eError) {
        eError = ReceiveViciTransportPacket(pContext, &Response);
    }
    else {
        /* Preserve transport error. */
    }
    if (IPSEC_OK == eError) {
        eError = DecodeViciPacket(Response.pucData, Response.uiLength, &View);
    }
    else {
        /* Preserve receive error. */
    }
    if (IPSEC_OK == eError) {
        eExpectedType = VICI_PACKET_EVENT_CONFIRM;
        if (eExpectedType != View.eType) {
            eError = (VICI_PACKET_EVENT_UNKNOWN == View.eType) ?
                     IPSEC_ERR_NOT_SUPPORTED : IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            /* Event registration confirmed. */
        }
    }
    else {
        /* Preserve packet decode error. */
    }

    DestroyViciBuffer(&Response);
    DestroyViciBuffer(&Packet);
    return eError;
}

static IpsecError_t ReceiveViciCommandStream(
    IpsecContext_t *pContext,
    const char *pcEventName,
    ViciMessageCallback_t pEventCallback,
    ViciMessageCallback_t pResponseCallback,
    void *pvUserData,
    ViciCommandResult_t *pResult)
{
    ViciBuffer_t Packet = {0};
    ViciPacketView_t View;
    IpsecError_t eError = IPSEC_OK;
    bool bComplete = false;

    while (!bComplete && (IPSEC_OK == eError)) {
        eError = ReceiveViciTransportPacket(pContext, &Packet);
        if (IPSEC_OK == eError) {
            eError = DecodeViciPacket(Packet.pucData, Packet.uiLength, &View);
        }
        else {
            /* Preserve receive error. */
        }

        if ((IPSEC_OK == eError) && (VICI_PACKET_EVENT == View.eType)) {
            if ((NULL != pcEventName) &&
                MatchViciText(View.pucName, View.ucNameLength, pcEventName)) {
                if (NULL != pEventCallback) {
                    eError = pEventCallback(View.pucMessage,
                                            View.uiMessageLength,
                                            pvUserData);
                }
                else {
                    /* Registered event is intentionally ignored. */
                }
            }
            else {
                /* Ignore unrelated event data on this connection. */
            }
        }
        else if ((IPSEC_OK == eError) &&
                 (VICI_PACKET_COMMAND_RESPONSE == View.eType)) {
            eError = ParseViciCommandResult(View.pucMessage,
                                            View.uiMessageLength, pResult);
            if ((IPSEC_OK == eError) && (NULL != pResponseCallback)) {
                eError = pResponseCallback(View.pucMessage,
                                           View.uiMessageLength,
                                           pvUserData);
            }
            else {
                /* No custom response parser or existing error. */
            }
            bComplete = true;
        }
        else if ((IPSEC_OK == eError) &&
                 (VICI_PACKET_COMMAND_UNKNOWN == View.eType)) {
            eError = IPSEC_ERR_NOT_SUPPORTED;
        }
        else if (IPSEC_OK == eError) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            /* Preserve existing error. */
        }

        DestroyViciBuffer(&Packet);
    }

    return eError;
}

IpsecError_t ExecuteViciCommand(
    IpsecContext_t *pContext,
    const char *pcCommand,
    const ViciBuffer_t *pRequest,
    const char *pcEventName,
    ViciMessageCallback_t pEventCallback,
    ViciMessageCallback_t pResponseCallback,
    void *pvUserData,
    ViciCommandResult_t *pResult)
{
    ViciBuffer_t Packet = {0};
    ViciCommandResult_t LocalResult;
    bool bRegistered = false;
    uint64_t ullNowMs;
    IpsecError_t eError;
    IpsecError_t eUnregisterError;

    if ((NULL == pContext) || (NULL == pcCommand)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        if (NULL == pResult) {
            pResult = &LocalResult;
        }
        else {
            /* Use caller result storage. */
        }
        memset(pResult, 0, sizeof(*pResult));

        if (0 != pthread_mutex_lock(&pContext->CommandMutex)) {
            eError = IPSEC_ERR_INTERNAL;
        }
        else {
            ullNowMs = GetIpsecMonotonicMilliseconds();
            if ((0U == ullNowMs) ||
                ((UINT64_MAX - pContext->uiCommandTimeoutMs) < ullNowMs)) {
                eError = IPSEC_ERR_INTERNAL;
            }
            else {
                pContext->ullCommandDeadlineMs =
                    ullNowMs + pContext->uiCommandTimeoutMs;
                eError = ConnectViciTransport(pContext);
            }
            if ((IPSEC_OK == eError) && (NULL != pcEventName)) {
                eError = ExchangeViciRegistration(pContext, pcEventName, true);
                bRegistered = (IPSEC_OK == eError);
            }
            else {
                /* No event registration or existing connection error. */
            }

            if (IPSEC_OK == eError) {
                eError = BuildViciNamedPacket(VICI_PACKET_COMMAND_REQUEST,
                                              pcCommand, pRequest, &Packet);
            }
            else {
                /* Preserve registration error. */
            }
            if (IPSEC_OK == eError) {
                eError = SendViciTransportPacket(pContext, &Packet);
            }
            else {
                /* Preserve packet error. */
            }
            if (IPSEC_OK == eError) {
                eError = ReceiveViciCommandStream(pContext, pcEventName,
                                                  pEventCallback,
                                                  pResponseCallback,
                                                  pvUserData, pResult);
            }
            else {
                /* Preserve send error. */
            }

            if (bRegistered && (0 <= pContext->iViciSocket)) {
                eUnregisterError = ExchangeViciRegistration(pContext,
                                                            pcEventName,
                                                            false);
                if ((IPSEC_OK == eError) && (IPSEC_OK != eUnregisterError)) {
                    eError = eUnregisterError;
                }
                else {
                    /* Preserve command result. */
                }
            }
            else {
                /* Event was not registered or transport was lost. */
            }

            pContext->ullCommandDeadlineMs = 0U;
            (void)pthread_mutex_unlock(&pContext->CommandMutex);
        }

        if ((IPSEC_OK == eError) && pResult->bSuccessPresent &&
            !pResult->bSuccess) {
            LogIpsec(pContext, IPSEC_LOG_ERROR, "VICI command %s failed: %s",
                     pcCommand,
                     ('\0' != pResult->acErrorMessage[0]) ?
                     pResult->acErrorMessage : "daemon rejected request");
            eError = IPSEC_ERR_VICI_COMMAND;
        }
        else {
            /* Command succeeded or does not have a success field. */
        }
    }

    DestroyViciBuffer(&Packet);
    return eError;
}
