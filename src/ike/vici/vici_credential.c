#include "vici_internal.h"

#include <string.h>

#define IPSEC_PSK_MAX_LENGTH 65535U
#define IPSEC_PSK_MAX_OWNERS 32U

static IpsecError_t ValidateIpsecPskId(const char *pcCredentialId)
{
    size_t zLength;

    if (NULL == pcCredentialId) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        zLength = strnlen(pcCredentialId, (size_t)UINT8_MAX + 1U);
    }
    if ((0U == zLength) || (UINT8_MAX < zLength)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        return IPSEC_OK;
    }
}

static IpsecError_t ValidateIpsecPsk(const IpsecPsk_t *pPsk)
{
    uint32_t uiIndex;
    size_t zLength;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pPsk) || (sizeof(IpsecPsk_t) != pPsk->uiStructSize) ||
        (NULL == pPsk->pucData) || (0U == pPsk->uiDataLength) ||
        (IPSEC_PSK_MAX_LENGTH < pPsk->uiDataLength) ||
        (IPSEC_PSK_MAX_OWNERS < pPsk->Owners.uiCount) ||
        ((0U < pPsk->Owners.uiCount) && (NULL == pPsk->Owners.ppcItems))) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        if (NULL != pPsk->pcId) {
            eError = ValidateIpsecPskId(pPsk->pcId);
        }
        else {
            /* A shared key identifier is optional. */
        }
        for (uiIndex = 0U;
             (uiIndex < pPsk->Owners.uiCount) && (IPSEC_OK == eError);
             uiIndex++) {
            if (NULL == pPsk->Owners.ppcItems[uiIndex]) {
                eError = IPSEC_ERR_INVALID_ARGUMENT;
            }
            else {
                zLength = strnlen(pPsk->Owners.ppcItems[uiIndex],
                                  (size_t)UINT16_MAX + 1U);
                if ((0U == zLength) || (UINT16_MAX < zLength)) {
                    eError = IPSEC_ERR_INVALID_ARGUMENT;
                }
                else {
                    /* Owner is representable by VICI. */
                }
            }
        }
    }

    return eError;
}

IpsecError_t RemoveIpsecPsk(
    IpsecContext_t *pContext,
    const char *pcCredentialId)
{
    ViciBuffer_t Message = {0};
    ViciCommandResult_t Result = {0};
    IpsecError_t eError;

    if (NULL == pContext) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ValidateIpsecPskId(pcCredentialId);
    }
    if (IPSEC_OK == eError) {
        eError = InitializeViciBuffer(&Message, 64U, false);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(&Message, "id", pcCredentialId);
    }
    else {
        /* Preserve allocation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ExecuteViciCommand(pContext, "unload-shared", &Message,
                                    NULL, NULL, NULL, NULL, &Result);
    }
    else {
        /* Preserve message error. */
    }
    DestroyViciBuffer(&Message);
    return eError;
}

IpsecError_t AddIpsecPsk(
    IpsecContext_t *pContext,
    const IpsecPsk_t *pPsk)
{
    ViciBuffer_t Message = {0};
    ViciCommandResult_t Result = {0};
    uint32_t uiIndex;
    IpsecError_t eError;

    if (NULL == pContext) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ValidateIpsecPsk(pPsk);
    }
    if (IPSEC_OK == eError) {
        eError = InitializeViciBuffer(&Message,
                                     pPsk->uiDataLength + 256U, true);
    }
    else {
        /* Preserve validation error. */
    }
    if ((IPSEC_OK == eError) && (NULL != pPsk->pcId)) {
        eError = AddViciKeyValueString(&Message, "id", pPsk->pcId);
    }
    else {
        /* The identifier is optional or an error exists. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(&Message, "type", "IKE");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValue(&Message, "data", pPsk->pucData,
                                 pPsk->uiDataLength);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListStart(&Message, "owners");
    }
    else {
        /* Preserve message error. */
    }
    for (uiIndex = 0U;
         (IPSEC_OK == eError) && (uiIndex < pPsk->Owners.uiCount);
         uiIndex++) {
        eError = AddViciListItemString(&Message,
                                       pPsk->Owners.ppcItems[uiIndex]);
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListEnd(&Message);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = ExecuteViciCommand(pContext, "load-shared", &Message,
                                    NULL, NULL, NULL, NULL, &Result);
    }
    else {
        /* Preserve message error. */
    }

    DestroyViciBuffer(&Message);
    return eError;
}

IpsecError_t ClearIpsecCredentials(IpsecContext_t *pContext)
{
    ViciBuffer_t Message = {0};
    ViciCommandResult_t Result = {0};
    IpsecError_t eError;

    if (NULL == pContext) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = InitializeViciBuffer(&Message, 1U, false);
    }
    if (IPSEC_OK == eError) {
        eError = ExecuteViciCommand(pContext, "clear-creds", &Message,
                                    NULL, NULL, NULL, NULL, &Result);
    }
    else {
        /* Preserve argument or allocation error. */
    }
    DestroyViciBuffer(&Message);
    return eError;
}
