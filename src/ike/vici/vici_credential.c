#include "vici_internal.h"

#include <stdlib.h>
#include <string.h>

#define IPSEC_PSK_MAX_LENGTH 65535U
#define IPSEC_PSK_MAX_OWNERS 32U
#define IPSEC_PSK_ID_CAPACITY ((size_t)UINT8_MAX + 1U)

struct IpsecOwnedCredential {
    struct IpsecOwnedCredential *pNext;
    char acId[IPSEC_PSK_ID_CAPACITY];
};

IpsecError_t InitializeIpsecCredentialState(IpsecContext_t *pContext)
{
    if (NULL == pContext) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (0 != pthread_mutex_init(&pContext->Credentials.Mutex, NULL)) {
        return IPSEC_ERR_INTERNAL;
    }
    pContext->Credentials.bMutexInitialized = true;
    return IPSEC_OK;
}

static void FreeOwnedIpsecCredentials(IpsecCredentialState_t *pState)
{
    IpsecOwnedCredential_t *pCurrent = pState->pOwned;

    while (NULL != pCurrent) {
        IpsecOwnedCredential_t *pNext = pCurrent->pNext;

        free(pCurrent);
        pCurrent = pNext;
    }
    pState->pOwned = NULL;
}

void DestroyIpsecCredentialState(IpsecContext_t *pContext)
{
    if ((NULL != pContext) && pContext->Credentials.bMutexInitialized) {
        FreeOwnedIpsecCredentials(&pContext->Credentials);
        (void)pthread_mutex_destroy(&pContext->Credentials.Mutex);
        pContext->Credentials.bMutexInitialized = false;
        pContext->Credentials.bAnonymousLoaded = false;
    }
    else {
        /* No initialized credential registry to destroy. */
    }
}

static IpsecOwnedCredential_t *FindOwnedIpsecCredential(
    IpsecCredentialState_t *pState,
    const char *pcCredentialId,
    IpsecOwnedCredential_t ***pppPreviousNext)
{
    IpsecOwnedCredential_t **ppCurrent = &pState->pOwned;

    while ((NULL != *ppCurrent) &&
           (0 != strcmp((*ppCurrent)->acId, pcCredentialId))) {
        ppCurrent = &(*ppCurrent)->pNext;
    }
    if (NULL != pppPreviousNext) {
        *pppPreviousNext = ppCurrent;
    }
    else {
        /* Caller does not need the unlink location. */
    }
    return *ppCurrent;
}

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

static IpsecError_t UnloadIpsecPskInternal(
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

static IpsecError_t LoadIpsecPskInternal(
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

static IpsecError_t ClearAllViciCredentialsInternal(
    IpsecContext_t *pContext)
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

IpsecError_t AddIpsecPsk(
    IpsecContext_t *pContext,
    const IpsecPsk_t *pPsk)
{
    IpsecOwnedCredential_t *pNew = NULL;
    IpsecOwnedCredential_t *pExisting = NULL;
    IpsecError_t eError;

    if ((NULL == pContext) ||
        !pContext->Credentials.bMutexInitialized) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ValidateIpsecPsk(pPsk);
    }
    if ((IPSEC_OK == eError) && (NULL != pPsk->pcId)) {
        pNew = (IpsecOwnedCredential_t *)calloc(1U, sizeof(*pNew));
        if (NULL == pNew) {
            eError = IPSEC_ERR_NO_MEMORY;
        }
        else {
            memcpy(pNew->acId, pPsk->pcId, strlen(pPsk->pcId) + 1U);
        }
    }
    else {
        /* Anonymous credentials do not need an ID registry node. */
    }
    if ((IPSEC_OK == eError) &&
        (0 != pthread_mutex_lock(&pContext->Credentials.Mutex))) {
        eError = IPSEC_ERR_INTERNAL;
    }
    else if (IPSEC_OK == eError) {
        if (NULL != pPsk->pcId) {
            pExisting = FindOwnedIpsecCredential(
                &pContext->Credentials, pPsk->pcId, NULL);
        }
        else {
            /* Anonymous credential ownership is tracked as a flag. */
        }
        eError = LoadIpsecPskInternal(pContext, pPsk);
        if ((IPSEC_OK == eError) && (NULL == pPsk->pcId)) {
            pContext->Credentials.bAnonymousLoaded = true;
        }
        else if ((IPSEC_OK == eError) && (NULL == pExisting)) {
            pNew->pNext = pContext->Credentials.pOwned;
            pContext->Credentials.pOwned = pNew;
            pNew = NULL;
        }
        else {
            /* Keep an existing ID node or preserve the load error. */
        }
        (void)pthread_mutex_unlock(&pContext->Credentials.Mutex);
    }
    else {
        /* Preserve validation or allocation error. */
    }
    free(pNew);
    return eError;
}

IpsecError_t RemoveIpsecPsk(
    IpsecContext_t *pContext,
    const char *pcCredentialId)
{
    IpsecOwnedCredential_t **ppOwned = NULL;
    IpsecOwnedCredential_t *pOwned = NULL;
    IpsecError_t eError;

    if ((NULL == pContext) ||
        !pContext->Credentials.bMutexInitialized) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ValidateIpsecPskId(pcCredentialId);
    }
    if ((IPSEC_OK == eError) &&
        (0 != pthread_mutex_lock(&pContext->Credentials.Mutex))) {
        eError = IPSEC_ERR_INTERNAL;
    }
    else if (IPSEC_OK == eError) {
        pOwned = FindOwnedIpsecCredential(
            &pContext->Credentials, pcCredentialId, &ppOwned);
        eError = UnloadIpsecPskInternal(pContext, pcCredentialId);
        if ((IPSEC_OK == eError) && (NULL != pOwned)) {
            *ppOwned = pOwned->pNext;
            free(pOwned);
        }
        else {
            /* Preserve an untracked ID or unload error. */
        }
        (void)pthread_mutex_unlock(&pContext->Credentials.Mutex);
    }
    else {
        /* Preserve validation error. */
    }
    return eError;
}

IpsecError_t ClearIpsecContextCredentials(IpsecContext_t *pContext)
{
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pContext) ||
        !pContext->Credentials.bMutexInitialized) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (0 != pthread_mutex_lock(&pContext->Credentials.Mutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    while ((IPSEC_OK == eError) &&
           (NULL != pContext->Credentials.pOwned)) {
        IpsecOwnedCredential_t *pOwned =
            pContext->Credentials.pOwned;

        eError = UnloadIpsecPskInternal(pContext, pOwned->acId);
        if (IPSEC_OK == eError) {
            pContext->Credentials.pOwned = pOwned->pNext;
            free(pOwned);
        }
        else {
            /* Retain this and remaining IDs for a retry. */
        }
    }
    if ((IPSEC_OK == eError) &&
        pContext->Credentials.bAnonymousLoaded) {
        eError = IPSEC_ERR_NOT_SUPPORTED;
    }
    else {
        /* Preserve an unload error or complete context cleanup. */
    }
    (void)pthread_mutex_unlock(&pContext->Credentials.Mutex);
    return eError;
}

IpsecError_t ClearAllIpsecDaemonCredentials(IpsecContext_t *pContext)
{
    IpsecError_t eError;

    if ((NULL == pContext) ||
        !pContext->Credentials.bMutexInitialized) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (0 != pthread_mutex_lock(&pContext->Credentials.Mutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    eError = ClearAllViciCredentialsInternal(pContext);
    if (IPSEC_OK == eError) {
        FreeOwnedIpsecCredentials(&pContext->Credentials);
        pContext->Credentials.bAnonymousLoaded = false;
    }
    else {
        /* Preserve registry state while daemon completion is uncertain. */
    }
    (void)pthread_mutex_unlock(&pContext->Credentials.Mutex);
    return eError;
}

IpsecError_t ClearIpsecCredentials(IpsecContext_t *pContext)
{
    return ClearAllIpsecDaemonCredentials(pContext);
}
