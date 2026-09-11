#include "../internal/ipsec_internal.h"

#include <string.h>
#include <time.h>

IpsecError_t InitializeIpsecContextState(
    IpsecContext_t *pContext,
    const IpsecConfig_t *pConfig)
{
    const char *pcSocketPath;
    size_t zSocketPathLength;
    IpsecError_t eError = IPSEC_OK;
    pthread_condattr_t ConditionAttributes;

    pContext->Vici.iSocket = -1;
    pContext->Vici.iTransportCancelFd = -1;
    pContext->Diagnostic.Last.uiStructSize = sizeof(pContext->Diagnostic.Last);
    pContext->Vici.uiConnectTimeoutMs = (0U == pConfig->uiConnectTimeoutMs) ?
        IPSEC_DEFAULT_CONNECT_TIMEOUT_MS : pConfig->uiConnectTimeoutMs;
    pContext->Vici.uiCommandTimeoutMs = (0U == pConfig->uiCommandTimeoutMs) ?
        IPSEC_DEFAULT_COMMAND_TIMEOUT_MS : pConfig->uiCommandTimeoutMs;
    pContext->Logger.pCallback = pConfig->pLogCallback;
    pContext->Logger.pvUserData = pConfig->pvLogUserData;

    if (0 != pthread_mutex_init(&pContext->Command.Mutex, NULL)) {
        eError = IPSEC_ERR_INTERNAL;
    }
    else {
        pContext->Command.bMutexInitialized = true;
    }

    if (IPSEC_OK == eError) {
        if (0 != pthread_condattr_init(&ConditionAttributes)) {
            eError = IPSEC_ERR_INTERNAL;
        }
        else {
            if ((0 != pthread_condattr_setclock(&ConditionAttributes, CLOCK_MONOTONIC)) ||
                (0 != pthread_cond_init(&pContext->Command.Condition, &ConditionAttributes))) {
                eError = IPSEC_ERR_INTERNAL;
            }
            else {
                pContext->Command.bConditionInitialized = true;
            }
            (void)pthread_condattr_destroy(&ConditionAttributes);
        }
    }

    if (IPSEC_OK == eError) {
        eError = InitializeIpsecCredentialState(pContext);
    }
    else {
        /* Preserve command synchronization initialization error. */
    }

    pcSocketPath = pConfig->pcViciSocketPath;
    if ((IPSEC_OK == eError) && (NULL != pcSocketPath)) {
        zSocketPathLength = strnlen(pcSocketPath,
                                    sizeof(pContext->Vici.acSocketPath));
        if ((0U == zSocketPathLength) ||
            (zSocketPathLength >= sizeof(pContext->Vici.acSocketPath))) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            memcpy(pContext->Vici.acSocketPath, pcSocketPath,
                   zSocketPathLength + 1U);
        }
    }
    else if (IPSEC_OK == eError) {
        pContext->Vici.acSocketPath[0] = '\0';
    }
    else {
        /* Preserve mutex initialization error. */
    }

    return eError;
}

void DestroyIpsecContextState(IpsecContext_t *pContext)
{
    DestroyIpsecCredentialState(pContext);
    if (pContext->Command.bConditionInitialized) {
        (void)pthread_cond_destroy(&pContext->Command.Condition);
        pContext->Command.bConditionInitialized = false;
    }
    if (pContext->Command.bMutexInitialized) {
        (void)pthread_mutex_destroy(&pContext->Command.Mutex);
        pContext->Command.bMutexInitialized = false;
    }
}

IpsecError_t GetIpsecLastDiagnostic(
    IpsecContext_t *pContext,
    IpsecDiagnostic_t *pDiagnostic)
{
    if ((NULL == pContext) || (NULL == pDiagnostic) ||
        (sizeof(*pDiagnostic) != pDiagnostic->uiStructSize)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (0 != pthread_mutex_lock(&pContext->Command.Mutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    *pDiagnostic = pContext->Diagnostic.Last;
    (void)pthread_mutex_unlock(&pContext->Command.Mutex);
    return IPSEC_OK;
}
