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

    pContext->iViciSocket = -1;
    pContext->iTransportCancelFd = -1;
    pContext->LastDiagnostic.uiStructSize = sizeof(pContext->LastDiagnostic);
    pContext->uiConnectTimeoutMs = (0U == pConfig->uiConnectTimeoutMs) ?
        IPSEC_DEFAULT_CONNECT_TIMEOUT_MS : pConfig->uiConnectTimeoutMs;
    pContext->uiCommandTimeoutMs = (0U == pConfig->uiCommandTimeoutMs) ?
        IPSEC_DEFAULT_COMMAND_TIMEOUT_MS : pConfig->uiCommandTimeoutMs;
    pContext->pLogCallback = pConfig->pLogCallback;
    pContext->pvLogUserData = pConfig->pvLogUserData;

    if (0 != pthread_mutex_init(&pContext->CommandMutex, NULL)) {
        eError = IPSEC_ERR_INTERNAL;
    }
    else {
        pContext->bCommandMutexInitialized = true;
    }

    if (IPSEC_OK == eError) {
        if (0 != pthread_condattr_init(&ConditionAttributes)) {
            eError = IPSEC_ERR_INTERNAL;
        }
        else {
            if ((0 != pthread_condattr_setclock(&ConditionAttributes, CLOCK_MONOTONIC)) ||
                (0 != pthread_cond_init(&pContext->CommandCondition, &ConditionAttributes))) {
                eError = IPSEC_ERR_INTERNAL;
            }
            else {
                pContext->bCommandConditionInitialized = true;
            }
            (void)pthread_condattr_destroy(&ConditionAttributes);
        }
    }

    pcSocketPath = pConfig->pcViciSocketPath;
    if ((IPSEC_OK == eError) && (NULL != pcSocketPath)) {
        zSocketPathLength = strnlen(pcSocketPath,
                                    sizeof(pContext->acViciSocketPath));
        if ((0U == zSocketPathLength) ||
            (zSocketPathLength >= sizeof(pContext->acViciSocketPath))) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            memcpy(pContext->acViciSocketPath, pcSocketPath,
                   zSocketPathLength + 1U);
        }
    }
    else if (IPSEC_OK == eError) {
        pContext->acViciSocketPath[0] = '\0';
    }
    else {
        /* Preserve mutex initialization error. */
    }

    return eError;
}

void DestroyIpsecContextState(IpsecContext_t *pContext)
{
    if (pContext->bCommandConditionInitialized) {
        (void)pthread_cond_destroy(&pContext->CommandCondition);
        pContext->bCommandConditionInitialized = false;
    }
    if (pContext->bCommandMutexInitialized) {
        (void)pthread_mutex_destroy(&pContext->CommandMutex);
        pContext->bCommandMutexInitialized = false;
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
    if (0 != pthread_mutex_lock(&pContext->CommandMutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    *pDiagnostic = pContext->LastDiagnostic;
    (void)pthread_mutex_unlock(&pContext->CommandMutex);
    return IPSEC_OK;
}
