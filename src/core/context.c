#include "../internal/ipsec_internal.h"

#include <string.h>

IpsecError_t InitializeIpsecContextState(
    IpsecContext_t *pContext,
    const IpsecConfig_t *pConfig)
{
    const char *pcSocketPath;
    size_t zSocketPathLength;
    IpsecError_t eError = IPSEC_OK;

    pContext->iViciSocket = -1;
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
