#include "../internal/ipsec_internal.h"
#include "../ike/vici/vici_internal.h"

#include <stdlib.h>
#include <string.h>

static IpsecError_t VerifyIpsecDaemon(IpsecContext_t *pContext)
{
    ViciBuffer_t Request = {0};
    ViciCommandResult_t Result = {0};
    IpsecError_t eError;

    eError = InitializeViciBuffer(&Request, 1U, false);
    if (IPSEC_OK == eError) {
        eError = ExecuteViciCommand(pContext, "version", &Request, NULL, NULL,
                                    NULL, NULL, &Result);
    }
    else {
        /* Preserve allocation error. */
    }
    DestroyViciBuffer(&Request);
    return eError;
}

static IpsecError_t ConnectDefaultIpsecSocket(IpsecContext_t *pContext)
{
    static const char *const apcSocketPaths[] = {
        "/run/charon.vici",
        "/var/run/charon.vici"
    };
    IpsecError_t eError = IPSEC_ERR_DAEMON_NOT_RUNNING;
    size_t zIndex;
    bool bPermissionDenied = false;

    for (zIndex = 0U; zIndex < (sizeof(apcSocketPaths) / sizeof(apcSocketPaths[0]));
         zIndex++) {
        eError = CopyIpsecString(
            pContext->acViciSocketPath,
            sizeof(pContext->acViciSocketPath),
            (const uint8_t *)apcSocketPaths[zIndex],
            strlen(apcSocketPaths[zIndex]));
        if (IPSEC_OK == eError) {
            eError = ConnectViciTransport(pContext);
            if (IPSEC_OK == eError) {
                break;
            }
            else if (IPSEC_ERR_PERMISSION == eError) {
                bPermissionDenied = true;
                DisconnectViciTransport(pContext);
            }
            else {
                DisconnectViciTransport(pContext);
            }
        }
        else {
            break;
        }
    }

    if ((IPSEC_OK != eError) && bPermissionDenied) {
        eError = IPSEC_ERR_PERMISSION;
    }
    else if (IPSEC_OK != eError) {
        eError = IPSEC_ERR_DAEMON_NOT_RUNNING;
    }
    else {
        /* Preserve success or permission failure. */
    }

    return eError;
}

IpsecError_t InitializeIpsec(
    IpsecContext_t **ppContext,
    const IpsecConfig_t *pConfig)
{
    IpsecContext_t *pContext = NULL;
    IpsecConfig_t DefaultConfig;
    IpsecError_t eError;

    memset(&DefaultConfig, 0, sizeof(DefaultConfig));
    DefaultConfig.uiStructSize = sizeof(DefaultConfig);

    if (NULL == ppContext) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        *ppContext = NULL;
        if (NULL == pConfig) {
            pConfig = &DefaultConfig;
        }
        else {
            /* Use caller configuration. */
        }

        if (sizeof(IpsecConfig_t) != pConfig->uiStructSize) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            pContext = (IpsecContext_t *)calloc(1U, sizeof(*pContext));
            if (NULL == pContext) {
                eError = IPSEC_ERR_NO_MEMORY;
            }
            else {
                eError = InitializeIpsecContextState(pContext, pConfig);
            }
        }
    }

    if ((IPSEC_OK == eError) && ('\0' == pContext->acViciSocketPath[0])) {
        eError = ConnectDefaultIpsecSocket(pContext);
    }
    else if (IPSEC_OK == eError) {
        eError = ConnectViciTransport(pContext);
    }
    else {
        /* Preserve initialization error. */
    }

    if (IPSEC_OK == eError) {
        eError = VerifyIpsecDaemon(pContext);
    }
    else {
        /* Connection failed. */
    }

    if (IPSEC_OK == eError) {
        *ppContext = pContext;
        LogIpsec(pContext, IPSEC_LOG_INFO, "connected to charon VICI socket %s",
                 pContext->acViciSocketPath);
    }
    else if (NULL != pContext) {
        DisconnectViciTransport(pContext);
        if (pContext->bCommandMutexInitialized) {
            (void)pthread_mutex_destroy(&pContext->CommandMutex);
            pContext->bCommandMutexInitialized = false;
        }
        else {
            /* Mutex was not initialized. */
        }
        SecureZeroIpsec(pContext, sizeof(*pContext));
        free(pContext);
    }
    else {
        /* No context to release. */
    }

    return eError;
}

void DeinitializeIpsec(IpsecContext_t *pContext)
{
    if (NULL != pContext) {
        if (0 == pthread_mutex_lock(&pContext->CommandMutex)) {
            DisconnectViciTransport(pContext);
            (void)pthread_mutex_unlock(&pContext->CommandMutex);
        }
        else {
            DisconnectViciTransport(pContext);
        }
        if (pContext->bCommandMutexInitialized) {
            (void)pthread_mutex_destroy(&pContext->CommandMutex);
            pContext->bCommandMutexInitialized = false;
        }
        else {
            /* Mutex was not initialized. */
        }
        SecureZeroIpsec(pContext, sizeof(*pContext));
        free(pContext);
    }
    else {
        /* NULL deinitialization is safe. */
    }
}
