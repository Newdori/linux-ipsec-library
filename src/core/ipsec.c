#include "../internal/ipsec_internal.h"
#include "../ike/vici/vici_internal.h"
#include "../datapath/common/datapath_ops.h"
#include "../datapath/protected/protected_path_ops.h"
#include "../datapath/plain/plain_path_ops.h"

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
            pContext->Vici.acSocketPath,
            sizeof(pContext->Vici.acSocketPath),
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

static IpsecError_t InitializeIpsecInternal(
    IpsecContext_t **ppContext,
    const IpsecConfig_t *pConfig,
    const IpsecDatapathConfig_t *pDatapathConfig,
    bool bStrictDatapath)
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

    if (IPSEC_OK == eError) {
        eError = ConfigureIpsecDatapath(pContext, pDatapathConfig);
    }

    if ((IPSEC_OK == eError) && ('\0' == pContext->Vici.acSocketPath[0])) {
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
        eError = InitializeIpsecDatapath(pContext);
        if ((IPSEC_OK != eError) && !bStrictDatapath) {
            /* Preserve legacy control-only initialization. Datapath getters
             * retain the probe error; no backend/path readiness is implied.
             */
            eError = IPSEC_OK;
        }
    }
    if (IPSEC_OK == eError) {
        eError = InitializeIpsecProtectedPath(pContext);
    }
    if (IPSEC_OK == eError) {
        eError = InitializeIpsecPlainPath(pContext);
    }
    if (IPSEC_OK == eError) {
        *ppContext = pContext;
        LogIpsec(pContext, IPSEC_LOG_INFO, "connected to charon VICI socket %s",
                 pContext->Vici.acSocketPath);
    }
    else if (NULL != pContext) {
        DeinitializeIpsecPlainPath(pContext);
        DeinitializeIpsecProtectedPath(pContext);
        DeinitializeIpsecDatapath(pContext);
        DisconnectViciTransport(pContext);
        DestroyIpsecContextState(pContext);
        SecureZeroIpsec(pContext, sizeof(*pContext));
        free(pContext);
    }
    else {
        /* No context to release. */
    }

    return eError;
}

IpsecError_t InitializeIpsecControl(IpsecContext_t **ppContext,
                                    const IpsecConfig_t *pConfig)
{
    return InitializeIpsecInternal(ppContext, pConfig, NULL, false);
}

IpsecError_t InitializeIpsec(IpsecContext_t **ppContext,
                             const IpsecConfig_t *pConfig)
{
    return InitializeIpsecControl(ppContext, pConfig);
}

IpsecError_t InitializeIpsecWithDatapath(IpsecContext_t **ppContext,
    const IpsecConfig_t *pConfig, const IpsecDatapathConfig_t *pDatapathConfig)
{
    return InitializeIpsecInternal(ppContext, pConfig, pDatapathConfig, true);
}

void DeinitializeIpsec(IpsecContext_t *pContext)
{
    if (NULL != pContext) {
        /* Caller prevents new API entries before destruction. Registered waits
         * are cancelled and drained; each owns/closes its receiver connection. */
        CloseViciWaits(pContext);
        DeinitializeIpsecPlainPath(pContext);
        DeinitializeIpsecProtectedPath(pContext);
        DeinitializeIpsecDatapath(pContext);
        DisconnectViciTransport(pContext);
        DestroyIpsecContextState(pContext);
        SecureZeroIpsec(pContext, sizeof(*pContext));
        free(pContext);
    }
}
