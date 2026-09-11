#include "../internal/ipsec_internal.h"
#include "../ike/vici/vici_internal.h"

static bool IsIpsecApplicationConnectionSupported(
    const IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig)
{
    bool bSupported = true;

    if (IPSEC_PACKET_PATH_APPLICATION ==
        pContext->Datapath.Config.eProtectedPacketPath) {
        bSupported = !pConfig->bForceUdpEncapsulation &&
            !pConfig->bEnableMobike &&
            (1U == pConfig->LocalAddresses.uiCount) &&
            (1U == pConfig->RemoteAddresses.uiCount);
    }
    else {
        /* SYSTEM packet paths retain the complete VICI configuration range. */
    }
    return bSupported;
}

static void RollbackIpsecConnectionPaths(
    IpsecContext_t *pContext,
    const char *pcName,
    bool bProtectedPeerAdded,
    bool bPlainPeerAdded)
{
    if (bPlainPeerAdded) {
        IpsecError_t eCleanupError =
            UnregisterIpsecPlainPeerInternal(pContext, pcName);

        if (IPSEC_OK != eCleanupError) {
            LogIpsec(pContext, IPSEC_LOG_WARNING,
                "plain APPLICATION rollback failed for %s: %s",
                pcName, GetIpsecErrorString(eCleanupError));
        }
        else {
            /* Plain path registration was rolled back. */
        }
    }
    else {
        /* No plain path registration was owned by this operation. */
    }

    if (bProtectedPeerAdded) {
        IpsecError_t eCleanupError =
            UnregisterIpsecProtectedPeerInternal(pContext, pcName);

        if (IPSEC_OK != eCleanupError) {
            LogIpsec(pContext, IPSEC_LOG_WARNING,
                "protected APPLICATION rollback failed for %s: %s",
                pcName, GetIpsecErrorString(eCleanupError));
        }
        else {
            /* Protected path registration was rolled back. */
        }
    }
    else {
        /* No protected path registration was owned by this operation. */
    }
}

IpsecError_t AddIpsecConnection(
    IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig)
{
    bool bProtectedPeerAdded = false;
    bool bPlainPeerAdded = false;
    IpsecError_t eError;

    if (NULL == pContext) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ValidateViciConnectionConfigInternal(pConfig);
    }
    if ((IPSEC_OK == eError) &&
        !IsIpsecApplicationConnectionSupported(pContext, pConfig)) {
        eError = IPSEC_ERR_NOT_SUPPORTED;
    }
    else {
        /* Preserve validation result. */
    }
    if (IPSEC_OK == eError) {
        eError = RegisterIpsecProtectedPeerInternal(
            pContext, pConfig, &bProtectedPeerAdded);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = RegisterIpsecPlainPeerInternal(
            pContext, pConfig, &bPlainPeerAdded);
    }
    else {
        /* Preserve protected path registration error. */
    }
    if (IPSEC_OK == eError) {
        eError = LoadViciConnectionInternal(pContext, pConfig);
    }
    else {
        /* Preserve path registration error. */
    }
    if ((IPSEC_OK != eError) &&
        (bProtectedPeerAdded || bPlainPeerAdded)) {
        RollbackIpsecConnectionPaths(
            pContext, pConfig->pcName,
            bProtectedPeerAdded, bPlainPeerAdded);
    }
    else {
        /* Loaded connection retains its registered packet paths. */
    }
    return eError;
}

IpsecError_t RemoveIpsecConnection(
    IpsecContext_t *pContext,
    const char *pcName)
{
    IpsecError_t eError = UnloadViciConnectionInternal(pContext, pcName);

    if (IPSEC_OK == eError) {
        IpsecError_t ePlainError =
            UnregisterIpsecPlainPeerInternal(pContext, pcName);
        IpsecError_t eProtectedError =
            UnregisterIpsecProtectedPeerInternal(pContext, pcName);

        eError = (IPSEC_OK != ePlainError) ? ePlainError : eProtectedError;
    }
    else {
        /* Keep local filters while daemon unload completion is uncertain. */
    }
    return eError;
}
