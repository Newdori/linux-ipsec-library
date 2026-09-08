#include "app_internal.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

IpsecError_t InitializeNativeAppOwnedResources(NativeAppOwnedResources_t *pResources)
{
    uint8_t aucNonce[16];
    static const char acHex[] = "0123456789abcdef";
    FILE *pFile;
    size_t zRead;
    uint32_t uiIndex;
    if (NULL == pResources) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pResources, 0, sizeof(*pResources));
    pFile = fopen("/dev/urandom", "rb");
    if (NULL == pFile) {
        return IPSEC_ERR_RANDOM;
    }
    zRead = fread(aucNonce, 1U, sizeof(aucNonce), pFile);
    (void)fclose(pFile);
    if (sizeof(aucNonce) != zRead) {
        return IPSEC_ERR_RANDOM;
    }
    for (uiIndex = 0U; uiIndex < sizeof(aucNonce); uiIndex++) {
        pResources->acNonce[uiIndex * 2U] = acHex[aucNonce[uiIndex] >> 4U];
        pResources->acNonce[uiIndex * 2U + 1U] = acHex[aucNonce[uiIndex] & 15U];
    }
    return IPSEC_OK;
}

static NativeAppOwnedResource_t *FindNativeAppOwnedResource(const NativeAppConfig_t *pConfig)
{
    uint32_t uiIndex;
    if ((NULL == pConfig) || (NULL == pConfig->pOwnedResources)) {
        return NULL;
    }
    for (uiIndex = 0U; uiIndex < pConfig->pOwnedResources->uiCount; uiIndex++) {
        NativeAppOwnedResource_t *pItem = &pConfig->pOwnedResources->aItems[uiIndex];
        if ((0 == strcmp(pItem->acConnectionName, pConfig->acConnectionName)) &&
            (0 == strcmp(pItem->acLogicalCredentialId, pConfig->acCredentialId))) {
            return pItem;
        }
    }
    return NULL;
}

static IpsecError_t PrepareNativeAppOwnedResource(const NativeAppConfig_t *pConfig,
    NativeAppOwnedResource_t **ppItem)
{
    NativeAppOwnedResources_t *pResources;
    NativeAppOwnedResource_t *pItem;
    size_t zConnection, zChild, zCredential;
    int32_t iLength;
    if ((NULL == pConfig) || (NULL == ppItem) ||
        (NULL == pConfig->pOwnedResources)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pResources = pConfig->pOwnedResources;
    if (pResources->bClosing) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    zConnection = strnlen(pConfig->acConnectionName, IPSEC_NAME_LENGTH);
    zChild = strnlen(pConfig->acChildName, IPSEC_NAME_LENGTH);
    zCredential = strnlen(pConfig->acCredentialId, IPSEC_NAME_LENGTH);
    if ((0U == zConnection) || (zConnection >= IPSEC_NAME_LENGTH) ||
        (0U == zChild) || (zChild >= IPSEC_NAME_LENGTH) ||
        (zCredential >= IPSEC_NAME_LENGTH) || (0U == pConfig->uiTimeoutMs) ||
        (32U != strnlen(pResources->acNonce, sizeof(pResources->acNonce)))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pItem = FindNativeAppOwnedResource(pConfig);
    if (NULL == pItem) {
        if (pResources->uiCount >= NATIVE_APP_PEER_CAPACITY + 1U) {
            return IPSEC_ERR_RESOURCE_CONFLICT;
        }
        pItem = &pResources->aItems[pResources->uiCount];
        memset(pItem, 0, sizeof(*pItem));
        memcpy(pItem->acConnectionName, pConfig->acConnectionName, zConnection + 1U);
        memcpy(pItem->acLogicalCredentialId, pConfig->acCredentialId, zCredential + 1U);
        /* The configured ID is a logical name. A private daemon ID prevents
         * replacement/removal of another process's shared credential. */
        iLength = snprintf(pItem->acDaemonCredentialId, sizeof(pItem->acDaemonCredentialId),
            "ipsec-app-%s-%" PRIu32, pResources->acNonce, pResources->uiCount);
        if ((iLength < 0) || ((size_t)iLength >= sizeof(pItem->acDaemonCredentialId))) {
            return IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        pResources->uiCount++;
    }
    memcpy(pItem->acChildName, pConfig->acChildName, zChild + 1U);
    pItem->uiTimeoutMs = pConfig->uiTimeoutMs;
    *ppItem = pItem;
    return IPSEC_OK;
}

static IpsecError_t QueryNativeAppConnectionPresent(IpsecContext_t *pContext,
    const char *pcName, bool *pbPresent)
{
    IpsecConnectionList_t List = {0};
    IpsecError_t eError = GetIpsecConnections(pContext, &List);
    uint32_t uiIndex;
    *pbPresent = false;
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
            if (0 == strcmp(pcName, List.pItems[uiIndex].acName)) {
                *pbPresent = true;
                break;
            }
        }
    }
    FreeIpsecConnectionList(&List);
    return eError;
}

IpsecError_t AddNativeAppConnection(IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig, const IpsecConnectionConfig_t *pConnection)
{
    NativeAppOwnedResource_t *pItem = NULL;
    IpsecError_t eError;
    bool bPresent = false;
    bool bSaPresent = false;
    if ((NULL == pContext) || (NULL == pConnection) || (NULL == pConnection->pcName) ||
        (NULL == pConfig) || (0 != strcmp(pConnection->pcName, pConfig->acConnectionName))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    eError = PrepareNativeAppOwnedResource(pConfig, &pItem);
    if (IPSEC_OK != eError) {
        return eError;
    }
    if (!pItem->bConnectionOwned) {
        uint32_t uiIndex;
        /* A different logical credential may refer to a previously owned name. */
        for (uiIndex = 0U; uiIndex < pConfig->pOwnedResources->uiCount; uiIndex++) {
            const NativeAppOwnedResource_t *pOther = &pConfig->pOwnedResources->aItems[uiIndex];
            if (pOther->bConnectionOwned &&
                (0 == strcmp(pOther->acConnectionName, pItem->acConnectionName))) {
                pItem->bConnectionOwned = true;
            }
        }
    }
    if (!pItem->bConnectionOwned) {
        eError = QueryNativeAppConnectionPresent(pContext, pItem->acConnectionName, &bPresent);
        if (IPSEC_OK == eError) {
            eError = GetNativeAppConnectionSaStatus(pContext, pItem->acConnectionName, &bSaPresent);
        }
        if ((IPSEC_OK == eError) && (bPresent || bSaPresent)) {
            (void)fprintf(stderr, "connection '%s' already exists outside this app session; "
                "automatic ownership refused\n", pItem->acConnectionName);
            eError = IPSEC_ERR_RESOURCE_CONFLICT;
        }
    }
    if (IPSEC_OK == eError) {
        /* Reserve before send: an uncertain reply must not lose the cleanup target.
         * Names must remain exclusive; VICI has no atomic owner/reservation API. */
        pItem->bConnectionOwned = true;
        eError = AddIpsecConnection(pContext, pConnection);
    }
    return eError;
}

IpsecError_t AddNativeAppPsk(IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig, const IpsecPsk_t *pPsk)
{
    NativeAppOwnedResource_t *pItem = NULL;
    IpsecError_t eError;
    IpsecPsk_t Psk;
    if ((NULL == pContext) || (NULL == pPsk)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    eError = PrepareNativeAppOwnedResource(pConfig, &pItem);
    if (IPSEC_OK == eError) {
        Psk = *pPsk;
        Psk.pcId = pItem->acDaemonCredentialId;
        pItem->bCredentialOwned = true; /* Retain ambiguous load for cleanup. */
        eError = AddIpsecPsk(pContext, &Psk);
    }
    return eError;
}

bool HasNativeAppCredential(const NativeAppConfig_t *pConfig)
{
    NativeAppOwnedResource_t *pItem = FindNativeAppOwnedResource(pConfig);
    return (NULL != pItem) && pItem->bCredentialOwned;
}

bool HasNativeAppOwnedSaTarget(const NativeAppOwnedResources_t *pResources,
    const char *pcName, bool bChild)
{
    uint32_t uiIndex;
    if ((NULL == pResources) || (NULL == pcName) || pResources->bClosing) {
        return false;
    }
    for (uiIndex = 0U; uiIndex < pResources->uiCount; uiIndex++) {
        const NativeAppOwnedResource_t *pItem = &pResources->aItems[uiIndex];
        if (pItem->bConnectionOwned &&
            (0 == strcmp(pcName, bChild ? pItem->acChildName : pItem->acConnectionName))) {
            return true;
        }
    }
    return false;
}

const char *GetNativeAppDaemonCredentialId(const NativeAppConfig_t *pConfig)
{
    NativeAppOwnedResource_t *pItem = FindNativeAppOwnedResource(pConfig);
    return (NULL != pItem) ? pItem->acDaemonCredentialId : "<not loaded by this session>";
}

IpsecError_t RemoveNativeAppCredential(IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig)
{
    NativeAppOwnedResource_t *pItem = FindNativeAppOwnedResource(pConfig);
    IpsecError_t eError = IPSEC_OK;
    if ((NULL == pContext) || (NULL == pConfig)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if ((NULL != pItem) && pItem->bCredentialOwned) {
        eError = RemoveIpsecPsk(pContext, pItem->acDaemonCredentialId);
        if (IPSEC_OK == eError) {
            pItem->bCredentialOwned = false;
        }
    }
    return eError;
}

IpsecError_t TerminateNativeAppTargetSas(IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig)
{
    IpsecChildSaList_t Children = {0};
    IpsecControlOptions_t Control = {.uiStructSize = sizeof(Control), .eMode = IPSEC_CONTROL_WAIT};
    IpsecError_t eError;
    bool bActive = false;
    NativeAppOwnedResource_t *pOwned;
    uint32_t uiIndex;
    if ((NULL == pContext) || (NULL == pConfig)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    Control.uiTimeoutMs = pConfig->uiTimeoutMs;
    pOwned = FindNativeAppOwnedResource(pConfig);
    eError = GetIpsecChildSas(pContext, &Children);
    /* Retain reqids across retries even if the daemon SA disappears before
     * kernel removal can be confirmed. Never lose an outstanding XFRM check. */
    for (uiIndex = 0U; (NULL != pOwned) && (IPSEC_OK == eError) &&
         (uiIndex < Children.uiCount); uiIndex++) {
        const IpsecChildSaInfo_t *pChild = &Children.pItems[uiIndex];
        uint32_t uiStored;
        if ((0U == pChild->uiReqid) ||
            (0 != strcmp(pConfig->acConnectionName, pChild->acIkeName))) {
            continue;
        }
        for (uiStored = 0U; uiStored < pOwned->uiPendingReqidCount; uiStored++) {
            if (pChild->uiReqid == pOwned->auiPendingReqids[uiStored]) {
                break;
            }
        }
        if (uiStored == pOwned->uiPendingReqidCount) {
            if (uiStored >= 64U) {
                eError = IPSEC_ERR_BUFFER_TOO_SMALL;
            }
            else {
                pOwned->auiPendingReqids[pOwned->uiPendingReqidCount++] = pChild->uiReqid;
            }
        }
    }
    if (IPSEC_OK == eError) {
        eError = GetNativeAppConnectionSaStatus(pContext, pConfig->acConnectionName, &bActive);
    }
    if ((IPSEC_OK == eError) && bActive) {
        eError = TerminateIpsecIke(pContext, pConfig->acConnectionName, &Control);
        if (IPSEC_OK != eError) {
            bool bStillActive = true;
            IpsecError_t eQuery = GetNativeAppConnectionSaStatus(
                pContext, pConfig->acConnectionName, &bStillActive);
            if ((IPSEC_OK == eQuery) && !bStillActive) {
                eError = IPSEC_OK; /* Remote delete/rekey race already completed. */
            }
        }
    }
    if (IPSEC_OK == eError) {
        eError = WaitNativeAppRemoved(pContext, pConfig, 0U);
    }
    /* Preserve every observed reqid, including overlapping old/new rekey SAs. */
    for (uiIndex = 0U; (NULL == pOwned) && (uiIndex < Children.uiCount) &&
         (IPSEC_OK == eError); uiIndex++) {
        const IpsecChildSaInfo_t *pChild = &Children.pItems[uiIndex];
        if ((0U != pChild->uiReqid) &&
            (0 == strcmp(pConfig->acConnectionName, pChild->acIkeName))) {
            eError = WaitNativeAppRemoved(pContext, pConfig, pChild->uiReqid);
        }
    }
    for (uiIndex = 0U; (NULL != pOwned) && (IPSEC_OK == eError) &&
         (uiIndex < pOwned->uiPendingReqidCount); uiIndex++) {
        eError = WaitNativeAppRemoved(pContext, pConfig, pOwned->auiPendingReqids[uiIndex]);
    }
    if ((NULL != pOwned) && (IPSEC_OK == eError)) {
        pOwned->uiPendingReqidCount = 0U;
    }
    FreeIpsecChildSaList(&Children);
    return eError;
}

IpsecError_t CleanupNativeAppOwnedResources(IpsecContext_t *pContext,
    NativeAppOwnedResources_t *pResources)
{
    IpsecError_t eFirstError = IPSEC_OK;
    uint32_t uiIndex;
    if ((NULL == pContext) || (NULL == pResources)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pResources->bClosing = true;
    for (uiIndex = 0U; uiIndex < pResources->uiCount; uiIndex++) {
        NativeAppOwnedResource_t *pItem = &pResources->aItems[uiIndex];
        NativeAppConfig_t Config = {.uiTimeoutMs = pItem->uiTimeoutMs,
            .pOwnedResources = pResources};
        IpsecError_t eError = IPSEC_OK;
        const char *pcStage = "already_clean";
        uint32_t uiAttempt;
        if (!pItem->bConnectionOwned && !pItem->bCredentialOwned) {
            continue;
        }
        memcpy(Config.acConnectionName, pItem->acConnectionName, sizeof(Config.acConnectionName));
        memcpy(Config.acChildName, pItem->acChildName, sizeof(Config.acChildName));
        memcpy(Config.acCredentialId, pItem->acLogicalCredentialId, sizeof(Config.acCredentialId));
        for (uiAttempt = 0U; uiAttempt < 3U; uiAttempt++) {
            bool bPresent = false;
            eError = IPSEC_OK;
            if (pItem->bConnectionOwned) {
                pcStage = "terminate_and_wait_sa";
                eError = TerminateNativeAppTargetSas(pContext, &Config);
                if (IPSEC_OK == eError) {
                    pcStage = "unload_connection";
                    /* Invoke even when absent so an uncertain earlier unload can
                     * finish its library-side peer/filter cleanup. */
                    IpsecError_t eUnload = RemoveIpsecConnection(pContext, pItem->acConnectionName);
                    eError = QueryNativeAppConnectionPresent(pContext, pItem->acConnectionName, &bPresent);
                    if ((IPSEC_OK == eError) && (IPSEC_OK != eUnload)) {
                        eError = eUnload; /* Includes owned TC/filter teardown failures. */
                    }
                    if ((IPSEC_OK == eError) && bPresent) {
                        eError = (IPSEC_OK == eUnload) ? IPSEC_ERR_RESOURCE_CONFLICT : eUnload;
                    }
                    if (IPSEC_OK == eError) {
                        bool bActive = true;
                        eError = GetNativeAppConnectionSaStatus(pContext, pItem->acConnectionName, &bActive);
                        if ((IPSEC_OK == eError) && bActive) {
                            eError = IPSEC_ERR_RESOURCE_CONFLICT;
                        }
                    }
                    if (IPSEC_OK == eError) {
                        pItem->bConnectionOwned = false;
                    }
                }
            }
            if ((IPSEC_OK == eError) && pItem->bCredentialOwned) {
                bool bActive = true;
                pcStage = "credential_sa_check";
                eError = GetNativeAppConnectionSaStatus(pContext, pItem->acConnectionName, &bActive);
                if ((IPSEC_OK == eError) && bActive) {
                    eError = IPSEC_ERR_RESOURCE_CONFLICT;
                }
                if (IPSEC_OK == eError) {
                    pcStage = "unload_credential";
                    eError = RemoveNativeAppCredential(pContext, &Config);
                }
            }
            (void)fprintf((IPSEC_OK == eError) ? stdout : stderr,
                "shutdown peer=%s attempt=%" PRIu32 " stage=%s result=%s error=%s\n",
                pItem->acConnectionName, uiAttempt + 1U, pcStage,
                (IPSEC_OK == eError) ? "PASS" : "FAIL",
                (IPSEC_OK == eError) ? "none" : GetIpsecErrorString(eError));
            if (IPSEC_OK == eError) {
                break;
            }
        }
        if ((IPSEC_OK != eError) && (IPSEC_OK == eFirstError)) {
            eFirstError = eError;
        }
    }
    return eFirstError;
}

IpsecError_t VerifyNativeAppExitSas(IpsecContext_t *pContext)
{
    IpsecIkeSaList_t Ikes = {0};
    IpsecChildSaList_t Children = {0};
    IpsecError_t eError = GetIpsecIkeSas(pContext, &Ikes);
    uint32_t uiIndex;
    if (IPSEC_OK == eError) {
        eError = GetIpsecChildSas(pContext, &Children);
    }
    if ((IPSEC_OK == eError) && ((0U != Ikes.uiCount) || (0U != Children.uiCount))) {
        eError = IPSEC_ERR_RESOURCE_CONFLICT;
        for (uiIndex = 0U; uiIndex < Ikes.uiCount; uiIndex++) {
            (void)fprintf(stderr, "shutdown blocked: remaining IKE=%s state=%s (not auto-deleted)\n",
                Ikes.pItems[uiIndex].acName, Ikes.pItems[uiIndex].acState);
        }
        for (uiIndex = 0U; uiIndex < Children.uiCount; uiIndex++) {
            (void)fprintf(stderr, "shutdown blocked: remaining CHILD=%s parent=%s state=%s\n",
                Children.pItems[uiIndex].acName, Children.pItems[uiIndex].acIkeName,
                Children.pItems[uiIndex].acState);
        }
    }
    FreeIpsecChildSaList(&Children);
    FreeIpsecIkeSaList(&Ikes);
    return eError;
}
