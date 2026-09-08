#include "app_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); return 1; \
} } while (0)

static const char *const gpacNames[] = {"conn-a", "conn-b", "external"};
static bool gabConnections[3];
static bool gabActive[3];
static uint32_t gauiTerminations[3];
static char gaacKeys[4][IPSEC_NAME_LENGTH];
static bool gabKeys[4];
static uint32_t guiKeyCount, guiTermFailures, guiUnloadFailures, guiKeyFailures;
static uint32_t guiReqidMask, guiUnloadCalls;
static uint32_t guiReqidWaitFailures;
static bool gbUnavailable, gbInvalidOperation, gbDisappearOnError, gbLoadUncertain;

static int32_t FindTestName(const char *pcName)
{
    int32_t iIndex;
    for (iIndex = 0; iIndex < 3; iIndex++) {
        if (0 == strcmp(pcName, gpacNames[iIndex])) {
            return iIndex;
        }
    }
    gbInvalidOperation = true;
    return -1;
}

IpsecError_t GetIpsecConnections(IpsecContext_t *pContext, IpsecConnectionList_t *pList)
{
    uint32_t uiIndex;
    (void)pContext;
    if (gbUnavailable) {
        return IPSEC_ERR_VICI_TRANSPORT;
    }
    pList->pItems = calloc(3U, sizeof(*pList->pItems));
    if (NULL == pList->pItems) {
        return IPSEC_ERR_NO_MEMORY;
    }
    for (uiIndex = 0U; uiIndex < 3U; uiIndex++) {
        if (gabConnections[uiIndex]) {
            memcpy(pList->pItems[pList->uiCount++].acName, gpacNames[uiIndex], strlen(gpacNames[uiIndex]) + 1U);
        }
    }
    return IPSEC_OK;
}

void FreeIpsecConnectionList(IpsecConnectionList_t *pList)
{
    free(pList->pItems);
    memset(pList, 0, sizeof(*pList));
}

IpsecError_t GetIpsecIkeSas(IpsecContext_t *pContext, IpsecIkeSaList_t *pList)
{
    uint32_t uiIndex;
    (void)pContext;
    if (gbUnavailable) {
        return IPSEC_ERR_VICI_TRANSPORT;
    }
    pList->pItems = calloc(3U, sizeof(*pList->pItems));
    if (NULL == pList->pItems) {
        return IPSEC_ERR_NO_MEMORY;
    }
    for (uiIndex = 0U; uiIndex < 3U; uiIndex++) {
        if (gabActive[uiIndex]) {
            IpsecIkeSaInfo_t *pIke = &pList->pItems[pList->uiCount++];
            memcpy(pIke->acName, gpacNames[uiIndex], strlen(gpacNames[uiIndex]) + 1U);
            memcpy(pIke->acState, "CONNECTING", sizeof("CONNECTING"));
            pIke->bEstablished = false;
        }
    }
    return IPSEC_OK;
}

void FreeIpsecIkeSaList(IpsecIkeSaList_t *pList)
{
    free(pList->pItems);
    memset(pList, 0, sizeof(*pList));
}

IpsecError_t GetIpsecChildSas(IpsecContext_t *pContext, IpsecChildSaList_t *pList)
{
    uint32_t uiIndex;
    (void)pContext;
    if (gbUnavailable) {
        return IPSEC_ERR_VICI_TRANSPORT;
    }
    pList->pItems = calloc(4U, sizeof(*pList->pItems));
    if (NULL == pList->pItems) {
        return IPSEC_ERR_NO_MEMORY;
    }
    for (uiIndex = 0U; uiIndex < 3U; uiIndex++) {
        if (gabActive[uiIndex]) {
            IpsecChildSaInfo_t *pChild = &pList->pItems[pList->uiCount++];
            memcpy(pChild->acName, "child", sizeof("child"));
            memcpy(pChild->acIkeName, gpacNames[uiIndex], strlen(gpacNames[uiIndex]) + 1U);
            memcpy(pChild->acState, "REKEYING", sizeof("REKEYING"));
            pChild->uiReqid = uiIndex * 10U + 11U;
            if (0U == uiIndex) {
                pList->pItems[pList->uiCount] = *pChild;
                pList->pItems[pList->uiCount++].uiReqid = 12U;
            }
        }
    }
    return IPSEC_OK;
}

void FreeIpsecChildSaList(IpsecChildSaList_t *pList)
{
    free(pList->pItems);
    memset(pList, 0, sizeof(*pList));
}

IpsecError_t AddIpsecConnection(IpsecContext_t *pContext, const IpsecConnectionConfig_t *pConfig)
{
    int32_t iIndex = FindTestName(pConfig->pcName);
    (void)pContext;
    if (iIndex < 0) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    gabConnections[iIndex] = true;
    return gbLoadUncertain ? IPSEC_ERR_VICI_TIMEOUT : IPSEC_OK;
}

IpsecError_t RemoveIpsecConnection(IpsecContext_t *pContext, const char *pcName)
{
    int32_t iIndex = FindTestName(pcName);
    (void)pContext;
    guiUnloadCalls++;
    if ((iIndex < 0) || (2 == iIndex) || gabActive[iIndex]) {
        gbInvalidOperation = true;
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    gabConnections[iIndex] = false;
    if (0U != guiUnloadFailures) {
        guiUnloadFailures--;
        return IPSEC_ERR_NETLINK_RECV; /* Daemon unloaded, local TC cleanup failed. */
    }
    return IPSEC_OK;
}

IpsecError_t TerminateIpsecIke(IpsecContext_t *pContext, const char *pcName,
    const IpsecControlOptions_t *pOptions)
{
    int32_t iIndex = FindTestName(pcName);
    (void)pContext;
    (void)pOptions;
    if ((iIndex < 0) || (2 == iIndex)) {
        gbInvalidOperation = true;
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    gauiTerminations[iIndex]++;
    if ((0 == iIndex) && (0U != guiTermFailures)) {
        guiTermFailures--;
        if (gbDisappearOnError) {
            gabActive[iIndex] = false;
        }
        return IPSEC_ERR_VICI_TIMEOUT;
    }
    gabActive[iIndex] = false;
    return IPSEC_OK;
}

IpsecError_t WaitNativeAppRemoved(IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig, uint32_t uiReqid)
{
    int32_t iIndex = FindTestName(pConfig->acConnectionName);
    (void)pContext;
    if (uiReqid < 32U) {
        guiReqidMask |= 1U << uiReqid;
    }
    if ((12U == uiReqid) && (0U != guiReqidWaitFailures)) {
        guiReqidWaitFailures--;
        return IPSEC_ERR_VICI_TIMEOUT;
    }
    return ((iIndex >= 0) && !gabActive[iIndex]) ? IPSEC_OK : IPSEC_ERR_VICI_TIMEOUT;
}

IpsecError_t AddIpsecPsk(IpsecContext_t *pContext, const IpsecPsk_t *pPsk)
{
    uint32_t uiIndex;
    (void)pContext;
    if ((NULL == pPsk->pcId) || (0 != strncmp(pPsk->pcId, "ipsec-app-", 10U))) {
        gbInvalidOperation = true;
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    for (uiIndex = 0U; uiIndex < guiKeyCount; uiIndex++) {
        if (0 == strcmp(gaacKeys[uiIndex], pPsk->pcId)) {
            gabKeys[uiIndex] = true;
            return IPSEC_OK;
        }
    }
    if (guiKeyCount >= 4U) {
        return IPSEC_ERR_NO_MEMORY;
    }
    memcpy(gaacKeys[guiKeyCount], pPsk->pcId, strlen(pPsk->pcId) + 1U);
    gabKeys[guiKeyCount++] = true;
    return IPSEC_OK;
}

IpsecError_t RemoveIpsecPsk(IpsecContext_t *pContext, const char *pcId)
{
    uint32_t uiIndex;
    (void)pContext;
    if (0U != guiKeyFailures) {
        guiKeyFailures--;
        return IPSEC_ERR_VICI_TIMEOUT;
    }
    for (uiIndex = 0U; uiIndex < guiKeyCount; uiIndex++) {
        if (0 == strcmp(gaacKeys[uiIndex], pcId)) {
            gabKeys[uiIndex] = false;
            return IPSEC_OK;
        }
    }
    gbInvalidOperation = true;
    return IPSEC_ERR_INVALID_ARGUMENT;
}

static NativeAppConfig_t BuildTestConfig(NativeAppOwnedResources_t *pResources, const char *pcName)
{
    NativeAppConfig_t Config = {.uiTimeoutMs = 100U, .pOwnedResources = pResources};
    memcpy(Config.acConnectionName, pcName, strlen(pcName) + 1U);
    memcpy(Config.acChildName, "child", sizeof("child"));
    memcpy(Config.acCredentialId, "logical-key", sizeof("logical-key"));
    return Config;
}

static void ResetTestState(void)
{
    memset(gabConnections, 0, sizeof(gabConnections));
    memset(gabActive, 0, sizeof(gabActive));
    memset(gauiTerminations, 0, sizeof(gauiTerminations));
    memset(gaacKeys, 0, sizeof(gaacKeys));
    memset(gabKeys, 0, sizeof(gabKeys));
    guiKeyCount = guiTermFailures = guiUnloadFailures = guiKeyFailures = 0U;
    guiReqidMask = guiUnloadCalls = 0U;
    guiReqidWaitFailures = 0U;
    gbUnavailable = gbInvalidOperation = gbDisappearOnError = gbLoadUncertain = false;
}

int main(void)
{
    NativeAppOwnedResources_t Resources = {.acNonce = "0123456789abcdef0123456789abcdef"};
    NativeAppConfig_t A = BuildTestConfig(&Resources, "conn-a");
    NativeAppConfig_t B = BuildTestConfig(&Resources, "conn-b");
    NativeAppConfig_t External = BuildTestConfig(&Resources, "external");
    IpsecConnectionConfig_t Connection = {.pcName = "external"};
    IpsecPsk_t Psk = {.pcId = "external-key"};
    IpsecContext_t *pContext = (IpsecContext_t *)(void *)&Connection;
    NativeAppTargetStatus_t Status = {0};
    uint32_t uiCount;
    ResetTestState();
    gabConnections[2] = gabActive[2] = true;
    CHECK(IPSEC_ERR_RESOURCE_CONFLICT == AddNativeAppConnection(pContext, &External, &Connection));
    Connection.pcName = "conn-a";
    CHECK(IPSEC_OK == AddNativeAppConnection(pContext, &A, &Connection));
    Connection.pcName = "conn-b";
    CHECK(IPSEC_OK == AddNativeAppConnection(pContext, &B, &Connection));
    CHECK(HasNativeAppOwnedSaTarget(&Resources, "conn-a", false));
    CHECK(HasNativeAppOwnedSaTarget(&Resources, A.acChildName, true));
    CHECK(!HasNativeAppOwnedSaTarget(&Resources, "external", false));
    CHECK(IPSEC_OK == AddNativeAppPsk(pContext, &A, &Psk));
    CHECK(IPSEC_OK == AddNativeAppPsk(pContext, &B, &Psk));
    CHECK(0 != strcmp(GetNativeAppDaemonCredentialId(&A), GetNativeAppDaemonCredentialId(&B)));
    gabActive[0] = gabActive[1] = true;
    CHECK(IPSEC_OK == GetNativeAppTargetStatus(pContext, &A, &Status));
    CHECK(Status.bIkePresent && Status.bChildPresent && !Status.bIkeEstablished && !Status.bChildInstalled);
    guiTermFailures = 1U;
    gbDisappearOnError = true;
    guiKeyFailures = 1U;
    CHECK(IPSEC_OK == CleanupNativeAppOwnedResources(pContext, &Resources));
    CHECK(!HasNativeAppCredential(&A) && !HasNativeAppCredential(&B));
    CHECK(!gabConnections[0] && !gabConnections[1] && gabConnections[2]);
    CHECK(gabActive[2] && (0U == gauiTerminations[2]));
    CHECK((0U != (guiReqidMask & (1U << 11U))) && (0U != (guiReqidMask & (1U << 12U))));
    CHECK(IPSEC_ERR_RESOURCE_CONFLICT == VerifyNativeAppExitSas(pContext));
    gabActive[2] = false;
    CHECK(IPSEC_OK == VerifyNativeAppExitSas(pContext));
    uiCount = guiUnloadCalls;
    CHECK(IPSEC_OK == CleanupNativeAppOwnedResources(pContext, &Resources));
    CHECK(uiCount == guiUnloadCalls); /* Repeat exit has no new deletes. */
    CHECK(IPSEC_ERR_RESOURCE_CONFLICT == AddNativeAppPsk(pContext, &A, &Psk));
    CHECK(!HasNativeAppOwnedSaTarget(&Resources, "conn-a", false));
    CHECK(!gbInvalidOperation);

    ResetTestState();
    memset(Resources.aItems, 0, sizeof(Resources.aItems));
    Resources.uiCount = 0U;
    Resources.bClosing = false;
    Connection.pcName = "conn-a";
    gbLoadUncertain = true;
    CHECK(IPSEC_ERR_VICI_TIMEOUT == AddNativeAppConnection(pContext, &A, &Connection));
    gbLoadUncertain = false;
    CHECK(IPSEC_OK == AddNativeAppPsk(pContext, &A, &Psk));
    Connection.pcName = "conn-b";
    CHECK(IPSEC_OK == AddNativeAppConnection(pContext, &B, &Connection));
    CHECK(IPSEC_OK == AddNativeAppPsk(pContext, &B, &Psk));
    gabActive[0] = gabActive[1] = true;
    guiTermFailures = 3U;
    CHECK(IPSEC_ERR_VICI_TIMEOUT == CleanupNativeAppOwnedResources(pContext, &Resources));
    CHECK(gabConnections[0] && gabActive[0] && HasNativeAppCredential(&A));
    CHECK(!gabConnections[1] && !gabActive[1] && !HasNativeAppCredential(&B));
    CHECK(3U == gauiTerminations[0]);
    gbUnavailable = true;
    CHECK(IPSEC_ERR_VICI_TRANSPORT == CleanupNativeAppOwnedResources(pContext, &Resources));
    CHECK(gabConnections[0] && HasNativeAppCredential(&A));
    gbUnavailable = false;
    guiUnloadFailures = 3U;
    CHECK(IPSEC_ERR_NETLINK_RECV == CleanupNativeAppOwnedResources(pContext, &Resources));
    CHECK(HasNativeAppCredential(&A) && Resources.aItems[0].bConnectionOwned);
    CHECK(IPSEC_OK == CleanupNativeAppOwnedResources(pContext, &Resources));
    CHECK(!HasNativeAppCredential(&A) && !gbInvalidOperation);

    ResetTestState();
    memset(Resources.aItems, 0, sizeof(Resources.aItems));
    Resources.uiCount = 0U;
    Resources.bClosing = false;
    Connection.pcName = "conn-a";
    CHECK(IPSEC_OK == AddNativeAppConnection(pContext, &A, &Connection));
    CHECK(IPSEC_OK == AddNativeAppPsk(pContext, &A, &Psk));
    gabActive[0] = true;
    guiReqidWaitFailures = 3U;
    CHECK(IPSEC_ERR_VICI_TIMEOUT == CleanupNativeAppOwnedResources(pContext, &Resources));
    CHECK(!gabActive[0] && gabConnections[0] && HasNativeAppCredential(&A));
    CHECK(2U == Resources.aItems[0].uiPendingReqidCount);
    CHECK(0U == guiUnloadCalls);
    guiReqidMask = 0U;
    CHECK(IPSEC_OK == CleanupNativeAppOwnedResources(pContext, &Resources));
    CHECK(0U != (guiReqidMask & (1U << 12U)));
    CHECK(0U == Resources.aItems[0].uiPendingReqidCount);
    CHECK(!gbInvalidOperation);
    (void)puts("app shutdown ownership/retry/transient-SA checks: PASS");
    return 0;
}
