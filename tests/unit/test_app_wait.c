#include "app_internal.h"
#include <stdio.h>
#include <string.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); return 1; \
} } while (0)

static IpsecIkeSaInfo_t gIke;
static bool gbPresent;
static uint32_t guiQueries;
static IpsecError_t geQueryError;

IpsecError_t GetIpsecDatapathStatus(IpsecContext_t *pContext, IpsecDatapathStatus_t *pStatus)
{
    (void)pContext;
    memset(pStatus, 0, sizeof(*pStatus));
    pStatus->eType = IPSEC_DATAPATH_KERNEL_LIBIPSEC;
    return IPSEC_OK;
}

IpsecError_t GetIpsecIkeSas(IpsecContext_t *pContext, IpsecIkeSaList_t *pList)
{
    (void)pContext;
    guiQueries++;
    pList->uiCount = gbPresent ? 1U : 0U;
    pList->pItems = gbPresent ? &gIke : NULL;
    return geQueryError;
}

IpsecError_t GetIpsecChildSas(IpsecContext_t *pContext, IpsecChildSaList_t *pList)
{
    (void)pContext;
    memset(pList, 0, sizeof(*pList));
    return IPSEC_OK;
}

void FreeIpsecIkeSaList(IpsecIkeSaList_t *pList) { (void)pList; }
void FreeIpsecChildSaList(IpsecChildSaList_t *pList) { (void)pList; }

IpsecError_t GetIpsecXfrmStates(IpsecContext_t *pContext, IpsecXfrmStateList_t *pList)
{
    (void)pContext;
    (void)pList;
    return IPSEC_ERR_NOT_SUPPORTED; /* Must not be queried for kernel-libipsec. */
}

IpsecError_t GetIpsecXfrmPolicies(IpsecContext_t *pContext, IpsecXfrmPolicyList_t *pList)
{
    (void)pContext;
    (void)pList;
    return IPSEC_ERR_NOT_SUPPORTED;
}

void FreeIpsecXfrmStateList(IpsecXfrmStateList_t *pList) { (void)pList; }
void FreeIpsecXfrmPolicyList(IpsecXfrmPolicyList_t *pList) { (void)pList; }

int main(void)
{
    NativeAppConfig_t Config = {0};
    /* Context is opaque and only passed through to the above deterministic seams. */
    IpsecContext_t *pContext = (IpsecContext_t *)&Config;
    memcpy(Config.acConnectionName, "wait-test", sizeof("wait-test"));
    memcpy(gIke.acName, Config.acConnectionName, sizeof("wait-test"));
    RequestNativeAppStop();
    CHECK(IPSEC_OK == WaitNativeAppRemovedWithTimeout(pContext, &Config, 0U, 0U));
    CHECK(1U == guiQueries); /* Ctrl-C still verifies absence, not fake timeout. */
    gbPresent = true;
    CHECK(IPSEC_ERR_CANCELLED == WaitNativeAppRemovedWithTimeout(pContext, &Config, 0U, 1000U));
    CHECK(2U == guiQueries);
    geQueryError = IPSEC_ERR_VICI_CONNECT;
    CHECK(IPSEC_ERR_VICI_CONNECT == WaitNativeAppRemovedWithTimeout(pContext, &Config, 0U, 0U));
    geQueryError = IPSEC_OK;
    ResetNativeAppStopRequest();
    CHECK(IPSEC_ERR_VICI_TIMEOUT == WaitNativeAppRemovedWithTimeout(pContext, &Config, 0U, 0U));
    gbPresent = false;
    CHECK(IPSEC_OK == WaitNativeAppRemovedWithTimeout(pContext, &Config, 0U, 0U));
    (void)puts("cleanup wait cancellation/absence/query-error: PASS");
    return 0;
}
