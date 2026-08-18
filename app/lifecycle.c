#include "app_internal.h"

#include <errno.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

static volatile sig_atomic_t gbNativeAppStopRequested = 0;

void RequestNativeAppStop(void)
{
    gbNativeAppStopRequested = 1;
}

void ResetNativeAppStopRequest(void)
{
    gbNativeAppStopRequested = 0;
}

bool IsNativeAppStopRequested(void)
{
    return (0 != gbNativeAppStopRequested);
}

static void SleepNativeApp(uint32_t uiMilliseconds)
{
    struct timespec Time;

    Time.tv_sec = (time_t)(uiMilliseconds / 1000U);
    Time.tv_nsec = (long)((uiMilliseconds % 1000U) * 1000000U);
    while ((0 != nanosleep(&Time, &Time)) && (EINTR == errno) &&
           (0 == gbNativeAppStopRequested)) {
        /* Resume the remaining interruptible delay. */
    }
}

IpsecError_t LoadNativeAppCredential(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig)
{
    NativeAppSecret_t Secret;
    const char *pacOwners[2];
    IpsecPsk_t Psk = {.uiStructSize = sizeof(IpsecPsk_t)};
    IpsecError_t eError;

    eError = ReadNativeAppSecret(pConfig, &Secret);
    if (IPSEC_OK != eError) {
        return eError;
    }
    else {
        /* Load the secret into charon and immediately wipe the local copy. */
    }
    pacOwners[0] = pConfig->acLocalId;
    pacOwners[1] = pConfig->acRemoteId;
    Psk.pcId = ('\0' != pConfig->acCredentialId[0]) ?
        pConfig->acCredentialId : pConfig->acConnectionName;
    Psk.pucData = Secret.pucData;
    Psk.uiDataLength = Secret.uiLength;
    Psk.Owners.ppcItems = pacOwners;
    Psk.Owners.uiCount = 2U;
    eError = AddIpsecPsk(pContext, &Psk);
    DestroyNativeAppSecret(&Secret);
    return eError;
}

IpsecError_t LoadNativeAppResources(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime)
{
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pRuntime)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = AddIpsecConnection(pContext, &pRuntime->Connection);
    }
    if (IPSEC_OK == eError) {
        eError = LoadNativeAppCredential(pContext, pConfig);
    }
    else {
        /* Preserve the connection error. */
    }
    if (IPSEC_OK != eError) {
        (void)RemoveIpsecConnection(pContext, pConfig->acConnectionName);
    }
    else {
        /* Both resources remain available to charon. */
    }
    return eError;
}

IpsecError_t StartNativeAppConnection(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const NativeAppRuntimeConfig_t *pRuntime)
{
    IpsecControlOptions_t Control = {
        .uiStructSize = sizeof(IpsecControlOptions_t),
        .eMode = IPSEC_CONTROL_WAIT
    };
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pRuntime)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        Control.uiTimeoutMs = pConfig->uiTimeoutMs;
    }
    if (NATIVE_APP_ROLE_RESPONDER == pConfig->eRole) {
        eError = WaitIpsecChildInstalled(pContext, pConfig->acChildName,
                                         pConfig->uiTimeoutMs);
    }
    else if (pConfig->bChildlessIke) {
        eError = InitiateIpsecIke(pContext, pConfig->acConnectionName,
                                  &Control);
        if (IPSEC_OK == eError) {
            eError = WaitIpsecIkeEstablished(pContext,
                                             pConfig->acConnectionName,
                                             pConfig->uiTimeoutMs);
        }
        else {
            /* Preserve the IKE initiation error. */
        }
        if (IPSEC_OK == eError) {
            eError = InitiateIpsecChild(pContext, pConfig->acChildName,
                                        &Control);
        }
        else {
            /* Do not initiate a child without an established IKE SA. */
        }
    }
    else {
        eError = InitiateIpsecChild(pContext, pConfig->acChildName, &Control);
    }
    if ((IPSEC_OK == eError) &&
        (NATIVE_APP_ROLE_INITIATOR == pConfig->eRole)) {
        eError = WaitIpsecChildInstalled(pContext, pConfig->acChildName,
                                         pConfig->uiTimeoutMs);
    }
    else {
        /* Preserve the preceding result. */
    }
    return eError;
}

IpsecError_t StopNativeAppConnection(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    bool bRemoveConnection,
    bool bClearCredentials)
{
    IpsecControlOptions_t Control = {
        .uiStructSize = sizeof(IpsecControlOptions_t),
        .eMode = IPSEC_CONTROL_WAIT
    };
    IpsecError_t eFirstError;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pConfig)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        Control.uiTimeoutMs = pConfig->uiTimeoutMs;
    }
    eFirstError = TerminateIpsecIke(pContext, pConfig->acConnectionName,
                                    &Control);
    if (bRemoveConnection) {
        eError = RemoveIpsecConnection(pContext,
                                       pConfig->acConnectionName);
        if ((IPSEC_OK == eFirstError) && (IPSEC_OK != eError)) {
            eFirstError = eError;
        }
        else {
            /* Preserve the earlier error. */
        }
    }
    else {
        /* Keep the connection definition loaded. */
    }
    if (bClearCredentials) {
        eError = ClearIpsecCredentials(pContext);
        if ((IPSEC_OK == eFirstError) && (IPSEC_OK != eError)) {
            eFirstError = eError;
        }
        else {
            /* Preserve the earlier error. */
        }
    }
    else {
        /* Clearing VICI credentials is deliberately explicit and global. */
    }
    return eFirstError;
}

static IpsecError_t VerifyNativeAppInstalled(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    uint32_t *puiReqid)
{
    IpsecIkeSaList_t IkeList = {0};
    IpsecChildSaList_t ChildList = {0};
    IpsecXfrmStateList_t StateList = {0};
    IpsecXfrmPolicyList_t PolicyList = {0};
    IpsecError_t eError;
    uint32_t uiIndex;
    uint32_t uiReqid = 0U;
    uint32_t uiStateCount = 0U;
    uint32_t uiPolicyCount = 0U;
    bool bIkeFound = false;
    bool bChildFound = false;

    eError = GetIpsecIkeSas(pContext, &IkeList);
    if (IPSEC_OK == eError) {
        eError = GetIpsecChildSas(pContext, &ChildList);
    }
    else {
        /* Preserve the IKE query error. */
    }
    if (IPSEC_OK == eError) {
        eError = GetIpsecXfrmStates(pContext, &StateList);
    }
    else {
        /* Preserve the CHILD query error. */
    }
    if (IPSEC_OK == eError) {
        eError = GetIpsecXfrmPolicies(pContext, &PolicyList);
    }
    else {
        /* Preserve the XFRM state query error. */
    }
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < IkeList.uiCount; uiIndex++) {
            if ((0 == strcmp(pConfig->acConnectionName,
                             IkeList.pItems[uiIndex].acName)) &&
                IkeList.pItems[uiIndex].bEstablished) {
                bIkeFound = true;
                break;
            }
            else {
                /* Check the next IKE SA. */
            }
        }
        for (uiIndex = 0U; uiIndex < ChildList.uiCount; uiIndex++) {
            if ((0 == strcmp(pConfig->acChildName,
                             ChildList.pItems[uiIndex].acName)) &&
                (0 == strcmp("INSTALLED",
                             ChildList.pItems[uiIndex].acState))) {
                bChildFound = true;
                uiReqid = ChildList.pItems[uiIndex].uiReqid;
                break;
            }
            else {
                /* Check the next CHILD SA. */
            }
        }
        for (uiIndex = 0U; uiIndex < StateList.uiCount; uiIndex++) {
            if ((0U != uiReqid) &&
                (uiReqid == StateList.pItems[uiIndex].uiReqid)) {
                uiStateCount++;
            }
            else {
                /* The state belongs to another CHILD SA. */
            }
        }
        for (uiIndex = 0U; uiIndex < PolicyList.uiCount; uiIndex++) {
            if ((0U != uiReqid) &&
                (uiReqid == PolicyList.pItems[uiIndex].uiReqid)) {
                uiPolicyCount++;
            }
            else {
                /* The policy belongs to another CHILD SA. */
            }
        }
        if (!bIkeFound || !bChildFound || (0U == uiStateCount) ||
            (0U == uiPolicyCount)) {
            eError = IPSEC_ERR_INTERNAL;
        }
        else {
            *puiReqid = uiReqid;
            (void)printf("verified reqid=%" PRIu32
                         " xfrm_states=%" PRIu32 " xfrm_policies=%" PRIu32
                         "\n", uiReqid, uiStateCount, uiPolicyCount);
        }
    }
    else {
        /* Preserve the query error. */
    }
    FreeIpsecXfrmPolicyList(&PolicyList);
    FreeIpsecXfrmStateList(&StateList);
    FreeIpsecChildSaList(&ChildList);
    FreeIpsecIkeSaList(&IkeList);
    return eError;
}

IpsecError_t WaitNativeAppRemovedWithTimeout(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    uint32_t uiReqid,
    uint32_t uiTimeoutMs)
{
    uint32_t uiElapsed = 0U;

    if ((NULL == pContext) || (NULL == pConfig)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    while ((uiElapsed <= uiTimeoutMs) &&
           (0 == gbNativeAppStopRequested)) {
        IpsecIkeSaList_t IkeList = {0};
        IpsecChildSaList_t ChildList = {0};
        IpsecXfrmStateList_t StateList = {0};
        IpsecXfrmPolicyList_t PolicyList = {0};
        IpsecError_t eError;
        uint32_t uiIndex;
        bool bPresent = false;

        eError = GetIpsecIkeSas(pContext, &IkeList);
        if (IPSEC_OK == eError) {
            eError = GetIpsecChildSas(pContext, &ChildList);
        }
        else {
            /* Preserve the IKE query error. */
        }
        if (IPSEC_OK == eError) {
            eError = GetIpsecXfrmStates(pContext, &StateList);
        }
        else {
            /* Preserve the CHILD query error. */
        }
        if (IPSEC_OK == eError) {
            eError = GetIpsecXfrmPolicies(pContext, &PolicyList);
        }
        else {
            /* Preserve the XFRM state query error. */
        }
        if (IPSEC_OK == eError) {
            for (uiIndex = 0U; uiIndex < IkeList.uiCount; uiIndex++) {
                bPresent = bPresent ||
                    (0 == strcmp(pConfig->acConnectionName,
                                 IkeList.pItems[uiIndex].acName));
            }
            for (uiIndex = 0U; uiIndex < ChildList.uiCount; uiIndex++) {
                bPresent = bPresent ||
                    (0 == strcmp(pConfig->acChildName,
                                 ChildList.pItems[uiIndex].acName));
            }
            for (uiIndex = 0U; uiIndex < StateList.uiCount; uiIndex++) {
                bPresent = bPresent ||
                    ((0U != uiReqid) &&
                     (uiReqid == StateList.pItems[uiIndex].uiReqid));
            }
            for (uiIndex = 0U; uiIndex < PolicyList.uiCount; uiIndex++) {
                bPresent = bPresent ||
                    ((0U != uiReqid) &&
                     (uiReqid == PolicyList.pItems[uiIndex].uiReqid));
            }
        }
        else {
            /* Preserve the query error. */
        }
        FreeIpsecXfrmPolicyList(&PolicyList);
        FreeIpsecXfrmStateList(&StateList);
        FreeIpsecChildSaList(&ChildList);
        FreeIpsecIkeSaList(&IkeList);
        if (IPSEC_OK != eError) {
            return eError;
        }
        else if (!bPresent) {
            return IPSEC_OK;
        }
        else {
            SleepNativeApp(100U);
            uiElapsed += 100U;
        }
    }
    return IPSEC_ERR_VICI_TIMEOUT;
}

IpsecError_t WaitNativeAppRemoved(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    uint32_t uiReqid)
{
    if (NULL == pConfig) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        return WaitNativeAppRemovedWithTimeout(
            pContext, pConfig, uiReqid, pConfig->uiTimeoutMs);
    }
}

IpsecError_t RunNativeAppLoop(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime,
    const NativeAppLoopOptions_t *pOptions)
{
    IpsecControlOptions_t Control = {
        .uiStructSize = sizeof(IpsecControlOptions_t),
        .eMode = IPSEC_CONTROL_WAIT
    };
    IpsecError_t eFirstError = IPSEC_OK;
    IpsecError_t eError;
    uint32_t uiIteration;
    uint32_t uiPassed = 0U;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pRuntime) ||
        (NULL == pOptions) || (0U == pOptions->uiCount)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (NATIVE_APP_ROLE_INITIATOR != pConfig->eRole) {
        return IPSEC_ERR_NOT_SUPPORTED;
    }
    else {
        Control.uiTimeoutMs = pConfig->uiTimeoutMs;
    }
    eError = LoadNativeAppCredential(pContext, pConfig);
    if (IPSEC_OK != eError) {
        return eError;
    }
    else {
        /* Reuse the credential while cycling only this connection and SA. */
    }

    for (uiIteration = 1U;
         (uiIteration <= pOptions->uiCount) &&
         (0 == gbNativeAppStopRequested);
         uiIteration++) {
        uint32_t uiReqid = 0U;
        bool bConnectionLoaded = false;
        bool bSaStarted = false;

        (void)printf("loop %" PRIu32 "/%" PRIu32 ": load\n",
                     uiIteration, pOptions->uiCount);
        eError = AddIpsecConnection(pContext, &pRuntime->Connection);
        if (IPSEC_OK == eError) {
            bConnectionLoaded = true;
            bSaStarted = true;
            eError = StartNativeAppConnection(pContext, pConfig, pRuntime);
        }
        else {
            /* Report the load failure after cleanup. */
        }
        if (IPSEC_OK == eError) {
            eError = VerifyNativeAppInstalled(pContext, pConfig, &uiReqid);
        }
        else {
            /* No installed state can be verified. */
        }
        if (bSaStarted) {
            IpsecError_t eCleanup = TerminateIpsecIke(
                pContext, pConfig->acConnectionName, &Control);

            if ((IPSEC_OK == eError) && (IPSEC_OK != eCleanup)) {
                eError = eCleanup;
            }
            else {
                /* Preserve the primary error. */
            }
            if (IPSEC_OK == eCleanup) {
                eCleanup = WaitNativeAppRemoved(pContext, pConfig, uiReqid);
                if ((IPSEC_OK == eError) && (IPSEC_OK != eCleanup)) {
                    eError = eCleanup;
                }
                else {
                    /* Preserve the primary error. */
                }
            }
            else {
                /* Termination did not complete. */
            }
        }
        else {
            /* No SA owned by this iteration requires termination. */
        }
        if (bConnectionLoaded) {
            IpsecError_t eCleanup = RemoveIpsecConnection(
                pContext, pConfig->acConnectionName);

            if ((IPSEC_OK == eError) && (IPSEC_OK != eCleanup)) {
                eError = eCleanup;
            }
            else {
                /* Preserve the primary error. */
            }
        }
        else {
            /* No connection definition requires unloading. */
        }
        if (IPSEC_OK == eError) {
            uiPassed++;
            (void)printf("loop %" PRIu32 "/%" PRIu32 ": passed\n",
                         uiIteration, pOptions->uiCount);
        }
        else {
            (void)fprintf(stderr,
                          "loop %" PRIu32 "/%" PRIu32 ": failed: %s\n",
                          uiIteration, pOptions->uiCount,
                          GetIpsecErrorString(eError));
            if (IPSEC_OK == eFirstError) {
                eFirstError = eError;
            }
            else {
                /* Preserve the first loop failure. */
            }
            if (!pOptions->bContinueOnError) {
                break;
            }
            else {
                /* Attempt the next isolated iteration. */
            }
        }
        if ((uiIteration < pOptions->uiCount) &&
            (0U < pOptions->uiDelayMs)) {
            SleepNativeApp(pOptions->uiDelayMs);
        }
        else {
            /* No inter-iteration delay is required. */
        }
    }
    if (pOptions->bClearCredentials) {
        eError = ClearIpsecCredentials(pContext);
        if ((IPSEC_OK == eFirstError) && (IPSEC_OK != eError)) {
            eFirstError = eError;
        }
        else {
            /* Preserve the loop result. */
        }
    }
    else {
        /* Avoid clearing credentials owned by other VICI clients. */
    }
    (void)printf("loop summary: passed=%" PRIu32 " requested=%" PRIu32
                 "\n", uiPassed, pOptions->uiCount);
    if ((0 != gbNativeAppStopRequested) && (IPSEC_OK == eFirstError)) {
        eFirstError = IPSEC_ERR_INTERNAL;
    }
    else {
        /* Preserve the loop result. */
    }
    return eFirstError;
}
