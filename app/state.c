#include "app_internal.h"

#include <string.h>

NativeAppPeerState_t GetNativeAppPeerState(
    bool bConnectionLoaded,
    bool bCredentialLoaded,
    bool bIkeEstablished,
    bool bChildInstalled)
{
    NativeAppPeerState_t eState;

    if (bChildInstalled) {
        eState = NATIVE_APP_PEER_STATE_CHILD_INSTALLED;
    }
    else if (bIkeEstablished) {
        eState = NATIVE_APP_PEER_STATE_IKE_ESTABLISHED;
    }
    else if (bConnectionLoaded && bCredentialLoaded) {
        eState = NATIVE_APP_PEER_STATE_READY;
    }
    else if (bConnectionLoaded) {
        eState = NATIVE_APP_PEER_STATE_CONNECTION_LOADED;
    }
    else if (bCredentialLoaded) {
        eState = NATIVE_APP_PEER_STATE_CREDENTIAL_LOADED;
    }
    else {
        eState = NATIVE_APP_PEER_STATE_REGISTERED;
    }
    return eState;
}

const char *GetNativeAppPeerStateName(NativeAppPeerState_t eState)
{
    const char *pcName;

    switch (eState) {
    case NATIVE_APP_PEER_STATE_REGISTERED:
        pcName = "REGISTERED";
        break;
    case NATIVE_APP_PEER_STATE_CREDENTIAL_LOADED:
        pcName = "CREDENTIAL";
        break;
    case NATIVE_APP_PEER_STATE_CONNECTION_LOADED:
        pcName = "CONNECTION";
        break;
    case NATIVE_APP_PEER_STATE_READY:
        pcName = "READY";
        break;
    case NATIVE_APP_PEER_STATE_IKE_ESTABLISHED:
        pcName = "IKE_ESTABLISHED";
        break;
    case NATIVE_APP_PEER_STATE_CHILD_INSTALLED:
        pcName = "CHILD_INSTALLED";
        break;
    default:
        pcName = "UNKNOWN";
        break;
    }
    return pcName;
}

void ResolveNativeAppTargetStatus(
    const NativeAppConfig_t *pConfig,
    const IpsecConnectionList_t *pConnections,
    const IpsecIkeSaList_t *pIkeSas,
    const IpsecChildSaList_t *pChildSas,
    NativeAppTargetStatus_t *pStatus)
{
    uint32_t uiIndex;

    if (NULL == pStatus) {
        return;
    }
    else {
        (void)memset(pStatus, 0, sizeof(*pStatus));
    }
    if ((NULL == pConfig) || (NULL == pConnections) ||
        (NULL == pIkeSas) || (NULL == pChildSas)) {
        return;
    }
    for (uiIndex = 0U; uiIndex < pConnections->uiCount; uiIndex++) {
        if (0 == strcmp(pConfig->acConnectionName,
                        pConnections->pItems[uiIndex].acName)) {
            pStatus->bConnectionLoaded = true;
            break;
        }
        else {
            /* Check the next connection. */
        }
    }
    for (uiIndex = 0U; uiIndex < pIkeSas->uiCount; uiIndex++) {
        if (0 == strcmp(pConfig->acConnectionName,
                        pIkeSas->pItems[uiIndex].acName)) {
            pStatus->bIkePresent = true;
            pStatus->bIkeEstablished = pStatus->bIkeEstablished ||
                pIkeSas->pItems[uiIndex].bEstablished;
        }
        else {
            /* Check the next IKE SA. */
        }
    }
    for (uiIndex = 0U; uiIndex < pChildSas->uiCount; uiIndex++) {
        if (0 == strcmp(pConfig->acConnectionName,
                        pChildSas->pItems[uiIndex].acIkeName)) {
            pStatus->bChildPresent = true;
        }
        if ((0 == strcmp(pConfig->acChildName, pChildSas->pItems[uiIndex].acName)) &&
            (0 == strcmp(pConfig->acConnectionName, pChildSas->pItems[uiIndex].acIkeName))) {
            pStatus->bChildPresent = true;
            pStatus->bChildInstalled = pStatus->bChildInstalled ||
                (0 == strcmp("INSTALLED", pChildSas->pItems[uiIndex].acState));
            pStatus->uiReqid = pChildSas->pItems[uiIndex].uiReqid;
        }
        else {
            /* Check the next CHILD SA. */
        }
    }
}

IpsecError_t GetNativeAppTargetStatus(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    NativeAppTargetStatus_t *pStatus)
{
    IpsecConnectionList_t Connections = {0};
    IpsecIkeSaList_t IkeSas = {0};
    IpsecChildSaList_t ChildSas = {0};
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pStatus)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        (void)memset(pStatus, 0, sizeof(*pStatus));
    }
    eError = GetIpsecConnections(pContext, &Connections);
    if (IPSEC_OK == eError) {
        eError = GetIpsecIkeSas(pContext, &IkeSas);
    }
    else {
        /* Preserve the connection query error. */
    }
    if (IPSEC_OK == eError) {
        eError = GetIpsecChildSas(pContext, &ChildSas);
    }
    else {
        /* Preserve the IKE query error. */
    }
    if (IPSEC_OK == eError) {
        ResolveNativeAppTargetStatus(pConfig, &Connections, &IkeSas,
                                     &ChildSas, pStatus);
    }
    else {
        /* Return an empty status with the query error. */
    }
    FreeIpsecChildSaList(&ChildSas);
    FreeIpsecIkeSaList(&IkeSas);
    FreeIpsecConnectionList(&Connections);
    return eError;
}

IpsecError_t GetNativeAppConnectionSaStatus(
    IpsecContext_t *pContext,
    const char *pcConnectionName,
    bool *pbActive)
{
    IpsecIkeSaList_t IkeSas = {0};
    IpsecChildSaList_t ChildSas = {0};
    IpsecError_t eError;
    uint32_t uiIndex;

    if ((NULL == pContext) || (NULL == pcConnectionName) ||
        ('\0' == pcConnectionName[0]) || (NULL == pbActive)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        *pbActive = false;
    }
    eError = GetIpsecIkeSas(pContext, &IkeSas);
    if (IPSEC_OK == eError) {
        eError = GetIpsecChildSas(pContext, &ChildSas);
    }
    else {
        /* Preserve the IKE query error. */
    }
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < IkeSas.uiCount; uiIndex++) {
            if (0 == strcmp(pcConnectionName,
                            IkeSas.pItems[uiIndex].acName)) {
                *pbActive = true;
                break;
            }
            else {
                /* Check the next IKE SA. */
            }
        }
        for (uiIndex = 0U;
             (uiIndex < ChildSas.uiCount) && !*pbActive;
             uiIndex++) {
            if (0 == strcmp(pcConnectionName,
                            ChildSas.pItems[uiIndex].acIkeName)) {
                *pbActive = true;
            }
            else {
                /* Check the next CHILD SA. */
            }
        }
    }
    else {
        /* Keep the conservative inactive result with the query error. */
    }
    FreeIpsecChildSaList(&ChildSas);
    FreeIpsecIkeSaList(&IkeSas);
    return eError;
}

IpsecError_t GetNativeAppAnySaStatus(
    IpsecContext_t *pContext,
    bool *pbActive)
{
    IpsecIkeSaList_t IkeSas = {0};
    IpsecChildSaList_t ChildSas = {0};
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pbActive)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        *pbActive = false;
    }
    eError = GetIpsecIkeSas(pContext, &IkeSas);
    if (IPSEC_OK == eError) {
        eError = GetIpsecChildSas(pContext, &ChildSas);
    }
    else {
        /* Preserve the IKE query error. */
    }
    if (IPSEC_OK == eError) {
        *pbActive = (0U < IkeSas.uiCount) || (0U < ChildSas.uiCount);
    }
    else {
        /* Keep the conservative inactive result with the query error. */
    }
    FreeIpsecChildSaList(&ChildSas);
    FreeIpsecIkeSaList(&IkeSas);
    return eError;
}
