#include "application_protected_internal.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

static IpsecError_t InitializeApplicationProtectedPath(IpsecContext_t *pContext)
{
    const IpsecDatapathConfig_t *pConfig = &pContext->DatapathConfig;
    IpsecProtectedApplicationState_t *pState;
    IpsecError_t eError;
    if (!pContext->bDatapathInitialized ||
        ('\0' == pConfig->acProtectedInterfaceName[0]) ||
        ('\0' == pConfig->acProtectedEgressInterfaceName[0]) ||
        (0 == strcmp(pConfig->acProtectedInterfaceName, pConfig->acProtectedEgressInterfaceName)) ||
        (0 == strcmp(pConfig->acProtectedInterfaceName, pContext->acDatapathInterfaceName)) ||
        (0 == strcmp(pConfig->acProtectedEgressInterfaceName, pContext->acDatapathInterfaceName)) ||
        (UINT16_MAX == pConfig->usProtectedFilterPriority)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pState = (IpsecProtectedApplicationState_t *)calloc(1U, sizeof(*pState));
    if (NULL == pState) {
        return IPSEC_ERR_NO_MEMORY;
    }
    pState->iTunFd = -1;
    pContext->pProtectedApplicationState = pState;
    pState->usPriority = (0U == pConfig->usProtectedFilterPriority) ?
        32000U : pConfig->usProtectedFilterPriority;
    memcpy(pState->acTunName, pConfig->acProtectedInterfaceName, sizeof(pState->acTunName));
    memcpy(pState->acEgressName, pConfig->acProtectedEgressInterfaceName, sizeof(pState->acEgressName));
    if ((1 != inet_pton(AF_INET, pConfig->acProtectedLocalAddress, &pState->uiLocalAddress)) ||
        (1 != inet_pton(AF_INET, pConfig->acProtectedRemoteAddress, &pState->uiRemoteAddress)) ||
        (0U == pState->uiLocalAddress) || (0U == pState->uiRemoteAddress) ||
        (ntohl(pState->uiLocalAddress) >= 0xe0000000U) ||
        (ntohl(pState->uiRemoteAddress) >= 0xe0000000U) ||
        (pState->uiLocalAddress == pState->uiRemoteAddress)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    eError = CreateIpsecProtectedApplicationEndpoint(pContext, pState);
    if (IPSEC_OK == eError) {
        eError = InstallIpsecProtectedApplicationFilters(pState);
    }
    return eError; /* Path manager cleans partial initialization. */
}

static IpsecError_t ValidateProtectedApplicationScope(
    const IpsecProtectedApplicationState_t *pState,
    const IpsecProtectedPacket_t *pPacket, bool bInbound)
{
    uint32_t uiSource;
    uint32_t uiDestination;
    IpsecError_t eError = ValidateIpsecProtectedPacket(pPacket);
    if (IPSEC_OK != eError) {
        return eError;
    }
    memcpy(&uiSource, pPacket->pucData + 12U, sizeof(uiSource));
    memcpy(&uiDestination, pPacket->pucData + 16U, sizeof(uiDestination));
    if ((uiSource != (bInbound ? pState->uiRemoteAddress : pState->uiLocalAddress)) ||
        (uiDestination != (bInbound ? pState->uiLocalAddress : pState->uiRemoteAddress))) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    return IPSEC_OK;
}

static IpsecError_t ReceiveApplicationProtectedPacket(IpsecContext_t *pContext,
    IpsecProtectedPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    IpsecError_t eError;
    if (NULL == pPacket->pucData) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (pPacket->zCapacity < IPSEC_PROTECTED_PACKET_CAPACITY) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    eError = ReceiveIpsecProtectedApplicationPacket(
        pContext->pProtectedApplicationState, pPacket, uiTimeoutMs);
    if (IPSEC_OK == eError) {
        pPacket->eType = IPSEC_PROTECTED_PACKET_RAW_ESP;
        pPacket->eDirection = IPSEC_PACKET_DIRECTION_OUTBOUND;
        eError = ValidateProtectedApplicationScope(
            pContext->pProtectedApplicationState, pPacket, false);
    }
    if (IPSEC_OK != eError) {
        pPacket->zLength = 0U;
    }
    return eError;
}

static IpsecError_t SubmitApplicationProtectedPacket(IpsecContext_t *pContext,
    const IpsecProtectedPacket_t *pPacket)
{
    IpsecError_t eError;
    if (IPSEC_PACKET_DIRECTION_INBOUND != pPacket->eDirection) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    eError = ValidateProtectedApplicationScope(
        pContext->pProtectedApplicationState, pPacket, true);
    if (IPSEC_OK == eError) {
        eError = SubmitIpsecProtectedApplicationPacket(
            pContext->pProtectedApplicationState, pPacket);
    }
    return eError;
}

static IpsecError_t GetApplicationProtectedPathStatus(IpsecContext_t *pContext,
    IpsecProtectedPathStatusInternal_t *pStatus)
{
    IpsecError_t eError = IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    if (NULL != pContext->pProtectedApplicationState) {
        const IpsecProtectedApplicationState_t *pState =
            pContext->pProtectedApplicationState;
        pStatus->uiInterfaceIndex = pState->uiTunIndex;
        memcpy(pStatus->acInterfaceName, pState->acTunName, sizeof(pStatus->acInterfaceName));
        eError = InspectIpsecProtectedApplicationEndpoint(pState);
        pStatus->bReady = pContext->bProtectedPathInitialized && (IPSEC_OK == eError);
    }
    return eError;
}

static void DeinitializeApplicationProtectedPath(IpsecContext_t *pContext)
{
    if (NULL != pContext->pProtectedApplicationState) {
        DestroyIpsecProtectedApplicationEndpoint(
            pContext, pContext->pProtectedApplicationState);
        free(pContext->pProtectedApplicationState);
        pContext->pProtectedApplicationState = NULL;
    }
}

const IpsecProtectedPathOps_t *GetApplicationProtectedPathOps(void)
{
    static const IpsecProtectedPathOps_t Ops = {
        InitializeApplicationProtectedPath, ReceiveApplicationProtectedPacket,
        SubmitApplicationProtectedPacket, GetApplicationProtectedPathStatus,
        DeinitializeApplicationProtectedPath
    };
    return &Ops;
}
