#include "application_protected_internal.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define IPSEC_PROTECTED_APPLICATION_HANDLE_BASE 0x49500000U

static bool IsProtectedApplicationAddressValid(uint32_t uiAddress)
{
    return (0U != uiAddress) &&
        (ntohl(uiAddress) < 0xe0000000U);
}

static void BuildProtectedApplicationFilterState(
    const IpsecProtectedApplicationState_t *pState,
    const IpsecProtectedApplicationPeer_t *pPeer,
    IpsecProtectedApplicationState_t *pFilterState)
{
    (void)memset(pFilterState, 0, sizeof(*pFilterState));
    pFilterState->iTunFd = pState->iTunFd;
    pFilterState->uiTunIndex = pState->uiTunIndex;
    pFilterState->uiEgressIndex = pState->uiEgressIndex;
    pFilterState->uiLocalAddress = pPeer->uiLocalAddress;
    pFilterState->uiRemoteAddress = pPeer->uiRemoteAddress;
    pFilterState->uiFilterHandle = pPeer->uiFilterHandle;
    pFilterState->usPriority = pState->usPriority;
    pFilterState->bRawFilter = pPeer->bRawFilter;
    pFilterState->bUdpFilter = pPeer->bUdpFilter;
    (void)memcpy(pFilterState->acTunName, pState->acTunName,
                 sizeof(pFilterState->acTunName));
    (void)memcpy(pFilterState->acEgressName, pState->acEgressName,
                 sizeof(pFilterState->acEgressName));
}

static IpsecError_t InitializeApplicationProtectedPath(IpsecContext_t *pContext)
{
    const IpsecDatapathConfig_t *pConfig = &pContext->Datapath.Config;
    IpsecProtectedApplicationState_t *pState;
    IpsecError_t eError;
    if (!pContext->Datapath.bInitialized ||
        ('\0' == pConfig->acProtectedInterfaceName[0]) ||
        ('\0' == pConfig->acProtectedEgressInterfaceName[0]) ||
        (0 == strcmp(pConfig->acProtectedInterfaceName, pConfig->acProtectedEgressInterfaceName)) ||
        (0 == strcmp(pConfig->acProtectedInterfaceName, pContext->Datapath.acInterfaceName)) ||
        (0 == strcmp(pConfig->acProtectedEgressInterfaceName, pContext->Datapath.acInterfaceName)) ||
        (UINT16_MAX == pConfig->usProtectedFilterPriority)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pState = (IpsecProtectedApplicationState_t *)calloc(1U, sizeof(*pState));
    if (NULL == pState) {
        return IPSEC_ERR_NO_MEMORY;
    }
    pState->iTunFd = -1;
    pContext->ProtectedPath.pApplicationState = pState;
    if (0 != pthread_mutex_init(&pState->PeerMutex, NULL)) {
        return IPSEC_ERR_INTERNAL;
    }
    else {
        pState->bPeerMutexInitialized = true;
    }
    pState->usPriority = (0U == pConfig->usProtectedFilterPriority) ?
        32000U : pConfig->usProtectedFilterPriority;
    memcpy(pState->acTunName, pConfig->acProtectedInterfaceName, sizeof(pState->acTunName));
    memcpy(pState->acEgressName, pConfig->acProtectedEgressInterfaceName, sizeof(pState->acEgressName));
    eError = CreateIpsecProtectedApplicationEndpoint(pContext, pState);
    return eError; /* Path manager cleans partial initialization. */
}

static IpsecError_t ParseProtectedApplicationPeer(
    const IpsecConnectionConfig_t *pConfig,
    uint32_t *puiLocalAddress,
    uint32_t *puiRemoteAddress)
{
    size_t zNameLength;

    if ((NULL == pConfig) || (NULL == puiLocalAddress) ||
        (NULL == puiRemoteAddress) || (NULL == pConfig->pcName) ||
        (1U != pConfig->LocalAddresses.uiCount) ||
        (1U != pConfig->RemoteAddresses.uiCount) ||
        (NULL == pConfig->LocalAddresses.ppcItems) ||
        (NULL == pConfig->RemoteAddresses.ppcItems) ||
        (NULL == pConfig->LocalAddresses.ppcItems[0]) ||
        (NULL == pConfig->RemoteAddresses.ppcItems[0])) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    zNameLength = strnlen(pConfig->pcName, IPSEC_NAME_LENGTH);
    if ((0U == zNameLength) || (zNameLength >= IPSEC_NAME_LENGTH) ||
        (1 != inet_pton(AF_INET, pConfig->LocalAddresses.ppcItems[0],
                        puiLocalAddress)) ||
        (1 != inet_pton(AF_INET, pConfig->RemoteAddresses.ppcItems[0],
                        puiRemoteAddress)) ||
        !IsProtectedApplicationAddressValid(*puiLocalAddress) ||
        !IsProtectedApplicationAddressValid(*puiRemoteAddress) ||
        (*puiLocalAddress == *puiRemoteAddress)) {
        return IPSEC_ERR_NOT_SUPPORTED;
    }
    else {
        return IPSEC_OK;
    }
}

static IpsecError_t InstallProtectedApplicationPeer(
    IpsecProtectedApplicationState_t *pState,
    IpsecProtectedApplicationPeer_t *pPeer)
{
    IpsecProtectedApplicationState_t *pFilterState;
    IpsecError_t eError;

    pFilterState = (IpsecProtectedApplicationState_t *)calloc(
        1U, sizeof(*pFilterState));
    if (NULL == pFilterState) {
        return IPSEC_ERR_NO_MEMORY;
    }
    BuildProtectedApplicationFilterState(pState, pPeer, pFilterState);
    eError = InstallIpsecProtectedApplicationFilters(pFilterState);
    pPeer->bRawFilter = pFilterState->bRawFilter;
    pPeer->bUdpFilter = pFilterState->bUdpFilter;
    free(pFilterState);
    return eError;
}

static IpsecError_t RemoveProtectedApplicationPeer(
    IpsecProtectedApplicationState_t *pState,
    IpsecProtectedApplicationPeer_t *pPeer)
{
    IpsecProtectedApplicationState_t *pFilterState;
    IpsecError_t eError;

    pFilterState = (IpsecProtectedApplicationState_t *)calloc(
        1U, sizeof(*pFilterState));
    if (NULL == pFilterState) {
        return IPSEC_ERR_NO_MEMORY;
    }
    BuildProtectedApplicationFilterState(pState, pPeer, pFilterState);
    eError = RemoveIpsecProtectedApplicationFilters(pFilterState);
    pPeer->bRawFilter = pFilterState->bRawFilter;
    pPeer->bUdpFilter = pFilterState->bUdpFilter;
    free(pFilterState);
    return eError;
}

IpsecError_t RegisterIpsecProtectedPeerInternal(
    IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig,
    bool *pbAdded)
{
    IpsecProtectedApplicationState_t *pState;
    uint32_t uiLocalAddress;
    uint32_t uiRemoteAddress;
    uint32_t uiIndex;
    uint32_t uiFreeIndex = UINT32_MAX;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pbAdded)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    *pbAdded = false;
    if (IPSEC_PACKET_PATH_APPLICATION !=
        pContext->Datapath.Config.eProtectedPacketPath) {
        return IPSEC_OK;
    }
    eError = ParseProtectedApplicationPeer(
        pConfig, &uiLocalAddress, &uiRemoteAddress);
    if (IPSEC_OK != eError) {
        return eError;
    }
    pState = pContext->ProtectedPath.pApplicationState;
    if ((NULL == pState) || !pState->bPeerMutexInitialized) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    if (0 != pthread_mutex_lock(&pState->PeerMutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    for (uiIndex = 0U;
         uiIndex < IPSEC_PROTECTED_APPLICATION_PEER_CAPACITY;
         uiIndex++) {
        IpsecProtectedApplicationPeer_t *pPeer =
            &pState->aPeers[uiIndex];

        if (!pPeer->bInUse && (UINT32_MAX == uiFreeIndex)) {
            uiFreeIndex = uiIndex;
        }
        else if (pPeer->bInUse &&
                 (0 == strcmp(pPeer->acConnectionName,
                              pConfig->pcName))) {
            eError = ((uiLocalAddress == pPeer->uiLocalAddress) &&
                      (uiRemoteAddress == pPeer->uiRemoteAddress)) ?
                IPSEC_OK : IPSEC_ERR_RESOURCE_CONFLICT;
            break;
        }
        else {
            /* Inspect the next dynamic peer slot. */
        }
    }
    if ((IPSEC_ERR_BUFFER_TOO_SMALL == eError) &&
        (UINT32_MAX != uiFreeIndex)) {
        IpsecProtectedApplicationPeer_t *pPeer =
            &pState->aPeers[uiFreeIndex];

        (void)memset(pPeer, 0, sizeof(*pPeer));
        (void)memcpy(pPeer->acConnectionName, pConfig->pcName,
                     strlen(pConfig->pcName) + 1U);
        pPeer->uiLocalAddress = uiLocalAddress;
        pPeer->uiRemoteAddress = uiRemoteAddress;
        pPeer->uiFilterHandle =
            IPSEC_PROTECTED_APPLICATION_HANDLE_BASE | (uiFreeIndex + 1U);
        eError = InstallProtectedApplicationPeer(pState, pPeer);
        if (IPSEC_OK == eError) {
            pPeer->bInUse = true;
            pState->uiPeerCount++;
            *pbAdded = true;
        }
        else {
            IpsecError_t eCleanupError =
                RemoveProtectedApplicationPeer(pState, pPeer);

            if (IPSEC_OK == eCleanupError) {
                (void)memset(pPeer, 0, sizeof(*pPeer));
            }
            else {
                /* Retain ownership so the caller and deinit can retry. */
                pPeer->bInUse = true;
                pState->uiPeerCount++;
                *pbAdded = true;
                LogIpsec(pContext, IPSEC_LOG_WARNING,
                    "protected APPLICATION partial filter rollback failed for %s: %s",
                    pConfig->pcName,
                    GetIpsecErrorString(eCleanupError));
            }
        }
    }
    else {
        /* Preserve an existing-peer or capacity result. */
    }
    (void)pthread_mutex_unlock(&pState->PeerMutex);
    return eError;
}

IpsecError_t UnregisterIpsecProtectedPeerInternal(
    IpsecContext_t *pContext,
    const char *pcConnectionName)
{
    IpsecProtectedApplicationState_t *pState;
    uint32_t uiIndex;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pContext) || (NULL == pcConnectionName)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (IPSEC_PACKET_PATH_APPLICATION !=
        pContext->Datapath.Config.eProtectedPacketPath) {
        return IPSEC_OK;
    }
    pState = pContext->ProtectedPath.pApplicationState;
    if ((NULL == pState) || !pState->bPeerMutexInitialized) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    if (0 != pthread_mutex_lock(&pState->PeerMutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    for (uiIndex = 0U;
         uiIndex < IPSEC_PROTECTED_APPLICATION_PEER_CAPACITY;
         uiIndex++) {
        IpsecProtectedApplicationPeer_t *pPeer =
            &pState->aPeers[uiIndex];

        if (pPeer->bInUse &&
            (0 == strcmp(pPeer->acConnectionName, pcConnectionName))) {
            eError = RemoveProtectedApplicationPeer(pState, pPeer);
            if (IPSEC_OK == eError) {
                (void)memset(pPeer, 0, sizeof(*pPeer));
                pState->uiPeerCount--;
            }
            else {
                /* Keep ownership metadata for deinitialization retry. */
            }
            break;
        }
        else {
            /* Inspect the next dynamic peer slot. */
        }
    }
    (void)pthread_mutex_unlock(&pState->PeerMutex);
    return eError;
}

bool MatchIpsecProtectedPeerInternal(
    IpsecContext_t *pContext,
    const char *pcLocalAddress,
    const char *pcRemoteAddress)
{
    IpsecProtectedApplicationState_t *pState;
    uint32_t uiLocalAddress;
    uint32_t uiRemoteAddress;
    uint32_t uiIndex;
    bool bMatch = false;

    if ((NULL == pContext) || (NULL == pcLocalAddress) ||
        (NULL == pcRemoteAddress) ||
        (1 != inet_pton(AF_INET, pcLocalAddress, &uiLocalAddress)) ||
        (1 != inet_pton(AF_INET, pcRemoteAddress, &uiRemoteAddress))) {
        return false;
    }
    pState = pContext->ProtectedPath.pApplicationState;
    if ((NULL == pState) || !pState->bPeerMutexInitialized ||
        (0 != pthread_mutex_lock(&pState->PeerMutex))) {
        return false;
    }
    for (uiIndex = 0U;
         (uiIndex < IPSEC_PROTECTED_APPLICATION_PEER_CAPACITY) &&
         !bMatch;
         uiIndex++) {
        const IpsecProtectedApplicationPeer_t *pPeer =
            &pState->aPeers[uiIndex];

        bMatch = pPeer->bInUse &&
            (uiLocalAddress == pPeer->uiLocalAddress) &&
            (uiRemoteAddress == pPeer->uiRemoteAddress);
    }
    (void)pthread_mutex_unlock(&pState->PeerMutex);
    return bMatch;
}

static bool IsProtectedApplicationPacketInScope(
    IpsecProtectedApplicationState_t *pState,
    uint32_t uiSource, uint32_t uiDestination, bool bInbound)
{
    uint32_t uiIndex;
    bool bMatch = false;

    if (!pState->bPeerMutexInitialized ||
        (0 != pthread_mutex_lock(&pState->PeerMutex))) {
        return false;
    }
    for (uiIndex = 0U;
         (uiIndex < IPSEC_PROTECTED_APPLICATION_PEER_CAPACITY) &&
         !bMatch;
         uiIndex++) {
        const IpsecProtectedApplicationPeer_t *pPeer =
            &pState->aPeers[uiIndex];

        bMatch = pPeer->bInUse &&
            (uiSource == (bInbound ? pPeer->uiRemoteAddress :
                                    pPeer->uiLocalAddress)) &&
            (uiDestination == (bInbound ? pPeer->uiLocalAddress :
                                         pPeer->uiRemoteAddress));
    }
    (void)pthread_mutex_unlock(&pState->PeerMutex);
    return bMatch;
}

static IpsecError_t ValidateProtectedApplicationScope(
    IpsecProtectedApplicationState_t *pState,
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
    if (!IsProtectedApplicationPacketInScope(
            pState, uiSource, uiDestination, bInbound)) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    return IPSEC_OK;
}

static IpsecError_t InspectProtectedApplicationPeerFilters(
    IpsecProtectedApplicationState_t *pState)
{
    IpsecProtectedApplicationState_t *pFilterState;
    uint32_t uiIndex;
    IpsecError_t eError = IPSEC_OK;

    if (!pState->bPeerMutexInitialized ||
        (0 != pthread_mutex_lock(&pState->PeerMutex))) {
        return IPSEC_ERR_INTERNAL;
    }
    pFilterState = (IpsecProtectedApplicationState_t *)calloc(
        1U, sizeof(*pFilterState));
    if (NULL == pFilterState) {
        eError = IPSEC_ERR_NO_MEMORY;
    }
    else {
        for (uiIndex = 0U;
             (IPSEC_OK == eError) &&
             (uiIndex < IPSEC_PROTECTED_APPLICATION_PEER_CAPACITY);
             uiIndex++) {
            const IpsecProtectedApplicationPeer_t *pPeer =
                &pState->aPeers[uiIndex];

            if (pPeer->bInUse) {
                BuildProtectedApplicationFilterState(
                    pState, pPeer, pFilterState);
                eError = InspectIpsecProtectedApplicationFilters(
                    pFilterState, false);
            }
            else {
                /* Inspect the next registered peer. */
            }
        }
        free(pFilterState);
    }
    (void)pthread_mutex_unlock(&pState->PeerMutex);
    return eError;
}

static IpsecError_t ReceiveApplicationProtectedPacket(IpsecContext_t *pContext,
    IpsecProtectedPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    IpsecError_t eError;
    const uint64_t ullDeadline = GetIpsecMonotonicMilliseconds() + uiTimeoutMs;
    uint32_t uiSkipped = 0U;
    if (NULL == pPacket->pucData) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (pPacket->zCapacity < IPSEC_PROTECTED_PACKET_CAPACITY) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    do {
        uint64_t ullNow = GetIpsecMonotonicMilliseconds();
        uint32_t uiRemaining = (ullNow < ullDeadline) ?
            (uint32_t)(ullDeadline - ullNow) : 0U;
        eError = ReceiveIpsecProtectedApplicationPacket(
            pContext->ProtectedPath.pApplicationState, pPacket, uiRemaining);
        if ((IPSEC_OK != eError) ||
            !IsIpsecProtectedTunControlPacket(pPacket->pucData, pPacket->zLength)) {
            break;
        }
        uiSkipped++;
        if (uiSkipped <= 4U) {
            LogIpsec(pContext, IPSEC_LOG_WARNING,
                "protected TUN control skipped: class=ipv6_link_control "
                "bytes=%zu first=0x%02x next_header=%u skipped=%u",
                pPacket->zLength, pPacket->pucData[0], pPacket->pucData[6], uiSkipped);
        }
        pPacket->zLength = 0U;
        eError = IPSEC_ERR_PACKET_TIMEOUT;
        /* A stream of control packets must not extend the caller's deadline. */
    } while (GetIpsecMonotonicMilliseconds() < ullDeadline);
    if (IPSEC_OK == eError) {
        pPacket->eType = IPSEC_PROTECTED_PACKET_RAW_ESP;
        pPacket->eDirection = IPSEC_PACKET_DIRECTION_OUTBOUND;
        eError = ValidateProtectedApplicationScope(
            pContext->ProtectedPath.pApplicationState, pPacket, false);
        if (IPSEC_OK != eError) {
            /* Header metadata only: never dump payload or keys into logs. */
            LogIpsec(pContext, IPSEC_LOG_WARNING,
                "protected TUN packet rejected: bytes=%zu first=0x%02x "
                "byte9=%u flags_fragment=0x%04x bytes12_13=0x%04x "
                "class=%s version=%u next_header=%u skipped=%u error=%s",
                pPacket->zLength,
                (pPacket->zLength > 0U) ? pPacket->pucData[0] : 0U,
                (pPacket->zLength > 9U) ? pPacket->pucData[9] : 0U,
                (pPacket->zLength > 7U) ?
                    ((uint32_t)pPacket->pucData[6] << 8U) | pPacket->pucData[7] : 0U,
                (pPacket->zLength > 13U) ?
                    ((uint32_t)pPacket->pucData[12] << 8U) | pPacket->pucData[13] : 0U,
                ((pPacket->zLength > 9U) && (4U == (pPacket->pucData[0] >> 4U)) &&
                    (50U == pPacket->pucData[9])) ? "invalid_or_out_of_scope_esp" :
                    "unsupported_or_malformed",
                (pPacket->zLength > 0U) ? pPacket->pucData[0] >> 4U : 0U,
                (pPacket->zLength > 6U) ? pPacket->pucData[6] : 0U,
                uiSkipped,
                GetIpsecErrorString(eError));
        }
    }
    if (0U != uiSkipped) {
        LogIpsec(pContext, IPSEC_LOG_WARNING,
            "protected TUN receive summary: skipped_control=%u esp_delivered=%u error=%s",
            uiSkipped, (IPSEC_OK == eError) ? 1U : 0U,
            (IPSEC_OK == eError) ? "none" : GetIpsecErrorString(eError));
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
        pContext->ProtectedPath.pApplicationState, pPacket, true);
    if (IPSEC_OK == eError) {
        eError = SubmitIpsecProtectedApplicationPacket(
            pContext->ProtectedPath.pApplicationState, pPacket);
    }
    return eError;
}

static IpsecError_t GetApplicationProtectedPathStatus(IpsecContext_t *pContext,
    IpsecProtectedPathStatusInternal_t *pStatus)
{
    IpsecError_t eError = IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    if (NULL != pContext->ProtectedPath.pApplicationState) {
        IpsecProtectedApplicationState_t *pState =
            pContext->ProtectedPath.pApplicationState;
        pStatus->uiInterfaceIndex = pState->uiTunIndex;
        memcpy(pStatus->acInterfaceName, pState->acTunName, sizeof(pStatus->acInterfaceName));
        eError = InspectIpsecProtectedApplicationEndpoint(pState);
        if (IPSEC_OK == eError) {
            eError = InspectProtectedApplicationPeerFilters(pState);
        }
        else {
            /* Preserve endpoint error. */
        }
        pStatus->bReady = pContext->ProtectedPath.bInitialized && (IPSEC_OK == eError);
    }
    return eError;
}

static void DeinitializeApplicationProtectedPath(IpsecContext_t *pContext)
{
    if (NULL != pContext->ProtectedPath.pApplicationState) {
        IpsecProtectedApplicationState_t *pState =
            pContext->ProtectedPath.pApplicationState;
        uint32_t uiIndex;

        if (pState->bPeerMutexInitialized &&
            (0 == pthread_mutex_lock(&pState->PeerMutex))) {
            for (uiIndex = 0U;
                 uiIndex < IPSEC_PROTECTED_APPLICATION_PEER_CAPACITY;
                 uiIndex++) {
                IpsecProtectedApplicationPeer_t *pPeer =
                    &pState->aPeers[uiIndex];

                if (pPeer->bInUse) {
                    IpsecError_t eError =
                        RemoveProtectedApplicationPeer(pState, pPeer);

                    if (IPSEC_OK != eError) {
                        LogIpsec(pContext, IPSEC_LOG_WARNING,
                            "protected APPLICATION peer filter cleanup failed for %s: %s",
                            pPeer->acConnectionName,
                            GetIpsecErrorString(eError));
                    }
                    else {
                        /* Filter pair removed. */
                    }
                    (void)memset(pPeer, 0, sizeof(*pPeer));
                }
                else {
                    /* Inspect the next dynamic peer slot. */
                }
            }
            pState->uiPeerCount = 0U;
            (void)pthread_mutex_unlock(&pState->PeerMutex);
        }
        else {
            /* No initialized peer registry to clean. */
        }
        DestroyIpsecProtectedApplicationEndpoint(
            pContext, pState);
        if (pState->bPeerMutexInitialized) {
            (void)pthread_mutex_destroy(&pState->PeerMutex);
            pState->bPeerMutexInitialized = false;
        }
        else {
            /* Mutex was never initialized. */
        }
        free(pState);
        pContext->ProtectedPath.pApplicationState = NULL;
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
