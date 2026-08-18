#include "app_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#define NATIVE_APP_PEER_PROTOCOL "RCST/1"

static void SetNativeAppPeerError(
    char *pcError,
    uint32_t uiErrorLength,
    const char *pcText)
{
    if ((NULL != pcError) && (0U < uiErrorLength)) {
        (void)snprintf(pcError, uiErrorLength, "%s", pcText);
    }
    else {
        /* The caller did not request diagnostic text. */
    }
}

static bool CopyNativeAppPeerText(
    char *pcDestination,
    uint32_t uiDestinationLength,
    const char *pcSource)
{
    size_t zLength;

    if ((NULL == pcDestination) || (NULL == pcSource) ||
        (0U == uiDestinationLength)) {
        return false;
    }
    else {
        zLength = strnlen(pcSource, uiDestinationLength);
    }
    if (zLength >= uiDestinationLength) {
        return false;
    }
    else {
        (void)memcpy(pcDestination, pcSource, zLength + 1U);
        return true;
    }
}

static bool IsNativeAppPeerToken(const char *pcText)
{
    const unsigned char *pucText = (const unsigned char *)pcText;

    if ((NULL == pcText) || ('\0' == pcText[0])) {
        return false;
    }
    else {
        /* Validate the protocol token below. */
    }
    while ('\0' != *pucText) {
        if ((*pucText <= (unsigned char)' ') ||
            ((unsigned char)0x7fU == *pucText)) {
            return false;
        }
        else {
            pucText++;
        }
    }
    return true;
}

static bool IsNativeAppPeerAddress(const char *pcAddress)
{
    uint8_t aucAddress[sizeof(struct in6_addr)];

    return (1 == inet_pton(AF_INET, pcAddress, aucAddress)) ||
           (1 == inet_pton(AF_INET6, pcAddress, aucAddress));
}

static bool IsNativeAppSameAddress(
    const char *pcLeft,
    const char *pcRight)
{
    uint8_t aucLeft[sizeof(struct in6_addr)];
    uint8_t aucRight[sizeof(struct in6_addr)];

    if ((1 == inet_pton(AF_INET, pcLeft, aucLeft)) &&
        (1 == inet_pton(AF_INET, pcRight, aucRight))) {
        return (0 == memcmp(aucLeft, aucRight, sizeof(struct in_addr)));
    }
    else if ((1 == inet_pton(AF_INET6, pcLeft, aucLeft)) &&
             (1 == inet_pton(AF_INET6, pcRight, aucRight))) {
        return (0 == memcmp(aucLeft, aucRight, sizeof(struct in6_addr)));
    }
    else {
        return false;
    }
}

static bool BuildNativeAppSocketAddress(
    const char *pcAddress,
    uint32_t uiPort,
    struct sockaddr_storage *pStorage,
    socklen_t *puiLength,
    int32_t *piFamily)
{
    struct sockaddr_in *pIpv4 = (struct sockaddr_in *)pStorage;
    struct sockaddr_in6 *pIpv6 = (struct sockaddr_in6 *)pStorage;

    (void)memset(pStorage, 0, sizeof(*pStorage));
    if (1 == inet_pton(AF_INET, pcAddress, &pIpv4->sin_addr)) {
        pIpv4->sin_family = AF_INET;
        pIpv4->sin_port = htons((uint16_t)uiPort);
        *puiLength = (socklen_t)sizeof(*pIpv4);
        *piFamily = AF_INET;
        return true;
    }
    else if (1 == inet_pton(AF_INET6, pcAddress, &pIpv6->sin6_addr)) {
        pIpv6->sin6_family = AF_INET6;
        pIpv6->sin6_port = htons((uint16_t)uiPort);
        *puiLength = (socklen_t)sizeof(*pIpv6);
        *piFamily = AF_INET6;
        return true;
    }
    else {
        return false;
    }
}

static bool GetNativeAppSocketAddressText(
    const struct sockaddr_storage *pStorage,
    char *pcAddress,
    uint32_t uiAddressLength)
{
    const void *pvAddress;
    int32_t iFamily;

    if (AF_INET == pStorage->ss_family) {
        const struct sockaddr_in *pIpv4 =
            (const struct sockaddr_in *)pStorage;

        pvAddress = &pIpv4->sin_addr;
        iFamily = AF_INET;
    }
    else if (AF_INET6 == pStorage->ss_family) {
        const struct sockaddr_in6 *pIpv6 =
            (const struct sockaddr_in6 *)pStorage;

        pvAddress = &pIpv6->sin6_addr;
        iFamily = AF_INET6;
    }
    else {
        return false;
    }
    return (NULL != inet_ntop(iFamily, pvAddress, pcAddress,
                              (socklen_t)uiAddressLength));
}

static int32_t GetNativeAppPollTimeout(uint32_t uiTimeoutMs)
{
    return (uiTimeoutMs > (uint32_t)INT_MAX) ? INT_MAX :
        (int32_t)uiTimeoutMs;
}

static IpsecError_t WaitNativeAppSocket(
    int32_t iSocket,
    int16_t sEvents,
    uint32_t uiTimeoutMs,
    char *pcError,
    uint32_t uiErrorLength)
{
    struct pollfd PollFd = {
        .fd = iSocket,
        .events = sEvents
    };
    int32_t iResult;

    do {
        iResult = poll(&PollFd, 1U, GetNativeAppPollTimeout(uiTimeoutMs));
    } while ((0 > iResult) && (EINTR == errno));

    if (0 == iResult) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "peer registration timed out");
        return IPSEC_ERR_VICI_TIMEOUT;
    }
    else if ((0 > iResult) || (0 != (PollFd.revents &
              (POLLERR | POLLHUP | POLLNVAL)))) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "peer registration socket failed");
        return IPSEC_ERR_INTERNAL;
    }
    else if (0 == (PollFd.revents & sEvents)) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "unexpected peer registration socket event");
        return IPSEC_ERR_INTERNAL;
    }
    else {
        return IPSEC_OK;
    }
}

static IpsecError_t SendNativeAppPeerMessage(
    int32_t iSocket,
    const char *pcMessage,
    char *pcError,
    uint32_t uiErrorLength)
{
    size_t zLength = strnlen(pcMessage, NATIVE_APP_PEER_MESSAGE_LENGTH);
    size_t zOffset = 0U;

    if (zLength >= NATIVE_APP_PEER_MESSAGE_LENGTH) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        /* Send the complete bounded message. */
    }
    while (zOffset < zLength) {
        ssize_t zSent = send(iSocket, pcMessage + zOffset,
                             zLength - zOffset, MSG_NOSIGNAL);

        if ((0 > zSent) && (EINTR == errno)) {
            continue;
        }
        else if (0 >= zSent) {
            SetNativeAppPeerError(pcError, uiErrorLength,
                                  "failed to send peer registration data");
            return IPSEC_ERR_INTERNAL;
        }
        else {
            zOffset += (size_t)zSent;
        }
    }
    return IPSEC_OK;
}

static IpsecError_t ReceiveNativeAppPeerMessage(
    int32_t iSocket,
    char *pcMessage,
    uint32_t uiMessageLength,
    uint32_t uiTimeoutMs,
    char *pcError,
    uint32_t uiErrorLength)
{
    uint32_t uiOffset = 0U;
    IpsecError_t eError = IPSEC_OK;

    while ((IPSEC_OK == eError) &&
           ((uiOffset + 1U) < uiMessageLength)) {
        ssize_t zRead;

        eError = WaitNativeAppSocket(iSocket, POLLIN, uiTimeoutMs,
                                     pcError, uiErrorLength);
        if (IPSEC_OK != eError) {
            break;
        }
        else {
            zRead = recv(iSocket, pcMessage + uiOffset, 1U, 0);
        }

        if ((0 > zRead) && (EINTR == errno)) {
            continue;
        }
        else if (0 >= zRead) {
            SetNativeAppPeerError(pcError, uiErrorLength,
                                  "peer registration data was truncated");
            eError = IPSEC_ERR_INTERNAL;
        }
        else if ('\n' == pcMessage[uiOffset]) {
            pcMessage[uiOffset] = '\0';
            return IPSEC_OK;
        }
        else {
            uiOffset++;
        }
    }
    if (IPSEC_OK == eError) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "peer registration message is too long");
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    return eError;
}

IpsecError_t GetNativeAppPeerSequence(
    uint32_t uiOrdinal,
    uint32_t *puiGroupId,
    uint32_t *puiLogonId)
{
    uint32_t uiGroupOffset;

    if ((NULL == puiGroupId) || (NULL == puiLogonId)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        uiGroupOffset = uiOrdinal / NATIVE_APP_PEER_LOGON_LIMIT;
        *puiGroupId = uiGroupOffset + 1U;
        *puiLogonId = (uiOrdinal % NATIVE_APP_PEER_LOGON_LIMIT) + 1U;
    }
    return IPSEC_OK;
}

static bool BuildNativeAppPeerName(
    char *pcDestination,
    uint32_t uiDestinationLength,
    const char *pcPrefix,
    const char *pcPeerId)
{
    int32_t iLength = snprintf(pcDestination, uiDestinationLength, "%s%s",
                               pcPrefix, pcPeerId);

    return (0 <= iLength) && ((uint32_t)iLength < uiDestinationLength);
}

static bool BuildNativeAppPeerId(
    char *pcPeerId,
    uint32_t uiPeerIdLength,
    uint32_t uiGroupId,
    uint32_t uiLogonId)
{
    int32_t iLength = snprintf(pcPeerId, uiPeerIdLength,
                               NATIVE_APP_PEER_ID_PREFIX "%" PRIu32
                               "-%" PRIu32,
                               uiGroupId, uiLogonId);

    return (0 <= iLength) && ((uint32_t)iLength < uiPeerIdLength);
}

static IpsecError_t BuildNativeAppPeerConfig(
    const NativeAppConfig_t *pBaseConfig,
    NativeAppPeer_t *pPeer,
    uint32_t uiGroupId,
    uint32_t uiLogonId,
    const char *pcLocalAddress,
    const char *pcRemoteAddress,
    const char *pcLocalId,
    const char *pcRemoteId)
{
    char acPeerId[IPSEC_ID_LENGTH];

    (void)memset(pPeer, 0, sizeof(*pPeer));
    pPeer->uiGroupId = uiGroupId;
    pPeer->uiLogonId = uiLogonId;
    pPeer->Config = *pBaseConfig;
    if (!BuildNativeAppPeerId(acPeerId, sizeof(acPeerId), uiGroupId,
                              uiLogonId) ||
        !CopyNativeAppPeerText(pPeer->Config.acLocalAddress,
                               sizeof(pPeer->Config.acLocalAddress),
                               pcLocalAddress) ||
        !CopyNativeAppPeerText(pPeer->Config.acRemoteAddress,
                               sizeof(pPeer->Config.acRemoteAddress),
                               pcRemoteAddress) ||
        !CopyNativeAppPeerText(pPeer->Config.acLocalId,
                               sizeof(pPeer->Config.acLocalId), pcLocalId) ||
        !CopyNativeAppPeerText(pPeer->Config.acRemoteId,
                               sizeof(pPeer->Config.acRemoteId), pcRemoteId) ||
        !BuildNativeAppPeerName(pPeer->Config.acConnectionName,
                                sizeof(pPeer->Config.acConnectionName),
                                NATIVE_APP_CONNECTION_PREFIX, acPeerId) ||
        !BuildNativeAppPeerName(pPeer->Config.acChildName,
                                sizeof(pPeer->Config.acChildName),
                                NATIVE_APP_CHILD_PREFIX, acPeerId) ||
        !BuildNativeAppPeerName(pPeer->Config.acCredentialId,
                                sizeof(pPeer->Config.acCredentialId),
                                NATIVE_APP_CREDENTIAL_PREFIX, acPeerId)) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        return IPSEC_OK;
    }
}

static IpsecError_t AllocateNativeAppPeerIds(
    NativeAppPeerTable_t *pTable,
    uint32_t *puiGroupId,
    uint32_t *puiLogonId)
{
    IpsecError_t eError;

    LockNativeAppPeerTable(pTable);
    if (pTable->uiCount >= NATIVE_APP_PEER_CAPACITY) {
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        eError = GetNativeAppPeerSequence(pTable->uiCount, puiGroupId,
                                          puiLogonId);
    }
    UnlockNativeAppPeerTable(pTable);
    return eError;
}

static IpsecError_t AppendNativeAppPeer(
    NativeAppPeerTable_t *pTable,
    const NativeAppPeer_t *pPeer,
    NativeAppPeer_t **ppPeer)
{
    IpsecError_t eError;

    LockNativeAppPeerTable(pTable);
    if (pTable->uiCount >= NATIVE_APP_PEER_CAPACITY) {
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else if ((NATIVE_APP_ROLE_INITIATOR == pPeer->Config.eRole) &&
             ((pPeer->uiGroupId !=
               ((pTable->uiCount / NATIVE_APP_PEER_LOGON_LIMIT) + 1U)) ||
              (pPeer->uiLogonId !=
               ((pTable->uiCount % NATIVE_APP_PEER_LOGON_LIMIT) + 1U)))) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        pTable->aPeers[pTable->uiCount] = *pPeer;
        *ppPeer = &pTable->aPeers[pTable->uiCount];
        pTable->uiCount++;
        eError = IPSEC_OK;
    }
    UnlockNativeAppPeerTable(pTable);
    return eError;
}

static int32_t OpenNativeAppServerSocket(
    const NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength)
{
    struct sockaddr_storage Address;
    socklen_t uiAddressLength;
    int32_t iFamily;
    int32_t iSocket;
    int32_t iEnabled = 1;

    if (!BuildNativeAppSocketAddress(
            pConfig->acPeerServerAddress, pConfig->uiPeerPort, &Address,
            &uiAddressLength, &iFamily)) {
        return -1;
    }
    iSocket = (int32_t)socket(iFamily, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (0 > iSocket) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "failed to create peer server socket");
    }
    else if ((0 != setsockopt(iSocket, SOL_SOCKET, SO_REUSEADDR,
                              &iEnabled, sizeof(iEnabled))) ||
             (0 != bind(iSocket, (const struct sockaddr *)&Address,
                        uiAddressLength)) ||
             (0 != listen(iSocket, 8))) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "failed to bind peer server socket");
        (void)close(iSocket);
        iSocket = -1;
    }
    else {
        /* The listener thread reuses this socket for every registration. */
    }
    return iSocket;
}

static int32_t OpenNativeAppClientSocket(
    const NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength)
{
    struct sockaddr_storage LocalAddress;
    struct sockaddr_storage ServerAddress;
    socklen_t uiLocalLength;
    socklen_t uiServerLength;
    int32_t iLocalFamily;
    int32_t iServerFamily;
    int32_t iSocket;
    int32_t iFlags;
    int32_t iResult;

    if (!BuildNativeAppSocketAddress(pConfig->acLocalAddress, 0U,
                                     &LocalAddress, &uiLocalLength,
                                     &iLocalFamily) ||
        !BuildNativeAppSocketAddress(
            pConfig->acPeerServerAddress, pConfig->uiPeerPort,
            &ServerAddress, &uiServerLength, &iServerFamily) ||
        (iLocalFamily != iServerFamily)) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "peer addresses use incompatible families");
        return -1;
    }
    iSocket = (int32_t)socket(iServerFamily,
                              SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (0 > iSocket) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "failed to create peer client socket");
        return -1;
    }
    else if (0 != bind(iSocket, (const struct sockaddr *)&LocalAddress,
                       uiLocalLength)) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "failed to bind peer client address");
        (void)close(iSocket);
        return -1;
    }
    else {
        /* Connect from the configured IPsec endpoint address. */
    }
    iFlags = fcntl(iSocket, F_GETFL, 0);
    if ((0 > iFlags) || (0 != fcntl(iSocket, F_SETFL, iFlags | O_NONBLOCK))) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "failed to configure peer client socket");
        (void)close(iSocket);
        return -1;
    }
    iResult = connect(iSocket, (const struct sockaddr *)&ServerAddress,
                      uiServerLength);
    if ((0 != iResult) && (EINPROGRESS == errno)) {
        IpsecError_t eError = WaitNativeAppSocket(
            iSocket, POLLOUT, pConfig->uiTimeoutMs, pcError, uiErrorLength);

        if (IPSEC_OK == eError) {
            socklen_t uiResultLength = (socklen_t)sizeof(iResult);

            if ((0 != getsockopt(iSocket, SOL_SOCKET, SO_ERROR, &iResult,
                                 &uiResultLength)) || (0 != iResult)) {
                SetNativeAppPeerError(pcError, uiErrorLength,
                                      "failed to connect to peer server");
                iResult = -1;
            }
            else {
                iResult = 0;
            }
        }
        else {
            iResult = -1;
        }
    }
    else if (0 != iResult) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "failed to connect to peer server");
        iResult = -1;
    }
    else {
        /* The nonblocking connect completed immediately. */
    }
    if ((0 != iResult) ||
        (0 != fcntl(iSocket, F_SETFL, iFlags))) {
        (void)close(iSocket);
        return -1;
    }
    else {
        return iSocket;
    }
}

IpsecError_t InitializeNativeAppPeerTable(NativeAppPeerTable_t *pTable)
{
    if (NULL == pTable) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        (void)memset(pTable, 0, sizeof(*pTable));
    }
    if (0 != pthread_mutex_init(&pTable->Mutex, NULL)) {
        return IPSEC_ERR_INTERNAL;
    }
    else {
        pTable->uiSelectedIndex = UINT32_MAX;
        return IPSEC_OK;
    }
}

void DeinitializeNativeAppPeerTable(NativeAppPeerTable_t *pTable)
{
    if (NULL != pTable) {
        (void)pthread_mutex_destroy(&pTable->Mutex);
        (void)memset(pTable, 0, sizeof(*pTable));
    }
    else {
        /* Nothing to deinitialize. */
    }
}

void LockNativeAppPeerTable(NativeAppPeerTable_t *pTable)
{
    if (NULL != pTable) {
        (void)pthread_mutex_lock(&pTable->Mutex);
    }
    else {
        /* Nothing to lock. */
    }
}

void UnlockNativeAppPeerTable(NativeAppPeerTable_t *pTable)
{
    if (NULL != pTable) {
        (void)pthread_mutex_unlock(&pTable->Mutex);
    }
    else {
        /* Nothing to unlock. */
    }
}

NativeAppPeer_t *FindNativeAppPeer(
    NativeAppPeerTable_t *pTable,
    const char *pcPeerId)
{
    uint32_t uiIndex;
    NativeAppPeer_t *pPeer = NULL;

    if ((NULL == pTable) || (NULL == pcPeerId)) {
        return NULL;
    }
    else {
        /* Search the active in-memory table. */
    }
    LockNativeAppPeerTable(pTable);
    for (uiIndex = 0U; uiIndex < pTable->uiCount; uiIndex++) {
        const char *pcCurrentId = pTable->aPeers[uiIndex].Config.acRemoteId;

        if (NATIVE_APP_ROLE_RESPONDER ==
            pTable->aPeers[uiIndex].Config.eRole) {
            pcCurrentId = pTable->aPeers[uiIndex].Config.acLocalId;
        }
        else {
            /* Initiators identify a peer by its remote IKE identity. */
        }
        if (0 == strcmp(pcPeerId, pcCurrentId)) {
            pPeer = &pTable->aPeers[uiIndex];
            break;
        }
        else {
            /* Check the next peer. */
        }
    }
    UnlockNativeAppPeerTable(pTable);
    return pPeer;
}

static IpsecError_t AcceptNativeAppPeerConnection(
    int32_t iServerSocket,
    const NativeAppConfig_t *pBaseConfig,
    NativeAppPeerTable_t *pTable,
    NativeAppPeer_t **ppPeer,
    char *pcError,
    uint32_t uiErrorLength)
{
    struct sockaddr_storage RemoteSocketAddress;
    socklen_t uiRemoteLength = (socklen_t)sizeof(RemoteSocketAddress);
    NativeAppPeer_t Peer;
    char acMessage[NATIVE_APP_PEER_MESSAGE_LENGTH];
    char acRemoteSocketAddress[IPSEC_ADDRESS_LENGTH];
    char *pcSave = NULL;
    char *pcProtocol;
    char *pcCommand;
    char *pcRemoteAddress;
    char *pcExtra;
    uint32_t uiGroupId = 0U;
    uint32_t uiLogonId = 0U;
    int32_t iPeerSocket = -1;
    int32_t iLength;
    IpsecError_t eError;

    if ((NULL == pBaseConfig) || (NULL == pTable) || (NULL == ppPeer) ||
        (0 > iServerSocket) ||
        (NATIVE_APP_ROLE_INITIATOR != pBaseConfig->eRole) ||
        !IsNativeAppPeerToken(pBaseConfig->acLocalId) ||
        !IsNativeAppPeerToken(pBaseConfig->acIkeProposals) ||
        !IsNativeAppPeerToken(pBaseConfig->acEspProposals)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        *ppPeer = NULL;
    }
    iPeerSocket = (int32_t)accept(
        iServerSocket, (struct sockaddr *)&RemoteSocketAddress,
        &uiRemoteLength);
    if (0 > iPeerSocket) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "failed to accept peer registration");
        eError = IPSEC_ERR_INTERNAL;
    }
    else if (0 != fcntl(iPeerSocket, F_SETFD, FD_CLOEXEC)) {
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "failed to configure peer registration");
        eError = IPSEC_ERR_INTERNAL;
    }
    else {
        eError = IPSEC_OK;
    }
    if (IPSEC_OK == eError) {
        eError = ReceiveNativeAppPeerMessage(
            iPeerSocket, acMessage, sizeof(acMessage),
            pBaseConfig->uiTimeoutMs, pcError, uiErrorLength);
    }
    if (IPSEC_OK == eError) {
        pcProtocol = strtok_r(acMessage, " ", &pcSave);
        pcCommand = strtok_r(NULL, " ", &pcSave);
        pcRemoteAddress = strtok_r(NULL, " ", &pcSave);
        pcExtra = strtok_r(NULL, " ", &pcSave);
        if ((NULL == pcProtocol) || (NULL == pcCommand) ||
            (NULL == pcRemoteAddress) || (NULL != pcExtra) ||
            (0 != strcmp(NATIVE_APP_PEER_PROTOCOL, pcProtocol)) ||
            (0 != strcmp("REGISTER", pcCommand)) ||
            !IsNativeAppPeerAddress(pcRemoteAddress) ||
            !GetNativeAppSocketAddressText(
                &RemoteSocketAddress, acRemoteSocketAddress,
                sizeof(acRemoteSocketAddress)) ||
            !IsNativeAppSameAddress(pcRemoteAddress,
                                    acRemoteSocketAddress)) {
            SetNativeAppPeerError(pcError, uiErrorLength,
                                  "invalid peer registration request");
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            eError = AllocateNativeAppPeerIds(pTable, &uiGroupId,
                                               &uiLogonId);
        }
    }
    if (IPSEC_OK == eError) {
        char acPeerId[IPSEC_ID_LENGTH];

        if (!BuildNativeAppPeerId(acPeerId, sizeof(acPeerId), uiGroupId,
                                  uiLogonId)) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            eError = BuildNativeAppPeerConfig(
                pBaseConfig, &Peer, uiGroupId, uiLogonId,
                pBaseConfig->acLocalAddress, pcRemoteAddress,
                pBaseConfig->acLocalId, acPeerId);
        }
    }
    if (IPSEC_OK == eError) {
        const char *pcMode = (IPSEC_MODE_TRANSPORT == pBaseConfig->eMode) ?
            "transport" : "tunnel";

        iLength = snprintf(
            acMessage, sizeof(acMessage),
            NATIVE_APP_PEER_PROTOCOL " ASSIGN %" PRIu32 " %" PRIu32
            " %s %s %s %s %s\n",
            uiGroupId, uiLogonId, pBaseConfig->acLocalAddress,
            pBaseConfig->acLocalId, pBaseConfig->acIkeProposals,
            pBaseConfig->acEspProposals, pcMode);
        if ((0 > iLength) || ((uint32_t)iLength >= sizeof(acMessage))) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            eError = SendNativeAppPeerMessage(iPeerSocket, acMessage,
                                               pcError, uiErrorLength);
        }
    }
    if (IPSEC_OK == eError) {
        eError = AppendNativeAppPeer(pTable, &Peer, ppPeer);
    }
    if (0 <= iPeerSocket) {
        (void)close(iPeerSocket);
    }
    else {
        /* No accepted socket needs closing. */
    }
    return eError;
}

IpsecError_t AcceptNativeAppPeer(
    const NativeAppConfig_t *pBaseConfig,
    NativeAppPeerTable_t *pTable,
    NativeAppPeer_t **ppPeer,
    char *pcError,
    uint32_t uiErrorLength)
{
    int32_t iServerSocket;
    IpsecError_t eError;

    if ((NULL == pBaseConfig) || (NULL == pTable) || (NULL == ppPeer)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        iServerSocket = OpenNativeAppServerSocket(pBaseConfig, pcError,
                                                   uiErrorLength);
    }
    if (0 > iServerSocket) {
        return IPSEC_ERR_INTERNAL;
    }
    else {
        eError = WaitNativeAppSocket(iServerSocket, POLLIN,
                                     pBaseConfig->uiTimeoutMs, pcError,
                                     uiErrorLength);
    }
    if (IPSEC_OK == eError) {
        eError = AcceptNativeAppPeerConnection(
            iServerSocket, pBaseConfig, pTable, ppPeer, pcError,
            uiErrorLength);
    }
    else {
        /* Preserve the listener wait error. */
    }
    (void)close(iServerSocket);
    return eError;
}

static void NotifyNativeAppPeerListener(
    NativeAppPeerListener_t *pListener,
    IpsecError_t eError,
    const NativeAppPeer_t *pPeer,
    const char *pcError)
{
    if (NULL != pListener->pCallback) {
        pListener->pCallback(eError, pPeer, pcError,
                             pListener->pvUserData);
    }
    else {
        /* No listener event callback was registered. */
    }
}

static void *RunNativeAppPeerListener(void *pvArgument)
{
    NativeAppPeerListener_t *pListener =
        (NativeAppPeerListener_t *)pvArgument;

    while (!atomic_load(&pListener->bStopRequested)) {
        NativeAppPeer_t *pPeer = NULL;
        char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
        IpsecError_t eError = WaitNativeAppSocket(
            pListener->iServerSocket, POLLIN,
            NATIVE_APP_PEER_LISTENER_POLL_MS, acError,
            sizeof(acError));

        if (IPSEC_ERR_VICI_TIMEOUT == eError) {
            continue;
        }
        else if (IPSEC_OK == eError) {
            eError = AcceptNativeAppPeerConnection(
                pListener->iServerSocket, &pListener->Config,
                pListener->pTable, &pPeer, acError, sizeof(acError));
        }
        else {
            NotifyNativeAppPeerListener(pListener, eError, NULL, acError);
            break;
        }
        NotifyNativeAppPeerListener(pListener, eError, pPeer, acError);
    }
    (void)close(pListener->iServerSocket);
    pListener->iServerSocket = -1;
    return NULL;
}

IpsecError_t StartNativeAppPeerListener(
    NativeAppPeerListener_t *pListener,
    const NativeAppConfig_t *pBaseConfig,
    NativeAppPeerTable_t *pTable,
    NativeAppPeerEventCallback_t pCallback,
    void *pvUserData,
    char *pcError,
    uint32_t uiErrorLength)
{
    int32_t iResult;

    if ((NULL == pListener) || (NULL == pBaseConfig) || (NULL == pTable) ||
        (NATIVE_APP_ROLE_INITIATOR != pBaseConfig->eRole) ||
        pListener->bRunning) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        (void)memset(pListener, 0, sizeof(*pListener));
        pListener->iServerSocket = -1;
        pListener->Config = *pBaseConfig;
        pListener->pTable = pTable;
        pListener->pCallback = pCallback;
        pListener->pvUserData = pvUserData;
        atomic_init(&pListener->bStopRequested, false);
    }
    pListener->iServerSocket = OpenNativeAppServerSocket(
        &pListener->Config, pcError, uiErrorLength);
    if (0 > pListener->iServerSocket) {
        return IPSEC_ERR_INTERNAL;
    }
    else {
        iResult = pthread_create(&pListener->Thread, NULL,
                                 RunNativeAppPeerListener, pListener);
    }
    if (0 != iResult) {
        (void)close(pListener->iServerSocket);
        pListener->iServerSocket = -1;
        SetNativeAppPeerError(pcError, uiErrorLength,
                              "failed to start peer listener thread");
        return IPSEC_ERR_INTERNAL;
    }
    else {
        pListener->bRunning = true;
        return IPSEC_OK;
    }
}

void StopNativeAppPeerListener(NativeAppPeerListener_t *pListener)
{
    if ((NULL != pListener) && pListener->bRunning) {
        atomic_store(&pListener->bStopRequested, true);
        (void)pthread_join(pListener->Thread, NULL);
        pListener->bRunning = false;
    }
    else {
        /* The peer listener is already stopped. */
    }
}

bool IsNativeAppPeerListenerRunning(
    const NativeAppPeerListener_t *pListener)
{
    return (NULL != pListener) && pListener->bRunning;
}

IpsecError_t RegisterNativeAppPeer(
    const NativeAppConfig_t *pBaseConfig,
    NativeAppPeerTable_t *pTable,
    NativeAppPeer_t **ppPeer,
    char *pcError,
    uint32_t uiErrorLength)
{
    NativeAppPeer_t Peer;
    char acMessage[NATIVE_APP_PEER_MESSAGE_LENGTH];
    char *pacTokens[10] = {0};
    char *pcSave = NULL;
    uint32_t uiTokenCount = 0U;
    uint32_t uiGroupId = 0U;
    uint32_t uiLogonId = 0U;
    IpsecMode_t eMode = IPSEC_MODE_TUNNEL;
    int32_t iSocket;
    int32_t iLength;
    IpsecError_t eError;

    if ((NULL == pBaseConfig) || (NULL == pTable) || (NULL == ppPeer) ||
        (NATIVE_APP_ROLE_RESPONDER != pBaseConfig->eRole) ||
        (pTable->uiCount >= NATIVE_APP_PEER_CAPACITY)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        *ppPeer = NULL;
    }
    iSocket = OpenNativeAppClientSocket(pBaseConfig, pcError,
                                         uiErrorLength);
    if (0 > iSocket) {
        return IPSEC_ERR_INTERNAL;
    }
    iLength = snprintf(acMessage, sizeof(acMessage),
                       NATIVE_APP_PEER_PROTOCOL " REGISTER %s\n",
                       pBaseConfig->acLocalAddress);
    if ((0 > iLength) || ((uint32_t)iLength >= sizeof(acMessage))) {
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        eError = SendNativeAppPeerMessage(iSocket, acMessage, pcError,
                                           uiErrorLength);
    }
    if (IPSEC_OK == eError) {
        eError = ReceiveNativeAppPeerMessage(
            iSocket, acMessage, sizeof(acMessage), pBaseConfig->uiTimeoutMs,
            pcError, uiErrorLength);
    }
    if (IPSEC_OK == eError) {
        char *pcToken = strtok_r(acMessage, " ", &pcSave);

        while ((NULL != pcToken) &&
               (uiTokenCount < (uint32_t)(sizeof(pacTokens) /
                                           sizeof(pacTokens[0])))) {
            pacTokens[uiTokenCount] = pcToken;
            uiTokenCount++;
            pcToken = strtok_r(NULL, " ", &pcSave);
        }
        if ((9U != uiTokenCount) || (NULL != pcToken) ||
            (0 != strcmp(NATIVE_APP_PEER_PROTOCOL, pacTokens[0])) ||
            (0 != strcmp("ASSIGN", pacTokens[1])) ||
            !ParseNativeAppNumber(pacTokens[2], &uiGroupId) ||
            !ParseNativeAppNumber(pacTokens[3], &uiLogonId) ||
            (0U == uiGroupId) || (0U == uiLogonId) ||
            (NATIVE_APP_PEER_LOGON_LIMIT < uiLogonId) ||
            !IsNativeAppPeerAddress(pacTokens[4]) ||
            !IsNativeAppPeerToken(pacTokens[5]) ||
            !IsNativeAppPeerToken(pacTokens[6]) ||
            !IsNativeAppPeerToken(pacTokens[7])) {
            SetNativeAppPeerError(pcError, uiErrorLength,
                                  "invalid peer assignment response");
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else if (0 == strcmp("transport", pacTokens[8])) {
            eMode = IPSEC_MODE_TRANSPORT;
        }
        else if (0 == strcmp("tunnel", pacTokens[8])) {
            eMode = IPSEC_MODE_TUNNEL;
        }
        else {
            SetNativeAppPeerError(pcError, uiErrorLength,
                                  "invalid peer IPsec mode");
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
    }
    if (IPSEC_OK == eError) {
        char acPeerId[IPSEC_ID_LENGTH];
        NativeAppConfig_t EffectiveConfig = *pBaseConfig;

        EffectiveConfig.eMode = eMode;
        if (!CopyNativeAppPeerText(
                EffectiveConfig.acIkeProposals,
                sizeof(EffectiveConfig.acIkeProposals), pacTokens[6]) ||
            !CopyNativeAppPeerText(
                EffectiveConfig.acEspProposals,
                sizeof(EffectiveConfig.acEspProposals), pacTokens[7]) ||
            !BuildNativeAppPeerId(acPeerId, sizeof(acPeerId), uiGroupId,
                                  uiLogonId)) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            eError = BuildNativeAppPeerConfig(
                &EffectiveConfig, &Peer, uiGroupId, uiLogonId,
                pBaseConfig->acLocalAddress, pacTokens[4], acPeerId,
                pacTokens[5]);
        }
    }
    if (IPSEC_OK == eError) {
        eError = AppendNativeAppPeer(pTable, &Peer, ppPeer);
    }
    (void)close(iSocket);
    return eError;
}
