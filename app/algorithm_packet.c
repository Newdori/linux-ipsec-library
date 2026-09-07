#define _DEFAULT_SOURCE
#include "algorithm_packet.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

uint64_t GetNativeAppPacketTestTime(void)
{
    struct timespec Time;
    if (0 != clock_gettime(CLOCK_MONOTONIC, &Time)) {
        return 0U;
    }
    return (uint64_t)Time.tv_sec * 1000U + (uint64_t)Time.tv_nsec / 1000000U;
}

static IpsecError_t WaitNativeAppTestSocket(int32_t iSocket, int16_t sEvents,
    uint64_t ullDeadline)
{
    while (!IsNativeAppStopRequested()) {
        struct pollfd Descriptor = {.fd = iSocket, .events = sEvents};
        uint64_t ullNow = GetNativeAppPacketTestTime();
        uint64_t ullRemaining = (ullNow < ullDeadline) ? ullDeadline - ullNow : 0U;
        int32_t iResult;
        if (0U == ullNow) {
            return IPSEC_ERR_INTERNAL;
        }
        if (0U == ullRemaining) {
            return IPSEC_ERR_PACKET_TIMEOUT;
        }
        iResult = poll(&Descriptor, 1U,
            (int32_t)((ullRemaining > 250U) ? 250U : ullRemaining));
        if ((iResult < 0) && (EINTR == errno)) {
            continue;
        }
        if (iResult < 0) {
            return IPSEC_ERR_INTERNAL;
        }
        if (0 != (Descriptor.revents & sEvents)) {
            return IPSEC_OK; /* Drain readable bytes even if HUP is also set. */
        }
        if (0 != (Descriptor.revents & (POLLERR | POLLHUP | POLLNVAL))) {
            return IPSEC_ERR_VICI_TRANSPORT;
        }
    }
    return IPSEC_ERR_CANCELLED;
}

static IpsecError_t TransferNativeAppTestBytes(int32_t iSocket, uint8_t *pucData,
    size_t zLength, bool bSend, uint64_t ullDeadline, size_t *pzTransferred)
{
    *pzTransferred = 0U;
    while (*pzTransferred < zLength) {
        ssize_t lCount;
        IpsecError_t eError = WaitNativeAppTestSocket(iSocket,
            bSend ? POLLOUT : POLLIN, ullDeadline);
        if (IPSEC_OK != eError) {
            return eError;
        }
        lCount = bSend ? send(iSocket, pucData + *pzTransferred,
            zLength - *pzTransferred, MSG_DONTWAIT | MSG_NOSIGNAL) :
            recv(iSocket, pucData + *pzTransferred,
                zLength - *pzTransferred, MSG_DONTWAIT);
        if ((lCount < 0) && ((EINTR == errno) || (EAGAIN == errno) ||
            (EWOULDBLOCK == errno))) {
            continue;
        }
        if (lCount <= 0) {
            return IPSEC_ERR_VICI_TRANSPORT;
        }
        *pzTransferred += (size_t)lCount;
    }
    return IPSEC_OK;
}

IpsecError_t SendNativeAppTestFrame(int32_t iSocket, const uint8_t *pucData,
    size_t zLength, uint64_t ullDeadline)
{
    uint8_t aucHeader[4];
    size_t zTransferred;
    IpsecError_t eError;
    if ((NULL == pucData) || (0U == zLength) ||
        (zLength > NATIVE_APP_RELAY_CAPACITY)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    EncodeNativeAppTestLength(aucHeader, (uint32_t)zLength);
    eError = TransferNativeAppTestBytes(iSocket, aucHeader,
        sizeof(aucHeader), true, ullDeadline, &zTransferred);
    if (IPSEC_OK == eError) {
        eError = TransferNativeAppTestBytes(iSocket, (uint8_t *)pucData,
            zLength, true, ullDeadline, &zTransferred);
    }
    if (IPSEC_OK != eError) {
        (void)shutdown(iSocket, SHUT_RDWR); /* A partial frame cannot be retried. */
    }
    return eError;
}

IpsecError_t ReceiveNativeAppTestFrame(int32_t iSocket, uint8_t *pucData,
    size_t zCapacity, size_t *pzLength, uint64_t ullDeadline)
{
    uint8_t aucHeader[4];
    size_t zTransferred;
    size_t zLength = 0U;
    IpsecError_t eError;
    if ((NULL == pucData) || (NULL == pzLength)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    *pzLength = 0U;
    eError = TransferNativeAppTestBytes(iSocket, aucHeader,
        sizeof(aucHeader), false, ullDeadline, &zTransferred);
    if ((IPSEC_ERR_PACKET_TIMEOUT == eError) && (0U == zTransferred)) {
        return eError; /* No bytes consumed: safe for the control loop to retry. */
    }
    if (IPSEC_OK == eError) {
        eError = DecodeNativeAppTestLength(aucHeader, zCapacity, &zLength);
    }
    if (IPSEC_OK == eError) {
        eError = TransferNativeAppTestBytes(iSocket, pucData, zLength,
            false, ullDeadline, &zTransferred);
    }
    if (IPSEC_OK != eError) {
        (void)shutdown(iSocket, SHUT_RDWR);
        return (IPSEC_ERR_PACKET_TIMEOUT == eError) ?
            IPSEC_ERR_VICI_PROTOCOL : eError;
    }
    *pzLength = zLength;
    return IPSEC_OK;
}

bool IsNativeAppAlgorithmApplication(const NativeAppConfig_t *pConfig)
{
    return (NULL != pConfig) &&
        (IPSEC_PACKET_PATH_APPLICATION == pConfig->Datapath.eProtectedPacketPath);
}

static bool ParseNativeAppTestAddress(const char *pcText, struct in_addr *pAddress,
    bool bSelector)
{
    char acAddress[16];
    const char *pcSlash = strchr(pcText, '/');
    size_t zLength = (NULL == pcSlash) ? strlen(pcText) : (size_t)(pcSlash - pcText);
    uint32_t uiHost;
    if ((0U == zLength) || (zLength >= sizeof(acAddress)) ||
        ((NULL != pcSlash) && (!bSelector || (0 != strcmp(pcSlash, "/32"))))) {
        return false;
    }
    memcpy(acAddress, pcText, zLength);
    acAddress[zLength] = '\0';
    if (1 != inet_pton(AF_INET, acAddress, pAddress)) {
        return false;
    }
    uiHost = ntohl(pAddress->s_addr);
    return (0U != (uiHost >> 24U)) && (127U != (uiHost >> 24U)) &&
        (uiHost < 0xe0000000U);
}

IpsecError_t ValidateNativeAppAlgorithmPacketConfig(const NativeAppConfig_t *pConfig)
{
    struct in_addr Local, Remote, LocalTs, RemoteTs;
    if (NULL == pConfig) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (pConfig->Datapath.eProtectedPacketPath != pConfig->Datapath.ePlainPacketPath) {
        return IPSEC_ERR_PACKET_PATH_MISMATCH;
    }
    if (!IsNativeAppAlgorithmApplication(pConfig)) {
        return IPSEC_OK;
    }
    if ((IPSEC_MODE_TUNNEL != pConfig->eMode) ||
        (NATIVE_APP_PLAIN_NETFILTER_INPUT != pConfig->ePlainNetfilterHook) ||
        !ParseNativeAppTestAddress(pConfig->acLocalAddress, &Local, false) ||
        !ParseNativeAppTestAddress(pConfig->acRemoteAddress, &Remote, false) ||
        !ParseNativeAppTestAddress(pConfig->acLocalTrafficSelector, &LocalTs, true) ||
        !ParseNativeAppTestAddress(pConfig->acRemoteTrafficSelector, &RemoteTs, true) ||
        (Local.s_addr == Remote.s_addr) || (LocalTs.s_addr == RemoteTs.s_addr) ||
        (Local.s_addr == LocalTs.s_addr) || (Remote.s_addr == RemoteTs.s_addr) ||
        (Local.s_addr == RemoteTs.s_addr) || (Remote.s_addr == LocalTs.s_addr)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    return IPSEC_OK;
}

IpsecError_t OpenNativeAppAlgorithmStream(const NativeAppConfig_t *pConfig,
    uint32_t uiPort, bool bServer, int32_t *piSocket)
{
    struct sockaddr_in Local = {.sin_family = AF_INET};
    struct sockaddr_in Remote = {.sin_family = AF_INET};
    int32_t iSocket;
    int32_t iReuse = 1;
    IpsecError_t eError = IPSEC_OK;
    uint64_t ullDeadline;
    if ((NULL == pConfig) || (NULL == piSocket)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    ullDeadline = GetNativeAppPacketTestTime() + pConfig->uiTimeoutMs;
    *piSocket = -1;
    if ((0U == uiPort) || (uiPort > UINT16_MAX) ||
        (1 != inet_pton(AF_INET, pConfig->acLocalAddress, &Local.sin_addr)) ||
        (1 != inet_pton(AF_INET, pConfig->acRemoteAddress, &Remote.sin_addr))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    Local.sin_port = bServer ? htons((uint16_t)uiPort) : 0U;
    Remote.sin_port = htons((uint16_t)uiPort);
    iSocket = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (iSocket < 0) {
        return IPSEC_ERR_INTERNAL;
    }
    if ((0 != setsockopt(iSocket, SOL_SOCKET, SO_REUSEADDR, &iReuse, sizeof(iReuse))) ||
        (0 != bind(iSocket, (const struct sockaddr *)&Local, sizeof(Local)))) {
        eError = IPSEC_ERR_INTERNAL;
    }
    else if (bServer) {
        if (0 != listen(iSocket, 4)) {
            eError = IPSEC_ERR_INTERNAL;
        }
        (void)printf("APPLICATION algorithm server: TCP %s:%" PRIu32
            " waiting for %s (Ctrl-C cancels)\n", pConfig->acLocalAddress,
            uiPort, pConfig->acRemoteAddress);
        (void)fflush(stdout);
        while ((IPSEC_OK == eError) && !IsNativeAppStopRequested()) {
            struct sockaddr_in Sender;
            socklen_t zLength = sizeof(Sender);
            int32_t iClient;
            eError = WaitNativeAppTestSocket(iSocket, POLLIN,
                GetNativeAppPacketTestTime() + 500U);
            if (IPSEC_ERR_PACKET_TIMEOUT == eError) {
                eError = IPSEC_OK;
                continue;
            }
            if (IPSEC_OK != eError) {
                break;
            }
            iClient = accept(iSocket, (struct sockaddr *)&Sender, &zLength);
            if (iClient < 0) {
                if ((EINTR == errno) || (EAGAIN == errno)) {
                    continue;
                }
                eError = IPSEC_ERR_INTERNAL;
                break;
            }
            if ((sizeof(Sender) != zLength) || (AF_INET != Sender.sin_family) ||
                (Remote.sin_addr.s_addr != Sender.sin_addr.s_addr)) {
                (void)close(iClient);
                continue;
            }
            if (0 != fcntl(iClient, F_SETFD, FD_CLOEXEC)) {
                (void)close(iClient);
                eError = IPSEC_ERR_INTERNAL;
                break;
            }
            (void)close(iSocket);
            *piSocket = iClient;
            return IPSEC_OK;
        }
        if (IsNativeAppStopRequested()) {
            eError = IPSEC_ERR_CANCELLED;
        }
    }
    else {
        if (0 != connect(iSocket, (const struct sockaddr *)&Remote, sizeof(Remote))) {
            if (EINPROGRESS != errno) {
                eError = IPSEC_ERR_VICI_TRANSPORT;
            }
            else {
                int32_t iError = 0;
                socklen_t zLength = sizeof(iError);
                eError = WaitNativeAppTestSocket(iSocket, POLLOUT, ullDeadline);
                if ((IPSEC_OK == eError) &&
                    ((0 != getsockopt(iSocket, SOL_SOCKET, SO_ERROR, &iError, &zLength)) ||
                     (0 != iError))) {
                    eError = IPSEC_ERR_VICI_TRANSPORT;
                }
            }
        }
        if (IPSEC_OK == eError) {
            *piSocket = iSocket;
            return IPSEC_OK;
        }
    }
    (void)fprintf(stderr, "APPLICATION algorithm TCP setup failed: %s:%" PRIu32
        " peer=%s error=%s errno=%d; start the updated responder serve command first\n",
        pConfig->acLocalAddress, uiPort, pConfig->acRemoteAddress,
        GetIpsecErrorString(eError), errno);
    (void)close(iSocket);
    return eError;
}

typedef struct NativeAppProbeSession {
    IpsecContext_t *pContext;
    const NativeAppConfig_t *pConfig;
    NativeAppPacketTestResult_t *pResult;
    FILE *pLog;
    int32_t iSocket;
    int32_t iUdp;
    struct sockaddr_in Local;
    struct sockaddr_in Remote;
    uint64_t ullDeadline;
    uint64_t ullStarted;
    NativeAppPacketEvidence_t *pEvidence;
    uint8_t aucNonce[16];
} NativeAppProbeSession_t;

static void RecordNativeAppProbeStage(NativeAppProbeSession_t *pSession,
    const char *pcStage, IpsecError_t eError, size_t zLength)
{
    size_t zStageLength = strlen(pcStage);
    if ((IPSEC_OK == pSession->pResult->eError) &&
        (zStageLength < sizeof(pSession->pResult->acStage))) {
        memcpy(pSession->pResult->acStage, pcStage, zStageLength + 1U);
        pSession->pResult->eError = eError;
    }
    (void)fprintf(pSession->pLog, "elapsed_ms=%" PRIu64 " probe=%" PRIu32
        " direction=%s stage=%s bytes=%zu error=%s errno_snapshot=%d\n",
        GetNativeAppPacketTestTime() - pSession->ullStarted,
        (NULL == pSession->pEvidence) ? 0U : pSession->pEvidence->uiProbeSequence,
        (NULL == pSession->pEvidence) ? "control" :
            (pSession->pEvidence->bOutbound ? "outbound" : "inbound"), pcStage,
        zLength, (IPSEC_OK == eError) ? "none" : GetIpsecErrorString(eError),
        (IPSEC_OK == eError) ? 0 : errno);
    if (NULL != pSession->pEvidence) {
        NativeAppPacketEvidence_t *pEvidence = pSession->pEvidence;
        if ((IPSEC_OK != eError) && (IPSEC_OK == pEvidence->eError)) {
            pEvidence->eError = eError;
        }
        (void)fprintf(pSession->pLog, "  esp_bytes=%" PRIu32 " spi=0x%08" PRIx32
            " esp_sequence=%" PRIu32 " plain_bytes=%" PRIu32
            " captured=%s relayed=%s esp_valid=%s submitted=%s plain_received=%s"
            " payload_match=%s peer_confirmed=%s\n",
            pEvidence->uiEspLength, pEvidence->uiEspSpi, pEvidence->uiEspSequence,
            pEvidence->uiPlainLength, pEvidence->bEspCaptured ? "yes" : "no",
            pEvidence->bEspRelayed ? "yes" : "no", pEvidence->bEspValid ? "yes" : "no",
            pEvidence->bEspSubmitted ? "yes" : "no", pEvidence->bPlainReceived ? "yes" : "no",
            pEvidence->bPayloadMatch ? "yes" : "no", pEvidence->bPeerConfirmed ? "yes" : "no");
    }
    (void)fflush(pSession->pLog);
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "APPLICATION packet test: stage=%s error=%s\n",
            pcStage, GetIpsecErrorString(eError));
    }
}

/* Records always carry a status, including local receive/submit failures.
 * This keeps the two endpoints in lockstep without submitting an empty file.
 */
static IpsecError_t SendNativeAppProbeRecord(NativeAppProbeSession_t *pSession,
    uint8_t ucKind, uint8_t ucSequence, IpsecError_t eStatus,
    const uint8_t *pucData, size_t zLength)
{
    uint8_t aucFrame[NATIVE_APP_RELAY_CAPACITY];
    if (zLength > sizeof(aucFrame) - 12U) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    memcpy(aucFrame, "IPRP", 4U);
    aucFrame[4] = 1U;
    aucFrame[5] = ucKind;
    aucFrame[6] = ucSequence;
    aucFrame[7] = 0U;
    EncodeNativeAppTestLength(aucFrame + 8U, (uint32_t)eStatus);
    if (0U != zLength) {
        memcpy(aucFrame + 12U, pucData, zLength);
    }
    return SendNativeAppTestFrame(pSession->iSocket, aucFrame,
        12U + zLength, pSession->ullDeadline + 5000U);
}

static IpsecError_t ReceiveNativeAppProbeRecord(NativeAppProbeSession_t *pSession,
    uint8_t ucKind, uint8_t ucSequence, uint8_t *pucData, size_t zCapacity,
    size_t *pzLength, IpsecError_t *peStatus)
{
    uint8_t aucFrame[NATIVE_APP_RELAY_CAPACITY];
    size_t zLength = 0U;
    uint32_t uiStatus;
    IpsecError_t eError = ReceiveNativeAppTestFrame(pSession->iSocket, aucFrame,
        sizeof(aucFrame), &zLength, pSession->ullDeadline + 5000U);
    /* Both sides reserve the same bounded control grace after the data
     * deadline so a receive timeout can still be reported and acknowledged. */
    *pzLength = 0U;
    if (IPSEC_OK != eError) {
        return eError;
    }
    if ((zLength < 12U) || (zLength - 12U > zCapacity) ||
        (0 != memcmp(aucFrame, "IPRP", 4U)) || (1U != aucFrame[4]) ||
        (ucKind != aucFrame[5]) || (ucSequence != aucFrame[6]) ||
        (0U != aucFrame[7])) {
        (void)shutdown(pSession->iSocket, SHUT_RDWR);
        return IPSEC_ERR_VICI_PROTOCOL;
    }
    uiStatus = ((uint32_t)aucFrame[8] << 24U) | ((uint32_t)aucFrame[9] << 16U) |
        ((uint32_t)aucFrame[10] << 8U) | aucFrame[11];
    if (uiStatus > (uint32_t)IPSEC_ERR_RESOURCE_CONFLICT) {
        (void)shutdown(pSession->iSocket, SHUT_RDWR);
        return IPSEC_ERR_VICI_PROTOCOL;
    }
    *peStatus = (IpsecError_t)uiStatus;
    *pzLength = zLength - 12U;
    if (0U != *pzLength) {
        memcpy(pucData, aucFrame + 12U, *pzLength);
    }
    return IPSEC_OK;
}

static IpsecError_t OpenNativeAppProbeUdp(NativeAppProbeSession_t *pSession)
{
    IpsecDatapathStatus_t Status = {0};
    IpsecPacketPathStatus_t Paths = {.uiStructSize = sizeof(Paths)};
    IpsecError_t eError = GetIpsecDatapathStatus(pSession->pContext, &Status);
    if (IPSEC_OK == eError) {
        eError = GetIpsecPacketPathStatus(pSession->pContext, &Paths);
    }
    if (IPSEC_OK != eError) {
        return eError;
    }
    if ((IPSEC_DATAPATH_KERNEL_LIBIPSEC != Status.eType) || !Status.bReady ||
        !Paths.bProtectedPathReady || !Paths.bPlainPathReady ||
        ('\0' == Status.acTunInterfaceName[0])) {
        return IPSEC_ERR_DATAPATH_UNAVAILABLE;
    }
    pSession->Local.sin_family = AF_INET;
    pSession->Remote.sin_family = AF_INET;
    pSession->Local.sin_port = htons(NATIVE_APP_PROBE_PORT);
    pSession->Remote.sin_port = htons(NATIVE_APP_PROBE_PORT);
    if (!ParseNativeAppTestAddress(pSession->pConfig->acLocalTrafficSelector,
            &pSession->Local.sin_addr, true) ||
        !ParseNativeAppTestAddress(pSession->pConfig->acRemoteTrafficSelector,
            &pSession->Remote.sin_addr, true)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pSession->iUdp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (pSession->iUdp < 0) {
        return IPSEC_ERR_INTERNAL;
    }
    /* Constrain locally generated plaintext to charon's actual TUN. Never
     * silently fall back to sending the probe over an ordinary NIC.
     */
    if ((0 != setsockopt(pSession->iUdp, SOL_SOCKET, SO_BINDTODEVICE,
            Status.acTunInterfaceName, strlen(Status.acTunInterfaceName) + 1U)) ||
        (0 != bind(pSession->iUdp, (const struct sockaddr *)&pSession->Local,
            sizeof(pSession->Local)))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    return IPSEC_OK;
}

static IpsecError_t ReceiveNativeAppProbePacket(NativeAppProbeSession_t *pSession,
    bool bPlain, uint8_t *pucData, size_t *pzLength)
{
    while (!IsNativeAppStopRequested()) {
        IpsecError_t eError;
        uint64_t ullNow = GetNativeAppPacketTestTime();
        uint32_t uiWait;
        if (ullNow >= pSession->ullDeadline) {
            return IPSEC_ERR_PACKET_TIMEOUT;
        }
        uiWait = (uint32_t)((pSession->ullDeadline - ullNow > 250U) ?
            250U : pSession->ullDeadline - ullNow);
        if (bPlain) {
            IpsecPlainPacket_t Packet = {.uiStructSize = sizeof(Packet),
                .pucData = pucData, .zCapacity = IPSEC_PROTECTED_PACKET_CAPACITY};
            eError = ReceiveIpsecPlainPacket(pSession->pContext, &Packet, uiWait);
            *pzLength = Packet.zLength;
        }
        else {
            IpsecProtectedPacket_t Packet = {.uiStructSize = sizeof(Packet),
                .pucData = pucData, .zCapacity = IPSEC_PROTECTED_PACKET_CAPACITY};
            eError = ReceiveIpsecProtectedPacket(pSession->pContext, &Packet, uiWait);
            *pzLength = Packet.zLength;
        }
        if (IPSEC_ERR_PACKET_TIMEOUT != eError) {
            return eError;
        }
    }
    return IPSEC_ERR_CANCELLED;
}

static IpsecError_t SendNativeAppProbe(NativeAppProbeSession_t *pSession,
    const char *pcCaseId, uint8_t ucSequence)
{
    uint8_t aucProbe[NATIVE_APP_PROBE_LENGTH];
    uint8_t aucData[IPSEC_PROTECTED_PACKET_CAPACITY];
    size_t zLength = 0U;
    IpsecError_t eStatus = IPSEC_OK;
    IpsecError_t ePeerStatus = IPSEC_OK;
    IpsecError_t eError;
    ssize_t lSent;
    NativeAppPacketEvidence_t *pEvidence;
    if ((0U == ucSequence) || (ucSequence > NATIVE_APP_PACKET_EVIDENCE_CAPACITY)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pEvidence = &pSession->pResult->aPackets[ucSequence - 1U];
    pSession->pEvidence = pEvidence;
    pEvidence->uiProbeSequence = ucSequence;
    pEvidence->bOutbound = true;
    BuildNativeAppTestProbe(aucProbe, pSession->aucNonce, pcCaseId, ucSequence);
    lSent = sendto(pSession->iUdp, aucProbe, sizeof(aucProbe), MSG_NOSIGNAL,
        (const struct sockaddr *)&pSession->Remote, sizeof(pSession->Remote));
    if ((ssize_t)sizeof(aucProbe) != lSent) {
        eStatus = IPSEC_ERR_INTERNAL;
    }
    RecordNativeAppProbeStage(pSession, "plain_send", eStatus, sizeof(aucProbe));
    if (IPSEC_OK == eStatus) {
        pEvidence->bCaptureAttempted = true;
        eStatus = ReceiveNativeAppProbePacket(pSession, false, aucData, &zLength);
        pEvidence->bEspCaptured = (IPSEC_OK == eStatus);
        if (IPSEC_OK == eStatus) {
            eStatus = InspectNativeAppTestEsp(aucData, zLength,
                pSession->pResult->uiExpectedOutboundSpi, pEvidence);
        }
        if ((IPSEC_OK == eStatus) && (zLength > NATIVE_APP_RELAY_CAPACITY - 12U)) {
            eStatus = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        RecordNativeAppProbeStage(pSession, "protected_receive", eStatus, zLength);
    }
    eError = SendNativeAppProbeRecord(pSession, 'E', ucSequence, eStatus,
        aucData, (IPSEC_OK == eStatus) ? zLength : 0U);
    if (IPSEC_OK == eError) {
        eError = ReceiveNativeAppProbeRecord(pSession, 'A', ucSequence, aucData,
            0U, &zLength, &ePeerStatus);
    }
    if (IPSEC_OK != eError) {
        RecordNativeAppProbeStage(pSession, "relay_send_ack", eError, 0U);
        return eError;
    }
    if (IPSEC_OK != eStatus) {
        return eStatus;
    }
    pEvidence->bPeerConfirmed = (IPSEC_OK == ePeerStatus);
    RecordNativeAppProbeStage(pSession, "peer_plain_verify", ePeerStatus, 0U);
    if (IPSEC_OK == ePeerStatus) {
        pSession->pResult->uiSent++;
    }
    return ePeerStatus;
}

static IpsecError_t ReceiveNativeAppProbe(NativeAppProbeSession_t *pSession,
    const char *pcCaseId, uint8_t ucSequence)
{
    uint8_t aucData[IPSEC_PROTECTED_PACKET_CAPACITY];
    uint8_t aucProbe[NATIVE_APP_PROBE_LENGTH];
    size_t zLength = 0U;
    IpsecError_t eStatus = IPSEC_OK;
    NativeAppPacketEvidence_t *pEvidence;
    if ((0U == ucSequence) || (ucSequence > NATIVE_APP_PACKET_EVIDENCE_CAPACITY)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pEvidence = &pSession->pResult->aPackets[ucSequence - 1U];
    pSession->pEvidence = pEvidence;
    pEvidence->uiProbeSequence = ucSequence;
    pEvidence->bOutbound = false;
    IpsecError_t eError = ReceiveNativeAppProbeRecord(pSession, 'E', ucSequence,
        aucData, sizeof(aucData), &zLength, &eStatus);
    if (IPSEC_OK != eError) {
        RecordNativeAppProbeStage(pSession, "relay_receive", eError, zLength);
        return eError;
    }
    pEvidence->bEspRelayed = (IPSEC_OK == eStatus);
    if (IPSEC_OK == eStatus) {
        eStatus = InspectNativeAppTestEsp(aucData, zLength,
            pSession->pResult->uiExpectedInboundSpi, pEvidence);
    }
    RecordNativeAppProbeStage(pSession, "peer_protected_receive", eStatus, zLength);
    if (IPSEC_OK == eStatus) {
        IpsecProtectedPacket_t Packet = {.uiStructSize = sizeof(Packet),
            .pucData = aucData, .zLength = zLength, .zCapacity = sizeof(aucData),
            .eType = IPSEC_PROTECTED_PACKET_RAW_ESP,
            .eDirection = IPSEC_PACKET_DIRECTION_INBOUND};
        pEvidence->bSubmitAttempted = true;
        eStatus = SubmitIpsecProtectedPacket(pSession->pContext, &Packet);
        pEvidence->bEspSubmitted = (IPSEC_OK == eStatus);
        RecordNativeAppProbeStage(pSession, "protected_submit", eStatus, zLength);
    }
    if (IPSEC_OK == eStatus) {
        pEvidence->bPlainAttempted = true;
        eStatus = ReceiveNativeAppProbePacket(pSession, true, aucData, &zLength);
        pEvidence->bPlainReceived = (IPSEC_OK == eStatus);
        pEvidence->uiPlainLength = (zLength <= UINT16_MAX) ? (uint32_t)zLength : 0U;
        RecordNativeAppProbeStage(pSession, "plain_receive", eStatus, zLength);
    }
    if (IPSEC_OK == eStatus) {
        BuildNativeAppTestProbe(aucProbe, pSession->aucNonce, pcCaseId, ucSequence);
        pEvidence->bCompareAttempted = true;
        eStatus = ValidateNativeAppTestPlain(aucData, zLength,
            (const uint8_t *)&pSession->Remote.sin_addr,
            (const uint8_t *)&pSession->Local.sin_addr, aucProbe);
        pEvidence->bPayloadMatch = (IPSEC_OK == eStatus);
        RecordNativeAppProbeStage(pSession, "plain_compare", eStatus, zLength);
        if (IPSEC_OK == eStatus) {
            pSession->pResult->uiReceived++;
        }
    }
    eError = SendNativeAppProbeRecord(pSession, 'A', ucSequence, eStatus, NULL, 0U);
    RecordNativeAppProbeStage(pSession, "relay_ack_send", eError, 0U);
    return (IPSEC_OK == eError) ? eStatus : eError;
}

IpsecError_t RunNativeAppAlgorithmPacketTest(IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig, int32_t iSocket, const char *pcCaseId,
    bool bServer, const char *pcDirectory, NativeAppPacketTestResult_t *pResult)
{
    NativeAppProbeSession_t Session = {.pContext = pContext, .pConfig = pConfig,
        .iSocket = iSocket, .iUdp = -1, .pResult = pResult};
    uint8_t aucHello[NATIVE_APP_ALGORITHM_CASE_ID_LENGTH + 16U] = {0};
    char acPath[NATIVE_APP_PATH_LENGTH];
    size_t zLength = 0U;
    uint32_t uiIndex;
    int32_t iLength;
    IpsecError_t eStatus = IPSEC_OK;
    IpsecError_t eError;
    uint32_t uiInboundSpi;
    uint32_t uiOutboundSpi;
    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pcCaseId) ||
        (NULL == pcDirectory) || (NULL == pResult) || (iSocket < 0)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    uiInboundSpi = pResult->uiExpectedInboundSpi;
    uiOutboundSpi = pResult->uiExpectedOutboundSpi;
    memset(pResult, 0, sizeof(*pResult));
    pResult->bAttempted = true;
    pResult->uiExpectedInboundSpi = uiInboundSpi;
    pResult->uiExpectedOutboundSpi = uiOutboundSpi;
    Session.ullStarted = GetNativeAppPacketTestTime();
    Session.ullDeadline = Session.ullStarted + pConfig->uiTimeoutMs;
    iLength = snprintf(acPath, sizeof(acPath), "%s/application_packet.log", pcDirectory);
    if ((iLength < 0) || ((size_t)iLength >= sizeof(acPath))) {
        pResult->eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        memcpy(pResult->acStage, "report_open", sizeof("report_open"));
        (void)shutdown(iSocket, SHUT_RDWR);
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    Session.pLog = fopen(acPath, "wx");
    if (NULL == Session.pLog) {
        pResult->eError = IPSEC_ERR_FILE_OPEN;
        memcpy(pResult->acStage, "report_open", sizeof("report_open"));
        (void)shutdown(iSocket, SHUT_RDWR);
        return IPSEC_ERR_FILE_OPEN;
    }
    iLength = snprintf(acPath, sizeof(acPath), "%s/library_packet.log", pcDirectory);
    eError = ((iLength < 0) || ((size_t)iLength >= sizeof(acPath))) ?
        IPSEC_ERR_BUFFER_TOO_SMALL :
        OpenNativeAppDiagnosticLog(pConfig->pDiagnosticLog, acPath);
    if (IPSEC_OK != eError) {
        pResult->eError = eError;
        memcpy(pResult->acStage, "diagnostic_open", sizeof("diagnostic_open"));
        (void)fclose(Session.pLog);
        (void)shutdown(iSocket, SHUT_RDWR);
        return eError;
    }
    (void)fprintf(Session.pLog, "transport=TCP packet_path=APPLICATION case=%s "
        "packets_per_direction=%u\n", pcCaseId, NATIVE_APP_PROBE_COUNT);
    (void)fprintf(Session.pLog, "outer_local=%s outer_remote=%s local_ts=%s remote_ts=%s\n"
        "expected_spi_in=0x%08" PRIx32 " expected_spi_out=0x%08" PRIx32 "\n",
        pConfig->acLocalAddress, pConfig->acRemoteAddress, pConfig->acLocalTrafficSelector,
        pConfig->acRemoteTrafficSelector, uiInboundSpi, uiOutboundSpi);
    eError = ValidateNativeAppAlgorithmPacketConfig(pConfig);
    if ((IPSEC_OK == eError) && ((0U == uiInboundSpi) || (0U == uiOutboundSpi))) {
        eError = IPSEC_ERR_CHILD_FAILED;
    }
    if (IPSEC_OK == eError) {
        eError = OpenNativeAppProbeUdp(&Session);
    }
    RecordNativeAppProbeStage(&Session, "preflight_inner_address_tun", eError, 0U);
    /* Exchange local preparation errors as well as the per-case nonce. */
    if (!bServer) {
        int32_t iRandom = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
        if (iRandom < 0) {
            eError = IPSEC_ERR_RANDOM;
        }
        else {
            ssize_t lRead = read(iRandom, Session.aucNonce, sizeof(Session.aucNonce));
            (void)close(iRandom);
            if ((ssize_t)sizeof(Session.aucNonce) != lRead) {
                eError = IPSEC_ERR_RANDOM;
            }
        }
        if (strlen(pcCaseId) >= NATIVE_APP_ALGORITHM_CASE_ID_LENGTH) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        if (IPSEC_OK == eError) {
            memcpy(aucHello, pcCaseId, strlen(pcCaseId));
            memcpy(aucHello + NATIVE_APP_ALGORITHM_CASE_ID_LENGTH, Session.aucNonce, 16U);
        }
        eStatus = eError;
        eError = SendNativeAppProbeRecord(&Session, 'H', 0U, eStatus,
            aucHello, sizeof(aucHello));
        if (IPSEC_OK == eError) {
            eError = ReceiveNativeAppProbeRecord(&Session, 'A', 0U,
                aucHello, 0U, &zLength, &eStatus);
        }
        if (IPSEC_OK == eError) {
            eError = eStatus;
        }
    }
    else {
        IpsecError_t eLocal = eError;
        eError = ReceiveNativeAppProbeRecord(&Session, 'H', 0U,
            aucHello, sizeof(aucHello), &zLength, &eStatus);
        if (IPSEC_OK == eError) {
            if ((sizeof(aucHello) != zLength) ||
                (NULL == memchr(aucHello, 0, NATIVE_APP_ALGORITHM_CASE_ID_LENGTH)) ||
                ((IPSEC_OK == eStatus) && (0 != strcmp((char *)aucHello, pcCaseId)))) {
                eStatus = IPSEC_ERR_VICI_PROTOCOL;
            }
            if (IPSEC_OK != eLocal) {
                eStatus = eLocal;
            }
            memcpy(Session.aucNonce, aucHello + NATIVE_APP_ALGORITHM_CASE_ID_LENGTH, 16U);
            eError = SendNativeAppProbeRecord(&Session, 'A', 0U, eStatus, NULL, 0U);
            if (IPSEC_OK == eError) {
                eError = eStatus;
            }
        }
    }
    RecordNativeAppProbeStage(&Session, "relay_handshake", eError, 0U);
    for (uiIndex = 0U; (uiIndex < NATIVE_APP_PROBE_COUNT) && (IPSEC_OK == eError);
         uiIndex++) {
        uint8_t ucSequence = (uint8_t)(uiIndex * 2U + 1U);
        eError = bServer ? ReceiveNativeAppProbe(&Session, pcCaseId, ucSequence) :
            SendNativeAppProbe(&Session, pcCaseId, ucSequence);
        if (IPSEC_OK == eError) {
            eError = bServer ? SendNativeAppProbe(&Session, pcCaseId, ucSequence + 1U) :
                ReceiveNativeAppProbe(&Session, pcCaseId, ucSequence + 1U);
        }
    }
    if (Session.iUdp >= 0) {
        (void)close(Session.iUdp);
    }
    Session.pEvidence = NULL;
    if (IPSEC_OK != pResult->eError) {
        eError = pResult->eError; /* Keep the first failed stage and its cause together. */
    }
    if ((IPSEC_OK == eError) && !VerifyNativeAppPacketTestProof(pResult)) {
        eError = IPSEC_ERR_PACKET_INVALID;
        RecordNativeAppProbeStage(&Session, "proof_incomplete", eError, 0U);
    }
    if (IPSEC_OK == eError) {
        RecordNativeAppProbeStage(&Session, "complete", IPSEC_OK, 0U);
    }
    pResult->eError = eError;
    {
        FILE *pCsv = NULL;
        IpsecError_t eReport = IPSEC_OK;
        iLength = snprintf(acPath, sizeof(acPath), "%s/packet_evidence.csv", pcDirectory);
        if ((iLength < 0) || ((size_t)iLength >= sizeof(acPath))) {
            eReport = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            pCsv = fopen(acPath, "wx");
            eReport = (NULL == pCsv) ? IPSEC_ERR_FILE_OPEN :
                WriteNativeAppPacketEvidenceCsv(pCsv, pResult);
        }
        if ((NULL != pCsv) && (0 != fclose(pCsv)) && (IPSEC_OK == eReport)) {
            eReport = IPSEC_ERR_FILE_WRITE;
        }
        if ((IPSEC_OK != eReport) && (IPSEC_OK == eError)) {
            eError = eReport;
            RecordNativeAppProbeStage(&Session, "evidence_write", eError, 0U);
        }
    }
    {
        IpsecError_t eDiagnostic =
            CloseNativeAppDiagnosticLog(pConfig->pDiagnosticLog);
        if ((IPSEC_OK != eDiagnostic) && (IPSEC_OK == eError)) {
            eError = eDiagnostic;
            pResult->eError = eError;
            memcpy(pResult->acStage, "diagnostic_write",
                sizeof("diagnostic_write"));
        }
        else {
            /* Preserve the earlier packet-path result. */
        }
    }
    (void)WriteNativeAppPacketEvidenceText(Session.pLog, pResult);
    (void)fprintf(Session.pLog, "sent_verified=%" PRIu32 " received_verified=%" PRIu32
        " result=%s\n", pResult->uiSent, pResult->uiReceived,
        (IPSEC_OK == eError) ? "PASS" : "FAIL");
    if ((0 != ferror(Session.pLog)) && (IPSEC_OK == eError)) {
        eError = IPSEC_ERR_FILE_WRITE;
        pResult->eError = eError;
        memcpy(pResult->acStage, "report_write", sizeof("report_write"));
    }
    if ((0 != fclose(Session.pLog)) && (IPSEC_OK == eError)) {
        eError = IPSEC_ERR_FILE_WRITE;
        pResult->eError = eError;
        memcpy(pResult->acStage, "report_write", sizeof("report_write"));
    }
    (void)WriteNativeAppPacketEvidenceText(stdout, pResult);
    return eError;
}
