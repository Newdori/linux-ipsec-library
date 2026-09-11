#define _POSIX_C_SOURCE 200809L
#include "ipsec.h"

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef enum LivePacketAction {
    LIVE_PACKET_STATUS = 0,
    LIVE_PACKET_PLAIN_RECEIVE
} LivePacketAction_t;

static volatile sig_atomic_t giStop;

static void LogLiveDiagnostic(IpsecLogLevel_t eLevel,
    const char *pcMessage, void *pvUserData)
{
    (void)pvUserData;
    if (eLevel <= IPSEC_LOG_WARNING) {
        (void)fprintf(stderr, "libipsecctrl: %s\n", pcMessage);
    }
}

static void HandleLiveStop(int32_t iSignal)
{
    (void)iSignal;
    giStop = 1;
}

static bool CopyLiveArgument(char *pcOutput, size_t zCapacity,
    const char *pcInput)
{
    size_t zLength = strlen(pcInput);
    if (zLength >= zCapacity) {
        return false;
    }
    memcpy(pcOutput, pcInput, zLength + 1U);
    return true;
}

static bool ParseLiveNumber(const char *pcText, uint16_t *pusValue)
{
    char *pcEnd = NULL;
    unsigned long ulValue;
    errno = 0;
    ulValue = strtoul(pcText, &pcEnd, 10);
    if ((0 != errno) || (pcEnd == pcText) || ('\0' != *pcEnd) ||
        (0UL == ulValue) || (UINT16_MAX < ulValue)) {
        return false;
    }
    *pusValue = (uint16_t)ulValue;
    return true;
}

static IpsecError_t WriteLiveFile(const char *pcPath,
    const uint8_t *pucData, size_t zLength)
{
    int32_t iFd = (int32_t)open(pcPath,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    size_t zOffset = 0U;
    if (iFd < 0) {
        return (EEXIST == errno) ? IPSEC_ERR_FILE_EXISTS : IPSEC_ERR_FILE_OPEN;
    }
    while (zOffset < zLength) {
        ssize_t lWritten = write(iFd, pucData + zOffset, zLength - zOffset);
        if ((lWritten < 0) && (EINTR == errno)) {
            continue;
        }
        if (lWritten <= 0) {
            (void)close(iFd);
            return IPSEC_ERR_FILE_WRITE;
        }
        zOffset += (size_t)lWritten;
    }
    return (0 == close(iFd)) ? IPSEC_OK : IPSEC_ERR_FILE_WRITE;
}

static IpsecError_t ReceiveLivePlainPacket(IpsecContext_t *pContext,
    const char *pcPath)
{
    uint8_t aucData[IPSEC_PROTECTED_PACKET_CAPACITY];
    IpsecPlainPacket_t Plain = {.uiStructSize = sizeof(Plain),
        .pucData = aucData, .zCapacity = sizeof(aucData)};
    IpsecError_t eError;
    size_t zLength;
    (void)puts("PLAIN APPLICATION READY: deliver one authenticated ESP packet within 10 seconds.");
    eError = ReceiveIpsecPlainPacket(pContext, &Plain, 10000U);
    zLength = Plain.zLength;
    if (IPSEC_OK == eError) {
        eError = WriteLiveFile(pcPath, aucData, zLength);
    }
    return (0 != giStop) ? IPSEC_ERR_CANCELLED : eError;
}

static void ShowLiveUsage(const char *pcProgram)
{
    (void)fprintf(stderr,
        "usage: %s status BACKEND VICI_SOCKET CHARON_TUN_OR_DASH\n"
        "       %s plain-receive BACKEND VICI_SOCKET CHARON_TUN_OR_DASH "
        "QUEUE_NUMBER FILE\n",
        pcProgram, pcProgram);
}

static bool ParseLiveAction(int32_t iArgumentCount, char **ppcArguments,
    LivePacketAction_t *peAction)
{
    if ((5 == iArgumentCount) && (0 == strcmp("status", ppcArguments[1]))) {
        *peAction = LIVE_PACKET_STATUS;
    }
    else if ((7 == iArgumentCount) &&
        (0 == strcmp("plain-receive", ppcArguments[1]))) {
        *peAction = LIVE_PACKET_PLAIN_RECEIVE;
    }
    else {
        return false;
    }
    return true;
}

static bool ConfigureLiveDatapath(char **ppcArguments,
    LivePacketAction_t eAction, IpsecDatapathConfig_t *pDatapath)
{
    if (0 == strcmp("xfrm", ppcArguments[2])) {
        pDatapath->ePreference = IPSEC_DATAPATH_PREFER_XFRM;
    }
    else if (0 == strcmp("kernel-libipsec", ppcArguments[2])) {
        pDatapath->ePreference = IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC;
    }
    else if (0 != strcmp("auto", ppcArguments[2])) {
        return false;
    }
    if ((0 != strcmp("-", ppcArguments[4])) &&
        !CopyLiveArgument(pDatapath->acKernelLibipsecTunName,
            sizeof(pDatapath->acKernelLibipsecTunName), ppcArguments[4])) {
        return false;
    }
    if (LIVE_PACKET_PLAIN_RECEIVE == eAction) {
        pDatapath->ePlainPacketPath = IPSEC_PACKET_PATH_APPLICATION;
        return ParseLiveNumber(ppcArguments[5], &pDatapath->usPlainQueueNumber);
    }
    return true;
}

int main(int iArgumentCount, char **ppcArguments)
{
    IpsecContext_t *pContext = NULL;
    IpsecConfig_t Config = {.uiStructSize = sizeof(Config)};
    IpsecDatapathConfig_t Datapath = {.uiStructSize = sizeof(Datapath)};
    IpsecDatapathStatusEx_t Status = {.uiStructSize = sizeof(Status)};
    struct sigaction Action = {0};
    LivePacketAction_t eAction;
    IpsecError_t eError;
    const char *pcFile = NULL;
    if (!ParseLiveAction(iArgumentCount, ppcArguments, &eAction) ||
        !ConfigureLiveDatapath(ppcArguments, eAction, &Datapath)) {
        ShowLiveUsage(ppcArguments[0]);
        return 2;
    }
    Config.pcViciSocketPath = ppcArguments[3];
    Config.pLogCallback = LogLiveDiagnostic;
    Action.sa_handler = HandleLiveStop;
    (void)sigemptyset(&Action.sa_mask);
    (void)sigaction(SIGINT, &Action, NULL);
    (void)sigaction(SIGTERM, &Action, NULL);
    eError = InitializeIpsecWithDatapath(&pContext, &Config, &Datapath);
    if (IPSEC_OK == eError) {
        eError = GetIpsecDatapathStatusEx(pContext, &Status);
    }
    if (IPSEC_OK == eError) {
        (void)printf("backend=%u protected=%u plain=%u backend_ready=%s "
            "protected_ready=%s plain_ready=%s traffic_ready=%s "
            "child_count=%" PRIu32 " tun=%s\n",
            (uint32_t)Status.Backend.eType,
            (uint32_t)Status.eProtectedPacketPath,
            (uint32_t)Status.ePlainPacketPath,
            Status.bBackendReady ? "yes" : "no",
            Status.bProtectedPathReady ? "yes" : "no",
            Status.bPlainPathReady ? "yes" : "no",
            Status.bTrafficReady ? "yes" : "no",
            Status.uiInstalledChildCount,
            Status.Backend.acTunInterfaceName);
    }
    if ((IPSEC_OK == eError) && (LIVE_PACKET_STATUS != eAction)) {
        pcFile = ppcArguments[iArgumentCount - 1];
        eError = ReceiveLivePlainPacket(pContext, pcFile);
    }
    DeinitializeIpsec(pContext);
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "%s\n", GetIpsecErrorString(eError));
        return 1;
    }
    return 0;
}
