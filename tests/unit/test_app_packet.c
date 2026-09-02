#include "app_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); return false; \
} } while (0)

static IpsecPacketPathMode_t geProtectedPath = IPSEC_PACKET_PATH_APPLICATION;
static IpsecPacketPathMode_t gePlainPath = IPSEC_PACKET_PATH_APPLICATION;
static IpsecError_t geProtectedReceiveError = IPSEC_OK;
static IpsecError_t geProtectedSubmitError = IPSEC_OK;
static IpsecError_t gePlainReceiveError = IPSEC_OK;
static uint32_t guiProtectedReceives;
static uint32_t guiProtectedSubmissions;
static uint32_t guiPlainReceives;

IpsecError_t GetIpsecPacketPathStatus(IpsecContext_t *pContext,
    IpsecPacketPathStatus_t *pStatus)
{
    (void)pContext;
    pStatus->eProtectedPacketPath = geProtectedPath;
    pStatus->ePlainPacketPath = gePlainPath;
    pStatus->bProtectedPathReady = true;
    pStatus->bPlainPathReady = true;
    return IPSEC_OK;
}

IpsecError_t ReceiveIpsecProtectedPacket(IpsecContext_t *pContext,
    IpsecProtectedPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    (void)pContext;
    (void)uiTimeoutMs;
    guiProtectedReceives++;
    if (IPSEC_OK == geProtectedReceiveError) {
        memset(pPacket->pucData, 0x5a, 40U);
        pPacket->zLength = 40U;
    }
    return geProtectedReceiveError;
}

IpsecError_t SubmitIpsecProtectedPacket(IpsecContext_t *pContext,
    const IpsecProtectedPacket_t *pPacket)
{
    (void)pContext;
    guiProtectedSubmissions++;
    if ((IPSEC_PACKET_DIRECTION_INBOUND != pPacket->eDirection) ||
        (IPSEC_PROTECTED_PACKET_RAW_ESP != pPacket->eType) ||
        (40U != pPacket->zLength)) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    return geProtectedSubmitError;
}

IpsecError_t ReceiveIpsecPlainPacket(IpsecContext_t *pContext,
    IpsecPlainPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    (void)pContext;
    (void)uiTimeoutMs;
    guiPlainReceives++;
    if (IPSEC_OK == gePlainReceiveError) {
        memset(pPacket->pucData, 0, 20U);
        pPacket->pucData[0] = 0x45U;
        pPacket->pucData[3] = 20U;
        pPacket->zLength = 20U;
        pPacket->eFamily = IPSEC_ADDRESS_FAMILY_IPV4;
    }
    return gePlainReceiveError;
}

bool IsNativeAppStopRequested(void)
{
    return false;
}

static bool WriteTestInput(const char *pcPath)
{
    uint8_t aucData[40] = {0};
    int32_t iFd = (int32_t)open(pcPath, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (iFd < 0) {
        return false;
    }
    return ((ssize_t)sizeof(aucData) == write(iFd, aucData, sizeof(aucData))) &&
        (0 == close(iFd));
}

static bool VerifyPacketFiles(void)
{
    IpsecContext_t *pContext = (IpsecContext_t *)(uintptr_t)1U;
    NativeAppPacketOptions_t Options = {.pcPath = "protected.bin",
        .uiTimeoutMs = 1U,
        .eAction = NATIVE_APP_PACKET_PROTECTED_RECEIVE};
    struct stat Status;
    geProtectedPath = IPSEC_PACKET_PATH_SYSTEM;
    CHECK(IPSEC_ERR_PACKET_PATH_MISMATCH ==
        TransferNativeAppPacketFile(pContext, &Options));
    CHECK(0 != access("protected.bin", F_OK));
    geProtectedPath = IPSEC_PACKET_PATH_APPLICATION;
    CHECK(IPSEC_OK == TransferNativeAppPacketFile(pContext, &Options));
    CHECK((0 == stat("protected.bin", &Status)) && (40 == Status.st_size));
    CHECK(IPSEC_ERR_FILE_EXISTS == TransferNativeAppPacketFile(pContext, &Options));
    Options.eAction = NATIVE_APP_PACKET_PROTECTED_SUBMIT;
    CHECK(IPSEC_OK == TransferNativeAppPacketFile(pContext, &Options));
    CHECK(1U == guiProtectedSubmissions);
    Options.pcPath = "plain.bin";
    Options.eAction = NATIVE_APP_PACKET_PLAIN_RECEIVE;
    CHECK(IPSEC_OK == TransferNativeAppPacketFile(pContext, &Options));
    CHECK((0 == stat("plain.bin", &Status)) && (20 == Status.st_size));
    gePlainPath = IPSEC_PACKET_PATH_SYSTEM;
    Options.pcPath = "plain-system.bin";
    CHECK(IPSEC_ERR_PACKET_PATH_MISMATCH ==
        TransferNativeAppPacketFile(pContext, &Options));
    CHECK(0 != access("plain-system.bin", F_OK));
    gePlainPath = IPSEC_PACKET_PATH_APPLICATION;
    geProtectedReceiveError = IPSEC_ERR_PACKET_TIMEOUT;
    Options.pcPath = "timeout.bin";
    Options.eAction = NATIVE_APP_PACKET_PROTECTED_RECEIVE;
    CHECK(IPSEC_ERR_PACKET_TIMEOUT ==
        TransferNativeAppPacketFile(pContext, &Options));
    CHECK(0 == access("timeout.bin", F_OK));
    CHECK((0 == unlink("protected.bin")) && (0 == unlink("plain.bin")) &&
          (0 == unlink("timeout.bin")));
    CHECK((guiProtectedReceives >= 2U) && (1U == guiPlainReceives));
    return true;
}

int main(void)
{
    char acDirectory[] = "/tmp/ipsec-app-packet-XXXXXX";
    bool bPassed;
    if ((NULL == mkdtemp(acDirectory)) || (0 != chdir(acDirectory))) {
        (void)fprintf(stderr, "setup failed: %s\n", strerror(errno));
        return 1;
    }
    bPassed = WriteTestInput("input.bin") && VerifyPacketFiles();
    if (0 != unlink("input.bin")) {
        perror("packet test cleanup: unlink");
        bPassed = false;
    }
    if (0 != chdir("/")) {
        perror("packet test cleanup: chdir");
        return 1;
    }
    else if (0 != rmdir(acDirectory)) {
        perror("packet test cleanup: rmdir");
        bPassed = false;
    }
    return bPassed ? 0 : 1;
}
