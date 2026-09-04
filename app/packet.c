#include "app_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

static bool GetNativeAppPacketTime(uint64_t *pullTimeMs)
{
    struct timespec Time;
    if (0 != clock_gettime(CLOCK_MONOTONIC, &Time)) {
        return false;
    }
    *pullTimeMs = (uint64_t)Time.tv_sec * 1000U +
        (uint64_t)Time.tv_nsec / 1000000U;
    return true;
}

static IpsecError_t ReceiveNativeAppPacket(IpsecContext_t *pContext,
    NativeAppPacketAction_t eAction, uint8_t *pucData, size_t zCapacity,
    size_t *pzLength, uint32_t uiTimeoutMs)
{
    IpsecProtectedPacket_t Protected = {.uiStructSize = sizeof(Protected),
        .pucData = pucData, .zCapacity = zCapacity};
    IpsecPlainPacket_t Plain = {.uiStructSize = sizeof(Plain),
        .pucData = pucData, .zCapacity = zCapacity};
    uint64_t ullStart;
    uint64_t ullNow;
    IpsecError_t eError;
    if (!GetNativeAppPacketTime(&ullStart)) {
        return IPSEC_ERR_INTERNAL;
    }
    ullNow = ullStart;
    do {
        uint64_t ullElapsed = ullNow - ullStart;
        uint32_t uiWait = (ullElapsed < uiTimeoutMs) ?
            uiTimeoutMs - (uint32_t)ullElapsed : 0U;
        if (IsNativeAppStopRequested()) {
            return IPSEC_ERR_CANCELLED;
        }
        if (uiWait > 250U) {
            uiWait = 250U;
        }
        if (NATIVE_APP_PACKET_PROTECTED_RECEIVE == eAction) {
            eError = ReceiveIpsecProtectedPacket(pContext, &Protected, uiWait);
            *pzLength = Protected.zLength;
        }
        else {
            eError = ReceiveIpsecPlainPacket(pContext, &Plain, uiWait);
            *pzLength = Plain.zLength;
        }
        if (IPSEC_ERR_PACKET_TIMEOUT != eError) {
            return eError;
        }
        if (!GetNativeAppPacketTime(&ullNow)) {
            return IPSEC_ERR_INTERNAL;
        }
    } while ((ullNow - ullStart) < uiTimeoutMs);
    return IPSEC_ERR_PACKET_TIMEOUT;
}

static IpsecError_t WriteNativeAppPacket(int32_t iFd,
    const uint8_t *pucData, size_t zLength, size_t zCapacity)
{
    size_t zOffset = 0U;
    if ((0U == zLength) || (zLength > zCapacity)) {
        return IPSEC_ERR_PACKET_INVALID;
    }
    while (zOffset < zLength) {
        ssize_t lWritten = write(iFd, pucData + zOffset, zLength - zOffset);
        if ((lWritten < 0) && (EINTR == errno) && !IsNativeAppStopRequested()) {
            continue;
        }
        if (lWritten <= 0) {
            return IPSEC_ERR_FILE_WRITE;
        }
        zOffset += (size_t)lWritten;
    }
    return (0 == fsync(iFd)) ? IPSEC_OK : IPSEC_ERR_FILE_WRITE;
}

static IpsecError_t ReadNativeAppPacket(int32_t iFd,
    uint8_t *pucData, size_t zCapacity, size_t *pzLength)
{
    struct stat Status;
    uint8_t ucExtra;
    ssize_t lRead;
    size_t zExpected;
    if ((0 != fstat(iFd, &Status)) || !S_ISREG(Status.st_mode) ||
        (Status.st_size <= 0) || ((uint64_t)Status.st_size > zCapacity)) {
        return IPSEC_ERR_FILE_READ;
    }
    zExpected = (size_t)Status.st_size;
    while (*pzLength < zExpected) {
        lRead = read(iFd, pucData + *pzLength, zExpected - *pzLength);
        if ((lRead < 0) && (EINTR == errno) && !IsNativeAppStopRequested()) {
            continue;
        }
        if (lRead <= 0) {
            return IPSEC_ERR_FILE_READ;
        }
        *pzLength += (size_t)lRead;
    }
    do {
        lRead = read(iFd, &ucExtra, sizeof(ucExtra));
    } while ((lRead < 0) && (EINTR == errno) && !IsNativeAppStopRequested());
    return (0 == lRead) ? IPSEC_OK : IPSEC_ERR_FILE_READ;
}

static bool IsNativeAppPacketReceive(NativeAppPacketAction_t eAction)
{
    return (NATIVE_APP_PACKET_PROTECTED_RECEIVE == eAction) ||
        (NATIVE_APP_PACKET_PLAIN_RECEIVE == eAction);
}

static IpsecError_t ValidateNativeAppPacketPath(IpsecContext_t *pContext,
    NativeAppPacketAction_t eAction)
{
    IpsecPacketPathStatus_t Status = {.uiStructSize = sizeof(Status)};
    IpsecError_t eError = GetIpsecPacketPathStatus(pContext, &Status);
    if (IPSEC_OK != eError) {
        return eError;
    }
    if (NATIVE_APP_PACKET_PLAIN_RECEIVE == eAction) {
        if (IPSEC_PACKET_PATH_APPLICATION != Status.ePlainPacketPath) {
            return IPSEC_ERR_PACKET_PATH_MISMATCH;
        }
        return Status.bPlainPathReady ? IPSEC_OK : IPSEC_ERR_PLAIN_PATH_UNAVAILABLE;
    }
    if (IPSEC_PACKET_PATH_APPLICATION != Status.eProtectedPacketPath) {
        return IPSEC_ERR_PACKET_PATH_MISMATCH;
    }
    return Status.bProtectedPathReady ?
        IPSEC_OK : IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
}

IpsecError_t TransferNativeAppPacketFile(IpsecContext_t *pContext,
    const NativeAppPacketOptions_t *pOptions)
{
    uint8_t aucData[IPSEC_PROTECTED_PACKET_CAPACITY];
    size_t zLength = 0U;
    IpsecError_t eError;
    int32_t iFd;
    bool bReceive;
    if ((NULL == pContext) || (NULL == pOptions) ||
        (NULL == pOptions->pcPath) || ('\0' == pOptions->pcPath[0]) ||
        (pOptions->uiTimeoutMs > 600000U) ||
        (pOptions->eAction > NATIVE_APP_PACKET_PLAIN_RECEIVE)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    eError = ValidateNativeAppPacketPath(pContext, pOptions->eAction);
    if (IPSEC_OK != eError) {
        return eError;
    }
    bReceive = IsNativeAppPacketReceive(pOptions->eAction);
    iFd = (int32_t)open(pOptions->pcPath,
        (bReceive ? (O_WRONLY | O_CREAT | O_EXCL) : O_RDONLY) |
        O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (iFd < 0) {
        return (EEXIST == errno) ? IPSEC_ERR_FILE_EXISTS : IPSEC_ERR_FILE_OPEN;
    }
    if (bReceive) {
        (void)puts("waiting for one packet (Ctrl-C cancels)");
        (void)fflush(stdout);
        eError = ReceiveNativeAppPacket(pContext, pOptions->eAction,
            aucData, sizeof(aucData), &zLength, pOptions->uiTimeoutMs);
        if (IPSEC_OK == eError) {
            eError = WriteNativeAppPacket(iFd, aucData, zLength, sizeof(aucData));
        }
    }
    else {
        IpsecProtectedPacket_t Packet = {.uiStructSize = sizeof(Packet),
            .pucData = aucData, .zCapacity = sizeof(aucData),
            .eType = IPSEC_PROTECTED_PACKET_RAW_ESP,
            .eDirection = IPSEC_PACKET_DIRECTION_INBOUND};
        eError = ReadNativeAppPacket(iFd, aucData, sizeof(aucData), &zLength);
        if (IPSEC_ERR_FILE_READ == eError) {
            (void)fprintf(stderr, "packet file is empty, oversized, unreadable, or incomplete: %s; "
                "submit requires a successful protected-receive file from the peer\n",
                pOptions->pcPath);
        }
        Packet.zLength = zLength;
        if ((IPSEC_OK == eError) && IsNativeAppStopRequested()) {
            eError = IPSEC_ERR_CANCELLED;
        }
        if (IPSEC_OK == eError) {
            eError = SubmitIpsecProtectedPacket(pContext, &Packet);
        }
    }
    if ((0 != close(iFd)) && (IPSEC_OK == eError)) {
        eError = bReceive ? IPSEC_ERR_FILE_WRITE : IPSEC_ERR_FILE_READ;
    }
    if (IPSEC_OK == eError) {
        const char *pcAction = (NATIVE_APP_PACKET_PROTECTED_RECEIVE == pOptions->eAction) ?
            "protected packet received" :
            ((NATIVE_APP_PACKET_PLAIN_RECEIVE == pOptions->eAction) ?
             "plain packet received" : "protected packet submitted");
        (void)printf("%s: %zu bytes, file=%s\n",
            pcAction, zLength, pOptions->pcPath);
    }
    else if (bReceive) {
        (void)fprintf(stderr,
            "incomplete packet file retained: %s; use a new path when retrying\n",
            pOptions->pcPath);
    }
    return eError;
}
