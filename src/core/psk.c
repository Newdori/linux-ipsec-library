#define _GNU_SOURCE

#include "../internal/ipsec_internal.h"

#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define IPSEC_GENERATED_PSK_TEXT_LENGTH \
    (IPSEC_GENERATED_PSK_BYTE_LENGTH * 2U)

static IpsecError_t ReadIpsecRandomFallback(
    uint8_t *pucData,
    size_t zLength)
{
    int32_t iFile;
    size_t zOffset = 0U;
    IpsecError_t eError = IPSEC_OK;

    iFile = (int32_t)open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (0 > iFile) {
        return IPSEC_ERR_RANDOM;
    }
    else {
        /* Read until the requested buffer is full. */
    }
    while ((zOffset < zLength) && (IPSEC_OK == eError)) {
        ssize_t zRead = read(iFile, &pucData[zOffset], zLength - zOffset);

        if (0 < zRead) {
            zOffset += (size_t)zRead;
        }
        else if ((0 > zRead) && (EINTR == errno)) {
            /* Retry an interrupted read. */
        }
        else {
            eError = IPSEC_ERR_RANDOM;
        }
    }
    (void)close(iFile);
    return eError;
}

static IpsecError_t FillIpsecRandom(
    uint8_t *pucData,
    size_t zLength)
{
    size_t zOffset = 0U;
    IpsecError_t eError = IPSEC_OK;
    bool bUseFallback = false;

    while ((zOffset < zLength) && (IPSEC_OK == eError) && !bUseFallback) {
#if defined(SYS_getrandom)
        ssize_t zRead = (ssize_t)syscall(
            SYS_getrandom, &pucData[zOffset], zLength - zOffset, 0U);

        if (0 < zRead) {
            zOffset += (size_t)zRead;
        }
        else if ((0 > zRead) && (EINTR == errno)) {
            /* Retry an interrupted request. */
        }
        else if ((0 > zRead) && (ENOSYS == errno)) {
            bUseFallback = true;
        }
        else {
            eError = IPSEC_ERR_RANDOM;
        }
#else
        bUseFallback = true;
#endif
    }
    if (bUseFallback) {
        eError = ReadIpsecRandomFallback(&pucData[zOffset],
                                         zLength - zOffset);
    }
    else {
        /* getrandom() supplied the complete buffer. */
    }
    return eError;
}

static IpsecError_t WriteIpsecPskText(
    const char *pcPath,
    const char *pcText,
    size_t zLength)
{
    int32_t iFile;
    size_t zOffset = 0U;
    IpsecError_t eError = IPSEC_OK;

    iFile = (int32_t)open(pcPath,
                         O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                         S_IRUSR | S_IWUSR);
    if ((0 > iFile) && (EEXIST == errno)) {
        return IPSEC_ERR_FILE_EXISTS;
    }
    else if ((0 > iFile) && ((EACCES == errno) || (EPERM == errno))) {
        return IPSEC_ERR_PERMISSION;
    }
    else if (0 > iFile) {
        return IPSEC_ERR_FILE_OPEN;
    }
    else {
        /* The exclusive create prevents replacing an existing secret. */
    }

    if (0 != fchmod(iFile, S_IRUSR | S_IWUSR)) {
        eError = (EPERM == errno) ? IPSEC_ERR_PERMISSION :
            IPSEC_ERR_FILE_WRITE;
    }
    else {
        /* Continue with the exact 0600 permission. */
    }
    while ((zOffset < zLength) && (IPSEC_OK == eError)) {
        ssize_t zWritten = write(iFile, &pcText[zOffset], zLength - zOffset);

        if (0 < zWritten) {
            zOffset += (size_t)zWritten;
        }
        else if ((0 > zWritten) && (EINTR == errno)) {
            /* Retry an interrupted write. */
        }
        else {
            eError = IPSEC_ERR_FILE_WRITE;
        }
    }
    if ((IPSEC_OK == eError) && (0 != fsync(iFile))) {
        eError = IPSEC_ERR_FILE_WRITE;
    }
    else {
        /* The data is durable or an earlier error is retained. */
    }
    if ((0 != close(iFile)) && (IPSEC_OK == eError)) {
        eError = IPSEC_ERR_FILE_WRITE;
    }
    else {
        /* Preserve the first failure. */
    }
    if (IPSEC_OK != eError) {
        (void)unlink(pcPath);
    }
    else {
        /* Keep the completed PSK file. */
    }
    return eError;
}

IpsecError_t GenerateIpsecPskFile(const char *pcPath)
{
    static const char acHex[] = "0123456789abcdef";
    uint8_t aucRandom[IPSEC_GENERATED_PSK_BYTE_LENGTH];
    char acText[IPSEC_GENERATED_PSK_TEXT_LENGTH + 1U];
    uint32_t uiIndex;
    IpsecError_t eError;

    if ((NULL == pcPath) || ('\0' == pcPath[0])) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = FillIpsecRandom(aucRandom, sizeof(aucRandom));
    }
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < IPSEC_GENERATED_PSK_BYTE_LENGTH;
             uiIndex++) {
            acText[uiIndex * 2U] = acHex[aucRandom[uiIndex] >> 4U];
            acText[(uiIndex * 2U) + 1U] =
                acHex[aucRandom[uiIndex] & 0x0fU];
        }
        acText[IPSEC_GENERATED_PSK_TEXT_LENGTH] = '\n';
        eError = WriteIpsecPskText(pcPath, acText, sizeof(acText));
    }
    else {
        /* Report the random source failure. */
    }
    SecureZeroIpsec(aucRandom, sizeof(aucRandom));
    SecureZeroIpsec(acText, sizeof(acText));
    return eError;
}
