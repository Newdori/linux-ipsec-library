#include "../internal/ipsec_internal.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

IpsecError_t CopyIpsecString(
    char *pcDestination,
    size_t zDestinationLength,
    const uint8_t *pucSource,
    size_t zSourceLength)
{
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pcDestination) || (0U == zDestinationLength) ||
        ((NULL == pucSource) && (0U != zSourceLength))) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (zSourceLength >= zDestinationLength) {
        pcDestination[0] = '\0';
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        if (0U < zSourceLength) {
            memcpy(pcDestination, pucSource, zSourceLength);
        }
        else {
            /* Empty string. */
        }
        pcDestination[zSourceLength] = '\0';
    }

    return eError;
}

static IpsecError_t ParseIpsecUnsigned(
    const uint8_t *pucValue,
    size_t zValueLength,
    uint64_t *pullValue,
    uint32_t uiBase)
{
    char acNumber[64];
    char *pcEnd = NULL;
    uint64_t ullParsed;
    IpsecError_t eError;

    if ((NULL == pucValue) || (NULL == pullValue) || (0U == zValueLength) ||
        (zValueLength >= sizeof(acNumber)) ||
        !((0U == uiBase) || (10U == uiBase) || (16U == uiBase))) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memcpy(acNumber, pucValue, zValueLength);
        acNumber[zValueLength] = '\0';
        errno = 0;
        ullParsed = (uint64_t)strtoull(acNumber, &pcEnd,
                                      (int32_t)uiBase);
        if ((0 != errno) || (pcEnd == acNumber) || ('\0' != *pcEnd)) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            *pullValue = (uint64_t)ullParsed;
            eError = IPSEC_OK;
        }
    }

    SecureZeroIpsec(acNumber, sizeof(acNumber));
    return eError;
}

IpsecError_t ParseIpsecUint32(
    const uint8_t *pucValue,
    size_t zValueLength,
    uint32_t *puiValue,
    uint32_t uiBase)
{
    uint64_t ullValue = 0U;
    IpsecError_t eError;

    if (NULL == puiValue) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ParseIpsecUnsigned(pucValue, zValueLength, &ullValue, uiBase);
        if ((IPSEC_OK == eError) && (UINT32_MAX < ullValue)) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else if (IPSEC_OK == eError) {
            *puiValue = (uint32_t)ullValue;
        }
        else {
            /* Preserve parser error. */
        }
    }

    return eError;
}

IpsecError_t ParseIpsecUint64(
    const uint8_t *pucValue,
    size_t zValueLength,
    uint64_t *pullValue,
    uint32_t uiBase)
{
    return ParseIpsecUnsigned(pucValue, zValueLength, pullValue, uiBase);
}

static bool GetIpsecDurationMultiplier(
    const char *pcUnit,
    size_t zUnitLength,
    uint64_t *pullMultiplier)
{
    bool bKnown = true;

    if ((1U < zUnitLength) && ('s' == pcUnit[zUnitLength - 1U])) {
        zUnitLength--;
    }
    else {
        /* The unit is already singular. */
    }
    if ((6U == zUnitLength) &&
        (0 == memcmp("second", pcUnit, zUnitLength))) {
        *pullMultiplier = 1U;
    }
    else if ((6U == zUnitLength) &&
             (0 == memcmp("minute", pcUnit, zUnitLength))) {
        *pullMultiplier = 60U;
    }
    else if ((4U == zUnitLength) &&
             (0 == memcmp("hour", pcUnit, zUnitLength))) {
        *pullMultiplier = 60U * 60U;
    }
    else if ((3U == zUnitLength) &&
             (0 == memcmp("day", pcUnit, zUnitLength))) {
        *pullMultiplier = 24U * 60U * 60U;
    }
    else if ((4U == zUnitLength) &&
             (0 == memcmp("week", pcUnit, zUnitLength))) {
        *pullMultiplier = 7U * 24U * 60U * 60U;
    }
    else {
        bKnown = false;
    }
    return bKnown;
}

IpsecError_t ParseIpsecDurationSeconds(
    const uint8_t *pucValue,
    size_t zValueLength,
    uint64_t *pullSeconds)
{
    char acText[128];
    char *pcCursor;
    uint64_t ullTotal = 0U;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pucValue) || (0U == zValueLength) ||
        (zValueLength >= sizeof(acText)) || (NULL == pullSeconds)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memcpy(acText, pucValue, zValueLength);
        acText[zValueLength] = '\0';
        pcCursor = acText;
    }
    if (0 == strcmp("less than a second", acText)) {
        *pullSeconds = 0U;
        SecureZeroIpsec(acText, sizeof(acText));
        return IPSEC_OK;
    }
    else {
        /* Parse one or more number/unit pairs below. */
    }

    while (('\0' != *pcCursor) && (IPSEC_OK == eError)) {
        const char *pcUnit;
        char *pcEnd = NULL;
        uint64_t ullValue;
        uint64_t ullMultiplier = 0U;
        size_t zUnitLength;

        while ((' ' == *pcCursor) || (',' == *pcCursor)) {
            pcCursor++;
        }
        if ('\0' == *pcCursor) {
            break;
        }
        else {
            errno = 0;
            ullValue = (uint64_t)strtoull(pcCursor, &pcEnd, 10);
        }
        if ((0 != errno) || (pcEnd == pcCursor)) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
            continue;
        }
        else {
            pcCursor = pcEnd;
        }
        while (' ' == *pcCursor) {
            pcCursor++;
        }
        pcUnit = pcCursor;
        while (0 != isalpha((unsigned char)*pcCursor)) {
            pcCursor++;
        }
        zUnitLength = (size_t)(pcCursor - pcUnit);
        if ((0U == zUnitLength) ||
            !GetIpsecDurationMultiplier(pcUnit, zUnitLength,
                                        &ullMultiplier) ||
            ((0U != ullValue) &&
             ((UINT64_MAX / ullValue) < ullMultiplier))) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else if ((UINT64_MAX - ullTotal) < (ullValue * ullMultiplier)) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            ullTotal += ullValue * ullMultiplier;
        }
        while (' ' == *pcCursor) {
            pcCursor++;
        }
        if (('\0' != *pcCursor) && (',' != *pcCursor)) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            /* The next loop consumes a comma or finishes the text. */
        }
    }
    if (IPSEC_OK == eError) {
        *pullSeconds = ullTotal;
    }
    else {
        /* Do not modify the output when the optional text is unknown. */
    }
    SecureZeroIpsec(acText, sizeof(acText));
    return eError;
}

IpsecError_t AppendIpsecText(
    char *pcDestination,
    size_t zDestinationLength,
    const uint8_t *pucValue,
    size_t zValueLength,
    const char *pcSeparator)
{
    size_t zUsed;
    size_t zSeparatorLength;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pcDestination) || (0U == zDestinationLength) ||
        (NULL == pcSeparator) || ((NULL == pucValue) && (0U != zValueLength))) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        zUsed = strnlen(pcDestination, zDestinationLength);
        zSeparatorLength = (0U < zUsed) ? strlen(pcSeparator) : 0U;
        if ((zUsed >= zDestinationLength) ||
            (zSeparatorLength > (zDestinationLength - zUsed - 1U)) ||
            (zValueLength > (zDestinationLength - zUsed - zSeparatorLength - 1U))) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            if (0U < zSeparatorLength) {
                memcpy(pcDestination + zUsed, pcSeparator, zSeparatorLength);
                zUsed += zSeparatorLength;
            }
            else {
                /* First value has no separator. */
            }
            if (0U < zValueLength) {
                memcpy(pcDestination + zUsed, pucValue, zValueLength);
                zUsed += zValueLength;
            }
            else {
                /* Empty value. */
            }
            pcDestination[zUsed] = '\0';
        }
    }

    return eError;
}

uint64_t GetIpsecMonotonicMilliseconds(void)
{
    struct timespec Time;
    uint64_t ullMilliseconds = 0U;

    if (0 == clock_gettime(CLOCK_MONOTONIC, &Time)) {
        ullMilliseconds = ((uint64_t)Time.tv_sec * 1000U) +
                          ((uint64_t)Time.tv_nsec / 1000000U);
    }
    else {
        /* A zero deadline makes callers fail closed. */
    }

    return ullMilliseconds;
}

IpsecError_t SleepIpsecMilliseconds(uint32_t uiMilliseconds)
{
    struct timespec Delay;
    IpsecError_t eError = IPSEC_OK;

    Delay.tv_sec = (time_t)(uiMilliseconds / 1000U);
    Delay.tv_nsec = (long)(uiMilliseconds % 1000U) * 1000000L;
    while (0 != nanosleep(&Delay, &Delay)) {
        if (EINTR != errno) {
            eError = IPSEC_ERR_INTERNAL;
            break;
        }
        else {
            /* Continue sleeping for the remaining time. */
        }
    }

    return eError;
}
