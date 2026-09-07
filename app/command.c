#include "app_internal.h"

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

bool ParseNativeAppStartupOptions(
    int32_t iArgumentCount,
    char **ppcArguments,
    NativeAppStartupOptions_t *pOptions)
{
    int32_t iIndex = 1;
    if ((iArgumentCount < 1) || (NULL == ppcArguments) ||
        (NULL == ppcArguments[0]) || (NULL == pOptions)) {
        return false;
    }
    (void)memset(pOptions, 0, sizeof(*pOptions));
    pOptions->iCommandIndex = iArgumentCount;
    while (iIndex < iArgumentCount) {
        const char *pcArgument = ppcArguments[iIndex];
        const char **ppcPath = NULL;
        if (NULL == pcArgument) {
            return false;
        }
        if ((0 == strcmp("-c", pcArgument)) ||
            (0 == strcmp("--app-config", pcArgument))) {
            ppcPath = &pOptions->pcApplicationConfigPath;
        }
        else if (0 == strcmp("--config", pcArgument)) {
            ppcPath = &pOptions->pcConfigPath;
        }
        else if (0 == strcmp("--management-config", pcArgument)) {
            ppcPath = &pOptions->pcManagementConfigPath;
        }
        else if (0 == strcmp("--generate-psk", pcArgument)) {
            ppcPath = &pOptions->pcGeneratePskPath;
        }
        else if ((0 == strcmp("-v", pcArgument)) ||
                 (0 == strcmp("--verbose", pcArgument))) {
            pOptions->bVerbose = true;
        }
        else if ((0 == strcmp("-h", pcArgument)) ||
                 (0 == strcmp("--help", pcArgument))) {
            pOptions->bHelp = true;
        }
        else if ('-' == pcArgument[0]) {
            return false;
        }
        else {
            pOptions->iCommandIndex = iIndex;
            break;
        }
        if (NULL != ppcPath) {
            if (((iIndex + 1) >= iArgumentCount) ||
                (NULL == ppcArguments[iIndex + 1]) ||
                ('\0' == ppcArguments[iIndex + 1][0]) ||
                ('-' == ppcArguments[iIndex + 1][0])) {
                return false;
            }
            *ppcPath = ppcArguments[++iIndex];
        }
        iIndex++;
    }
    return true;
}

static bool IsNativeAppNamedShowScope(const char *pcScope)
{
    return (0 == strcmp("connections", pcScope)) ||
           (0 == strcmp("ike", pcScope)) ||
           (0 == strcmp("child", pcScope));
}

bool ParseNativeAppPacketOptions(uint32_t uiArgumentCount,
    char **ppcArguments, NativeAppPacketOptions_t *pOptions)
{
    NativeAppPacketOptions_t Options = {.uiTimeoutMs = 10000U};
    if ((NULL == ppcArguments) || (NULL == pOptions) ||
        ((3U != uiArgumentCount) && (5U != uiArgumentCount))) {
        return false;
    }
    if ((NULL == ppcArguments[0]) || (NULL == ppcArguments[1]) ||
        (NULL == ppcArguments[2]) || ('\0' == ppcArguments[2][0]) ||
        (0 != strcmp("packet", ppcArguments[0]))) {
        return false;
    }
    if (0 == strcmp("protected-receive", ppcArguments[1])) {
        Options.eAction = NATIVE_APP_PACKET_PROTECTED_RECEIVE;
    }
    else if (0 == strcmp("protected-submit", ppcArguments[1])) {
        Options.eAction = NATIVE_APP_PACKET_PROTECTED_SUBMIT;
    }
    else if (0 == strcmp("plain-receive", ppcArguments[1])) {
        Options.eAction = NATIVE_APP_PACKET_PLAIN_RECEIVE;
    }
    else {
        return false;
    }
    Options.pcPath = ppcArguments[2];
    if (5U == uiArgumentCount) {
        if ((NATIVE_APP_PACKET_PROTECTED_SUBMIT == Options.eAction) ||
            (NULL == ppcArguments[3]) ||
            (0 != strcmp("--timeout-ms", ppcArguments[3])) ||
            !ParseNativeAppNumber(ppcArguments[4], &Options.uiTimeoutMs) ||
            (Options.uiTimeoutMs > 600000U)) {
            return false;
        }
    }
    *pOptions = Options;
    return true;
}

static bool IsNativeAppDetailedShowScope(const char *pcScope)
{
    return IsNativeAppNamedShowScope(pcScope) ||
           (0 == strcmp("all", pcScope)) ||
           (0 == strcmp("summary", pcScope));
}

bool ParseNativeAppShowOptions(
    uint32_t uiArgumentCount,
    char **ppcArguments,
    NativeAppShowOptions_t *pOptions)
{
    bool bParsed = true;

    if ((0U == uiArgumentCount) || (4U < uiArgumentCount) ||
        (NULL == ppcArguments) || (NULL == pOptions)) {
        bParsed = false;
    }
    else {
        (void)memset(pOptions, 0, sizeof(*pOptions));
        pOptions->pcScope = (2U <= uiArgumentCount) ? ppcArguments[1] :
            "summary";
    }
    if (bParsed && (3U <= uiArgumentCount) &&
        (0 == strcmp("detail", ppcArguments[2]))) {
        pOptions->bDetail = true;
        if (4U == uiArgumentCount) {
            pOptions->pcName = ppcArguments[3];
        }
        else {
            /* Detail output is not filtered by name. */
        }
    }
    else if (bParsed && (3U == uiArgumentCount)) {
        pOptions->pcName = ppcArguments[2];
    }
    else if (bParsed && (3U < uiArgumentCount)) {
        bParsed = false;
    }
    else {
        /* No optional output mode or name was supplied. */
    }
    if (bParsed && pOptions->bDetail &&
        !IsNativeAppDetailedShowScope(pOptions->pcScope)) {
        bParsed = false;
    }
    else if (bParsed && (NULL != pOptions->pcName) &&
             !IsNativeAppNamedShowScope(pOptions->pcScope)) {
        bParsed = false;
    }
    else {
        /* The parsed option combination is supported. */
    }
    return bParsed;
}

bool ParseNativeAppNumber(
    const char *pcText,
    uint32_t *puiValue)
{
    char *pcEnd = NULL;
    uint64_t ullValue;

    if ((NULL == pcText) || (NULL == puiValue)) {
        return false;
    }
    else {
        errno = 0;
        ullValue = strtoull(pcText, &pcEnd, 10);
    }
    if ((0 != errno) || (pcEnd == pcText) || ('\0' != *pcEnd) ||
        (UINT32_MAX < ullValue)) {
        return false;
    }
    else {
        *puiValue = (uint32_t)ullValue;
        return true;
    }
}

bool ParseNativeAppCommandLine(
    char *pcLine,
    char **ppcArguments,
    uint32_t uiArgumentCapacity,
    uint32_t *puiArgumentCount)
{
    char *pcRead;
    char *pcWrite;
    uint32_t uiArgumentCount = 0U;
    bool bParsed = true;

    if ((NULL == pcLine) || (NULL == ppcArguments) ||
        (0U == uiArgumentCapacity) || (NULL == puiArgumentCount)) {
        return false;
    }
    else {
        pcRead = pcLine;
        pcWrite = pcLine;
        *puiArgumentCount = 0U;
    }

    while (bParsed) {
        char cQuote = '\0';

        while (0 != isspace((unsigned char)*pcRead)) {
            pcRead++;
        }
        if ('\0' == *pcRead) {
            break;
        }
        else if (uiArgumentCount >= uiArgumentCapacity) {
            bParsed = false;
            break;
        }
        else {
            ppcArguments[uiArgumentCount] = pcWrite;
            uiArgumentCount++;
        }

        while ('\0' != *pcRead) {
            char cValue = *pcRead;

            if ('\0' != cQuote) {
                if (cQuote == cValue) {
                    cQuote = '\0';
                    pcRead++;
                }
                else if (('\\' == cValue) && ('\0' != pcRead[1])) {
                    pcRead++;
                    *pcWrite = *pcRead;
                    pcWrite++;
                    pcRead++;
                }
                else {
                    *pcWrite = cValue;
                    pcWrite++;
                    pcRead++;
                }
            }
            else if (('\'' == cValue) || ('"' == cValue)) {
                cQuote = cValue;
                pcRead++;
            }
            else if (0 != isspace((unsigned char)cValue)) {
                break;
            }
            else if (('\\' == cValue) && ('\0' != pcRead[1])) {
                pcRead++;
                *pcWrite = *pcRead;
                pcWrite++;
                pcRead++;
            }
            else {
                *pcWrite = cValue;
                pcWrite++;
                pcRead++;
            }
        }
        if ('\0' != cQuote) {
            bParsed = false;
        }
        else {
            while (0 != isspace((unsigned char)*pcRead)) {
                pcRead++;
            }
            *pcWrite = '\0';
            pcWrite++;
        }
    }

    if (bParsed) {
        *puiArgumentCount = uiArgumentCount;
    }
    else {
        *puiArgumentCount = 0U;
    }
    return bParsed;
}
