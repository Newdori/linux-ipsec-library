#include "app_internal.h"

#include <stdio.h>
#include <string.h>

static bool VerifyCommandParsing(void)
{
    char acLine[] =
        "config set ike_proposals \"aes256-sha256 modp2048\" escaped\\ value";
    char *pacArguments[8] = {0};
    uint32_t uiArgumentCount = 0U;

    return ParseNativeAppCommandLine(
               acLine, pacArguments,
               (uint32_t)(sizeof(pacArguments) / sizeof(pacArguments[0])),
               &uiArgumentCount) &&
        (5U == uiArgumentCount) &&
        (0 == strcmp("config", pacArguments[0])) &&
        (0 == strcmp("set", pacArguments[1])) &&
        (0 == strcmp("ike_proposals", pacArguments[2])) &&
        (0 == strcmp("aes256-sha256 modp2048", pacArguments[3])) &&
        (0 == strcmp("escaped value", pacArguments[4]));
}

static bool VerifyInvalidCommandParsing(void)
{
    char acUnterminated[] = "config set key \"unterminated";
    char acOverflow[] = "one two three";
    char *pacArguments[2] = {0};
    uint32_t uiArgumentCount = UINT32_MAX;
    bool bUnterminatedRejected;
    bool bOverflowRejected;

    bUnterminatedRejected = !ParseNativeAppCommandLine(
        acUnterminated, pacArguments,
        (uint32_t)(sizeof(pacArguments) / sizeof(pacArguments[0])),
        &uiArgumentCount) && (0U == uiArgumentCount);
    uiArgumentCount = UINT32_MAX;
    bOverflowRejected = !ParseNativeAppCommandLine(
        acOverflow, pacArguments,
        (uint32_t)(sizeof(pacArguments) / sizeof(pacArguments[0])),
        &uiArgumentCount) && (0U == uiArgumentCount);
    return bUnterminatedRejected && bOverflowRejected;
}

static bool VerifyNumberParsing(void)
{
    uint32_t uiValue = 0U;

    return ParseNativeAppNumber("4294967295", &uiValue) &&
        (UINT32_MAX == uiValue) &&
        !ParseNativeAppNumber("4294967296", &uiValue) &&
        !ParseNativeAppNumber("-1", &uiValue) &&
        !ParseNativeAppNumber("1x", &uiValue) &&
        !ParseNativeAppNumber("", &uiValue);
}

static bool VerifyShowOptionParsing(void)
{
    char *pacDetail[] = {"show", "ike", "detail", "conn-1"};
    char *pacInvalid[] = {"show", "routes", "detail"};
    NativeAppShowOptions_t Options;

    if (!ParseNativeAppShowOptions(4U, pacDetail, &Options) ||
        !Options.bDetail ||
        (0 != strcmp("ike", Options.pcScope)) ||
        (0 != strcmp("conn-1", Options.pcName))) {
        return false;
    }
    else {
        return !ParseNativeAppShowOptions(3U, pacInvalid, &Options);
    }
}

int main(void)
{
    if (!VerifyCommandParsing()) {
        (void)fprintf(stderr, "quoted command parsing failed\n");
        return 1;
    }
    else if (!VerifyInvalidCommandParsing()) {
        (void)fprintf(stderr, "invalid command parsing was accepted\n");
        return 1;
    }
    else if (!VerifyNumberParsing()) {
        (void)fprintf(stderr, "bounded number parsing failed\n");
        return 1;
    }
    else if (!VerifyShowOptionParsing()) {
        (void)fprintf(stderr, "show option parsing failed\n");
        return 1;
    }
    else {
        return 0;
    }
}
