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

static bool VerifyStartupOptionParsing(void)
{
    char *pacShort[] = {"ipsec_app", "-c", "initiator.conf", "-v"};
    char *pacLong[] = {"ipsec_app", "--app-config", "initiator.conf", "--verbose"};
    char *pacReversed[] = {"ipsec_app", "-v", "-c", "/tmp/config with spaces.conf", "show", "daemon"};
    char *pacConfigOnly[] = {"ipsec_app", "-c", "responder.conf"};
    char *pacLegacy[] = {"ipsec_app", "--config", "legacy.conf", "-v"};
    char *pacGenerate[] = {"ipsec_app", "--generate-psk", "secret.psk"};
    char *pacHelp[] = {"ipsec_app", "-h"};
    NativeAppStartupOptions_t Short, Long, Options;

    if (!ParseNativeAppStartupOptions(4, pacShort, &Short) ||
        !ParseNativeAppStartupOptions(4, pacLong, &Long) ||
        !Short.bVerbose || !Long.bVerbose ||
        (NULL != Short.pcConfigPath) ||
        (0 != strcmp("initiator.conf", Short.pcApplicationConfigPath)) ||
        (0 != strcmp(Short.pcApplicationConfigPath, Long.pcApplicationConfigPath)) ||
        (4 != Short.iCommandIndex) || (4 != Long.iCommandIndex)) {
        return false;
    }
    if (!ParseNativeAppStartupOptions(6, pacReversed, &Options) ||
        !Options.bVerbose || (4 != Options.iCommandIndex) ||
        (0 != strcmp("/tmp/config with spaces.conf", Options.pcApplicationConfigPath))) {
        return false;
    }
    if (!ParseNativeAppStartupOptions(3, pacConfigOnly, &Options) ||
        Options.bVerbose || (3 != Options.iCommandIndex) ||
        (0 != strcmp("responder.conf", Options.pcApplicationConfigPath))) {
        return false;
    }
    if (!ParseNativeAppStartupOptions(4, pacLegacy, &Options) ||
        !Options.bVerbose || (NULL != Options.pcApplicationConfigPath) ||
        (0 != strcmp("legacy.conf", Options.pcConfigPath))) {
        return false;
    }
    if (!ParseNativeAppStartupOptions(3, pacGenerate, &Options) ||
        (0 != strcmp("secret.psk", Options.pcGeneratePskPath))) {
        return false;
    }
    return ParseNativeAppStartupOptions(2, pacHelp, &Options) && Options.bHelp;
}

static bool VerifyInvalidStartupOptions(void)
{
    char *pacMissing[] = {"ipsec_app", "-c"};
    char *pacNextOption[] = {"ipsec_app", "-c", "-v"};
    char *pacNull[] = {"ipsec_app", "-c", NULL};
    char *pacEmpty[] = {"ipsec_app", "-c", ""};
    char *pacUnknown[] = {"ipsec_app", "--unknown"};
    char *pacRemoved[] = {"ipsec_app", "-c", "initiator.conf",
                          "--management-config", "management.conf"};
    NativeAppStartupOptions_t Options;
    return !ParseNativeAppStartupOptions(2, pacMissing, &Options) &&
        !ParseNativeAppStartupOptions(3, pacNextOption, &Options) &&
        !ParseNativeAppStartupOptions(3, pacNull, &Options) &&
        !ParseNativeAppStartupOptions(3, pacEmpty, &Options) &&
        !ParseNativeAppStartupOptions(2, pacUnknown, &Options) &&
        !ParseNativeAppStartupOptions(5, pacRemoved, &Options) &&
        !ParseNativeAppStartupOptions(0, pacMissing, &Options) &&
        !ParseNativeAppStartupOptions(2, NULL, &Options) &&
        !ParseNativeAppStartupOptions(2, pacMissing, NULL);
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
    else if (!VerifyStartupOptionParsing() || !VerifyInvalidStartupOptions()) {
        (void)fprintf(stderr, "startup option parsing failed\n");
        return 1;
    }
    else {
        return 0;
    }
}
