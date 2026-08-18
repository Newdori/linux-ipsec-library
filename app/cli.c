#include "app_internal.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

typedef struct NativeAppStartupOptions {
    const char *pcConfigPath;
    const char *pcApplicationConfigPath;
    const char *pcManagementConfigPath;
    const char *pcGeneratePskPath;
    int32_t iCommandIndex;
    bool bVerbose;
    bool bHelp;
} NativeAppStartupOptions_t;

typedef struct NativeAppSession {
    IpsecContext_t *pContext;
    NativeAppConfig_t BaseConfig;
    NativeAppConfig_t Config;
    NativeAppRuntimeConfig_t Runtime;
    NativeAppPeerTable_t PeerTable;
    NativeAppPeerListener_t PeerListener;
    char acConfigPath[NATIVE_APP_PATH_LENGTH];
    char acApplicationConfigPath[NATIVE_APP_PATH_LENGTH];
    char acManagementConfigPath[NATIVE_APP_PATH_LENGTH];
    bool bConfigValid;
    bool bConnectionLoaded;
    bool bCredentialLoaded;
    bool bVerbose;
    atomic_bool bPromptVisible;
} NativeAppSession_t;

static void PrintNativeAppPrompt(NativeAppSession_t *pSession)
{
    (void)printf("ipsec> ");
    (void)fflush(stdout);
    atomic_store(&pSession->bPromptVisible, true);
}

static const char *GetNativeAppLogLevel(IpsecLogLevel_t eLevel)
{
    const char *pcLevel;

    switch (eLevel) {
    case IPSEC_LOG_ERROR:
        pcLevel = "error";
        break;
    case IPSEC_LOG_WARNING:
        pcLevel = "warning";
        break;
    case IPSEC_LOG_INFO:
        pcLevel = "info";
        break;
    default:
        pcLevel = "debug";
        break;
    }
    return pcLevel;
}

static void LogNativeApp(
    IpsecLogLevel_t eLevel,
    const char *pcMessage,
    void *pvUserData)
{
    NativeAppSession_t *pSession = (NativeAppSession_t *)pvUserData;
    bool bRestorePrompt = (NULL != pSession) &&
        atomic_load(&pSession->bPromptVisible);

    if ((NULL != pSession) && !pSession->bVerbose &&
        (IPSEC_LOG_WARNING < eLevel)) {
        return;
    }
    else {
        if (bRestorePrompt) {
            (void)fprintf(stderr, "\n");
        }
        else {
            /* No visible prompt needs restoration. */
        }
        (void)fprintf(stderr, "libipsec[%s]: %s\n",
                      GetNativeAppLogLevel(eLevel), pcMessage);
        if (bRestorePrompt) {
            PrintNativeAppPrompt(pSession);
        }
        else {
            /* The command loop prints the next prompt. */
        }
    }
}

static void PrintNativeAppUsage(const char *pcProgram)
{
    (void)printf(
        "Usage: %s --app-config FILE --management-config FILE\n"
        "          [--verbose] [COMMAND ...]\n"
        "       %s [--config LEGACY_FILE] [--verbose] [COMMAND ...]\n"
        "       %s --generate-psk FILE\n"
        "\n"
        "Without COMMAND, ipsec_app starts an interactive CLI session.\n"
        "The application connects to charon before accepting commands.\n"
        "--generate-psk creates a new 48-byte hex PSK file without\n"
        "connecting to charon and never overwrites an existing file.\n",
        pcProgram, pcProgram, pcProgram);
}

static void PrintNativeAppHelp(void)
{
    (void)printf(
        "Commands:\n"
        "  config load FILE             load a legacy combined configuration\n"
        "  config set KEY VALUE         update one in-memory setting\n"
        "  config validate              validate and rebuild settings\n"
        "  connection load              load the configured connection\n"
        "  connection unload [NAME]     unload a connection\n"
        "  credential load              load the configured PSK\n"
        "  credential clear             clear charon's VICI credentials\n"
        "  ike initiate [NAME]          initiate and wait for an IKE SA\n"
        "  ike terminate [NAME]         terminate an IKE SA\n"
        "  ike rekey [NAME]             rekey an IKE SA\n"
        "  ike wait [NAME]              wait for an established IKE SA\n"
        "  child initiate [NAME]        initiate and wait for a CHILD SA\n"
        "  child terminate [NAME]       terminate a CHILD SA\n"
        "  child rekey [NAME]           rekey a CHILD SA\n"
        "  child wait [NAME]            wait for an installed CHILD SA\n"
        "  peer register                responder registers with initiator\n"
        "                               initiator listener starts automatically\n"
        "  peer show                    show the in-memory peer table\n"
        "  peer select PEER_ID          select a peer for control commands\n"
        "  show [SCOPE]                 show a compact table (summary default)\n"
        "  show {connections|ike|child} detail [NAME]\n"
        "                               show every field, optionally by name\n"
        "  show SCOPE [NAME]            filter a compact named-object table\n"
        "  up                           convenience load and initiate\n"
        "  down                         convenience terminate and unload\n"
        "  test loop [--count N] [--delay-ms N] [--continue-on-error]\n"
        "                               run explicit lifecycle verification\n"
        "  test algorithm count MODE   show algorithm testcase count\n"
        "  test algorithm check MODE   validate the generated catalog\n"
        "  test algorithm serve [--port N]\n"
        "                               serve Native peer test requests\n"
        "  test algorithm run MODE [--start N] [--limit N|--all] [--port N]\n"
        "      [--results FILE] [--delay-ms N] [--stop-on-error]\n"
        "      [--ike PROPOSAL --esp PROPOSAL]\n"
        "                               run baseline/exhaustive/custom tests\n"
        "  help                         show this command list\n"
        "  exit                         close only this client session\n"
        "\n"
        "Show scopes:\n"
        "  summary, all, config, credential, daemon, connections, ike,\n"
        "  child, algorithms,\n"
        "  xfrm, xfrm-state, xfrm-policy, xfrm-stat, network,\n"
        "  interfaces, addresses, routes\n"
        "  NAME filtering is supported for connections, ike, and child.\n"
        "\n"
        "Algorithm modes:\n"
        "  baseline, exhaustive-ike, exhaustive-esp, custom\n"
        "\n"
        "Configuration changes are rejected while this session owns a\n"
        "connection. PSK contents are never displayed.\n");
}

static bool ParseNativeAppStartupOptions(
    int32_t iArgumentCount,
    char **ppcArguments,
    NativeAppStartupOptions_t *pOptions)
{
    int32_t iIndex = 1;
    bool bParsed = true;

    (void)memset(pOptions, 0, sizeof(*pOptions));
    pOptions->iCommandIndex = iArgumentCount;
    while ((iIndex < iArgumentCount) && bParsed) {
        const char *pcArgument = ppcArguments[iIndex];

        if (0 == strcmp("--config", pcArgument)) {
            if ((iIndex + 1) < iArgumentCount) {
                iIndex++;
                pOptions->pcConfigPath = ppcArguments[iIndex];
                iIndex++;
            }
            else {
                bParsed = false;
            }
        }
        else if (0 == strcmp("--app-config", pcArgument)) {
            if ((iIndex + 1) < iArgumentCount) {
                iIndex++;
                pOptions->pcApplicationConfigPath = ppcArguments[iIndex];
                iIndex++;
            }
            else {
                bParsed = false;
            }
        }
        else if (0 == strcmp("--management-config", pcArgument)) {
            if ((iIndex + 1) < iArgumentCount) {
                iIndex++;
                pOptions->pcManagementConfigPath = ppcArguments[iIndex];
                iIndex++;
            }
            else {
                bParsed = false;
            }
        }
        else if (0 == strcmp("--generate-psk", pcArgument)) {
            if ((iIndex + 1) < iArgumentCount) {
                iIndex++;
                pOptions->pcGeneratePskPath = ppcArguments[iIndex];
                iIndex++;
            }
            else {
                bParsed = false;
            }
        }
        else if (0 == strcmp("--verbose", pcArgument)) {
            pOptions->bVerbose = true;
            iIndex++;
        }
        else if ((0 == strcmp("--help", pcArgument)) ||
                 (0 == strcmp("-h", pcArgument))) {
            pOptions->bHelp = true;
            iIndex++;
        }
        else {
            pOptions->iCommandIndex = iIndex;
            break;
        }
    }
    return bParsed;
}

static bool CopyNativeAppSessionText(
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

static IpsecError_t OpenNativeAppContext(
    NativeAppSession_t *pSession,
    const NativeAppConfig_t *pAppConfig,
    IpsecContext_t **ppContext)
{
    IpsecConfig_t Config = {.uiStructSize = sizeof(IpsecConfig_t)};

    Config.pcViciSocketPath = ('\0' != pAppConfig->acViciSocket[0]) ?
        pAppConfig->acViciSocket : NULL;
    Config.uiConnectTimeoutMs = pAppConfig->uiTimeoutMs;
    Config.uiCommandTimeoutMs = pAppConfig->uiTimeoutMs;
    Config.pLogCallback = LogNativeApp;
    Config.pvLogUserData = pSession;
    return InitializeIpsec(ppContext, &Config);
}

static IpsecError_t ReconnectNativeAppContext(
    NativeAppSession_t *pSession,
    const NativeAppConfig_t *pConfig)
{
    IpsecContext_t *pNewContext = NULL;
    IpsecError_t eError;

    if (pSession->bConnectionLoaded) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = OpenNativeAppContext(pSession, pConfig, &pNewContext);
    }
    if (IPSEC_OK == eError) {
        DeinitializeIpsec(pSession->pContext);
        pSession->pContext = pNewContext;
    }
    else {
        /* Keep the existing connection and configuration. */
    }
    return eError;
}

static IpsecError_t RebuildNativeAppRuntime(NativeAppSession_t *pSession)
{
    char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
    IpsecError_t eError;

    eError = ValidateNativeAppConfig(&pSession->Config, acError,
                                     sizeof(acError));
    if (IPSEC_OK == eError) {
        eError = BuildNativeAppRuntimeConfig(&pSession->Config,
                                             &pSession->Runtime,
                                             acError, sizeof(acError));
    }
    else {
        /* Report the validation error below. */
    }
    pSession->bConfigValid = (IPSEC_OK == eError);
    if (IPSEC_OK != eError) {
        (void)memset(&pSession->Runtime, 0, sizeof(pSession->Runtime));
        (void)fprintf(stderr, "configuration is incomplete: %s\n", acError);
    }
    else {
        /* The runtime view is ready for control commands. */
    }
    return eError;
}

static IpsecError_t RequireNativeAppConfig(NativeAppSession_t *pSession)
{
    if (pSession->bConfigValid) {
        return IPSEC_OK;
    }
    else {
        return RebuildNativeAppRuntime(pSession);
    }
}

static const char *GetNativeAppRoleText(NativeAppRole_t eRole)
{
    return (NATIVE_APP_ROLE_RESPONDER == eRole) ? "responder" : "initiator";
}

static const char *GetNativeAppModeText(IpsecMode_t eMode)
{
    return (IPSEC_MODE_TRANSPORT == eMode) ? "transport" : "tunnel";
}

static void ShowNativeAppConfig(const NativeAppSession_t *pSession)
{
    const NativeAppConfig_t *pConfig = &pSession->Config;

    (void)printf(
        "[CONFIGURATION]\n"
        "  Legacy Path      : %s\n"
        "  Application Path : %s\n"
        "  Management Path  : %s\n"
        "  Valid            : %s\n"
        "  Role             : %s\n"
        "  Local Address    : %s\n"
        "  Remote Address   : %s\n"
        "  Local ID         : %s\n"
        "  Remote ID        : %s\n"
        "  PSK File         : %s\n"
        "  Output Root      : %s\n"
        "  VICI URI         : unix://%s\n"
        "  Connection Name  : %s\n"
        "  CHILD Name       : %s\n"
        "  Credential ID    : %s\n"
        "  Peer Server      : %s:%" PRIu32 "\n"
        "  IKE Proposals    : %s\n"
        "  ESP Proposals    : %s\n"
        "  IPsec Mode       : %s\n"
        "  Childless IKE    : %s\n"
        "  Terminate On Exit: %s\n"
        "  Command Timeout  : %" PRIu32 " ms\n",
        ('\0' != pSession->acConfigPath[0]) ? pSession->acConfigPath :
            "<none>",
        ('\0' != pSession->acApplicationConfigPath[0]) ?
            pSession->acApplicationConfigPath : "<none>",
        ('\0' != pSession->acManagementConfigPath[0]) ?
            pSession->acManagementConfigPath : "<none>",
        pSession->bConfigValid ? "yes" : "no",
        GetNativeAppRoleText(pConfig->eRole), pConfig->acLocalAddress,
        pConfig->acRemoteAddress, pConfig->acLocalId, pConfig->acRemoteId,
        pConfig->acPskFile, pConfig->acOutputRoot, pConfig->acViciSocket,
        pConfig->acConnectionName, pConfig->acChildName,
        pConfig->acCredentialId, pConfig->acPeerServerAddress,
        pConfig->uiPeerPort,
        pConfig->acIkeProposals, pConfig->acEspProposals,
        GetNativeAppModeText(pConfig->eMode),
        pConfig->bChildlessIke ? "true" : "false",
        pConfig->bTerminateOnExit ? "true" : "false",
        pConfig->uiTimeoutMs);
}

static void ShowNativeAppCredential(const NativeAppSession_t *pSession)
{
    (void)printf("[CREDENTIAL]\n"
                 "  Session Loaded   : %s\n"
                 "  Secret Displayed : no\n",
                 pSession->bCredentialLoaded ? "yes" : "no");
}

static const char *GetNativeAppPeerId(const NativeAppPeer_t *pPeer)
{
    return (NATIVE_APP_ROLE_RESPONDER == pPeer->Config.eRole) ?
        pPeer->Config.acLocalId : pPeer->Config.acRemoteId;
}

static void SaveNativeAppSelectedPeer(NativeAppSession_t *pSession)
{
    LockNativeAppPeerTable(&pSession->PeerTable);
    if (pSession->PeerTable.uiSelectedIndex <
        pSession->PeerTable.uiCount) {
        NativeAppPeer_t *pPeer =
            &pSession->PeerTable.aPeers[
                pSession->PeerTable.uiSelectedIndex];

        pPeer->Config = pSession->Config;
        pPeer->bConnectionLoaded = pSession->bConnectionLoaded;
        pPeer->bCredentialLoaded = pSession->bCredentialLoaded;
    }
    else {
        /* No registered peer is currently selected. */
    }
    UnlockNativeAppPeerTable(&pSession->PeerTable);
}

static IpsecError_t SelectNativeAppPeer(
    NativeAppSession_t *pSession,
    NativeAppPeer_t *pPeer)
{
    uint32_t uiIndex;
    bool bFound = false;
    IpsecError_t eError;

    if (NULL == pPeer) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        SaveNativeAppSelectedPeer(pSession);
        LockNativeAppPeerTable(&pSession->PeerTable);
        for (uiIndex = 0U;
             uiIndex < pSession->PeerTable.uiCount;
             uiIndex++) {
            if (pPeer == &pSession->PeerTable.aPeers[uiIndex]) {
                bFound = true;
                break;
            }
            else {
                /* Check the next table entry. */
            }
        }
    }
    if (!bFound) {
        UnlockNativeAppPeerTable(&pSession->PeerTable);
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        pSession->PeerTable.uiSelectedIndex = uiIndex;
        pSession->Config = pPeer->Config;
        pSession->bConnectionLoaded = pPeer->bConnectionLoaded;
        pSession->bCredentialLoaded = pPeer->bCredentialLoaded;
        UnlockNativeAppPeerTable(&pSession->PeerTable);
        pSession->bConfigValid = false;
        eError = RebuildNativeAppRuntime(pSession);
    }
    return eError;
}

static void ShowNativeAppPeers(NativeAppSession_t *pSession)
{
    uint32_t uiIndex;

    LockNativeAppPeerTable(&pSession->PeerTable);
    (void)printf(
        "[PEERS]\n"
        "  Count: %" PRIu32 "\n"
        "\n"
        "  Sel  Peer ID                    Group       Logon"
        "       Remote Address                           Connection\n"
        "  ---  -------------------------  ----------  ----------"
        "  ---------------------------------------"
        "  -------------------------------\n",
        pSession->PeerTable.uiCount);
    for (uiIndex = 0U; uiIndex < pSession->PeerTable.uiCount; uiIndex++) {
        const NativeAppPeer_t *pPeer =
            &pSession->PeerTable.aPeers[uiIndex];

        (void)printf(
            "  %-3s  %-25.25s  %-10" PRIu32 "  %-10" PRIu32
            "  %-39.39s  %-31.31s\n",
            (uiIndex == pSession->PeerTable.uiSelectedIndex) ? "*" : "",
            GetNativeAppPeerId(pPeer), pPeer->uiGroupId, pPeer->uiLogonId,
            pPeer->Config.acRemoteAddress,
            pPeer->Config.acConnectionName);
    }
    if (0U == pSession->PeerTable.uiCount) {
        (void)printf("  No registered peers.\n");
    }
    else {
        /* All peer rows were printed. */
    }
    UnlockNativeAppPeerTable(&pSession->PeerTable);
}

static void HandleNativeAppPeerListenerEvent(
    IpsecError_t eError,
    const NativeAppPeer_t *pPeer,
    const char *pcError,
    void *pvUserData)
{
    NativeAppSession_t *pSession = (NativeAppSession_t *)pvUserData;
    bool bRestorePrompt = (NULL != pSession) &&
        atomic_load(&pSession->bPromptVisible);

    if (bRestorePrompt) {
        (void)printf("\n");
    }
    else {
        /* No visible prompt needs restoration. */
    }
    if ((IPSEC_OK == eError) && (NULL != pPeer)) {
        (void)printf(
            "peer registered: %s group_id=%" PRIu32
            " logon_id=%" PRIu32 " remote=%s\n",
            GetNativeAppPeerId(pPeer), pPeer->uiGroupId,
            pPeer->uiLogonId, pPeer->Config.acRemoteAddress);
    }
    else {
        (void)fprintf(stderr, "peer listener error: %s (%s)\n",
                      ((NULL != pcError) && ('\0' != pcError[0])) ?
                          pcError : GetIpsecErrorString(eError),
                      GetIpsecErrorString(eError));
    }
    if (bRestorePrompt) {
        PrintNativeAppPrompt(pSession);
    }
    else {
        /* The command loop prints the next prompt. */
    }
}

static IpsecError_t ExecuteNativeAppPeerCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments)
{
    NativeAppPeer_t *pPeer = NULL;
    char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
    IpsecError_t eError;

    if ((2U == uiArgumentCount) &&
        (0 == strcmp("show", ppcArguments[1]))) {
        SaveNativeAppSelectedPeer(pSession);
        ShowNativeAppPeers(pSession);
        return IPSEC_OK;
    }
    else if ((3U == uiArgumentCount) &&
             (0 == strcmp("select", ppcArguments[1]))) {
        pPeer = FindNativeAppPeer(&pSession->PeerTable, ppcArguments[2]);
        if (NULL == pPeer) {
            return IPSEC_ERR_CONNECTION_NOT_FOUND;
        }
        else {
            eError = SelectNativeAppPeer(pSession, pPeer);
        }
    }
    else if ((2U == uiArgumentCount) &&
             (0 == strcmp("register", ppcArguments[1]))) {
        if (NATIVE_APP_ROLE_RESPONDER != pSession->BaseConfig.eRole) {
            return IPSEC_ERR_NOT_SUPPORTED;
        }
        else {
            (void)printf("registering with initiator %s:%" PRIu32 "...\n",
                         pSession->BaseConfig.acPeerServerAddress,
                         pSession->BaseConfig.uiPeerPort);
            eError = RegisterNativeAppPeer(
                &pSession->BaseConfig, &pSession->PeerTable, &pPeer,
                acError, sizeof(acError));
        }
        if (IPSEC_OK == eError) {
            eError = SelectNativeAppPeer(pSession, pPeer);
        }
    }
    else {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (IPSEC_OK == eError) {
        (void)printf(
            "peer selected: %s group_id=%" PRIu32
            " logon_id=%" PRIu32 "\n",
            GetNativeAppPeerId(pPeer), pPeer->uiGroupId,
            pPeer->uiLogonId);
    }
    else if ('\0' != acError[0]) {
        (void)fprintf(stderr, "peer operation failed: %s\n", acError);
    }
    else {
        /* The structured error is reported by the command loop. */
    }
    return eError;
}

static IpsecError_t LoadNativeAppSessionConfig(
    NativeAppSession_t *pSession,
    const char *pcPath)
{
    NativeAppConfig_t Config;
    NativeAppRuntimeConfig_t Runtime;
    IpsecContext_t *pNewContext = NULL;
    char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
    IpsecError_t eError;
    bool bSocketChanged;

    if (pSession->bConnectionLoaded) {
        (void)fprintf(stderr,
                      "unload the session connection first\n");
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = LoadNativeAppConfig(pcPath, &Config, acError,
                                     sizeof(acError));
    }
    if (IPSEC_OK == eError) {
        eError = BuildNativeAppRuntimeConfig(&Config, &Runtime, acError,
                                             sizeof(acError));
    }
    else {
        /* Report the configuration error below. */
    }
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "configuration load failed: %s\n", acError);
        return eError;
    }
    else {
        bSocketChanged =
            (0 != strcmp(Config.acViciSocket, pSession->Config.acViciSocket));
    }
    if (bSocketChanged) {
        eError = OpenNativeAppContext(pSession, &Config, &pNewContext);
    }
    else {
        eError = IPSEC_OK;
    }
    if ((IPSEC_OK == eError) &&
        !CopyNativeAppSessionText(pSession->acConfigPath,
                                  sizeof(pSession->acConfigPath), pcPath)) {
        DeinitializeIpsec(pNewContext);
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else if (IPSEC_OK == eError) {
        if (NULL != pNewContext) {
            DeinitializeIpsec(pSession->pContext);
            pSession->pContext = pNewContext;
        }
        else {
            /* Reuse the existing VICI context. */
        }
        pSession->Config = Config;
        pSession->BaseConfig = Config;
        pSession->acApplicationConfigPath[0] = '\0';
        pSession->acManagementConfigPath[0] = '\0';
        pSession->bCredentialLoaded = false;
        pSession->bConfigValid = false;
        eError = RebuildNativeAppRuntime(pSession);
    }
    else {
        /* Preserve the new VICI connection error. */
    }
    if (IPSEC_OK == eError) {
        (void)printf("configuration loaded: %s\n", pcPath);
    }
    else {
        /* The caller reports the structured error. */
    }
    return eError;
}

static IpsecError_t SetNativeAppSessionConfig(
    NativeAppSession_t *pSession,
    const char *pcKey,
    const char *pcValue)
{
    NativeAppConfig_t Config = pSession->Config;
    IpsecError_t eError;
    bool bSocketChanged;

    if (pSession->bConnectionLoaded) {
        (void)fprintf(stderr,
                      "unload the session connection first\n");
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = SetNativeAppConfigSetting(&Config, pcKey, pcValue);
    }
    if (IPSEC_OK == eError) {
        bSocketChanged =
            (0 != strcmp(Config.acViciSocket, pSession->Config.acViciSocket));
        if (bSocketChanged) {
            eError = ReconnectNativeAppContext(pSession, &Config);
        }
        else {
            /* The existing VICI context remains valid. */
        }
    }
    else {
        /* Preserve the setting validation error. */
    }
    if (IPSEC_OK == eError) {
        bool bBaseConfig;

        LockNativeAppPeerTable(&pSession->PeerTable);
        bBaseConfig = (pSession->PeerTable.uiSelectedIndex >=
                       pSession->PeerTable.uiCount);
        UnlockNativeAppPeerTable(&pSession->PeerTable);
        pSession->Config = Config;
        if (bBaseConfig) {
            pSession->BaseConfig = Config;
        }
        else {
            /* This change applies only to the selected peer profile. */
        }
        pSession->acConfigPath[0] = '\0';
        pSession->bCredentialLoaded = false;
        pSession->bConfigValid = false;
        (void)RebuildNativeAppRuntime(pSession);
        (void)printf("configuration updated: %s\n", pcKey);
    }
    else {
        /* The caller reports the structured error. */
    }
    return eError;
}

static IpsecControlOptions_t GetNativeAppControlOptions(
    const NativeAppSession_t *pSession)
{
    IpsecControlOptions_t Control = {
        .uiStructSize = sizeof(IpsecControlOptions_t),
        .eMode = IPSEC_CONTROL_WAIT,
        .uiTimeoutMs = pSession->Config.uiTimeoutMs
    };

    return Control;
}

static IpsecError_t ExecuteNativeAppConnectionCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments)
{
    IpsecError_t eError;

    if ((2U == uiArgumentCount) &&
        (0 == strcmp("load", ppcArguments[1]))) {
        eError = RequireNativeAppConfig(pSession);
        if (IPSEC_OK == eError) {
            eError = AddIpsecConnection(pSession->pContext,
                                        &pSession->Runtime.Connection);
        }
        if (IPSEC_OK == eError) {
            pSession->bConnectionLoaded = true;
            (void)printf("connection loaded: %s\n",
                         pSession->Config.acConnectionName);
        }
    }
    else if (((2U == uiArgumentCount) || (3U == uiArgumentCount)) &&
             (0 == strcmp("unload", ppcArguments[1]))) {
        const char *pcName;

        if (3U == uiArgumentCount) {
            pcName = ppcArguments[2];
            eError = IPSEC_OK;
        }
        else {
            eError = RequireNativeAppConfig(pSession);
            pcName = pSession->Config.acConnectionName;
        }
        if (IPSEC_OK == eError) {
            eError = RemoveIpsecConnection(pSession->pContext, pcName);
        }
        if (IPSEC_OK == eError) {
            if (0 == strcmp(pcName, pSession->Config.acConnectionName)) {
                pSession->bConnectionLoaded = false;
            }
            else {
                /* Another explicitly named connection was removed. */
            }
            (void)printf("connection unloaded: %s\n", pcName);
        }
    }
    else if ((2U == uiArgumentCount) &&
             (0 == strcmp("show", ppcArguments[1]))) {
        eError = ShowNativeAppInformation(pSession->pContext,
                                          "connections", false, NULL);
    }
    else {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppCredentialCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments)
{
    IpsecError_t eError;

    if ((2U == uiArgumentCount) &&
        (0 == strcmp("load", ppcArguments[1]))) {
        eError = RequireNativeAppConfig(pSession);
        if (IPSEC_OK == eError) {
            eError = LoadNativeAppCredential(pSession->pContext,
                                             &pSession->Config);
        }
        if (IPSEC_OK == eError) {
            pSession->bCredentialLoaded = true;
            (void)printf("credential loaded for connection: %s\n",
                         pSession->Config.acConnectionName);
        }
    }
    else if ((2U == uiArgumentCount) &&
             (0 == strcmp("clear", ppcArguments[1]))) {
        eError = ClearIpsecCredentials(pSession->pContext);
        if (IPSEC_OK == eError) {
            uint32_t uiIndex;

            pSession->bCredentialLoaded = false;
            LockNativeAppPeerTable(&pSession->PeerTable);
            for (uiIndex = 0U;
                 uiIndex < pSession->PeerTable.uiCount;
                 uiIndex++) {
                pSession->PeerTable.aPeers[
                    uiIndex].bCredentialLoaded = false;
            }
            UnlockNativeAppPeerTable(&pSession->PeerTable);
            (void)printf("all VICI credentials cleared\n");
        }
    }
    else if ((2U == uiArgumentCount) &&
             (0 == strcmp("show", ppcArguments[1]))) {
        ShowNativeAppCredential(pSession);
        eError = IPSEC_OK;
    }
    else {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppIkeCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments)
{
    IpsecControlOptions_t Control = GetNativeAppControlOptions(pSession);
    const char *pcName;
    IpsecError_t eError;

    if ((2U != uiArgumentCount) && (3U != uiArgumentCount)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (3U == uiArgumentCount) {
        pcName = ppcArguments[2];
        eError = IPSEC_OK;
    }
    else {
        eError = RequireNativeAppConfig(pSession);
        pcName = pSession->Config.acConnectionName;
    }
    if (IPSEC_OK != eError) {
        return eError;
    }
    else if (0 == strcmp("initiate", ppcArguments[1])) {
        eError = InitiateIpsecIke(pSession->pContext, pcName, &Control);
        if (IPSEC_OK == eError) {
            eError = WaitIpsecIkeEstablished(pSession->pContext, pcName,
                                             pSession->Config.uiTimeoutMs);
        }
    }
    else if (0 == strcmp("terminate", ppcArguments[1])) {
        eError = TerminateIpsecIke(pSession->pContext, pcName, &Control);
    }
    else if (0 == strcmp("rekey", ppcArguments[1])) {
        eError = RekeyIpsecIke(pSession->pContext, pcName);
    }
    else if (0 == strcmp("wait", ppcArguments[1])) {
        eError = WaitIpsecIkeEstablished(pSession->pContext, pcName,
                                         pSession->Config.uiTimeoutMs);
    }
    else {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (IPSEC_OK == eError) {
        (void)printf("ike %s completed: %s\n", ppcArguments[1], pcName);
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppChildCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments)
{
    IpsecControlOptions_t Control = GetNativeAppControlOptions(pSession);
    const char *pcName;
    IpsecError_t eError;

    if ((2U != uiArgumentCount) && (3U != uiArgumentCount)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (3U == uiArgumentCount) {
        pcName = ppcArguments[2];
        eError = IPSEC_OK;
    }
    else {
        eError = RequireNativeAppConfig(pSession);
        pcName = pSession->Config.acChildName;
    }
    if (IPSEC_OK != eError) {
        return eError;
    }
    else if (0 == strcmp("initiate", ppcArguments[1])) {
        eError = InitiateIpsecChild(pSession->pContext, pcName, &Control);
        if (IPSEC_OK == eError) {
            eError = WaitIpsecChildInstalled(pSession->pContext, pcName,
                                             pSession->Config.uiTimeoutMs);
        }
    }
    else if (0 == strcmp("terminate", ppcArguments[1])) {
        eError = TerminateIpsecChild(pSession->pContext, pcName, &Control);
    }
    else if (0 == strcmp("rekey", ppcArguments[1])) {
        eError = RekeyIpsecChild(pSession->pContext, pcName);
    }
    else if (0 == strcmp("wait", ppcArguments[1])) {
        eError = WaitIpsecChildInstalled(pSession->pContext, pcName,
                                         pSession->Config.uiTimeoutMs);
    }
    else {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (IPSEC_OK == eError) {
        (void)printf("child %s completed: %s\n", ppcArguments[1], pcName);
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppUp(NativeAppSession_t *pSession)
{
    bool bConnectionAdded = false;
    IpsecError_t eError;

    eError = RequireNativeAppConfig(pSession);
    if ((IPSEC_OK == eError) && !pSession->bConnectionLoaded) {
        eError = AddIpsecConnection(pSession->pContext,
                                    &pSession->Runtime.Connection);
        if (IPSEC_OK == eError) {
            pSession->bConnectionLoaded = true;
            bConnectionAdded = true;
        }
    }
    if ((IPSEC_OK == eError) && !pSession->bCredentialLoaded) {
        eError = LoadNativeAppCredential(pSession->pContext,
                                         &pSession->Config);
        if (IPSEC_OK == eError) {
            pSession->bCredentialLoaded = true;
        }
    }
    if (IPSEC_OK == eError) {
        eError = StartNativeAppConnection(pSession->pContext,
                                          &pSession->Config,
                                          &pSession->Runtime);
    }
    if ((IPSEC_OK != eError) && bConnectionAdded) {
        if (IPSEC_OK == RemoveIpsecConnection(
                pSession->pContext, pSession->Config.acConnectionName)) {
            pSession->bConnectionLoaded = false;
        }
        else {
            /* Leave ownership set because cleanup did not complete. */
        }
    }
    if (IPSEC_OK == eError) {
        (void)printf("up completed: %s/%s\n",
                     pSession->Config.acConnectionName,
                     pSession->Config.acChildName);
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppDown(NativeAppSession_t *pSession)
{
    IpsecControlOptions_t Control = GetNativeAppControlOptions(pSession);
    IpsecError_t eFirstError;
    IpsecError_t eError;

    eFirstError = RequireNativeAppConfig(pSession);
    if (IPSEC_OK == eFirstError) {
        eFirstError = TerminateIpsecIke(pSession->pContext,
                                        pSession->Config.acConnectionName,
                                        &Control);
    }
    if (pSession->bConnectionLoaded) {
        eError = RemoveIpsecConnection(pSession->pContext,
                                       pSession->Config.acConnectionName);
        if (IPSEC_OK == eError) {
            pSession->bConnectionLoaded = false;
        }
        else if (IPSEC_OK == eFirstError) {
            eFirstError = eError;
        }
        else {
            /* Preserve the termination error. */
        }
    }
    else {
        /* No connection owned by this session needs unloading. */
    }
    if (IPSEC_OK == eFirstError) {
        (void)printf("down completed; credentials were retained\n");
    }
    return eFirstError;
}

static IpsecError_t ParseNativeAppLoopOptions(
    uint32_t uiArgumentCount,
    char **ppcArguments,
    uint32_t uiStartIndex,
    NativeAppLoopOptions_t *pOptions)
{
    uint32_t uiIndex = uiStartIndex;

    (void)memset(pOptions, 0, sizeof(*pOptions));
    pOptions->uiCount = 10U;
    pOptions->uiDelayMs = 1000U;
    while (uiIndex < uiArgumentCount) {
        if ((0 == strcmp("--count", ppcArguments[uiIndex])) &&
            ((uiIndex + 1U) < uiArgumentCount) &&
            ParseNativeAppNumber(ppcArguments[uiIndex + 1U],
                                 &pOptions->uiCount) &&
            (0U < pOptions->uiCount)) {
            uiIndex += 2U;
        }
        else if ((0 == strcmp("--delay-ms", ppcArguments[uiIndex])) &&
                 ((uiIndex + 1U) < uiArgumentCount) &&
                 ParseNativeAppNumber(ppcArguments[uiIndex + 1U],
                                      &pOptions->uiDelayMs)) {
            uiIndex += 2U;
        }
        else if (0 == strcmp("--continue-on-error",
                             ppcArguments[uiIndex])) {
            pOptions->bContinueOnError = true;
            uiIndex++;
        }
        else if (0 == strcmp("--clear-credentials",
                             ppcArguments[uiIndex])) {
            pOptions->bClearCredentials = true;
            uiIndex++;
        }
        else {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
    }
    return IPSEC_OK;
}

static IpsecError_t ExecuteNativeAppLoopCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments,
    uint32_t uiStartIndex)
{
    NativeAppLoopOptions_t Options;
    IpsecError_t eError;

    if (pSession->bConnectionLoaded) {
        (void)fprintf(stderr,
                      "unload the session connection before a loop test\n");
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = RequireNativeAppConfig(pSession);
    }
    if (IPSEC_OK == eError) {
        eError = ParseNativeAppLoopOptions(uiArgumentCount, ppcArguments,
                                           uiStartIndex, &Options);
    }
    if (IPSEC_OK == eError) {
        ResetNativeAppStopRequest();
        eError = RunNativeAppLoop(pSession->pContext, &pSession->Config,
                                  &pSession->Runtime, &Options);
        ResetNativeAppStopRequest();
        pSession->bConnectionLoaded = false;
        pSession->bCredentialLoaded = !Options.bClearCredentials;
    }
    return eError;
}

static IpsecError_t ParseNativeAppAlgorithmRunOptions(
    uint32_t uiArgumentCount,
    char **ppcArguments,
    NativeAppAlgorithmOptions_t *pOptions)
{
    uint32_t uiIndex = 4U;

    (void)memset(pOptions, 0, sizeof(*pOptions));
    if ((4U > uiArgumentCount) ||
        !ParseNativeAppAlgorithmMode(ppcArguments[3], &pOptions->eMode)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pOptions->uiStart = 1U;
    pOptions->uiPort = NATIVE_APP_ALGORITHM_DEFAULT_PORT;
    pOptions->uiDelayMs = 500U;
    pOptions->bContinueOnError = true;
    pOptions->uiLimit =
        (NATIVE_APP_ALGORITHM_BASELINE == pOptions->eMode) ?
        GetNativeAppAlgorithmCaseCount(pOptions->eMode) :
        NATIVE_APP_ALGORITHM_DEFAULT_LIMIT;
    if (NATIVE_APP_ALGORITHM_CUSTOM == pOptions->eMode) {
        pOptions->uiLimit = 1U;
    }
    while (uiIndex < uiArgumentCount) {
        if ((0 == strcmp("--start", ppcArguments[uiIndex])) &&
            ((uiIndex + 1U) < uiArgumentCount) &&
            ParseNativeAppNumber(ppcArguments[uiIndex + 1U],
                                 &pOptions->uiStart) &&
            (0U < pOptions->uiStart)) {
            uiIndex += 2U;
        }
        else if ((0 == strcmp("--limit", ppcArguments[uiIndex])) &&
                 ((uiIndex + 1U) < uiArgumentCount) &&
                 ParseNativeAppNumber(ppcArguments[uiIndex + 1U],
                                      &pOptions->uiLimit) &&
                 (0U < pOptions->uiLimit)) {
            uiIndex += 2U;
        }
        else if (0 == strcmp("--all", ppcArguments[uiIndex])) {
            pOptions->uiLimit = 0U;
            uiIndex++;
        }
        else if ((0 == strcmp("--port", ppcArguments[uiIndex])) &&
                 ((uiIndex + 1U) < uiArgumentCount) &&
                 ParseNativeAppNumber(ppcArguments[uiIndex + 1U],
                                      &pOptions->uiPort) &&
                 (0U < pOptions->uiPort) &&
                 (UINT16_MAX >= pOptions->uiPort)) {
            uiIndex += 2U;
        }
        else if ((0 == strcmp("--delay-ms", ppcArguments[uiIndex])) &&
                 ((uiIndex + 1U) < uiArgumentCount) &&
                 ParseNativeAppNumber(ppcArguments[uiIndex + 1U],
                                      &pOptions->uiDelayMs)) {
            uiIndex += 2U;
        }
        else if ((0 == strcmp("--results", ppcArguments[uiIndex])) &&
                 ((uiIndex + 1U) < uiArgumentCount)) {
            pOptions->pcResultsPath = ppcArguments[uiIndex + 1U];
            uiIndex += 2U;
        }
        else if ((0 == strcmp("--ike", ppcArguments[uiIndex])) &&
                 ((uiIndex + 1U) < uiArgumentCount)) {
            pOptions->pcCustomIke = ppcArguments[uiIndex + 1U];
            uiIndex += 2U;
        }
        else if ((0 == strcmp("--esp", ppcArguments[uiIndex])) &&
                 ((uiIndex + 1U) < uiArgumentCount)) {
            pOptions->pcCustomEsp = ppcArguments[uiIndex + 1U];
            uiIndex += 2U;
        }
        else if (0 == strcmp("--continue-on-error",
                             ppcArguments[uiIndex])) {
            pOptions->bContinueOnError = true;
            uiIndex++;
        }
        else if (0 == strcmp("--stop-on-error",
                             ppcArguments[uiIndex])) {
            pOptions->bContinueOnError = false;
            uiIndex++;
        }
        else {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
    }
    if ((NATIVE_APP_ALGORITHM_CUSTOM == pOptions->eMode) &&
        ((NULL == pOptions->pcCustomIke) ||
         (NULL == pOptions->pcCustomEsp))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if ((NATIVE_APP_ALGORITHM_CUSTOM != pOptions->eMode) &&
             ((NULL != pOptions->pcCustomIke) ||
              (NULL != pOptions->pcCustomEsp))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        return IPSEC_OK;
    }
}

static IpsecError_t CheckNativeAppAlgorithmCatalog(
    const NativeAppConfig_t *pConfig,
    NativeAppAlgorithmMode_t eMode)
{
    uint32_t uiCount = GetNativeAppAlgorithmCaseCount(eMode);
    uint32_t uiIndex;

    for (uiIndex = 0U; uiIndex < uiCount; uiIndex++) {
        NativeAppAlgorithmCase_t Case;
        IpsecError_t eError = GetNativeAppAlgorithmCase(
            eMode, uiIndex, pConfig,
            (NATIVE_APP_ALGORITHM_CUSTOM == eMode) ?
            pConfig->acIkeProposals : NULL,
            (NATIVE_APP_ALGORITHM_CUSTOM == eMode) ?
            pConfig->acEspProposals : NULL, &Case);

        if (IPSEC_OK != eError) {
            return eError;
        }
    }
    (void)printf("algorithm catalog valid: mode=%s cases=%" PRIu32 "\n",
                 GetNativeAppAlgorithmModeName(eMode), uiCount);
    return IPSEC_OK;
}

static IpsecError_t ExecuteNativeAppAlgorithmCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments)
{
    NativeAppAlgorithmMode_t eMode;
    IpsecError_t eError;

    if ((4U == uiArgumentCount) &&
        (0 == strcmp("count", ppcArguments[2])) &&
        ParseNativeAppAlgorithmMode(ppcArguments[3], &eMode)) {
        (void)printf("algorithm cases: mode=%s count=%" PRIu32 "\n",
                     GetNativeAppAlgorithmModeName(eMode),
                     GetNativeAppAlgorithmCaseCount(eMode));
        eError = IPSEC_OK;
    }
    else if ((4U == uiArgumentCount) &&
             (0 == strcmp("check", ppcArguments[2])) &&
             ParseNativeAppAlgorithmMode(ppcArguments[3], &eMode)) {
        eError = RequireNativeAppConfig(pSession);
        if (IPSEC_OK == eError) {
            eError = CheckNativeAppAlgorithmCatalog(&pSession->Config, eMode);
        }
    }
    else if ((3U <= uiArgumentCount) &&
             (0 == strcmp("serve", ppcArguments[2]))) {
        uint32_t uiPort = NATIVE_APP_ALGORITHM_DEFAULT_PORT;

        if ((5U == uiArgumentCount) &&
            (0 == strcmp("--port", ppcArguments[3])) &&
            ParseNativeAppNumber(ppcArguments[4], &uiPort) &&
            (0U < uiPort) && (UINT16_MAX >= uiPort)) {
            eError = IPSEC_OK;
        }
        else if (3U == uiArgumentCount) {
            eError = IPSEC_OK;
        }
        else {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        if ((IPSEC_OK == eError) && pSession->bConnectionLoaded) {
            (void)fprintf(stderr,
                          "unload the session connection before serving tests\n");
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        if (IPSEC_OK == eError) {
            eError = RequireNativeAppConfig(pSession);
        }
        if (IPSEC_OK == eError) {
            ResetNativeAppStopRequest();
            eError = RunNativeAppAlgorithmServer(
                pSession->pContext, &pSession->Config, uiPort);
            ResetNativeAppStopRequest();
            pSession->bCredentialLoaded = true;
        }
    }
    else if ((4U <= uiArgumentCount) &&
             (0 == strcmp("run", ppcArguments[2]))) {
        NativeAppAlgorithmOptions_t Options;

        if (pSession->bConnectionLoaded) {
            (void)fprintf(stderr,
                          "unload the session connection before algorithm tests\n");
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            eError = RequireNativeAppConfig(pSession);
        }
        if (IPSEC_OK == eError) {
            eError = ParseNativeAppAlgorithmRunOptions(
                uiArgumentCount, ppcArguments, &Options);
        }
        if (IPSEC_OK == eError) {
            ResetNativeAppStopRequest();
            eError = RunNativeAppAlgorithmClient(
                pSession->pContext, &pSession->Config, &Options);
            ResetNativeAppStopRequest();
            pSession->bCredentialLoaded = true;
        }
    }
    else {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppConfigCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments)
{
    IpsecError_t eError;

    if ((3U == uiArgumentCount) &&
        (0 == strcmp("load", ppcArguments[1]))) {
        eError = LoadNativeAppSessionConfig(pSession, ppcArguments[2]);
    }
    else if ((4U == uiArgumentCount) &&
             (0 == strcmp("set", ppcArguments[1]))) {
        eError = SetNativeAppSessionConfig(pSession, ppcArguments[2],
                                           ppcArguments[3]);
    }
    else if ((2U == uiArgumentCount) &&
             (0 == strcmp("show", ppcArguments[1]))) {
        ShowNativeAppConfig(pSession);
        eError = IPSEC_OK;
    }
    else if ((2U == uiArgumentCount) &&
             (0 == strcmp("validate", ppcArguments[1]))) {
        eError = RebuildNativeAppRuntime(pSession);
        if (IPSEC_OK == eError) {
            (void)printf("configuration is valid\n");
        }
    }
    else {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppLegacyLoad(NativeAppSession_t *pSession)
{
    IpsecError_t eError;

    if (pSession->bConnectionLoaded || pSession->bCredentialLoaded) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = RequireNativeAppConfig(pSession);
    }
    if (IPSEC_OK == eError) {
        eError = LoadNativeAppResources(pSession->pContext,
                                        &pSession->Config,
                                        &pSession->Runtime);
    }
    if (IPSEC_OK == eError) {
        pSession->bConnectionLoaded = true;
        pSession->bCredentialLoaded = true;
        (void)printf("connection and credential loaded\n");
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments,
    bool *pbExit)
{
    IpsecError_t eError;

    *pbExit = false;
    if (0U == uiArgumentCount) {
        eError = IPSEC_OK;
    }
    else if (0 == strcmp("config", ppcArguments[0])) {
        eError = ExecuteNativeAppConfigCommand(pSession, uiArgumentCount,
                                               ppcArguments);
    }
    else if (0 == strcmp("connection", ppcArguments[0])) {
        eError = ExecuteNativeAppConnectionCommand(pSession, uiArgumentCount,
                                                   ppcArguments);
    }
    else if (0 == strcmp("credential", ppcArguments[0])) {
        eError = ExecuteNativeAppCredentialCommand(pSession, uiArgumentCount,
                                                   ppcArguments);
    }
    else if (0 == strcmp("peer", ppcArguments[0])) {
        eError = ExecuteNativeAppPeerCommand(pSession, uiArgumentCount,
                                             ppcArguments);
    }
    else if (0 == strcmp("ike", ppcArguments[0])) {
        eError = ExecuteNativeAppIkeCommand(pSession, uiArgumentCount,
                                            ppcArguments);
    }
    else if (0 == strcmp("child", ppcArguments[0])) {
        eError = ExecuteNativeAppChildCommand(pSession, uiArgumentCount,
                                              ppcArguments);
    }
    else if ((1U <= uiArgumentCount) &&
             ((0 == strcmp("show", ppcArguments[0])) ||
              (0 == strcmp("status", ppcArguments[0])))) {
        NativeAppShowOptions_t Options = {0};

        if (!ParseNativeAppShowOptions(uiArgumentCount, ppcArguments,
                                       &Options)) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            eError = IPSEC_OK;
        }
        if ((IPSEC_OK == eError) &&
            (0 == strcmp("config", Options.pcScope))) {
            ShowNativeAppConfig(pSession);
            eError = IPSEC_OK;
        }
        else if ((IPSEC_OK == eError) &&
                 (0 == strcmp("credential", Options.pcScope))) {
            ShowNativeAppCredential(pSession);
            eError = IPSEC_OK;
        }
        else if (IPSEC_OK == eError) {
            eError = ShowNativeAppInformation(
                pSession->pContext, Options.pcScope, Options.bDetail,
                Options.pcName);
        }
        else {
            /* Preserve the argument parsing error. */
        }
    }
    else if ((1U == uiArgumentCount) &&
             (0 == strcmp("up", ppcArguments[0]))) {
        eError = ExecuteNativeAppUp(pSession);
    }
    else if ((1U == uiArgumentCount) &&
             (0 == strcmp("down", ppcArguments[0]))) {
        eError = ExecuteNativeAppDown(pSession);
    }
    else if ((2U <= uiArgumentCount) &&
             (0 == strcmp("test", ppcArguments[0])) &&
             (0 == strcmp("loop", ppcArguments[1]))) {
        eError = ExecuteNativeAppLoopCommand(pSession, uiArgumentCount,
                                             ppcArguments, 2U);
    }
    else if ((3U <= uiArgumentCount) &&
             (0 == strcmp("test", ppcArguments[0])) &&
             (0 == strcmp("algorithm", ppcArguments[1]))) {
        eError = ExecuteNativeAppAlgorithmCommand(
            pSession, uiArgumentCount, ppcArguments);
    }
    else if ((1U == uiArgumentCount) &&
             (0 == strcmp("check", ppcArguments[0]))) {
        eError = ShowNativeAppInformation(pSession->pContext, "daemon",
                                          false, NULL);
    }
    else if ((1U == uiArgumentCount) &&
             (0 == strcmp("load", ppcArguments[0]))) {
        eError = ExecuteNativeAppLegacyLoad(pSession);
    }
    else if ((1U == uiArgumentCount) &&
             (0 == strcmp("unload", ppcArguments[0]))) {
        char *pacUnload[] = {"connection", "unload"};

        eError = ExecuteNativeAppConnectionCommand(pSession, 2U, pacUnload);
    }
    else if ((1U == uiArgumentCount) &&
             (0 == strcmp("rekey-ike", ppcArguments[0]))) {
        char *pacRekey[] = {"ike", "rekey"};

        eError = ExecuteNativeAppIkeCommand(pSession, 2U, pacRekey);
    }
    else if ((1U == uiArgumentCount) &&
             (0 == strcmp("rekey-child", ppcArguments[0]))) {
        char *pacRekey[] = {"child", "rekey"};

        eError = ExecuteNativeAppChildCommand(pSession, 2U, pacRekey);
    }
    else if ((1U == uiArgumentCount) &&
             (0 == strcmp("clear-credentials", ppcArguments[0]))) {
        char *pacClear[] = {"credential", "clear"};

        eError = ExecuteNativeAppCredentialCommand(pSession, 2U, pacClear);
    }
    else if ((1U == uiArgumentCount) &&
             ((0 == strcmp("help", ppcArguments[0])) ||
              (0 == strcmp("?", ppcArguments[0])))) {
        PrintNativeAppHelp();
        eError = IPSEC_OK;
    }
    else if ((1U == uiArgumentCount) &&
             ((0 == strcmp("exit", ppcArguments[0])) ||
              (0 == strcmp("quit", ppcArguments[0])))) {
        *pbExit = true;
        eError = IPSEC_OK;
    }
    else {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    SaveNativeAppSelectedPeer(pSession);
    return eError;
}

static int32_t RunNativeAppInteractive(NativeAppSession_t *pSession)
{
    char acLine[NATIVE_APP_COMMAND_LINE_LENGTH];
    char *pacArguments[NATIVE_APP_COMMAND_ARGUMENT_COUNT];
    bool bExit = false;

    (void)printf("Native IPsec CLI connected. Type 'help' for commands.\n");
    while (!bExit) {
        uint32_t uiArgumentCount = 0U;
        IpsecError_t eError;

        PrintNativeAppPrompt(pSession);
        errno = 0;
        if (NULL == fgets(acLine, sizeof(acLine), stdin)) {
            atomic_store(&pSession->bPromptVisible, false);
            if (EINTR == errno) {
                clearerr(stdin);
                (void)printf("\n");
                continue;
            }
            else {
                (void)printf("\n");
                break;
            }
        }
        else {
            atomic_store(&pSession->bPromptVisible, false);
        }
        if (!ParseNativeAppCommandLine(acLine, pacArguments,
                                       NATIVE_APP_COMMAND_ARGUMENT_COUNT,
                                       &uiArgumentCount)) {
            (void)fprintf(stderr, "command parse failed\n");
            continue;
        }
        else {
            eError = ExecuteNativeAppCommand(pSession, uiArgumentCount,
                                             pacArguments, &bExit);
        }
        if (IPSEC_OK != eError) {
            (void)fprintf(stderr, "command failed: %s\n",
                          GetIpsecErrorString(eError));
        }
        else {
            /* The command completed or requested exit. */
        }
    }
    (void)printf("session closed; daemon resources were not changed on exit\n");
    return 0;
}

int32_t RunNativeAppCli(
    int32_t iArgumentCount,
    char **ppcArguments)
{
    NativeAppStartupOptions_t Options;
    NativeAppSession_t Session;
    char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
    IpsecError_t eError;
    int32_t iResult;

    if ((0 >= iArgumentCount) || (NULL == ppcArguments) ||
        !ParseNativeAppStartupOptions(iArgumentCount, ppcArguments,
                                      &Options)) {
        PrintNativeAppUsage((0 < iArgumentCount) ? ppcArguments[0] :
                            "ipsec_app");
        return 2;
    }
    else if (Options.bHelp) {
        PrintNativeAppUsage(ppcArguments[0]);
        PrintNativeAppHelp();
        return 0;
    }
    else if (NULL != Options.pcGeneratePskPath) {
        if ((NULL != Options.pcConfigPath) ||
            (NULL != Options.pcApplicationConfigPath) ||
            (NULL != Options.pcManagementConfigPath) ||
            (Options.iCommandIndex < iArgumentCount)) {
            PrintNativeAppUsage(ppcArguments[0]);
            return 2;
        }
        else {
            /* PSK generation is a standalone action without VICI. */
        }
        eError = GenerateIpsecPskFile(Options.pcGeneratePskPath);
        if (IPSEC_OK == eError) {
            (void)printf("PSK generated: %s\n",
                         Options.pcGeneratePskPath);
            return 0;
        }
        else {
            (void)fprintf(stderr, "PSK generation failed: %s\n",
                          GetIpsecErrorString(eError));
            return 1;
        }
    }
    else {
        bool bHasApplicationConfig =
            (NULL != Options.pcApplicationConfigPath);
        bool bHasManagementConfig =
            (NULL != Options.pcManagementConfigPath);

        if ((bHasApplicationConfig != bHasManagementConfig) ||
            ((NULL != Options.pcConfigPath) && bHasApplicationConfig)) {
            PrintNativeAppUsage(ppcArguments[0]);
            return 2;
        }
        else {
            /* The selected configuration mode is complete. */
        }
        (void)memset(&Session, 0, sizeof(Session));
        atomic_init(&Session.bPromptVisible, false);
        Session.bVerbose = Options.bVerbose;
        InitializeNativeAppConfig(&Session.Config);
        InitializeNativeAppConfig(&Session.BaseConfig);
        eError = InitializeNativeAppPeerTable(&Session.PeerTable);
        if (IPSEC_OK != eError) {
            (void)fprintf(stderr, "peer table initialization failed: %s\n",
                          GetIpsecErrorString(eError));
            return 1;
        }
        else {
            /* Continue loading the selected configuration. */
        }
    }

    if (NULL != Options.pcApplicationConfigPath) {
        eError = LoadNativeAppConfigFiles(
            Options.pcApplicationConfigPath,
            Options.pcManagementConfigPath, &Session.Config,
            acError, sizeof(acError));
        if ((IPSEC_OK == eError) &&
            CopyNativeAppSessionText(
                Session.acApplicationConfigPath,
                sizeof(Session.acApplicationConfigPath),
                Options.pcApplicationConfigPath) &&
            CopyNativeAppSessionText(
                Session.acManagementConfigPath,
                sizeof(Session.acManagementConfigPath),
                Options.pcManagementConfigPath)) {
            Session.BaseConfig = Session.Config;
            Session.bConfigValid = false;
        }
        else if (IPSEC_OK == eError) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            /* Report the split configuration error below. */
        }
    }
    else if (NULL != Options.pcConfigPath) {
        eError = LoadNativeAppConfig(Options.pcConfigPath, &Session.Config,
                                     acError, sizeof(acError));
        if (IPSEC_OK == eError) {
            eError = BuildNativeAppRuntimeConfig(&Session.Config,
                                                 &Session.Runtime,
                                                 acError, sizeof(acError));
        }
        if ((IPSEC_OK == eError) &&
            CopyNativeAppSessionText(Session.acConfigPath,
                                     sizeof(Session.acConfigPath),
                                     Options.pcConfigPath)) {
            Session.BaseConfig = Session.Config;
            Session.bConfigValid = true;
        }
        else if (IPSEC_OK == eError) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            /* Report the parser error below. */
        }
    }
    else {
        eError = IPSEC_OK;
    }
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "configuration failed: %s (%s)\n", acError,
                      GetIpsecErrorString(eError));
        DeinitializeNativeAppPeerTable(&Session.PeerTable);
        return 1;
    }
    else {
        eError = OpenNativeAppContext(&Session, &Session.Config,
                                      &Session.pContext);
    }
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "InitializeIpsec failed: %s\n",
                      GetIpsecErrorString(eError));
        DeinitializeNativeAppPeerTable(&Session.PeerTable);
        return 1;
    }
    else if ((NATIVE_APP_ROLE_INITIATOR == Session.BaseConfig.eRole) &&
             ((NULL != Options.pcConfigPath) ||
              (NULL != Options.pcApplicationConfigPath))) {
        eError = StartNativeAppPeerListener(
            &Session.PeerListener, &Session.BaseConfig, &Session.PeerTable,
            HandleNativeAppPeerListenerEvent, &Session, acError,
            sizeof(acError));
        if (IPSEC_OK != eError) {
            (void)fprintf(stderr, "peer listener startup failed: %s (%s)\n",
                          acError, GetIpsecErrorString(eError));
            DeinitializeIpsec(Session.pContext);
            DeinitializeNativeAppPeerTable(&Session.PeerTable);
            return 1;
        }
        else {
            (void)printf("peer listener started: %s:%" PRIu32 "\n",
                         Session.BaseConfig.acPeerServerAddress,
                         Session.BaseConfig.uiPeerPort);
        }
    }
    else {
        /* Responders register explicitly and unconfigured sessions stay idle. */
    }

    if (Options.iCommandIndex < iArgumentCount) {
        bool bExit = false;
        uint32_t uiCommandCount =
            (uint32_t)(iArgumentCount - Options.iCommandIndex);

        eError = ExecuteNativeAppCommand(
            &Session, uiCommandCount, &ppcArguments[Options.iCommandIndex],
            &bExit);
        if (IPSEC_OK == eError) {
            iResult = 0;
        }
        else {
            (void)fprintf(stderr, "command failed: %s\n",
                          GetIpsecErrorString(eError));
            iResult = 1;
        }
    }
    else {
        iResult = RunNativeAppInteractive(&Session);
    }
    StopNativeAppPeerListener(&Session.PeerListener);
    DeinitializeIpsec(Session.pContext);
    DeinitializeNativeAppPeerTable(&Session.PeerTable);
    return iResult;
}
