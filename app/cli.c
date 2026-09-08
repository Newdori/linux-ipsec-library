#include "app_internal.h"

#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

typedef struct NativeAppSession {
    IpsecContext_t *pContext;
    NativeAppConfig_t BaseConfig;
    NativeAppConfig_t ContextConfig;
    NativeAppConfig_t Config;
    NativeAppRuntimeConfig_t Runtime;
    NativeAppPeerTable_t PeerTable;
    NativeAppPeerListener_t PeerListener;
    NativeAppOwnedResources_t OwnedResources;
    NativeAppDiagnosticLog_t DiagnosticLog;
    pthread_mutex_t OutputMutex;
    char acConfigPath[NATIVE_APP_PATH_LENGTH];
    char acApplicationConfigPath[NATIVE_APP_PATH_LENGTH];
    char acManagementConfigPath[NATIVE_APP_PATH_LENGTH];
    bool bConfigValid;
    NativeAppPeerState_t ePeerState;
    bool bConnectionLoaded;
    bool bCredentialLoaded;
    bool bIkeEstablished;
    bool bChildInstalled;
    bool bVerbose;
    bool bOutputMutexInitialized;
    bool bExitCleaned;
    bool bExitForced;
    atomic_bool bPromptVisible;
} NativeAppSession_t;

static void PrintNativeAppPromptUnlocked(NativeAppSession_t *pSession)
{
    (void)printf("ipsec> ");
    (void)fflush(stdout);
    atomic_store(&pSession->bPromptVisible, true);
}

static void PrintNativeAppPrompt(NativeAppSession_t *pSession)
{
    const bool bLockOutput = pSession->bOutputMutexInitialized;
    if (bLockOutput) {
        (void)pthread_mutex_lock(&pSession->OutputMutex);
    }
    else {
        /* Startup output does not require serialization. */
    }
    PrintNativeAppPromptUnlocked(pSession);
    if (bLockOutput) {
        (void)pthread_mutex_unlock(&pSession->OutputMutex);
    }
    else {
        /* Startup output does not require serialization. */
    }
}

static void HideNativeAppPrompt(NativeAppSession_t *pSession)
{
    const bool bLockOutput = pSession->bOutputMutexInitialized;
    if (bLockOutput) {
        (void)pthread_mutex_lock(&pSession->OutputMutex);
    }
    else {
        /* Startup output does not require serialization. */
    }
    atomic_store(&pSession->bPromptVisible, false);
    if (bLockOutput) {
        (void)pthread_mutex_unlock(&pSession->OutputMutex);
    }
    else {
        /* Startup output does not require serialization. */
    }
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
    bool bRestorePrompt;

    if (NULL != pSession) {
        WriteNativeAppDiagnosticLog(&pSession->DiagnosticLog, eLevel, pcMessage);
    }
    else {
        /* A logger without session state has no diagnostic file sink. */
    }
    if ((NULL != pSession) && !pSession->bVerbose &&
        (IPSEC_LOG_WARNING < eLevel)) {
        return;
    }
    else {
        if ((NULL != pSession) && pSession->bOutputMutexInitialized) {
            (void)pthread_mutex_lock(&pSession->OutputMutex);
        }
        else {
            /* A logger without session state cannot serialize output. */
        }
        bRestorePrompt = (NULL != pSession) &&
            atomic_load(&pSession->bPromptVisible);
        if (bRestorePrompt) {
            (void)fprintf(stderr, "\n");
        }
        else {
            /* No visible prompt needs restoration. */
        }
        (void)fprintf(stderr, "libipsecctrl[%s]: %s\n",
                      GetNativeAppLogLevel(eLevel), pcMessage);
        if (bRestorePrompt) {
            PrintNativeAppPromptUnlocked(pSession);
        }
        else {
            /* The command loop prints the next prompt. */
        }
        if ((NULL != pSession) && pSession->bOutputMutexInitialized) {
            (void)pthread_mutex_unlock(&pSession->OutputMutex);
        }
        else {
            /* A logger without session state cannot serialize output. */
        }
    }
}

static void PrintNativeAppUsage(const char *pcProgram)
{
    (void)printf(
        "Usage: %s -c FILE [-v] [COMMAND ...]\n"
        "       %s [--config LEGACY_FILE] [-v] [COMMAND ...]\n"
        "       %s --generate-psk FILE\n"
        "\n"
        "  -c FILE   read the role-specific application configuration\n"
        "  -v        enable verbose logging\n"
        "  -h        show this help\n"
        "Long aliases: --app-config FILE, --verbose, --help.\n"
        "Optional legacy override: --management-config LEGACY_FILE (with -c).\n"
        "Place startup options before COMMAND.\n"
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
        "  mode show                    show the selected peer IPsec mode\n"
        "  mode set {transport|tunnel}  update the selected peer IPsec mode\n"
        "  connection load              load the configured connection\n"
        "  connection unload [NAME]     unload a connection\n"
        "  credential load              load the configured PSK\n"
        "  credential unload            unload the selected peer PSK\n"
        "  credential clear all         clear every VICI credential explicitly\n"
        "  ike initiate [NAME]          initiate and wait for an IKE SA\n"
        "  ike terminate [NAME]         terminate an IKE SA\n"
        "  ike rekey [NAME]             rekey an IKE SA\n"
        "  ike wait [NAME]              wait for an established IKE SA\n"
        "  child initiate [NAME]        initiate and wait for a CHILD SA\n"
        "  child terminate [NAME]       terminate a CHILD SA\n"
        "  child rekey [NAME]           rekey a CHILD SA\n"
        "  child wait [NAME]            wait for an installed CHILD SA\n"
        "  peer listen port PORT        listen on all local control addresses\n"
        "  peer listen address IP port PORT\n"
        "                               listen on one control address\n"
        "  peer listen show             show listener state and endpoint\n"
        "  peer listen stop             stop the initiator listener\n"
        "  peer register IP PORT        responder registers with initiator\n"
        "  peer show                    show the in-memory peer table\n"
        "  peer select PEER_ID          select a peer for control commands\n"
        "  show [SCOPE]                 show a compact table (summary default)\n"
        "  show {connections|ike|child} detail [NAME]\n"
        "                               show every field, optionally by name\n"
        "  show SCOPE [NAME]            filter a compact named-object table\n"
        "  up                           convenience load and initiate\n"
        "  down                         convenience terminate and unload\n"
        "  test loop [--count N] [--delay-ms N] [--continue-on-error]\n"
        "      [--unload-credential]\n"
        "                               run explicit lifecycle verification\n"
        "  test algorithm count MODE   show algorithm testcase count\n"
        "  test algorithm check MODE   validate the generated catalog\n"
        "  test algorithm serve [--port N]\n"
        "    APPLICATION/APPLICATION: TCP relay with inner IPv4 /32 payload verification\n"
        "                               serve Native peer test requests\n"
        "  test algorithm run MODE [--start N] [--limit N|--all] [--port N]\n"
        "      [--results FILE] [--delay-ms N] [--stop-on-error|--continue-on-error]\n"
        "      [--continue-on-data-path-error]\n"
        "      APPLICATION packet failures stop unless the data-path override is explicit.\n"
        "      [--ike PROPOSAL --esp PROPOSAL]\n"
        "                               run baseline/exhaustive/custom tests\n"
        "  help                         show this command list\n"
        "  packet protected-receive FILE [--timeout-ms N]\n"
        "                               save one outbound IPv4 RAW ESP packet\n"
        "  packet protected-submit FILE submit one inbound IPv4 RAW ESP packet\n"
        "  packet plain-receive FILE [--timeout-ms N]\n"
        "                               save one decrypted inner IPv4 packet\n"
        "  exit | quit                  clean this session's resources and close\n"
        "  exit --force                 skip cleanup; accept packet-path teardown risk\n"
        "\n"
        "Show scopes:\n"
        "  summary, all, config, credential, daemon, datapath, connections, ike,\n"
        "  child, algorithms, packet-path, traffic,\n"
        "  xfrm, xfrm-state, xfrm-policy, xfrm-stat, network,\n"
        "  interfaces, addresses, routes\n"
        "  NAME filtering is supported for connections, ike, and child.\n"
        "\n"
        "Algorithm modes:\n"
        "  baseline, exhaustive-ike, exhaustive-esp, custom\n"
        "\n"
        "Configuration changes are rejected while this session owns a\n"
        "connection. PSK contents are never displayed.\n"
        "VICI path/timeout and datapath/packet-path settings are startup-only.\n"
        "Packet files are diagnostics, not a continuous forwarder.\n");
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
    return InitializeIpsecWithDatapath(ppContext, &Config, &pAppConfig->Datapath);
}

static IpsecError_t RebuildNativeAppRuntime(NativeAppSession_t *pSession)
{
    char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
    IpsecError_t eError;

    pSession->Config.pOwnedResources = &pSession->OwnedResources;
    pSession->Config.pDiagnosticLog = &pSession->DiagnosticLog;
    if (!AreNativeAppContextSettingsEqual(&pSession->Config, &pSession->ContextConfig)) {
        (void)fprintf(stderr, "context settings differ; restart with the intended application config\n");
        pSession->bConfigValid = false;
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
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
    pSession->Config.pOwnedResources = &pSession->OwnedResources;
    pSession->Config.pDiagnosticLog = &pSession->DiagnosticLog;
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
        "  Local TS         : %s\n"
        "  Remote TS        : %s\n"
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
        pConfig->acRemoteAddress, pConfig->acLocalTrafficSelector,
        pConfig->acRemoteTrafficSelector, pConfig->acLocalId,
        pConfig->acRemoteId,
        pConfig->acPskFile, pConfig->acOutputRoot, pConfig->acViciSocket,
        pConfig->acConnectionName, pConfig->acChildName,
        pConfig->acCredentialId, pConfig->acPeerServerAddress,
        pConfig->uiPeerPort,
        pConfig->acIkeProposals, pConfig->acEspProposals,
        GetNativeAppModeText(pConfig->eMode),
        pConfig->bChildlessIke ? "true" : "false",
        pConfig->bTerminateOnExit ? "true" : "false",
        pConfig->uiTimeoutMs);
    ShowNativeAppDatapathConfig(&pSession->ContextConfig);
}

static void ShowNativeAppCredential(const NativeAppSession_t *pSession)
{
    (void)printf("[CREDENTIAL]\n"
                 "  Session Loaded   : %s\n"
                 "  Daemon ID        : %s\n"
                 "  Secret Displayed : no\n",
                 HasNativeAppCredential(&pSession->Config) ? "yes" : "no",
                 GetNativeAppDaemonCredentialId(&pSession->Config));
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
        pPeer->eState = pSession->ePeerState;
        pPeer->bConnectionLoaded = pSession->bConnectionLoaded;
        pPeer->bCredentialLoaded = pSession->bCredentialLoaded;
        pPeer->bIkeEstablished = pSession->bIkeEstablished;
        pPeer->bChildInstalled = pSession->bChildInstalled;
    }
    else {
        /* No registered peer is currently selected. */
    }
    UnlockNativeAppPeerTable(&pSession->PeerTable);
}

static IpsecError_t SelectNativeAppPeer(
    NativeAppSession_t *pSession,
    const char *pcPeerId,
    NativeAppPeer_t *pSelectedPeer)
{
    NativeAppPeer_t Peer = {0};
    NativeAppConfig_t PreviousConfig;
    NativeAppRuntimeConfig_t PreviousRuntime;
    NativeAppPeerState_t ePreviousState;
    uint32_t uiPreviousIndex;
    bool bPreviousConfigValid;
    bool bPreviousConnectionLoaded;
    bool bPreviousCredentialLoaded;
    bool bPreviousIkeEstablished;
    bool bPreviousChildInstalled;
    IpsecError_t eError;

    if ((NULL == pSession) || (NULL == pcPeerId) ||
        (NULL == pSelectedPeer)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        SaveNativeAppSelectedPeer(pSession);
        PreviousConfig = pSession->Config;
        PreviousRuntime = pSession->Runtime;
        ePreviousState = pSession->ePeerState;
        bPreviousConfigValid = pSession->bConfigValid;
        bPreviousConnectionLoaded = pSession->bConnectionLoaded;
        bPreviousCredentialLoaded = pSession->bCredentialLoaded;
        bPreviousIkeEstablished = pSession->bIkeEstablished;
        bPreviousChildInstalled = pSession->bChildInstalled;
        LockNativeAppPeerTable(&pSession->PeerTable);
        uiPreviousIndex = pSession->PeerTable.uiSelectedIndex;
        UnlockNativeAppPeerTable(&pSession->PeerTable);
        eError = SelectNativeAppPeerRecord(&pSession->PeerTable, pcPeerId,
                                           &Peer);
    }
    if (IPSEC_OK != eError) {
        return eError;
    }
    else {
        pSession->Config = Peer.Config;
        pSession->ePeerState = Peer.eState;
        pSession->bConnectionLoaded = Peer.bConnectionLoaded;
        pSession->bCredentialLoaded = Peer.bCredentialLoaded;
        pSession->bIkeEstablished = Peer.bIkeEstablished;
        pSession->bChildInstalled = Peer.bChildInstalled;
        pSession->bConfigValid = false;
        eError = RebuildNativeAppRuntime(pSession);
    }
    if (IPSEC_OK != eError) {
        pSession->Config = PreviousConfig;
        pSession->Runtime = PreviousRuntime;
        pSession->ePeerState = ePreviousState;
        pSession->bConfigValid = bPreviousConfigValid;
        pSession->bConnectionLoaded = bPreviousConnectionLoaded;
        pSession->bCredentialLoaded = bPreviousCredentialLoaded;
        pSession->bIkeEstablished = bPreviousIkeEstablished;
        pSession->bChildInstalled = bPreviousChildInstalled;
        LockNativeAppPeerTable(&pSession->PeerTable);
        pSession->PeerTable.uiSelectedIndex = uiPreviousIndex;
        UnlockNativeAppPeerTable(&pSession->PeerTable);
    }
    else {
        /* The selected peer and rebuilt runtime are consistent. */
    }
    *pSelectedPeer = Peer;
    return eError;
}

static void UpdateNativeAppSessionState(
    NativeAppSession_t *pSession,
    const NativeAppTargetStatus_t *pStatus)
{
    pSession->bConnectionLoaded = pStatus->bConnectionLoaded;
    pSession->bIkeEstablished = pStatus->bIkeEstablished;
    pSession->bChildInstalled = pStatus->bChildInstalled;
    pSession->ePeerState = GetNativeAppPeerState(
        pSession->bConnectionLoaded, pSession->bCredentialLoaded,
        pSession->bIkeEstablished, pSession->bChildInstalled);
}

static IpsecError_t RefreshNativeAppSelectedState(
    NativeAppSession_t *pSession)
{
    NativeAppTargetStatus_t Status = {0};
    IpsecError_t eError;

    if ((NULL == pSession) || !pSession->bConfigValid ||
        ('\0' == pSession->Config.acConnectionName[0]) ||
        ('\0' == pSession->Config.acChildName[0])) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = GetNativeAppTargetStatus(pSession->pContext,
                                          &pSession->Config, &Status);
    }
    if (IPSEC_OK == eError) {
        UpdateNativeAppSessionState(pSession, &Status);
        SaveNativeAppSelectedPeer(pSession);
    }
    else {
        /* Preserve the last known state when the daemon query fails. */
    }
    return eError;
}

static void UpdateNativeAppSessionPeerState(NativeAppSession_t *pSession)
{
    pSession->ePeerState = GetNativeAppPeerState(
        pSession->bConnectionLoaded, pSession->bCredentialLoaded,
        pSession->bIkeEstablished, pSession->bChildInstalled);
}

static IpsecError_t ValidateNativeAppSessionResources(
    NativeAppSession_t *pSession,
    bool bAllowCredential,
    const char *pcOperation)
{
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pSession) || (NULL == pcOperation)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (pSession->bConfigValid &&
             ('\0' != pSession->Config.acConnectionName[0]) &&
             ('\0' != pSession->Config.acChildName[0])) {
        eError = RefreshNativeAppSelectedState(pSession);
    }
    else {
        /* Use the locally tracked state before the first valid config. */
    }
    if (IPSEC_OK != eError) {
        return eError;
    }
    else if (pSession->bConnectionLoaded || pSession->bIkeEstablished ||
             pSession->bChildInstalled ||
             (!bAllowCredential && pSession->bCredentialLoaded)) {
        (void)fprintf(
            stderr,
            "%s requires clean selected-peer resources "
            "(connection=%s credential=%s ike=%s child=%s)\n",
            pcOperation,
            pSession->bConnectionLoaded ? "loaded" : "absent",
            pSession->bCredentialLoaded ? "loaded" : "absent",
            pSession->bIkeEstablished ? "established" : "absent",
            pSession->bChildInstalled ? "installed" : "absent");
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        return IPSEC_OK;
    }
}

static IpsecError_t RefreshNativeAppPeerStates(NativeAppSession_t *pSession)
{
    IpsecConnectionList_t Connections = {0};
    IpsecIkeSaList_t IkeSas = {0};
    IpsecChildSaList_t ChildSas = {0};
    IpsecError_t eError;
    uint32_t uiIndex;

    eError = GetIpsecConnections(pSession->pContext, &Connections);
    if (IPSEC_OK == eError) {
        eError = GetIpsecIkeSas(pSession->pContext, &IkeSas);
    }
    else {
        /* Preserve the connection query error. */
    }
    if (IPSEC_OK == eError) {
        eError = GetIpsecChildSas(pSession->pContext, &ChildSas);
    }
    else {
        /* Preserve the IKE query error. */
    }
    if (IPSEC_OK == eError) {
        LockNativeAppPeerTable(&pSession->PeerTable);
        for (uiIndex = 0U; uiIndex < pSession->PeerTable.uiCount; uiIndex++) {
            NativeAppPeer_t *pPeer = &pSession->PeerTable.aPeers[uiIndex];
            NativeAppTargetStatus_t Status;

            ResolveNativeAppTargetStatus(&pPeer->Config, &Connections,
                                         &IkeSas, &ChildSas, &Status);
            pPeer->bConnectionLoaded = Status.bConnectionLoaded;
            pPeer->bIkeEstablished = Status.bIkeEstablished;
            pPeer->bChildInstalled = Status.bChildInstalled;
            pPeer->eState = GetNativeAppPeerState(
                pPeer->bConnectionLoaded, pPeer->bCredentialLoaded,
                pPeer->bIkeEstablished, pPeer->bChildInstalled);
            if (uiIndex == pSession->PeerTable.uiSelectedIndex) {
                pSession->bConnectionLoaded = pPeer->bConnectionLoaded;
                pSession->bCredentialLoaded = pPeer->bCredentialLoaded;
                pSession->bIkeEstablished = pPeer->bIkeEstablished;
                pSession->bChildInstalled = pPeer->bChildInstalled;
                pSession->ePeerState = pPeer->eState;
            }
            else {
                /* The peer state is stored without changing the selection. */
            }
        }
        UnlockNativeAppPeerTable(&pSession->PeerTable);
    }
    else {
        /* Preserve the last known peer table state. */
    }
    FreeIpsecChildSaList(&ChildSas);
    FreeIpsecIkeSaList(&IkeSas);
    FreeIpsecConnectionList(&Connections);
    return eError;
}

static void ShowNativeAppPeers(NativeAppSession_t *pSession)
{
    uint32_t uiIndex;
    IpsecError_t eRefreshError = RefreshNativeAppPeerStates(pSession);

    if (IPSEC_OK != eRefreshError) {
        (void)fprintf(stderr, "peer state refresh failed: %s\n",
                      GetIpsecErrorString(eRefreshError));
    }
    else {
        /* Display daemon-synchronized peer state. */
    }

    LockNativeAppPeerTable(&pSession->PeerTable);
    (void)printf(
        "[PEERS]\n"
        "  Count: %" PRIu32 "\n"
        "\n"
        "  Sel  Peer ID                    Group  Logon  Registrations"
        "  State              Remote Address                           Connection\n"
        "  ---  -------------------------  -----  -----  -------------"
        "  -----------------  ---------------------------------------"
        "  -------------------------------\n",
        pSession->PeerTable.uiCount);
    for (uiIndex = 0U; uiIndex < pSession->PeerTable.uiCount; uiIndex++) {
        const NativeAppPeer_t *pPeer =
            &pSession->PeerTable.aPeers[uiIndex];

        (void)printf(
            "  %-3s  %-25.25s  %-5" PRIu32 "  %-5" PRIu32
            "  %-13" PRIu32 "  %-17.17s  %-39.39s  %-31.31s\n",
            (uiIndex == pSession->PeerTable.uiSelectedIndex) ? "*" : "",
            GetNativeAppPeerId(pPeer), pPeer->uiGroupId, pPeer->uiLogonId,
            pPeer->uiRegistrationCount,
            GetNativeAppPeerStateName(pPeer->eState),
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
    bool bRestorePrompt;

    if ((NULL != pSession) && pSession->bOutputMutexInitialized) {
        (void)pthread_mutex_lock(&pSession->OutputMutex);
    }
    else {
        /* A listener without session state cannot serialize output. */
    }
    bRestorePrompt = (NULL != pSession) &&
        atomic_load(&pSession->bPromptVisible);
    if (bRestorePrompt) {
        (void)printf("\n");
    }
    else {
        /* No visible prompt needs restoration. */
    }
    if ((IPSEC_OK == eError) && (NULL != pPeer)) {
        (void)printf(
            "peer %s: %s group_id=%" PRIu32
            " logon_id=%" PRIu32 " registrations=%" PRIu32
            " remote=%s\n",
            (1U < pPeer->uiRegistrationCount) ? "re-registered" :
                "registered",
            GetNativeAppPeerId(pPeer), pPeer->uiGroupId,
            pPeer->uiLogonId, pPeer->uiRegistrationCount,
            pPeer->Config.acRemoteAddress);
    }
    else {
        (void)fprintf(stderr, "peer listener error: %s (%s)\n",
                      ((NULL != pcError) && ('\0' != pcError[0])) ?
                          pcError : GetIpsecErrorString(eError),
                      GetIpsecErrorString(eError));
    }
    if (bRestorePrompt) {
        PrintNativeAppPromptUnlocked(pSession);
    }
    else {
        /* The command loop prints the next prompt. */
    }
    if ((NULL != pSession) && pSession->bOutputMutexInitialized) {
        (void)pthread_mutex_unlock(&pSession->OutputMutex);
    }
    else {
        /* A listener without session state cannot serialize output. */
    }
}

static IpsecError_t ExecuteNativeAppPeerCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments)
{
    NativeAppPeer_t Peer;
    NativeAppConfig_t PeerConfig;
    const char *pcPeerId = NULL;
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
        pcPeerId = ppcArguments[2];
        eError = SelectNativeAppPeer(pSession, pcPeerId, &Peer);
    }
    else if ((4U == uiArgumentCount) &&
             (0 == strcmp("listen", ppcArguments[1])) &&
             (0 == strcmp("port", ppcArguments[2]))) {
        uint32_t uiPort;

        if ((NATIVE_APP_ROLE_INITIATOR != pSession->BaseConfig.eRole) ||
            IsNativeAppPeerListenerRunning(&pSession->PeerListener)) {
            return IPSEC_ERR_RESOURCE_CONFLICT;
        }
        if (!ParseNativeAppNumber(ppcArguments[3], &uiPort) ||
            (0U == uiPort) || (uiPort > UINT16_MAX)) {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
        PeerConfig = pSession->BaseConfig;
        PeerConfig.acPeerServerAddress[0] = '\0';
        PeerConfig.uiPeerPort = uiPort;
        eError = StartNativeAppPeerListener(
            &pSession->PeerListener, &PeerConfig, &pSession->PeerTable,
            HandleNativeAppPeerListenerEvent, pSession, acError,
            sizeof(acError));
        if (IPSEC_OK == eError) {
            const char *pcAnyAddress =
                (NULL != strchr(PeerConfig.acLocalAddress, ':')) ?
                    "::" : "0.0.0.0";

            (void)printf("peer listener started: %s:%" PRIu32 "\n",
                         pcAnyAddress, uiPort);
        }
        else {
            /* Report the listener error below. */
        }
        return eError;
    }
    else if ((6U == uiArgumentCount) &&
             (0 == strcmp("listen", ppcArguments[1])) &&
             (0 == strcmp("address", ppcArguments[2])) &&
             (0 == strcmp("port", ppcArguments[4]))) {
        uint32_t uiPort;

        if ((NATIVE_APP_ROLE_INITIATOR != pSession->BaseConfig.eRole) ||
            IsNativeAppPeerListenerRunning(&pSession->PeerListener)) {
            return IPSEC_ERR_RESOURCE_CONFLICT;
        }
        if (!ParseNativeAppNumber(ppcArguments[5], &uiPort) ||
            (0U == uiPort) || (uiPort > UINT16_MAX)) {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
        PeerConfig = pSession->BaseConfig;
        if (!CopyNativeAppSessionText(
                PeerConfig.acPeerServerAddress,
                sizeof(PeerConfig.acPeerServerAddress), ppcArguments[3])) {
            return IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        PeerConfig.uiPeerPort = uiPort;
        eError = StartNativeAppPeerListener(
            &pSession->PeerListener, &PeerConfig, &pSession->PeerTable,
            HandleNativeAppPeerListenerEvent, pSession, acError,
            sizeof(acError));
        if (IPSEC_OK == eError) {
            (void)printf("peer listener started: %s:%" PRIu32 "\n",
                         PeerConfig.acPeerServerAddress, uiPort);
        }
        else {
            /* Report the listener error below. */
        }
        return eError;
    }
    else if ((3U == uiArgumentCount) &&
             (0 == strcmp("listen", ppcArguments[1])) &&
             (0 == strcmp("show", ppcArguments[2]))) {
        const NativeAppPeerListener_t *pListener = &pSession->PeerListener;
        const char *pcAddress = pListener->Config.acPeerServerAddress;

        if ('\0' == pcAddress[0]) {
            pcAddress = (NULL != strchr(
                pListener->Config.acLocalAddress, ':')) ? "::" :
                "0.0.0.0";
        }
        (void)printf("peer listener: %s address=%s port=%" PRIu32 "\n",
                     IsNativeAppPeerListenerRunning(pListener) ?
                         "running" : "stopped",
                     pcAddress, pListener->Config.uiPeerPort);
        return IPSEC_OK;
    }
    else if ((3U == uiArgumentCount) &&
             (0 == strcmp("listen", ppcArguments[1])) &&
             (0 == strcmp("stop", ppcArguments[2]))) {
        if (NATIVE_APP_ROLE_INITIATOR != pSession->BaseConfig.eRole) {
            return IPSEC_ERR_NOT_SUPPORTED;
        }
        StopNativeAppPeerListener(&pSession->PeerListener);
        (void)puts("peer listener stopped");
        return IPSEC_OK;
    }
    else if (((4U == uiArgumentCount) ||
              (2U == uiArgumentCount)) &&
             (0 == strcmp("register", ppcArguments[1]))) {
        if (NATIVE_APP_ROLE_RESPONDER != pSession->BaseConfig.eRole) {
            return IPSEC_ERR_NOT_SUPPORTED;
        }
        else {
            PeerConfig = pSession->BaseConfig;
            if (4U == uiArgumentCount) {
                if (!CopyNativeAppSessionText(
                        PeerConfig.acPeerServerAddress,
                        sizeof(PeerConfig.acPeerServerAddress),
                        ppcArguments[2]) ||
                    !ParseNativeAppNumber(ppcArguments[3],
                                          &PeerConfig.uiPeerPort) ||
                    (0U == PeerConfig.uiPeerPort) ||
                    (PeerConfig.uiPeerPort > UINT16_MAX)) {
                    return IPSEC_ERR_INVALID_ARGUMENT;
                }
            }
            else if ('\0' == PeerConfig.acPeerServerAddress[0]) {
                return IPSEC_ERR_INVALID_ARGUMENT;
            }
            else {
                /* Retain the legacy static control endpoint. */
            }
            (void)printf("registering with initiator %s:%" PRIu32 "...\n",
                         PeerConfig.acPeerServerAddress,
                         PeerConfig.uiPeerPort);
            eError = RegisterNativeAppPeer(
                &PeerConfig, &pSession->PeerTable, &Peer,
                acError, sizeof(acError));
        }
        if (IPSEC_OK == eError) {
            pcPeerId = GetNativeAppPeerId(&Peer);
            eError = SelectNativeAppPeer(pSession, pcPeerId, &Peer);
        }
    }
    else {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (IPSEC_OK == eError) {
        (void)printf(
            "peer selected: %s group_id=%" PRIu32
            " logon_id=%" PRIu32 "\n",
            GetNativeAppPeerId(&Peer), Peer.uiGroupId,
            Peer.uiLogonId);
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
    char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
    IpsecError_t eError;

    eError = ValidateNativeAppSessionResources(
        pSession, false, "configuration load");
    if (IPSEC_OK == eError) {
        eError = LoadNativeAppConfig(pcPath, &Config, acError,
                                     sizeof(acError));
    }
    else {
        return eError;
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
    if (!AreNativeAppContextSettingsEqual(&Config, &pSession->ContextConfig)) {
        (void)fprintf(stderr, "context settings are startup-only; restart with this configuration\n");
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    if ((IPSEC_OK == eError) &&
        !CopyNativeAppSessionText(pSession->acConfigPath,
                                  sizeof(pSession->acConfigPath), pcPath)) {
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else if (IPSEC_OK == eError) {
        Config.pOwnedResources = &pSession->OwnedResources;
        Config.pDiagnosticLog = &pSession->DiagnosticLog;
        pSession->Config = Config;
        pSession->BaseConfig = Config;
        pSession->acApplicationConfigPath[0] = '\0';
        pSession->acManagementConfigPath[0] = '\0';
        pSession->bCredentialLoaded = false;
        UpdateNativeAppSessionPeerState(pSession);
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

static bool DoesNativeAppSettingReplaceCredential(
    const NativeAppSession_t *pSession,
    const char *pcKey)
{
    return (0 == strcmp("role", pcKey)) ||
        (0 == strcmp("local_id", pcKey)) ||
        (0 == strcmp("remote_id", pcKey)) ||
        (0 == strcmp("psk_file", pcKey)) ||
        (0 == strcmp("credential_id", pcKey)) ||
        (0 == strcmp("vici_uri", pcKey)) ||
        ((0 == strcmp("connection_name", pcKey)) &&
         ('\0' == pSession->Config.acCredentialId[0]));
}

static IpsecError_t SetNativeAppSessionConfig(
    NativeAppSession_t *pSession,
    const char *pcKey,
    const char *pcValue)
{
    NativeAppConfig_t Config = pSession->Config;
    IpsecError_t eError;
    bool bReplaceCredential;

    bReplaceCredential = DoesNativeAppSettingReplaceCredential(
        pSession, pcKey);
    eError = ValidateNativeAppSessionResources(
        pSession, !bReplaceCredential, "configuration update");
    if (IPSEC_OK != eError) {
        return eError;
    }
    else {
        eError = SetNativeAppConfigSetting(&Config, pcKey, pcValue);
    }
    if (IPSEC_OK == eError) {
        if (!AreNativeAppContextSettingsEqual(&Config, &pSession->ContextConfig)) {
            (void)fprintf(stderr, "context settings are startup-only; restart after stopping traffic and SAs\n");
            eError = IPSEC_ERR_RESOURCE_CONFLICT;
        }
        else {
            eError = ValidateNativeAppDatapathConfig(&Config);
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
        UpdateNativeAppSessionPeerState(pSession);
        pSession->bConfigValid = false;
        (void)RebuildNativeAppRuntime(pSession);
        (void)printf("configuration updated: %s\n", pcKey);
    }
    else {
        /* The caller reports the structured error. */
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppModeCommand(
    NativeAppSession_t *pSession,
    uint32_t uiArgumentCount,
    char **ppcArguments)
{
    IpsecError_t eError;

    if ((2U == uiArgumentCount) &&
        (0 == strcmp("show", ppcArguments[1]))) {
        (void)printf("IPsec mode: %s\n",
                     GetNativeAppModeText(pSession->Config.eMode));
        eError = IPSEC_OK;
    }
    else if ((3U == uiArgumentCount) &&
             (0 == strcmp("set", ppcArguments[1])) &&
             ((0 == strcmp("transport", ppcArguments[2])) ||
              (0 == strcmp("tunnel", ppcArguments[2])))) {
        eError = SetNativeAppSessionConfig(pSession, "ipsec_mode",
                                           ppcArguments[2]);
    }
    else {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
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
            eError = AddNativeAppConnection(pSession->pContext, &pSession->Config,
                                        &pSession->Runtime.Connection);
        }
        if (IPSEC_OK == eError) {
            pSession->bConnectionLoaded = true;
            pSession->ePeerState = GetNativeAppPeerState(
                pSession->bConnectionLoaded, pSession->bCredentialLoaded,
                pSession->bIkeEstablished, pSession->bChildInstalled);
            (void)printf("connection loaded: %s\n",
                         pSession->Config.acConnectionName);
        }
    }
    else if (((2U == uiArgumentCount) || (3U == uiArgumentCount)) &&
             (0 == strcmp("unload", ppcArguments[1]))) {
        const char *pcName;
        bool bSelectedConnection = false;
        bool bActive = false;

        if (3U == uiArgumentCount) {
            pcName = ppcArguments[2];
            eError = IPSEC_OK;
        }
        else {
            eError = RequireNativeAppConfig(pSession);
            pcName = pSession->Config.acConnectionName;
        }
        if ((IPSEC_OK == eError) &&
            (0 == strcmp(pcName, pSession->Config.acConnectionName))) {
            bSelectedConnection = true;
            eError = RefreshNativeAppSelectedState(pSession);
        }
        else {
            /* An explicitly named, non-selected connection is independent. */
        }
        if (IPSEC_OK == eError) {
            eError = GetNativeAppConnectionSaStatus(
                pSession->pContext, pcName, &bActive);
        }
        else {
            /* Preserve the selected-peer state query error. */
        }
        if ((IPSEC_OK == eError) && bActive) {
            (void)fprintf(
                stderr,
                "connection '%s' has an active SA; terminate it before "
                "unloading the connection\n", pcName);
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            /* It is safe to unload a connection with no active SA. */
        }
        if (IPSEC_OK == eError) {
            eError = RemoveIpsecConnection(pSession->pContext, pcName);
        }
        if (IPSEC_OK == eError) {
            if (bSelectedConnection) {
                pSession->bConnectionLoaded = false;
                if (IPSEC_OK != RefreshNativeAppSelectedState(pSession)) {
                    pSession->ePeerState = GetNativeAppPeerState(
                        pSession->bConnectionLoaded,
                        pSession->bCredentialLoaded,
                        pSession->bIkeEstablished,
                        pSession->bChildInstalled);
                }
                else {
                    /* The remaining IKE and CHILD state is synchronized. */
                }
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
            pSession->ePeerState = GetNativeAppPeerState(
                pSession->bConnectionLoaded, pSession->bCredentialLoaded,
                pSession->bIkeEstablished, pSession->bChildInstalled);
            (void)printf("credential loaded for connection: %s\n",
                         pSession->Config.acConnectionName);
        }
    }
    else if ((2U == uiArgumentCount) &&
             (0 == strcmp("unload", ppcArguments[1]))) {
        eError = RequireNativeAppConfig(pSession);
        if (IPSEC_OK == eError) {
            eError = RefreshNativeAppSelectedState(pSession);
        }
        else {
            /* Preserve the configuration error. */
        }
        if ((IPSEC_OK == eError) &&
            (pSession->bIkeEstablished || pSession->bChildInstalled)) {
            (void)fprintf(stderr,
                          "terminate the selected peer before unloading "
                          "its credential\n");
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            /* A credential may be unloaded when no SA depends on it. */
        }
        if ((IPSEC_OK == eError) && !pSession->bCredentialLoaded) {
            (void)printf("credential already unloaded: %s\n",
                         pSession->Config.acCredentialId);
            return IPSEC_OK;
        }
        else if (IPSEC_OK == eError) {
            eError = RemoveNativeAppCredential(pSession->pContext, &pSession->Config);
        }
        else {
            /* Preserve the state validation error. */
        }
        if (IPSEC_OK == eError) {
            pSession->bCredentialLoaded = false;
            pSession->ePeerState = GetNativeAppPeerState(
                pSession->bConnectionLoaded, pSession->bCredentialLoaded,
                pSession->bIkeEstablished, pSession->bChildInstalled);
            (void)printf("credential unloaded: %s\n",
                         pSession->Config.acCredentialId);
        }
    }
    else if ((3U == uiArgumentCount) &&
             (0 == strcmp("clear", ppcArguments[1])) &&
             (0 == strcmp("all", ppcArguments[2]))) {
        bool bActive = false;

        eError = GetNativeAppAnySaStatus(pSession->pContext, &bActive);
        if ((IPSEC_OK == eError) && bActive) {
            (void)fprintf(
                stderr,
                "active IKE or CHILD SAs exist; terminate all peers before "
                "clearing every credential\n");
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else if (IPSEC_OK == eError) {
            eError = ClearIpsecCredentials(pSession->pContext);
        }
        else {
            /* Preserve the SA status query error. */
        }
        if (IPSEC_OK == eError) {
            uint32_t uiIndex;

            pSession->bCredentialLoaded = false;
            for (uiIndex = 0U; uiIndex < pSession->OwnedResources.uiCount; uiIndex++) {
                pSession->OwnedResources.aItems[uiIndex].bCredentialOwned = false;
            }
            LockNativeAppPeerTable(&pSession->PeerTable);
            for (uiIndex = 0U;
                 uiIndex < pSession->PeerTable.uiCount;
                 uiIndex++) {
                pSession->PeerTable.aPeers[
                    uiIndex].bCredentialLoaded = false;
                pSession->PeerTable.aPeers[uiIndex].eState =
                    GetNativeAppPeerState(
                        pSession->PeerTable.aPeers[
                            uiIndex].bConnectionLoaded,
                        false,
                        pSession->PeerTable.aPeers[
                            uiIndex].bIkeEstablished,
                        pSession->PeerTable.aPeers[
                            uiIndex].bChildInstalled);
            }
            UnlockNativeAppPeerTable(&pSession->PeerTable);
            pSession->ePeerState = GetNativeAppPeerState(
                pSession->bConnectionLoaded, pSession->bCredentialLoaded,
                pSession->bIkeEstablished, pSession->bChildInstalled);
            (void)printf("all VICI credentials cleared explicitly\n");
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
        if (!HasNativeAppOwnedSaTarget(&pSession->OwnedResources, pcName, false)) {
            (void)fprintf(stderr, "load the connection in this session before initiating IKE\n");
            return IPSEC_ERR_RESOURCE_CONFLICT;
        }
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
        IpsecError_t eRefreshError = RefreshNativeAppSelectedState(pSession);

        if (IPSEC_OK != eRefreshError) {
            (void)fprintf(stderr, "IKE state refresh failed: %s\n",
                          GetIpsecErrorString(eRefreshError));
        }
        else {
            /* The command result is reflected in the selected peer state. */
        }
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
        if (!HasNativeAppOwnedSaTarget(&pSession->OwnedResources, pcName, true)) {
            (void)fprintf(stderr, "load the parent connection in this session before initiating CHILD\n");
            return IPSEC_ERR_RESOURCE_CONFLICT;
        }
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
        IpsecError_t eRefreshError = RefreshNativeAppSelectedState(pSession);

        if (IPSEC_OK != eRefreshError) {
            (void)fprintf(stderr, "CHILD state refresh failed: %s\n",
                          GetIpsecErrorString(eRefreshError));
        }
        else {
            /* The command result is reflected in the selected peer state. */
        }
        (void)printf("child %s completed: %s\n", ppcArguments[1], pcName);
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppUp(NativeAppSession_t *pSession)
{
    bool bConnectionAdded = false;
    NativeAppTargetStatus_t Status;
    IpsecError_t eError;

    eError = RequireNativeAppConfig(pSession);
    if (IPSEC_OK == eError) {
        eError = GetNativeAppTargetStatus(pSession->pContext,
                                          &pSession->Config, &Status);
    }
    else {
        /* Preserve the configuration error. */
    }
    if (IPSEC_OK == eError) {
        UpdateNativeAppSessionState(pSession, &Status);
    }
    else {
        /* Preserve the daemon state query error. */
    }
    if ((IPSEC_OK == eError) && (!pSession->bConnectionLoaded ||
        !HasNativeAppOwnedSaTarget(&pSession->OwnedResources, pSession->Config.acConnectionName, false))) {
        eError = AddNativeAppConnection(pSession->pContext, &pSession->Config,
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
    if ((IPSEC_OK == eError) && !pSession->bChildInstalled) {
        eError = StartNativeAppConnection(pSession->pContext,
                                          &pSession->Config,
                                          &pSession->Runtime);
    }
    else {
        /* An already installed CHILD makes up idempotent. */
    }
    if ((IPSEC_OK != eError) && bConnectionAdded) {
        NativeAppTargetStatus_t FailureStatus = {0};
        IpsecError_t eStatusError = GetNativeAppTargetStatus(
            pSession->pContext, &pSession->Config, &FailureStatus);

        if ((IPSEC_OK == eStatusError) &&
            !FailureStatus.bIkePresent &&
            !FailureStatus.bChildPresent) {
            if (IPSEC_OK == RemoveIpsecConnection(
                    pSession->pContext,
                    pSession->Config.acConnectionName)) {
                pSession->bConnectionLoaded = false;
            }
            else {
                /* Leave ownership set because removal did not complete. */
            }
        }
        else {
            UpdateNativeAppSessionState(pSession, &FailureStatus);
            pSession->bConnectionLoaded = true;
            (void)fprintf(
                stderr,
                "up failed with remaining SA state; connection retained "
                "for 'down' recovery\n");
        }
    }
    if (IPSEC_OK == eError) {
        (void)RefreshNativeAppSelectedState(pSession);
        (void)printf("up completed: %s/%s\n",
                     pSession->Config.acConnectionName,
                     pSession->Config.acChildName);
    }
    return eError;
}

static IpsecError_t ExecuteNativeAppDown(NativeAppSession_t *pSession)
{
    NativeAppTargetStatus_t Status = {0};
    IpsecError_t eFirstError;
    IpsecError_t eError;

    eFirstError = RequireNativeAppConfig(pSession);
    if (IPSEC_OK == eFirstError) {
        eFirstError = GetNativeAppTargetStatus(pSession->pContext,
                                               &pSession->Config, &Status);
    }
    else {
        /* Preserve the configuration error. */
    }
    if (IPSEC_OK == eFirstError) {
        UpdateNativeAppSessionState(pSession, &Status);
        eFirstError = TerminateNativeAppTargetSas(pSession->pContext, &pSession->Config);
    }
    else {
        /* Preserve the daemon state query error. */
    }
    if ((IPSEC_OK == eFirstError) && Status.bConnectionLoaded) {
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
    else if (Status.bConnectionLoaded) {
        /* Keep the definition loaded when SA termination did not complete. */
    }
    else {
        /* No selected connection definition needs unloading. */
    }
    if (IPSEC_OK == eFirstError) {
        pSession->bIkeEstablished = false;
        pSession->bChildInstalled = false;
        pSession->ePeerState = GetNativeAppPeerState(
            pSession->bConnectionLoaded, pSession->bCredentialLoaded,
            pSession->bIkeEstablished, pSession->bChildInstalled);
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
        else if ((0 == strcmp("--unload-credential",
                              ppcArguments[uiIndex])) ||
                 (0 == strcmp("--clear-credentials",
                              ppcArguments[uiIndex]))) {
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
    NativeAppTargetStatus_t Status;
    IpsecError_t eError;

    eError = RequireNativeAppConfig(pSession);
    if (IPSEC_OK == eError) {
        eError = GetNativeAppTargetStatus(pSession->pContext,
                                          &pSession->Config, &Status);
    }
    else {
        /* Preserve the configuration error. */
    }
    if (IPSEC_OK == eError) {
        UpdateNativeAppSessionState(pSession, &Status);
        if (Status.bConnectionLoaded || Status.bIkeEstablished ||
            Status.bChildInstalled) {
            (void)fprintf(
                stderr,
                "loop requires a clean selected peer; run 'down' first "
                "(connection=%s ike=%s child=%s)\n",
                Status.bConnectionLoaded ? "loaded" : "absent",
                Status.bIkeEstablished ? "established" : "absent",
                Status.bChildInstalled ? "installed" : "absent");
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            /* The loop owns every resource it creates. */
        }
    }
    else {
        /* Preserve the daemon state query error. */
    }
    if (IPSEC_OK == eError) {
        eError = ParseNativeAppLoopOptions(uiArgumentCount, ppcArguments,
                                           uiStartIndex, &Options);
    }
    if (IPSEC_OK == eError) {
        bool bCredentialLoaded = pSession->bCredentialLoaded;

        ResetNativeAppStopRequest();
        eError = RunNativeAppLoop(pSession->pContext, &pSession->Config,
                                  &pSession->Runtime, &Options,
                                  &bCredentialLoaded);
        ResetNativeAppStopRequest();
        pSession->bCredentialLoaded = bCredentialLoaded;
        {
            IpsecError_t eRefreshError =
                RefreshNativeAppSelectedState(pSession);

            if ((IPSEC_OK == eError) && (IPSEC_OK != eRefreshError)) {
                eError = eRefreshError;
            }
            else if (IPSEC_OK != eRefreshError) {
                (void)fprintf(stderr, "loop state refresh failed: %s\n",
                              GetIpsecErrorString(eRefreshError));
            }
            else {
                /* Daemon state is authoritative after the loop. */
            }
        }
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
        else if (0 == strcmp("--continue-on-data-path-error",
                             ppcArguments[uiIndex])) {
            pOptions->bContinueOnError = true;
            pOptions->bContinueOnDataPathError = true;
            uiIndex++;
        }
        else if (0 == strcmp("--stop-on-error",
                             ppcArguments[uiIndex])) {
            pOptions->bContinueOnError = false;
            pOptions->bContinueOnDataPathError = false;
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
        char acExpectedIke[IPSEC_PROPOSAL_LENGTH] = {0};
        char acExpectedEsp[IPSEC_PROPOSAL_LENGTH] = {0};
        IpsecError_t eError = GetNativeAppAlgorithmCase(
            eMode, uiIndex, pConfig,
            (NATIVE_APP_ALGORITHM_CUSTOM == eMode) ?
            pConfig->acIkeProposals : NULL,
            (NATIVE_APP_ALGORITHM_CUSTOM == eMode) ?
            pConfig->acEspProposals : NULL, &Case);

        if (IPSEC_OK == eError) {
            eError = BuildNativeAppExpectedProposals(
                &Case, acExpectedIke, sizeof(acExpectedIke),
                acExpectedEsp, sizeof(acExpectedEsp));
        }
        else {
            /* Preserve the testcase generation error. */
        }
        if (IPSEC_OK != eError) {
            return eError;
        }
        else if (('\0' == acExpectedIke[0]) ||
                 ('\0' == acExpectedEsp[0])) {
            return IPSEC_ERR_INTERNAL;
        }
        else {
            /* Continue through the complete exact-validation catalog. */
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

    if ((pSession->ContextConfig.Datapath.eProtectedPacketPath !=
         pSession->ContextConfig.Datapath.ePlainPacketPath) &&
        (uiArgumentCount >= 3U) &&
        ((0 == strcmp("run", ppcArguments[2])) ||
         (0 == strcmp("serve", ppcArguments[2])))) {
        (void)fprintf(stderr, "algorithm traffic tests require SYSTEM/SYSTEM or "
                      "APPLICATION/APPLICATION; mixed paths are not supported.\n");
        return IPSEC_ERR_NOT_SUPPORTED;
    }
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
        if (IPSEC_OK == eError) {
            eError = ValidateNativeAppSessionResources(
                pSession, true, "algorithm server");
        }
        if (IPSEC_OK == eError) {
            eError = RequireNativeAppConfig(pSession);
        }
        if (IPSEC_OK == eError) {
            ResetNativeAppStopRequest();
            eError = RunNativeAppAlgorithmServer(
                pSession->pContext, &pSession->Config, uiPort);
            ResetNativeAppStopRequest();
            pSession->bCredentialLoaded = HasNativeAppCredential(&pSession->Config);
            UpdateNativeAppSessionPeerState(pSession);
        }
    }
    else if ((4U <= uiArgumentCount) &&
             (0 == strcmp("run", ppcArguments[2]))) {
        NativeAppAlgorithmOptions_t Options;

        eError = ValidateNativeAppSessionResources(
            pSession, true, "algorithm test");
        if (IPSEC_OK == eError) {
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
            pSession->bCredentialLoaded = HasNativeAppCredential(&pSession->Config);
            UpdateNativeAppSessionPeerState(pSession);
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

    eError = ValidateNativeAppSessionResources(
        pSession, false, "legacy load");
    if (IPSEC_OK == eError) {
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
        UpdateNativeAppSessionPeerState(pSession);
        (void)printf("connection and credential loaded\n");
    }
    return eError;
}

static IpsecError_t ValidateNativeAppApplicationExit(NativeAppSession_t *pSession)
{
    if (IPSEC_PACKET_PATH_APPLICATION != pSession->ContextConfig.Datapath.eProtectedPacketPath) {
        return IPSEC_OK;
    }
    return VerifyNativeAppExitSas(pSession->pContext);
}

static IpsecError_t CloseNativeAppSession(NativeAppSession_t *pSession, bool bForce)
{
    IpsecError_t eError = IPSEC_OK;
    uint32_t uiIndex;
    bool bApplication =
        (IPSEC_PACKET_PATH_APPLICATION == pSession->ContextConfig.Datapath.eProtectedPacketPath) ||
        (IPSEC_PACKET_PATH_APPLICATION == pSession->ContextConfig.Datapath.ePlainPacketPath);
    StopNativeAppPeerListener(&pSession->PeerListener);
    ResetNativeAppStopRequest();
    ResetNativeAppExitRequest();
    if (bForce) {
        pSession->bExitForced = true;
        (void)fprintf(stderr, "FORCED EXIT: daemon resources may remain; owned packet "
            "paths will be removed and ordinary NIC egress restored. Stop external traffic.\n");
        return IPSEC_OK;
    }
    if (pSession->Config.bTerminateOnExit || bApplication) {
        SaveNativeAppSelectedPeer(pSession);
        (void)printf("shutdown: peer listener stopped; cleaning all resources owned by this session\n");
        eError = CleanupNativeAppOwnedResources(pSession->pContext, &pSession->OwnedResources);
        LockNativeAppPeerTable(&pSession->PeerTable);
        for (uiIndex = 0U; uiIndex < pSession->PeerTable.uiCount; uiIndex++) {
            NativeAppPeer_t *pPeer = &pSession->PeerTable.aPeers[uiIndex];
            pPeer->bCredentialLoaded = HasNativeAppCredential(&pPeer->Config);
        }
        UnlockNativeAppPeerTable(&pSession->PeerTable);
        pSession->bCredentialLoaded = HasNativeAppCredential(&pSession->Config);
        (void)RefreshNativeAppPeerStates(pSession);
        if (IPSEC_OK == eError) {
            eError = ValidateNativeAppApplicationExit(pSession);
        }
        pSession->bExitCleaned = (IPSEC_OK == eError);
    }
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "shutdown incomplete: %s; session and remaining packet paths retained. "
            "New loads/tests are disabled. Inspect show/peer show, then retry quit.\n",
            GetIpsecErrorString(eError));
    }
    else if (!pSession->bExitCleaned) {
        (void)printf("SYSTEM detach: terminate_on_exit=false; daemon resources retained by request\n");
    }
    return eError;
}

static bool IsNativeAppShutdownCommand(uint32_t uiCount, char **ppcArguments)
{
    const char *pcCommand = ppcArguments[0];
    if ((0 == strcmp(pcCommand, "quit")) || (0 == strcmp(pcCommand, "exit")) ||
        (0 == strcmp(pcCommand, "show")) || (0 == strcmp(pcCommand, "status")) ||
        (0 == strcmp(pcCommand, "help")) || (0 == strcmp(pcCommand, "?")) ||
        (0 == strcmp(pcCommand, "check")) || (0 == strcmp(pcCommand, "down")) ||
        (0 == strcmp(pcCommand, "unload"))) {
        return true;
    }
    if (uiCount < 2U) {
        return false;
    }
    if ((0 == strcmp(pcCommand, "ike")) || (0 == strcmp(pcCommand, "child"))) {
        return 0 == strcmp(ppcArguments[1], "terminate");
    }
    if ((0 == strcmp(pcCommand, "connection")) || (0 == strcmp(pcCommand, "credential"))) {
        return (0 == strcmp(ppcArguments[1], "show")) || (0 == strcmp(ppcArguments[1], "unload"));
    }
    if (0 == strcmp(pcCommand, "config")) {
        return 0 == strcmp(ppcArguments[1], "show");
    }
    if (0 == strcmp(pcCommand, "peer")) {
        return (0 == strcmp(ppcArguments[1], "show")) || (0 == strcmp(ppcArguments[1], "select")) ||
            ((3U == uiCount) && (0 == strcmp(ppcArguments[1], "listen")) &&
             ((0 == strcmp(ppcArguments[2], "show")) || (0 == strcmp(ppcArguments[2], "stop"))));
    }
    return false;
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
    else if (pSession->OwnedResources.bClosing &&
             !IsNativeAppShutdownCommand(uiArgumentCount, ppcArguments)) {
        (void)fprintf(stderr, "shutdown recovery: only inspection, selection, termination, unload and exit are allowed\n");
        eError = IPSEC_ERR_RESOURCE_CONFLICT;
    }
    else if (0 == strcmp("config", ppcArguments[0])) {
        eError = ExecuteNativeAppConfigCommand(pSession, uiArgumentCount,
                                               ppcArguments);
    }
    else if (0 == strcmp("mode", ppcArguments[0])) {
        eError = ExecuteNativeAppModeCommand(pSession, uiArgumentCount,
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
    else if (0 == strcmp("packet", ppcArguments[0])) {
        NativeAppPacketOptions_t Options;
        if (!ParseNativeAppPacketOptions(uiArgumentCount, ppcArguments, &Options)) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            ResetNativeAppStopRequest();
            eError = TransferNativeAppPacketFile(pSession->pContext, &Options);
            ResetNativeAppStopRequest();
        }
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
        char *pacClear[] = {"credential", "unload"};

        eError = ExecuteNativeAppCredentialCommand(pSession, 2U, pacClear);
    }
    else if ((1U == uiArgumentCount) &&
             ((0 == strcmp("help", ppcArguments[0])) ||
              (0 == strcmp("?", ppcArguments[0])))) {
        PrintNativeAppHelp();
        eError = IPSEC_OK;
    }
    else if (((1U == uiArgumentCount) ||
              ((2U == uiArgumentCount) && (0 == strcmp("--force", ppcArguments[1])))) &&
             ((0 == strcmp("exit", ppcArguments[0])) ||
              (0 == strcmp("quit", ppcArguments[0])))) {
        eError = CloseNativeAppSession(pSession, 2U == uiArgumentCount);
        *pbExit = (IPSEC_OK == eError);
    }
    else {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    SaveNativeAppSelectedPeer(pSession);
    return eError;
}

static IpsecError_t ReadNativeAppInput(char *pcLine, size_t zCapacity, bool *pbEof)
{
    size_t zLength = 0U;
    bool bOverflow = false;
    *pbEof = false;
    while (!IsNativeAppStopRequested() && !IsNativeAppExitRequested()) {
        struct pollfd Input = {.fd = STDIN_FILENO, .events = POLLIN};
        char cValue;
        int32_t iReady = poll(&Input, 1U, 250);
        ssize_t lRead;
        if ((iReady < 0) && (EINTR == errno)) {
            continue;
        }
        if ((iReady < 0) || (0 != (Input.revents & (POLLERR | POLLNVAL)))) {
            return IPSEC_ERR_FILE_READ;
        }
        if (0 == iReady) {
            continue;
        }
        lRead = read(STDIN_FILENO, &cValue, 1U);
        if ((lRead < 0) && ((EINTR == errno) || (EAGAIN == errno))) {
            continue;
        }
        if (lRead < 0) {
            return IPSEC_ERR_FILE_READ;
        }
        if ((0 == lRead) || ('\n' == cValue)) {
            pcLine[zLength] = '\0';
            *pbEof = (0 == lRead) && (0U == zLength);
            return bOverflow ? IPSEC_ERR_BUFFER_TOO_SMALL : IPSEC_OK;
        }
        if (zLength + 1U < zCapacity) {
            pcLine[zLength++] = cValue;
        }
        else {
            bOverflow = true; /* Drain the rest; never execute a truncated command. */
        }
    }
    return IPSEC_ERR_CANCELLED;
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
        bool bEof = false;

        if (IsNativeAppExitRequested()) {
            if (IPSEC_OK == CloseNativeAppSession(pSession, false)) {
                bExit = true;
                break;
            }
            ResetNativeAppExitRequest();
            ResetNativeAppStopRequest();
        }
        PrintNativeAppPrompt(pSession);
        eError = ReadNativeAppInput(acLine, sizeof(acLine), &bEof);
        HideNativeAppPrompt(pSession);
        if (IPSEC_ERR_CANCELLED == eError) {
            (void)printf("\n");
            ResetNativeAppStopRequest();
            continue;
        }
        if (bEof || (IPSEC_ERR_FILE_READ == eError)) {
            (void)printf("\ninput closed; attempting normal shutdown\n");
            if (IPSEC_OK == CloseNativeAppSession(pSession, false)) {
                bExit = true;
                break;
            }
            if (0 == isatty(STDIN_FILENO)) {
                (void)fprintf(stderr, "input unavailable; process/remaining paths retained. "
                    "Resolve the failure externally and send SIGTERM to retry cleanup.\n");
                while (!IsNativeAppExitRequested() && !IsNativeAppStopRequested()) {
                    (void)poll(NULL, 0U, 250);
                }
            }
            ResetNativeAppStopRequest();
            continue;
        }
        if (IPSEC_OK != eError) {
            (void)fprintf(stderr, "command input failed: %s\n", GetIpsecErrorString(eError));
            continue;
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
    (void)printf("session closed; %s\n",
        pSession->bExitForced ? "forced teardown; daemon cleanup was not guaranteed" :
        (pSession->bExitCleaned ? "owned IKE/CHILD, connections and credentials cleaned; files preserved" :
                                "SYSTEM daemon resources retained (terminate_on_exit=false)"));
    return 0;
}

static IpsecError_t InitializeNativeAppSession(
    NativeAppSession_t *pSession,
    bool bVerbose)
{
    IpsecError_t eError;

    if (NULL == pSession) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        (void)memset(pSession, 0, sizeof(*pSession));
        atomic_init(&pSession->bPromptVisible, false);
        pSession->bVerbose = bVerbose;
        InitializeNativeAppConfig(&pSession->Config);
        InitializeNativeAppConfig(&pSession->BaseConfig);
    }
    eError = InitializeNativeAppOwnedResources(&pSession->OwnedResources);
    if (IPSEC_OK != eError) {
        return eError;
    }
    if (0 != pthread_mutex_init(&pSession->OutputMutex, NULL)) {
        return IPSEC_ERR_INTERNAL;
    }
    else {
        pSession->bOutputMutexInitialized = true;
        eError = InitializeNativeAppPeerTable(&pSession->PeerTable);
    }
    if (IPSEC_OK == eError) {
        eError = InitializeNativeAppDiagnosticLog(&pSession->DiagnosticLog);
        if (IPSEC_OK != eError) {
            DeinitializeNativeAppPeerTable(&pSession->PeerTable);
        }
        else {
            /* Diagnostic logging is ready for any subsequently opened case. */
        }
    }
    if (IPSEC_OK != eError) {
        (void)pthread_mutex_destroy(&pSession->OutputMutex);
        pSession->bOutputMutexInitialized = false;
    }
    else {
        /* Both session mutexes are initialized. */
    }
    return eError;
}

static void DeinitializeNativeAppSession(NativeAppSession_t *pSession)
{
    if (NULL != pSession) {
        StopNativeAppPeerListener(&pSession->PeerListener);
        if (NULL != pSession->pContext) {
            DeinitializeIpsec(pSession->pContext);
            pSession->pContext = NULL;
        }
        else {
            /* No VICI context was opened. */
        }
        DeinitializeNativeAppDiagnosticLog(&pSession->DiagnosticLog);
        DeinitializeNativeAppPeerTable(&pSession->PeerTable);
        if (pSession->bOutputMutexInitialized) {
            (void)pthread_mutex_destroy(&pSession->OutputMutex);
            pSession->bOutputMutexInitialized = false;
        }
        else {
            /* No output mutex was initialized. */
        }
    }
    else {
        /* Nothing to deinitialize. */
    }
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
        PrintNativeAppUsage(((iArgumentCount > 0) && (NULL != ppcArguments) &&
                             (NULL != ppcArguments[0])) ? ppcArguments[0] :
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

        if ((!bHasApplicationConfig && bHasManagementConfig) ||
            ((NULL != Options.pcConfigPath) && bHasApplicationConfig)) {
            PrintNativeAppUsage(ppcArguments[0]);
            return 2;
        }
        else {
            /* The selected configuration mode is complete. */
        }
        eError = InitializeNativeAppSession(&Session, Options.bVerbose);
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
            ((NULL == Options.pcManagementConfigPath) ||
             CopyNativeAppSessionText(
                 Session.acManagementConfigPath,
                 sizeof(Session.acManagementConfigPath),
                 Options.pcManagementConfigPath))) {
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
        DeinitializeNativeAppSession(&Session);
        return 1;
    }
    else {
        Session.Config.pOwnedResources = &Session.OwnedResources;
        Session.BaseConfig.pOwnedResources = &Session.OwnedResources;
        Session.Config.pDiagnosticLog = &Session.DiagnosticLog;
        Session.BaseConfig.pDiagnosticLog = &Session.DiagnosticLog;
        Session.ContextConfig = Session.Config;
        if ((IPSEC_PACKET_PATH_APPLICATION == Session.Config.Datapath.eProtectedPacketPath) &&
            (Options.iCommandIndex < iArgumentCount)) {
            (void)fprintf(stderr, "Protected APPLICATION requires an interactive session; "
                          "one-shot teardown is unsafe\n");
            DeinitializeNativeAppSession(&Session);
            return 2;
        }
        if (IPSEC_PACKET_PATH_APPLICATION == Session.Config.Datapath.eProtectedPacketPath) {
            (void)fprintf(stderr, "EXPERIMENTAL Protected APPLICATION: dedicated egress and "
                          "fixed IPv4 RAW ESP pair only. "
                          "No automatic forwarding; stop traffic and SAs before closing.\n");
        }
        if (IPSEC_PACKET_PATH_APPLICATION ==
            Session.Config.Datapath.ePlainPacketPath) {
            (void)fprintf(stderr, "EXPERIMENTAL Plain APPLICATION: the OS must enqueue "
                "post-decrypt traffic only; returned packets are removed from the Linux stack.\n");
        }
        eError = OpenNativeAppContext(&Session, &Session.Config,
                                      &Session.pContext);
    }
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "InitializeIpsecWithDatapath failed "
                      "(check backend/plugin/TUN/TC/NFQUEUE settings): %s\n",
                      GetIpsecErrorString(eError));
        DeinitializeNativeAppSession(&Session);
        return 1;
    }
    else {
        /* Peer control endpoints are started explicitly from the CLI. */
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
    DeinitializeNativeAppSession(&Session);
    return iResult;
}
