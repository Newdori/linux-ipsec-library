#ifndef IPSEC_APP_INTERNAL_H
#define IPSEC_APP_INTERNAL_H

#include "ipsec.h"

#include <pthread.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <stddef.h>
#include <stdint.h>

#define NATIVE_APP_PATH_LENGTH             512U
#define NATIVE_APP_PROPOSAL_TEXT_LENGTH   1024U
#define NATIVE_APP_PROPOSAL_COUNT           32U
#define NATIVE_APP_ERROR_TEXT_LENGTH       256U
#define NATIVE_APP_PSK_MAX_LENGTH        65535U
#define NATIVE_APP_COMMAND_LINE_LENGTH     2048U
#define NATIVE_APP_COMMAND_ARGUMENT_COUNT    32U
#define NATIVE_APP_ALGORITHM_CASE_ID_LENGTH  64U
#define NATIVE_APP_ALGORITHM_RUN_ID_LENGTH    96U
#define NATIVE_APP_ALGORITHM_RESULT_LENGTH  128U
#define NATIVE_APP_ALGORITHM_REASON_LENGTH  256U
#define NATIVE_APP_ALGORITHM_CAPABILITY_LENGTH 512U
#define NATIVE_APP_ALGORITHM_DEFAULT_PORT  39001U
#define NATIVE_APP_ALGORITHM_DEFAULT_LIMIT   10U
#define NATIVE_APP_PEER_DEFAULT_PORT        39002U

#ifndef NATIVE_APP_BUILD_ID
#define NATIVE_APP_BUILD_ID "unknown"
#endif
#define NATIVE_APP_PEER_CAPACITY              256U
#define NATIVE_APP_PEER_LOGON_LIMIT            100U
#define NATIVE_APP_PEER_LISTENER_POLL_MS       250U
#define NATIVE_APP_PEER_MESSAGE_LENGTH        4096U
#define NATIVE_APP_PEER_ID_PREFIX           "rcst-"
#define NATIVE_APP_CONNECTION_PREFIX        "conn-"
#define NATIVE_APP_CHILD_PREFIX             "child-"
#define NATIVE_APP_CREDENTIAL_PREFIX        "psk-"

typedef enum NativeAppRole {
    NATIVE_APP_ROLE_INITIATOR = 0,
    NATIVE_APP_ROLE_RESPONDER
} NativeAppRole_t;

typedef enum NativeAppPeerState {
    NATIVE_APP_PEER_STATE_REGISTERED = 0,
    NATIVE_APP_PEER_STATE_CREDENTIAL_LOADED,
    NATIVE_APP_PEER_STATE_CONNECTION_LOADED,
    NATIVE_APP_PEER_STATE_READY,
    NATIVE_APP_PEER_STATE_IKE_ESTABLISHED,
    NATIVE_APP_PEER_STATE_CHILD_INSTALLED
} NativeAppPeerState_t;

typedef struct NativeAppTargetStatus {
    uint32_t uiReqid;
    bool bConnectionLoaded;
    bool bIkeEstablished;
    bool bChildInstalled;
} NativeAppTargetStatus_t;

typedef struct NativeAppConfig {
    NativeAppRole_t eRole;
    char acLocalAddress[IPSEC_ADDRESS_LENGTH];
    char acRemoteAddress[IPSEC_ADDRESS_LENGTH];
    char acLocalId[IPSEC_ID_LENGTH];
    char acRemoteId[IPSEC_ID_LENGTH];
    char acPskFile[NATIVE_APP_PATH_LENGTH];
    char acOutputRoot[NATIVE_APP_PATH_LENGTH];
    char acViciSocket[NATIVE_APP_PATH_LENGTH];
    char acConnectionName[IPSEC_NAME_LENGTH];
    char acChildName[IPSEC_NAME_LENGTH];
    char acCredentialId[IPSEC_NAME_LENGTH];
    char acPeerServerAddress[IPSEC_ADDRESS_LENGTH];
    char acIkeProposals[NATIVE_APP_PROPOSAL_TEXT_LENGTH];
    char acEspProposals[NATIVE_APP_PROPOSAL_TEXT_LENGTH];
    IpsecMode_t eMode;
    bool bChildlessIke;
    bool bTerminateOnExit;
    uint32_t uiTimeoutMs;
    uint32_t uiPeerPort;
} NativeAppConfig_t;

typedef struct NativeAppPeer {
    uint32_t uiGroupId;
    uint32_t uiLogonId;
    uint32_t uiRegistrationCount;
    NativeAppConfig_t Config;
    NativeAppPeerState_t eState;
    bool bConnectionLoaded;
    bool bCredentialLoaded;
    bool bIkeEstablished;
    bool bChildInstalled;
} NativeAppPeer_t;

typedef struct NativeAppPeerTable {
    NativeAppPeer_t aPeers[NATIVE_APP_PEER_CAPACITY];
    uint32_t uiCount;
    uint32_t uiSelectedIndex;
    pthread_mutex_t Mutex;
} NativeAppPeerTable_t;

typedef void (*NativeAppPeerEventCallback_t)(
    IpsecError_t eError,
    const NativeAppPeer_t *pPeer,
    const char *pcError,
    void *pvUserData);

typedef struct NativeAppPeerListener {
    pthread_t Thread;
    NativeAppConfig_t Config;
    NativeAppPeerTable_t *pTable;
    NativeAppPeerEventCallback_t pCallback;
    void *pvUserData;
    int32_t iServerSocket;
    atomic_bool bStopRequested;
    bool bRunning;
} NativeAppPeerListener_t;

typedef struct NativeAppRuntimeConfig {
    IpsecConnectionConfig_t Connection;
    char acLocalTrafficSelector[IPSEC_SELECTOR_LIST_LENGTH];
    char acRemoteTrafficSelector[IPSEC_SELECTOR_LIST_LENGTH];
    char aacIkeProposals[NATIVE_APP_PROPOSAL_COUNT]
                         [IPSEC_PROPOSAL_LENGTH];
    char aacEspProposals[NATIVE_APP_PROPOSAL_COUNT]
                         [IPSEC_PROPOSAL_LENGTH];
    const char *pacLocalAddresses[1];
    const char *pacRemoteAddresses[1];
    const char *pacLocalTrafficSelectors[1];
    const char *pacRemoteTrafficSelectors[1];
    const char *pacIkeProposals[NATIVE_APP_PROPOSAL_COUNT];
    const char *pacEspProposals[NATIVE_APP_PROPOSAL_COUNT];
} NativeAppRuntimeConfig_t;

typedef struct NativeAppShowOptions {
    const char *pcScope;
    const char *pcName;
    bool bDetail;
} NativeAppShowOptions_t;

typedef struct NativeAppSecret {
    uint8_t *pucData;
    uint32_t uiLength;
} NativeAppSecret_t;

typedef struct NativeAppLoopOptions {
    uint32_t uiCount;
    uint32_t uiDelayMs;
    bool bContinueOnError;
    bool bClearCredentials;
} NativeAppLoopOptions_t;

typedef enum NativeAppAlgorithmMode {
    NATIVE_APP_ALGORITHM_BASELINE = 0,
    NATIVE_APP_ALGORITHM_EXHAUSTIVE_IKE,
    NATIVE_APP_ALGORITHM_EXHAUSTIVE_ESP,
    NATIVE_APP_ALGORITHM_CUSTOM
} NativeAppAlgorithmMode_t;

typedef enum NativeAppAlgorithmResult {
    NATIVE_APP_ALGORITHM_RESULT_PASS = 0,
    NATIVE_APP_ALGORITHM_RESULT_EXPECTED_NOT_SUPPORTED,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_CONFIG,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_SYNC,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_IKE,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_CHILD,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_PROPOSAL,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_PFS,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_ESN,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_XFRM,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_INSTALL,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_CLEANUP,
    NATIVE_APP_ALGORITHM_RESULT_STOPPED
} NativeAppAlgorithmResult_t;

typedef enum NativeAppAlgorithmPhase {
    NATIVE_APP_ALGORITHM_PHASE_IKE = 0,
    NATIVE_APP_ALGORITHM_PHASE_ESP,
    NATIVE_APP_ALGORITHM_PHASE_INSTALL,
    NATIVE_APP_ALGORITHM_PHASE_DATA_PATH
} NativeAppAlgorithmPhase_t;

typedef enum NativeAppAlgorithmPhaseResult {
    NATIVE_APP_ALGORITHM_PHASE_NOT_RUN = 0,
    NATIVE_APP_ALGORITHM_PHASE_PASS,
    NATIVE_APP_ALGORITHM_PHASE_FAIL,
    NATIVE_APP_ALGORITHM_PHASE_NOT_APPLICABLE
} NativeAppAlgorithmPhaseResult_t;

typedef enum NativeAppAlgorithmFailureStage {
    NATIVE_APP_ALGORITHM_FAILURE_NONE = 0,
    NATIVE_APP_ALGORITHM_FAILURE_CONFIG,
    NATIVE_APP_ALGORITHM_FAILURE_SYNC,
    NATIVE_APP_ALGORITHM_FAILURE_IKE_NEGOTIATION,
    NATIVE_APP_ALGORITHM_FAILURE_CHILD_NEGOTIATION,
    NATIVE_APP_ALGORITHM_FAILURE_PROPOSAL_VALIDATION,
    NATIVE_APP_ALGORITHM_FAILURE_SA_INSTALL,
    NATIVE_APP_ALGORITHM_FAILURE_TRAFFIC,
    NATIVE_APP_ALGORITHM_FAILURE_CLEANUP
} NativeAppAlgorithmFailureStage_t;

typedef enum NativeAppAlgorithmErrorSource {
    NATIVE_APP_ALGORITHM_ERROR_NONE = 0,
    NATIVE_APP_ALGORITHM_ERROR_APPLICATION,
    NATIVE_APP_ALGORITHM_ERROR_TEST_CONTROL,
    NATIVE_APP_ALGORITHM_ERROR_VICI,
    NATIVE_APP_ALGORITHM_ERROR_DATAPATH,
    NATIVE_APP_ALGORITHM_ERROR_PEER,
    NATIVE_APP_ALGORITHM_ERROR_CLEANUP
} NativeAppAlgorithmErrorSource_t;

typedef enum NativeAppAlgorithmUnsupportedSide {
    NATIVE_APP_ALGORITHM_UNSUPPORTED_NONE = 0,
    NATIVE_APP_ALGORITHM_UNSUPPORTED_LOCAL,
    NATIVE_APP_ALGORITHM_UNSUPPORTED_PEER,
    NATIVE_APP_ALGORITHM_UNSUPPORTED_BOTH
} NativeAppAlgorithmUnsupportedSide_t;

typedef struct NativeAppAlgorithmCapabilities {
    IpsecDatapathType_t eDatapathType;
    uint64_t ullOpenSslVersion;
    char acOsName[IPSEC_OS_NAME_LENGTH];
    char acOsVersion[IPSEC_VERSION_LENGTH];
    char acDaemonVersion[IPSEC_VERSION_LENGTH];
    char acKernelRelease[IPSEC_OS_NAME_LENGTH];
    char acMachine[IPSEC_OS_NAME_LENGTH];
    char acOpenSslLibrary[NATIVE_APP_PATH_LENGTH];
    char acModp8192Plugin[IPSEC_PLUGIN_LENGTH];
    char acKdfPrfPlusPlugin[IPSEC_PLUGIN_LENGTH];
    char acModp8192Reason[NATIVE_APP_ALGORITHM_REASON_LENGTH];
    bool bDatapathReady;
    bool bOpenSslVersionKnown;
    bool bEsnSupported;
    bool bModp8192Supported;
} NativeAppAlgorithmCapabilities_t;

typedef struct NativeAppAlgorithmCase {
    uint32_t uiNumber;
    char acId[NATIVE_APP_ALGORITHM_CASE_ID_LENGTH];
    char acIkeProposal[IPSEC_PROPOSAL_LENGTH];
    char acEspProposal[IPSEC_PROPOSAL_LENGTH];
    char acExpectedChildKe[IPSEC_ALGORITHM_LENGTH];
    bool bSeparateChildExchange;
    bool bExpectEsn;
    bool bExpectNoEsn;
} NativeAppAlgorithmCase_t;

typedef struct NativeAppAlgorithmCleanup {
    IpsecError_t eTerminateError;
    IpsecError_t eWaitRemovedError;
    IpsecError_t eRemoveConnectionError;
    IpsecError_t eFinalVerifyError;
    IpsecError_t ePeerError;
    uint32_t uiTerminateAttempts;
    uint32_t uiWaitRemovedAttempts;
    uint32_t uiRemoveConnectionAttempts;
    uint32_t uiPeerAttempts;
    bool bRecovered;
    bool bLocalVerified;
} NativeAppAlgorithmCleanup_t;

typedef struct NativeAppAlgorithmCaseResult {
    NativeAppAlgorithmCase_t Case;
    NativeAppAlgorithmResult_t eResult;
    NativeAppAlgorithmResult_t ePeerCaseResult;
    NativeAppAlgorithmFailureStage_t eFailureStage;
    NativeAppAlgorithmErrorSource_t eErrorSource;
    NativeAppAlgorithmUnsupportedSide_t eUnsupportedSide;
    IpsecError_t eError;
    IpsecError_t ePeerCaseError;
    IpsecError_t eCleanupError;
    NativeAppAlgorithmCleanup_t Cleanup;
    uint32_t uiReqid;
    uint32_t uiXfrmStateCount;
    uint32_t uiXfrmPolicyCount;
    uint32_t uiTunRouteCount;
    uint64_t ullDurationMs;
    uint64_t ullBytesIn;
    uint64_t ullBytesOut;
    uint64_t ullPacketsIn;
    uint64_t ullPacketsOut;
    IpsecDatapathType_t eDatapathType;
    char acNegotiatedIke[IPSEC_PROPOSAL_LENGTH];
    char acNegotiatedEsp[IPSEC_PROPOSAL_LENGTH];
    char acExpectedIke[IPSEC_PROPOSAL_LENGTH];
    char acExpectedEsp[IPSEC_PROPOSAL_LENGTH];
    char acPeerResult[NATIVE_APP_ALGORITHM_RESULT_LENGTH];
    char acSupportReason[NATIVE_APP_ALGORITHM_REASON_LENGTH];
    char acPeerSupportReason[NATIVE_APP_ALGORITHM_REASON_LENGTH];
    char acPeerCapability[NATIVE_APP_ALGORITHM_CAPABILITY_LENGTH];
    bool bExecutionStarted;
    bool bPeerCaseKnown;
    bool bIkeVerified;
    bool bEspVerified;
    bool bInstallVerified;
    bool bDataPathVerified;
} NativeAppAlgorithmCaseResult_t;

typedef struct NativeAppAlgorithmOptions {
    NativeAppAlgorithmMode_t eMode;
    uint32_t uiStart;
    uint32_t uiLimit;
    uint32_t uiPort;
    uint32_t uiDelayMs;
    const char *pcResultsPath;
    const char *pcCustomIke;
    const char *pcCustomEsp;
    bool bContinueOnError;
} NativeAppAlgorithmOptions_t;

const char *GetNativeAppAlgorithmResultName(
    NativeAppAlgorithmResult_t eResult);

const char *GetNativeAppAlgorithmFailureStageName(
    NativeAppAlgorithmFailureStage_t eStage);

const char *GetNativeAppAlgorithmErrorSourceName(
    NativeAppAlgorithmErrorSource_t eSource);

const char *GetNativeAppAlgorithmUnsupportedSideName(
    NativeAppAlgorithmUnsupportedSide_t eSide);

NativeAppAlgorithmPhaseResult_t GetNativeAppAlgorithmPhaseResult(
    const NativeAppAlgorithmCaseResult_t *pResult,
    NativeAppAlgorithmPhase_t ePhase);

const char *GetNativeAppAlgorithmPhaseResultName(
    NativeAppAlgorithmPhaseResult_t eResult);

const char *GetNativeAppAlgorithmErrorText(
    IpsecError_t eError);

IpsecError_t WriteNativeAppAlgorithmRunReport(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    NativeAppAlgorithmMode_t eMode,
    const char *pcRole,
    const char *pcResultDirectory,
    uint32_t uiRequested,
    bool bFinal);

IpsecError_t CreateNativeAppAlgorithmCaseReport(
    const NativeAppConfig_t *pConfig,
    const NativeAppAlgorithmCase_t *pCase,
    const char *pcRole,
    const char *pcResultDirectory,
    uint32_t uiOrdinal,
    uint32_t uiRequested,
    char *pcCaseDirectory,
    size_t zCaseDirectoryLength);

IpsecError_t CaptureNativeAppAlgorithmCaseReport(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const NativeAppAlgorithmCaseResult_t *pResult,
    const char *pcCaseDirectory);

IpsecError_t FinishNativeAppAlgorithmCaseReport(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const NativeAppAlgorithmCaseResult_t *pResult,
    const char *pcRole,
    const char *pcResultDirectory,
    const char *pcCaseDirectory,
    uint32_t uiOrdinal,
    uint32_t uiRequested);

void InitializeNativeAppConfig(NativeAppConfig_t *pConfig);

IpsecError_t SetNativeAppConfigSetting(
    NativeAppConfig_t *pConfig,
    const char *pcKey,
    const char *pcValue);

IpsecError_t ValidateNativeAppConfig(
    const NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength);

IpsecError_t LoadNativeAppConfig(
    const char *pcPath,
    NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength);

IpsecError_t LoadNativeAppConfigFiles(
    const char *pcApplicationPath,
    const char *pcManagementPath,
    NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength);

IpsecError_t ValidateNativeAppBaseConfig(
    const NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength);

IpsecError_t BuildNativeAppRuntimeConfig(
    const NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime,
    char *pcError,
    uint32_t uiErrorLength);

IpsecError_t ReadNativeAppSecret(
    const NativeAppConfig_t *pConfig,
    NativeAppSecret_t *pSecret);

void DestroyNativeAppSecret(NativeAppSecret_t *pSecret);

IpsecError_t LoadNativeAppCredential(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig);

IpsecError_t LoadNativeAppResources(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime);

IpsecError_t StartNativeAppConnection(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const NativeAppRuntimeConfig_t *pRuntime);

IpsecError_t StopNativeAppConnection(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    bool bRemoveConnection,
    bool bClearCredentials);

IpsecError_t RunNativeAppLoop(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime,
    const NativeAppLoopOptions_t *pOptions,
    bool *pbCredentialLoaded);

const char *GetNativeAppAlgorithmModeName(
    NativeAppAlgorithmMode_t eMode);

bool ParseNativeAppAlgorithmMode(
    const char *pcText,
    NativeAppAlgorithmMode_t *pMode);

uint32_t GetNativeAppAlgorithmCaseCount(
    NativeAppAlgorithmMode_t eMode);

IpsecError_t GetNativeAppAlgorithmCase(
    NativeAppAlgorithmMode_t eMode,
    uint32_t uiIndex,
    const NativeAppConfig_t *pBaseConfig,
    const char *pcCustomIke,
    const char *pcCustomEsp,
    NativeAppAlgorithmCase_t *pCase);

IpsecError_t BuildNativeAppExpectedProposals(
    const NativeAppAlgorithmCase_t *pCase,
    char *pcExpectedIke,
    size_t zExpectedIkeLength,
    char *pcExpectedEsp,
    size_t zExpectedEspLength);

IpsecError_t CollectNativeAppAlgorithmCapabilities(
    IpsecContext_t *pContext,
    NativeAppAlgorithmCapabilities_t *pCapabilities);

IpsecError_t CheckNativeAppAlgorithmCaseSupport(
    const NativeAppAlgorithmCapabilities_t *pCapabilities,
    const NativeAppAlgorithmCase_t *pCase,
    char *pcReason,
    size_t zReasonLength);

IpsecError_t FormatNativeAppAlgorithmCapabilitySummary(
    const NativeAppAlgorithmCapabilities_t *pCapabilities,
    const char *pcSupportReason,
    char *pcSummary,
    size_t zSummaryLength);

IpsecError_t RunNativeAppAlgorithmClient(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const NativeAppAlgorithmOptions_t *pOptions);

IpsecError_t RunNativeAppAlgorithmServer(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    uint32_t uiPort);

IpsecError_t InitializeNativeAppPeerTable(NativeAppPeerTable_t *pTable);

void DeinitializeNativeAppPeerTable(NativeAppPeerTable_t *pTable);

void LockNativeAppPeerTable(NativeAppPeerTable_t *pTable);

void UnlockNativeAppPeerTable(NativeAppPeerTable_t *pTable);

IpsecError_t GetNativeAppPeerSequence(
    uint32_t uiOrdinal,
    uint32_t *puiGroupId,
    uint32_t *puiLogonId);

IpsecError_t StartNativeAppPeerListener(
    NativeAppPeerListener_t *pListener,
    const NativeAppConfig_t *pBaseConfig,
    NativeAppPeerTable_t *pTable,
    NativeAppPeerEventCallback_t pCallback,
    void *pvUserData,
    char *pcError,
    uint32_t uiErrorLength);

void StopNativeAppPeerListener(NativeAppPeerListener_t *pListener);

bool IsNativeAppPeerListenerRunning(
    const NativeAppPeerListener_t *pListener);

IpsecError_t AcceptNativeAppPeer(
    const NativeAppConfig_t *pBaseConfig,
    NativeAppPeerTable_t *pTable,
    NativeAppPeer_t *pPeer,
    char *pcError,
    uint32_t uiErrorLength);

IpsecError_t RegisterNativeAppPeer(
    const NativeAppConfig_t *pBaseConfig,
    NativeAppPeerTable_t *pTable,
    NativeAppPeer_t *pPeer,
    char *pcError,
    uint32_t uiErrorLength);

IpsecError_t SelectNativeAppPeerRecord(
    NativeAppPeerTable_t *pTable,
    const char *pcPeerId,
    NativeAppPeer_t *pPeer);

IpsecError_t UpsertNativeAppPeer(
    NativeAppPeerTable_t *pTable,
    const NativeAppPeer_t *pPeer,
    NativeAppPeer_t *pStoredPeer);

NativeAppPeerState_t GetNativeAppPeerState(
    bool bConnectionLoaded,
    bool bCredentialLoaded,
    bool bIkeEstablished,
    bool bChildInstalled);

const char *GetNativeAppPeerStateName(
    NativeAppPeerState_t eState);

void ResolveNativeAppTargetStatus(
    const NativeAppConfig_t *pConfig,
    const IpsecConnectionList_t *pConnections,
    const IpsecIkeSaList_t *pIkeSas,
    const IpsecChildSaList_t *pChildSas,
    NativeAppTargetStatus_t *pStatus);

IpsecError_t GetNativeAppTargetStatus(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    NativeAppTargetStatus_t *pStatus);

IpsecError_t GetNativeAppConnectionSaStatus(
    IpsecContext_t *pContext,
    const char *pcConnectionName,
    bool *pbActive);

IpsecError_t GetNativeAppAnySaStatus(
    IpsecContext_t *pContext,
    bool *pbActive);

IpsecError_t ShowNativeAppInformation(
    IpsecContext_t *pContext,
    const char *pcScope,
    bool bDetail,
    const char *pcName);

void RequestNativeAppStop(void);

void ResetNativeAppStopRequest(void);

bool ParseNativeAppCommandLine(
    char *pcLine,
    char **ppcArguments,
    uint32_t uiArgumentCapacity,
    uint32_t *puiArgumentCount);

bool ParseNativeAppNumber(
    const char *pcText,
    uint32_t *puiValue);

bool IsNativeAppStopRequested(void);

IpsecError_t WaitNativeAppRemoved(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    uint32_t uiReqid);

IpsecError_t WaitNativeAppRemovedWithTimeout(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    uint32_t uiReqid,
    uint32_t uiTimeoutMs);

bool ParseNativeAppShowOptions(
    uint32_t uiArgumentCount,
    char **ppcArguments,
    NativeAppShowOptions_t *pOptions);

int32_t RunNativeAppCli(
    int32_t iArgumentCount,
    char **ppcArguments);

#endif
