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
#define NATIVE_APP_ALGORITHM_DEFAULT_PORT  39001U
#define NATIVE_APP_ALGORITHM_DEFAULT_LIMIT   10U
#define NATIVE_APP_PEER_DEFAULT_PORT        39002U
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
    NativeAppConfig_t Config;
    bool bConnectionLoaded;
    bool bCredentialLoaded;
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
    NATIVE_APP_ALGORITHM_RESULT_FAIL_CONFIG,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_SYNC,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_IKE,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_CHILD,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_PROPOSAL,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_PFS,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_ESN,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_XFRM,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH,
    NATIVE_APP_ALGORITHM_RESULT_FAIL_CLEANUP,
    NATIVE_APP_ALGORITHM_RESULT_STOPPED
} NativeAppAlgorithmResult_t;

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
    IpsecError_t eError;
    IpsecError_t eCleanupError;
    NativeAppAlgorithmCleanup_t Cleanup;
    uint32_t uiReqid;
    uint32_t uiXfrmStateCount;
    uint32_t uiXfrmPolicyCount;
    uint64_t ullDurationMs;
    char acNegotiatedIke[IPSEC_PROPOSAL_LENGTH];
    char acNegotiatedEsp[IPSEC_PROPOSAL_LENGTH];
    char acPeerResult[NATIVE_APP_ALGORITHM_RESULT_LENGTH];
    bool bIkeVerified;
    bool bEspVerified;
    bool bXfrmVerified;
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
    const NativeAppLoopOptions_t *pOptions);

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
    NativeAppPeer_t **ppPeer,
    char *pcError,
    uint32_t uiErrorLength);

IpsecError_t RegisterNativeAppPeer(
    const NativeAppConfig_t *pBaseConfig,
    NativeAppPeerTable_t *pTable,
    NativeAppPeer_t **ppPeer,
    char *pcError,
    uint32_t uiErrorLength);

NativeAppPeer_t *FindNativeAppPeer(
    NativeAppPeerTable_t *pTable,
    const char *pcPeerId);

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
