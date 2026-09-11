#ifndef IPSEC_INTERNAL_H
#define IPSEC_INTERNAL_H

#define _POSIX_C_SOURCE 200809L

#include "ipsec.h"
#include "buffer_validate.h"
#include "secure_zero.h"

#include <pthread.h>
#include <stddef.h>
#include <stdint.h>

#define IPSEC_DEFAULT_CONNECT_TIMEOUT_MS 3000U
#define IPSEC_DEFAULT_COMMAND_TIMEOUT_MS 10000U
#define IPSEC_VICI_SOCKET_PATH_LENGTH 108U
#define IPSEC_LOG_MESSAGE_LENGTH 1024U

typedef struct IpsecViciState {
    int32_t iSocket;
    char acSocketPath[IPSEC_VICI_SOCKET_PATH_LENGTH];
    uint32_t uiConnectTimeoutMs;
    uint32_t uiCommandTimeoutMs;
    uint64_t ullCommandDeadlineMs;
    int32_t iTransportCancelFd;
} IpsecViciState_t;

typedef struct IpsecCommandState {
    pthread_mutex_t Mutex;
    bool bMutexInitialized;
    pthread_cond_t Condition;
    bool bConditionInitialized;
    bool bActive;
    bool bClosing;
    struct ViciWaiter *pWaiters;
} IpsecCommandState_t;

typedef struct IpsecDiagnosticState {
    IpsecDiagnostic_t Last;
} IpsecDiagnosticState_t;

typedef struct IpsecLoggerState {
    IpsecLogCallback_t pCallback;
    void *pvUserData;
} IpsecLoggerState_t;

typedef struct IpsecDatapathManager {
    IpsecDatapathConfig_t Config;
    IpsecDatapathType_t eActiveType;
    const struct IpsecDatapathOps *pOps;
    IpsecError_t eError;
    bool bInitialized;
    char acInterfaceName[IPSEC_DATAPATH_NAME_LENGTH];
    uint32_t uiInterfaceIndex;
} IpsecDatapathManager_t;

typedef struct IpsecProtectedPathManager {
    const struct IpsecProtectedPathOps *pOps;
    bool bInitialized;
    struct IpsecProtectedApplicationState *pApplicationState;
} IpsecProtectedPathManager_t;

typedef struct IpsecPlainPathManager {
    const struct IpsecPlainPathOps *pOps;
    bool bInitialized;
    struct IpsecPlainApplicationState *pApplicationState;
} IpsecPlainPathManager_t;

typedef struct IpsecOwnedCredential IpsecOwnedCredential_t;

typedef struct IpsecCredentialState {
    pthread_mutex_t Mutex;
    bool bMutexInitialized;
    bool bAnonymousLoaded;
    IpsecOwnedCredential_t *pOwned;
} IpsecCredentialState_t;

struct IpsecContext {
    IpsecViciState_t Vici;
    IpsecCommandState_t Command;
    IpsecDiagnosticState_t Diagnostic;
    IpsecLoggerState_t Logger;
    IpsecDatapathManager_t Datapath;
    IpsecProtectedPathManager_t ProtectedPath;
    IpsecPlainPathManager_t PlainPath;
    IpsecCredentialState_t Credentials;
};

void DestroyIpsecContextState(IpsecContext_t *pContext);

IpsecError_t InitializeIpsecContextState(
    IpsecContext_t *pContext,
    const IpsecConfig_t *pConfig);

IpsecError_t InitializeIpsecCredentialState(IpsecContext_t *pContext);

void DestroyIpsecCredentialState(IpsecContext_t *pContext);

void LogIpsec(
    const IpsecContext_t *pContext,
    IpsecLogLevel_t eLevel,
    const char *pcFormat,
    ...);

IpsecError_t CopyIpsecString(
    char *pcDestination,
    size_t zDestinationLength,
    const uint8_t *pucSource,
    size_t zSourceLength);

IpsecError_t ParseIpsecUint32(
    const uint8_t *pucValue,
    size_t zValueLength,
    uint32_t *puiValue,
    uint32_t uiBase);

IpsecError_t ParseIpsecUint64(
    const uint8_t *pucValue,
    size_t zValueLength,
    uint64_t *pullValue,
    uint32_t uiBase);

IpsecError_t ParseIpsecDurationSeconds(
    const uint8_t *pucValue,
    size_t zValueLength,
    uint64_t *pullSeconds);

IpsecError_t AppendIpsecText(
    char *pcDestination,
    size_t zDestinationLength,
    const uint8_t *pucValue,
    size_t zValueLength,
    const char *pcSeparator);

uint64_t GetIpsecMonotonicMilliseconds(void);

IpsecError_t SleepIpsecMilliseconds(uint32_t uiMilliseconds);

IpsecError_t RegisterIpsecProtectedPeerInternal(
    IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig,
    bool *pbAdded);

IpsecError_t UnregisterIpsecProtectedPeerInternal(
    IpsecContext_t *pContext,
    const char *pcConnectionName);

IpsecError_t RegisterIpsecPlainPeerInternal(
    IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig,
    bool *pbAdded);

IpsecError_t UnregisterIpsecPlainPeerInternal(
    IpsecContext_t *pContext,
    const char *pcConnectionName);

bool MatchIpsecProtectedPeerInternal(
    IpsecContext_t *pContext,
    const char *pcLocalAddress,
    const char *pcRemoteAddress);

#endif
