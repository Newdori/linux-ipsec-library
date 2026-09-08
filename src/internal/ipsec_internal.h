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

struct IpsecContext {
    int32_t iViciSocket;
    char acViciSocketPath[IPSEC_VICI_SOCKET_PATH_LENGTH];
    uint32_t uiConnectTimeoutMs;
    uint32_t uiCommandTimeoutMs;
    uint64_t ullCommandDeadlineMs;
    pthread_mutex_t CommandMutex;
    bool bCommandMutexInitialized;
    pthread_cond_t CommandCondition;
    bool bCommandConditionInitialized;
    bool bCommandActive;
    bool bClosing;
    struct ViciWaiter *pWaiters;
    int32_t iTransportCancelFd;
    IpsecDiagnostic_t LastDiagnostic;
    IpsecLogCallback_t pLogCallback;
    void *pvLogUserData;
    IpsecDatapathConfig_t DatapathConfig;
    IpsecDatapathType_t eActiveDatapath;
    const struct IpsecDatapathOps *pDatapathOps;
    const struct IpsecProtectedPathOps *pProtectedPathOps;
    const struct IpsecPlainPathOps *pPlainPathOps;
    IpsecError_t eDatapathError;
    bool bDatapathInitialized;
    bool bProtectedPathInitialized;
    bool bPlainPathInitialized;
    char acDatapathInterfaceName[IPSEC_DATAPATH_NAME_LENGTH];
    uint32_t uiDatapathInterfaceIndex;
    /* Packet path implementations own these opaque allocations. */
    struct IpsecProtectedApplicationState *pProtectedApplicationState;
    struct IpsecPlainApplicationState *pPlainApplicationState;
};

void DestroyIpsecContextState(IpsecContext_t *pContext);

IpsecError_t InitializeIpsecContextState(
    IpsecContext_t *pContext,
    const IpsecConfig_t *pConfig);

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

bool MatchIpsecProtectedPeerInternal(
    IpsecContext_t *pContext,
    const char *pcLocalAddress,
    const char *pcRemoteAddress);

#endif
