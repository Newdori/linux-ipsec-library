#ifndef VICI_INTERNAL_H
#define VICI_INTERNAL_H

#include "../../internal/ipsec_internal.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define VICI_MAX_SEGMENT_LENGTH (512U * 1024U)
#define VICI_MAX_SECTION_DEPTH 32U
#define VICI_ERROR_MESSAGE_LENGTH 256U

typedef enum ViciPacketType {
    VICI_PACKET_COMMAND_REQUEST = 0,
    VICI_PACKET_COMMAND_RESPONSE = 1,
    VICI_PACKET_COMMAND_UNKNOWN = 2,
    VICI_PACKET_EVENT_REGISTER = 3,
    VICI_PACKET_EVENT_UNREGISTER = 4,
    VICI_PACKET_EVENT_CONFIRM = 5,
    VICI_PACKET_EVENT_UNKNOWN = 6,
    VICI_PACKET_EVENT = 7
} ViciPacketType_t;

typedef enum ViciElementType {
    VICI_ELEMENT_SECTION_START = 1,
    VICI_ELEMENT_SECTION_END = 2,
    VICI_ELEMENT_KEY_VALUE = 3,
    VICI_ELEMENT_LIST_START = 4,
    VICI_ELEMENT_LIST_ITEM = 5,
    VICI_ELEMENT_LIST_END = 6
} ViciElementType_t;

typedef struct ViciBuffer {
    uint8_t *pucData;
    uint32_t uiLength;
    uint32_t uiCapacity;
    bool bSensitive;
} ViciBuffer_t;

typedef struct ViciPacketView {
    ViciPacketType_t eType;
    const uint8_t *pucName;
    uint8_t ucNameLength;
    const uint8_t *pucMessage;
    uint32_t uiMessageLength;
} ViciPacketView_t;

typedef struct ViciElement {
    ViciElementType_t eType;
    const uint8_t *pucName;
    uint8_t ucNameLength;
    const uint8_t *pucValue;
    uint16_t usValueLength;
    uint32_t uiDepth;
} ViciElement_t;

typedef struct ViciCommandResult {
    bool bSuccessPresent;
    bool bSuccess;
    char acErrorMessage[VICI_ERROR_MESSAGE_LENGTH];
} ViciCommandResult_t;

/* Each active wait owns its event socket and cancellation socketpair. There is no
 * background receiver thread and no authoritative SA cache to go stale. */
typedef struct ViciWaiter {
    struct ViciWaiter *pNext;
    int32_t aiCancelSockets[2];
    IpsecContext_t EventContext;
    uint64_t ullDeadlineMs;
    bool bPolling;
} ViciWaiter_t;

bool IsViciWaitCancelled(int32_t iCancelFd);
IpsecError_t BeginViciWait(IpsecContext_t *pContext, ViciWaiter_t *pWaiter,
                           uint64_t ullDeadlineMs);
void EndViciWait(IpsecContext_t *pContext, ViciWaiter_t *pWaiter);
IpsecError_t SubscribeViciSaEvents(ViciWaiter_t *pWaiter, bool bChild);
IpsecError_t ReceiveViciSaChange(ViciWaiter_t *pWaiter);
IpsecError_t PauseViciWait(ViciWaiter_t *pWaiter);
void CloseViciWaits(IpsecContext_t *pContext);

IpsecError_t WaitViciTransportReadable(IpsecContext_t *pContext,
                                      uint64_t ullDeadlineMs);

typedef IpsecError_t (*ViciElementCallback_t)(
    const ViciElement_t *pElement,
    void *pvUserData);

typedef IpsecError_t (*ViciMessageCallback_t)(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    void *pvUserData);

IpsecError_t InitializeViciBuffer(
    ViciBuffer_t *pBuffer,
    uint32_t uiInitialCapacity,
    bool bSensitive);

void DestroyViciBuffer(
    ViciBuffer_t *pBuffer);

IpsecError_t AppendViciBuffer(
    ViciBuffer_t *pBuffer,
    const void *pvData,
    uint32_t uiLength);

IpsecError_t AddViciSectionStart(
    ViciBuffer_t *pBuffer,
    const char *pcName);

IpsecError_t AddViciSectionEnd(
    ViciBuffer_t *pBuffer);

IpsecError_t AddViciKeyValue(
    ViciBuffer_t *pBuffer,
    const char *pcName,
    const void *pvValue,
    uint32_t uiValueLength);

IpsecError_t AddViciKeyValueString(
    ViciBuffer_t *pBuffer,
    const char *pcName,
    const char *pcValue);

IpsecError_t AddViciListStart(
    ViciBuffer_t *pBuffer,
    const char *pcName);

IpsecError_t AddViciListItem(
    ViciBuffer_t *pBuffer,
    const void *pvValue,
    uint32_t uiValueLength);

IpsecError_t AddViciListItemString(
    ViciBuffer_t *pBuffer,
    const char *pcValue);

IpsecError_t AddViciListEnd(
    ViciBuffer_t *pBuffer);

IpsecError_t BuildViciNamedPacket(
    ViciPacketType_t eType,
    const char *pcName,
    const ViciBuffer_t *pMessage,
    ViciBuffer_t *pPacket);

IpsecError_t DecodeViciPacket(
    const uint8_t *pucPacket,
    uint32_t uiPacketLength,
    ViciPacketView_t *pView);

IpsecError_t ParseViciMessage(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    ViciElementCallback_t pCallback,
    void *pvUserData);

IpsecError_t ConnectViciTransport(
    IpsecContext_t *pContext);

void DisconnectViciTransport(
    IpsecContext_t *pContext);

IpsecError_t SendViciTransportPacket(
    IpsecContext_t *pContext,
    const ViciBuffer_t *pPacket);

IpsecError_t ReceiveViciTransportPacket(
    IpsecContext_t *pContext,
    ViciBuffer_t *pPacket);

IpsecError_t ExecuteViciCommand(
    IpsecContext_t *pContext,
    const char *pcCommand,
    const ViciBuffer_t *pRequest,
    const char *pcEventName,
    ViciMessageCallback_t pEventCallback,
    ViciMessageCallback_t pResponseCallback,
    void *pvUserData,
    ViciCommandResult_t *pResult);

IpsecError_t ParseViciCommandResult(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    ViciCommandResult_t *pResult);

IpsecError_t ExecuteViciCommandUntil(
    IpsecContext_t *pContext,
    const char *pcCommand,
    const ViciBuffer_t *pRequest,
    const char *pcEventName,
    ViciMessageCallback_t pEventCallback,
    ViciMessageCallback_t pResponseCallback,
    void *pvUserData,
    ViciCommandResult_t *pResult,
    uint64_t ullDeadlineMs,
    int32_t iCancelFd);

IpsecError_t ParseViciDaemonStatusMessage(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    IpsecDaemonStatus_t *pStatus);

IpsecError_t ValidateViciConnectionConfigInternal(
    const IpsecConnectionConfig_t *pConfig);

IpsecError_t LoadViciConnectionInternal(
    IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig);

IpsecError_t UnloadViciConnectionInternal(
    IpsecContext_t *pContext,
    const char *pcName);

#endif
