#ifndef IPSEC_APPLICATION_PROTECTED_INTERNAL_H
#define IPSEC_APPLICATION_PROTECTED_INTERNAL_H

#include "protected_path_ops.h"

#include <pthread.h>

#define IPSEC_PROTECTED_APPLICATION_PEER_CAPACITY 256U

typedef struct IpsecProtectedApplicationPeer {
    char acConnectionName[IPSEC_NAME_LENGTH];
    uint32_t uiLocalAddress;
    uint32_t uiRemoteAddress;
    uint32_t uiFilterHandle;
    bool bRawFilter;
    bool bUdpFilter;
    bool bInUse;
} IpsecProtectedApplicationPeer_t;

typedef struct IpsecProtectedApplicationState {
    int32_t iTunFd;
    uint32_t uiTunIndex;
    uint32_t uiEgressIndex;
    uint32_t uiLocalAddress;
    uint32_t uiRemoteAddress;
    uint32_t uiFilterHandle;
    uint16_t usPriority;
    bool bRawFilter;
    bool bUdpFilter;
    bool bPeerMutexInitialized;
    pthread_mutex_t PeerMutex;
    IpsecProtectedApplicationPeer_t
        aPeers[IPSEC_PROTECTED_APPLICATION_PEER_CAPACITY];
    uint32_t uiPeerCount;
    char acTunName[IPSEC_DATAPATH_NAME_LENGTH];
    char acEgressName[IPSEC_DATAPATH_NAME_LENGTH];
} IpsecProtectedApplicationState_t;

IpsecError_t CreateIpsecProtectedApplicationEndpoint(IpsecContext_t *pContext,
    IpsecProtectedApplicationState_t *pState);
IpsecError_t InstallIpsecProtectedApplicationFilters(
    IpsecProtectedApplicationState_t *pState);
IpsecError_t InspectIpsecProtectedApplicationEndpoint(
    const IpsecProtectedApplicationState_t *pState);
void DestroyIpsecProtectedApplicationEndpoint(IpsecContext_t *pContext,
    IpsecProtectedApplicationState_t *pState);
IpsecError_t ReceiveIpsecProtectedApplicationPacket(
    IpsecProtectedApplicationState_t *pState,
    IpsecProtectedPacket_t *pPacket, uint32_t uiTimeoutMs);
IpsecError_t SubmitIpsecProtectedApplicationPacket(
    IpsecProtectedApplicationState_t *pState,
    const IpsecProtectedPacket_t *pPacket);
IpsecError_t InspectIpsecProtectedApplicationFilters(
    const IpsecProtectedApplicationState_t *pState, bool bRequireEmpty);
IpsecError_t RemoveIpsecProtectedApplicationFilters(
    IpsecProtectedApplicationState_t *pState);

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
