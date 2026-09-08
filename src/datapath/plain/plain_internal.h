#ifndef IPSEC_PLAIN_INTERNAL_H
#define IPSEC_PLAIN_INTERNAL_H

#include "plain_path_ops.h"

#include <pthread.h>

#define IPSEC_PLAIN_NETLINK_CAPACITY (IPSEC_PROTECTED_PACKET_CAPACITY + 4096U)
#define IPSEC_PLAIN_APPLICATION_PEER_CAPACITY 256U
#define IPSEC_PLAIN_NFT_NAME_LENGTH 32U

struct nlmsghdr;

typedef struct IpsecPlainApplicationPeer {
    char acConnectionName[IPSEC_NAME_LENGTH];
    uint32_t uiLocalNetwork;
    uint32_t uiRemoteNetwork;
    uint32_t uiLocalMask;
    uint32_t uiRemoteMask;
    bool bInUse;
} IpsecPlainApplicationPeer_t;

typedef struct IpsecPlainApplicationState {
    int32_t iQueueSocket;
    int32_t iRuleSocket;
    uint32_t uiSequence;
    uint32_t uiRuleSequence;
    uint32_t uiExpectedInterfaceIndex;
    uint16_t usQueueNumber;
    uint8_t *pucReceiveBuffer;
    size_t zReceiveCapacity;
    bool bQueueBound;
    bool bManageRule;
    bool bRuleTableOwned;
    bool bPeerMutexInitialized;
    pthread_mutex_t PeerMutex;
    IpsecPlainApplicationPeer_t
        aPeers[IPSEC_PLAIN_APPLICATION_PEER_CAPACITY];
    uint32_t uiPeerCount;
    char acRuleTableName[IPSEC_PLAIN_NFT_NAME_LENGTH];
    char acRuleChainName[IPSEC_PLAIN_NFT_NAME_LENGTH];
} IpsecPlainApplicationState_t;

IpsecError_t OpenIpsecPlainQueue(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState);
void CloseIpsecPlainQueue(IpsecPlainApplicationState_t *pState);
IpsecError_t ReceiveIpsecPlainQueuePacket(IpsecPlainApplicationState_t *pState,
    IpsecPlainPacket_t *pPacket, uint32_t uiTimeoutMs);
IpsecError_t ParseIpsecPlainQueueMessage(const struct nlmsghdr *pHeader,
    size_t zMessageLength, uint32_t uiExpectedInterfaceIndex,
    IpsecPlainPacket_t *pPacket, uint32_t *puiPacketId, bool *pbPacketId);
IpsecError_t InitializeIpsecPlainRules(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState);
void DeinitializeIpsecPlainRules(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState);
IpsecError_t RegisterIpsecPlainPeerInternal(IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig, bool *pbAdded);
IpsecError_t UnregisterIpsecPlainPeerInternal(IpsecContext_t *pContext,
    const char *pcConnectionName);
IpsecError_t BuildIpsecPlainRuleRequest(
    const IpsecPlainApplicationState_t *pState,
    const IpsecPlainApplicationPeer_t *pPeer,
    uint8_t *pucBuffer, size_t zCapacity, size_t *pzLength);

#endif
