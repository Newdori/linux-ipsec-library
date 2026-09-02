#ifndef IPSEC_PLAIN_INTERNAL_H
#define IPSEC_PLAIN_INTERNAL_H

#include "plain_path_ops.h"

#define IPSEC_PLAIN_NETLINK_CAPACITY (IPSEC_PROTECTED_PACKET_CAPACITY + 4096U)

struct nlmsghdr;

typedef struct IpsecPlainApplicationState {
    int32_t iQueueSocket;
    uint32_t uiSequence;
    uint32_t uiExpectedInterfaceIndex;
    uint16_t usQueueNumber;
    uint8_t *pucReceiveBuffer;
    size_t zReceiveCapacity;
    bool bQueueBound;
} IpsecPlainApplicationState_t;

IpsecError_t OpenIpsecPlainQueue(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState);
void CloseIpsecPlainQueue(IpsecPlainApplicationState_t *pState);
IpsecError_t ReceiveIpsecPlainQueuePacket(IpsecPlainApplicationState_t *pState,
    IpsecPlainPacket_t *pPacket, uint32_t uiTimeoutMs);
IpsecError_t ParseIpsecPlainQueueMessage(const struct nlmsghdr *pHeader,
    size_t zMessageLength, uint32_t uiExpectedInterfaceIndex,
    IpsecPlainPacket_t *pPacket, uint32_t *puiPacketId, bool *pbPacketId);

#endif
