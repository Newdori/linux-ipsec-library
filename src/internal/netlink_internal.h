#ifndef NETLINK_INTERNAL_H
#define NETLINK_INTERNAL_H

#include "ipsec_internal.h"

#include <linux/netlink.h>
#include <stddef.h>
#include <stdint.h>

#define IPSEC_NETLINK_TIMEOUT_MS 5000U
#define IPSEC_NETLINK_RECEIVE_LENGTH 65536U
#define IPSEC_NETLINK_MAX_REQUEST_PAYLOAD 512U

typedef IpsecError_t (*NetlinkMessageCallback_t)(
    const struct nlmsghdr *pHeader,
    void *pvUserData);

IpsecError_t ExecuteNetlinkDump(
    int32_t iProtocol,
    uint16_t usMessageType,
    const void *pvPayload,
    uint32_t uiPayloadLength,
    NetlinkMessageCallback_t pCallback,
    void *pvUserData);

#endif
