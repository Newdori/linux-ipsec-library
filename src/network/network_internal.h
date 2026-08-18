#ifndef NETWORK_INTERNAL_H
#define NETWORK_INTERNAL_H

#include "../internal/netlink_internal.h"

IpsecError_t ParseInterfaceMessage(
    const struct nlmsghdr *pHeader,
    void *pvUserData);

IpsecError_t ParseAddressMessage(
    const struct nlmsghdr *pHeader,
    void *pvUserData);

IpsecError_t ParseRouteMessage(
    const struct nlmsghdr *pHeader,
    void *pvUserData);

#endif
