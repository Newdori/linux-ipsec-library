#ifndef XFRM_INTERNAL_H
#define XFRM_INTERNAL_H

#include "../../internal/netlink_internal.h"

#include <linux/xfrm.h>

IpsecError_t ParseXfrmStateMessage(
    const struct nlmsghdr *pHeader,
    void *pvUserData);

IpsecError_t ParseXfrmPolicyMessage(
    const struct nlmsghdr *pHeader,
    void *pvUserData);

IpsecError_t ParseXfrmStatisticsText(
    const char *pcText,
    size_t zTextLength,
    IpsecXfrmStatistics_t *pStatistics);

#endif
