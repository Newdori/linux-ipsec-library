#ifndef IPSEC_APPLICATION_PROTECTED_FILTER_H
#define IPSEC_APPLICATION_PROTECTED_FILTER_H

#include "application_protected_internal.h"
#include <linux/filter.h>
#include <linux/rtnetlink.h>

#define IPSEC_PROTECTED_APPLICATION_FILTER_CAPACITY 32U
#define IPSEC_PROTECTED_APPLICATION_NETLINK_CAPACITY 2048U

typedef union IpsecProtectedApplicationMessage {
    max_align_t Alignment;
    uint8_t aucData[IPSEC_PROTECTED_APPLICATION_NETLINK_CAPACITY];
} IpsecProtectedApplicationMessage_t;

uint16_t BuildIpsecProtectedApplicationProgram(const IpsecProtectedApplicationState_t *pState,
    bool bUdpDrop, struct sock_filter *pProgram);
IpsecError_t BuildIpsecProtectedApplicationFilterRequest(const IpsecProtectedApplicationState_t *pState,
    bool bUdpDrop, bool bRemove, IpsecProtectedApplicationMessage_t *pMessage);
IpsecError_t ValidateIpsecProtectedApplicationFilter(const IpsecProtectedApplicationState_t *pState,
    const struct nlmsghdr *pHeader, bool bUdpDrop);
IpsecError_t InspectIpsecProtectedApplicationFilterMessage(const IpsecProtectedApplicationState_t *pState,
    const struct nlmsghdr *pHeader, bool bRequireEmpty, uint32_t *puiFilterMask);
IpsecError_t FindIpsecProtectedApplicationAttribute(const uint8_t *pucData, size_t zLength,
    uint16_t usType, const uint8_t **ppucValue, size_t *pzLength);

#endif
