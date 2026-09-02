#include "application_protected_filter.h"
#include "../../internal/netlink_internal.h"

#include <errno.h>
#include <limits.h>
#include <linux/pkt_sched.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

typedef struct IpsecProtectedApplicationInspection {
    const IpsecProtectedApplicationState_t *pState;
    bool bRequireEmpty;
    bool bClsact;
    uint32_t uiFilterMask;
} IpsecProtectedApplicationInspection_t;

static IpsecError_t InspectProtectedApplicationMessage(const struct nlmsghdr *pHeader, void *pvData)
{
    IpsecProtectedApplicationInspection_t *pInspection = (IpsecProtectedApplicationInspection_t *)pvData;
    const IpsecProtectedApplicationState_t *pState = pInspection->pState;
    struct tcmsg Tc;
    const uint8_t *pucKind;
    size_t zKind;
    IpsecError_t eError;
    if (pHeader->nlmsg_len < NLMSG_LENGTH(sizeof(Tc))) {
        return IPSEC_ERR_NETLINK_PARSE;
    }
    memcpy(&Tc, NLMSG_DATA(pHeader), sizeof(Tc));
    if ((uint32_t)Tc.tcm_ifindex != pState->uiEgressIndex) {
        return IPSEC_OK;
    }
    if (RTM_NEWQDISC == pHeader->nlmsg_type) {
        eError = FindIpsecProtectedApplicationAttribute(
            (const uint8_t *)NLMSG_DATA(pHeader) + NLMSG_ALIGN(sizeof(Tc)),
            pHeader->nlmsg_len - NLMSG_LENGTH(sizeof(Tc)), TCA_KIND, &pucKind, &zKind);
        if ((IPSEC_OK == eError) && (7U == zKind) && (0 == memcmp(pucKind, "clsact", 7U))) {
            const uint8_t *pucBlock;
            size_t zBlock;
            uint32_t uiBlock = 0U;
            eError = FindIpsecProtectedApplicationAttribute(
                (const uint8_t *)NLMSG_DATA(pHeader) + NLMSG_ALIGN(sizeof(Tc)),
                pHeader->nlmsg_len - NLMSG_LENGTH(sizeof(Tc)),
                TCA_EGRESS_BLOCK, &pucBlock, &zBlock);
            if (IPSEC_OK != eError) {
                return eError;
            }
            if (NULL != pucBlock) {
                if (sizeof(uiBlock) != zBlock) {
                    return IPSEC_ERR_NETLINK_PARSE;
                }
                memcpy(&uiBlock, pucBlock, sizeof(uiBlock));
            }
            if (0U != uiBlock) {
                /* A shared block would change other interfaces' egress too. */
                return IPSEC_ERR_RESOURCE_CONFLICT;
            }
            pInspection->bClsact = true;
        }
        return eError;
    }
    return InspectIpsecProtectedApplicationFilterMessage(pState, pHeader,
        pInspection->bRequireEmpty, &pInspection->uiFilterMask);
}

IpsecError_t InspectIpsecProtectedApplicationFilters(const IpsecProtectedApplicationState_t *pState, bool bRequireEmpty)
{
    IpsecProtectedApplicationInspection_t Inspection = {0};
    struct tcmsg Request = {0};
    IpsecError_t eError;
    Inspection.pState = pState;
    Inspection.bRequireEmpty = bRequireEmpty;
    Request.tcm_ifindex = (int32_t)pState->uiEgressIndex;
    eError = ExecuteNetlinkDump(NETLINK_ROUTE, RTM_GETQDISC, &Request,
        sizeof(Request), InspectProtectedApplicationMessage, &Inspection);
    if ((IPSEC_OK == eError) && !Inspection.bClsact) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    if (IPSEC_OK == eError) {
        Request.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
        eError = ExecuteNetlinkDump(NETLINK_ROUTE, RTM_GETTFILTER, &Request,
            sizeof(Request), InspectProtectedApplicationMessage, &Inspection);
    }
    if ((IPSEC_OK == eError) && !bRequireEmpty && (3U != Inspection.uiFilterMask)) {
        eError = IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    return eError;
}

static IpsecError_t MapProtectedApplicationNetlinkError(int32_t iError)
{
    if ((EPERM == iError) || (EACCES == iError)) {
        return IPSEC_ERR_PERMISSION;
    }
    if (EEXIST == iError) {
        return IPSEC_ERR_RESOURCE_CONFLICT;
    }
    if ((ENOENT == iError) || (ENODEV == iError)) {
        return IPSEC_ERR_INTERFACE_NOT_FOUND;
    }
    return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
}

static IpsecError_t ReceiveProtectedApplicationAck(int32_t iSocket, uint32_t uiSequence,
    bool bRemove, bool *pbOwned)
{
    union {
        max_align_t Alignment;
        uint8_t aucData[4096];
    } Reply;
    uint64_t ullDeadline = GetIpsecMonotonicMilliseconds() + IPSEC_NETLINK_TIMEOUT_MS;
    for (;;) {
        struct pollfd Descriptor = {.fd = iSocket, .events = POLLIN};
        struct sockaddr_nl Sender = {0};
        struct iovec Vector = {.iov_base = Reply.aucData, .iov_len = sizeof(Reply.aucData)};
        struct msghdr Message = {0};
        struct nlmsghdr Header;
        struct nlmsgerr Ack;
        uint64_t ullNow = GetIpsecMonotonicMilliseconds();
        uint64_t ullRemaining = (ullNow < ullDeadline) ? ullDeadline - ullNow : 0U;
        int32_t iResult = (int32_t)poll(&Descriptor, 1U, (int32_t)ullRemaining);
        ssize_t lLength;
        if ((iResult < 0) && (EINTR == errno) && (ullNow < ullDeadline)) {
            continue;
        }
        if ((iResult <= 0) || (0 == (Descriptor.revents & POLLIN))) {
            return IPSEC_ERR_NETLINK_RECV;
        }
        Message.msg_name = &Sender;
        Message.msg_namelen = sizeof(Sender);
        Message.msg_iov = &Vector;
        Message.msg_iovlen = 1U;
        lLength = recvmsg(iSocket, &Message, 0);
        if ((lLength < 0) && ((EINTR == errno) || (EAGAIN == errno)) && (ullNow < ullDeadline)) {
            continue;
        }
        if ((lLength < (ssize_t)NLMSG_LENGTH(sizeof(Ack))) ||
            (0 != (Message.msg_flags & MSG_TRUNC)) ||
            (Message.msg_namelen < sizeof(Sender)) || (0U != Sender.nl_pid)) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        memcpy(&Header, Reply.aucData, sizeof(Header));
        if ((Header.nlmsg_len > (uint32_t)lLength) ||
            (Header.nlmsg_len < NLMSG_LENGTH(sizeof(Ack))) ||
            (Header.nlmsg_seq != uiSequence) || (NLMSG_ERROR != Header.nlmsg_type)) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        memcpy(&Ack, Reply.aucData + NLMSG_HDRLEN, sizeof(Ack));
        if (0 == Ack.error) {
            *pbOwned = !bRemove;
            return IPSEC_OK;
        }
        if (Ack.error >= 0 || INT32_MIN == Ack.error) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        if (!bRemove) {
            /* A definite failed exclusive create did not acquire ownership. */
            *pbOwned = false;
        }
        else if ((-ENOENT == Ack.error) || (-ENODEV == Ack.error)) {
            *pbOwned = false;
            return IPSEC_OK; /* Idempotent cleanup. */
        }
        return MapProtectedApplicationNetlinkError(-Ack.error);
    }
}

static IpsecError_t ChangeProtectedApplicationFilter(const IpsecProtectedApplicationState_t *pState,
    bool bUdpDrop, bool bRemove, bool *pbOwned)
{
    IpsecProtectedApplicationMessage_t Request;
    struct nlmsghdr *pHeader = (struct nlmsghdr *)Request.aucData;
    struct sockaddr_nl Address = {0};
    int32_t iSocket;
    ssize_t lLength;
    IpsecError_t eError = BuildIpsecProtectedApplicationFilterRequest(pState, bUdpDrop, bRemove, &Request);
    if (IPSEC_OK != eError) {
        return eError;
    }
    iSocket = (int32_t)socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC | SOCK_NONBLOCK, NETLINK_ROUTE);
    if (iSocket < 0) {
        return MapProtectedApplicationNetlinkError(errno);
    }
    Address.nl_family = AF_NETLINK;
    if (0 != bind(iSocket, (const struct sockaddr *)&Address, sizeof(Address))) {
        eError = MapProtectedApplicationNetlinkError(errno);
    }
    else {
        pHeader->nlmsg_seq = (uint32_t)GetIpsecMonotonicMilliseconds();
        lLength = sendto(iSocket, Request.aucData, pHeader->nlmsg_len, 0,
            (const struct sockaddr *)&Address, sizeof(Address));
        if ((lLength < 0) || ((uint32_t)lLength != pHeader->nlmsg_len)) {
            eError = IPSEC_ERR_NETLINK_SEND;
        }
        else {
            if (!bRemove) {
                /* Unknown ACK outcome must be rolled back too. The OS/app
                 * reserves this exact priority/handle namespace exclusively.
                 */
                *pbOwned = true;
            }
            eError = ReceiveProtectedApplicationAck(iSocket, pHeader->nlmsg_seq, bRemove, pbOwned);
        }
    }
    (void)close(iSocket);
    return eError;
}

IpsecError_t InstallIpsecProtectedApplicationFilters(IpsecProtectedApplicationState_t *pState)
{
    IpsecError_t eError = InspectIpsecProtectedApplicationFilters(pState, true);
    /* Protect against unsupported NAT-T before making RAW ESP delivery live. */
    if (IPSEC_OK == eError) {
        eError = ChangeProtectedApplicationFilter(pState, true, false, &pState->bUdpFilter);
    }
    if (IPSEC_OK == eError) {
        eError = ChangeProtectedApplicationFilter(pState, false, false, &pState->bRawFilter);
    }
    if (IPSEC_OK == eError) {
        eError = InspectIpsecProtectedApplicationFilters(pState, false);
    }
    return eError;
}

IpsecError_t RemoveIpsecProtectedApplicationFilters(IpsecProtectedApplicationState_t *pState)
{
    IpsecError_t eFirst = IPSEC_OK;
    IpsecError_t eError;
    if (pState->bRawFilter) {
        eFirst = ChangeProtectedApplicationFilter(pState, false, true, &pState->bRawFilter);
    }
    if (pState->bUdpFilter) {
        eError = ChangeProtectedApplicationFilter(pState, true, true, &pState->bUdpFilter);
        if (IPSEC_OK == eFirst) {
            eFirst = eError;
        }
    }
    return eFirst;
}
