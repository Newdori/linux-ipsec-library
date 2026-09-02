#include "../common/datapath_ops.h"
#include "xfrm_internal.h"
#include "../../internal/netlink_internal.h"

#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/xfrm.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

IpsecError_t InspectXfrmOffload(const struct nlmsghdr *pHeader, void *pvData)
{
    const uint8_t *pucData;
    size_t zLength;
    (void)pvData;
    if ((XFRM_MSG_NEWSA != pHeader->nlmsg_type) ||
        (pHeader->nlmsg_len < NLMSG_LENGTH(sizeof(struct xfrm_usersa_info)))) {
        return IPSEC_ERR_NETLINK_PARSE;
    }
    pucData = (const uint8_t *)NLMSG_DATA(pHeader) + NLMSG_ALIGN(sizeof(struct xfrm_usersa_info));
    zLength = pHeader->nlmsg_len - NLMSG_LENGTH(sizeof(struct xfrm_usersa_info));
    while (zLength > 0U) {
        struct rtattr Attribute;
        size_t zStep;
        if (zLength < sizeof(Attribute)) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        memcpy(&Attribute, pucData, sizeof(Attribute));
        zStep = RTA_ALIGN(Attribute.rta_len);
        if ((Attribute.rta_len < sizeof(Attribute)) || (zStep > zLength)) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        if (XFRMA_OFFLOAD_DEV == (Attribute.rta_type & NLA_TYPE_MASK)) {
            /* NIC offload can encrypt AFTER the TC egress hook. A raw-looking
             * skb is then not proof that ciphertext has been produced.
             */
            return IPSEC_ERR_NOT_SUPPORTED;
        }
        pucData += zStep;
        zLength -= zStep;
    }
    return IPSEC_OK;
}

IpsecError_t ValidateXfrmSoftwarePath(void)
{
    struct xfrm_usersa_id Request = {0};
    Request.family = AF_UNSPEC;
    return ExecuteNetlinkDump(NETLINK_XFRM, XFRM_MSG_GETSA, &Request,
        sizeof(Request), InspectXfrmOffload, NULL);
}

static IpsecError_t ProbeXfrmBackend(IpsecContext_t *pContext,
                                     IpsecDatapathStatus_t *pStatus)
{
    int32_t iSocket;
    struct sockaddr_nl Address = {0};
    IpsecError_t eError = ReadIpsecBackendPlugins(pContext, pStatus);
    pStatus->eType = IPSEC_DATAPATH_KERNEL_XFRM;
    if (IPSEC_OK != eError) {
        return eError;
    }
    if (pStatus->bKernelLibipsecLoaded) {
        return IPSEC_ERR_BACKEND_MISMATCH;
    }
    if (!pStatus->bKernelNetlinkLoaded) {
        return IPSEC_ERR_DATAPATH_UNAVAILABLE;
    }
    iSocket = (int32_t)socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_XFRM);
    if (iSocket < 0) {
        return ((EPERM == errno) || (EACCES == errno)) ?
            IPSEC_ERR_PERMISSION : IPSEC_ERR_DATAPATH_UNAVAILABLE;
    }
    Address.nl_family = AF_NETLINK;
    if (0 != bind(iSocket, (const struct sockaddr *)&Address, sizeof(Address))) {
        eError = ((EPERM == errno) || (EACCES == errno)) ?
            IPSEC_ERR_PERMISSION : IPSEC_ERR_DATAPATH_UNAVAILABLE;
    }
    (void)close(iSocket);
    pStatus->bReady = IPSEC_OK == eError;
    return eError;
}

static IpsecError_t InitializeXfrmBackend(IpsecContext_t *pContext)
{
    (void)pContext;
    return IPSEC_OK;
}

static void DeinitializeXfrmBackend(IpsecContext_t *pContext)
{
    (void)pContext; /* charon owns all SAs/policies. */
}

static IpsecError_t GetXfrmBackendStatistics(IpsecContext_t *pContext,
                                             IpsecTrafficStatistics_t *pStatistics)
{
    IpsecXfrmStateList_t States = {0};
    IpsecError_t eError = GetIpsecXfrmStates(pContext, &States);
    uint32_t uiIndex;
    for (uiIndex = 0U; (IPSEC_OK == eError) && (uiIndex < States.uiCount); uiIndex++) {
        const IpsecXfrmStateInfo_t *pState = &States.pItems[uiIndex];
        if ((pState->ullPacketCount > UINT64_MAX - pStatistics->ullPackets) ||
            (pState->ullByteCount > UINT64_MAX - pStatistics->ullBytes)) {
            eError = IPSEC_ERR_INTERNAL;
        }
        else {
            pStatistics->ullPackets += pState->ullPacketCount;
            pStatistics->ullBytes += pState->ullByteCount;
        }
    }
    pStatistics->uiSaCount = States.uiCount;
    pStatistics->bCountersValid = IPSEC_OK == eError;
    FreeIpsecXfrmStateList(&States);
    return eError;
}

const IpsecDatapathOps_t *GetXfrmDatapathOps(void)
{
    static const IpsecDatapathOps_t Ops = {
        IPSEC_DATAPATH_KERNEL_XFRM, ProbeXfrmBackend, InitializeXfrmBackend,
        ProbeXfrmBackend, GetXfrmBackendStatistics, DeinitializeXfrmBackend
    };
    return &Ops;
}
