#ifndef KERNEL_LIBIPSEC_INTERNAL_H
#define KERNEL_LIBIPSEC_INTERNAL_H

#include "../common/datapath_ops.h"
#include "../../internal/netlink_internal.h"

#define IPSEC_TUN_CANDIDATE_LIMIT 128U

typedef struct IpsecTunCandidate {
    char acName[IPSEC_DATAPATH_NAME_LENGTH];
    uint32_t uiIndex;
    bool bUp;
    bool bTun;
    uint32_t uiRouteCount;
} IpsecTunCandidate_t;

typedef struct IpsecTunCandidates {
    IpsecTunCandidate_t aItems[IPSEC_TUN_CANDIDATE_LIMIT];
    uint32_t uiCount;
} IpsecTunCandidates_t;

IpsecError_t ParseIpsecTunMessage(const struct nlmsghdr *pHeader, void *pvData);
IpsecError_t SelectIpsecTun(const IpsecTunCandidates_t *pCandidates,
    const char *pcRequestedName, const char *pcExcludedName, IpsecDatapathStatus_t *pStatus);
IpsecError_t InspectKernelLibipsecDatapath(IpsecContext_t *pContext,
                                          IpsecDatapathStatus_t *pStatus);

#endif
