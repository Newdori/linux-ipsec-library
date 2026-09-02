#ifndef IPSEC_DATAPATH_OPS_H
#define IPSEC_DATAPATH_OPS_H

#include "../../internal/ipsec_internal.h"

typedef struct IpsecDatapathOps {
    IpsecDatapathType_t eType;
    IpsecError_t (*pProbe)(IpsecContext_t *pContext, IpsecDatapathStatus_t *pStatus);
    IpsecError_t (*pInitialize)(IpsecContext_t *pContext);
    IpsecError_t (*pGetStatus)(IpsecContext_t *pContext, IpsecDatapathStatus_t *pStatus);
    IpsecError_t (*pGetStatistics)(IpsecContext_t *pContext, IpsecTrafficStatistics_t *pStatistics);
    void (*pDeinitialize)(IpsecContext_t *pContext);
} IpsecDatapathOps_t;

const IpsecDatapathOps_t *GetXfrmDatapathOps(void);
IpsecError_t ValidateXfrmSoftwarePath(void);
const IpsecDatapathOps_t *GetKernelLibipsecDatapathOps(void);
IpsecError_t ConfigureIpsecDatapath(IpsecContext_t *pContext,
                                    const IpsecDatapathConfig_t *pConfig);
IpsecError_t InitializeIpsecDatapath(IpsecContext_t *pContext);
void DeinitializeIpsecDatapath(IpsecContext_t *pContext);
IpsecError_t RequireIpsecXfrmBackend(IpsecContext_t *pContext);
IpsecError_t ReadIpsecBackendPlugins(IpsecContext_t *pContext,
                                     IpsecDatapathStatus_t *pStatus);
/* Selection seam for deterministic tests; production supplies the real ops. */
IpsecError_t SelectIpsecDatapath(IpsecContext_t *pContext,
    const IpsecDatapathOps_t *pLibipsec, const IpsecDatapathOps_t *pXfrm);

#endif
