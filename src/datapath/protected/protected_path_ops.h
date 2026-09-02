#ifndef IPSEC_PROTECTED_PATH_OPS_H
#define IPSEC_PROTECTED_PATH_OPS_H

#include "../../internal/ipsec_internal.h"

typedef struct IpsecProtectedPathStatusInternal {
    bool bReady;
    uint32_t uiInterfaceIndex;
    char acInterfaceName[IPSEC_DATAPATH_NAME_LENGTH];
} IpsecProtectedPathStatusInternal_t;

typedef struct IpsecProtectedPathOps {
    IpsecError_t (*pInitialize)(IpsecContext_t *pContext);
    IpsecError_t (*pReceivePacket)(IpsecContext_t *pContext,
        IpsecProtectedPacket_t *pPacket, uint32_t uiTimeoutMs);
    IpsecError_t (*pSubmitPacket)(IpsecContext_t *pContext,
        const IpsecProtectedPacket_t *pPacket);
    IpsecError_t (*pGetStatus)(IpsecContext_t *pContext,
        IpsecProtectedPathStatusInternal_t *pStatus);
    void (*pDeinitialize)(IpsecContext_t *pContext);
} IpsecProtectedPathOps_t;

const IpsecProtectedPathOps_t *GetSystemProtectedPathOps(void);
const IpsecProtectedPathOps_t *GetApplicationProtectedPathOps(void);
IpsecError_t InitializeIpsecProtectedPath(IpsecContext_t *pContext);
void DeinitializeIpsecProtectedPath(IpsecContext_t *pContext);
IpsecError_t GetIpsecProtectedPathStatusInternal(IpsecContext_t *pContext,
    IpsecProtectedPathStatusInternal_t *pStatus);
IpsecError_t ValidateIpsecProtectedPacket(const IpsecProtectedPacket_t *pPacket);

#endif
