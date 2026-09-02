#ifndef IPSEC_PLAIN_PATH_OPS_H
#define IPSEC_PLAIN_PATH_OPS_H

#include "../../internal/ipsec_internal.h"

typedef struct IpsecPlainPathStatusInternal {
    bool bReady;
    uint32_t uiInterfaceIndex;
    char acInterfaceName[IPSEC_DATAPATH_NAME_LENGTH];
    uint16_t usQueueNumber;
} IpsecPlainPathStatusInternal_t;

typedef struct IpsecPlainPathOps {
    IpsecError_t (*pInitialize)(IpsecContext_t *pContext);
    IpsecError_t (*pReceivePacket)(IpsecContext_t *pContext,
        IpsecPlainPacket_t *pPacket, uint32_t uiTimeoutMs);
    IpsecError_t (*pGetStatus)(IpsecContext_t *pContext,
        IpsecPlainPathStatusInternal_t *pStatus);
    void (*pDeinitialize)(IpsecContext_t *pContext);
} IpsecPlainPathOps_t;

const IpsecPlainPathOps_t *GetSystemPlainPathOps(void);
const IpsecPlainPathOps_t *GetApplicationPlainPathOps(void);
IpsecError_t InitializeIpsecPlainPath(IpsecContext_t *pContext);
void DeinitializeIpsecPlainPath(IpsecContext_t *pContext);
IpsecError_t GetIpsecPlainPathStatusInternal(IpsecContext_t *pContext,
    IpsecPlainPathStatusInternal_t *pStatus);

#endif
