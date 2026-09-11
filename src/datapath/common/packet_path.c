#include "../protected/protected_path_ops.h"
#include "../plain/plain_path_ops.h"

#include <string.h>

IpsecError_t GetIpsecPacketPathStatus(IpsecContext_t *pContext,
    IpsecPacketPathStatus_t *pStatus)
{
    IpsecProtectedPathStatusInternal_t Protected = {0};
    IpsecPlainPathStatusInternal_t Plain = {0};
    IpsecError_t eError;
    if ((NULL == pContext) || (NULL == pStatus) ||
        (sizeof(*pStatus) != pStatus->uiStructSize)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pStatus, 0, sizeof(*pStatus));
    pStatus->uiStructSize = sizeof(*pStatus);
    pStatus->eProtectedPacketPath =
        pContext->Datapath.Config.eProtectedPacketPath;
    pStatus->ePlainPacketPath = pContext->Datapath.Config.ePlainPacketPath;
    eError = GetIpsecProtectedPathStatusInternal(pContext, &Protected);
    if (IPSEC_OK == eError) {
        pStatus->bProtectedPathReady = Protected.bReady;
        pStatus->uiProtectedInterfaceIndex = Protected.uiInterfaceIndex;
        memcpy(pStatus->acProtectedInterfaceName, Protected.acInterfaceName,
               sizeof(pStatus->acProtectedInterfaceName));
        eError = GetIpsecPlainPathStatusInternal(pContext, &Plain);
    }
    if (IPSEC_OK == eError) {
        pStatus->bPlainPathReady = Plain.bReady;
        pStatus->uiPlainInterfaceIndex = Plain.uiInterfaceIndex;
        memcpy(pStatus->acPlainInterfaceName, Plain.acInterfaceName,
               sizeof(pStatus->acPlainInterfaceName));
        pStatus->usPlainQueueNumber = Plain.usQueueNumber;
    }
    return eError;
}
