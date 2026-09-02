#include "ipsec.h"

#include <string.h>

int main(void)
{
    IpsecIkeSaList_t List = {0};
    IpsecDiagnostic_t Diagnostic = {0};
    IpsecDatapathStatusEx_t Status = {.uiStructSize = sizeof(Status)};
    IpsecPacketPathStatus_t PathStatus = {.uiStructSize = sizeof(PathStatus)};
    IpsecProtectedPacket_t Protected = {.uiStructSize = sizeof(Protected)};
    IpsecPlainPacket_t Plain = {.uiStructSize = sizeof(Plain)};
    IpsecContext_t *pContext = NULL;

    FreeIpsecIkeSaList(&List);
    Diagnostic.uiStructSize = sizeof(Diagnostic);
    if ((0 != strcmp("success", GetIpsecErrorString(IPSEC_OK))) ||
        (IPSEC_ERR_INVALID_ARGUMENT != CancelIpsecWaits(NULL)) ||
        (IPSEC_ERR_INVALID_ARGUMENT != GetIpsecLastDiagnostic(NULL, &Diagnostic)) ||
        (IPSEC_ERR_INVALID_ARGUMENT != GetIpsecDatapathStatusEx(NULL, &Status)) ||
        (IPSEC_ERR_INVALID_ARGUMENT != GetIpsecPacketPathStatus(NULL, &PathStatus)) ||
        (IPSEC_ERR_INVALID_ARGUMENT != ReceiveIpsecProtectedPacket(NULL, &Protected, 0U)) ||
        (IPSEC_ERR_INVALID_ARGUMENT != SubmitIpsecProtectedPacket(NULL, &Protected)) ||
        (IPSEC_ERR_INVALID_ARGUMENT != ReceiveIpsecPlainPacket(NULL, &Plain, 0U)) ||
        (IPSEC_ERR_INVALID_ARGUMENT != InitializeIpsecWithDatapath(NULL, NULL, NULL))) {
        return 1;
    }
    (void)pContext;
    return 0;
}
