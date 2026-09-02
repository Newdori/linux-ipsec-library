#include "ipsec.h"

int main()
{
    IpsecContext_t *pContext = nullptr;
    IpsecConfig_t Config = {};
    IpsecDatapathConfig_t Datapath = {};
    IpsecProtectedPacket_t Protected = {};
    IpsecPlainPacket_t Plain = {};
    IpsecPacketPathStatus_t PathStatus = {};

    Config.uiStructSize = sizeof(Config);
    (void)pContext;
    (void)Config;
    (void)Datapath;
    (void)Protected;
    (void)Plain;
    (void)PathStatus;
    return 0;
}
