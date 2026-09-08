#include "../../src/datapath/common/datapath_ops.h"
#include "../../src/datapath/protected/application_protected_internal.h"
#include "../../src/datapath/plain/plain_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); exit(1); \
} } while (0)

static IpsecError_t geLibProbe;
static IpsecError_t geXfrmProbe;
static IpsecError_t geBackendInitialize;
static IpsecError_t geEndpointCreate;
static IpsecError_t geFilterInstall;
static IpsecError_t gePlainOpen;
static uint32_t guiBackendCleanup;
static uint32_t guiEndpointCleanup;
static uint32_t guiPlainCleanup;
static uint32_t guiSubmissions;
static uint32_t guiChildren;
static bool gbLibLoaded;
static bool gbControlBeforeEsp;
static bool gbMalformedControl;
static uint32_t guiProtectedReceives;

uint64_t GetIpsecMonotonicMilliseconds(void)
{
    static uint64_t gullNow = 1000U;
    return gullNow++;
}

static IpsecError_t ProbeTestLib(IpsecContext_t *pContext,
    IpsecDatapathStatus_t *pStatus)
{
    (void)pContext;
    pStatus->eType = IPSEC_DATAPATH_KERNEL_LIBIPSEC;
    pStatus->bReady = IPSEC_OK == geLibProbe;
    pStatus->bKernelLibipsecLoaded = true;
    pStatus->uiTunInterfaceIndex = 9U;
    pStatus->uiTunRouteCount = 1U;
    memcpy(pStatus->acTunInterfaceName, "custom-tun", 11U);
    return geLibProbe;
}

static IpsecError_t ProbeTestXfrm(IpsecContext_t *pContext,
    IpsecDatapathStatus_t *pStatus)
{
    (void)pContext;
    pStatus->eType = IPSEC_DATAPATH_KERNEL_XFRM;
    pStatus->bReady = IPSEC_OK == geXfrmProbe;
    return geXfrmProbe;
}

static IpsecError_t InitializeTestBackend(IpsecContext_t *pContext)
{
    (void)pContext;
    return geBackendInitialize;
}

static void DeinitializeTestBackend(IpsecContext_t *pContext)
{
    CHECK(NULL == pContext->pProtectedApplicationState);
    CHECK(NULL == pContext->pPlainApplicationState);
    guiBackendCleanup++;
}

static IpsecError_t GetTestStatistics(IpsecContext_t *pContext,
    IpsecTrafficStatistics_t *pStatistics)
{
    if (IPSEC_DATAPATH_KERNEL_LIBIPSEC == pContext->eActiveDatapath) {
        return IPSEC_ERR_NOT_SUPPORTED;
    }
    pStatistics->bCountersValid = true;
    pStatistics->ullPackets = 17U;
    return IPSEC_OK;
}

const IpsecDatapathOps_t *GetKernelLibipsecDatapathOps(void)
{
    static const IpsecDatapathOps_t Ops = {IPSEC_DATAPATH_KERNEL_LIBIPSEC,
        ProbeTestLib, InitializeTestBackend, ProbeTestLib,
        GetTestStatistics, DeinitializeTestBackend};
    return &Ops;
}

const IpsecDatapathOps_t *GetXfrmDatapathOps(void)
{
    static const IpsecDatapathOps_t Ops = {IPSEC_DATAPATH_KERNEL_XFRM,
        ProbeTestXfrm, InitializeTestBackend, ProbeTestXfrm,
        GetTestStatistics, DeinitializeTestBackend};
    return &Ops;
}

IpsecError_t GetIpsecDaemonStatus(IpsecContext_t *pContext,
    IpsecDaemonStatus_t *pStatus)
{
    (void)pContext;
    pStatus->bKernelLibipsecLoaded = gbLibLoaded;
    pStatus->bKernelNetlinkLoaded = true;
    return IPSEC_OK;
}

IpsecError_t GetIpsecXfrmStatistics(IpsecXfrmStatistics_t *pStatistics)
{
    pStatistics->ullPresentMask = 1U;
    return IPSEC_OK;
}

IpsecError_t GetIpsecChildSas(IpsecContext_t *pContext,
    IpsecChildSaList_t *pList)
{
    (void)pContext;
    if (0U != guiChildren) {
        pList->pItems = (IpsecChildSaInfo_t *)calloc(1U, sizeof(*pList->pItems));
        CHECK(NULL != pList->pItems);
        pList->uiCount = 1U;
        memcpy(pList->pItems[0].acState, "INSTALLED", 10U);
        memcpy(pList->pItems[0].acIkeName, "vpn", 4U);
    }
    return IPSEC_OK;
}

void FreeIpsecChildSaList(IpsecChildSaList_t *pList)
{
    free(pList->pItems);
    memset(pList, 0, sizeof(*pList));
}

IpsecError_t GetIpsecIkeSas(IpsecContext_t *pContext,
    IpsecIkeSaList_t *pList)
{
    (void)pContext;
    pList->pItems = (IpsecIkeSaInfo_t *)calloc(1U, sizeof(*pList->pItems));
    CHECK(NULL != pList->pItems);
    pList->uiCount = 1U;
    memcpy(pList->pItems[0].acName, "vpn", 4U);
    memcpy(pList->pItems[0].acLocalAddress, "192.0.2.1", 10U);
    memcpy(pList->pItems[0].acRemoteAddress, "192.0.2.2", 10U);
    return IPSEC_OK;
}

void FreeIpsecIkeSaList(IpsecIkeSaList_t *pList)
{
    free(pList->pItems);
    memset(pList, 0, sizeof(*pList));
}

IpsecError_t CreateIpsecProtectedApplicationEndpoint(IpsecContext_t *pContext,
    IpsecProtectedApplicationState_t *pState)
{
    (void)pContext;
    pState->iTunFd = 42;
    pState->uiTunIndex = 15U;
    pState->uiEgressIndex = 2U;
    return geEndpointCreate;
}

IpsecError_t InstallIpsecProtectedApplicationFilters(
    IpsecProtectedApplicationState_t *pState)
{
    pState->bUdpFilter = true;
    pState->bRawFilter = IPSEC_OK == geFilterInstall;
    return geFilterInstall;
}

IpsecError_t InspectIpsecProtectedApplicationEndpoint(
    const IpsecProtectedApplicationState_t *pState)
{
    return (pState->iTunFd >= 0) ?
        IPSEC_OK : IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
}

IpsecError_t InspectIpsecProtectedApplicationFilters(
    const IpsecProtectedApplicationState_t *pState, bool bRequireEmpty)
{
    if (bRequireEmpty) {
        return IPSEC_OK;
    }
    return (pState->bRawFilter && pState->bUdpFilter) ?
        IPSEC_OK : IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
}

IpsecError_t RemoveIpsecProtectedApplicationFilters(
    IpsecProtectedApplicationState_t *pState)
{
    pState->bRawFilter = false;
    pState->bUdpFilter = false;
    return IPSEC_OK;
}

const char *GetIpsecErrorString(IpsecError_t eError)
{
    (void)eError;
    return "test error";
}

void LogIpsec(const IpsecContext_t *pContext, IpsecLogLevel_t eLevel,
    const char *pcFormat, ...)
{
    (void)pContext;
    (void)eLevel;
    (void)pcFormat;
}

void DestroyIpsecProtectedApplicationEndpoint(IpsecContext_t *pContext,
    IpsecProtectedApplicationState_t *pState)
{
    (void)pContext;
    pState->iTunFd = -1;
    pState->bRawFilter = false;
    pState->bUdpFilter = false;
    guiEndpointCleanup++;
}

static void SetTestChecksum(uint8_t *pucData)
{
    uint32_t uiSum = 0U;
    uint32_t uiIndex;
    pucData[10] = 0U;
    pucData[11] = 0U;
    for (uiIndex = 0U; uiIndex < 20U; uiIndex += 2U) {
        uiSum += ((uint32_t)pucData[uiIndex] << 8U) | pucData[uiIndex + 1U];
    }
    while (uiSum > UINT16_MAX) {
        uiSum = (uiSum & UINT16_MAX) + (uiSum >> 16U);
    }
    uiSum = (~uiSum) & UINT16_MAX;
    pucData[10] = (uint8_t)(uiSum >> 8U);
    pucData[11] = (uint8_t)uiSum;
}

static void SetTestIcmpv6Checksum(uint8_t *pucData, size_t zLength)
{
    const size_t zOffset = 40U;
    const size_t zIcmpLength = zLength - zOffset;
    uint32_t uiSum = (uint32_t)zIcmpLength + 58U;
    size_t zIndex;

    pucData[zOffset + 2U] = 0U;
    pucData[zOffset + 3U] = 0U;
    for (zIndex = 8U; zIndex < 40U; zIndex += 2U) {
        uiSum += ((uint32_t)pucData[zIndex] << 8U) | pucData[zIndex + 1U];
    }
    for (zIndex = zOffset; zIndex < zLength; zIndex += 2U) {
        uiSum += (uint32_t)pucData[zIndex] << 8U;
        if (zIndex + 1U < zLength) {
            uiSum += pucData[zIndex + 1U];
        }
    }
    while (uiSum > UINT16_MAX) {
        uiSum = (uiSum & UINT16_MAX) + (uiSum >> 16U);
    }
    uiSum = (~uiSum) & UINT16_MAX;
    pucData[zOffset + 2U] = (uint8_t)(uiSum >> 8U);
    pucData[zOffset + 3U] = (uint8_t)uiSum;
}

static void BuildTestRouterSolicitation(uint8_t *pucData)
{
    memset(pucData, 0, 48U);
    pucData[0] = 0x60U;
    pucData[5] = 8U;
    pucData[6] = 58U;
    pucData[7] = 255U;
    pucData[8] = 0xfeU;
    pucData[9] = 0x80U;
    pucData[23] = 1U;
    pucData[24] = 0xffU;
    pucData[25] = 2U;
    pucData[39] = 2U;
    pucData[40] = 133U;
    SetTestIcmpv6Checksum(pucData, 48U);
}

IpsecError_t ReceiveIpsecProtectedApplicationPacket(
    IpsecProtectedApplicationState_t *pState,
    IpsecProtectedPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    uint32_t uiLocalAddress = pState->uiLocalAddress;
    uint32_t uiRemoteAddress = pState->uiRemoteAddress;
    uint32_t uiIndex;

    (void)uiTimeoutMs;
    guiProtectedReceives++;
    if (gbControlBeforeEsp && (1U == guiProtectedReceives)) {
        BuildTestRouterSolicitation(pPacket->pucData);
        if (gbMalformedControl) {
            pPacket->pucData[42] ^= 1U;
        }
        pPacket->zLength = 48U;
        return IPSEC_OK;
    }
    memset(pPacket->pucData, 0, 40U);
    pPacket->pucData[0] = 0x45U;
    pPacket->pucData[3] = 40U;
    pPacket->pucData[8] = 64U;
    pPacket->pucData[9] = 50U;
    pPacket->pucData[23] = 1U;
    if (0U == uiRemoteAddress) {
        for (uiIndex = 0U;
             uiIndex < IPSEC_PROTECTED_APPLICATION_PEER_CAPACITY;
             uiIndex++) {
            if (pState->aPeers[uiIndex].bInUse) {
                uiLocalAddress = pState->aPeers[uiIndex].uiLocalAddress;
                uiRemoteAddress = pState->aPeers[uiIndex].uiRemoteAddress;
                break;
            }
            else {
                /* Find the first registered dynamic peer. */
            }
        }
    }
    memcpy(pPacket->pucData + 12U, &uiLocalAddress, 4U);
    memcpy(pPacket->pucData + 16U, &uiRemoteAddress, 4U);
    SetTestChecksum(pPacket->pucData);
    pPacket->zLength = 40U;
    return IPSEC_OK;
}

IpsecError_t SubmitIpsecProtectedApplicationPacket(
    IpsecProtectedApplicationState_t *pState,
    const IpsecProtectedPacket_t *pPacket)
{
    (void)pState;
    CHECK(40U == pPacket->zLength);
    guiSubmissions++;
    return IPSEC_OK;
}

IpsecError_t OpenIpsecPlainQueue(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState)
{
    (void)pContext;
    if (IPSEC_OK == gePlainOpen) {
        pState->iQueueSocket = 43;
        pState->bQueueBound = true;
    }
    return gePlainOpen;
}

void CloseIpsecPlainQueue(IpsecPlainApplicationState_t *pState)
{
    pState->iQueueSocket = -1;
    pState->bQueueBound = false;
    guiPlainCleanup++;
}

IpsecError_t InitializeIpsecPlainRules(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState)
{
    (void)pContext;
    (void)pState;
    return IPSEC_OK;
}

void DeinitializeIpsecPlainRules(IpsecContext_t *pContext,
    IpsecPlainApplicationState_t *pState)
{
    (void)pContext;
    (void)pState;
}

IpsecError_t ReceiveIpsecPlainQueuePacket(IpsecPlainApplicationState_t *pState,
    IpsecPlainPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    (void)pState;
    (void)uiTimeoutMs;
    memset(pPacket->pucData, 0, 20U);
    pPacket->pucData[0] = 0x45U;
    pPacket->pucData[3] = 20U;
    pPacket->zLength = 20U;
    pPacket->eFamily = IPSEC_ADDRESS_FAMILY_IPV4;
    pPacket->eDirection = IPSEC_PACKET_DIRECTION_INBOUND;
    return IPSEC_OK;
}

static IpsecDatapathConfig_t CreateTestConfig(
    IpsecDatapathPreference_t ePreference,
    IpsecPacketPathMode_t eProtected,
    IpsecPacketPathMode_t ePlain)
{
    IpsecDatapathConfig_t Config = {.uiStructSize = sizeof(Config)};
    Config.ePreference = ePreference;
    Config.eProtectedPacketPath = eProtected;
    Config.ePlainPacketPath = ePlain;
    Config.usPlainQueueNumber = 32002U;
    memcpy(Config.acProtectedInterfaceName, "path-test", 10U);
    memcpy(Config.acProtectedEgressInterfaceName, "eth-test", 9U);
    memcpy(Config.acProtectedLocalAddress, "192.0.2.1", 10U);
    memcpy(Config.acProtectedRemoteAddress, "192.0.2.2", 10U);
    return Config;
}

static void VerifyCombination(IpsecDatapathPreference_t ePreference,
    IpsecPacketPathMode_t eProtected, IpsecPacketPathMode_t ePlain)
{
    IpsecContext_t Context = {0};
    IpsecDatapathConfig_t Config = CreateTestConfig(ePreference, eProtected, ePlain);
    IpsecDatapathStatusEx_t Status = {.uiStructSize = sizeof(Status)};
    IpsecTrafficStatistics_t Statistics = {.uiStructSize = sizeof(Statistics)};
    IpsecXfrmStatistics_t XfrmStatistics = {0};
    uint8_t aucPacket[IPSEC_PROTECTED_PACKET_CAPACITY];
    IpsecProtectedPacket_t Protected = {.uiStructSize = sizeof(Protected),
        .pucData = aucPacket, .zCapacity = sizeof(aucPacket)};
    IpsecPlainPacket_t Plain = {.uiStructSize = sizeof(Plain),
        .pucData = aucPacket, .zCapacity = sizeof(aucPacket)};
    uint32_t uiEndpointBefore = guiEndpointCleanup;
    uint32_t uiPlainBefore = guiPlainCleanup;
    bool bLib = IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC == ePreference;
    CHECK(IPSEC_OK == ConfigureIpsecDatapath(&Context, &Config));
    CHECK(IPSEC_OK == InitializeIpsecDatapath(&Context));
    CHECK(IPSEC_OK == InitializeIpsecProtectedPath(&Context));
    CHECK(IPSEC_OK == InitializeIpsecPlainPath(&Context));
    CHECK(IPSEC_OK == GetIpsecDatapathStatusEx(&Context, &Status));
    CHECK(Status.bBackendReady && Status.bProtectedPathReady &&
          Status.bPlainPathReady && !Status.bTrafficReady);
    guiChildren = 1U;
    CHECK(IPSEC_OK == GetIpsecDatapathStatusEx(&Context, &Status));
    CHECK(Status.bTrafficReady);
    guiChildren = 0U;
    CHECK((bLib ? IPSEC_ERR_NOT_SUPPORTED : IPSEC_OK) ==
        GetIpsecTrafficStatistics(&Context, &Statistics));
    CHECK(Statistics.bCountersValid == !bLib);
    CHECK((bLib ? IPSEC_ERR_BACKEND_MISMATCH : IPSEC_OK) ==
        GetIpsecBackendXfrmStatistics(&Context, &XfrmStatistics));
    if (IPSEC_PACKET_PATH_SYSTEM == eProtected) {
        CHECK(IPSEC_ERR_PACKET_PATH_MISMATCH ==
            ReceiveIpsecProtectedPacket(&Context, &Protected, 0U));
        CHECK(IPSEC_ERR_PACKET_PATH_MISMATCH ==
            SubmitIpsecProtectedPacket(&Context, &Protected));
    }
    else {
        CHECK(IPSEC_OK == ReceiveIpsecProtectedPacket(&Context, &Protected, 1U));
        CHECK(IPSEC_PACKET_DIRECTION_OUTBOUND == Protected.eDirection);
        CHECK(IPSEC_ERR_INVALID_ARGUMENT ==
            SubmitIpsecProtectedPacket(&Context, &Protected));
        Protected.eDirection = IPSEC_PACKET_DIRECTION_INBOUND;
        aucPacket[15] = 2U;
        aucPacket[19] = 1U;
        SetTestChecksum(aucPacket);
        CHECK(IPSEC_OK == SubmitIpsecProtectedPacket(&Context, &Protected));
    }
    if (IPSEC_PACKET_PATH_SYSTEM == ePlain) {
        CHECK(IPSEC_ERR_PACKET_PATH_MISMATCH ==
            ReceiveIpsecPlainPacket(&Context, &Plain, 0U));
    }
    else {
        CHECK(IPSEC_OK == ReceiveIpsecPlainPacket(&Context, &Plain, 1U));
        CHECK((20U == Plain.zLength) &&
              (IPSEC_ADDRESS_FAMILY_IPV4 == Plain.eFamily));
    }
    DeinitializeIpsecPlainPath(&Context);
    DeinitializeIpsecPlainPath(&Context);
    DeinitializeIpsecProtectedPath(&Context);
    DeinitializeIpsecProtectedPath(&Context);
    DeinitializeIpsecDatapath(&Context);
    DeinitializeIpsecDatapath(&Context);
    CHECK(guiEndpointCleanup == uiEndpointBefore +
        ((IPSEC_PACKET_PATH_APPLICATION == eProtected) ? 1U : 0U));
    CHECK(guiPlainCleanup == uiPlainBefore +
        ((IPSEC_PACKET_PATH_APPLICATION == ePlain) ? 1U : 0U));
}

static void VerifyFailures(void)
{
    IpsecContext_t Context = {0};
    IpsecDatapathConfig_t Config = CreateTestConfig(
        IPSEC_DATAPATH_PREFER_AUTO, IPSEC_PACKET_PATH_APPLICATION,
        IPSEC_PACKET_PATH_APPLICATION);
    uint32_t uiBefore;
    CHECK(IPSEC_OK == ConfigureIpsecDatapath(&Context, &Config));
    geLibProbe = IPSEC_ERR_INTERFACE_NOT_FOUND;
    CHECK(IPSEC_OK == InitializeIpsecDatapath(&Context));
    CHECK(IPSEC_DATAPATH_KERNEL_XFRM == Context.eActiveDatapath);
    DeinitializeIpsecDatapath(&Context);
    geLibProbe = IPSEC_ERR_INTERFACE_AMBIGUOUS;
    geXfrmProbe = IPSEC_ERR_BACKEND_MISMATCH;
    CHECK(IPSEC_ERR_INTERFACE_AMBIGUOUS == InitializeIpsecDatapath(&Context));
    geLibProbe = IPSEC_OK;
    geXfrmProbe = IPSEC_OK;
    geBackendInitialize = IPSEC_ERR_INTERNAL;
    uiBefore = guiBackendCleanup;
    CHECK(IPSEC_ERR_INTERNAL == InitializeIpsecDatapath(&Context));
    CHECK(guiBackendCleanup == uiBefore + 1U);
    geBackendInitialize = IPSEC_OK;
    CHECK(IPSEC_OK == InitializeIpsecDatapath(&Context));
    geEndpointCreate = IPSEC_ERR_PERMISSION;
    uiBefore = guiEndpointCleanup;
    CHECK(IPSEC_ERR_PERMISSION == InitializeIpsecProtectedPath(&Context));
    CHECK(NULL == Context.pProtectedApplicationState);
    CHECK(guiEndpointCleanup == uiBefore + 1U);
    geEndpointCreate = IPSEC_OK;
    geFilterInstall = IPSEC_ERR_RESOURCE_CONFLICT;
    CHECK(IPSEC_ERR_RESOURCE_CONFLICT == InitializeIpsecProtectedPath(&Context));
    CHECK(NULL == Context.pProtectedApplicationState);
    geFilterInstall = IPSEC_OK;
    CHECK(IPSEC_OK == InitializeIpsecProtectedPath(&Context));
    gePlainOpen = IPSEC_ERR_RESOURCE_CONFLICT;
    uiBefore = guiPlainCleanup;
    CHECK(IPSEC_ERR_RESOURCE_CONFLICT == InitializeIpsecPlainPath(&Context));
    CHECK(NULL == Context.pPlainApplicationState);
    CHECK(guiPlainCleanup == uiBefore + 1U);
    gePlainOpen = IPSEC_OK;
    DeinitializeIpsecProtectedPath(&Context);
    DeinitializeIpsecDatapath(&Context);
    Config.ePreference = (IpsecDatapathPreference_t)99;
    CHECK(IPSEC_ERR_INVALID_DATAPATH == ConfigureIpsecDatapath(&Context, &Config));
    Config.ePreference = IPSEC_DATAPATH_PREFER_AUTO;
    Config.ePlainPacketPath = (IpsecPacketPathMode_t)99;
    CHECK(IPSEC_ERR_INVALID_PACKET_PATH == ConfigureIpsecDatapath(&Context, &Config));
}

static void VerifyDefaultsAndPacketTypes(void)
{
    IpsecContext_t Context = {0};
    IpsecDatapathConfig_t Config = {.uiStructSize = sizeof(Config),
        .ePlainPacketPath = IPSEC_PACKET_PATH_APPLICATION};
    uint8_t aucPacket[48] = {0};
    IpsecProtectedPacket_t Packet = {.uiStructSize = sizeof(Packet),
        .pucData = aucPacket, .zCapacity = sizeof(aucPacket),
        .zLength = sizeof(aucPacket),
        .eType = IPSEC_PROTECTED_PACKET_UDP_ESP};
    CHECK(IPSEC_OK == ConfigureIpsecDatapath(&Context, NULL));
    CHECK((IPSEC_DATAPATH_PREFER_AUTO == Context.DatapathConfig.ePreference) &&
        (IPSEC_PACKET_PATH_SYSTEM ==
            Context.DatapathConfig.eProtectedPacketPath) &&
        (IPSEC_PACKET_PATH_SYSTEM == Context.DatapathConfig.ePlainPacketPath));
    CHECK(IPSEC_ERR_INVALID_ARGUMENT ==
        ConfigureIpsecDatapath(&Context, &Config));
    CHECK(IPSEC_ERR_PACKET_TYPE == ValidateIpsecProtectedPacket(&Packet));
    BuildTestRouterSolicitation(aucPacket);
    CHECK(IsIpsecProtectedTunControlPacket(aucPacket, 48U));
    aucPacket[42] ^= 1U;
    CHECK(!IsIpsecProtectedTunControlPacket(aucPacket, 48U));
    BuildTestRouterSolicitation(aucPacket);
    aucPacket[40] = 128U;
    SetTestIcmpv6Checksum(aucPacket, 48U);
    CHECK(!IsIpsecProtectedTunControlPacket(aucPacket, 48U));
}

static void VerifyDynamicProtectedPeers(void)
{
    const char *apcLocal[] = {"192.0.2.1"};
    const char *apcRemote[] = {"192.0.2.2"};
    const char *apcSecondRemote[] = {"192.0.2.3"};
    IpsecConnectionConfig_t Connection = {0};
    IpsecConnectionConfig_t SecondConnection;
    IpsecContext_t Context = {0};
    IpsecDatapathConfig_t Config = CreateTestConfig(
        IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC,
        IPSEC_PACKET_PATH_APPLICATION, IPSEC_PACKET_PATH_SYSTEM);
    IpsecDatapathStatusEx_t Status = {.uiStructSize = sizeof(Status)};
    bool bAdded = false;
    uint8_t aucPacket[IPSEC_PROTECTED_PACKET_CAPACITY];
    IpsecProtectedPacket_t Packet = {.uiStructSize = sizeof(Packet),
        .pucData = aucPacket, .zCapacity = sizeof(aucPacket)};

    Config.acProtectedLocalAddress[0] = '\0';
    Config.acProtectedRemoteAddress[0] = '\0';
    Connection.pcName = "vpn";
    Connection.LocalAddresses.ppcItems = apcLocal;
    Connection.LocalAddresses.uiCount = 1U;
    Connection.RemoteAddresses.ppcItems = apcRemote;
    Connection.RemoteAddresses.uiCount = 1U;
    SecondConnection = Connection;
    SecondConnection.pcName = "vpn-second";
    SecondConnection.RemoteAddresses.ppcItems = apcSecondRemote;
    CHECK(IPSEC_OK == ConfigureIpsecDatapath(&Context, &Config));
    CHECK(IPSEC_OK == InitializeIpsecDatapath(&Context));
    CHECK(IPSEC_OK == InitializeIpsecProtectedPath(&Context));
    CHECK(IPSEC_OK == InitializeIpsecPlainPath(&Context));
    CHECK(IPSEC_OK == RegisterIpsecProtectedPeerInternal(
        &Context, &Connection, &bAdded));
    CHECK(bAdded);
    CHECK(MatchIpsecProtectedPeerInternal(
        &Context, "192.0.2.1", "192.0.2.2"));
    guiProtectedReceives = 0U;
    gbControlBeforeEsp = true;
    CHECK(IPSEC_OK == ReceiveIpsecProtectedPacket(&Context, &Packet, 1000U));
    CHECK((2U == guiProtectedReceives) && (40U == Packet.zLength));
    guiProtectedReceives = 0U;
    gbMalformedControl = true;
    CHECK(IPSEC_ERR_PACKET_TYPE ==
        ReceiveIpsecProtectedPacket(&Context, &Packet, 1000U));
    CHECK((1U == guiProtectedReceives) && (0U == Packet.zLength));
    gbMalformedControl = false;
    gbControlBeforeEsp = false;
    bAdded = true;
    CHECK(IPSEC_OK == RegisterIpsecProtectedPeerInternal(
        &Context, &Connection, &bAdded));
    CHECK(!bAdded);
    CHECK(IPSEC_OK == RegisterIpsecProtectedPeerInternal(
        &Context, &SecondConnection, &bAdded));
    CHECK(bAdded);
    CHECK(MatchIpsecProtectedPeerInternal(
        &Context, "192.0.2.1", "192.0.2.3"));
    guiChildren = 1U;
    CHECK(IPSEC_OK == GetIpsecDatapathStatusEx(&Context, &Status));
    CHECK(Status.bTrafficReady && (1U == Status.uiInstalledChildCount));
    CHECK(IPSEC_OK == UnregisterIpsecProtectedPeerInternal(&Context, "vpn"));
    CHECK(!MatchIpsecProtectedPeerInternal(
        &Context, "192.0.2.1", "192.0.2.2"));
    CHECK(IPSEC_OK == UnregisterIpsecProtectedPeerInternal(&Context, "vpn"));
    CHECK(IPSEC_OK == UnregisterIpsecProtectedPeerInternal(
        &Context, "vpn-second"));
    CHECK(!MatchIpsecProtectedPeerInternal(
        &Context, "192.0.2.1", "192.0.2.3"));
    guiChildren = 0U;
    DeinitializeIpsecPlainPath(&Context);
    DeinitializeIpsecProtectedPath(&Context);
    DeinitializeIpsecDatapath(&Context);
}

int main(void)
{
    IpsecDatapathPreference_t aeBackends[] = {
        IPSEC_DATAPATH_PREFER_XFRM,
        IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC
    };
    IpsecPacketPathMode_t aePaths[] = {
        IPSEC_PACKET_PATH_SYSTEM,
        IPSEC_PACKET_PATH_APPLICATION
    };
    uint32_t uiBackend;
    uint32_t uiProtected;
    uint32_t uiPlain;
    for (uiBackend = 0U; uiBackend < 2U; uiBackend++) {
        for (uiProtected = 0U; uiProtected < 2U; uiProtected++) {
            for (uiPlain = 0U; uiPlain < 2U; uiPlain++) {
                VerifyCombination(aeBackends[uiBackend], aePaths[uiProtected],
                                  aePaths[uiPlain]);
            }
        }
    }
    VerifyDefaultsAndPacketTypes();
    VerifyFailures();
    VerifyDynamicProtectedPeers();
    CHECK(4U == guiSubmissions);
    (void)puts("PASS: backend/path dispatch, dynamic 1:N peer scope, rollback and cleanup (mock OS)");
    return 0;
}
