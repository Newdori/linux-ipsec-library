#ifndef IPSEC_TYPES_H
#define IPSEC_TYPES_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define IPSEC_NAME_LENGTH              64U
#define IPSEC_STATE_LENGTH             32U
#define IPSEC_ADDRESS_LENGTH           64U
#define IPSEC_ID_LENGTH               128U
#define IPSEC_PROPOSAL_LENGTH         256U
#define IPSEC_SELECTOR_LIST_LENGTH    512U
#define IPSEC_ALGORITHM_LENGTH        128U
#define IPSEC_PLUGIN_LENGTH            64U
#define IPSEC_INTERFACE_NAME_LENGTH    64U
#define IPSEC_MAC_ADDRESS_LENGTH      128U
#define IPSEC_VERSION_LENGTH           64U
#define IPSEC_OS_NAME_LENGTH           64U

typedef enum IpsecLogLevel {
    IPSEC_LOG_ERROR = 0,
    IPSEC_LOG_WARNING,
    IPSEC_LOG_INFO,
    IPSEC_LOG_DEBUG
} IpsecLogLevel_t;

typedef enum IpsecMode {
    IPSEC_MODE_TUNNEL = 0,
    IPSEC_MODE_TRANSPORT,
    IPSEC_MODE_BEET,
    IPSEC_MODE_UNKNOWN
} IpsecMode_t;

typedef enum IpsecAuthMethod {
    IPSEC_AUTH_PSK = 0,
    IPSEC_AUTH_CERTIFICATE,
    IPSEC_AUTH_EAP
} IpsecAuthMethod_t;
/* Certificate/EAP values reserve the API vocabulary. AddIpsecConnection
 * currently accepts PSK only; no certificate/private-key loader is provided. */

typedef enum IpsecEsnMode {
    IPSEC_ESN_AUTO = 0,
    IPSEC_ESN_DISABLED,
    IPSEC_ESN_ENABLED
} IpsecEsnMode_t;

typedef enum IpsecControlMode {
    IPSEC_CONTROL_WAIT = 0,
    IPSEC_CONTROL_IMMEDIATE
} IpsecControlMode_t;

typedef enum IpsecDatapathType {
    IPSEC_DATAPATH_UNKNOWN = 0,
    IPSEC_DATAPATH_KERNEL_XFRM,
    IPSEC_DATAPATH_KERNEL_LIBIPSEC
} IpsecDatapathType_t;

typedef enum IpsecAddressFamily {
    IPSEC_ADDRESS_FAMILY_UNSPECIFIED = 0,
    IPSEC_ADDRESS_FAMILY_IPV4,
    IPSEC_ADDRESS_FAMILY_IPV6
} IpsecAddressFamily_t;

typedef enum IpsecXfrmDirection {
    IPSEC_XFRM_DIRECTION_IN = 0,
    IPSEC_XFRM_DIRECTION_OUT,
    IPSEC_XFRM_DIRECTION_FORWARD,
    IPSEC_XFRM_DIRECTION_UNKNOWN
} IpsecXfrmDirection_t;

typedef void (*IpsecLogCallback_t)(
    IpsecLogLevel_t eLevel,
    const char *pcMessage,
    void *pvUserData);

typedef struct IpsecStringListView {
    const char *const *ppcItems;
    uint32_t uiCount;
} IpsecStringListView_t;

typedef struct IpsecConfig {
    uint32_t uiStructSize;
    const char *pcViciSocketPath;
    uint32_t uiConnectTimeoutMs;
    uint32_t uiCommandTimeoutMs;
    IpsecLogCallback_t pLogCallback;
    void *pvLogUserData;
} IpsecConfig_t;

/* Separate extension: the layout of IpsecConfig_t remains ABI compatible. */
typedef enum IpsecDatapathPreference {
    IPSEC_DATAPATH_PREFER_AUTO = 0,
    IPSEC_DATAPATH_PREFER_XFRM,
    IPSEC_DATAPATH_PREFER_KERNEL_LIBIPSEC
} IpsecDatapathPreference_t;

typedef enum IpsecPacketPathMode {
    IPSEC_PACKET_PATH_SYSTEM = 0,
    IPSEC_PACKET_PATH_APPLICATION
} IpsecPacketPathMode_t;

typedef enum IpsecPlainNetfilterHook {
    IPSEC_PLAIN_NETFILTER_INPUT = 0,
    IPSEC_PLAIN_NETFILTER_FORWARD
} IpsecPlainNetfilterHook_t;

#define IPSEC_DATAPATH_NAME_LENGTH 16U
#define IPSEC_PROTECTED_PACKET_CAPACITY 65535U

typedef struct IpsecDatapathConfig {
    uint32_t uiStructSize;
    IpsecDatapathPreference_t ePreference;
    IpsecPacketPathMode_t eProtectedPacketPath;
    IpsecPacketPathMode_t ePlainPacketPath;
    /* Existing charon-owned TUN. Empty means discovery, never creation. */
    char acKernelLibipsecTunName[IPSEC_DATAPATH_NAME_LENGTH];
    /* Protected APPLICATION owns a distinct, non-persistent TUN. */
    char acProtectedInterfaceName[IPSEC_DATAPATH_NAME_LENGTH];
    /* Dedicated Ethernet egress, with an OS-provisioned clsact qdisc.
     * Empty local/remote addresses install scoped filters from each loaded
     * connection. Supplying both selects one legacy fixed IPv4 outer pair.
     * No automatic route, firewall, qdisc or strongSwan configuration changes.
     */
    char acProtectedEgressInterfaceName[IPSEC_DATAPATH_NAME_LENGTH];
    char acProtectedLocalAddress[16];
    char acProtectedRemoteAddress[16];
    /* Base and base+1 are exclusively reserved TC priorities; zero = 32000.
     * Each peer uses a distinct handle at both priorities. The application/OS
     * must prevent concurrent changes in this reserved priority namespace.
     */
    uint16_t usProtectedFilterPriority;
    /* Plain APPLICATION binds this NFQUEUE. Zero is invalid in APPLICATION
     * mode. If bManagePlainNetfilterRule is true, the library owns a dedicated
     * nftables table and installs one post-decrypt rule per loaded connection.
     * Otherwise the OS must provision equivalent rules before packet receive.
     */
    uint16_t usPlainQueueNumber;
    IpsecPlainNetfilterHook_t ePlainNetfilterHook;
    bool bManagePlainNetfilterRule;
} IpsecDatapathConfig_t;

typedef enum IpsecProtectedPacketType {
    IPSEC_PROTECTED_PACKET_RAW_ESP = 0,
    /* Reserved API value. Current packet paths return IPSEC_ERR_PACKET_TYPE. */
    IPSEC_PROTECTED_PACKET_UDP_ESP
} IpsecProtectedPacketType_t;

typedef enum IpsecPacketDirection {
    IPSEC_PACKET_DIRECTION_INBOUND = 0,
    IPSEC_PACKET_DIRECTION_OUTBOUND
} IpsecPacketDirection_t;

typedef struct IpsecProtectedPacket {
    uint32_t uiStructSize;
    uint8_t *pucData;
    size_t zCapacity;
    size_t zLength;
    IpsecProtectedPacketType_t eType;
    IpsecPacketDirection_t eDirection;
} IpsecProtectedPacket_t;

typedef struct IpsecPlainPacket {
    uint32_t uiStructSize;
    uint8_t *pucData;
    size_t zCapacity;
    size_t zLength;
    IpsecAddressFamily_t eFamily;
    IpsecPacketDirection_t eDirection;
} IpsecPlainPacket_t;

typedef struct IpsecConnectionConfig {
    uint32_t uiStructSize;
    const char *pcName;
    const char *pcChildName;
    IpsecStringListView_t LocalAddresses;
    IpsecStringListView_t RemoteAddresses;
    IpsecAuthMethod_t eLocalAuth;
    IpsecAuthMethod_t eRemoteAuth;
    const char *pcLocalId;
    const char *pcRemoteId;
    IpsecStringListView_t IkeProposals;
    IpsecStringListView_t EspProposals;
    IpsecStringListView_t LocalTrafficSelectors;
    IpsecStringListView_t RemoteTrafficSelectors;
    IpsecMode_t eMode;
    IpsecEsnMode_t eEsn;
    bool bEnablePfs;
    bool bEnableMobike;
    bool bEnableFragmentation;
    bool bForceUdpEncapsulation;
    bool bForceChildlessIke;
    uint32_t uiDpdDelayMs;
    uint32_t uiDpdTimeoutMs;
    uint64_t ullIkeRekeyTimeMs;
    uint64_t ullIkeLifetimeMs; /* Legacy name: maps to VICI reauth_time, not life_time. */
    uint64_t ullChildRekeyTimeMs;
    uint64_t ullChildLifetimeMs;
} IpsecConnectionConfig_t;

typedef struct IpsecPsk {
    uint32_t uiStructSize;
    const char *pcId;
    const uint8_t *pucData;
    uint32_t uiDataLength;
    IpsecStringListView_t Owners;
} IpsecPsk_t;

typedef struct IpsecControlOptions {
    uint32_t uiStructSize;
    IpsecControlMode_t eMode;
    uint32_t uiTimeoutMs;
} IpsecControlOptions_t;

typedef struct IpsecConnectionInfo {
    char acName[IPSEC_NAME_LENGTH];
    char acLocalAddresses[IPSEC_SELECTOR_LIST_LENGTH];
    char acRemoteAddresses[IPSEC_SELECTOR_LIST_LENGTH];
    char acLocalId[IPSEC_ID_LENGTH];
    char acRemoteId[IPSEC_ID_LENGTH];
    char acChildNames[IPSEC_SELECTOR_LIST_LENGTH];
    uint64_t ullRekeyTimeMs;
    uint64_t ullReauthTimeMs;
} IpsecConnectionInfo_t;

typedef struct IpsecConnectionList {
    IpsecConnectionInfo_t *pItems;
    uint32_t uiCount;
} IpsecConnectionList_t;

typedef struct IpsecIkeSaInfo {
    char acName[IPSEC_NAME_LENGTH];
    char acState[IPSEC_STATE_LENGTH];
    bool bEstablished;
    bool bInitiator;
    bool bNatLocal;
    bool bNatRemote;
    char acLocalAddress[IPSEC_ADDRESS_LENGTH];
    char acRemoteAddress[IPSEC_ADDRESS_LENGTH];
    char acLocalId[IPSEC_ID_LENGTH];
    char acRemoteId[IPSEC_ID_LENGTH];
    char acProposal[IPSEC_PROPOSAL_LENGTH];
    uint64_t ullUniqueId;
    uint64_t ullEstablishedTimeMs;
    uint64_t ullRekeyTimeMs;
} IpsecIkeSaInfo_t;

typedef struct IpsecIkeSaList {
    IpsecIkeSaInfo_t *pItems;
    uint32_t uiCount;
} IpsecIkeSaList_t;

typedef struct IpsecChildSaInfo {
    char acIkeName[IPSEC_NAME_LENGTH];
    char acName[IPSEC_NAME_LENGTH];
    char acState[IPSEC_STATE_LENGTH];
    char acProposal[IPSEC_PROPOSAL_LENGTH];
    char acLocalTrafficSelectors[IPSEC_SELECTOR_LIST_LENGTH];
    char acRemoteTrafficSelectors[IPSEC_SELECTOR_LIST_LENGTH];
    IpsecMode_t eMode;
    bool bEsn;
    bool bUdpEncapsulation;
    uint32_t uiReqid;
    uint32_t uiInboundSpi;
    uint32_t uiOutboundSpi;
    uint64_t ullBytesIn;
    uint64_t ullBytesOut;
    uint64_t ullPacketsIn;
    uint64_t ullPacketsOut;
    uint64_t ullInstallTimeMs;
    uint64_t ullRekeyTimeMs;
    uint64_t ullLifetimeMs;
} IpsecChildSaInfo_t;

typedef struct IpsecChildSaList {
    IpsecChildSaInfo_t *pItems;
    uint32_t uiCount;
} IpsecChildSaList_t;

typedef struct IpsecAlgorithmInfo {
    char acType[IPSEC_ALGORITHM_LENGTH];
    char acName[IPSEC_ALGORITHM_LENGTH];
    char acPlugin[IPSEC_PLUGIN_LENGTH];
} IpsecAlgorithmInfo_t;

typedef struct IpsecAlgorithmList {
    IpsecAlgorithmInfo_t *pItems;
    uint32_t uiCount;
} IpsecAlgorithmList_t;

typedef struct IpsecDaemonStatus {
    char acDaemon[IPSEC_NAME_LENGTH];
    char acVersion[IPSEC_VERSION_LENGTH];
    char acSystemName[IPSEC_OS_NAME_LENGTH];
    char acSystemRelease[IPSEC_OS_NAME_LENGTH];
    char acMachine[IPSEC_OS_NAME_LENGTH];
    uint64_t ullUptimeSeconds;
    uint32_t uiWorkerTotal;
    uint32_t uiWorkerIdle;
    uint32_t uiIkeSaTotal;
    uint32_t uiIkeSaHalfOpen;
    bool bKernelNetlinkLoaded;
    bool bKernelLibipsecLoaded;
} IpsecDaemonStatus_t;

typedef struct IpsecDatapathStatus {
    IpsecDatapathType_t eType;
    bool bReady;
    bool bKernelNetlinkLoaded;
    bool bKernelLibipsecLoaded;
    bool bTunInterfacePresent;
    bool bTunInterfaceUp;
    uint32_t uiTunInterfaceIndex;
    uint32_t uiTunRouteCount;
    char acTunInterfaceName[IPSEC_INTERFACE_NAME_LENGTH];
} IpsecDatapathStatus_t;

/* Additive status; legacy IpsecDatapathStatus_t is not enlarged. */
typedef struct IpsecDatapathStatusEx {
    uint32_t uiStructSize;
    IpsecDatapathStatus_t Backend;
    IpsecPacketPathMode_t eProtectedPacketPath;
    IpsecPacketPathMode_t ePlainPacketPath;
    bool bBackendReady;
    bool bProtectedPathReady;
    bool bPlainPathReady;
    /* Necessary local conditions, NOT a peer reachability/traffic proof. */
    bool bTrafficReady;
    uint32_t uiInstalledChildCount;
    uint32_t uiProtectedInterfaceIndex;
    char acProtectedInterfaceName[IPSEC_DATAPATH_NAME_LENGTH];
    uint32_t uiPlainInterfaceIndex;
    char acPlainInterfaceName[IPSEC_DATAPATH_NAME_LENGTH];
    uint16_t usPlainQueueNumber;
} IpsecDatapathStatusEx_t;

typedef struct IpsecRuntimeStatus {
    uint32_t uiStructSize;
    bool bDaemonReady;
    bool bDatapathReady;
    IpsecDaemonStatus_t Daemon;
    IpsecDatapathStatusEx_t Datapath;
} IpsecRuntimeStatus_t;

typedef struct IpsecPacketPathStatus {
    uint32_t uiStructSize;
    IpsecPacketPathMode_t eProtectedPacketPath;
    IpsecPacketPathMode_t ePlainPacketPath;
    bool bProtectedPathReady;
    bool bPlainPathReady;
    uint32_t uiProtectedInterfaceIndex;
    char acProtectedInterfaceName[IPSEC_DATAPATH_NAME_LENGTH];
    uint32_t uiPlainInterfaceIndex;
    char acPlainInterfaceName[IPSEC_DATAPATH_NAME_LENGTH];
    uint16_t usPlainQueueNumber;
} IpsecPacketPathStatus_t;

typedef struct IpsecTrafficStatistics {
    uint32_t uiStructSize;
    bool bCountersValid;
    /* XFRM: network-namespace-wide SA totals, not per-context/directional.
     * kernel-libipsec: NOT_SUPPORTED; use the separate VICI CHILD SA API.
     */
    uint64_t ullPackets;
    uint64_t ullBytes;
    uint32_t uiSaCount;
} IpsecTrafficStatistics_t;

typedef struct IpsecXfrmStateInfo {
    IpsecAddressFamily_t eFamily;
    char acSource[IPSEC_ADDRESS_LENGTH];
    char acDestination[IPSEC_ADDRESS_LENGTH];
    uint32_t uiProtocol;
    uint32_t uiSpi;
    uint32_t uiReqid;
    IpsecMode_t eMode;
    char acEncryptionAlgorithm[IPSEC_ALGORITHM_LENGTH];
    char acIntegrityAlgorithm[IPSEC_ALGORITHM_LENGTH];
    char acAeadAlgorithm[IPSEC_ALGORITHM_LENGTH];
    bool bEsn;
    uint32_t uiReplayWindow;
    uint64_t ullPacketCount;
    uint64_t ullByteCount;
    uint64_t ullAddTimeSeconds;
    uint64_t ullUseTimeSeconds;
    uint64_t ullSoftByteLimit;
    uint64_t ullHardByteLimit;
    uint64_t ullSoftPacketLimit;
    uint64_t ullHardPacketLimit;
} IpsecXfrmStateInfo_t;

typedef struct IpsecXfrmStateList {
    IpsecXfrmStateInfo_t *pItems;
    uint32_t uiCount;
} IpsecXfrmStateList_t;

typedef struct IpsecXfrmPolicyInfo {
    IpsecAddressFamily_t eFamily;
    IpsecXfrmDirection_t eDirection;
    char acSourceSelector[IPSEC_ADDRESS_LENGTH];
    uint8_t ucSourcePrefixLength;
    char acDestinationSelector[IPSEC_ADDRESS_LENGTH];
    uint8_t ucDestinationPrefixLength;
    uint32_t uiPriority;
    uint32_t uiIndex;
    uint32_t uiReqid;
    IpsecMode_t eMode;
    char acTemplateSource[IPSEC_ADDRESS_LENGTH];
    char acTemplateDestination[IPSEC_ADDRESS_LENGTH];
    uint32_t uiProtocol;
} IpsecXfrmPolicyInfo_t;

typedef struct IpsecXfrmPolicyList {
    IpsecXfrmPolicyInfo_t *pItems;
    uint32_t uiCount;
} IpsecXfrmPolicyList_t;

typedef struct IpsecXfrmStatistics {
    uint64_t ullPresentMask;
    uint64_t ullInError;
    uint64_t ullInBufferError;
    uint64_t ullInHeaderError;
    uint64_t ullInNoStates;
    uint64_t ullInStateProtocolError;
    uint64_t ullInStateModeError;
    uint64_t ullInStateSequenceError;
    uint64_t ullInStateExpired;
    uint64_t ullInStateMismatch;
    uint64_t ullInStateInvalid;
    uint64_t ullInTemplateMismatch;
    uint64_t ullOutError;
    uint64_t ullOutBundleGenerationError;
    uint64_t ullOutBundleCheckError;
    uint64_t ullOutNoStates;
    uint64_t ullOutStateProtocolError;
    uint64_t ullOutStateModeError;
    uint64_t ullOutStateSequenceError;
    uint64_t ullOutStateExpired;
    uint64_t ullOutPolicyBlock;
} IpsecXfrmStatistics_t;

typedef struct IpsecInterfaceInfo {
    uint32_t uiIndex;
    char acName[IPSEC_INTERFACE_NAME_LENGTH];
    bool bUp;
    bool bRunning;
    bool bCarrier;
    uint32_t uiMtu;
    char acMacAddress[IPSEC_MAC_ADDRESS_LENGTH];
    uint32_t uiFlags;
} IpsecInterfaceInfo_t;

typedef struct IpsecInterfaceList {
    IpsecInterfaceInfo_t *pItems;
    uint32_t uiCount;
} IpsecInterfaceList_t;

typedef struct IpsecAddressInfo {
    uint32_t uiInterfaceIndex;
    char acInterfaceName[IPSEC_INTERFACE_NAME_LENGTH];
    IpsecAddressFamily_t eFamily;
    char acAddress[IPSEC_ADDRESS_LENGTH];
    uint8_t ucPrefixLength;
    uint8_t ucScope;
} IpsecAddressInfo_t;

typedef struct IpsecAddressList {
    IpsecAddressInfo_t *pItems;
    uint32_t uiCount;
} IpsecAddressList_t;

typedef struct IpsecRouteInfo {
    IpsecAddressFamily_t eFamily;
    char acDestination[IPSEC_ADDRESS_LENGTH];
    uint8_t ucPrefixLength;
    char acGateway[IPSEC_ADDRESS_LENGTH];
    char acSource[IPSEC_ADDRESS_LENGTH];
    uint32_t uiInterfaceIndex;
    char acInterfaceName[IPSEC_INTERFACE_NAME_LENGTH];
    uint32_t uiMetric;
    uint32_t uiTable;
    uint8_t ucProtocol;
    uint8_t ucScope;
} IpsecRouteInfo_t;

typedef struct IpsecRouteList {
    IpsecRouteInfo_t *pItems;
    uint32_t uiCount;
} IpsecRouteList_t;

#ifdef __cplusplus
}
#endif

#endif
