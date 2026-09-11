#ifndef IPSEC_H
#define IPSEC_H

#include "ipsec_error.h"
#include "ipsec_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IpsecContext IpsecContext_t;

/*
 * Contexts support concurrent commands and SA waits. Commands on one VICI
 * connection remain serialized. Stop new API calls, cancel/join caller-owned
 * workers, then DeinitializeIpsec; deinit must not race a new API entry.
 * Logger callbacks run on the calling thread, outside internal locks. They
 * must not destroy the context and must synchronize their own shared state.
 *
 * Input strings/views are borrowed for the duration of the call. Get*List
 * outputs must be empty (zero-initialized or previously freed); release them
 * with their matching Free*List before reuse. Free functions clear the list.
 * No getter transfers ownership of a context or of caller input buffers.
 */

#define IPSEC_GENERATED_PSK_BYTE_LENGTH 48U

IpsecError_t GenerateIpsecPskFile(
    const char *pcPath);

/* Control-compatible initialization. The default datapath is initialized when
 * available, but datapath probe errors remain queryable and do not fail this
 * call. Use InitializeIpsecWithDatapath for required product packet paths.
 */
IpsecError_t InitializeIpsecControl(
    IpsecContext_t **ppContext,
    const IpsecConfig_t *pConfig);

/* Compatibility alias for InitializeIpsecControl(). */
IpsecError_t InitializeIpsec(
    IpsecContext_t **ppContext,
    const IpsecConfig_t *pConfig);

/* Strict backend/path initialization. NULL datapath config = AUTO/SYSTEM/SYSTEM.
 * InitializeIpsec keeps its legacy VICI-only success contract if probing is
 * unavailable; its datapath getters then report that probe error.
 * Neither function changes the backend selected inside charon.
 */
IpsecError_t InitializeIpsecWithDatapath(
    IpsecContext_t **ppContext,
    const IpsecConfig_t *pConfig,
    const IpsecDatapathConfig_t *pDatapathConfig);

IpsecError_t GetIpsecDatapathStatusEx(
    IpsecContext_t *pContext, IpsecDatapathStatusEx_t *pStatus);
IpsecError_t GetIpsecRuntimeStatus(
    IpsecContext_t *pContext, IpsecRuntimeStatus_t *pStatus);
IpsecError_t GetIpsecTrafficStatistics(
    IpsecContext_t *pContext, IpsecTrafficStatistics_t *pStatistics);
IpsecError_t GetIpsecPacketPathStatus(
    IpsecContext_t *pContext, IpsecPacketPathStatus_t *pStatus);

/* Caller owns the buffer. Protected receive requires capacity >= 65535 (TUN reads must
 * never silently truncate). timeout=0 is a non-blocking attempt. No per-packet
 * allocation. Exactly one protected reader and one protected writer per context;
 * both may run concurrently, but must stop/join before deinit.
 * Full unfragmented IPv4 RAW ESP packets only in the first implementation.
 * Submit validates framing/scope, not authenticity; the backend checks ESP.
 * Stop protected traffic/terminate SAs before APPLICATION teardown: removal of
 * redirect filters restores the OS's ordinary egress behavior.
 */
IpsecError_t ReceiveIpsecProtectedPacket(
    IpsecContext_t *pContext, IpsecProtectedPacket_t *pPacket,
    uint32_t uiTimeoutMs);
IpsecError_t SubmitIpsecProtectedPacket(
    IpsecContext_t *pContext, const IpsecProtectedPacket_t *pPacket);

/* Returns one authenticated, decrypted and decapsulated inner IPv4 packet
 * selected by the configured post-decrypt NFQUEUE rule. The library copies the
 * full IPv4 packet and issues NF_DROP, so it is not also delivered to the
 * Linux stack. Exactly one plain reader may use a context. The caller must
 * continuously drain the configured queue and stop/join the reader before
 * deinitialization. A library-owned rule is installed per connection when
 * IpsecDatapathConfig_t.bManagePlainNetfilterRule is true.
 */
IpsecError_t ReceiveIpsecPlainPacket(
    IpsecContext_t *pContext, IpsecPlainPacket_t *pPacket,
    uint32_t uiTimeoutMs);

void DeinitializeIpsec(
    IpsecContext_t *pContext);

/* Cancel currently registered SA waits; future waits are unaffected. */
IpsecError_t CancelIpsecWaits(IpsecContext_t *pContext);

/* Set uiStructSize=sizeof(*pDiagnostic). Does not consume the snapshot.
 * Concurrent callers may overwrite it; externally serialize if correlation
 * with one particular command is required. Validation-only errors and raw
 * Netlink queries do not update this VICI-command diagnostic.
 */
IpsecError_t GetIpsecLastDiagnostic(
    IpsecContext_t *pContext,
    IpsecDiagnostic_t *pDiagnostic);

IpsecError_t AddIpsecConnection(
    IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig);

IpsecError_t RemoveIpsecConnection(
    IpsecContext_t *pContext,
    const char *pcName);

IpsecError_t GetIpsecConnections(
    IpsecContext_t *pContext,
    IpsecConnectionList_t *pList);

void FreeIpsecConnectionList(
    IpsecConnectionList_t *pList);

IpsecError_t AddIpsecPsk(
    IpsecContext_t *pContext,
    const IpsecPsk_t *pPsk);

IpsecError_t RemoveIpsecPsk(
    IpsecContext_t *pContext,
    const char *pcCredentialId);

/* Removes credentials with explicit IDs successfully loaded by this context.
 * Anonymous credentials cannot be isolated and return NOT_SUPPORTED.
 */
IpsecError_t ClearIpsecContextCredentials(
    IpsecContext_t *pContext);

/* Daemon-wide destructive operation. Other contexts are not isolated. */
IpsecError_t ClearAllIpsecDaemonCredentials(
    IpsecContext_t *pContext);

/* Compatibility alias for ClearAllIpsecDaemonCredentials(). */
IpsecError_t ClearIpsecCredentials(
    IpsecContext_t *pContext);

IpsecError_t InitiateIpsecIke(
    IpsecContext_t *pContext,
    const char *pcConnectionName,
    const IpsecControlOptions_t *pOptions);

IpsecError_t TerminateIpsecIke(
    IpsecContext_t *pContext,
    const char *pcIkeName,
    const IpsecControlOptions_t *pOptions);

IpsecError_t RekeyIpsecIke(
    IpsecContext_t *pContext,
    const char *pcIkeName);

/* Waits observe an existing/requested SA; they do not initiate it. Timeout is
 * a nonzero monotonic end-to-end budget (queue/connect/registration/query).
 * Matching is by configuration name: after rekey, any matching established
 * SA satisfies the predicate. This is not a rekey-completion barrier.
 */
IpsecError_t WaitIpsecIkeEstablished(
    IpsecContext_t *pContext,
    const char *pcIkeName,
    uint32_t uiTimeoutMs);

IpsecError_t InitiateIpsecChild(
    IpsecContext_t *pContext,
    const char *pcChildName,
    const IpsecControlOptions_t *pOptions);

IpsecError_t TerminateIpsecChild(
    IpsecContext_t *pContext,
    const char *pcChildName,
    const IpsecControlOptions_t *pOptions);

IpsecError_t RekeyIpsecChild(
    IpsecContext_t *pContext,
    const char *pcChildName);

/* Same timeout, cancellation and name-matching contract as the IKE wait. */
IpsecError_t WaitIpsecChildInstalled(
    IpsecContext_t *pContext,
    const char *pcChildName,
    uint32_t uiTimeoutMs);

IpsecError_t GetIpsecIkeSas(
    IpsecContext_t *pContext,
    IpsecIkeSaList_t *pList);

void FreeIpsecIkeSaList(
    IpsecIkeSaList_t *pList);

IpsecError_t GetIpsecChildSas(
    IpsecContext_t *pContext,
    IpsecChildSaList_t *pList);

void FreeIpsecChildSaList(
    IpsecChildSaList_t *pList);

IpsecError_t GetIpsecAlgorithms(
    IpsecContext_t *pContext,
    IpsecAlgorithmList_t *pList);

void FreeIpsecAlgorithmList(
    IpsecAlgorithmList_t *pList);

IpsecError_t GetIpsecDaemonStatus(
    IpsecContext_t *pContext,
    IpsecDaemonStatus_t *pStatus);

IpsecError_t GetIpsecDatapathStatus(
    IpsecContext_t *pContext,
    IpsecDatapathStatus_t *pStatus);

IpsecError_t GetIpsecXfrmStates(
    IpsecContext_t *pContext,
    IpsecXfrmStateList_t *pList);

void FreeIpsecXfrmStateList(
    IpsecXfrmStateList_t *pList);

IpsecError_t GetIpsecXfrmPolicies(
    IpsecContext_t *pContext,
    IpsecXfrmPolicyList_t *pList);

void FreeIpsecXfrmPolicyList(
    IpsecXfrmPolicyList_t *pList);

IpsecError_t GetIpsecXfrmStatistics(
    IpsecXfrmStatistics_t *pStatistics);

/* Backend-aware alternative to the legacy contextless system diagnostic. */
IpsecError_t GetIpsecBackendXfrmStatistics(
    IpsecContext_t *pContext, IpsecXfrmStatistics_t *pStatistics);

IpsecError_t GetIpsecInterfaces(
    IpsecInterfaceList_t *pList);

void FreeIpsecInterfaceList(
    IpsecInterfaceList_t *pList);

IpsecError_t GetIpsecAddresses(
    IpsecAddressList_t *pList);

void FreeIpsecAddressList(
    IpsecAddressList_t *pList);

IpsecError_t GetIpsecRoutes(
    IpsecRouteList_t *pList);

void FreeIpsecRouteList(
    IpsecRouteList_t *pList);

#ifdef __cplusplus
}
#endif

#endif
