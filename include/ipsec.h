#ifndef IPSEC_H
#define IPSEC_H

#include "ipsec_error.h"
#include "ipsec_types.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct IpsecContext IpsecContext_t;

#define IPSEC_GENERATED_PSK_BYTE_LENGTH 48U

IpsecError_t GenerateIpsecPskFile(
    const char *pcPath);

IpsecError_t InitializeIpsec(
    IpsecContext_t **ppContext,
    const IpsecConfig_t *pConfig);

void DeinitializeIpsec(
    IpsecContext_t *pContext);

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
