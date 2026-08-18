#include "app_internal.h"

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static IpsecError_t JoinReportPath(
    char *pcPath,
    size_t zPathLength,
    const char *pcDirectory,
    const char *pcName)
{
    size_t zDirectoryLength;
    int32_t iLength;

    if ((NULL == pcPath) || (0U == zPathLength) ||
        (NULL == pcDirectory) || (NULL == pcName)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    zDirectoryLength = strlen(pcDirectory);
    iLength = snprintf(pcPath, zPathLength, "%s%s%s", pcDirectory,
                       ((0U < zDirectoryLength) &&
                        ('/' == pcDirectory[zDirectoryLength - 1U])) ?
                       "" : "/", pcName);
    return ((0 <= iLength) && ((size_t)iLength < zPathLength)) ?
        IPSEC_OK : IPSEC_ERR_BUFFER_TOO_SMALL;
}

static IpsecError_t CreateReportDirectory(const char *pcPath)
{
    char acPath[NATIVE_APP_PATH_LENGTH];
    char *pcCursor;
    int32_t iLength = snprintf(acPath, sizeof(acPath), "%s", pcPath);

    if ((0 > iLength) || ((size_t)iLength >= sizeof(acPath))) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    for (pcCursor = acPath + 1; '\0' != *pcCursor; pcCursor++) {
        if ('/' == *pcCursor) {
            *pcCursor = '\0';
            if ((0 != mkdir(acPath, 0750)) && (EEXIST != errno)) {
                return IPSEC_ERR_FILE_OPEN;
            }
            *pcCursor = '/';
        }
        else {
            /* Continue through the path. */
        }
    }
    return ((0 == mkdir(acPath, 0750)) || (EEXIST == errno)) ?
        IPSEC_OK : IPSEC_ERR_FILE_OPEN;
}

static FILE *OpenReportFile(
    const char *pcDirectory,
    const char *pcName,
    const char *pcMode)
{
    char acPath[NATIVE_APP_PATH_LENGTH];

    if (IPSEC_OK != JoinReportPath(acPath, sizeof(acPath),
                                   pcDirectory, pcName)) {
        return NULL;
    }
    return fopen(acPath, pcMode);
}

static const char *GetReportMode(IpsecMode_t eMode)
{
    const char *pcMode;

    switch (eMode) {
    case IPSEC_MODE_TUNNEL:
        pcMode = "tunnel";
        break;
    case IPSEC_MODE_TRANSPORT:
        pcMode = "transport";
        break;
    case IPSEC_MODE_BEET:
        pcMode = "beet";
        break;
    default:
        pcMode = "unknown";
        break;
    }
    return pcMode;
}

static const char *GetReportFamily(IpsecAddressFamily_t eFamily)
{
    return (IPSEC_ADDRESS_FAMILY_IPV6 == eFamily) ? "IPv6" : "IPv4";
}

static const char *GetReportDirection(IpsecXfrmDirection_t eDirection)
{
    const char *pcDirection;

    switch (eDirection) {
    case IPSEC_XFRM_DIRECTION_IN:
        pcDirection = "IN";
        break;
    case IPSEC_XFRM_DIRECTION_OUT:
        pcDirection = "OUT";
        break;
    case IPSEC_XFRM_DIRECTION_FORWARD:
        pcDirection = "FWD";
        break;
    default:
        pcDirection = "UNKNOWN";
        break;
    }
    return pcDirection;
}

static uint64_t GetXfrmErrorTotal(const IpsecXfrmStatistics_t *pStats)
{
    return pStats->ullInError + pStats->ullInBufferError +
        pStats->ullInHeaderError + pStats->ullInNoStates +
        pStats->ullInStateProtocolError + pStats->ullInStateModeError +
        pStats->ullInStateSequenceError + pStats->ullInStateExpired +
        pStats->ullInStateMismatch + pStats->ullInStateInvalid +
        pStats->ullInTemplateMismatch + pStats->ullOutError +
        pStats->ullOutBundleGenerationError +
        pStats->ullOutBundleCheckError + pStats->ullOutNoStates +
        pStats->ullOutStateProtocolError + pStats->ullOutStateModeError +
        pStats->ullOutStateSequenceError + pStats->ullOutStateExpired +
        pStats->ullOutPolicyBlock;
}

static void SaveXfrmStatistics(
    const char *pcDirectory,
    const char *pcName)
{
    IpsecXfrmStatistics_t Stats = {0};
    IpsecError_t eError = GetIpsecXfrmStatistics(&Stats);
    FILE *pFile = OpenReportFile(pcDirectory, pcName, "w");

    if (NULL != pFile) {
        if (IPSEC_OK == eError) {
            (void)fprintf(pFile,
                "present_mask=0x%016" PRIx64 "\n"
                "in_error=%" PRIu64 "\nin_buffer_error=%" PRIu64 "\n"
                "in_header_error=%" PRIu64 "\nin_no_states=%" PRIu64 "\n"
                "in_state_protocol_error=%" PRIu64 "\n"
                "in_state_mode_error=%" PRIu64 "\n"
                "in_state_sequence_error=%" PRIu64 "\n"
                "in_state_expired=%" PRIu64 "\n"
                "in_state_mismatch=%" PRIu64 "\n"
                "in_state_invalid=%" PRIu64 "\n"
                "in_template_mismatch=%" PRIu64 "\n"
                "out_error=%" PRIu64 "\n"
                "out_bundle_generation_error=%" PRIu64 "\n"
                "out_bundle_check_error=%" PRIu64 "\n"
                "out_no_states=%" PRIu64 "\n"
                "out_state_protocol_error=%" PRIu64 "\n"
                "out_state_mode_error=%" PRIu64 "\n"
                "out_state_sequence_error=%" PRIu64 "\n"
                "out_state_expired=%" PRIu64 "\n"
                "out_policy_block=%" PRIu64 "\nerror_total=%" PRIu64 "\n",
                Stats.ullPresentMask, Stats.ullInError,
                Stats.ullInBufferError, Stats.ullInHeaderError,
                Stats.ullInNoStates, Stats.ullInStateProtocolError,
                Stats.ullInStateModeError, Stats.ullInStateSequenceError,
                Stats.ullInStateExpired, Stats.ullInStateMismatch,
                Stats.ullInStateInvalid, Stats.ullInTemplateMismatch,
                Stats.ullOutError, Stats.ullOutBundleGenerationError,
                Stats.ullOutBundleCheckError, Stats.ullOutNoStates,
                Stats.ullOutStateProtocolError, Stats.ullOutStateModeError,
                Stats.ullOutStateSequenceError, Stats.ullOutStateExpired,
                Stats.ullOutPolicyBlock, GetXfrmErrorTotal(&Stats));
        }
        else {
            (void)fprintf(pFile, "error=%s\n", GetIpsecErrorString(eError));
        }
        (void)fclose(pFile);
    }
}

static void SaveDaemonStatus(
    IpsecContext_t *pContext,
    const char *pcDirectory,
    const char *pcName)
{
    IpsecDaemonStatus_t Status = {0};
    IpsecError_t eError = GetIpsecDaemonStatus(pContext, &Status);
    FILE *pFile = OpenReportFile(pcDirectory, pcName, "w");

    if (NULL != pFile) {
        if (IPSEC_OK == eError) {
            (void)fprintf(pFile,
                "daemon=%s\nversion=%s\nsystem=%s\nrelease=%s\nmachine=%s\n"
                "uptime_seconds=%" PRIu64 "\nworker_total=%" PRIu32
                "\nworker_idle=%" PRIu32 "\nike_total=%" PRIu32
                "\nike_half_open=%" PRIu32 "\n",
                Status.acDaemon, Status.acVersion, Status.acSystemName,
                Status.acSystemRelease, Status.acMachine,
                Status.ullUptimeSeconds, Status.uiWorkerTotal,
                Status.uiWorkerIdle, Status.uiIkeSaTotal,
                Status.uiIkeSaHalfOpen);
        }
        else {
            (void)fprintf(pFile, "error=%s\n", GetIpsecErrorString(eError));
        }
        (void)fclose(pFile);
    }
}

static void SaveAlgorithms(
    IpsecContext_t *pContext,
    const char *pcDirectory)
{
    IpsecAlgorithmList_t List = {0};
    IpsecError_t eError = GetIpsecAlgorithms(pContext, &List);
    FILE *pFile = OpenReportFile(pcDirectory, "daemon_algorithms.txt", "w");
    uint32_t uiIndex;

    if (NULL != pFile) {
        (void)fprintf(pFile, "query=%s count=%" PRIu32 "\n",
                      GetIpsecErrorString(eError), List.uiCount);
        if (IPSEC_OK == eError) {
            for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
                (void)fprintf(pFile, "type=%s name=%s plugin=%s\n",
                              List.pItems[uiIndex].acType,
                              List.pItems[uiIndex].acName,
                              List.pItems[uiIndex].acPlugin);
            }
        }
        (void)fclose(pFile);
    }
    FreeIpsecAlgorithmList(&List);
}

static void SaveNetwork(const char *pcDirectory)
{
    IpsecInterfaceList_t Interfaces = {0};
    IpsecAddressList_t Addresses = {0};
    IpsecRouteList_t Routes = {0};
    IpsecError_t eInterfaces = GetIpsecInterfaces(&Interfaces);
    IpsecError_t eAddresses = GetIpsecAddresses(&Addresses);
    IpsecError_t eRoutes = GetIpsecRoutes(&Routes);
    FILE *pFile;
    uint32_t uiIndex;

    pFile = OpenReportFile(pcDirectory, "network_interfaces.txt", "w");
    if (NULL != pFile) {
        (void)fprintf(pFile, "query=%s count=%" PRIu32 "\n",
                      GetIpsecErrorString(eInterfaces), Interfaces.uiCount);
        if (IPSEC_OK == eInterfaces) {
            for (uiIndex = 0U; uiIndex < Interfaces.uiCount; uiIndex++) {
                const IpsecInterfaceInfo_t *pItem =
                    &Interfaces.pItems[uiIndex];
                (void)fprintf(pFile,
                    "ifindex=%" PRIu32 " name=%s up=%s running=%s "
                    "carrier=%s mtu=%" PRIu32 " mac=%s flags=0x%08" PRIx32 "\n",
                    pItem->uiIndex, pItem->acName,
                    pItem->bUp ? "yes" : "no",
                    pItem->bRunning ? "yes" : "no",
                    pItem->bCarrier ? "yes" : "no", pItem->uiMtu,
                    pItem->acMacAddress, pItem->uiFlags);
            }
        }
        (void)fclose(pFile);
    }
    pFile = OpenReportFile(pcDirectory, "network_addresses.txt", "w");
    if (NULL != pFile) {
        (void)fprintf(pFile, "query=%s count=%" PRIu32 "\n",
                      GetIpsecErrorString(eAddresses), Addresses.uiCount);
        if (IPSEC_OK == eAddresses) {
            for (uiIndex = 0U; uiIndex < Addresses.uiCount; uiIndex++) {
                const IpsecAddressInfo_t *pItem = &Addresses.pItems[uiIndex];
                (void)fprintf(pFile,
                    "ifindex=%" PRIu32 " interface=%s family=%s "
                    "address=%s/%u scope=%u\n",
                    pItem->uiInterfaceIndex, pItem->acInterfaceName,
                    GetReportFamily(pItem->eFamily), pItem->acAddress,
                    (unsigned int)pItem->ucPrefixLength,
                    (unsigned int)pItem->ucScope);
            }
        }
        (void)fclose(pFile);
    }
    pFile = OpenReportFile(pcDirectory, "network_routes.txt", "w");
    if (NULL != pFile) {
        (void)fprintf(pFile, "query=%s count=%" PRIu32 "\n",
                      GetIpsecErrorString(eRoutes), Routes.uiCount);
        if (IPSEC_OK == eRoutes) {
            for (uiIndex = 0U; uiIndex < Routes.uiCount; uiIndex++) {
                const IpsecRouteInfo_t *pItem = &Routes.pItems[uiIndex];
                (void)fprintf(pFile,
                    "family=%s destination=%s/%u gateway=%s source=%s "
                    "ifindex=%" PRIu32 " interface=%s metric=%" PRIu32
                    " table=%" PRIu32 " protocol=%u scope=%u\n",
                    GetReportFamily(pItem->eFamily), pItem->acDestination,
                    (unsigned int)pItem->ucPrefixLength, pItem->acGateway,
                    pItem->acSource, pItem->uiInterfaceIndex,
                    pItem->acInterfaceName, pItem->uiMetric, pItem->uiTable,
                    (unsigned int)pItem->ucProtocol,
                    (unsigned int)pItem->ucScope);
            }
        }
        (void)fclose(pFile);
    }
    FreeIpsecRouteList(&Routes);
    FreeIpsecAddressList(&Addresses);
    FreeIpsecInterfaceList(&Interfaces);
}

static void SaveFinalState(
    IpsecContext_t *pContext,
    const char *pcDirectory)
{
    IpsecConnectionList_t Connections = {0};
    IpsecIkeSaList_t Ikes = {0};
    IpsecChildSaList_t Children = {0};
    IpsecXfrmStateList_t States = {0};
    IpsecXfrmPolicyList_t Policies = {0};
    IpsecError_t eConnections = GetIpsecConnections(pContext, &Connections);
    IpsecError_t eIkes = GetIpsecIkeSas(pContext, &Ikes);
    IpsecError_t eChildren = GetIpsecChildSas(pContext, &Children);
    IpsecError_t eStates = GetIpsecXfrmStates(pContext, &States);
    IpsecError_t ePolicies = GetIpsecXfrmPolicies(pContext, &Policies);
    FILE *pFile = OpenReportFile(pcDirectory, "final_state.txt", "w");

    if (NULL != pFile) {
        (void)fprintf(pFile,
            "connections_query=%s\nconnections=%" PRIu32 "\n"
            "ike_query=%s\nike=%" PRIu32 "\n"
            "child_query=%s\nchild=%" PRIu32 "\n"
            "xfrm_state_query=%s\nxfrm_states=%" PRIu32 "\n"
            "xfrm_policy_query=%s\nxfrm_policies=%" PRIu32 "\n",
            GetIpsecErrorString(eConnections), Connections.uiCount,
            GetIpsecErrorString(eIkes), Ikes.uiCount,
            GetIpsecErrorString(eChildren), Children.uiCount,
            GetIpsecErrorString(eStates), States.uiCount,
            GetIpsecErrorString(ePolicies), Policies.uiCount);
        (void)fclose(pFile);
    }
    FreeIpsecXfrmPolicyList(&Policies);
    FreeIpsecXfrmStateList(&States);
    FreeIpsecChildSaList(&Children);
    FreeIpsecIkeSaList(&Ikes);
    FreeIpsecConnectionList(&Connections);
}

IpsecError_t WriteNativeAppAlgorithmRunReport(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    NativeAppAlgorithmMode_t eMode,
    const char *pcRole,
    const char *pcResultDirectory,
    uint32_t uiRequested,
    bool bFinal)
{
    FILE *pFile;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pcRole) ||
        (NULL == pcResultDirectory)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (!bFinal) {
        pFile = OpenReportFile(pcResultDirectory, "run_context.txt", "w");
        if (NULL == pFile) {
            return IPSEC_ERR_FILE_OPEN;
        }
        (void)fprintf(pFile,
            "role=%s\nmode=%s\nrequested=%" PRIu32 "\n"
            "local_address=%s\nremote_address=%s\nlocal_id=%s\nremote_id=%s\n"
            "connection=%s\nchild=%s\nipsec_mode=%s\nvici_socket=%s\n"
            "timeout_ms=%" PRIu32 "\n",
            pcRole, GetNativeAppAlgorithmModeName(eMode), uiRequested,
            pConfig->acLocalAddress, pConfig->acRemoteAddress,
            pConfig->acLocalId, pConfig->acRemoteId,
            pConfig->acConnectionName, pConfig->acChildName,
            GetReportMode(pConfig->eMode), pConfig->acViciSocket,
            pConfig->uiTimeoutMs);
        (void)fclose(pFile);
        SaveDaemonStatus(pContext, pcResultDirectory,
                         "daemon_status_initial.txt");
        SaveAlgorithms(pContext, pcResultDirectory);
        SaveNetwork(pcResultDirectory);
        SaveXfrmStatistics(pcResultDirectory, "xfrm_statistics_initial.txt");
        pFile = OpenReportFile(pcResultDirectory, "matrix_summary.csv", "w");
        if (NULL != pFile) {
            (void)fputs(
                "number,case_id,role,ike_proposal,esp_proposal,"
                "negotiated_ike,negotiated_esp,reqid,xfrm_states,"
                "xfrm_policies,ike_result,esp_result,xfrm_result,"
                "data_path_result,duration_ms,peer_result,result,error,cleanup,"
                "cleanup_terminate,cleanup_wait_removed,"
                "cleanup_remove_connection,cleanup_final_verify,cleanup_peer,"
                "cleanup_terminate_attempts,cleanup_wait_attempts,"
                "cleanup_remove_attempts,cleanup_peer_attempts,"
                "cleanup_recovered,cleanup_local_verified\n",
                pFile);
            (void)fclose(pFile);
        }
    }
    else {
        SaveDaemonStatus(pContext, pcResultDirectory,
                         "daemon_status_final.txt");
        SaveXfrmStatistics(pcResultDirectory, "xfrm_statistics_final.txt");
        SaveFinalState(pContext, pcResultDirectory);
    }
    return IPSEC_OK;
}

IpsecError_t CreateNativeAppAlgorithmCaseReport(
    const NativeAppConfig_t *pConfig,
    const NativeAppAlgorithmCase_t *pCase,
    const char *pcRole,
    const char *pcResultDirectory,
    uint32_t uiOrdinal,
    uint32_t uiRequested,
    char *pcCaseDirectory,
    size_t zCaseDirectoryLength)
{
    char acDirectoryName[NATIVE_APP_PATH_LENGTH];
    int32_t iLength;
    FILE *pFile;
    IpsecError_t eError;

    if ((NULL == pConfig) || (NULL == pCase) || (NULL == pcRole) ||
        (NULL == pcResultDirectory) || (NULL == pcCaseDirectory)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    iLength = snprintf(acDirectoryName, sizeof(acDirectoryName),
                       "case_%03" PRIu32 "_%s", pCase->uiNumber, pCase->acId);
    if ((0 > iLength) || ((size_t)iLength >= sizeof(acDirectoryName))) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    eError = JoinReportPath(pcCaseDirectory, zCaseDirectoryLength,
                            pcResultDirectory, acDirectoryName);
    if (IPSEC_OK == eError) {
        eError = CreateReportDirectory(pcCaseDirectory);
    }
    if (IPSEC_OK != eError) {
        return eError;
    }
    pFile = OpenReportFile(pcCaseDirectory, "case_config.txt", "w");
    if (NULL == pFile) {
        return IPSEC_ERR_FILE_OPEN;
    }
    (void)fprintf(pFile,
        "number=%" PRIu32 "\nordinal=%" PRIu32 "\nrequested=%" PRIu32
        "\ncase_id=%s\nrole=%s\nlocal_address=%s\nremote_address=%s\n"
        "local_id=%s\nremote_id=%s\nconnection=%s\nchild=%s\n"
        "ike_proposal=%s\nesp_proposal=%s\nipsec_mode=%s\n"
        "separate_child_exchange=%s\nexpected_child_ke=%s\n"
        "expect_esn=%s\nexpect_no_esn=%s\n",
        pCase->uiNumber, uiOrdinal, uiRequested, pCase->acId, pcRole,
        pConfig->acLocalAddress, pConfig->acRemoteAddress,
        pConfig->acLocalId, pConfig->acRemoteId,
        pConfig->acConnectionName, pConfig->acChildName,
        pCase->acIkeProposal, pCase->acEspProposal,
        GetReportMode(pConfig->eMode),
        pCase->bSeparateChildExchange ? "yes" : "no",
        ('\0' == pCase->acExpectedChildKe[0]) ? "N/A" :
        pCase->acExpectedChildKe, pCase->bExpectEsn ? "yes" : "no",
        pCase->bExpectNoEsn ? "yes" : "no");
    (void)fclose(pFile);
    pFile = OpenReportFile(pcCaseDirectory, "application.log", "w");
    if (NULL != pFile) {
        (void)fprintf(pFile,
            "[INFO] CASE %" PRIu32 "/%" PRIu32 " [%s] role=%s\n"
            "[INFO] IKE proposal: %s\n[INFO] ESP proposal: %s\n",
            uiOrdinal, uiRequested, pCase->acId, pcRole,
            pCase->acIkeProposal, pCase->acEspProposal);
        (void)fclose(pFile);
    }
    return IPSEC_OK;
}

static void SaveSaSnapshot(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const char *pcCaseDirectory)
{
    IpsecIkeSaList_t Ikes = {0};
    IpsecChildSaList_t Children = {0};
    IpsecError_t eIke = GetIpsecIkeSas(pContext, &Ikes);
    IpsecError_t eChild = GetIpsecChildSas(pContext, &Children);
    FILE *pFile = OpenReportFile(pcCaseDirectory, "sa_snapshot.txt", "w");
    uint32_t uiIndex;

    if (NULL != pFile) {
        (void)fprintf(pFile, "ike_query=%s count=%" PRIu32 "\n",
                      GetIpsecErrorString(eIke), Ikes.uiCount);
        if (IPSEC_OK == eIke) {
            for (uiIndex = 0U; uiIndex < Ikes.uiCount; uiIndex++) {
                const IpsecIkeSaInfo_t *pItem = &Ikes.pItems[uiIndex];
                if (0 == strcmp(pConfig->acConnectionName, pItem->acName)) {
                    (void)fprintf(pFile,
                        "IKE name=%s state=%s established=%s initiator=%s "
                        "unique_id=%" PRIu64 " local=%s remote=%s "
                        "local_id=%s remote_id=%s proposal=%s nat_local=%s "
                        "nat_remote=%s established_ms=%" PRIu64
                        " rekey_ms=%" PRIu64 "\n",
                        pItem->acName, pItem->acState,
                        pItem->bEstablished ? "yes" : "no",
                        pItem->bInitiator ? "yes" : "no",
                        pItem->ullUniqueId, pItem->acLocalAddress,
                        pItem->acRemoteAddress, pItem->acLocalId,
                        pItem->acRemoteId, pItem->acProposal,
                        pItem->bNatLocal ? "yes" : "no",
                        pItem->bNatRemote ? "yes" : "no",
                        pItem->ullEstablishedTimeMs, pItem->ullRekeyTimeMs);
                }
            }
        }
        (void)fprintf(pFile, "child_query=%s count=%" PRIu32 "\n",
                      GetIpsecErrorString(eChild), Children.uiCount);
        if (IPSEC_OK == eChild) {
            for (uiIndex = 0U; uiIndex < Children.uiCount; uiIndex++) {
                const IpsecChildSaInfo_t *pItem = &Children.pItems[uiIndex];
                if (0 == strcmp(pConfig->acChildName, pItem->acName)) {
                    (void)fprintf(pFile,
                        "CHILD ike=%s name=%s state=%s reqid=%" PRIu32
                        " spi_in=0x%08" PRIx32 " spi_out=0x%08" PRIx32
                        " mode=%s esn=%s udp=%s proposal=%s local_ts=%s "
                        "remote_ts=%s bytes_in=%" PRIu64
                        " bytes_out=%" PRIu64 " packets_in=%" PRIu64
                        " packets_out=%" PRIu64 " install_ms=%" PRIu64
                        " rekey_ms=%" PRIu64 " lifetime_ms=%" PRIu64 "\n",
                        pItem->acIkeName, pItem->acName, pItem->acState,
                        pItem->uiReqid, pItem->uiInboundSpi,
                        pItem->uiOutboundSpi, GetReportMode(pItem->eMode),
                        pItem->bEsn ? "yes" : "no",
                        pItem->bUdpEncapsulation ? "yes" : "no",
                        pItem->acProposal, pItem->acLocalTrafficSelectors,
                        pItem->acRemoteTrafficSelectors, pItem->ullBytesIn,
                        pItem->ullBytesOut, pItem->ullPacketsIn,
                        pItem->ullPacketsOut, pItem->ullInstallTimeMs,
                        pItem->ullRekeyTimeMs, pItem->ullLifetimeMs);
                }
            }
        }
        (void)fclose(pFile);
    }
    FreeIpsecChildSaList(&Children);
    FreeIpsecIkeSaList(&Ikes);
}

IpsecError_t CaptureNativeAppAlgorithmCaseReport(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const NativeAppAlgorithmCaseResult_t *pResult,
    const char *pcCaseDirectory)
{
    IpsecXfrmStateList_t States = {0};
    IpsecXfrmPolicyList_t Policies = {0};
    IpsecError_t eState;
    IpsecError_t ePolicy;
    FILE *pFile;
    uint32_t uiIndex;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pResult) ||
        (NULL == pcCaseDirectory)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    SaveSaSnapshot(pContext, pConfig, pcCaseDirectory);
    eState = GetIpsecXfrmStates(pContext, &States);
    ePolicy = GetIpsecXfrmPolicies(pContext, &Policies);
    pFile = OpenReportFile(pcCaseDirectory, "xfrm_states_active.txt", "w");
    if (NULL != pFile) {
        (void)fprintf(pFile, "query=%s count=%" PRIu32 " reqid=%" PRIu32 "\n",
                      GetIpsecErrorString(eState), States.uiCount,
                      pResult->uiReqid);
        if (IPSEC_OK == eState) {
            for (uiIndex = 0U; uiIndex < States.uiCount; uiIndex++) {
                const IpsecXfrmStateInfo_t *pItem = &States.pItems[uiIndex];
                if (pResult->uiReqid == pItem->uiReqid) {
                    (void)fprintf(pFile,
                        "family=%s source=%s destination=%s protocol=%" PRIu32
                        " spi=0x%08" PRIx32 " reqid=%" PRIu32 " mode=%s "
                        "encryption=%s integrity=%s aead=%s esn=%s "
                        "replay_window=%" PRIu32 " packets=%" PRIu64
                        " bytes=%" PRIu64 " add_time=%" PRIu64
                        " use_time=%" PRIu64 " soft_bytes=%" PRIu64
                        " hard_bytes=%" PRIu64 " soft_packets=%" PRIu64
                        " hard_packets=%" PRIu64 "\n",
                        GetReportFamily(pItem->eFamily), pItem->acSource,
                        pItem->acDestination, pItem->uiProtocol, pItem->uiSpi,
                        pItem->uiReqid, GetReportMode(pItem->eMode),
                        pItem->acEncryptionAlgorithm,
                        pItem->acIntegrityAlgorithm, pItem->acAeadAlgorithm,
                        pItem->bEsn ? "yes" : "no", pItem->uiReplayWindow,
                        pItem->ullPacketCount, pItem->ullByteCount,
                        pItem->ullAddTimeSeconds, pItem->ullUseTimeSeconds,
                        pItem->ullSoftByteLimit, pItem->ullHardByteLimit,
                        pItem->ullSoftPacketLimit, pItem->ullHardPacketLimit);
                }
            }
        }
        (void)fclose(pFile);
    }
    pFile = OpenReportFile(pcCaseDirectory, "xfrm_policies_active.txt", "w");
    if (NULL != pFile) {
        (void)fprintf(pFile, "query=%s count=%" PRIu32 " reqid=%" PRIu32 "\n",
                      GetIpsecErrorString(ePolicy), Policies.uiCount,
                      pResult->uiReqid);
        if (IPSEC_OK == ePolicy) {
            for (uiIndex = 0U; uiIndex < Policies.uiCount; uiIndex++) {
                const IpsecXfrmPolicyInfo_t *pItem = &Policies.pItems[uiIndex];
                if (pResult->uiReqid == pItem->uiReqid) {
                    (void)fprintf(pFile,
                        "family=%s direction=%s source=%s/%u destination=%s/%u "
                        "priority=%" PRIu32 " index=%" PRIu32
                        " reqid=%" PRIu32 " mode=%s template_source=%s "
                        "template_destination=%s protocol=%" PRIu32 "\n",
                        GetReportFamily(pItem->eFamily),
                        GetReportDirection(pItem->eDirection),
                        pItem->acSourceSelector,
                        (unsigned int)pItem->ucSourcePrefixLength,
                        pItem->acDestinationSelector,
                        (unsigned int)pItem->ucDestinationPrefixLength,
                        pItem->uiPriority, pItem->uiIndex, pItem->uiReqid,
                        GetReportMode(pItem->eMode),
                        pItem->acTemplateSource, pItem->acTemplateDestination,
                        pItem->uiProtocol);
                }
            }
        }
        (void)fclose(pFile);
    }
    SaveXfrmStatistics(pcCaseDirectory, "xfrm_statistics_active.txt");
    FreeIpsecXfrmPolicyList(&Policies);
    FreeIpsecXfrmStateList(&States);
    return ((IPSEC_OK == eState) && (IPSEC_OK == ePolicy)) ?
        IPSEC_OK : IPSEC_ERR_INTERNAL;
}

static void CountCleanupState(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    uint32_t uiReqid,
    uint32_t *puiConnections,
    uint32_t *puiIkes,
    uint32_t *puiChildren,
    uint32_t *puiStates,
    uint32_t *puiPolicies)
{
    IpsecConnectionList_t Connections = {0};
    IpsecIkeSaList_t Ikes = {0};
    IpsecChildSaList_t Children = {0};
    IpsecXfrmStateList_t States = {0};
    IpsecXfrmPolicyList_t Policies = {0};
    uint32_t uiIndex;

    (void)GetIpsecConnections(pContext, &Connections);
    (void)GetIpsecIkeSas(pContext, &Ikes);
    (void)GetIpsecChildSas(pContext, &Children);
    (void)GetIpsecXfrmStates(pContext, &States);
    (void)GetIpsecXfrmPolicies(pContext, &Policies);
    for (uiIndex = 0U; uiIndex < Connections.uiCount; uiIndex++) {
        *puiConnections += (0 == strcmp(
            pConfig->acConnectionName, Connections.pItems[uiIndex].acName)) ?
            1U : 0U;
    }
    for (uiIndex = 0U; uiIndex < Ikes.uiCount; uiIndex++) {
        *puiIkes += (0 == strcmp(
            pConfig->acConnectionName, Ikes.pItems[uiIndex].acName)) ? 1U : 0U;
    }
    for (uiIndex = 0U; uiIndex < Children.uiCount; uiIndex++) {
        *puiChildren += (0 == strcmp(
            pConfig->acChildName, Children.pItems[uiIndex].acName)) ? 1U : 0U;
    }
    for (uiIndex = 0U; uiIndex < States.uiCount; uiIndex++) {
        *puiStates += ((0U != uiReqid) &&
            (uiReqid == States.pItems[uiIndex].uiReqid)) ? 1U : 0U;
    }
    for (uiIndex = 0U; uiIndex < Policies.uiCount; uiIndex++) {
        *puiPolicies += ((0U != uiReqid) &&
            (uiReqid == Policies.pItems[uiIndex].uiReqid)) ? 1U : 0U;
    }
    FreeIpsecXfrmPolicyList(&Policies);
    FreeIpsecXfrmStateList(&States);
    FreeIpsecChildSaList(&Children);
    FreeIpsecIkeSaList(&Ikes);
    FreeIpsecConnectionList(&Connections);
}

IpsecError_t FinishNativeAppAlgorithmCaseReport(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const NativeAppAlgorithmCaseResult_t *pResult,
    const char *pcRole,
    const char *pcResultDirectory,
    const char *pcCaseDirectory,
    uint32_t uiOrdinal,
    uint32_t uiRequested)
{
    uint32_t uiConnections = 0U;
    uint32_t uiIkes = 0U;
    uint32_t uiChildren = 0U;
    uint32_t uiStates = 0U;
    uint32_t uiPolicies = 0U;
    FILE *pFile;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pResult) ||
        (NULL == pcRole) || (NULL == pcResultDirectory) ||
        (NULL == pcCaseDirectory)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    CountCleanupState(pContext, pConfig, pResult->uiReqid,
                      &uiConnections, &uiIkes, &uiChildren,
                      &uiStates, &uiPolicies);
    pFile = OpenReportFile(pcCaseDirectory, "cleanup_state.txt", "w");
    if (NULL != pFile) {
        (void)fprintf(pFile,
            "cleanup=%s\nconnection_remaining=%" PRIu32
            "\nterminate_error=%s\nwait_removed_error=%s"
            "\nremove_connection_error=%s\nfinal_verify_error=%s"
            "\npeer_error=%s\nterminate_attempts=%" PRIu32
            "\nwait_removed_attempts=%" PRIu32
            "\nremove_connection_attempts=%" PRIu32
            "\npeer_attempts=%" PRIu32
            "\nrecovered=%s\nlocal_verified=%s"
            "\nike_remaining=%" PRIu32 "\nchild_remaining=%" PRIu32
            "\nxfrm_states_remaining=%" PRIu32
            "\nxfrm_policies_remaining=%" PRIu32 "\n",
            GetNativeAppAlgorithmErrorText(pResult->eCleanupError),
            uiConnections,
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eTerminateError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eWaitRemovedError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eRemoveConnectionError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eFinalVerifyError),
            GetNativeAppAlgorithmErrorText(pResult->Cleanup.ePeerError),
            pResult->Cleanup.uiTerminateAttempts,
            pResult->Cleanup.uiWaitRemovedAttempts,
            pResult->Cleanup.uiRemoveConnectionAttempts,
            pResult->Cleanup.uiPeerAttempts,
            pResult->Cleanup.bRecovered ? "yes" : "no",
            pResult->Cleanup.bLocalVerified ? "yes" : "no", uiIkes,
            uiChildren, uiStates, uiPolicies);
        (void)fclose(pFile);
    }
    pFile = OpenReportFile(pcCaseDirectory, "result_summary.txt", "w");
    if (NULL != pFile) {
        (void)fprintf(pFile,
            "number=%" PRIu32 "\nordinal=%" PRIu32 "\nrequested=%" PRIu32
            "\ncase_id=%s\nrole=%s\nike_proposal=%s\nesp_proposal=%s\n"
            "negotiated_ike=%s\nnegotiated_esp=%s\nreqid=%" PRIu32
            "\nxfrm_states_active=%" PRIu32
            "\nxfrm_policies_active=%" PRIu32
            "\npeer_result=%s\nduration_ms=%" PRIu64
            "\nike_result=%s\nesp_result=%s\nxfrm_result=%s\n"
            "data_path_result=%s\n"
            "\nresult=%s\nerror=%s\ncleanup=%s"
            "\ncleanup_terminate=%s\ncleanup_wait_removed=%s"
            "\ncleanup_remove_connection=%s\ncleanup_final_verify=%s"
            "\ncleanup_peer=%s\ncleanup_terminate_attempts=%" PRIu32
            "\ncleanup_wait_attempts=%" PRIu32
            "\ncleanup_remove_attempts=%" PRIu32
            "\ncleanup_peer_attempts=%" PRIu32
            "\ncleanup_recovered=%s\ncleanup_local_verified=%s\n"
            "connection_remaining=%" PRIu32 "\nike_remaining=%" PRIu32
            "\nchild_remaining=%" PRIu32
            "\nxfrm_states_remaining=%" PRIu32
            "\nxfrm_policies_remaining=%" PRIu32 "\noverall=%s\n",
            pResult->Case.uiNumber, uiOrdinal, uiRequested,
            pResult->Case.acId, pcRole, pResult->Case.acIkeProposal,
            pResult->Case.acEspProposal, pResult->acNegotiatedIke,
            pResult->acNegotiatedEsp, pResult->uiReqid,
            pResult->uiXfrmStateCount, pResult->uiXfrmPolicyCount,
            ('\0' == pResult->acPeerResult[0]) ? "N/A" :
            pResult->acPeerResult, pResult->ullDurationMs,
            pResult->bIkeVerified ? "PASS" : "FAIL",
            pResult->bEspVerified ? "PASS" : "FAIL",
            pResult->bXfrmVerified ? "PASS" : "FAIL",
            pResult->bDataPathVerified ? "PASS" : "FAIL",
            GetNativeAppAlgorithmResultName(pResult->eResult),
            GetNativeAppAlgorithmErrorText(pResult->eError),
            GetNativeAppAlgorithmErrorText(pResult->eCleanupError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eTerminateError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eWaitRemovedError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eRemoveConnectionError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eFinalVerifyError),
            GetNativeAppAlgorithmErrorText(pResult->Cleanup.ePeerError),
            pResult->Cleanup.uiTerminateAttempts,
            pResult->Cleanup.uiWaitRemovedAttempts,
            pResult->Cleanup.uiRemoveConnectionAttempts,
            pResult->Cleanup.uiPeerAttempts,
            pResult->Cleanup.bRecovered ? "yes" : "no",
            pResult->Cleanup.bLocalVerified ? "yes" : "no",
            uiConnections, uiIkes,
            uiChildren, uiStates, uiPolicies,
            (NATIVE_APP_ALGORITHM_RESULT_PASS == pResult->eResult) ?
            "PASS" : "FAIL");
        (void)fclose(pFile);
    }
    pFile = OpenReportFile(pcCaseDirectory, "ike_result.txt", "w");
    if (NULL != pFile) {
        (void)fprintf(pFile,
            "case_id=%s\nrole=%s\nrequested_proposal=%s\n"
            "established=%s\nnegotiated_proposal=%s\nresult=%s\n",
            pResult->Case.acId, pcRole, pResult->Case.acIkeProposal,
            pResult->bIkeVerified ? "yes" : "no",
            ('\0' == pResult->acNegotiatedIke[0]) ? "N/A" :
            pResult->acNegotiatedIke,
            pResult->bIkeVerified ? "PASS" : "FAIL");
        (void)fclose(pFile);
    }
    pFile = OpenReportFile(pcCaseDirectory, "esp_result.txt", "w");
    if (NULL != pFile) {
        bool bEspOverall = pResult->bEspVerified &&
            pResult->bXfrmVerified && pResult->bDataPathVerified;

        (void)fprintf(pFile,
            "case_id=%s\nrole=%s\nexchange=%s\nrequested_proposal=%s\n"
            "child_installed=%s\nnegotiated_proposal=%s\n"
            "separate_child_exchange=%s\nexpected_child_ke=%s\n"
            "expect_esn=%s\nexpect_no_esn=%s\nreqid=%" PRIu32
            "\nxfrm_states=%" PRIu32 "\nxfrm_policies=%" PRIu32
            "\nxfrm_result=%s\ndata_path_result=%s\npeer_result=%s\n"
            "result=%s\n",
            pResult->Case.acId, pcRole,
            pResult->Case.bSeparateChildExchange ?
            "CREATE_CHILD_SA" : "IKE_AUTH_CHILD_SA",
            pResult->Case.acEspProposal,
            pResult->bEspVerified ? "yes" : "no",
            ('\0' == pResult->acNegotiatedEsp[0]) ? "N/A" :
            pResult->acNegotiatedEsp,
            pResult->Case.bSeparateChildExchange ? "yes" : "no",
            ('\0' == pResult->Case.acExpectedChildKe[0]) ? "N/A" :
            pResult->Case.acExpectedChildKe,
            pResult->Case.bExpectEsn ? "yes" : "no",
            pResult->Case.bExpectNoEsn ? "yes" : "no",
            pResult->uiReqid, pResult->uiXfrmStateCount,
            pResult->uiXfrmPolicyCount,
            pResult->bXfrmVerified ? "PASS" : "FAIL",
            pResult->bDataPathVerified ? "PASS" : "FAIL",
            ('\0' == pResult->acPeerResult[0]) ? "N/A" :
            pResult->acPeerResult, bEspOverall ? "PASS" : "FAIL");
        (void)fclose(pFile);
    }
    pFile = OpenReportFile(pcCaseDirectory, "application.log", "a");
    if (NULL != pFile) {
        (void)fprintf(pFile,
            "[INFO] negotiated IKE: %s\n[INFO] negotiated ESP: %s\n"
            "[INFO] reqid=%" PRIu32 " XFRM states=%" PRIu32
            " policies=%" PRIu32 "\n[%s] IKE phase=%s\n"
            "[%s] ESP phase=%s XFRM=%s DATA_PATH=%s\n"
            "[%s] result=%s error=%s "
            "cleanup=%s duration=%" PRIu64 " ms\n"
            "[INFO] cleanup stages: terminate=%s wait_removed=%s "
            "remove_connection=%s final_verify=%s peer=%s "
            "attempts=%" PRIu32 "/%" PRIu32 "/%" PRIu32 "/%" PRIu32
            " recovered=%s local_verified=%s\n",
            pResult->acNegotiatedIke, pResult->acNegotiatedEsp,
            pResult->uiReqid, pResult->uiXfrmStateCount,
            pResult->uiXfrmPolicyCount,
            pResult->bIkeVerified ? "PASS" : "FAIL",
            pResult->bIkeVerified ? "PASS" : "FAIL",
            pResult->bEspVerified ? "PASS" : "FAIL",
            pResult->bEspVerified ? "PASS" : "FAIL",
            pResult->bXfrmVerified ? "PASS" : "FAIL",
            pResult->bDataPathVerified ? "PASS" : "FAIL",
            (NATIVE_APP_ALGORITHM_RESULT_PASS == pResult->eResult) ?
            "PASS" : "FAIL",
            GetNativeAppAlgorithmResultName(pResult->eResult),
            GetNativeAppAlgorithmErrorText(pResult->eError),
            GetNativeAppAlgorithmErrorText(pResult->eCleanupError),
            pResult->ullDurationMs,
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eTerminateError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eWaitRemovedError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eRemoveConnectionError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eFinalVerifyError),
            GetNativeAppAlgorithmErrorText(pResult->Cleanup.ePeerError),
            pResult->Cleanup.uiTerminateAttempts,
            pResult->Cleanup.uiWaitRemovedAttempts,
            pResult->Cleanup.uiRemoveConnectionAttempts,
            pResult->Cleanup.uiPeerAttempts,
            pResult->Cleanup.bRecovered ? "yes" : "no",
            pResult->Cleanup.bLocalVerified ? "yes" : "no");
        (void)fclose(pFile);
    }
    pFile = OpenReportFile(pcResultDirectory, "matrix_summary.csv", "a");
    if (NULL != pFile) {
        (void)fprintf(pFile,
            "%" PRIu32 ",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\","
            "%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",\"%s\",\"%s\",\"%s\","
            "\"%s\",%" PRIu64 ",\"%s\","
            "\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\","
            "\"%s\",%" PRIu32 ",%" PRIu32 ",%" PRIu32 ",%" PRIu32
            ",\"%s\",\"%s\"\n",
            pResult->Case.uiNumber, pResult->Case.acId, pcRole,
            pResult->Case.acIkeProposal, pResult->Case.acEspProposal,
            pResult->acNegotiatedIke, pResult->acNegotiatedEsp,
            pResult->uiReqid, pResult->uiXfrmStateCount,
            pResult->uiXfrmPolicyCount,
            pResult->bIkeVerified ? "PASS" : "FAIL",
            pResult->bEspVerified ? "PASS" : "FAIL",
            pResult->bXfrmVerified ? "PASS" : "FAIL",
            pResult->bDataPathVerified ? "PASS" : "FAIL",
            pResult->ullDurationMs,
            ('\0' == pResult->acPeerResult[0]) ? "N/A" :
            pResult->acPeerResult,
            GetNativeAppAlgorithmResultName(pResult->eResult),
            GetNativeAppAlgorithmErrorText(pResult->eError),
            GetNativeAppAlgorithmErrorText(pResult->eCleanupError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eTerminateError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eWaitRemovedError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eRemoveConnectionError),
            GetNativeAppAlgorithmErrorText(
                pResult->Cleanup.eFinalVerifyError),
            GetNativeAppAlgorithmErrorText(pResult->Cleanup.ePeerError),
            pResult->Cleanup.uiTerminateAttempts,
            pResult->Cleanup.uiWaitRemovedAttempts,
            pResult->Cleanup.uiRemoveConnectionAttempts,
            pResult->Cleanup.uiPeerAttempts,
            pResult->Cleanup.bRecovered ? "yes" : "no",
            pResult->Cleanup.bLocalVerified ? "yes" : "no");
        (void)fclose(pFile);
    }
    return IPSEC_OK;
}
