#include "app_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define NATIVE_APP_ALGORITHM_PROTOCOL       "IPSEC-ALGORITHM-1"
#define NATIVE_APP_ALGORITHM_MESSAGE_LENGTH 1024U
#define NATIVE_APP_ALGORITHM_POLL_MS         500U
#define NATIVE_APP_ALGORITHM_CLEANUP_ATTEMPTS 3U
#define NATIVE_APP_ALGORITHM_CLEANUP_WAIT_MS  5000U
#define NATIVE_APP_ALGORITHM_CLEANUP_RETRY_MS 200U
#define NATIVE_APP_ARRAY_COUNT(a) \
    ((uint32_t)(sizeof(a) / sizeof((a)[0])))

typedef struct NativeAppAlgorithmEndpoint {
    struct sockaddr_storage Address;
    socklen_t zLength;
} NativeAppAlgorithmEndpoint_t;

typedef struct NativeAppAlgorithmJsonWriter {
    FILE *pFile;
    long lTailOffset;
    uint32_t uiCaseCount;
    uint32_t uiPassed;
    uint32_t uiFailed;
} NativeAppAlgorithmJsonWriter_t;

static void SleepNativeAppAlgorithm(uint32_t uiMilliseconds)
{
    struct timespec Time;

    Time.tv_sec = (time_t)(uiMilliseconds / 1000U);
    Time.tv_nsec = (long)((uiMilliseconds % 1000U) * 1000000U);
    while ((0 != nanosleep(&Time, &Time)) && (EINTR == errno) &&
           !IsNativeAppStopRequested()) {
        /* Resume an interrupted verification delay. */
    }
}

static uint64_t GetNativeAppAlgorithmTimeMs(void)
{
    struct timespec Time = {0};

    if (0 != clock_gettime(CLOCK_MONOTONIC, &Time)) {
        return 0U;
    }
    else {
        return ((uint64_t)Time.tv_sec * 1000U) +
               ((uint64_t)Time.tv_nsec / 1000000U);
    }
}

const char *GetNativeAppAlgorithmResultName(
    NativeAppAlgorithmResult_t eResult)
{
    const char *pcName;

    switch (eResult) {
    case NATIVE_APP_ALGORITHM_RESULT_PASS:
        pcName = "PASS";
        break;
    case NATIVE_APP_ALGORITHM_RESULT_FAIL_CONFIG:
        pcName = "FAIL_CONFIG";
        break;
    case NATIVE_APP_ALGORITHM_RESULT_FAIL_SYNC:
        pcName = "FAIL_SYNC";
        break;
    case NATIVE_APP_ALGORITHM_RESULT_FAIL_IKE:
        pcName = "FAIL_IKE";
        break;
    case NATIVE_APP_ALGORITHM_RESULT_FAIL_CHILD:
        pcName = "FAIL_CHILD";
        break;
    case NATIVE_APP_ALGORITHM_RESULT_FAIL_PROPOSAL:
        pcName = "FAIL_PROPOSAL";
        break;
    case NATIVE_APP_ALGORITHM_RESULT_FAIL_PFS:
        pcName = "FAIL_PFS";
        break;
    case NATIVE_APP_ALGORITHM_RESULT_FAIL_ESN:
        pcName = "FAIL_ESN";
        break;
    case NATIVE_APP_ALGORITHM_RESULT_FAIL_XFRM:
        pcName = "FAIL_XFRM";
        break;
    case NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH:
        pcName = "FAIL_DATA_PATH";
        break;
    case NATIVE_APP_ALGORITHM_RESULT_FAIL_CLEANUP:
        pcName = "FAIL_CLEANUP";
        break;
    default:
        pcName = "STOPPED";
        break;
    }
    return pcName;
}

static IpsecError_t CopyNativeAppAlgorithmValue(
    char *pcDestination,
    size_t zDestinationLength,
    const char *pcSource)
{
    int32_t iLength;

    if ((NULL == pcDestination) || (0U == zDestinationLength) ||
        (NULL == pcSource)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        iLength = snprintf(pcDestination, zDestinationLength, "%s", pcSource);
    }
    if ((0 > iLength) || ((size_t)iLength >= zDestinationLength)) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        return IPSEC_OK;
    }
}

static void ReportNativeAppAlgorithm(
    FILE *pLog,
    FILE *pStream,
    const char *pcLevel,
    const char *pcFormat,
    ...)
{
    char acTimestamp[32] = {0};
    struct tm TimeValue;
    time_t TimeNow = time(NULL);
    va_list Arguments;
    va_list LogArguments;

    va_start(Arguments, pcFormat);
    va_copy(LogArguments, Arguments);
    (void)vfprintf(pStream, pcFormat, Arguments);
    (void)fputc('\n', pStream);
    (void)fflush(pStream);
    va_end(Arguments);

    if ((NULL != pLog) &&
        (NULL != localtime_r(&TimeNow, &TimeValue)) &&
        (0U < strftime(acTimestamp, sizeof(acTimestamp),
                       "%Y-%m-%d %H:%M:%S", &TimeValue))) {
        (void)fprintf(pLog, "[%s] [%s] ", acTimestamp, pcLevel);
        (void)vfprintf(pLog, pcFormat, LogArguments);
        (void)fputc('\n', pLog);
        (void)fflush(pLog);
    }
    else {
        /* Console reporting remains available when no result log is open. */
    }
    va_end(LogArguments);
}

static IpsecError_t CreateNativeAppAlgorithmDirectory(const char *pcPath)
{
    char acPath[NATIVE_APP_PATH_LENGTH];
    char *pcCursor;
    IpsecError_t eError;

    eError = CopyNativeAppAlgorithmValue(acPath, sizeof(acPath), pcPath);
    if (IPSEC_OK != eError) {
        return eError;
    }
    for (pcCursor = acPath + 1; '\0' != *pcCursor; pcCursor++) {
        if ('/' == *pcCursor) {
            *pcCursor = '\0';
            if ((0 != mkdir(acPath, 0750)) && (EEXIST != errno)) {
                return IPSEC_ERR_FILE_OPEN;
            }
            else {
                *pcCursor = '/';
            }
        }
        else {
            /* Continue through the current path component. */
        }
    }
    if ((0 != mkdir(acPath, 0750)) && (EEXIST != errno)) {
        eError = IPSEC_ERR_FILE_OPEN;
    }
    else {
        struct stat Status;

        eError = ((0 == stat(acPath, &Status)) && S_ISDIR(Status.st_mode)) ?
            IPSEC_OK : IPSEC_ERR_FILE_OPEN;
    }
    return eError;
}

static IpsecError_t JoinNativeAppAlgorithmPath(
    char *pcPath,
    size_t zPathLength,
    const char *pcDirectory,
    const char *pcName)
{
    int32_t iLength;
    size_t zDirectoryLength;

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

static IpsecError_t CreateNativeAppAlgorithmRunId(
    NativeAppAlgorithmMode_t eMode,
    char *pcRunId,
    size_t zRunIdLength)
{
    char acTimestamp[32];
    struct tm TimeValue;
    time_t TimeNow = time(NULL);
    int32_t iLength;

    if ((NULL == pcRunId) || (0U == zRunIdLength) ||
        (NULL == localtime_r(&TimeNow, &TimeValue)) ||
        (0U == strftime(acTimestamp, sizeof(acTimestamp),
                        "%Y%m%d_%H%M%S", &TimeValue))) {
        return IPSEC_ERR_INTERNAL;
    }
    iLength = snprintf(pcRunId, zRunIdLength, "%s_%s_%ld",
                       GetNativeAppAlgorithmModeName(eMode), acTimestamp,
                       (long)getpid());
    return ((0 <= iLength) && ((size_t)iLength < zRunIdLength)) ?
        IPSEC_OK : IPSEC_ERR_BUFFER_TOO_SMALL;
}

static bool IsNativeAppAlgorithmRunIdValid(const char *pcRunId)
{
    const unsigned char *pucCursor = (const unsigned char *)pcRunId;
    size_t zLength;

    if (NULL == pcRunId) {
        return false;
    }
    zLength = strnlen(pcRunId, NATIVE_APP_ALGORITHM_RUN_ID_LENGTH);
    if ((0U == zLength) ||
        (NATIVE_APP_ALGORITHM_RUN_ID_LENGTH <= zLength)) {
        return false;
    }
    while ('\0' != *pucCursor) {
        if (((*pucCursor >= (unsigned char)'a') &&
             (*pucCursor <= (unsigned char)'z')) ||
            ((*pucCursor >= (unsigned char)'A') &&
             (*pucCursor <= (unsigned char)'Z')) ||
            ((*pucCursor >= (unsigned char)'0') &&
             (*pucCursor <= (unsigned char)'9')) ||
            ((unsigned char)'_' == *pucCursor) ||
            ((unsigned char)'-' == *pucCursor)) {
            pucCursor++;
        }
        else {
            return false;
        }
    }
    return true;
}

static NativeAppAlgorithmMode_t GetNativeAppAlgorithmRunMode(
    const char *pcRunId)
{
    NativeAppAlgorithmMode_t eMode;

    if (0 == strncmp(pcRunId, "baseline_", strlen("baseline_"))) {
        eMode = NATIVE_APP_ALGORITHM_BASELINE;
    }
    else if (0 == strncmp(pcRunId, "exhaustive-ike_",
                          strlen("exhaustive-ike_"))) {
        eMode = NATIVE_APP_ALGORITHM_EXHAUSTIVE_IKE;
    }
    else if (0 == strncmp(pcRunId, "exhaustive-esp_",
                          strlen("exhaustive-esp_"))) {
        eMode = NATIVE_APP_ALGORITHM_EXHAUSTIVE_ESP;
    }
    else {
        eMode = NATIVE_APP_ALGORITHM_CUSTOM;
    }
    return eMode;
}

static IpsecError_t OpenNativeAppAlgorithmRunLog(
    const NativeAppConfig_t *pConfig,
    const char *pcRunId,
    const char *pcRole,
    char *pcResultDirectory,
    size_t zResultDirectoryLength,
    FILE **ppLog)
{
    char acDirectoryName[NATIVE_APP_PATH_LENGTH];
    char acLogPath[NATIVE_APP_PATH_LENGTH];
    int32_t iLength;
    IpsecError_t eError;

    iLength = snprintf(acDirectoryName, sizeof(acDirectoryName), "%s_%s",
                       pcRunId, pcRole);
    if ((0 > iLength) || ((size_t)iLength >= sizeof(acDirectoryName))) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    eError = JoinNativeAppAlgorithmPath(
        pcResultDirectory, zResultDirectoryLength, pConfig->acOutputRoot,
        acDirectoryName);
    if (IPSEC_OK == eError) {
        eError = CreateNativeAppAlgorithmDirectory(pcResultDirectory);
    }
    if (IPSEC_OK == eError) {
        eError = JoinNativeAppAlgorithmPath(
            acLogPath, sizeof(acLogPath), pcResultDirectory,
            "application.log");
    }
    if (IPSEC_OK == eError) {
        *ppLog = fopen(acLogPath, "w");
        if (NULL == *ppLog) {
            eError = IPSEC_ERR_FILE_OPEN;
        }
    }
    return eError;
}

static IpsecError_t BuildNativeAppAlgorithmConfig(
    const NativeAppConfig_t *pBaseConfig,
    const NativeAppAlgorithmCase_t *pCase,
    NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime)
{
    char acError[NATIVE_APP_ERROR_TEXT_LENGTH] = {0};
    IpsecError_t eError;

    if ((NULL == pBaseConfig) || (NULL == pCase) || (NULL == pConfig) ||
        (NULL == pRuntime)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        *pConfig = *pBaseConfig;
        pConfig->bChildlessIke = pCase->bSeparateChildExchange;
    }
    eError = CopyNativeAppAlgorithmValue(
        pConfig->acIkeProposals, sizeof(pConfig->acIkeProposals),
        pCase->acIkeProposal);
    if (IPSEC_OK == eError) {
        eError = CopyNativeAppAlgorithmValue(
            pConfig->acEspProposals, sizeof(pConfig->acEspProposals),
            pCase->acEspProposal);
    }
    else {
        /* Preserve the IKE proposal copy error. */
    }
    if (IPSEC_OK == eError) {
        eError = BuildNativeAppRuntimeConfig(pConfig, pRuntime, acError,
                                             sizeof(acError));
    }
    else {
        /* Preserve the proposal copy error. */
    }
    if (IPSEC_OK != eError) {
        (void)fprintf(stderr, "algorithm config failed for %s: %s\n",
                      pCase->acId, ('\0' != acError[0]) ? acError :
                      GetIpsecErrorString(eError));
    }
    else {
        /* Return the testcase-specific runtime view. */
    }
    return eError;
}

static IpsecError_t InitializeNativeAppAlgorithmEndpoint(
    const char *pcAddress,
    uint32_t uiPort,
    NativeAppAlgorithmEndpoint_t *pEndpoint)
{
    struct sockaddr_in *pIpv4;
    struct sockaddr_in6 *pIpv6;

    if ((NULL == pcAddress) || (NULL == pEndpoint) ||
        (0U == uiPort) || (UINT16_MAX < uiPort)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        (void)memset(pEndpoint, 0, sizeof(*pEndpoint));
        pIpv4 = (struct sockaddr_in *)&pEndpoint->Address;
        pIpv6 = (struct sockaddr_in6 *)&pEndpoint->Address;
    }
    if (1 == inet_pton(AF_INET, pcAddress, &pIpv4->sin_addr)) {
        pIpv4->sin_family = AF_INET;
        pIpv4->sin_port = htons((uint16_t)uiPort);
        pEndpoint->zLength = sizeof(*pIpv4);
    }
    else if (1 == inet_pton(AF_INET6, pcAddress, &pIpv6->sin6_addr)) {
        pIpv6->sin6_family = AF_INET6;
        pIpv6->sin6_port = htons((uint16_t)uiPort);
        pEndpoint->zLength = sizeof(*pIpv6);
    }
    else {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    return IPSEC_OK;
}

static bool MatchNativeAppAlgorithmPeer(
    const NativeAppAlgorithmEndpoint_t *pExpected,
    const struct sockaddr_storage *pActual)
{
    if ((NULL == pExpected) || (NULL == pActual) ||
        (pExpected->Address.ss_family != pActual->ss_family)) {
        return false;
    }
    else if (AF_INET == pActual->ss_family) {
        const struct sockaddr_in *pExpectedIpv4 =
            (const struct sockaddr_in *)&pExpected->Address;
        const struct sockaddr_in *pActualIpv4 =
            (const struct sockaddr_in *)pActual;

        return (pExpectedIpv4->sin_addr.s_addr ==
                pActualIpv4->sin_addr.s_addr);
    }
    else if (AF_INET6 == pActual->ss_family) {
        const struct sockaddr_in6 *pExpectedIpv6 =
            (const struct sockaddr_in6 *)&pExpected->Address;
        const struct sockaddr_in6 *pActualIpv6 =
            (const struct sockaddr_in6 *)pActual;

        return (0 == memcmp(&pExpectedIpv6->sin6_addr,
                            &pActualIpv6->sin6_addr,
                            sizeof(pExpectedIpv6->sin6_addr)));
    }
    else {
        return false;
    }
}

static IpsecError_t OpenNativeAppAlgorithmSocket(
    const NativeAppAlgorithmEndpoint_t *pLocal,
    uint32_t uiTimeoutMs,
    int32_t *piSocket)
{
    struct timeval Timeout;
    int32_t iSocket;

    if ((NULL == pLocal) || (NULL == piSocket)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        iSocket = socket(pLocal->Address.ss_family, SOCK_DGRAM, 0);
    }
    if (0 > iSocket) {
        return IPSEC_ERR_INTERNAL;
    }
    Timeout.tv_sec = (time_t)(uiTimeoutMs / 1000U);
    Timeout.tv_usec = (suseconds_t)((uiTimeoutMs % 1000U) * 1000U);
    if ((0 != setsockopt(iSocket, SOL_SOCKET, SO_RCVTIMEO, &Timeout,
                         sizeof(Timeout))) ||
        (0 != bind(iSocket, (const struct sockaddr *)&pLocal->Address,
                   pLocal->zLength))) {
        (void)close(iSocket);
        return IPSEC_ERR_INTERNAL;
    }
    else {
        *piSocket = iSocket;
        return IPSEC_OK;
    }
}

static IpsecError_t SendNativeAppAlgorithmMessage(
    int32_t iSocket,
    const NativeAppAlgorithmEndpoint_t *pRemote,
    const char *pcMessage)
{
    size_t zLength;
    ssize_t zSent;

    if ((0 > iSocket) || (NULL == pRemote) || (NULL == pcMessage)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        zLength = strlen(pcMessage);
    }
    zSent = sendto(iSocket, pcMessage, zLength, 0,
                   (const struct sockaddr *)&pRemote->Address,
                   pRemote->zLength);
    return ((0 <= zSent) && ((size_t)zSent == zLength)) ? IPSEC_OK :
        IPSEC_ERR_INTERNAL;
}

static IpsecError_t ReceiveNativeAppAlgorithmMessage(
    int32_t iSocket,
    const NativeAppAlgorithmEndpoint_t *pExpectedPeer,
    char *pcMessage,
    size_t zMessageLength,
    NativeAppAlgorithmEndpoint_t *pSender)
{
    struct sockaddr_storage Sender = {0};
    socklen_t zSenderLength = sizeof(Sender);
    ssize_t zReceived;

    if ((0 > iSocket) || (NULL == pExpectedPeer) || (NULL == pcMessage) ||
        (2U > zMessageLength)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    zReceived = recvfrom(iSocket, pcMessage, zMessageLength - 1U, 0,
                         (struct sockaddr *)&Sender, &zSenderLength);
    if (0 > zReceived) {
        return ((EAGAIN == errno) || (EWOULDBLOCK == errno) ||
                (EINTR == errno)) ? IPSEC_ERR_VICI_TIMEOUT :
                IPSEC_ERR_INTERNAL;
    }
    else if (!MatchNativeAppAlgorithmPeer(pExpectedPeer, &Sender)) {
        return IPSEC_ERR_PERMISSION;
    }
    else {
        pcMessage[zReceived] = '\0';
    }
    if (NULL != pSender) {
        pSender->Address = Sender;
        pSender->zLength = zSenderLength;
    }
    else {
        /* The caller does not require the sender port. */
    }
    return IPSEC_OK;
}

static bool SplitNativeAppAlgorithmMessage(
    char *pcMessage,
    char **ppcFields,
    uint32_t uiCapacity,
    uint32_t *puiCount)
{
    char *pcState = NULL;
    char *pcField;
    uint32_t uiCount = 0U;

    if ((NULL == pcMessage) || (NULL == ppcFields) ||
        (0U == uiCapacity) || (NULL == puiCount)) {
        return false;
    }
    pcField = strtok_r(pcMessage, "|", &pcState);
    while ((NULL != pcField) && (uiCount < uiCapacity)) {
        ppcFields[uiCount] = pcField;
        uiCount++;
        pcField = strtok_r(NULL, "|", &pcState);
    }
    if ((NULL != pcField) || (2U > uiCount) ||
        (0 != strcmp(NATIVE_APP_ALGORITHM_PROTOCOL, ppcFields[0]))) {
        return false;
    }
    else {
        *puiCount = uiCount;
        return true;
    }
}

static bool ParseNativeAppAlgorithmUint32(
    const char *pcText,
    uint32_t *puiValue)
{
    uint64_t ullValue = 0U;
    const unsigned char *pucCursor = (const unsigned char *)pcText;

    if ((NULL == pcText) || ('\0' == pcText[0]) || (NULL == puiValue)) {
        return false;
    }
    while ('\0' != *pucCursor) {
        if ((*pucCursor < (unsigned char)'0') ||
            (*pucCursor > (unsigned char)'9')) {
            return false;
        }
        ullValue = (ullValue * 10U) +
            (uint64_t)(*pucCursor - (unsigned char)'0');
        if (UINT32_MAX < ullValue) {
            return false;
        }
        pucCursor++;
    }
    *puiValue = (uint32_t)ullValue;
    return true;
}

static IpsecError_t FormatNativeAppAlgorithmMessage(
    char *pcMessage,
    size_t zMessageLength,
    const char *pcAction,
    const NativeAppAlgorithmCase_t *pCase,
    const char *pcValue1,
    const char *pcValue2)
{
    int32_t iLength;

    if ((NULL == pcMessage) || (NULL == pcAction) || (NULL == pCase) ||
        (NULL == pcValue1) || (NULL == pcValue2) ||
        (NULL != strpbrk(pcAction, "|\r\n")) ||
        (NULL != strpbrk(pCase->acId, "|\r\n")) ||
        (NULL != strpbrk(pcValue1, "|\r\n")) ||
        (NULL != strpbrk(pcValue2, "|\r\n"))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        iLength = snprintf(pcMessage, zMessageLength, "%s|%s|%s|%s|%s",
                           NATIVE_APP_ALGORITHM_PROTOCOL, pcAction,
                           pCase->acId, pcValue1, pcValue2);
    }
    return ((0 <= iLength) && ((size_t)iLength < zMessageLength)) ?
        IPSEC_OK : IPSEC_ERR_BUFFER_TOO_SMALL;
}

static IpsecError_t QueryNativeAppAlgorithmState(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const NativeAppAlgorithmCase_t *pCase,
    NativeAppAlgorithmCaseResult_t *pResult)
{
    IpsecIkeSaList_t IkeList = {0};
    IpsecChildSaList_t ChildList = {0};
    IpsecXfrmStateList_t StateList = {0};
    IpsecXfrmPolicyList_t PolicyList = {0};
    const IpsecIkeSaInfo_t *pIke = NULL;
    const IpsecChildSaInfo_t *pChild = NULL;
    uint32_t uiIndex;
    IpsecError_t eError;

    pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_XFRM;
    eError = GetIpsecIkeSas(pContext, &IkeList);
    if (IPSEC_OK == eError) {
        eError = GetIpsecChildSas(pContext, &ChildList);
    }
    if (IPSEC_OK == eError) {
        eError = GetIpsecXfrmStates(pContext, &StateList);
    }
    if (IPSEC_OK == eError) {
        eError = GetIpsecXfrmPolicies(pContext, &PolicyList);
    }
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < IkeList.uiCount; uiIndex++) {
            if ((0 == strcmp(pConfig->acConnectionName,
                             IkeList.pItems[uiIndex].acName)) &&
                IkeList.pItems[uiIndex].bEstablished) {
                pIke = &IkeList.pItems[uiIndex];
                break;
            }
        }
        for (uiIndex = 0U; uiIndex < ChildList.uiCount; uiIndex++) {
            if ((0 == strcmp(pConfig->acChildName,
                             ChildList.pItems[uiIndex].acName)) &&
                (0 == strcmp("INSTALLED",
                             ChildList.pItems[uiIndex].acState))) {
                pChild = &ChildList.pItems[uiIndex];
                break;
            }
        }
    }
    if ((IPSEC_OK == eError) && (NULL != pIke)) {
        eError = CopyNativeAppAlgorithmValue(
            pResult->acNegotiatedIke, sizeof(pResult->acNegotiatedIke),
            pIke->acProposal);
        if ((IPSEC_OK == eError) &&
            ('\0' != pResult->acNegotiatedIke[0])) {
            pResult->bIkeVerified = true;
        }
        else {
            /* The IKE object did not provide a usable proposal. */
        }
    }
    if ((IPSEC_OK == eError) && (NULL != pChild)) {
        pResult->uiReqid = pChild->uiReqid;
        eError = CopyNativeAppAlgorithmValue(
            pResult->acNegotiatedEsp, sizeof(pResult->acNegotiatedEsp),
            pChild->acProposal);
    }
    if ((IPSEC_OK == eError) && (NULL == pIke)) {
        pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_IKE;
        eError = IPSEC_ERR_IKE_FAILED;
    }
    else if ((IPSEC_OK == eError) &&
             ('\0' == pResult->acNegotiatedIke[0])) {
        pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_PROPOSAL;
        eError = IPSEC_ERR_VICI_PROTOCOL;
    }
    else if ((IPSEC_OK == eError) && (NULL == pChild)) {
        pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_CHILD;
        eError = IPSEC_ERR_CHILD_FAILED;
    }
    else if ((IPSEC_OK == eError) &&
             ('\0' == pResult->acNegotiatedEsp[0])) {
        pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_PROPOSAL;
        eError = IPSEC_ERR_VICI_PROTOCOL;
    }
    else {
        /* Continue with the negotiated and kernel state. */
    }
    if ((IPSEC_OK == eError) && pCase->bSeparateChildExchange &&
        (NULL == strstr(pResult->acNegotiatedEsp,
                        pCase->acExpectedChildKe))) {
        pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_PFS;
        eError = IPSEC_ERR_CHILD_FAILED;
    }
    else {
        /* PFS is either not requested or was observed in the CHILD SA. */
    }
    if ((IPSEC_OK == eError) &&
        ((pCase->bExpectEsn && !pChild->bEsn) ||
         (pCase->bExpectNoEsn && pChild->bEsn))) {
        pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_ESN;
        eError = IPSEC_ERR_CHILD_FAILED;
    }
    else {
        /* ESN matches the testcase intent. */
    }
    if ((IPSEC_OK == eError) &&
        ('\0' != pResult->acNegotiatedEsp[0])) {
        pResult->bEspVerified = true;
    }
    else {
        /* Preserve the ESP negotiation failure stage. */
    }
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < StateList.uiCount; uiIndex++) {
            if (pResult->uiReqid == StateList.pItems[uiIndex].uiReqid) {
                pResult->uiXfrmStateCount++;
            }
        }
        for (uiIndex = 0U; uiIndex < PolicyList.uiCount; uiIndex++) {
            if (pResult->uiReqid == PolicyList.pItems[uiIndex].uiReqid) {
                pResult->uiXfrmPolicyCount++;
            }
        }
        if ((0U == pResult->uiReqid) ||
            (0U == pResult->uiXfrmStateCount) ||
            (0U == pResult->uiXfrmPolicyCount)) {
            pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_XFRM;
            eError = IPSEC_ERR_INTERNAL;
        }
        else {
            pResult->bXfrmVerified = true;
        }
    }
    FreeIpsecXfrmPolicyList(&PolicyList);
    FreeIpsecXfrmStateList(&StateList);
    FreeIpsecChildSaList(&ChildList);
    FreeIpsecIkeSaList(&IkeList);
    return eError;
}

static void ReportNativeAppAlgorithmFinalState(
    IpsecContext_t *pContext,
    FILE *pLog)
{
    IpsecConnectionList_t ConnectionList = {0};
    IpsecIkeSaList_t IkeList = {0};
    IpsecChildSaList_t ChildList = {0};
    IpsecXfrmStateList_t StateList = {0};
    IpsecXfrmPolicyList_t PolicyList = {0};
    IpsecError_t eConnection;
    IpsecError_t eIke;
    IpsecError_t eChild;
    IpsecError_t eState;
    IpsecError_t ePolicy;

    eConnection = GetIpsecConnections(pContext, &ConnectionList);
    eIke = GetIpsecIkeSas(pContext, &IkeList);
    eChild = GetIpsecChildSas(pContext, &ChildList);
    eState = GetIpsecXfrmStates(pContext, &StateList);
    ePolicy = GetIpsecXfrmPolicies(pContext, &PolicyList);
    if ((IPSEC_OK == eConnection) && (IPSEC_OK == eIke) &&
        (IPSEC_OK == eChild) && (IPSEC_OK == eState) &&
        (IPSEC_OK == ePolicy)) {
        ReportNativeAppAlgorithm(
            pLog, stdout, "INFO",
            "final state: connections=%" PRIu32 " ike=%" PRIu32
            " child=%" PRIu32 " xfrm_states=%" PRIu32
            " xfrm_policies=%" PRIu32,
            ConnectionList.uiCount, IkeList.uiCount, ChildList.uiCount,
            StateList.uiCount, PolicyList.uiCount);
    }
    else {
        ReportNativeAppAlgorithm(
            pLog, stderr, "WARN",
            "final state query: connections=%s ike=%s child=%s"
            " xfrm_states=%s xfrm_policies=%s",
            GetIpsecErrorString(eConnection), GetIpsecErrorString(eIke),
            GetIpsecErrorString(eChild), GetIpsecErrorString(eState),
            GetIpsecErrorString(ePolicy));
    }
    FreeIpsecXfrmPolicyList(&PolicyList);
    FreeIpsecXfrmStateList(&StateList);
    FreeIpsecChildSaList(&ChildList);
    FreeIpsecIkeSaList(&IkeList);
    FreeIpsecConnectionList(&ConnectionList);
}

static void RecordNativeAppAlgorithmCleanupError(
    IpsecError_t *peTarget,
    IpsecError_t eError)
{
    if ((NULL != peTarget) && (IPSEC_OK == *peTarget) &&
        (IPSEC_OK != eError)) {
        *peTarget = eError;
    }
    else {
        /* Preserve the first error observed for this cleanup stage. */
    }
}

static bool IsNativeAppAlgorithmCleanupAbsent(IpsecError_t eError)
{
    return (IPSEC_ERR_CONNECTION_NOT_FOUND == eError) ||
           (IPSEC_ERR_IKE_FAILED == eError);
}

static uint32_t GetNativeAppAlgorithmCleanupWaitMs(
    const NativeAppConfig_t *pConfig)
{
    uint32_t uiWaitMs = pConfig->uiTimeoutMs;

    if ((0U == uiWaitMs) ||
        (NATIVE_APP_ALGORITHM_CLEANUP_WAIT_MS < uiWaitMs)) {
        uiWaitMs = NATIVE_APP_ALGORITHM_CLEANUP_WAIT_MS;
    }
    return uiWaitMs;
}

static IpsecError_t CheckNativeAppAlgorithmConnectionRemoved(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    bool *pbRemoved)
{
    IpsecConnectionList_t ConnectionList = {0};
    IpsecError_t eError;
    uint32_t uiIndex;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pbRemoved)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    *pbRemoved = true;
    eError = GetIpsecConnections(pContext, &ConnectionList);
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < ConnectionList.uiCount; uiIndex++) {
            if (0 == strcmp(pConfig->acConnectionName,
                            ConnectionList.pItems[uiIndex].acName)) {
                *pbRemoved = false;
                break;
            }
            else {
                /* Check the next loaded connection. */
            }
        }
    }
    FreeIpsecConnectionList(&ConnectionList);
    return eError;
}

static IpsecError_t CleanupNativeAppAlgorithmCase(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    uint32_t uiReqid,
    bool bTerminate,
    NativeAppAlgorithmCleanup_t *pCleanup)
{
    IpsecControlOptions_t Control = {
        .uiStructSize = sizeof(IpsecControlOptions_t),
        .eMode = IPSEC_CONTROL_IMMEDIATE,
        .uiTimeoutMs = 0U
    };
    uint32_t uiWaitMs;
    uint32_t uiAttempt;
    IpsecError_t eError;
    IpsecError_t eFinalError = IPSEC_OK;
    bool bSaRemoved = false;
    bool bConnectionRemoved = false;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pCleanup)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    (void)memset(pCleanup, 0, sizeof(*pCleanup));
    uiWaitMs = GetNativeAppAlgorithmCleanupWaitMs(pConfig);
    for (uiAttempt = 0U;
         (uiAttempt < NATIVE_APP_ALGORITHM_CLEANUP_ATTEMPTS) && !bSaRemoved;
         uiAttempt++) {
        if (bTerminate) {
            pCleanup->uiTerminateAttempts++;
            eError = TerminateIpsecIke(pContext,
                                       pConfig->acConnectionName,
                                       &Control);
            if (IsNativeAppAlgorithmCleanupAbsent(eError)) {
                eError = IPSEC_OK;
            }
            else {
                RecordNativeAppAlgorithmCleanupError(
                    &pCleanup->eTerminateError, eError);
            }
        }
        pCleanup->uiWaitRemovedAttempts++;
        eError = WaitNativeAppRemovedWithTimeout(
            pContext, pConfig, uiReqid, uiWaitMs);
        if (IPSEC_OK == eError) {
            bSaRemoved = true;
        }
        else {
            RecordNativeAppAlgorithmCleanupError(
                &pCleanup->eWaitRemovedError, eError);
            if ((uiAttempt + 1U) <
                NATIVE_APP_ALGORITHM_CLEANUP_ATTEMPTS) {
                SleepNativeAppAlgorithm(
                    NATIVE_APP_ALGORITHM_CLEANUP_RETRY_MS);
            }
            else {
                /* The final verification below records the terminal state. */
            }
        }
    }
    for (uiAttempt = 0U;
         (uiAttempt < NATIVE_APP_ALGORITHM_CLEANUP_ATTEMPTS) &&
         !bConnectionRemoved;
         uiAttempt++) {
        pCleanup->uiRemoveConnectionAttempts++;
        eError = RemoveIpsecConnection(pContext, pConfig->acConnectionName);
        if ((IPSEC_OK == eError) ||
            (IPSEC_ERR_CONNECTION_NOT_FOUND == eError)) {
            bConnectionRemoved = true;
        }
        else {
            RecordNativeAppAlgorithmCleanupError(
                &pCleanup->eRemoveConnectionError, eError);
            eError = CheckNativeAppAlgorithmConnectionRemoved(
                pContext, pConfig, &bConnectionRemoved);
            if (!bConnectionRemoved &&
                ((uiAttempt + 1U) <
                 NATIVE_APP_ALGORITHM_CLEANUP_ATTEMPTS)) {
                SleepNativeAppAlgorithm(
                    NATIVE_APP_ALGORITHM_CLEANUP_RETRY_MS);
            }
            else {
                /* Removal completed or the retry budget is exhausted. */
            }
        }
    }
    eError = WaitNativeAppRemovedWithTimeout(pContext, pConfig, uiReqid, 0U);
    if (IPSEC_OK != eError) {
        RecordNativeAppAlgorithmCleanupError(
            &pCleanup->eFinalVerifyError, eError);
        eFinalError = eError;
    }
    eError = CheckNativeAppAlgorithmConnectionRemoved(
        pContext, pConfig, &bConnectionRemoved);
    if (IPSEC_OK != eError) {
        RecordNativeAppAlgorithmCleanupError(
            &pCleanup->eFinalVerifyError, eError);
        if (IPSEC_OK == eFinalError) {
            eFinalError = eError;
        }
    }
    else if (!bConnectionRemoved) {
        RecordNativeAppAlgorithmCleanupError(
            &pCleanup->eFinalVerifyError, IPSEC_ERR_VICI_TIMEOUT);
        if (IPSEC_OK == eFinalError) {
            eFinalError = IPSEC_ERR_VICI_TIMEOUT;
        }
    }
    else {
        /* The connection is absent. */
    }
    if (IPSEC_OK == eFinalError) {
        pCleanup->bLocalVerified = true;
        pCleanup->bRecovered =
            (IPSEC_OK != pCleanup->eTerminateError) ||
            (IPSEC_OK != pCleanup->eWaitRemovedError) ||
            (IPSEC_OK != pCleanup->eRemoveConnectionError) ||
            (1U < pCleanup->uiTerminateAttempts) ||
            (1U < pCleanup->uiWaitRemovedAttempts) ||
            (1U < pCleanup->uiRemoveConnectionAttempts);
    }
    else {
        /* Preserve the failed terminal verification result. */
    }
    return eFinalError;
}

static void WriteNativeAppJsonString(FILE *pFile, const char *pcText)
{
    const unsigned char *pucText = (const unsigned char *)pcText;

    (void)fputc('"', pFile);
    while ('\0' != *pucText) {
        if (('"' == *pucText) || ('\\' == *pucText)) {
            (void)fputc('\\', pFile);
            (void)fputc((int)*pucText, pFile);
        }
        else if ('\n' == *pucText) {
            (void)fputs("\\n", pFile);
        }
        else if ('\r' == *pucText) {
            (void)fputs("\\r", pFile);
        }
        else if ('\t' == *pucText) {
            (void)fputs("\\t", pFile);
        }
        else if (0x20U > *pucText) {
            (void)fprintf(pFile, "\\u%04x", (unsigned int)*pucText);
        }
        else {
            (void)fputc((int)*pucText, pFile);
        }
        pucText++;
    }
    (void)fputc('"', pFile);
}

static IpsecError_t OpenNativeAppAlgorithmJson(
    const NativeAppAlgorithmOptions_t *pOptions,
    const char *pcRunId,
    uint32_t uiRequested,
    NativeAppAlgorithmJsonWriter_t *pWriter)
{
    const char *pcPath = (NULL != pOptions->pcResultsPath) ?
        pOptions->pcResultsPath : "results.json";

    (void)memset(pWriter, 0, sizeof(*pWriter));
    pWriter->pFile = fopen(pcPath, "w+b");
    if (NULL == pWriter->pFile) {
        return IPSEC_ERR_FILE_OPEN;
    }
    (void)fputs("{\n  \"schema_version\": 4,\n  \"run_id\": ",
                pWriter->pFile);
    WriteNativeAppJsonString(pWriter->pFile, pcRunId);
    (void)fputs(",\n  \"mode\": ", pWriter->pFile);
    WriteNativeAppJsonString(pWriter->pFile,
                             GetNativeAppAlgorithmModeName(pOptions->eMode));
    (void)fprintf(pWriter->pFile,
                  ",\n  \"start\": %" PRIu32
                  ",\n  \"requested\": %" PRIu32
                  ",\n  \"cases\": [\n",
                  pOptions->uiStart, uiRequested);
    pWriter->lTailOffset = ftell(pWriter->pFile);
    (void)fputs("\n  ]\n}\n", pWriter->pFile);
    if ((0 > pWriter->lTailOffset) || (0 != fflush(pWriter->pFile))) {
        (void)fclose(pWriter->pFile);
        (void)memset(pWriter, 0, sizeof(*pWriter));
        return IPSEC_ERR_FILE_READ;
    }
    return IPSEC_OK;
}

static IpsecError_t AppendNativeAppAlgorithmJson(
    NativeAppAlgorithmJsonWriter_t *pWriter,
    const NativeAppAlgorithmCaseResult_t *pResult)
{
    FILE *pFile = pWriter->pFile;

    if ((NULL == pFile) || (0 != fseek(pFile, pWriter->lTailOffset,
                                      SEEK_SET))) {
        return IPSEC_ERR_FILE_READ;
    }
    if (0U < pWriter->uiCaseCount) {
        (void)fputs(",\n", pFile);
    }
    (void)fputs("    {\"case_id\": ", pFile);
    WriteNativeAppJsonString(pFile, pResult->Case.acId);
    (void)fputs(", \"ike_proposal\": ", pFile);
    WriteNativeAppJsonString(pFile, pResult->Case.acIkeProposal);
    (void)fputs(", \"esp_proposal\": ", pFile);
    WriteNativeAppJsonString(pFile, pResult->Case.acEspProposal);
    (void)fputs(", \"negotiated_ike\": ", pFile);
    WriteNativeAppJsonString(pFile, pResult->acNegotiatedIke);
    (void)fputs(", \"negotiated_esp\": ", pFile);
    WriteNativeAppJsonString(pFile, pResult->acNegotiatedEsp);
    (void)fprintf(pFile,
                  ", \"reqid\": %" PRIu32
                  ", \"xfrm_states\": %" PRIu32
                  ", \"xfrm_policies\": %" PRIu32
                  ", \"duration_ms\": %" PRIu64
                  ", \"result\": ",
                  pResult->uiReqid, pResult->uiXfrmStateCount,
                  pResult->uiXfrmPolicyCount, pResult->ullDurationMs);
    WriteNativeAppJsonString(pFile,
                             GetNativeAppAlgorithmResultName(pResult->eResult));
    (void)fputs(", \"error\": ", pFile);
    WriteNativeAppJsonString(
        pFile, GetNativeAppAlgorithmErrorText(pResult->eError));
    (void)fputs(", \"cleanup_error\": ", pFile);
    WriteNativeAppJsonString(
        pFile, GetNativeAppAlgorithmErrorText(pResult->eCleanupError));
    (void)fputs(", \"cleanup\": {\"terminate_error\": ", pFile);
    WriteNativeAppJsonString(
        pFile, GetNativeAppAlgorithmErrorText(
            pResult->Cleanup.eTerminateError));
    (void)fputs(", \"wait_removed_error\": ", pFile);
    WriteNativeAppJsonString(
        pFile, GetNativeAppAlgorithmErrorText(
            pResult->Cleanup.eWaitRemovedError));
    (void)fputs(", \"remove_connection_error\": ", pFile);
    WriteNativeAppJsonString(
        pFile, GetNativeAppAlgorithmErrorText(
            pResult->Cleanup.eRemoveConnectionError));
    (void)fputs(", \"final_verify_error\": ", pFile);
    WriteNativeAppJsonString(
        pFile, GetNativeAppAlgorithmErrorText(
            pResult->Cleanup.eFinalVerifyError));
    (void)fputs(", \"peer_error\": ", pFile);
    WriteNativeAppJsonString(
        pFile, GetNativeAppAlgorithmErrorText(
            pResult->Cleanup.ePeerError));
    (void)fprintf(
        pFile,
        ", \"terminate_attempts\": %" PRIu32
        ", \"wait_removed_attempts\": %" PRIu32
        ", \"remove_connection_attempts\": %" PRIu32
        ", \"peer_attempts\": %" PRIu32
        ", \"recovered\": %s, \"local_verified\": %s}",
        pResult->Cleanup.uiTerminateAttempts,
        pResult->Cleanup.uiWaitRemovedAttempts,
        pResult->Cleanup.uiRemoveConnectionAttempts,
        pResult->Cleanup.uiPeerAttempts,
        pResult->Cleanup.bRecovered ? "true" : "false",
        pResult->Cleanup.bLocalVerified ? "true" : "false");
    (void)fprintf(pFile,
        ", \"ike_result\": \"%s\", \"esp_result\": \"%s\", "
        "\"xfrm_result\": \"%s\", \"data_path_result\": \"%s\"",
        pResult->bIkeVerified ? "PASS" : "FAIL",
        pResult->bEspVerified ? "PASS" : "FAIL",
        pResult->bXfrmVerified ? "PASS" : "FAIL",
        pResult->bDataPathVerified ? "PASS" : "FAIL");
    (void)fputs(", \"peer_result\": ", pFile);
    WriteNativeAppJsonString(pFile, pResult->acPeerResult);
    (void)fputc('}', pFile);
    pWriter->lTailOffset = ftell(pFile);
    (void)fputs("\n  ]\n}\n", pFile);
    if ((0 > pWriter->lTailOffset) || (0 != fflush(pFile))) {
        return IPSEC_ERR_FILE_READ;
    }
    pWriter->uiCaseCount++;
    if (NATIVE_APP_ALGORITHM_RESULT_PASS == pResult->eResult) {
        pWriter->uiPassed++;
    }
    else {
        pWriter->uiFailed++;
    }
    return IPSEC_OK;
}

static void CloseNativeAppAlgorithmJson(
    NativeAppAlgorithmJsonWriter_t *pWriter)
{
    if (NULL != pWriter->pFile) {
        if (0 == fseek(pWriter->pFile, pWriter->lTailOffset, SEEK_SET)) {
            (void)fprintf(pWriter->pFile,
                          "\n  ],\n  \"summary\": {\"completed\": %" PRIu32
                          ", \"passed\": %" PRIu32
                          ", \"failed\": %" PRIu32 "}\n}\n",
                          pWriter->uiCaseCount, pWriter->uiPassed,
                          pWriter->uiFailed);
            (void)fflush(pWriter->pFile);
        }
        (void)fclose(pWriter->pFile);
        pWriter->pFile = NULL;
    }
}

static IpsecError_t WaitNativeAppAlgorithmResponse(
    int32_t iSocket,
    const NativeAppAlgorithmEndpoint_t *pRemote,
    const char *pcExpectedAction,
    const char *pcExpectedId,
    uint32_t uiTimeoutMs,
    char *pcResponse,
    size_t zResponseLength)
{
    uint64_t ullElapsedMs = 0U;

    while ((ullElapsedMs <= (uint64_t)uiTimeoutMs) &&
           !IsNativeAppStopRequested()) {
        char acMessage[NATIVE_APP_ALGORITHM_MESSAGE_LENGTH];
        char *pacFields[8];
        uint32_t uiFieldCount = 0U;
        IpsecError_t eError = ReceiveNativeAppAlgorithmMessage(
            iSocket, pRemote, acMessage, sizeof(acMessage), NULL);

        if (IPSEC_ERR_VICI_TIMEOUT == eError) {
            ullElapsedMs += NATIVE_APP_ALGORITHM_POLL_MS;
            continue;
        }
        else if (IPSEC_OK != eError) {
            if (IPSEC_ERR_PERMISSION == eError) {
                continue;
            }
            return eError;
        }
        if (SplitNativeAppAlgorithmMessage(acMessage, pacFields,
                                           NATIVE_APP_ARRAY_COUNT(pacFields),
                                           &uiFieldCount) &&
            (3U <= uiFieldCount) &&
            (0 == strcmp(pcExpectedAction, pacFields[1])) &&
            (0 == strcmp(pcExpectedId, pacFields[2]))) {
            if (NULL != pcResponse) {
                return CopyNativeAppAlgorithmValue(pcResponse,
                                                   zResponseLength,
                                                   (4U <= uiFieldCount) ?
                                                   pacFields[3] : "");
            }
            else {
                return IPSEC_OK;
            }
        }
    }
    return IPSEC_ERR_VICI_TIMEOUT;
}

static IpsecError_t PrepareNativeAppAlgorithmPeer(
    int32_t iSocket,
    const NativeAppAlgorithmEndpoint_t *pRemote,
    const NativeAppAlgorithmCase_t *pCase,
    const char *pcRunId,
    uint32_t uiRequested,
    uint32_t uiTimeoutMs)
{
    char acMessage[NATIVE_APP_ALGORITHM_MESSAGE_LENGTH];
    uint64_t ullElapsedMs = 0U;
    int32_t iLength;
    IpsecError_t eError;

    if ((NULL == pcRunId) || (NULL != strpbrk(pcRunId, "|\r\n"))) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        iLength = snprintf(
            acMessage, sizeof(acMessage),
            "%s|PREPARE|%s|%s|%s|%s|%" PRIu32 "|%" PRIu32,
            NATIVE_APP_ALGORITHM_PROTOCOL, pCase->acId,
            pCase->acIkeProposal, pCase->acEspProposal, pcRunId,
            pCase->uiNumber, uiRequested);
        eError = ((0 <= iLength) &&
                  ((size_t)iLength < sizeof(acMessage))) ?
            IPSEC_OK : IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    while ((IPSEC_OK == eError) &&
           (ullElapsedMs <= (uint64_t)uiTimeoutMs) &&
           !IsNativeAppStopRequested()) {
        eError = SendNativeAppAlgorithmMessage(iSocket, pRemote, acMessage);
        if (IPSEC_OK == eError) {
            eError = WaitNativeAppAlgorithmResponse(
                iSocket, pRemote, "READY", pCase->acId,
                NATIVE_APP_ALGORITHM_POLL_MS, NULL, 0U);
        }
        if (IPSEC_ERR_VICI_TIMEOUT == eError) {
            eError = IPSEC_OK;
            ullElapsedMs += NATIVE_APP_ALGORITHM_POLL_MS;
        }
        else {
            break;
        }
    }
    return ((IPSEC_OK == eError) &&
            (ullElapsedMs <= (uint64_t)uiTimeoutMs)) ?
        IPSEC_OK : ((IPSEC_OK == eError) ? IPSEC_ERR_VICI_TIMEOUT : eError);
}

static IpsecError_t VerifyNativeAppAlgorithmPeer(
    int32_t iSocket,
    const NativeAppAlgorithmEndpoint_t *pRemote,
    const NativeAppAlgorithmCase_t *pCase,
    uint32_t uiTimeoutMs,
    char *pcPeerResult,
    size_t zPeerResultLength)
{
    char acMessage[NATIVE_APP_ALGORITHM_MESSAGE_LENGTH];
    IpsecError_t eError;

    eError = FormatNativeAppAlgorithmMessage(acMessage, sizeof(acMessage),
                                             "VERIFY", pCase, "DATA", "1");
    if (IPSEC_OK == eError) {
        eError = SendNativeAppAlgorithmMessage(iSocket, pRemote, acMessage);
    }
    if (IPSEC_OK == eError) {
        eError = WaitNativeAppAlgorithmResponse(
            iSocket, pRemote, "RESULT", pCase->acId, uiTimeoutMs,
            pcPeerResult, zPeerResultLength);
    }
    return eError;
}

static IpsecError_t FinishNativeAppAlgorithmPeer(
    int32_t iSocket,
    const NativeAppAlgorithmEndpoint_t *pRemote,
    const NativeAppAlgorithmCase_t *pCase,
    const char *pcAction,
    uint32_t uiTimeoutMs,
    NativeAppAlgorithmCleanup_t *pCleanup)
{
    char acMessage[NATIVE_APP_ALGORITHM_MESSAGE_LENGTH];
    uint32_t uiAttemptTimeoutMs;
    uint32_t uiAttempt;
    IpsecError_t eError = IPSEC_OK;

    if (NULL == pCleanup) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    eError = FormatNativeAppAlgorithmMessage(acMessage, sizeof(acMessage),
                                             pcAction, pCase, "NONE", "0");
    if (IPSEC_OK != eError) {
        pCleanup->ePeerError = eError;
        return eError;
    }
    uiAttemptTimeoutMs = uiTimeoutMs /
        NATIVE_APP_ALGORITHM_CLEANUP_ATTEMPTS;
    if (NATIVE_APP_ALGORITHM_POLL_MS > uiAttemptTimeoutMs) {
        uiAttemptTimeoutMs = NATIVE_APP_ALGORITHM_POLL_MS;
    }
    for (uiAttempt = 0U;
         uiAttempt < NATIVE_APP_ALGORITHM_CLEANUP_ATTEMPTS;
         uiAttempt++) {
        pCleanup->uiPeerAttempts++;
        eError = SendNativeAppAlgorithmMessage(iSocket, pRemote, acMessage);
        if (IPSEC_OK == eError) {
            eError = WaitNativeAppAlgorithmResponse(
                iSocket, pRemote, "DONE", pCase->acId,
                uiAttemptTimeoutMs, NULL, 0U);
        }
        if (IPSEC_OK == eError) {
            if (1U < pCleanup->uiPeerAttempts) {
                pCleanup->bRecovered = true;
            }
            break;
        }
        RecordNativeAppAlgorithmCleanupError(&pCleanup->ePeerError, eError);
        if ((uiAttempt + 1U) < NATIVE_APP_ALGORITHM_CLEANUP_ATTEMPTS) {
            SleepNativeAppAlgorithm(NATIVE_APP_ALGORITHM_CLEANUP_RETRY_MS);
        }
        else {
            /* The peer cleanup retry budget is exhausted. */
        }
    }
    return eError;
}

static IpsecError_t FinishNativeAppAlgorithmRun(
    int32_t iSocket,
    const NativeAppAlgorithmEndpoint_t *pRemote,
    const char *pcRunId,
    uint32_t uiTimeoutMs)
{
    NativeAppAlgorithmCase_t Case = {0};
    char acMessage[NATIVE_APP_ALGORITHM_MESSAGE_LENGTH];
    IpsecError_t eError;

    eError = CopyNativeAppAlgorithmValue(Case.acId, sizeof(Case.acId),
                                         pcRunId);
    if (IPSEC_OK == eError) {
        eError = FormatNativeAppAlgorithmMessage(
            acMessage, sizeof(acMessage), "FINISH", &Case, "DONE", "0");
    }
    if (IPSEC_OK == eError) {
        eError = SendNativeAppAlgorithmMessage(iSocket, pRemote, acMessage);
    }
    if (IPSEC_OK == eError) {
        eError = WaitNativeAppAlgorithmResponse(
            iSocket, pRemote, "FINISHED", Case.acId, uiTimeoutMs, NULL, 0U);
    }
    return eError;
}

static IpsecError_t RunNativeAppAlgorithmCaseClient(
    IpsecContext_t *pContext,
    int32_t iSocket,
    const NativeAppAlgorithmEndpoint_t *pRemote,
    const NativeAppConfig_t *pBaseConfig,
    const char *pcRunId,
    uint32_t uiRequested,
    const NativeAppAlgorithmCase_t *pCase,
    const char *pcCaseDirectory,
    NativeAppAlgorithmCaseResult_t *pResult)
{
    NativeAppRuntimeConfig_t Runtime = {0};
    NativeAppConfig_t Config = *pBaseConfig;
    bool bConnectionLoaded = false;
    bool bStartAttempted = false;
    IpsecError_t eCleanup;
    IpsecError_t eError;

    pResult->Case = *pCase;
    pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_CONFIG;
    eError = PrepareNativeAppAlgorithmPeer(
        iSocket, pRemote, pCase, pcRunId, uiRequested,
        pBaseConfig->uiTimeoutMs);
    if (IPSEC_OK != eError) {
        pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_SYNC;
    }
    if (IPSEC_OK == eError) {
        eError = BuildNativeAppAlgorithmConfig(pBaseConfig, pCase, &Config,
                                               &Runtime);
    }
    if (IPSEC_OK == eError) {
        eError = AddIpsecConnection(pContext, &Runtime.Connection);
        bConnectionLoaded = (IPSEC_OK == eError);
    }
    if (IPSEC_OK == eError) {
        bStartAttempted = true;
        eError = StartNativeAppConnection(pContext, &Config, &Runtime);
        if (IPSEC_OK != eError) {
            pResult->eResult = pCase->bSeparateChildExchange ?
                NATIVE_APP_ALGORITHM_RESULT_FAIL_CHILD :
                NATIVE_APP_ALGORITHM_RESULT_FAIL_IKE;
        }
    }
    if (bStartAttempted) {
        IpsecError_t eState = QueryNativeAppAlgorithmState(
            pContext, &Config, pCase, pResult);

        if (IPSEC_OK == eError) {
            eError = eState;
        }
        else {
            /* Keep the control failure while retaining observed SA stages. */
        }
    }
    if (bStartAttempted) {
        IpsecError_t eReport = CaptureNativeAppAlgorithmCaseReport(
            pContext, &Config, pResult, pcCaseDirectory);

        if ((IPSEC_OK != eReport) && (IPSEC_OK == eError)) {
            eError = eReport;
            pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_XFRM;
        }
    }
    if (IPSEC_OK == eError) {
        eError = VerifyNativeAppAlgorithmPeer(
            iSocket, pRemote, pCase, pBaseConfig->uiTimeoutMs,
            pResult->acPeerResult, sizeof(pResult->acPeerResult));
        if (IPSEC_OK != eError) {
            pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH;
        }
        else if (0 != strcmp("PASS", pResult->acPeerResult)) {
            pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_DATA_PATH;
            eError = IPSEC_ERR_INTERNAL;
        }
        else {
            pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_PASS;
            pResult->bDataPathVerified = true;
        }
    }
    if (bStartAttempted) {
        (void)CaptureNativeAppAlgorithmCaseReport(
            pContext, &Config, pResult, pcCaseDirectory);
    }
    pResult->eError = eError;
    if (bConnectionLoaded) {
        eCleanup = CleanupNativeAppAlgorithmCase(pContext, &Config,
                                                 pResult->uiReqid,
                                                 bStartAttempted,
                                                 &pResult->Cleanup);
        pResult->eCleanupError = eCleanup;
        if ((IPSEC_OK != eCleanup) && (IPSEC_OK == pResult->eError)) {
            pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_CLEANUP;
            pResult->eError = eCleanup;
        }
    }
    else {
        pResult->Cleanup.bLocalVerified = true;
    }
    eCleanup = FinishNativeAppAlgorithmPeer(
        iSocket, pRemote, pCase,
        bConnectionLoaded ? "CLEANUP" : "ABORT",
        pBaseConfig->uiTimeoutMs, &pResult->Cleanup);
    if ((IPSEC_OK != eCleanup) &&
        (IPSEC_OK == pResult->eCleanupError)) {
        pResult->eCleanupError = eCleanup;
    }
    if ((IPSEC_OK != eCleanup) && (IPSEC_OK == pResult->eError)) {
        pResult->eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_CLEANUP;
        pResult->eError = eCleanup;
        pResult->eCleanupError = eCleanup;
    }
    return pResult->eError;
}

IpsecError_t RunNativeAppAlgorithmClient(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    const NativeAppAlgorithmOptions_t *pOptions)
{
    NativeAppAlgorithmEndpoint_t Local;
    NativeAppAlgorithmEndpoint_t Remote;
    NativeAppAlgorithmJsonWriter_t Writer;
    NativeAppAlgorithmOptions_t EffectiveOptions;
    char acRunId[NATIVE_APP_ALGORITHM_RUN_ID_LENGTH];
    char acResultDirectory[NATIVE_APP_PATH_LENGTH];
    char acResultPath[NATIVE_APP_PATH_LENGTH];
    const char *pcResultName;
    FILE *pLog = NULL;
    uint32_t uiTotal;
    uint32_t uiAvailable;
    uint32_t uiRequested;
    uint32_t uiOffset;
    int32_t iSocket = -1;
    IpsecError_t eFirstError = IPSEC_OK;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pConfig) || (NULL == pOptions) ||
        (NATIVE_APP_ROLE_INITIATOR != pConfig->eRole)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    uiTotal = GetNativeAppAlgorithmCaseCount(pOptions->eMode);
    if ((0U == uiTotal) || (0U == pOptions->uiStart) ||
        (uiTotal < pOptions->uiStart)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    uiAvailable = uiTotal - pOptions->uiStart + 1U;
    uiRequested = (0U == pOptions->uiLimit) ? uiAvailable :
        ((pOptions->uiLimit < uiAvailable) ? pOptions->uiLimit : uiAvailable);
    EffectiveOptions = *pOptions;
    eError = CreateNativeAppAlgorithmRunId(pOptions->eMode, acRunId,
                                            sizeof(acRunId));
    if (IPSEC_OK == eError) {
        eError = OpenNativeAppAlgorithmRunLog(
            pConfig, acRunId, "initiator", acResultDirectory,
            sizeof(acResultDirectory), &pLog);
    }
    if (IPSEC_OK == eError) {
        pcResultName = (NULL != pOptions->pcResultsPath) ?
            strrchr(pOptions->pcResultsPath, '/') : NULL;
        pcResultName = (NULL != pcResultName) ? pcResultName + 1U :
            pOptions->pcResultsPath;
        if ((NULL == pcResultName) || ('\0' == pcResultName[0])) {
            pcResultName = "results.json";
        }
        eError = JoinNativeAppAlgorithmPath(
            acResultPath, sizeof(acResultPath), acResultDirectory,
            pcResultName);
        EffectiveOptions.pcResultsPath = acResultPath;
    }
    if (IPSEC_OK == eError) {
        eError = InitializeNativeAppAlgorithmEndpoint(
        pConfig->acLocalAddress, 0U == pOptions->uiPort ?
        NATIVE_APP_ALGORITHM_DEFAULT_PORT : pOptions->uiPort, &Local);
    }
    if (IPSEC_OK == eError) {
        if (AF_INET == Local.Address.ss_family) {
            ((struct sockaddr_in *)&Local.Address)->sin_port = 0U;
        }
        else {
            ((struct sockaddr_in6 *)&Local.Address)->sin6_port = 0U;
        }
        eError = InitializeNativeAppAlgorithmEndpoint(
            pConfig->acRemoteAddress, 0U == pOptions->uiPort ?
            NATIVE_APP_ALGORITHM_DEFAULT_PORT : pOptions->uiPort, &Remote);
    }
    if (IPSEC_OK == eError) {
        eError = OpenNativeAppAlgorithmSocket(
            &Local, NATIVE_APP_ALGORITHM_POLL_MS, &iSocket);
    }
    if (IPSEC_OK == eError) {
        eError = LoadNativeAppCredential(pContext, pConfig);
    }
    if (IPSEC_OK == eError) {
        eError = WriteNativeAppAlgorithmRunReport(
            pContext, pConfig, pOptions->eMode, "initiator",
            acResultDirectory, uiRequested, false);
    }
    if (IPSEC_OK == eError) {
        eError = OpenNativeAppAlgorithmJson(&EffectiveOptions, acRunId,
                                            uiRequested, &Writer);
    }
    if (IPSEC_OK != eError) {
        if (0 <= iSocket) {
            (void)close(iSocket);
        }
        if (NULL != pLog) {
            (void)fclose(pLog);
        }
        return eError;
    }

    ReportNativeAppAlgorithm(
        pLog, stdout, "INFO",
        "algorithm test: run=%s mode=%s start=%" PRIu32
        " cases=%" PRIu32 " results=%s",
        acRunId, GetNativeAppAlgorithmModeName(pOptions->eMode),
        pOptions->uiStart, uiRequested, acResultPath);
    for (uiOffset = 0U;
         (uiOffset < uiRequested) && !IsNativeAppStopRequested();
         uiOffset++) {
        NativeAppAlgorithmCaseResult_t Result = {0};
        char acCaseDirectory[NATIVE_APP_PATH_LENGTH] = {0};
        uint32_t uiIndex = (pOptions->uiStart - 1U) + uiOffset;
        uint64_t ullStartMs = GetNativeAppAlgorithmTimeMs();

        eError = GetNativeAppAlgorithmCase(
            pOptions->eMode, uiIndex, pConfig, pOptions->pcCustomIke,
            pOptions->pcCustomEsp, &Result.Case);
        if (IPSEC_OK == eError) {
            eError = CreateNativeAppAlgorithmCaseReport(
                pConfig, &Result.Case, "initiator", acResultDirectory,
                uiOffset + 1U, uiRequested, acCaseDirectory,
                sizeof(acCaseDirectory));
        }
        if (IPSEC_OK == eError) {
            ReportNativeAppAlgorithm(
                pLog, stdout, "INFO", "[%" PRIu32 "/%" PRIu32 "] %s",
                uiOffset + 1U, uiRequested, Result.Case.acId);
            eError = RunNativeAppAlgorithmCaseClient(
                pContext, iSocket, &Remote, pConfig, acRunId, uiRequested,
                &Result.Case, acCaseDirectory, &Result);
        }
        else {
            Result.eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_CONFIG;
            Result.eError = eError;
        }
        Result.ullDurationMs = GetNativeAppAlgorithmTimeMs() - ullStartMs;
        if ('\0' != acCaseDirectory[0]) {
            (void)FinishNativeAppAlgorithmCaseReport(
                pContext, pConfig, &Result, "initiator",
                acResultDirectory, acCaseDirectory, uiOffset + 1U,
                uiRequested);
        }
        ReportNativeAppAlgorithm(
            pLog, stdout,
            (Result.bIkeVerified && Result.bEspVerified &&
             Result.bXfrmVerified && Result.bDataPathVerified) ?
            "PASS" : "FAIL",
            "phases case=%s IKE=%s ESP=%s XFRM=%s DATA_PATH=%s",
            Result.Case.acId, Result.bIkeVerified ? "PASS" : "FAIL",
            Result.bEspVerified ? "PASS" : "FAIL",
            Result.bXfrmVerified ? "PASS" : "FAIL",
            Result.bDataPathVerified ? "PASS" : "FAIL");
        ReportNativeAppAlgorithm(
            pLog, stdout,
            (NATIVE_APP_ALGORITHM_RESULT_PASS == Result.eResult) ?
            "PASS" : "FAIL",
            "result=%s case=%s duration=%" PRIu64
            " ms error=%s cleanup=%s recovered=%s"
            " attempts=%" PRIu32 "/%" PRIu32 "/%" PRIu32 "/%" PRIu32,
            GetNativeAppAlgorithmResultName(Result.eResult), Result.Case.acId,
            Result.ullDurationMs,
            GetNativeAppAlgorithmErrorText(Result.eError),
            GetNativeAppAlgorithmErrorText(Result.eCleanupError),
            Result.Cleanup.bRecovered ? "yes" : "no",
            Result.Cleanup.uiTerminateAttempts,
            Result.Cleanup.uiWaitRemovedAttempts,
            Result.Cleanup.uiRemoveConnectionAttempts,
            Result.Cleanup.uiPeerAttempts);
        if (IPSEC_OK != AppendNativeAppAlgorithmJson(&Writer, &Result)) {
            eError = IPSEC_ERR_FILE_READ;
        }
        if ((IPSEC_OK != eError) && (IPSEC_OK == eFirstError)) {
            eFirstError = eError;
        }
        if ((IPSEC_OK != eError) && !pOptions->bContinueOnError) {
            break;
        }
        if ((0U < pOptions->uiDelayMs) &&
            ((uiOffset + 1U) < uiRequested)) {
            SleepNativeAppAlgorithm(pOptions->uiDelayMs);
        }
    }
    if (IsNativeAppStopRequested() && (IPSEC_OK == eFirstError)) {
        eFirstError = IPSEC_ERR_INTERNAL;
    }
    ReportNativeAppAlgorithm(
        pLog, stdout, (0U == Writer.uiFailed) ? "PASS" : "FAIL",
        "algorithm summary: completed=%" PRIu32
        " passed=%" PRIu32 " failed=%" PRIu32,
        Writer.uiCaseCount, Writer.uiPassed, Writer.uiFailed);
    CloseNativeAppAlgorithmJson(&Writer);
    eError = FinishNativeAppAlgorithmRun(iSocket, &Remote, acRunId,
                                         pConfig->uiTimeoutMs);
    if ((IPSEC_OK != eError) && (IPSEC_OK == eFirstError)) {
        eFirstError = eError;
    }
    ReportNativeAppAlgorithm(
        pLog, stdout, (IPSEC_OK == eError) ? "INFO" : "WARN",
        "responder completion: %s", GetIpsecErrorString(eError));
    ReportNativeAppAlgorithmFinalState(pContext, pLog);
    (void)WriteNativeAppAlgorithmRunReport(
        pContext, pConfig, pOptions->eMode, "initiator",
        acResultDirectory, uiRequested, true);
    (void)close(iSocket);
    (void)fclose(pLog);
    return eFirstError;
}

static IpsecError_t ReplyNativeAppAlgorithmServer(
    int32_t iSocket,
    const NativeAppAlgorithmEndpoint_t *pSender,
    const char *pcAction,
    const NativeAppAlgorithmCase_t *pCase,
    const char *pcResult)
{
    char acMessage[NATIVE_APP_ALGORITHM_MESSAGE_LENGTH];
    IpsecError_t eError = FormatNativeAppAlgorithmMessage(
        acMessage, sizeof(acMessage), pcAction, pCase, pcResult, "0");

    if (IPSEC_OK == eError) {
        eError = SendNativeAppAlgorithmMessage(iSocket, pSender, acMessage);
    }
    return eError;
}

static IpsecError_t RunNativeAppAlgorithmServerCase(
    IpsecContext_t *pContext,
    int32_t iSocket,
    const NativeAppAlgorithmEndpoint_t *pPeer,
    const NativeAppAlgorithmEndpoint_t *pSender,
    const NativeAppConfig_t *pBaseConfig,
    const NativeAppAlgorithmCase_t *pCase,
    const char *pcResultDirectory,
    const char *pcCaseDirectory,
    uint32_t uiOrdinal,
    uint32_t uiRequested,
    bool *pbCleanupVerified)
{
    NativeAppAlgorithmCaseResult_t Result = {0};
    NativeAppRuntimeConfig_t Runtime = {0};
    NativeAppConfig_t Config = *pBaseConfig;
    uint64_t ullElapsedMs = 0U;
    uint64_t ullTimeoutMs = (uint64_t)pBaseConfig->uiTimeoutMs * 2U;
    bool bConnectionLoaded = false;
    bool bVerified = false;
    uint64_t ullStartMs = GetNativeAppAlgorithmTimeMs();
    IpsecError_t eCleanupResult = IPSEC_OK;
    IpsecError_t eCaseError = IPSEC_OK;
    IpsecError_t eError;

    if (NULL == pbCleanupVerified) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    *pbCleanupVerified = false;
    Result.Case = *pCase;
    Result.eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_CONFIG;
    eError = BuildNativeAppAlgorithmConfig(pBaseConfig, pCase, &Config,
                                           &Runtime);
    if (IPSEC_OK == eError) {
        eError = AddIpsecConnection(pContext, &Runtime.Connection);
        bConnectionLoaded = (IPSEC_OK == eError);
    }
    if (IPSEC_OK == eError) {
        eError = ReplyNativeAppAlgorithmServer(iSocket, pSender, "READY",
                                               pCase, "OK");
    }
    while ((IPSEC_OK == eError) &&
           (ullElapsedMs <= ullTimeoutMs) &&
           !IsNativeAppStopRequested()) {
        char acMessage[NATIVE_APP_ALGORITHM_MESSAGE_LENGTH];
        char *pacFields[10];
        uint32_t uiFieldCount = 0U;
        NativeAppAlgorithmEndpoint_t ActualSender;

        eError = ReceiveNativeAppAlgorithmMessage(
            iSocket, pPeer, acMessage, sizeof(acMessage), &ActualSender);
        if (IPSEC_ERR_VICI_TIMEOUT == eError) {
            eError = IPSEC_OK;
            ullElapsedMs += NATIVE_APP_ALGORITHM_POLL_MS;
            continue;
        }
        else if ((IPSEC_ERR_PERMISSION == eError) ||
                 !SplitNativeAppAlgorithmMessage(
                     acMessage, pacFields,
                     NATIVE_APP_ARRAY_COUNT(pacFields), &uiFieldCount) ||
                 (3U > uiFieldCount) ||
                 (0 != strcmp(pCase->acId, pacFields[2]))) {
            eError = IPSEC_OK;
            continue;
        }
        else {
            /* Process the matching peer and testcase message. */
        }
        if (0 == strcmp("PREPARE", pacFields[1])) {
            eError = ReplyNativeAppAlgorithmServer(
                iSocket, &ActualSender, "READY", pCase, "OK");
        }
        else if (0 == strcmp("VERIFY", pacFields[1])) {
            IpsecError_t eVerify = QueryNativeAppAlgorithmState(
                pContext, &Config, pCase, &Result);
            IpsecError_t eReply;

            if (IPSEC_OK == eVerify) {
                Result.eResult = NATIVE_APP_ALGORITHM_RESULT_PASS;
                Result.bDataPathVerified = true;
            }
            else {
                /* QueryNativeAppAlgorithmState set the failure stage. */
            }
            (void)CaptureNativeAppAlgorithmCaseReport(
                pContext, &Config, &Result, pcCaseDirectory);
            eReply = ReplyNativeAppAlgorithmServer(
                iSocket, &ActualSender, "RESULT", pCase,
                GetNativeAppAlgorithmResultName(Result.eResult));
            eCaseError = eVerify;
            eError = eReply;
            bVerified = true;
        }
        else if ((0 == strcmp("CLEANUP", pacFields[1])) ||
                 (0 == strcmp("ABORT", pacFields[1]))) {
            IpsecError_t eCleanup = IPSEC_OK;

            if (bConnectionLoaded) {
                eCleanup = CleanupNativeAppAlgorithmCase(
                    pContext, &Config, Result.uiReqid, false,
                    &Result.Cleanup);
                bConnectionLoaded = false;
            }
            eCleanupResult = eCleanup;
            if (IPSEC_OK == eCleanup) {
                eError = ReplyNativeAppAlgorithmServer(
                    iSocket, &ActualSender, "DONE", pCase, "OK");
            }
            else {
                eError = eCleanup;
                Result.eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_CLEANUP;
            }
            if (0 == strcmp("ABORT", pacFields[1])) {
                bVerified = true;
                Result.eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_SYNC;
            }
            else {
                /* A verified testcase follows the normal cleanup path. */
            }
            break;
        }
        else {
            /* Ignore unknown protocol actions from the configured peer. */
        }
    }
    if (bConnectionLoaded) {
        IpsecError_t eCleanup = CleanupNativeAppAlgorithmCase(
            pContext, &Config, Result.uiReqid, false, &Result.Cleanup);

        eCleanupResult = eCleanup;
        if (IPSEC_OK != eCleanup) {
            Result.eResult = NATIVE_APP_ALGORITHM_RESULT_FAIL_CLEANUP;
        }
        else {
            /* Preserve the verification result after successful cleanup. */
        }
        if (IPSEC_OK == eError) {
            eError = eCleanup;
        }
    }
    if ((IPSEC_OK == eError) && !bVerified) {
        eError = IPSEC_ERR_VICI_TIMEOUT;
    }
    else if ((IPSEC_OK == eError) && (IPSEC_OK != eCaseError)) {
        eError = eCaseError;
    }
    else {
        /* Preserve protocol or verification result. */
    }
    Result.eError = eError;
    Result.eCleanupError = eCleanupResult;
    *pbCleanupVerified = Result.Cleanup.bLocalVerified;
    Result.ullDurationMs = GetNativeAppAlgorithmTimeMs() - ullStartMs;
    (void)FinishNativeAppAlgorithmCaseReport(
        pContext, &Config, &Result, "responder", pcResultDirectory,
        pcCaseDirectory, uiOrdinal, uiRequested);
    return eError;
}

IpsecError_t RunNativeAppAlgorithmServer(
    IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig,
    uint32_t uiPort)
{
    NativeAppAlgorithmEndpoint_t Local;
    NativeAppAlgorithmEndpoint_t Peer;
    char acRunId[NATIVE_APP_ALGORITHM_RUN_ID_LENGTH] = {0};
    char acLastCleanupCaseId[NATIVE_APP_ALGORITHM_CASE_ID_LENGTH] = {0};
    char acResultDirectory[NATIVE_APP_PATH_LENGTH] = {0};
    FILE *pLog = NULL;
    uint32_t uiRunRequested = 0U;
    uint32_t uiRunCaseOrdinal = 0U;
    NativeAppAlgorithmMode_t eRunMode = NATIVE_APP_ALGORITHM_CUSTOM;
    int32_t iSocket = -1;
    bool bRunCompleted = false;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pConfig) ||
        (NATIVE_APP_ROLE_RESPONDER != pConfig->eRole)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (0U == uiPort) {
        uiPort = NATIVE_APP_ALGORITHM_DEFAULT_PORT;
    }
    eError = InitializeNativeAppAlgorithmEndpoint(
        pConfig->acLocalAddress, uiPort, &Local);
    if (IPSEC_OK == eError) {
        eError = InitializeNativeAppAlgorithmEndpoint(
            pConfig->acRemoteAddress, uiPort, &Peer);
    }
    if (IPSEC_OK == eError) {
        eError = OpenNativeAppAlgorithmSocket(
            &Local, NATIVE_APP_ALGORITHM_POLL_MS, &iSocket);
    }
    if (IPSEC_OK == eError) {
        eError = LoadNativeAppCredential(pContext, pConfig);
    }
    if (IPSEC_OK != eError) {
        if (0 <= iSocket) {
            (void)close(iSocket);
        }
        return eError;
    }

    ReportNativeAppAlgorithm(
        NULL, stdout, "INFO",
        "algorithm responder ready: %s:%" PRIu32
        " peer=%s (Ctrl-C to stop)",
        pConfig->acLocalAddress, uiPort, pConfig->acRemoteAddress);
    while (!IsNativeAppStopRequested()) {
        char acMessage[NATIVE_APP_ALGORITHM_MESSAGE_LENGTH];
        char *pacFields[8];
        uint32_t uiFieldCount = 0U;
        NativeAppAlgorithmEndpoint_t Sender;
        NativeAppAlgorithmCase_t Case = {0};

        eError = ReceiveNativeAppAlgorithmMessage(
            iSocket, &Peer, acMessage, sizeof(acMessage), &Sender);
        if (IPSEC_ERR_VICI_TIMEOUT == eError) {
            eError = IPSEC_OK;
            continue;
        }
        else if (IPSEC_ERR_PERMISSION == eError) {
            eError = IPSEC_OK;
            continue;
        }
        else if (IPSEC_OK != eError) {
            break;
        }
        if (!SplitNativeAppAlgorithmMessage(
                acMessage, pacFields, NATIVE_APP_ARRAY_COUNT(pacFields),
                &uiFieldCount) || (3U > uiFieldCount)) {
            continue;
        }
        if (((0 == strcmp("CLEANUP", pacFields[1])) ||
             (0 == strcmp("ABORT", pacFields[1]))) &&
            ('\0' != acLastCleanupCaseId[0]) &&
            (0 == strcmp(acLastCleanupCaseId, pacFields[2]))) {
            eError = CopyNativeAppAlgorithmValue(
                Case.acId, sizeof(Case.acId), pacFields[2]);
            if (IPSEC_OK == eError) {
                eError = ReplyNativeAppAlgorithmServer(
                    iSocket, &Sender, "DONE", &Case, "OK");
            }
            if (IPSEC_OK != eError) {
                break;
            }
            continue;
        }
        else if ((0 == strcmp("FINISH", pacFields[1])) &&
            ('\0' != acRunId[0]) &&
            (0 == strcmp(acRunId, pacFields[2]))) {
            eError = CopyNativeAppAlgorithmValue(
                Case.acId, sizeof(Case.acId), pacFields[2]);
            if (IPSEC_OK == eError) {
                eError = ReplyNativeAppAlgorithmServer(
                    iSocket, &Sender, "FINISHED", &Case, "OK");
            }
            if (IPSEC_OK == eError) {
                ReportNativeAppAlgorithmFinalState(pContext, pLog);
                (void)WriteNativeAppAlgorithmRunReport(
                    pContext, pConfig, eRunMode, "responder",
                    acResultDirectory, uiRunRequested, true);
                ReportNativeAppAlgorithm(
                    pLog, stdout, "INFO",
                    "algorithm responder completed: run=%s results=%s",
                    acRunId, acResultDirectory);
                bRunCompleted = true;
            }
            break;
        }
        else if ((0 != strcmp("PREPARE", pacFields[1])) ||
                 (8U > uiFieldCount) ||
                 !IsNativeAppAlgorithmRunIdValid(pacFields[5])) {
            continue;
        }
        else if (!ParseNativeAppAlgorithmUint32(pacFields[6],
                                                &Case.uiNumber) ||
                 !ParseNativeAppAlgorithmUint32(pacFields[7],
                                                &uiRunRequested) ||
                 (0U == Case.uiNumber) || (0U == uiRunRequested)) {
            continue;
        }
        else if ('\0' == acRunId[0]) {
            eError = CopyNativeAppAlgorithmValue(
                acRunId, sizeof(acRunId), pacFields[5]);
            if (IPSEC_OK == eError) {
                eError = OpenNativeAppAlgorithmRunLog(
                    pConfig, acRunId, "responder", acResultDirectory,
                    sizeof(acResultDirectory), &pLog);
            }
            if (IPSEC_OK == eError) {
                eRunMode = GetNativeAppAlgorithmRunMode(acRunId);
                eError = WriteNativeAppAlgorithmRunReport(
                    pContext, pConfig, eRunMode, "responder",
                    acResultDirectory, uiRunRequested, false);
            }
            if (IPSEC_OK == eError) {
                ReportNativeAppAlgorithm(
                    pLog, stdout, "INFO",
                    "algorithm responder run started: run=%s results=%s",
                    acRunId, acResultDirectory);
            }
        }
        else if (0 != strcmp(acRunId, pacFields[5])) {
            continue;
        }
        else {
            eError = IPSEC_OK;
        }
        if (IPSEC_OK != eError) {
            break;
        }
        eError = CopyNativeAppAlgorithmValue(Case.acId, sizeof(Case.acId),
                                             pacFields[2]);
        if (IPSEC_OK == eError) {
            eError = CopyNativeAppAlgorithmValue(
                Case.acIkeProposal, sizeof(Case.acIkeProposal), pacFields[3]);
        }
        if (IPSEC_OK == eError) {
            eError = CopyNativeAppAlgorithmValue(
                Case.acEspProposal, sizeof(Case.acEspProposal), pacFields[4]);
        }
        if (IPSEC_OK == eError) {
            NativeAppAlgorithmCase_t Derived = {0};

            eError = GetNativeAppAlgorithmCase(
                NATIVE_APP_ALGORITHM_CUSTOM, 0U, pConfig,
                Case.acIkeProposal, Case.acEspProposal, &Derived);
            if (IPSEC_OK == eError) {
                uint32_t uiCaseNumber = Case.uiNumber;

                (void)CopyNativeAppAlgorithmValue(
                    Derived.acId, sizeof(Derived.acId), Case.acId);
                Case = Derived;
                Case.uiNumber = uiCaseNumber;
            }
        }
        if (IPSEC_OK == eError) {
            char acCaseDirectory[NATIVE_APP_PATH_LENGTH] = {0};
            bool bCleanupVerified = false;

            uiRunCaseOrdinal++;
            eError = CreateNativeAppAlgorithmCaseReport(
                pConfig, &Case, "responder", acResultDirectory,
                uiRunCaseOrdinal, uiRunRequested, acCaseDirectory,
                sizeof(acCaseDirectory));
            if (IPSEC_OK != eError) {
                ReportNativeAppAlgorithm(
                    pLog, stderr, "FAIL",
                    "responder report directory failed: %s",
                    GetIpsecErrorString(eError));
            }
            else {
                ReportNativeAppAlgorithm(
                    pLog, stdout, "INFO",
                    "responder case: %s ike=%s esp=%s",
                    Case.acId, Case.acIkeProposal, Case.acEspProposal);
                eError = RunNativeAppAlgorithmServerCase(
                    pContext, iSocket, &Peer, &Sender, pConfig, &Case,
                    acResultDirectory, acCaseDirectory, uiRunCaseOrdinal,
                    uiRunRequested, &bCleanupVerified);
                if (bCleanupVerified) {
                    (void)CopyNativeAppAlgorithmValue(
                        acLastCleanupCaseId, sizeof(acLastCleanupCaseId),
                        Case.acId);
                }
                else {
                    acLastCleanupCaseId[0] = '\0';
                }
                ReportNativeAppAlgorithm(
                    pLog, (IPSEC_OK == eError) ? stdout : stderr,
                    (IPSEC_OK == eError) ? "PASS" : "FAIL",
                    "responder result: %s %s", Case.acId,
                    (IPSEC_OK == eError) ? "PASS" :
                    GetIpsecErrorString(eError));
            }
        }
        if ((IPSEC_OK != eError) && !IsNativeAppStopRequested()) {
            ReportNativeAppAlgorithm(
                pLog, stderr, "FAIL", "algorithm responder case failed: %s",
                GetIpsecErrorString(eError));
            eError = IPSEC_OK;
        }
    }
    (void)close(iSocket);
    if (NULL != pLog) {
        (void)fclose(pLog);
    }
    if (IsNativeAppStopRequested() || bRunCompleted) {
        eError = IPSEC_OK;
    }
    else {
        /* Preserve the responder transport or result-file error. */
    }
    return eError;
}
