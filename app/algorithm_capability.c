#include "app_internal.h"

#include <ctype.h>
#include <dirent.h>
#include <dlfcn.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/utsname.h>

#define NATIVE_APP_OPENSSL_3_0_5_VERSION 0x30000050ULL

typedef uintptr_t (*NativeAppOpenSslVersionFunction_t)(void);

static bool CopyNativeAppCapabilityText(
    char *pcDestination,
    size_t zDestinationLength,
    const char *pcSource)
{
    int32_t iLength;

    if ((NULL == pcDestination) || (0U == zDestinationLength) ||
        (NULL == pcSource)) {
        return false;
    }
    iLength = snprintf(pcDestination, zDestinationLength, "%s", pcSource);
    return (0 <= iLength) && ((size_t)iLength < zDestinationLength);
}

static void RemoveNativeAppCapabilityQuotes(char *pcValue)
{
    size_t zLength;

    if (NULL == pcValue) {
        return;
    }
    zLength = strlen(pcValue);
    if ((2U <= zLength) && ('"' == pcValue[0]) &&
        ('"' == pcValue[zLength - 1U])) {
        (void)memmove(pcValue, pcValue + 1, zLength - 2U);
        pcValue[zLength - 2U] = '\0';
    }
    else {
        /* The os-release value was not quoted. */
    }
}

static void CollectNativeAppOperatingSystem(
    NativeAppAlgorithmCapabilities_t *pCapabilities)
{
    char acLine[512];
    FILE *pFile;

    pFile = fopen("/etc/os-release", "r");
    if (NULL == pFile) {
        return;
    }
    while (NULL != fgets(acLine, sizeof(acLine), pFile)) {
        char *pcValue = NULL;
        char *pcDestination = NULL;
        size_t zDestinationLength = 0U;

        acLine[strcspn(acLine, "\r\n")] = '\0';
        if (0 == strncmp("NAME=", acLine, 5U)) {
            pcValue = acLine + 5U;
            pcDestination = pCapabilities->acOsName;
            zDestinationLength = sizeof(pCapabilities->acOsName);
        }
        else if (0 == strncmp("VERSION_ID=", acLine, 11U)) {
            pcValue = acLine + 11U;
            pcDestination = pCapabilities->acOsVersion;
            zDestinationLength = sizeof(pCapabilities->acOsVersion);
        }
        else {
            /* This os-release field is not required by the report. */
        }
        if ((NULL != pcValue) &&
            CopyNativeAppCapabilityText(pcDestination, zDestinationLength,
                                        pcValue)) {
            RemoveNativeAppCapabilityQuotes(pcDestination);
        }
        else {
            /* Continue even when an optional value cannot be copied. */
        }
    }
    (void)fclose(pFile);
}

static void CollectNativeAppSystemIdentity(
    IpsecContext_t *pContext,
    NativeAppAlgorithmCapabilities_t *pCapabilities)
{
    IpsecDaemonStatus_t Status = {0};
    struct utsname SystemIdentity;

    CollectNativeAppOperatingSystem(pCapabilities);
    if (IPSEC_OK == GetIpsecDaemonStatus(pContext, &Status)) {
        (void)CopyNativeAppCapabilityText(
            pCapabilities->acDaemonVersion,
            sizeof(pCapabilities->acDaemonVersion), Status.acVersion);
        (void)CopyNativeAppCapabilityText(
            pCapabilities->acKernelRelease,
            sizeof(pCapabilities->acKernelRelease), Status.acSystemRelease);
        (void)CopyNativeAppCapabilityText(
            pCapabilities->acMachine,
            sizeof(pCapabilities->acMachine), Status.acMachine);
    }
    else if (0 == uname(&SystemIdentity)) {
        (void)CopyNativeAppCapabilityText(
            pCapabilities->acKernelRelease,
            sizeof(pCapabilities->acKernelRelease), SystemIdentity.release);
        (void)CopyNativeAppCapabilityText(
            pCapabilities->acMachine,
            sizeof(pCapabilities->acMachine), SystemIdentity.machine);
    }
    else {
        /* Environment identity remains unknown when both queries fail. */
    }
}

static const char *GetNativeAppCapabilityDatapath(
    IpsecDatapathType_t eType)
{
    const char *pcName;

    switch (eType) {
    case IPSEC_DATAPATH_KERNEL_XFRM:
        pcName = "kernel-xfrm";
        break;

    case IPSEC_DATAPATH_KERNEL_LIBIPSEC:
        pcName = "kernel-libipsec";
        break;

    default:
        pcName = "unknown";
        break;
    }
    return pcName;
}

static void UpdateNativeAppModp8192Policy(
    NativeAppAlgorithmCapabilities_t *pCapabilities)
{
    int32_t iLength = 0;

    pCapabilities->bModp8192Supported = true;
    pCapabilities->acModp8192Reason[0] = '\0';
    if ('\0' == pCapabilities->acModp8192Plugin[0]) {
        iLength = snprintf(
            pCapabilities->acModp8192Reason,
            sizeof(pCapabilities->acModp8192Reason),
            "charon does not advertise MODP8192");
        pCapabilities->bModp8192Supported = false;
    }
    else if ('\0' == pCapabilities->acKdfPrfPlusPlugin[0]) {
        iLength = snprintf(
            pCapabilities->acModp8192Reason,
            sizeof(pCapabilities->acModp8192Reason),
            "charon does not advertise KDF_PRF_PLUS");
        pCapabilities->bModp8192Supported = false;
    }
    else if ((0 == strcmp("openssl", pCapabilities->acKdfPrfPlusPlugin)) &&
             pCapabilities->bOpenSslVersionKnown &&
             (pCapabilities->ullOpenSslVersion <
              NATIVE_APP_OPENSSL_3_0_5_VERSION)) {
        iLength = snprintf(
            pCapabilities->acModp8192Reason,
            sizeof(pCapabilities->acModp8192Reason),
            "OpenSSL PRF+ KDF with MODP8192 requires OpenSSL 3.0.5 or newer"
            " (detected=0x%" PRIx64 ")",
            pCapabilities->ullOpenSslVersion);
        pCapabilities->bModp8192Supported = false;
    }
    else {
        /* Unknown OpenSSL versions are verified by actual negotiation. */
    }
    if ((0 > iLength) ||
        ((size_t)iLength >= sizeof(pCapabilities->acModp8192Reason))) {
        pCapabilities->acModp8192Reason[0] = '\0';
    }
    else {
        /* The capability reason is empty or complete. */
    }
}

static bool IsNativeAppNumericName(const char *pcName)
{
    const unsigned char *pucText = (const unsigned char *)pcName;

    if ((NULL == pucText) || ('\0' == *pucText)) {
        return false;
    }
    while ('\0' != *pucText) {
        if (0 == isdigit(*pucText)) {
            return false;
        }
        else {
            pucText++;
        }
    }
    return true;
}

static bool IsNativeAppCharonProcess(const char *pcProcessId)
{
    char acPath[NATIVE_APP_PATH_LENGTH];
    char acName[64] = {0};
    FILE *pFile;
    int32_t iLength;
    bool bCharon = false;

    iLength = snprintf(acPath, sizeof(acPath), "/proc/%s/comm", pcProcessId);
    if ((0 > iLength) || ((size_t)iLength >= sizeof(acPath))) {
        return false;
    }
    pFile = fopen(acPath, "r");
    if (NULL != pFile) {
        if (NULL != fgets(acName, sizeof(acName), pFile)) {
            acName[strcspn(acName, "\r\n")] = '\0';
            bCharon = (0 == strcmp("charon", acName)) ||
                (0 == strcmp("charon-systemd", acName));
        }
        else {
            /* Ignore a process that terminated while /proc was scanned. */
        }
        (void)fclose(pFile);
    }
    else {
        /* Ignore inaccessible and short-lived processes. */
    }
    return bCharon;
}

static IpsecError_t FindNativeAppCharonOpenSslLibrary(
    char *pcLibrary,
    size_t zLibraryLength)
{
    DIR *pDirectory;
    struct dirent *pEntry;
    IpsecError_t eError = IPSEC_ERR_FILE_OPEN;

    if ((NULL == pcLibrary) || (0U == zLibraryLength)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pcLibrary[0] = '\0';
    pDirectory = opendir("/proc");
    if (NULL == pDirectory) {
        return IPSEC_ERR_FILE_OPEN;
    }
    while ((NULL != (pEntry = readdir(pDirectory))) &&
           (IPSEC_OK != eError)) {
        char acMapsPath[NATIVE_APP_PATH_LENGTH];
        char acLine[1024];
        FILE *pMaps;
        int32_t iLength;

        if (!IsNativeAppNumericName(pEntry->d_name) ||
            !IsNativeAppCharonProcess(pEntry->d_name)) {
            continue;
        }
        iLength = snprintf(acMapsPath, sizeof(acMapsPath),
                           "/proc/%s/maps", pEntry->d_name);
        if ((0 > iLength) || ((size_t)iLength >= sizeof(acMapsPath))) {
            continue;
        }
        pMaps = fopen(acMapsPath, "r");
        if (NULL == pMaps) {
            continue;
        }
        while (NULL != fgets(acLine, sizeof(acLine), pMaps)) {
            char *pcPath = strchr(acLine, '/');

            if ((NULL != pcPath) &&
                (NULL != strstr(pcPath, "libcrypto.so"))) {
                pcPath[strcspn(pcPath, "\r\n")] = '\0';
                iLength = snprintf(pcLibrary, zLibraryLength, "%s", pcPath);
                eError = ((0 <= iLength) &&
                          ((size_t)iLength < zLibraryLength)) ?
                    IPSEC_OK : IPSEC_ERR_BUFFER_TOO_SMALL;
                break;
            }
            else {
                /* Continue until the mapped OpenSSL library is found. */
            }
        }
        (void)fclose(pMaps);
    }
    (void)closedir(pDirectory);
    return eError;
}

static IpsecError_t ReadNativeAppOpenSslVersion(
    const char *pcLibrary,
    uint64_t *pullVersion)
{
    NativeAppOpenSslVersionFunction_t pVersionFunction = NULL;
    void *pvHandle;
    void *pvSymbol;
    IpsecError_t eError = IPSEC_ERR_NOT_SUPPORTED;

    if ((NULL == pcLibrary) || (NULL == pullVersion)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pvHandle = dlopen(pcLibrary, RTLD_LAZY | RTLD_LOCAL);
    if (NULL == pvHandle) {
        return IPSEC_ERR_FILE_OPEN;
    }
    pvSymbol = dlsym(pvHandle, "OpenSSL_version_num");
    if ((NULL != pvSymbol) &&
        (sizeof(pVersionFunction) == sizeof(pvSymbol))) {
        (void)memcpy(&pVersionFunction, &pvSymbol,
                     sizeof(pVersionFunction));
        *pullVersion = (uint64_t)pVersionFunction();
        eError = IPSEC_OK;
    }
    else {
        /* The mapped library does not expose a compatible version API. */
    }
    (void)dlclose(pvHandle);
    return eError;
}

static void SaveNativeAppAlgorithmPlugin(
    const IpsecAlgorithmInfo_t *pAlgorithm,
    NativeAppAlgorithmCapabilities_t *pCapabilities)
{
    char *pcDestination = NULL;
    size_t zDestinationLength = 0U;

    if (((0 == strcmp("ke", pAlgorithm->acType)) ||
         (0 == strcmp("dh", pAlgorithm->acType))) &&
        (0 == strcmp("MODP_8192", pAlgorithm->acName))) {
        pcDestination = pCapabilities->acModp8192Plugin;
        zDestinationLength = sizeof(pCapabilities->acModp8192Plugin);
    }
    else if ((0 == strcmp("kdf", pAlgorithm->acType)) &&
             (0 == strcmp("KDF_PRF_PLUS", pAlgorithm->acName))) {
        pcDestination = pCapabilities->acKdfPrfPlusPlugin;
        zDestinationLength = sizeof(pCapabilities->acKdfPrfPlusPlugin);
    }
    else {
        /* This algorithm is not part of the MODP8192 capability check. */
    }
    if (NULL != pcDestination) {
        int32_t iLength = snprintf(pcDestination, zDestinationLength, "%s",
                                   pAlgorithm->acPlugin);

        if ((0 > iLength) || ((size_t)iLength >= zDestinationLength)) {
            pcDestination[0] = '\0';
        }
        else {
            /* The provider name was saved without truncation. */
        }
    }
    else {
        /* No capability field needs to be updated. */
    }
}

IpsecError_t CollectNativeAppAlgorithmCapabilities(
    IpsecContext_t *pContext,
    NativeAppAlgorithmCapabilities_t *pCapabilities)
{
    IpsecAlgorithmList_t Algorithms = {0};
    IpsecDatapathStatus_t Datapath = {0};
    uint32_t uiIndex;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pCapabilities)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    (void)memset(pCapabilities, 0, sizeof(*pCapabilities));
    CollectNativeAppSystemIdentity(pContext, pCapabilities);
    eError = GetIpsecDatapathStatus(pContext, &Datapath);
    if (IPSEC_OK == eError) {
        pCapabilities->eDatapathType = Datapath.eType;
        pCapabilities->bDatapathReady = Datapath.bReady;
        pCapabilities->bEsnSupported =
            (IPSEC_DATAPATH_KERNEL_LIBIPSEC != Datapath.eType);
        eError = GetIpsecAlgorithms(pContext, &Algorithms);
    }
    else {
        /* The datapath query error is returned to the caller. */
    }
    if (IPSEC_OK == eError) {
        for (uiIndex = 0U; uiIndex < Algorithms.uiCount; uiIndex++) {
            SaveNativeAppAlgorithmPlugin(&Algorithms.pItems[uiIndex],
                                         pCapabilities);
        }
        if (IPSEC_OK == FindNativeAppCharonOpenSslLibrary(
                pCapabilities->acOpenSslLibrary,
                sizeof(pCapabilities->acOpenSslLibrary)) &&
            (IPSEC_OK == ReadNativeAppOpenSslVersion(
                pCapabilities->acOpenSslLibrary,
                &pCapabilities->ullOpenSslVersion))) {
            pCapabilities->bOpenSslVersionKnown = true;
        }
        else {
            /* Unknown versions are verified by the actual negotiation. */
        }
        UpdateNativeAppModp8192Policy(pCapabilities);
    }
    else {
        /* Preserve the algorithm query error. */
    }
    FreeIpsecAlgorithmList(&Algorithms);
    return eError;
}

IpsecError_t CheckNativeAppAlgorithmCaseSupport(
    const NativeAppAlgorithmCapabilities_t *pCapabilities,
    const NativeAppAlgorithmCase_t *pCase,
    char *pcReason,
    size_t zReasonLength)
{
    int32_t iLength = 0;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pCapabilities) || (NULL == pCase) ||
        (NULL == pcReason) || (0U == zReasonLength)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    pcReason[0] = '\0';
    if (pCase->bExpectEsn && !pCapabilities->bEsnSupported) {
        iLength = snprintf(
            pcReason, zReasonLength,
            "kernel-libipsec does not support ESP ESN");
        eError = IPSEC_ERR_NOT_SUPPORTED;
    }
    else if ((0 == strcmp("MODP_8192", pCase->acExpectedChildKe)) &&
             !pCapabilities->bModp8192Supported) {
        iLength = snprintf(pcReason, zReasonLength, "%s",
                           ('\0' == pCapabilities->acModp8192Reason[0]) ?
                           "MODP8192 is not supported by local charon" :
                           pCapabilities->acModp8192Reason);
        eError = IPSEC_ERR_NOT_SUPPORTED;
    }
    else {
        /* This testcase has no known local capability limitation. */
    }
    if ((IPSEC_ERR_NOT_SUPPORTED == eError) &&
        ((0 > iLength) || ((size_t)iLength >= zReasonLength))) {
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        /* Return the support decision and complete reason. */
    }
    return eError;
}

IpsecError_t FormatNativeAppAlgorithmCapabilitySummary(
    const NativeAppAlgorithmCapabilities_t *pCapabilities,
    const char *pcSupportReason,
    char *pcSummary,
    size_t zSummaryLength)
{
    int32_t iLength;

    if ((NULL == pCapabilities) || (NULL == pcSupportReason) ||
        (NULL == pcSummary) || (0U == zSummaryLength) ||
        (NULL != strpbrk(pcSupportReason, "|\r\n"))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    iLength = snprintf(
        pcSummary, zSummaryLength,
        "datapath=%s;esn=%s;modp8192=%s;openssl_known=%s;"
        "openssl_version=0x%" PRIx64 ";modp_plugin=%s;kdf_plugin=%s;reason=%s",
        GetNativeAppCapabilityDatapath(pCapabilities->eDatapathType),
        pCapabilities->bEsnSupported ? "supported" : "unsupported",
        pCapabilities->bModp8192Supported ? "supported" : "unsupported",
        pCapabilities->bOpenSslVersionKnown ? "yes" : "no",
        pCapabilities->ullOpenSslVersion,
        ('\0' == pCapabilities->acModp8192Plugin[0]) ? "unknown" :
            pCapabilities->acModp8192Plugin,
        ('\0' == pCapabilities->acKdfPrfPlusPlugin[0]) ? "unknown" :
            pCapabilities->acKdfPrfPlusPlugin,
        ('\0' == pcSupportReason[0]) ? "none" : pcSupportReason);
    return ((0 <= iLength) && ((size_t)iLength < zSummaryLength)) ?
        IPSEC_OK : IPSEC_ERR_BUFFER_TOO_SMALL;
}
