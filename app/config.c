#include "app_internal.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NATIVE_APP_LINE_LENGTH 2048U

static char *TrimNativeAppText(char *pcText)
{
    char *pcEnd;

    while (0 != isspace((unsigned char)*pcText)) {
        pcText++;
    }
    pcEnd = pcText + strlen(pcText);
    while ((pcEnd > pcText) &&
           (0 != isspace((unsigned char)pcEnd[-1]))) {
        pcEnd--;
    }
    *pcEnd = '\0';
    return pcText;
}

static void SetNativeAppError(
    char *pcError,
    uint32_t uiErrorLength,
    const char *pcFormat,
    const char *pcValue)
{
    if ((NULL != pcError) && (0U < uiErrorLength)) {
        (void)snprintf(pcError, uiErrorLength, pcFormat, pcValue);
    }
    else {
        /* The caller did not request diagnostic text. */
    }
}

static bool CopyNativeAppText(
    char *pcDestination,
    uint32_t uiDestinationLength,
    const char *pcSource)
{
    size_t ulLength = strnlen(pcSource, uiDestinationLength);

    if (ulLength >= uiDestinationLength) {
        return false;
    }
    else {
        (void)memcpy(pcDestination, pcSource, ulLength + 1U);
        return true;
    }
}

static bool ParseNativeAppBoolean(const char *pcValue, bool *pbValue)
{
    bool bParsed = true;

    if ((0 == strcmp("true", pcValue)) ||
        (0 == strcmp("yes", pcValue)) ||
        (0 == strcmp("1", pcValue))) {
        *pbValue = true;
    }
    else if ((0 == strcmp("false", pcValue)) ||
             (0 == strcmp("no", pcValue)) ||
             (0 == strcmp("0", pcValue))) {
        *pbValue = false;
    }
    else {
        bParsed = false;
    }
    return bParsed;
}

static bool ParseNativeAppUint32(
    const char *pcValue,
    uint32_t *puiValue)
{
    char *pcEnd = NULL;
    uint64_t ullValue;

    errno = 0;
    ullValue = strtoull(pcValue, &pcEnd, 10);
    if ((0 != errno) || (pcEnd == pcValue) || ('\0' != *pcEnd) ||
        (UINT32_MAX < ullValue)) {
        return false;
    }
    else {
        *puiValue = (uint32_t)ullValue;
        return true;
    }
}

static bool IsNativeAppIgnoredV15Key(const char *pcKey)
{
    static const char *pacKeys[] = {
        "local_cidr", "interface", "interface_name", "service_name",
        "initiator_udp_bind_ip", "responder_udp_bind_ip", "udp_port",
        "matrix_control_port", "packet_count", "payload_size", "udp_size",
        "udp_interval_ms", "udp_start_delay_sec", "test_timeout_sec",
        "matrix_timeout_sec", "barrier_timeout_sec", "barrier_hold_ms",
        "capture_drain_ms", "capture_buffer_kib", "measurement_guard_ms",
        "capture_enabled", "capture_interface", "capture_all_traffic",
        "capture_filter", "tshark_display_filter", "manage_firewall",
        "configure_address", "cleanup_existing_sa", "capture_plaintext",
        "capture_xfrm_compare"
    };
    uint32_t uiIndex;
    bool bFound = false;

    for (uiIndex = 0U;
         uiIndex < (uint32_t)(sizeof(pacKeys) / sizeof(pacKeys[0]));
         uiIndex++) {
        if (0 == strcmp(pacKeys[uiIndex], pcKey)) {
            bFound = true;
            break;
        }
        else {
            /* Check the next v15-only setting. */
        }
    }
    return bFound;
}

IpsecError_t SetNativeAppConfigSetting(
    NativeAppConfig_t *pConfig,
    const char *pcKey,
    const char *pcValue)
{
    bool bAccepted = true;

    if (0 == strcmp("role", pcKey)) {
        if (0 == strcmp("initiator", pcValue)) {
            pConfig->eRole = NATIVE_APP_ROLE_INITIATOR;
        }
        else if (0 == strcmp("responder", pcValue)) {
            pConfig->eRole = NATIVE_APP_ROLE_RESPONDER;
        }
        else {
            bAccepted = false;
        }
    }
    else if (0 == strcmp("local_ip", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acLocalAddress,
                                     sizeof(pConfig->acLocalAddress), pcValue);
    }
    else if (0 == strcmp("remote_ip", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acRemoteAddress,
                                     sizeof(pConfig->acRemoteAddress), pcValue);
    }
    else if (0 == strcmp("local_id", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acLocalId,
                                     sizeof(pConfig->acLocalId), pcValue);
    }
    else if (0 == strcmp("remote_id", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acRemoteId,
                                     sizeof(pConfig->acRemoteId), pcValue);
    }
    else if (0 == strcmp("psk_file", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acPskFile,
                                     sizeof(pConfig->acPskFile), pcValue);
    }
    else if (0 == strcmp("output_root", pcKey)) {
        bAccepted = ('\0' != pcValue[0]) &&
            CopyNativeAppText(pConfig->acOutputRoot,
                              sizeof(pConfig->acOutputRoot), pcValue);
    }
    else if (0 == strcmp("vici_uri", pcKey)) {
        const char *pcPath = pcValue;

        if ('\0' == pcValue[0]) {
            pcPath = "/run/charon.vici";
        }
        else if (0 == strncmp("unix://", pcValue, 7U)) {
            pcPath = pcValue + 7U;
        }
        else if ('/' == pcValue[0]) {
            /* The value is already an absolute Unix socket path. */
        }
        else {
            bAccepted = false;
        }
        if (bAccepted) {
            bAccepted = CopyNativeAppText(pConfig->acViciSocket,
                                         sizeof(pConfig->acViciSocket), pcPath);
        }
        else {
            /* Preserve the invalid URI result. */
        }
    }
    else if (0 == strcmp("connection_name", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acConnectionName,
                                     sizeof(pConfig->acConnectionName), pcValue);
    }
    else if (0 == strcmp("child_name", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acChildName,
                                     sizeof(pConfig->acChildName), pcValue);
    }
    else if (0 == strcmp("credential_id", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acCredentialId,
                                     sizeof(pConfig->acCredentialId), pcValue);
    }
    else if (0 == strcmp("peer_server_ip", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acPeerServerAddress,
                                     sizeof(pConfig->acPeerServerAddress),
                                     pcValue);
    }
    else if (0 == strcmp("ike_proposals", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acIkeProposals,
                                     sizeof(pConfig->acIkeProposals), pcValue);
    }
    else if (0 == strcmp("esp_proposals", pcKey)) {
        bAccepted = CopyNativeAppText(pConfig->acEspProposals,
                                     sizeof(pConfig->acEspProposals), pcValue);
    }
    else if (0 == strcmp("ipsec_mode", pcKey)) {
        if (0 == strcmp("tunnel", pcValue)) {
            pConfig->eMode = IPSEC_MODE_TUNNEL;
        }
        else if (0 == strcmp("transport", pcValue)) {
            pConfig->eMode = IPSEC_MODE_TRANSPORT;
        }
        else {
            bAccepted = false;
        }
    }
    else if (0 == strcmp("childless_ike", pcKey)) {
        bAccepted = ParseNativeAppBoolean(pcValue, &pConfig->bChildlessIke);
    }
    else if (0 == strcmp("terminate_on_exit", pcKey)) {
        bAccepted = ParseNativeAppBoolean(pcValue,
                                         &pConfig->bTerminateOnExit);
    }
    else if ((0 == strcmp("command_timeout_sec", pcKey)) ||
             (0 == strcmp("timeout_sec", pcKey))) {
        uint32_t uiSeconds;

        bAccepted = ParseNativeAppUint32(pcValue, &uiSeconds) &&
                    (uiSeconds <= (UINT32_MAX / 1000U));
        if (bAccepted) {
            pConfig->uiTimeoutMs = uiSeconds * 1000U;
        }
        else {
            /* Preserve the invalid numeric result. */
        }
    }
    else if (0 == strcmp("peer_port", pcKey)) {
        bAccepted = ParseNativeAppUint32(pcValue, &pConfig->uiPeerPort) &&
                    (0U < pConfig->uiPeerPort) &&
                    (UINT16_MAX >= pConfig->uiPeerPort);
    }
    else if (IsNativeAppIgnoredV15Key(pcKey)) {
        /* Accepted for direct reuse of v15 configuration files. */
    }
    else {
        bAccepted = false;
    }
    return bAccepted ? IPSEC_OK : IPSEC_ERR_INVALID_ARGUMENT;
}

static bool IsNativeAppAddressValid(const char *pcAddress)
{
    uint8_t aucBuffer[sizeof(struct in6_addr)];

    return (1 == inet_pton(AF_INET, pcAddress, aucBuffer)) ||
           (1 == inet_pton(AF_INET6, pcAddress, aucBuffer));
}

IpsecError_t ValidateNativeAppConfig(
    const NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength)
{
    const char *pcInvalid = NULL;

    if (!IsNativeAppAddressValid(pConfig->acLocalAddress)) {
        pcInvalid = "local_ip";
    }
    else if (!IsNativeAppAddressValid(pConfig->acRemoteAddress)) {
        pcInvalid = "remote_ip";
    }
    else if ('\0' == pConfig->acLocalId[0]) {
        pcInvalid = "local_id";
    }
    else if ('\0' == pConfig->acRemoteId[0]) {
        pcInvalid = "remote_id";
    }
    else if ('\0' == pConfig->acPskFile[0]) {
        pcInvalid = "psk_file";
    }
    else if ('\0' == pConfig->acConnectionName[0]) {
        pcInvalid = "connection_name";
    }
    else if ('\0' == pConfig->acChildName[0]) {
        pcInvalid = "child_name";
    }
    else if ('\0' == pConfig->acIkeProposals[0]) {
        pcInvalid = "ike_proposals";
    }
    else if ('\0' == pConfig->acEspProposals[0]) {
        pcInvalid = "esp_proposals";
    }
    else if (0U == pConfig->uiTimeoutMs) {
        pcInvalid = "command_timeout_sec";
    }
    else {
        /* All required product settings are valid. */
    }

    if (NULL != pcInvalid) {
        SetNativeAppError(pcError, uiErrorLength,
                          "missing or invalid setting: %s", pcInvalid);
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        return IPSEC_OK;
    }
}

void InitializeNativeAppConfig(NativeAppConfig_t *pConfig)
{
    if (NULL != pConfig) {
        (void)memset(pConfig, 0, sizeof(*pConfig));
        pConfig->eRole = NATIVE_APP_ROLE_INITIATOR;
        pConfig->eMode = IPSEC_MODE_TUNNEL;
        pConfig->uiTimeoutMs = 30000U;
        pConfig->uiPeerPort = NATIVE_APP_PEER_DEFAULT_PORT;
        (void)CopyNativeAppText(pConfig->acOutputRoot,
                               sizeof(pConfig->acOutputRoot), "./results");
        (void)CopyNativeAppText(pConfig->acViciSocket,
                               sizeof(pConfig->acViciSocket),
                               "/run/charon.vici");
    }
    else {
        /* Nothing to initialize. */
    }
}

typedef IpsecError_t (*NativeAppConfigSetter_t)(
    NativeAppConfig_t *pConfig,
    const char *pcKey,
    const char *pcValue);

static bool IsNativeAppApplicationKey(const char *pcKey)
{
    static const char *pacKeys[] = {
        "role", "local_ip", "local_id", "psk_file", "output_root",
        "vici_uri", "childless_ike", "terminate_on_exit",
        "command_timeout_sec", "timeout_sec", "peer_server_ip",
        "peer_port"
    };
    uint32_t uiIndex;

    for (uiIndex = 0U;
         uiIndex < (uint32_t)(sizeof(pacKeys) / sizeof(pacKeys[0]));
         uiIndex++) {
        if (0 == strcmp(pacKeys[uiIndex], pcKey)) {
            return true;
        }
        else {
            /* Check the next application setting. */
        }
    }
    return false;
}

static IpsecError_t SetNativeAppApplicationSetting(
    NativeAppConfig_t *pConfig,
    const char *pcKey,
    const char *pcValue)
{
    if (!IsNativeAppApplicationKey(pcKey)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        return SetNativeAppConfigSetting(pConfig, pcKey, pcValue);
    }
}

static IpsecError_t SetNativeAppManagementSetting(
    NativeAppConfig_t *pConfig,
    const char *pcKey,
    const char *pcValue)
{
    if ((0 != strcmp("ike_proposals", pcKey)) &&
        (0 != strcmp("esp_proposals", pcKey)) &&
        (0 != strcmp("ipsec_mode", pcKey))) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        return SetNativeAppConfigSetting(pConfig, pcKey, pcValue);
    }
}

static IpsecError_t LoadNativeAppSettingsFile(
    const char *pcPath,
    NativeAppConfig_t *pConfig,
    NativeAppConfigSetter_t pSetter,
    char *pcError,
    uint32_t uiErrorLength)
{
    FILE *pFile;
    char acLine[NATIVE_APP_LINE_LENGTH];
    IpsecError_t eError = IPSEC_OK;

    pFile = fopen(pcPath, "r");
    if (NULL == pFile) {
        SetNativeAppError(pcError, uiErrorLength,
                          "cannot open configuration: %s", pcPath);
        return IPSEC_ERR_FILE_OPEN;
    }
    else {
        /* Parse the opened settings file. */
    }

    while ((IPSEC_OK == eError) &&
           (NULL != fgets(acLine, sizeof(acLine), pFile))) {
        char *pcKey;
        char *pcValue;
        char *pcSeparator;
        size_t zLength = strlen(acLine);

        if ((0U < zLength) && ('\n' != acLine[zLength - 1U]) &&
            (0 == feof(pFile))) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
            SetNativeAppError(pcError, uiErrorLength,
                              "configuration line is too long: %s", pcPath);
            break;
        }
        else {
            /* The complete line is in the bounded buffer. */
        }
        pcKey = TrimNativeAppText(acLine);
        if (('#' == pcKey[0]) || (';' == pcKey[0]) ||
            ('\0' == pcKey[0])) {
            continue;
        }
        else {
            /* Parse a key/value setting. */
        }
        pcSeparator = strchr(pcKey, '=');
        if (NULL == pcSeparator) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
            SetNativeAppError(pcError, uiErrorLength,
                              "setting has no '=' near: %s", pcKey);
            break;
        }
        else {
            *pcSeparator = '\0';
        }
        pcValue = TrimNativeAppText(pcSeparator + 1U);
        pcKey = TrimNativeAppText(pcKey);
        eError = pSetter(pConfig, pcKey, pcValue);
        if (IPSEC_OK != eError) {
            SetNativeAppError(pcError, uiErrorLength,
                              "unknown or invalid setting: %s", pcKey);
        }
        else {
            /* Continue parsing. */
        }
    }
    if ((IPSEC_OK == eError) && (0 != ferror(pFile))) {
        eError = IPSEC_ERR_FILE_READ;
        SetNativeAppError(pcError, uiErrorLength,
                          "cannot read configuration: %s", pcPath);
    }
    else {
        /* Preserve the parser result. */
    }
    (void)fclose(pFile);
    return eError;
}

IpsecError_t ValidateNativeAppBaseConfig(
    const NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength)
{
    const char *pcInvalid = NULL;

    if (NULL == pConfig) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (!IsNativeAppAddressValid(pConfig->acLocalAddress)) {
        pcInvalid = "local_ip";
    }
    else if ((NATIVE_APP_ROLE_INITIATOR == pConfig->eRole) &&
             ('\0' == pConfig->acLocalId[0])) {
        pcInvalid = "local_id";
    }
    else if ('\0' == pConfig->acPskFile[0]) {
        pcInvalid = "psk_file";
    }
    else if (!IsNativeAppAddressValid(pConfig->acPeerServerAddress)) {
        pcInvalid = "peer_server_ip";
    }
    else if ((0U == pConfig->uiPeerPort) ||
             (UINT16_MAX < pConfig->uiPeerPort)) {
        pcInvalid = "peer_port";
    }
    else if ('\0' == pConfig->acIkeProposals[0]) {
        pcInvalid = "ike_proposals";
    }
    else if ('\0' == pConfig->acEspProposals[0]) {
        pcInvalid = "esp_proposals";
    }
    else if (!((IPSEC_MODE_TUNNEL == pConfig->eMode) ||
               (IPSEC_MODE_TRANSPORT == pConfig->eMode))) {
        pcInvalid = "ipsec_mode";
    }
    else if (0U == pConfig->uiTimeoutMs) {
        pcInvalid = "command_timeout_sec";
    }
    else {
        /* The application and management settings are complete. */
    }

    if (NULL != pcInvalid) {
        SetNativeAppError(pcError, uiErrorLength,
                          "missing or invalid setting: %s", pcInvalid);
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        return IPSEC_OK;
    }
}

IpsecError_t LoadNativeAppConfigFiles(
    const char *pcApplicationPath,
    const char *pcManagementPath,
    NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength)
{
    IpsecError_t eError;

    if ((NULL == pcApplicationPath) || (NULL == pcManagementPath) ||
        (NULL == pConfig)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        InitializeNativeAppConfig(pConfig);
    }
    eError = LoadNativeAppSettingsFile(
        pcApplicationPath, pConfig, SetNativeAppApplicationSetting,
        pcError, uiErrorLength);
    if ((IPSEC_OK == eError) &&
        (NATIVE_APP_ROLE_INITIATOR == pConfig->eRole) &&
        ('\0' == pConfig->acPeerServerAddress[0])) {
        if (!CopyNativeAppText(pConfig->acPeerServerAddress,
                               sizeof(pConfig->acPeerServerAddress),
                               pConfig->acLocalAddress)) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            /* The initiator listens on its configured local address. */
        }
    }
    if (IPSEC_OK == eError) {
        pConfig->acIkeProposals[0] = '\0';
        pConfig->acEspProposals[0] = '\0';
        pConfig->eMode = (IpsecMode_t)-1;
        eError = LoadNativeAppSettingsFile(
            pcManagementPath, pConfig, SetNativeAppManagementSetting,
            pcError, uiErrorLength);
    }
    else {
        /* Preserve the application configuration error. */
    }
    if (IPSEC_OK == eError) {
        eError = ValidateNativeAppBaseConfig(pConfig, pcError,
                                             uiErrorLength);
    }
    else {
        /* Preserve the management configuration error. */
    }
    return eError;
}

IpsecError_t LoadNativeAppConfig(
    const char *pcPath,
    NativeAppConfig_t *pConfig,
    char *pcError,
    uint32_t uiErrorLength)
{
    FILE *pFile;
    char acLine[NATIVE_APP_LINE_LENGTH];
    uint32_t uiLine = 0U;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pcPath) || (NULL == pConfig)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        InitializeNativeAppConfig(pConfig);
    }
    pFile = fopen(pcPath, "r");
    if (NULL == pFile) {
        SetNativeAppError(pcError, uiErrorLength,
                          "cannot open configuration: %s", pcPath);
        return IPSEC_ERR_FILE_OPEN;
    }
    else {
        /* Parse the opened configuration. */
    }

    while ((IPSEC_OK == eError) && (NULL != fgets(acLine, sizeof(acLine), pFile))) {
        char *pcKey;
        char *pcValue;
        char *pcSeparator;
        size_t ulLength;

        uiLine++;
        ulLength = strlen(acLine);
        if ((0U < ulLength) && ('\n' != acLine[ulLength - 1U]) &&
            (0 == feof(pFile))) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
            SetNativeAppError(pcError, uiErrorLength,
                              "configuration line is too long: %s", pcPath);
            break;
        }
        else {
            /* The complete line is in the bounded buffer. */
        }
        pcKey = TrimNativeAppText(acLine);
        if (('#' == pcKey[0]) || (';' == pcKey[0]) || ('\0' == pcKey[0])) {
            continue;
        }
        else {
            /* Parse a key/value setting. */
        }
        pcSeparator = strchr(pcKey, '=');
        if (NULL == pcSeparator) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
            SetNativeAppError(pcError, uiErrorLength,
                              "setting has no '=' near: %s", pcKey);
            break;
        }
        else {
            *pcSeparator = '\0';
        }
        pcValue = TrimNativeAppText(pcSeparator + 1U);
        pcKey = TrimNativeAppText(pcKey);
        eError = SetNativeAppConfigSetting(pConfig, pcKey, pcValue);
        if (IPSEC_OK != eError) {
            SetNativeAppError(pcError, uiErrorLength,
                              "unknown or invalid setting: %s", pcKey);
        }
        else {
            /* Continue parsing. */
        }
    }
    if ((IPSEC_OK == eError) && (0 != ferror(pFile))) {
        eError = IPSEC_ERR_FILE_READ;
        SetNativeAppError(pcError, uiErrorLength,
                          "cannot read configuration: %s", pcPath);
    }
    else {
        /* Preserve the parser result. */
    }
    (void)fclose(pFile);
    if ((IPSEC_OK == eError) &&
        (NATIVE_APP_ROLE_INITIATOR == pConfig->eRole) &&
        ('\0' == pConfig->acPeerServerAddress[0])) {
        if (!CopyNativeAppText(pConfig->acPeerServerAddress,
                               sizeof(pConfig->acPeerServerAddress),
                               pConfig->acLocalAddress)) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            /* The initiator listens on its configured local address. */
        }
    }
    else {
        /* Preserve the parsed peer server address or parser error. */
    }
    if (IPSEC_OK == eError) {
        eError = ValidateNativeAppConfig(pConfig, pcError, uiErrorLength);
    }
    else {
        /* Preserve the first parser error. */
    }
    (void)uiLine;
    return eError;
}

static IpsecError_t SplitNativeAppProposals(
    const char *pcText,
    char aacItems[NATIVE_APP_PROPOSAL_COUNT][IPSEC_PROPOSAL_LENGTH],
    const char **pacItems,
    uint32_t *puiCount)
{
    const char *pcStart = pcText;
    uint32_t uiCount = 0U;

    while ('\0' != *pcStart) {
        const char *pcEnd = strchr(pcStart, ',');
        size_t ulLength;

        if (NULL == pcEnd) {
            pcEnd = pcStart + strlen(pcStart);
        }
        else {
            /* The current item ends at the comma. */
        }
        while ((pcEnd > pcStart) &&
               (0 != isspace((unsigned char)pcEnd[-1]))) {
            pcEnd--;
        }
        while (0 != isspace((unsigned char)*pcStart)) {
            pcStart++;
        }
        ulLength = (size_t)(pcEnd - pcStart);
        if ((0U == ulLength) || (uiCount >= NATIVE_APP_PROPOSAL_COUNT) ||
            (ulLength >= IPSEC_PROPOSAL_LENGTH)) {
            return IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            (void)memcpy(aacItems[uiCount], pcStart, ulLength);
            aacItems[uiCount][ulLength] = '\0';
            pacItems[uiCount] = aacItems[uiCount];
            uiCount++;
        }
        pcStart = strchr(pcStart, ',');
        if (NULL != pcStart) {
            pcStart++;
        }
        else {
            break;
        }
    }
    *puiCount = uiCount;
    return (0U < uiCount) ? IPSEC_OK : IPSEC_ERR_INVALID_ARGUMENT;
}

static bool HasNativeAppProposalToken(
    const NativeAppRuntimeConfig_t *pRuntime,
    const char *pcToken)
{
    uint32_t uiIndex;
    bool bFound = false;

    for (uiIndex = 0U;
         (uiIndex < pRuntime->Connection.EspProposals.uiCount) && !bFound;
         uiIndex++) {
        const char *pcProposal = pRuntime->pacEspProposals[uiIndex];
        const char *pcPosition = pcProposal;
        size_t ulTokenLength = strlen(pcToken);

        while (NULL != (pcPosition = strstr(pcPosition, pcToken))) {
            bool bLeft = (pcPosition == pcProposal) || ('-' == pcPosition[-1]);
            char cRight = pcPosition[ulTokenLength];
            bool bRight = ('\0' == cRight) || ('-' == cRight);

            if (bLeft && bRight) {
                bFound = true;
                break;
            }
            else {
                pcPosition += ulTokenLength;
            }
        }
    }
    return bFound;
}

static bool HasNativeAppPfsToken(const NativeAppRuntimeConfig_t *pRuntime)
{
    uint32_t uiIndex;
    bool bFound = false;

    for (uiIndex = 0U;
         (uiIndex < pRuntime->Connection.EspProposals.uiCount) && !bFound;
         uiIndex++) {
        const char *pcCursor = pRuntime->pacEspProposals[uiIndex];

        while ('\0' != *pcCursor) {
            const char *pcEnd = strchr(pcCursor, '-');
            size_t ulLength = (NULL == pcEnd) ? strlen(pcCursor) :
                (size_t)(pcEnd - pcCursor);

            bFound = ((4U <= ulLength) &&
                      (0 == memcmp("modp", pcCursor, 4U))) ||
                     ((3U <= ulLength) &&
                      (0 == memcmp("ecp", pcCursor, 3U))) ||
                     ((5U <= ulLength) &&
                      (0 == memcmp("curve", pcCursor, 5U)));
            if (NULL == pcEnd) {
                break;
            }
            else {
                pcCursor = pcEnd + 1U;
            }
        }
    }
    return bFound;
}

IpsecError_t BuildNativeAppRuntimeConfig(
    const NativeAppConfig_t *pConfig,
    NativeAppRuntimeConfig_t *pRuntime,
    char *pcError,
    uint32_t uiErrorLength)
{
    uint8_t aucAddress[sizeof(struct in6_addr)];
    uint32_t uiIkeCount = 0U;
    uint32_t uiEspCount = 0U;
    IpsecError_t eError;

    if ((NULL == pConfig) || (NULL == pRuntime)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        (void)memset(pRuntime, 0, sizeof(*pRuntime));
    }
    if (1 == inet_pton(AF_INET, pConfig->acLocalAddress, aucAddress)) {
        (void)snprintf(pRuntime->acLocalTrafficSelector,
                       sizeof(pRuntime->acLocalTrafficSelector), "%s/32",
                       pConfig->acLocalAddress);
    }
    else {
        (void)snprintf(pRuntime->acLocalTrafficSelector,
                       sizeof(pRuntime->acLocalTrafficSelector), "%s/128",
                       pConfig->acLocalAddress);
    }
    if (1 == inet_pton(AF_INET, pConfig->acRemoteAddress, aucAddress)) {
        (void)snprintf(pRuntime->acRemoteTrafficSelector,
                       sizeof(pRuntime->acRemoteTrafficSelector), "%s/32",
                       pConfig->acRemoteAddress);
    }
    else {
        (void)snprintf(pRuntime->acRemoteTrafficSelector,
                       sizeof(pRuntime->acRemoteTrafficSelector), "%s/128",
                       pConfig->acRemoteAddress);
    }

    eError = SplitNativeAppProposals(pConfig->acIkeProposals,
                                     pRuntime->aacIkeProposals,
                                     pRuntime->pacIkeProposals, &uiIkeCount);
    if (IPSEC_OK == eError) {
        eError = SplitNativeAppProposals(pConfig->acEspProposals,
                                         pRuntime->aacEspProposals,
                                         pRuntime->pacEspProposals,
                                         &uiEspCount);
    }
    else {
        /* Report the IKE proposal error below. */
    }
    if (IPSEC_OK != eError) {
        SetNativeAppError(pcError, uiErrorLength,
                          "invalid proposal list: %s", pConfig->acConnectionName);
        return eError;
    }
    else {
        /* Build the public library view. */
    }

    pRuntime->pacLocalAddresses[0] = pConfig->acLocalAddress;
    pRuntime->pacRemoteAddresses[0] = pConfig->acRemoteAddress;
    pRuntime->pacLocalTrafficSelectors[0] =
        pRuntime->acLocalTrafficSelector;
    pRuntime->pacRemoteTrafficSelectors[0] =
        pRuntime->acRemoteTrafficSelector;
    pRuntime->Connection.uiStructSize = sizeof(IpsecConnectionConfig_t);
    pRuntime->Connection.pcName = pConfig->acConnectionName;
    pRuntime->Connection.pcChildName = pConfig->acChildName;
    pRuntime->Connection.LocalAddresses.ppcItems =
        pRuntime->pacLocalAddresses;
    pRuntime->Connection.LocalAddresses.uiCount = 1U;
    pRuntime->Connection.RemoteAddresses.ppcItems =
        pRuntime->pacRemoteAddresses;
    pRuntime->Connection.RemoteAddresses.uiCount = 1U;
    pRuntime->Connection.eLocalAuth = IPSEC_AUTH_PSK;
    pRuntime->Connection.eRemoteAuth = IPSEC_AUTH_PSK;
    pRuntime->Connection.pcLocalId = pConfig->acLocalId;
    pRuntime->Connection.pcRemoteId = pConfig->acRemoteId;
    pRuntime->Connection.IkeProposals.ppcItems = pRuntime->pacIkeProposals;
    pRuntime->Connection.IkeProposals.uiCount = uiIkeCount;
    pRuntime->Connection.EspProposals.ppcItems = pRuntime->pacEspProposals;
    pRuntime->Connection.EspProposals.uiCount = uiEspCount;
    pRuntime->Connection.LocalTrafficSelectors.ppcItems =
        pRuntime->pacLocalTrafficSelectors;
    pRuntime->Connection.LocalTrafficSelectors.uiCount = 1U;
    pRuntime->Connection.RemoteTrafficSelectors.ppcItems =
        pRuntime->pacRemoteTrafficSelectors;
    pRuntime->Connection.RemoteTrafficSelectors.uiCount = 1U;
    pRuntime->Connection.eMode = pConfig->eMode;
    pRuntime->Connection.eEsn = IPSEC_ESN_AUTO;
    if (HasNativeAppProposalToken(pRuntime, "noesn")) {
        pRuntime->Connection.eEsn = IPSEC_ESN_DISABLED;
    }
    else if (HasNativeAppProposalToken(pRuntime, "esn")) {
        pRuntime->Connection.eEsn = IPSEC_ESN_ENABLED;
    }
    else {
        /* Preserve strongSwan's automatic ESN behavior used by v15. */
    }
    pRuntime->Connection.bEnablePfs = HasNativeAppPfsToken(pRuntime);
    pRuntime->Connection.bEnableMobike = false;
    pRuntime->Connection.bEnableFragmentation = true;
    pRuntime->Connection.bForceChildlessIke = pConfig->bChildlessIke;
    return IPSEC_OK;
}

IpsecError_t ReadNativeAppSecret(
    const NativeAppConfig_t *pConfig,
    NativeAppSecret_t *pSecret)
{
    FILE *pFile;
    size_t ulRead;

    if ((NULL == pConfig) || (NULL == pSecret)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        (void)memset(pSecret, 0, sizeof(*pSecret));
    }
    pFile = fopen(pConfig->acPskFile, "rb");
    if (NULL == pFile) {
        return IPSEC_ERR_FILE_OPEN;
    }
    else {
        /* Read the bounded secret. */
    }
    pSecret->pucData = malloc(NATIVE_APP_PSK_MAX_LENGTH + 1U);
    if (NULL == pSecret->pucData) {
        (void)fclose(pFile);
        return IPSEC_ERR_NO_MEMORY;
    }
    else {
        /* The extra byte detects oversized input. */
    }
    ulRead = fread(pSecret->pucData, 1U, NATIVE_APP_PSK_MAX_LENGTH + 1U,
                   pFile);
    if (0 != ferror(pFile)) {
        (void)fclose(pFile);
        DestroyNativeAppSecret(pSecret);
        return IPSEC_ERR_FILE_READ;
    }
    else {
        (void)fclose(pFile);
    }
    if ((0U == ulRead) || (ulRead > NATIVE_APP_PSK_MAX_LENGTH)) {
        DestroyNativeAppSecret(pSecret);
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        while ((0U < ulRead) &&
               (('\n' == pSecret->pucData[ulRead - 1U]) ||
                ('\r' == pSecret->pucData[ulRead - 1U]))) {
            ulRead--;
        }
    }
    if (0U == ulRead) {
        DestroyNativeAppSecret(pSecret);
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        pSecret->uiLength = (uint32_t)ulRead;
        return IPSEC_OK;
    }
}

void DestroyNativeAppSecret(NativeAppSecret_t *pSecret)
{
    if ((NULL != pSecret) && (NULL != pSecret->pucData)) {
        volatile uint8_t *pucData = pSecret->pucData;
        uint32_t uiIndex;

        for (uiIndex = 0U; uiIndex < (NATIVE_APP_PSK_MAX_LENGTH + 1U);
             uiIndex++) {
            pucData[uiIndex] = 0U;
        }
        free(pSecret->pucData);
        pSecret->pucData = NULL;
        pSecret->uiLength = 0U;
    }
    else {
        /* No secret is owned. */
    }
}
