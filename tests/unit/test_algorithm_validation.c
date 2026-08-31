#include "app_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

static bool SetTestText(
    char *pcDestination,
    size_t zDestinationLength,
    const char *pcSource)
{
    int32_t iLength = snprintf(pcDestination, zDestinationLength, "%s",
                               pcSource);

    return (0 <= iLength) && ((size_t)iLength < zDestinationLength);
}

static bool VerifyExpectedProposal(
    const char *pcIke,
    const char *pcEsp,
    const char *pcExpectedIke,
    const char *pcExpectedEsp)
{
    NativeAppAlgorithmCase_t Case = {0};
    char acIke[IPSEC_PROPOSAL_LENGTH];
    char acEsp[IPSEC_PROPOSAL_LENGTH];
    IpsecError_t eError;

    if (!SetTestText(Case.acIkeProposal, sizeof(Case.acIkeProposal), pcIke) ||
        !SetTestText(Case.acEspProposal, sizeof(Case.acEspProposal), pcEsp)) {
        return false;
    }
    else {
        /* Both input proposals fit in the public testcase structure. */
    }
    eError = BuildNativeAppExpectedProposals(
        &Case, acIke, sizeof(acIke), acEsp, sizeof(acEsp));
    return (IPSEC_OK == eError) &&
        (0 == strcmp(pcExpectedIke, acIke)) &&
        (0 == strcmp(pcExpectedEsp, acEsp));
}

static bool VerifyAllAlgorithmCases(
    NativeAppAlgorithmMode_t eMode,
    const NativeAppConfig_t *pConfig)
{
    NativeAppAlgorithmCase_t Case;
    char acIke[IPSEC_PROPOSAL_LENGTH];
    char acEsp[IPSEC_PROPOSAL_LENGTH];
    uint32_t uiCount = GetNativeAppAlgorithmCaseCount(eMode);
    uint32_t uiIndex;

    for (uiIndex = 0U; uiIndex < uiCount; uiIndex++) {
        if ((IPSEC_OK != GetNativeAppAlgorithmCase(
                eMode, uiIndex, pConfig, NULL, NULL, &Case)) ||
            (IPSEC_OK != BuildNativeAppExpectedProposals(
                &Case, acIke, sizeof(acIke), acEsp, sizeof(acEsp))) ||
            ('\0' == acIke[0]) || ('\0' == acEsp[0])) {
            (void)fprintf(stderr, "proposal conversion failed at %" PRIu32
                          "\n", uiIndex + 1U);
            return false;
        }
        else {
            /* Continue through the complete generated matrix. */
        }
    }
    return true;
}

static bool VerifyCapabilityTextBoundaries(void)
{
    char acSource[IPSEC_OS_NAME_LENGTH + 3U];
    char acGuarded[IPSEC_OS_NAME_LENGTH + 2U];
    char *pcDestination = acGuarded + 1U;
    const size_t zCapacity = IPSEC_OS_NAME_LENGTH;
    char acSingle[1] = {'X'};
    char acOverlap[] = "abcd";
    size_t zLength;
    bool bCopied;

    /* Include a 64-character uname value that cannot fit in a 64-byte field.
     * Canary bytes verify that both successful and rejected copies stay bounded.
     */
    for (zLength = 0U; zLength < sizeof(acSource); zLength++) {
        (void)memset(acSource, 'K', sizeof(acSource));
        acSource[zLength] = '\0';
        (void)memset(acGuarded, '#', sizeof(acGuarded));
        bCopied = CopyNativeAppCapabilityText(pcDestination, zCapacity, acSource);
        if ((bCopied != (zLength < zCapacity)) ||
            ('#' != acGuarded[0]) || ('#' != acGuarded[zCapacity + 1U])) {
            return false;
        }
        if (bCopied) {
            if (0 != memcmp(pcDestination, acSource, zLength + 1U)) {
                return false;
            }
        }
        else if ('\0' != pcDestination[0]) {
            return false;
        }
    }

    /* An unterminated source is rejected after at most zCapacity bytes. */
    (void)memset(acSource, 'K', sizeof(acSource));
    if (CopyNativeAppCapabilityText(pcDestination, zCapacity, acSource) ||
        ('\0' != pcDestination[0]) ||
        CopyNativeAppCapabilityText(NULL, zCapacity, "text") ||
        CopyNativeAppCapabilityText(acSingle, 0U, "text") ||
        ('X' != acSingle[0]) ||
        CopyNativeAppCapabilityText(acSingle, sizeof(acSingle), "X") ||
        ('\0' != acSingle[0]) ||
        !CopyNativeAppCapabilityText(acSingle, sizeof(acSingle), "") ||
        ('\0' != acSingle[0])) {
        return false;
    }
    pcDestination[0] = 'X';
    if (CopyNativeAppCapabilityText(pcDestination, zCapacity, NULL) ||
        ('\0' != pcDestination[0])) {
        return false;
    }
    return CopyNativeAppCapabilityText(acOverlap, sizeof(acOverlap), acOverlap + 1U) &&
        (0 == strcmp("bcd", acOverlap));
}

static bool VerifyCapabilityPolicy(void)
{
    NativeAppAlgorithmCapabilities_t Capabilities = {0};
    NativeAppAlgorithmCase_t Case = {0};
    char acReason[NATIVE_APP_ALGORITHM_REASON_LENGTH];
    char acSummary[NATIVE_APP_ALGORITHM_CAPABILITY_LENGTH];

    Capabilities.eDatapathType = IPSEC_DATAPATH_KERNEL_LIBIPSEC;
    Capabilities.bDatapathReady = true;
    Capabilities.bEsnSupported = false;
    Capabilities.bModp8192Supported = true;
    Case.bExpectEsn = true;
    if (IPSEC_ERR_NOT_SUPPORTED != CheckNativeAppAlgorithmCaseSupport(
            &Capabilities, &Case, acReason, sizeof(acReason))) {
        return false;
    }
    Case.bExpectEsn = false;
    Capabilities.bModp8192Supported = false;
    if (!SetTestText(Case.acExpectedChildKe,
                     sizeof(Case.acExpectedChildKe), "MODP_8192")) {
        return false;
    }
    else {
        /* The fixed test value fits the capability structure. */
    }
    if (IPSEC_ERR_NOT_SUPPORTED != CheckNativeAppAlgorithmCaseSupport(
            &Capabilities, &Case, acReason, sizeof(acReason))) {
        return false;
    }
    Capabilities.bModp8192Supported = true;
    if (IPSEC_OK != CheckNativeAppAlgorithmCaseSupport(
            &Capabilities, &Case, acReason, sizeof(acReason))) {
        return false;
    }
    if (!SetTestText(Capabilities.acModp8192Plugin,
                     sizeof(Capabilities.acModp8192Plugin), "openssl") ||
        !SetTestText(Capabilities.acKdfPrfPlusPlugin,
                     sizeof(Capabilities.acKdfPrfPlusPlugin), "openssl")) {
        return false;
    }
    Capabilities.bOpenSslVersionKnown = true;
    Capabilities.ullOpenSslVersion = 0x30000050ULL;
    if (IPSEC_OK != FormatNativeAppAlgorithmCapabilitySummary(
            &Capabilities, "none", acSummary, sizeof(acSummary))) {
        return false;
    }
    return (NULL != strstr(acSummary, "datapath=kernel-libipsec")) &&
        (NULL != strstr(acSummary, "openssl_version=0x30000050")) &&
        (NULL != strstr(acSummary, "reason=none"));
}

int main(void)
{
    NativeAppConfig_t Config = {0};
    bool bPassed;

    bPassed = SetTestText(
        Config.acIkeProposals, sizeof(Config.acIkeProposals),
        "aes256-sha256-prfsha256-modp2048");
    bPassed = bPassed && SetTestText(
        Config.acEspProposals, sizeof(Config.acEspProposals),
        "aes256-sha256-noesn");
    bPassed = bPassed && VerifyExpectedProposal(
        "aes256-sha256-prfsha256-modp2048", "aes256-sha256-noesn",
        "AES_CBC-256/HMAC_SHA2_256_128/PRF_HMAC_SHA2_256/MODP_2048",
        "AES_CBC-256/HMAC_SHA2_256_128");
    bPassed = bPassed && VerifyExpectedProposal(
        "aes256-aescmac-prfaescmac-modp2048",
        "aes256gcm16-curve25519-noesn",
        "AES_CBC-256/AES_CMAC_96/PRF_AES128_CMAC/MODP_2048",
        "AES_GCM_16-256/CURVE_25519");
    bPassed = bPassed && VerifyExpectedProposal(
        "chacha20poly1305-prfsha512-curve448",
        "chacha20poly1305-esn",
        "CHACHA20_POLY1305/PRF_HMAC_SHA2_512/CURVE_448",
        "CHACHA20_POLY1305");
    bPassed = bPassed && VerifyAllAlgorithmCases(
        NATIVE_APP_ALGORITHM_BASELINE, &Config);
    bPassed = bPassed && VerifyAllAlgorithmCases(
        NATIVE_APP_ALGORITHM_EXHAUSTIVE_IKE, &Config);
    bPassed = bPassed && VerifyAllAlgorithmCases(
        NATIVE_APP_ALGORITHM_EXHAUSTIVE_ESP, &Config);
    bPassed = bPassed && VerifyCapabilityPolicy();
    bPassed = bPassed && VerifyCapabilityTextBoundaries();
    return bPassed ? 0 : 1;
}
