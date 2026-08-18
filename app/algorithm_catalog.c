#include "app_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

typedef struct NativeAppBaselineCase {
    const char *pcId;
    const char *pcIkeProposal;
    const char *pcEspProposal;
    bool bSeparateChildExchange;
} NativeAppBaselineCase_t;

typedef struct NativeAppKeAlgorithm {
    const char *pcKeyword;
    const char *pcObservedName;
} NativeAppKeAlgorithm_t;

static const NativeAppBaselineCase_t gaNativeAppBaselineCases[] = {
    {"BASE-001", "aes256-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-CBC-128", "aes128-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-CBC-192", "aes192-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-CBC-256", "aes256-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-INTEG-256", "aes256-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-INTEG-384", "aes256-sha384-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-INTEG-512", "aes256-sha512-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-PRF-256", "aes256-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-PRF-384", "aes256-sha256-prfsha384-modp2048", "aes256-sha256", false},
    {"IKE-PRF-512", "aes256-sha256-prfsha512-modp2048", "aes256-sha256", false},
    {"IKE-DH-MODP2048", "aes256-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-DH-MODP3072", "aes256-sha256-prfsha256-modp3072", "aes256-sha256", false},
    {"IKE-DH-MODP4096", "aes256-sha256-prfsha256-modp4096", "aes256-sha256", false},
    {"IKE-DH-MODP6144", "aes256-sha256-prfsha256-modp6144", "aes256-sha256", false},
    {"IKE-DH-MODP8192", "aes256-sha256-prfsha256-modp8192", "aes256-sha256", false},
    {"IKE-DH-ECP256", "aes256-sha256-prfsha256-ecp256", "aes256-sha256", false},
    {"IKE-DH-ECP384", "aes256-sha256-prfsha384-ecp384", "aes256-sha256", false},
    {"IKE-DH-ECP521", "aes256-sha512-prfsha512-ecp521", "aes256-sha256", false},
    {"IKE-DH-CURVE25519", "aes256-sha256-prfsha256-curve25519", "aes256-sha256", false},
    {"IKE-DH-CURVE448", "aes256-sha512-prfsha512-curve448", "aes256-sha256", false},
    {"IKE-GCM-128-16", "aes128gcm16-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-GCM-192-16", "aes192gcm16-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-GCM-256-8", "aes256gcm8-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-GCM-256-12", "aes256gcm12-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-GCM-256-16", "aes256gcm16-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-CHACHA20", "chacha20poly1305-prfsha256-curve25519", "aes256-sha256", false},
    {"ESP-CBC-128", "aes256-sha256-prfsha256-modp2048", "aes128-sha256", false},
    {"ESP-CBC-192", "aes256-sha256-prfsha256-modp2048", "aes192-sha256", false},
    {"ESP-CBC-256", "aes256-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"ESP-INTEG-384", "aes256-sha256-prfsha256-modp2048", "aes256-sha384", false},
    {"ESP-INTEG-512", "aes256-sha256-prfsha256-modp2048", "aes256-sha512", false},
    {"ESP-GCM-128-16", "aes256-sha256-prfsha256-modp2048", "aes128gcm16", false},
    {"ESP-GCM-192-16", "aes256-sha256-prfsha256-modp2048", "aes192gcm16", false},
    {"ESP-GCM-256-8", "aes256-sha256-prfsha256-modp2048", "aes256gcm8", false},
    {"ESP-GCM-256-12", "aes256-sha256-prfsha256-modp2048", "aes256gcm12", false},
    {"ESP-GCM-256-16", "aes256-sha256-prfsha256-modp2048", "aes256gcm16", false},
    {"ESP-CHACHA20", "aes256-sha256-prfsha256-modp2048", "chacha20poly1305", false},
    {"ESP-PFS-MODP2048", "aes256-sha256-prfsha256-modp2048", "aes256-sha256-modp2048", true},
    {"ESP-PFS-ECP256", "aes256-sha256-prfsha256-modp2048", "aes256-sha256-ecp256", true},
    {"ESP-PFS-ECP384", "aes256-sha256-prfsha256-modp2048", "aes256-sha256-ecp384", true},
    {"ESP-PFS-CURVE25519", "aes256-sha256-prfsha256-modp2048", "aes256-sha256-curve25519", true},
    {"ESP-NOESN", "aes256-sha256-prfsha256-modp2048", "aes256gcm16-noesn", false},
    {"ESP-ESN", "aes256-sha256-prfsha256-modp2048", "aes256gcm16-esn", false},
    {"IKE-CAMELLIA-128", "camellia128-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-CAMELLIA-192", "camellia192-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"IKE-CAMELLIA-256", "camellia256-sha256-prfsha256-modp2048", "aes256-sha256", false},
    {"ESP-CAMELLIA-128", "aes256-sha256-prfsha256-modp2048", "camellia128-sha256", false},
    {"ESP-CAMELLIA-192", "aes256-sha256-prfsha256-modp2048", "camellia192-sha256", false},
    {"ESP-CAMELLIA-256", "aes256-sha256-prfsha256-modp2048", "camellia256-sha256", false},
    {"IKE-AES-XCBC", "aes256-aesxcbc-prfaesxcbc-modp2048", "aes256-sha256", false},
    {"IKE-AES-CMAC", "aes256-aescmac-prfaescmac-modp2048", "aes256-sha256", false},
    {"IKE-DH-ECP256BP", "aes256-sha256-prfsha256-ecp256bp", "aes256-sha256", false},
    {"IKE-DH-ECP384BP", "aes256-sha384-prfsha384-ecp384bp", "aes256-sha256", false},
    {"IKE-DH-ECP512BP", "aes256-sha512-prfsha512-ecp512bp", "aes256-sha256", false}
};

static const char *const gapcNativeAppClassicEncryption[] = {
    "3des", "cast128", "blowfish128", "blowfish192", "blowfish256",
    "null", "aes128", "aes192", "aes256", "camellia128",
    "camellia192", "camellia256"
};

static const char *const gapcNativeAppIkeIntegrity[] = {
    "md5", "md5_128", "sha1", "sha1_160", "aesxcbc", "aescmac",
    "sha256", "sha384", "sha512"
};

static const char *const gapcNativeAppEspIntegrity[] = {
    "md5", "md5_128", "sha1", "sha1_160", "aesxcbc", "sha256",
    "sha384", "sha512"
};

static const char *const gapcNativeAppIkePrf[] = {
    "prfmd5", "prfsha1", "prfaesxcbc", "prfaescmac", "prfsha256",
    "prfsha384", "prfsha512"
};

static const char *const gapcNativeAppAead[] = {
    "aes128gcm8", "aes192gcm8", "aes256gcm8", "aes128gcm12",
    "aes192gcm12", "aes256gcm12", "aes128gcm16", "aes192gcm16",
    "aes256gcm16", "chacha20poly1305"
};

static const NativeAppKeAlgorithm_t gaNativeAppKeAlgorithms[] = {
    {"modp768", "MODP_768"}, {"modp1024", "MODP_1024"},
    {"modp1536", "MODP_1536"}, {"modp2048", "MODP_2048"},
    {"modp3072", "MODP_3072"}, {"modp4096", "MODP_4096"},
    {"modp6144", "MODP_6144"}, {"modp8192", "MODP_8192"},
    {"modp1024s160", "MODP_1024_160"},
    {"modp2048s224", "MODP_2048_224"},
    {"modp2048s256", "MODP_2048_256"},
    {"ecp192", "ECP_192"}, {"ecp224", "ECP_224"},
    {"ecp256", "ECP_256"}, {"ecp384", "ECP_384"},
    {"ecp521", "ECP_521"}, {"ecp224bp", "ECP_224_BP"},
    {"ecp256bp", "ECP_256_BP"}, {"ecp384bp", "ECP_384_BP"},
    {"ecp512bp", "ECP_512_BP"}, {"curve25519", "CURVE_25519"},
    {"curve448", "CURVE_448"}
};

static const char *const gapcNativeAppEsnModes[] = {"noesn", "esn"};

#define NATIVE_APP_ARRAY_COUNT(a) \
    ((uint32_t)(sizeof(a) / sizeof((a)[0])))

static bool CopyNativeAppAlgorithmText(
    char *pcDestination,
    uint32_t uiDestinationLength,
    const char *pcSource)
{
    int32_t iLength;

    if ((NULL == pcDestination) || (0U == uiDestinationLength) ||
        (NULL == pcSource)) {
        return false;
    }
    else {
        iLength = snprintf(pcDestination, uiDestinationLength, "%s", pcSource);
        return (0 <= iLength) && ((uint32_t)iLength < uiDestinationLength);
    }
}

static bool HasNativeAppAlgorithmToken(
    const char *pcProposal,
    const char *pcToken)
{
    const char *pcCursor = pcProposal;
    size_t zTokenLength = strlen(pcToken);

    while (NULL != (pcCursor = strstr(pcCursor, pcToken))) {
        bool bLeftBoundary = (pcCursor == pcProposal) || ('-' == pcCursor[-1]);
        char cRight = pcCursor[zTokenLength];
        bool bRightBoundary = ('\0' == cRight) || ('-' == cRight);

        if (bLeftBoundary && bRightBoundary) {
            return true;
        }
        else {
            pcCursor += zTokenLength;
        }
    }
    return false;
}

const char *GetNativeAppAlgorithmErrorText(IpsecError_t eError)
{
    const char *pcText;

    if (IPSEC_OK == eError) {
        pcText = "none";
    }
    else {
        pcText = GetIpsecErrorString(eError);
    }
    return pcText;
}

static IpsecError_t SetNativeAppExpectedChildKe(
    NativeAppAlgorithmCase_t *pCase)
{
    uint32_t uiIndex;

    pCase->acExpectedChildKe[0] = '\0';
    pCase->bSeparateChildExchange = false;
    for (uiIndex = 0U;
         uiIndex < NATIVE_APP_ARRAY_COUNT(gaNativeAppKeAlgorithms);
         uiIndex++) {
        if (HasNativeAppAlgorithmToken(
                pCase->acEspProposal,
                gaNativeAppKeAlgorithms[uiIndex].pcKeyword)) {
            pCase->bSeparateChildExchange = true;
            if (!CopyNativeAppAlgorithmText(
                    pCase->acExpectedChildKe,
                    sizeof(pCase->acExpectedChildKe),
                    gaNativeAppKeAlgorithms[uiIndex].pcObservedName)) {
                return IPSEC_ERR_BUFFER_TOO_SMALL;
            }
            else {
                break;
            }
        }
        else {
            /* Check the next key exchange method. */
        }
    }
    pCase->bExpectEsn = HasNativeAppAlgorithmToken(pCase->acEspProposal,
                                                   "esn");
    pCase->bExpectNoEsn = HasNativeAppAlgorithmToken(pCase->acEspProposal,
                                                     "noesn");
    return IPSEC_OK;
}

const char *GetNativeAppAlgorithmModeName(NativeAppAlgorithmMode_t eMode)
{
    const char *pcName;

    switch (eMode) {
    case NATIVE_APP_ALGORITHM_BASELINE:
        pcName = "baseline";
        break;
    case NATIVE_APP_ALGORITHM_EXHAUSTIVE_IKE:
        pcName = "exhaustive-ike";
        break;
    case NATIVE_APP_ALGORITHM_EXHAUSTIVE_ESP:
        pcName = "exhaustive-esp";
        break;
    case NATIVE_APP_ALGORITHM_CUSTOM:
        pcName = "custom";
        break;
    default:
        pcName = "unknown";
        break;
    }
    return pcName;
}

bool ParseNativeAppAlgorithmMode(
    const char *pcText,
    NativeAppAlgorithmMode_t *pMode)
{
    bool bParsed = true;

    if ((NULL == pcText) || (NULL == pMode)) {
        return false;
    }
    else if (0 == strcmp("baseline", pcText)) {
        *pMode = NATIVE_APP_ALGORITHM_BASELINE;
    }
    else if (0 == strcmp("exhaustive-ike", pcText)) {
        *pMode = NATIVE_APP_ALGORITHM_EXHAUSTIVE_IKE;
    }
    else if (0 == strcmp("exhaustive-esp", pcText)) {
        *pMode = NATIVE_APP_ALGORITHM_EXHAUSTIVE_ESP;
    }
    else if (0 == strcmp("custom", pcText)) {
        *pMode = NATIVE_APP_ALGORITHM_CUSTOM;
    }
    else {
        bParsed = false;
    }
    return bParsed;
}

uint32_t GetNativeAppAlgorithmCaseCount(NativeAppAlgorithmMode_t eMode)
{
    uint32_t uiCount;

    switch (eMode) {
    case NATIVE_APP_ALGORITHM_BASELINE:
        uiCount = NATIVE_APP_ARRAY_COUNT(gaNativeAppBaselineCases);
        break;
    case NATIVE_APP_ALGORITHM_EXHAUSTIVE_IKE:
        uiCount =
            (NATIVE_APP_ARRAY_COUNT(gapcNativeAppClassicEncryption) *
             NATIVE_APP_ARRAY_COUNT(gapcNativeAppIkeIntegrity) *
             NATIVE_APP_ARRAY_COUNT(gapcNativeAppIkePrf) *
             NATIVE_APP_ARRAY_COUNT(gaNativeAppKeAlgorithms)) +
            (NATIVE_APP_ARRAY_COUNT(gapcNativeAppAead) *
             NATIVE_APP_ARRAY_COUNT(gapcNativeAppIkePrf) *
             NATIVE_APP_ARRAY_COUNT(gaNativeAppKeAlgorithms));
        break;
    case NATIVE_APP_ALGORITHM_EXHAUSTIVE_ESP:
        uiCount =
            (NATIVE_APP_ARRAY_COUNT(gapcNativeAppClassicEncryption) *
             NATIVE_APP_ARRAY_COUNT(gapcNativeAppEspIntegrity) *
             (NATIVE_APP_ARRAY_COUNT(gaNativeAppKeAlgorithms) + 1U) *
             NATIVE_APP_ARRAY_COUNT(gapcNativeAppEsnModes)) +
            (NATIVE_APP_ARRAY_COUNT(gapcNativeAppAead) *
             (NATIVE_APP_ARRAY_COUNT(gaNativeAppKeAlgorithms) + 1U) *
             NATIVE_APP_ARRAY_COUNT(gapcNativeAppEsnModes));
        break;
    case NATIVE_APP_ALGORITHM_CUSTOM:
        uiCount = 1U;
        break;
    default:
        uiCount = 0U;
        break;
    }
    return uiCount;
}

static IpsecError_t GetNativeAppBaselineCase(
    uint32_t uiIndex,
    NativeAppAlgorithmCase_t *pCase)
{
    const NativeAppBaselineCase_t *pSource;

    if (NATIVE_APP_ARRAY_COUNT(gaNativeAppBaselineCases) <= uiIndex) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        pSource = &gaNativeAppBaselineCases[uiIndex];
    }
    if (!CopyNativeAppAlgorithmText(pCase->acId, sizeof(pCase->acId),
                                    pSource->pcId) ||
        !CopyNativeAppAlgorithmText(pCase->acIkeProposal,
                                    sizeof(pCase->acIkeProposal),
                                    pSource->pcIkeProposal) ||
        !CopyNativeAppAlgorithmText(pCase->acEspProposal,
                                    sizeof(pCase->acEspProposal),
                                    pSource->pcEspProposal)) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        pCase->bSeparateChildExchange = pSource->bSeparateChildExchange;
        return SetNativeAppExpectedChildKe(pCase);
    }
}

static IpsecError_t GetNativeAppExhaustiveIkeCase(
    uint32_t uiIndex,
    const NativeAppConfig_t *pBaseConfig,
    NativeAppAlgorithmCase_t *pCase)
{
    uint32_t uiKeCount = NATIVE_APP_ARRAY_COUNT(gaNativeAppKeAlgorithms);
    uint32_t uiPrfCount = NATIVE_APP_ARRAY_COUNT(gapcNativeAppIkePrf);
    uint32_t uiIntegrityCount =
        NATIVE_APP_ARRAY_COUNT(gapcNativeAppIkeIntegrity);
    uint32_t uiClassicCount =
        NATIVE_APP_ARRAY_COUNT(gapcNativeAppClassicEncryption) *
        uiIntegrityCount * uiPrfCount * uiKeCount;
    int32_t iLength;

    if (GetNativeAppAlgorithmCaseCount(
            NATIVE_APP_ALGORITHM_EXHAUSTIVE_IKE) <= uiIndex) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (uiIndex < uiClassicCount) {
        uint32_t uiValue = uiIndex;
        uint32_t uiKe = uiValue % uiKeCount;
        uint32_t uiPrf;
        uint32_t uiIntegrity;
        uint32_t uiEncryption;

        uiValue /= uiKeCount;
        uiPrf = uiValue % uiPrfCount;
        uiValue /= uiPrfCount;
        uiIntegrity = uiValue % uiIntegrityCount;
        uiValue /= uiIntegrityCount;
        uiEncryption = uiValue;
        iLength = snprintf(
            pCase->acIkeProposal, sizeof(pCase->acIkeProposal),
            "%s-%s-%s-%s", gapcNativeAppClassicEncryption[uiEncryption],
            gapcNativeAppIkeIntegrity[uiIntegrity],
            gapcNativeAppIkePrf[uiPrf],
            gaNativeAppKeAlgorithms[uiKe].pcKeyword);
    }
    else {
        uint32_t uiValue = uiIndex - uiClassicCount;
        uint32_t uiKe = uiValue % uiKeCount;
        uint32_t uiPrf;
        uint32_t uiAead;

        uiValue /= uiKeCount;
        uiPrf = uiValue % uiPrfCount;
        uiValue /= uiPrfCount;
        uiAead = uiValue;
        iLength = snprintf(
            pCase->acIkeProposal, sizeof(pCase->acIkeProposal),
            "%s-%s-%s", gapcNativeAppAead[uiAead],
            gapcNativeAppIkePrf[uiPrf],
            gaNativeAppKeAlgorithms[uiKe].pcKeyword);
    }
    if ((0 > iLength) ||
        ((uint32_t)iLength >= sizeof(pCase->acIkeProposal)) ||
        !CopyNativeAppAlgorithmText(pCase->acEspProposal,
                                    sizeof(pCase->acEspProposal),
                                    pBaseConfig->acEspProposals)) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        iLength = snprintf(pCase->acId, sizeof(pCase->acId),
                           "EXH-I-%05" PRIu32, uiIndex + 1U);
    }
    if ((0 > iLength) || ((uint32_t)iLength >= sizeof(pCase->acId))) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        return SetNativeAppExpectedChildKe(pCase);
    }
}

static IpsecError_t GetNativeAppExhaustiveEspCase(
    uint32_t uiIndex,
    const NativeAppConfig_t *pBaseConfig,
    NativeAppAlgorithmCase_t *pCase)
{
    uint32_t uiKeCount = NATIVE_APP_ARRAY_COUNT(gaNativeAppKeAlgorithms);
    uint32_t uiPfsCount = uiKeCount + 1U;
    uint32_t uiEsnCount = NATIVE_APP_ARRAY_COUNT(gapcNativeAppEsnModes);
    uint32_t uiIntegrityCount =
        NATIVE_APP_ARRAY_COUNT(gapcNativeAppEspIntegrity);
    uint32_t uiClassicCount =
        NATIVE_APP_ARRAY_COUNT(gapcNativeAppClassicEncryption) *
        uiIntegrityCount * uiPfsCount * uiEsnCount;
    uint32_t uiPfs;
    uint32_t uiEsn;
    int32_t iLength;

    if (GetNativeAppAlgorithmCaseCount(
            NATIVE_APP_ALGORITHM_EXHAUSTIVE_ESP) <= uiIndex) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (uiIndex < uiClassicCount) {
        uint32_t uiValue = uiIndex;
        uint32_t uiIntegrity;
        uint32_t uiEncryption;

        uiEsn = uiValue % uiEsnCount;
        uiValue /= uiEsnCount;
        uiPfs = uiValue % uiPfsCount;
        uiValue /= uiPfsCount;
        uiIntegrity = uiValue % uiIntegrityCount;
        uiValue /= uiIntegrityCount;
        uiEncryption = uiValue;
        if (0U == uiPfs) {
            iLength = snprintf(
                pCase->acEspProposal, sizeof(pCase->acEspProposal),
                "%s-%s-%s", gapcNativeAppClassicEncryption[uiEncryption],
                gapcNativeAppEspIntegrity[uiIntegrity],
                gapcNativeAppEsnModes[uiEsn]);
        }
        else {
            iLength = snprintf(
                pCase->acEspProposal, sizeof(pCase->acEspProposal),
                "%s-%s-%s-%s",
                gapcNativeAppClassicEncryption[uiEncryption],
                gapcNativeAppEspIntegrity[uiIntegrity],
                gaNativeAppKeAlgorithms[uiPfs - 1U].pcKeyword,
                gapcNativeAppEsnModes[uiEsn]);
        }
    }
    else {
        uint32_t uiValue = uiIndex - uiClassicCount;
        uint32_t uiAead;

        uiEsn = uiValue % uiEsnCount;
        uiValue /= uiEsnCount;
        uiPfs = uiValue % uiPfsCount;
        uiValue /= uiPfsCount;
        uiAead = uiValue;
        if (0U == uiPfs) {
            iLength = snprintf(
                pCase->acEspProposal, sizeof(pCase->acEspProposal),
                "%s-%s", gapcNativeAppAead[uiAead],
                gapcNativeAppEsnModes[uiEsn]);
        }
        else {
            iLength = snprintf(
                pCase->acEspProposal, sizeof(pCase->acEspProposal),
                "%s-%s-%s", gapcNativeAppAead[uiAead],
                gaNativeAppKeAlgorithms[uiPfs - 1U].pcKeyword,
                gapcNativeAppEsnModes[uiEsn]);
        }
    }
    if ((0 > iLength) ||
        ((uint32_t)iLength >= sizeof(pCase->acEspProposal)) ||
        !CopyNativeAppAlgorithmText(pCase->acIkeProposal,
                                    sizeof(pCase->acIkeProposal),
                                    pBaseConfig->acIkeProposals)) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        iLength = snprintf(pCase->acId, sizeof(pCase->acId),
                           "EXH-E-%04" PRIu32, uiIndex + 1U);
    }
    if ((0 > iLength) || ((uint32_t)iLength >= sizeof(pCase->acId))) {
        return IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        return SetNativeAppExpectedChildKe(pCase);
    }
}

IpsecError_t GetNativeAppAlgorithmCase(
    NativeAppAlgorithmMode_t eMode,
    uint32_t uiIndex,
    const NativeAppConfig_t *pBaseConfig,
    const char *pcCustomIke,
    const char *pcCustomEsp,
    NativeAppAlgorithmCase_t *pCase)
{
    IpsecError_t eError;

    if ((NULL == pBaseConfig) || (NULL == pCase) ||
        (GetNativeAppAlgorithmCaseCount(eMode) <= uiIndex)) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        (void)memset(pCase, 0, sizeof(*pCase));
        pCase->uiNumber = uiIndex + 1U;
    }

    switch (eMode) {
    case NATIVE_APP_ALGORITHM_BASELINE:
        eError = GetNativeAppBaselineCase(uiIndex, pCase);
        break;
    case NATIVE_APP_ALGORITHM_EXHAUSTIVE_IKE:
        eError = GetNativeAppExhaustiveIkeCase(uiIndex, pBaseConfig, pCase);
        break;
    case NATIVE_APP_ALGORITHM_EXHAUSTIVE_ESP:
        eError = GetNativeAppExhaustiveEspCase(uiIndex, pBaseConfig, pCase);
        break;
    case NATIVE_APP_ALGORITHM_CUSTOM:
        if ((NULL == pcCustomIke) || (NULL == pcCustomEsp) ||
            !CopyNativeAppAlgorithmText(pCase->acId, sizeof(pCase->acId),
                                        "CUSTOM-0001") ||
            !CopyNativeAppAlgorithmText(pCase->acIkeProposal,
                                        sizeof(pCase->acIkeProposal),
                                        pcCustomIke) ||
            !CopyNativeAppAlgorithmText(pCase->acEspProposal,
                                        sizeof(pCase->acEspProposal),
                                        pcCustomEsp)) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            eError = SetNativeAppExpectedChildKe(pCase);
        }
        break;
    default:
        eError = IPSEC_ERR_INVALID_ARGUMENT;
        break;
    }
    return eError;
}
