#include "vici_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IPSEC_VICI_MAX_LIST_ITEMS 64U
#define IPSEC_VICI_MAX_INPUT_LENGTH 1024U

typedef struct ConnectionCollector {
    IpsecConnectionList_t *pList;
    IpsecConnectionInfo_t *pCurrent;
    char aacSections[VICI_MAX_SECTION_DEPTH][IPSEC_NAME_LENGTH];
    char acListName[IPSEC_NAME_LENGTH];
} ConnectionCollector_t;

static bool MatchConnectionText(
    const uint8_t *pucText,
    uint32_t uiTextLength,
    const char *pcExpected)
{
    size_t zExpectedLength;

    if ((NULL == pucText) || (NULL == pcExpected)) {
        return false;
    }
    else {
        zExpectedLength = strlen(pcExpected);
        return (zExpectedLength == uiTextLength) &&
               (0 == memcmp(pucText, pcExpected, uiTextLength));
    }
}

static IpsecError_t ValidateConnectionName(const char *pcName)
{
    size_t zLength;
    const unsigned char *pucCharacter;
    IpsecError_t eError = IPSEC_OK;

    if (NULL == pcName) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        zLength = strnlen(pcName, IPSEC_NAME_LENGTH);
        if ((0U == zLength) || (IPSEC_NAME_LENGTH <= zLength) ||
            (UINT8_MAX < zLength)) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            pucCharacter = (const unsigned char *)pcName;
            while ('\0' != *pucCharacter) {
                if ((*pucCharacter < 0x21U) || (*pucCharacter > 0x7eU) ||
                    ('{' == *pucCharacter) || ('}' == *pucCharacter)) {
                    eError = IPSEC_ERR_INVALID_ARGUMENT;
                    break;
                }
                else {
                    pucCharacter++;
                }
            }
        }
    }

    return eError;
}

static IpsecError_t ValidateConnectionList(
    const IpsecStringListView_t *pList,
    bool bRequired)
{
    uint32_t uiIndex;
    size_t zLength;
    IpsecError_t eError = IPSEC_OK;

    if ((NULL == pList) ||
        (IPSEC_VICI_MAX_LIST_ITEMS < pList->uiCount) ||
        (bRequired && (0U == pList->uiCount)) ||
        ((0U < pList->uiCount) && (NULL == pList->ppcItems))) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        for (uiIndex = 0U; uiIndex < pList->uiCount; uiIndex++) {
            if (NULL == pList->ppcItems[uiIndex]) {
                eError = IPSEC_ERR_INVALID_ARGUMENT;
                break;
            }
            else {
                zLength = strnlen(pList->ppcItems[uiIndex],
                                  IPSEC_VICI_MAX_INPUT_LENGTH + 1U);
                if ((0U == zLength) || (IPSEC_VICI_MAX_INPUT_LENGTH < zLength) ||
                    (UINT16_MAX < zLength)) {
                    eError = IPSEC_ERR_INVALID_ARGUMENT;
                    break;
                }
                else {
                    /* Item is representable by VICI. */
                }
            }
        }
    }

    return eError;
}

static bool ContainsConnectionProposalToken(
    const IpsecStringListView_t *pList,
    const char *pcToken)
{
    uint32_t uiIndex;
    const char *pcCursor;
    const char *pcEnd;
    size_t zTokenLength = strlen(pcToken);
    size_t zPartLength;
    bool bFound = false;

    for (uiIndex = 0U; (uiIndex < pList->uiCount) && !bFound; uiIndex++) {
        pcCursor = pList->ppcItems[uiIndex];
        while ('\0' != *pcCursor) {
            pcEnd = strchr(pcCursor, '-');
            if (NULL == pcEnd) {
                zPartLength = strlen(pcCursor);
            }
            else {
                zPartLength = (size_t)(pcEnd - pcCursor);
            }
            if ((zTokenLength == zPartLength) &&
                (0 == memcmp(pcCursor, pcToken, zTokenLength))) {
                bFound = true;
                break;
            }
            else if (NULL == pcEnd) {
                break;
            }
            else {
                pcCursor = pcEnd + 1;
            }
        }
    }

    return bFound;
}

static bool ContainsConnectionPfsToken(const IpsecStringListView_t *pList)
{
    uint32_t uiIndex;
    const char *pcProposal;
    bool bFound = false;

    for (uiIndex = 0U; (uiIndex < pList->uiCount) && !bFound; uiIndex++) {
        pcProposal = pList->ppcItems[uiIndex];
        bFound = (NULL != strstr(pcProposal, "-modp")) ||
                 (NULL != strstr(pcProposal, "-ecp")) ||
                 (NULL != strstr(pcProposal, "-curve"));
    }

    return bFound;
}

static IpsecError_t ValidateConnectionConfig(
    const IpsecConnectionConfig_t *pConfig)
{
    size_t zLocalIdLength;
    size_t zRemoteIdLength;
    IpsecError_t eError;

    if (NULL == pConfig) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        zLocalIdLength = (NULL == pConfig->pcLocalId) ? 0U :
            strnlen(pConfig->pcLocalId, IPSEC_ID_LENGTH);
        zRemoteIdLength = (NULL == pConfig->pcRemoteId) ? 0U :
            strnlen(pConfig->pcRemoteId, IPSEC_ID_LENGTH);
        if ((sizeof(IpsecConnectionConfig_t) != pConfig->uiStructSize) ||
        (NULL == pConfig->pcLocalId) || (NULL == pConfig->pcRemoteId) ||
        (0U == zLocalIdLength) || (0U == zRemoteIdLength) ||
        (IPSEC_ID_LENGTH <= zLocalIdLength) ||
        (IPSEC_ID_LENGTH <= zRemoteIdLength) ||
        !((IPSEC_MODE_TUNNEL == pConfig->eMode) ||
          (IPSEC_MODE_TRANSPORT == pConfig->eMode)) ||
        !((IPSEC_ESN_AUTO == pConfig->eEsn) ||
          (IPSEC_ESN_DISABLED == pConfig->eEsn) ||
          (IPSEC_ESN_ENABLED == pConfig->eEsn))) {
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            eError = ValidateConnectionName(pConfig->pcName);
        }
        if ((IPSEC_OK == eError) &&
            ((IPSEC_AUTH_PSK != pConfig->eLocalAuth) ||
             (IPSEC_AUTH_PSK != pConfig->eRemoteAuth))) {
            eError = IPSEC_ERR_NOT_SUPPORTED;
        }
        else {
            /* PSK is supported or a prior validation failed. */
        }
    }
    if (IPSEC_OK == eError) {
        eError = ValidateConnectionName(pConfig->pcChildName);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ValidateConnectionList(&pConfig->LocalAddresses, true);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ValidateConnectionList(&pConfig->RemoteAddresses, true);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ValidateConnectionList(&pConfig->IkeProposals, true);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ValidateConnectionList(&pConfig->EspProposals, true);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ValidateConnectionList(&pConfig->LocalTrafficSelectors, true);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ValidateConnectionList(&pConfig->RemoteTrafficSelectors, true);
    }
    else {
        /* Preserve validation error. */
    }

    if ((IPSEC_OK == eError) && (IPSEC_ESN_ENABLED == pConfig->eEsn) &&
        !ContainsConnectionProposalToken(&pConfig->EspProposals, "esn")) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if ((IPSEC_OK == eError) && (IPSEC_ESN_DISABLED == pConfig->eEsn) &&
             !ContainsConnectionProposalToken(&pConfig->EspProposals, "noesn")) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if ((IPSEC_OK == eError) && pConfig->bEnablePfs &&
             !ContainsConnectionPfsToken(&pConfig->EspProposals)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        /* Proposal intent is consistent. */
    }

    return eError;
}

static bool MatchConnectionAuthSection(
    const char *pcSection,
    const char *pcExpected)
{
    size_t zExpectedLength = strlen(pcExpected);

    return (0 == strncmp(pcSection, pcExpected, zExpectedLength)) &&
           (('\0' == pcSection[zExpectedLength]) ||
            ('-' == pcSection[zExpectedLength]));
}

static IpsecError_t AddConnectionList(
    ViciBuffer_t *pMessage,
    const char *pcName,
    const IpsecStringListView_t *pList)
{
    uint32_t uiIndex;
    IpsecError_t eError;

    eError = AddViciListStart(pMessage, pcName);
    for (uiIndex = 0U; (uiIndex < pList->uiCount) && (IPSEC_OK == eError);
         uiIndex++) {
        eError = AddViciListItemString(pMessage, pList->ppcItems[uiIndex]);
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListEnd(pMessage);
    }
    else {
        /* Preserve list error. */
    }
    return eError;
}

static IpsecError_t AddConnectionDuration(
    ViciBuffer_t *pMessage,
    const char *pcName,
    uint64_t ullMilliseconds)
{
    char acDuration[32];
    uint64_t ullSeconds;
    int32_t iLength;
    IpsecError_t eError = IPSEC_OK;

    if (0U < ullMilliseconds) {
        if ((UINT64_MAX - 999U) < ullMilliseconds) {
            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        else {
            ullSeconds = (ullMilliseconds + 999U) / 1000U;
            iLength = (int32_t)snprintf(acDuration, sizeof(acDuration),
                                        "%" PRIu64 "s", ullSeconds);
            if ((0 > iLength) || ((size_t)iLength >= sizeof(acDuration))) {
                eError = IPSEC_ERR_BUFFER_TOO_SMALL;
            }
            else {
                eError = AddViciKeyValueString(pMessage, pcName, acDuration);
            }
        }
    }
    else {
        /* Zero keeps the daemon default. */
    }

    return eError;
}

static IpsecError_t BuildConnectionMessage(
    const IpsecConnectionConfig_t *pConfig,
    ViciBuffer_t *pMessage)
{
    const char *pcMode = (IPSEC_MODE_TUNNEL == pConfig->eMode) ?
                         "tunnel" : "transport";
    IpsecError_t eError;

    eError = InitializeViciBuffer(pMessage, 2048U, false);
    if (IPSEC_OK == eError) {
        eError = AddViciSectionStart(pMessage, pConfig->pcName);
    }
    else {
        /* Preserve allocation error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "version", "2");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionList(pMessage, "local_addrs",
                                   &pConfig->LocalAddresses);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionList(pMessage, "remote_addrs",
                                   &pConfig->RemoteAddresses);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionList(pMessage, "proposals",
                                   &pConfig->IkeProposals);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "mobike",
                                       pConfig->bEnableMobike ? "yes" : "no");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "fragmentation",
                                       pConfig->bEnableFragmentation ?
                                       "yes" : "no");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "encap",
                                       pConfig->bForceUdpEncapsulation ?
                                       "yes" : "no");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "childless",
                                       pConfig->bForceChildlessIke ?
                                       "force" : "allow");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionDuration(pMessage, "dpd_delay",
                                       pConfig->uiDpdDelayMs);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionDuration(pMessage, "dpd_timeout",
                                       pConfig->uiDpdTimeoutMs);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionDuration(pMessage, "rekey_time",
                                       pConfig->ullIkeRekeyTimeMs);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionDuration(pMessage, "reauth_time",
                                       pConfig->ullIkeLifetimeMs);
    }
    else {
        /* Preserve message error. */
    }

    if (IPSEC_OK == eError) {
        eError = AddViciSectionStart(pMessage, "local");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "auth", "psk");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "id", pConfig->pcLocalId);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionEnd(pMessage);
    }
    else {
        /* Preserve message error. */
    }

    if (IPSEC_OK == eError) {
        eError = AddViciSectionStart(pMessage, "remote");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "auth", "psk");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "id", pConfig->pcRemoteId);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionEnd(pMessage);
    }
    else {
        /* Preserve message error. */
    }

    if (IPSEC_OK == eError) {
        eError = AddViciSectionStart(pMessage, "children");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionStart(pMessage, pConfig->pcChildName);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionList(pMessage, "local_ts",
                                   &pConfig->LocalTrafficSelectors);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionList(pMessage, "remote_ts",
                                   &pConfig->RemoteTrafficSelectors);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "mode", pcMode);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionList(pMessage, "esp_proposals",
                                   &pConfig->EspProposals);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "start_action", "none");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "close_action", "none");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "dpd_action", "clear");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionDuration(pMessage, "rekey_time",
                                       pConfig->ullChildRekeyTimeMs);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddConnectionDuration(pMessage, "life_time",
                                       pConfig->ullChildLifetimeMs);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionEnd(pMessage);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionEnd(pMessage);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionEnd(pMessage);
    }
    else {
        /* Preserve message error. */
    }

    if (IPSEC_OK != eError) {
        DestroyViciBuffer(pMessage);
    }
    else {
        /* Message complete. */
    }
    return eError;
}

IpsecError_t AddIpsecConnection(
    IpsecContext_t *pContext,
    const IpsecConnectionConfig_t *pConfig)
{
    ViciBuffer_t Message = {0};
    ViciCommandResult_t Result = {0};
    IpsecError_t eError;

    if (NULL == pContext) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ValidateConnectionConfig(pConfig);
    }
    if (IPSEC_OK == eError) {
        eError = BuildConnectionMessage(pConfig, &Message);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ExecuteViciCommand(pContext, "load-conn", &Message, NULL,
                                    NULL, NULL, NULL, &Result);
    }
    else {
        /* Preserve message error. */
    }
    DestroyViciBuffer(&Message);
    return eError;
}

IpsecError_t RemoveIpsecConnection(
    IpsecContext_t *pContext,
    const char *pcName)
{
    ViciBuffer_t Message = {0};
    ViciCommandResult_t Result = {0};
    IpsecError_t eError;

    if (NULL == pContext) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ValidateConnectionName(pcName);
    }
    if (IPSEC_OK == eError) {
        eError = InitializeViciBuffer(&Message, 64U, false);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(&Message, "name", pcName);
    }
    else {
        /* Preserve allocation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ExecuteViciCommand(pContext, "unload-conn", &Message, NULL,
                                    NULL, NULL, NULL, &Result);
    }
    else {
        /* Preserve message error. */
    }
    DestroyViciBuffer(&Message);
    return eError;
}

static IpsecError_t AppendConnectionInfo(ConnectionCollector_t *pCollector)
{
    IpsecConnectionInfo_t *pNewItems;
    uint32_t uiNewCount;
    size_t zAllocationSize;
    IpsecError_t eError;

    if (UINT32_MAX == pCollector->pList->uiCount) {
        eError = IPSEC_ERR_NO_MEMORY;
    }
    else {
        uiNewCount = pCollector->pList->uiCount + 1U;
        if (!CalculateIpsecArraySize(uiNewCount, sizeof(*pNewItems),
                                    &zAllocationSize)) {
            eError = IPSEC_ERR_NO_MEMORY;
        }
        else {
            pNewItems = (IpsecConnectionInfo_t *)realloc(
                pCollector->pList->pItems, zAllocationSize);
            if (NULL == pNewItems) {
                eError = IPSEC_ERR_NO_MEMORY;
            }
            else {
                pCollector->pList->pItems = pNewItems;
                pCollector->pCurrent = &pNewItems[uiNewCount - 1U];
                memset(pCollector->pCurrent, 0, sizeof(*pCollector->pCurrent));
                pCollector->pList->uiCount = uiNewCount;
                eError = IPSEC_OK;
            }
        }
    }

    return eError;
}

static IpsecError_t ParseConnectionSeconds(
    const ViciElement_t *pElement,
    uint64_t *pullMilliseconds)
{
    uint64_t ullSeconds;
    IpsecError_t eError;

    eError = ParseIpsecUint64(pElement->pucValue, pElement->usValueLength,
                              &ullSeconds, 10U);
    if ((IPSEC_OK == eError) && (UINT64_MAX / 1000U < ullSeconds)) {
        eError = IPSEC_ERR_VICI_PROTOCOL;
    }
    else if (IPSEC_OK == eError) {
        *pullMilliseconds = ullSeconds * 1000U;
    }
    else {
        /* Preserve parser error. */
    }
    return eError;
}

static IpsecError_t CollectConnectionElement(
    const ViciElement_t *pElement,
    void *pvUserData)
{
    ConnectionCollector_t *pCollector = (ConnectionCollector_t *)pvUserData;
    uint32_t uiIndex;
    IpsecError_t eError = IPSEC_OK;

    if (VICI_ELEMENT_SECTION_START == pElement->eType) {
        uiIndex = pElement->uiDepth - 1U;
        eError = CopyIpsecString(pCollector->aacSections[uiIndex],
                                 sizeof(pCollector->aacSections[uiIndex]),
                                 pElement->pucName, pElement->ucNameLength);
        if ((IPSEC_OK == eError) && (1U == pElement->uiDepth)) {
            eError = AppendConnectionInfo(pCollector);
            if (IPSEC_OK == eError) {
                eError = CopyIpsecString(pCollector->pCurrent->acName,
                                         sizeof(pCollector->pCurrent->acName),
                                         pElement->pucName,
                                         pElement->ucNameLength);
            }
            else {
                /* Preserve allocation error. */
            }
        }
        else if ((IPSEC_OK == eError) && (3U == pElement->uiDepth) &&
                 (0 == strcmp(pCollector->aacSections[1], "children")) &&
                 (NULL != pCollector->pCurrent)) {
            eError = AppendIpsecText(pCollector->pCurrent->acChildNames,
                                     sizeof(pCollector->pCurrent->acChildNames),
                                     pElement->pucName,
                                     pElement->ucNameLength, ",");
        }
        else {
            /* No connection field on this section. */
        }
    }
    else if (VICI_ELEMENT_SECTION_END == pElement->eType) {
        if ((0U < pElement->uiDepth) &&
            (pElement->uiDepth <= VICI_MAX_SECTION_DEPTH)) {
            pCollector->aacSections[pElement->uiDepth - 1U][0] = '\0';
        }
        else {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
    }
    else if (VICI_ELEMENT_LIST_START == pElement->eType) {
        eError = CopyIpsecString(pCollector->acListName,
                                 sizeof(pCollector->acListName),
                                 pElement->pucName,
                                 pElement->ucNameLength);
    }
    else if (VICI_ELEMENT_LIST_END == pElement->eType) {
        pCollector->acListName[0] = '\0';
    }
    else if ((VICI_ELEMENT_LIST_ITEM == pElement->eType) &&
             (NULL != pCollector->pCurrent) &&
             (1U == pElement->uiDepth)) {
        if (0 == strcmp(pCollector->acListName, "local_addrs")) {
            eError = AppendIpsecText(pCollector->pCurrent->acLocalAddresses,
                                     sizeof(pCollector->pCurrent->acLocalAddresses),
                                     pElement->pucValue,
                                     pElement->usValueLength, ",");
        }
        else if (0 == strcmp(pCollector->acListName, "remote_addrs")) {
            eError = AppendIpsecText(pCollector->pCurrent->acRemoteAddresses,
                                     sizeof(pCollector->pCurrent->acRemoteAddresses),
                                     pElement->pucValue,
                                     pElement->usValueLength, ",");
        }
        else {
            /* Ignore other lists. */
        }
    }
    else if ((VICI_ELEMENT_KEY_VALUE == pElement->eType) &&
             (NULL != pCollector->pCurrent)) {
        if ((1U == pElement->uiDepth) &&
            MatchConnectionText(pElement->pucName, pElement->ucNameLength,
                                "rekey_time")) {
            eError = ParseConnectionSeconds(pElement,
                                             &pCollector->pCurrent->ullRekeyTimeMs);
        }
        else if ((1U == pElement->uiDepth) &&
                 MatchConnectionText(pElement->pucName, pElement->ucNameLength,
                                     "reauth_time")) {
            eError = ParseConnectionSeconds(pElement,
                                             &pCollector->pCurrent->ullReauthTimeMs);
        }
        else if ((2U == pElement->uiDepth) &&
                 MatchConnectionText(pElement->pucName, pElement->ucNameLength,
                                     "id") &&
                 MatchConnectionAuthSection(pCollector->aacSections[1],
                                            "local")) {
            eError = CopyIpsecString(pCollector->pCurrent->acLocalId,
                                     sizeof(pCollector->pCurrent->acLocalId),
                                     pElement->pucValue,
                                     pElement->usValueLength);
        }
        else if ((2U == pElement->uiDepth) &&
                 MatchConnectionText(pElement->pucName, pElement->ucNameLength,
                                     "id") &&
                 MatchConnectionAuthSection(pCollector->aacSections[1],
                                            "remote")) {
            eError = CopyIpsecString(pCollector->pCurrent->acRemoteId,
                                     sizeof(pCollector->pCurrent->acRemoteId),
                                     pElement->pucValue,
                                     pElement->usValueLength);
        }
        else {
            /* Ignore optional fields. */
        }
    }
    else {
        /* Element does not map to the public connection view. */
    }

    return eError;
}

static IpsecError_t CollectConnectionEvent(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    void *pvUserData)
{
    return ParseViciMessage(pucMessage, uiMessageLength,
                            CollectConnectionElement, pvUserData);
}

IpsecError_t GetIpsecConnections(
    IpsecContext_t *pContext,
    IpsecConnectionList_t *pList)
{
    ViciBuffer_t Request = {0};
    ViciCommandResult_t Result = {0};
    ConnectionCollector_t Collector;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pList)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pList, 0, sizeof(*pList));
        memset(&Collector, 0, sizeof(Collector));
        Collector.pList = pList;
        eError = InitializeViciBuffer(&Request, 1U, false);
    }
    if (IPSEC_OK == eError) {
        eError = ExecuteViciCommand(pContext, "list-conns", &Request,
                                    "list-conn", CollectConnectionEvent,
                                    NULL, &Collector, &Result);
    }
    else {
        /* Preserve argument or allocation error. */
    }
    DestroyViciBuffer(&Request);
    if (IPSEC_OK != eError) {
        FreeIpsecConnectionList(pList);
    }
    else {
        /* Return collected connections. */
    }
    return eError;
}

void FreeIpsecConnectionList(IpsecConnectionList_t *pList)
{
    if (NULL != pList) {
        free(pList->pItems);
        memset(pList, 0, sizeof(*pList));
    }
    else {
        /* NULL free is safe. */
    }
}
