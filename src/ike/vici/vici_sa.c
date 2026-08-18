#include "vici_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define IPSEC_SA_POLL_INTERVAL_MS 250U

typedef struct SaCollector {
    IpsecIkeSaList_t *pIkeList;
    IpsecChildSaList_t *pChildList;
    IpsecIkeSaInfo_t *pCurrentIke;
    IpsecChildSaInfo_t *pCurrentChild;
    char acCurrentIkeName[IPSEC_NAME_LENGTH];
    char aacSections[VICI_MAX_SECTION_DEPTH][IPSEC_NAME_LENGTH];
    char acListName[IPSEC_NAME_LENGTH];
} SaCollector_t;

static bool MatchSaText(
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

static IpsecError_t ValidateSaName(const char *pcName)
{
    size_t zLength;
    IpsecError_t eError;

    if (NULL == pcName) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        zLength = strnlen(pcName, IPSEC_NAME_LENGTH);
        eError = ((0U == zLength) || (IPSEC_NAME_LENGTH <= zLength)) ?
                 IPSEC_ERR_INVALID_ARGUMENT : IPSEC_OK;
    }
    return eError;
}

static IpsecError_t AddSaControlTimeout(
    IpsecContext_t *pContext,
    ViciBuffer_t *pMessage,
    const IpsecControlOptions_t *pOptions)
{
    char acTimeout[32];
    uint32_t uiTimeoutMs;
    int32_t iLength;
    IpsecError_t eError;

    if (NULL == pOptions) {
        uiTimeoutMs = pContext->uiCommandTimeoutMs;
        iLength = (int32_t)snprintf(acTimeout, sizeof(acTimeout), "%u",
                                    uiTimeoutMs);
        eError = IPSEC_OK;
    }
    else if ((sizeof(IpsecControlOptions_t) != pOptions->uiStructSize) ||
             !((IPSEC_CONTROL_WAIT == pOptions->eMode) ||
               (IPSEC_CONTROL_IMMEDIATE == pOptions->eMode))) {
        iLength = -1;
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (IPSEC_CONTROL_IMMEDIATE == pOptions->eMode) {
        iLength = (int32_t)snprintf(acTimeout, sizeof(acTimeout), "-1");
        eError = IPSEC_OK;
    }
    else {
        uiTimeoutMs = (0U == pOptions->uiTimeoutMs) ?
                      pContext->uiCommandTimeoutMs : pOptions->uiTimeoutMs;
        if (pContext->uiCommandTimeoutMs < uiTimeoutMs) {
            iLength = -1;
            eError = IPSEC_ERR_INVALID_ARGUMENT;
        }
        else {
            iLength = (int32_t)snprintf(acTimeout, sizeof(acTimeout), "%u",
                                        uiTimeoutMs);
            eError = IPSEC_OK;
        }
    }

    if ((IPSEC_OK == eError) &&
        ((0 > iLength) || ((size_t)iLength >= sizeof(acTimeout)))) {
        eError = IPSEC_ERR_BUFFER_TOO_SMALL;
    }
    else {
        /* Preserve option validation. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "timeout", acTimeout);
    }
    else {
        /* Preserve timeout formatting error. */
    }
    return eError;
}

static IpsecError_t ExecuteSaControl(
    IpsecContext_t *pContext,
    const char *pcCommand,
    const char *pcSelector,
    const char *pcName,
    const IpsecControlOptions_t *pOptions,
    bool bAddTimeout,
    IpsecError_t eOperationError)
{
    ViciBuffer_t Message = {0};
    ViciCommandResult_t Result = {0};
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pcCommand) || (NULL == pcSelector)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ValidateSaName(pcName);
    }
    if (IPSEC_OK == eError) {
        eError = InitializeViciBuffer(&Message, 128U, false);
    }
    else {
        /* Preserve validation error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(&Message, pcSelector, pcName);
    }
    else {
        /* Preserve message error. */
    }
    if ((IPSEC_OK == eError) && bAddTimeout) {
        eError = AddSaControlTimeout(pContext, &Message, pOptions);
    }
    else {
        /* This command has no timeout field or already failed. */
    }
    if (IPSEC_OK == eError) {
        eError = ExecuteViciCommand(pContext, pcCommand, &Message, NULL,
                                    NULL, NULL, NULL, &Result);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_ERR_VICI_COMMAND == eError) {
        eError = eOperationError;
    }
    else {
        /* Preserve transport/protocol result. */
    }

    DestroyViciBuffer(&Message);
    return eError;
}

IpsecError_t InitiateIpsecIke(
    IpsecContext_t *pContext,
    const char *pcConnectionName,
    const IpsecControlOptions_t *pOptions)
{
    return ExecuteSaControl(pContext, "initiate", "ike", pcConnectionName,
                            pOptions, true, IPSEC_ERR_IKE_FAILED);
}

IpsecError_t TerminateIpsecIke(
    IpsecContext_t *pContext,
    const char *pcIkeName,
    const IpsecControlOptions_t *pOptions)
{
    return ExecuteSaControl(pContext, "terminate", "ike", pcIkeName,
                            pOptions, true, IPSEC_ERR_IKE_FAILED);
}

IpsecError_t RekeyIpsecIke(
    IpsecContext_t *pContext,
    const char *pcIkeName)
{
    return ExecuteSaControl(pContext, "rekey", "ike", pcIkeName,
                            NULL, false, IPSEC_ERR_IKE_FAILED);
}

IpsecError_t InitiateIpsecChild(
    IpsecContext_t *pContext,
    const char *pcChildName,
    const IpsecControlOptions_t *pOptions)
{
    return ExecuteSaControl(pContext, "initiate", "child", pcChildName,
                            pOptions, true, IPSEC_ERR_CHILD_FAILED);
}

IpsecError_t TerminateIpsecChild(
    IpsecContext_t *pContext,
    const char *pcChildName,
    const IpsecControlOptions_t *pOptions)
{
    return ExecuteSaControl(pContext, "terminate", "child", pcChildName,
                            pOptions, true, IPSEC_ERR_CHILD_FAILED);
}

IpsecError_t RekeyIpsecChild(
    IpsecContext_t *pContext,
    const char *pcChildName)
{
    return ExecuteSaControl(pContext, "rekey", "child", pcChildName,
                            NULL, false, IPSEC_ERR_CHILD_FAILED);
}

static IpsecError_t AppendIkeSa(SaCollector_t *pCollector)
{
    IpsecIkeSaInfo_t *pNewItems;
    uint32_t uiNewCount;
    size_t zAllocationSize;
    IpsecError_t eError;

    if (NULL == pCollector->pIkeList) {
        pCollector->pCurrentIke = NULL;
        eError = IPSEC_OK;
    }
    else if (UINT32_MAX == pCollector->pIkeList->uiCount) {
        eError = IPSEC_ERR_NO_MEMORY;
    }
    else {
        uiNewCount = pCollector->pIkeList->uiCount + 1U;
        if (!CalculateIpsecArraySize(uiNewCount, sizeof(*pNewItems),
                                    &zAllocationSize)) {
            eError = IPSEC_ERR_NO_MEMORY;
        }
        else {
            pNewItems = (IpsecIkeSaInfo_t *)realloc(
                pCollector->pIkeList->pItems, zAllocationSize);
            if (NULL == pNewItems) {
                eError = IPSEC_ERR_NO_MEMORY;
            }
            else {
                pCollector->pIkeList->pItems = pNewItems;
                pCollector->pCurrentIke = &pNewItems[uiNewCount - 1U];
                memset(pCollector->pCurrentIke, 0,
                       sizeof(*pCollector->pCurrentIke));
                pCollector->pIkeList->uiCount = uiNewCount;
                eError = IPSEC_OK;
            }
        }
    }
    return eError;
}

static IpsecError_t AppendChildSa(SaCollector_t *pCollector)
{
    IpsecChildSaInfo_t *pNewItems;
    uint32_t uiNewCount;
    size_t zAllocationSize;
    IpsecError_t eError;

    if (NULL == pCollector->pChildList) {
        pCollector->pCurrentChild = NULL;
        eError = IPSEC_OK;
    }
    else if (UINT32_MAX == pCollector->pChildList->uiCount) {
        eError = IPSEC_ERR_NO_MEMORY;
    }
    else {
        uiNewCount = pCollector->pChildList->uiCount + 1U;
        if (!CalculateIpsecArraySize(uiNewCount, sizeof(*pNewItems),
                                    &zAllocationSize)) {
            eError = IPSEC_ERR_NO_MEMORY;
        }
        else {
            pNewItems = (IpsecChildSaInfo_t *)realloc(
                pCollector->pChildList->pItems, zAllocationSize);
            if (NULL == pNewItems) {
                eError = IPSEC_ERR_NO_MEMORY;
            }
            else {
                pCollector->pChildList->pItems = pNewItems;
                pCollector->pCurrentChild = &pNewItems[uiNewCount - 1U];
                memset(pCollector->pCurrentChild, 0,
                       sizeof(*pCollector->pCurrentChild));
                pCollector->pCurrentChild->eMode = IPSEC_MODE_UNKNOWN;
                pCollector->pChildList->uiCount = uiNewCount;
                eError = IPSEC_OK;
            }
        }
    }
    return eError;
}

static IpsecError_t ParseSaSeconds(
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

static IpsecError_t ParseSaBoolean(
    const ViciElement_t *pElement,
    bool *pbValue)
{
    IpsecError_t eError;

    if (MatchSaText(pElement->pucValue, pElement->usValueLength, "yes") ||
        MatchSaText(pElement->pucValue, pElement->usValueLength, "1")) {
        *pbValue = true;
        eError = IPSEC_OK;
    }
    else if (MatchSaText(pElement->pucValue, pElement->usValueLength, "no") ||
             MatchSaText(pElement->pucValue, pElement->usValueLength, "0")) {
        *pbValue = false;
        eError = IPSEC_OK;
    }
    else {
        eError = IPSEC_ERR_VICI_PROTOCOL;
    }
    return eError;
}

static IpsecError_t AppendSaProposal(
    char *pcProposal,
    size_t zProposalLength,
    const ViciElement_t *pElement)
{
    return AppendIpsecText(pcProposal, zProposalLength, pElement->pucValue,
                           pElement->usValueLength, "/");
}

static IpsecError_t AppendSaKeySize(
    char *pcProposal,
    size_t zProposalLength,
    const ViciElement_t *pElement)
{
    uint32_t uiKeySize;
    IpsecError_t eError;

    eError = ParseIpsecUint32(pElement->pucValue, pElement->usValueLength,
                              &uiKeySize, 10U);
    if ((IPSEC_OK == eError) && (0U == uiKeySize)) {
        eError = IPSEC_ERR_VICI_PROTOCOL;
    }
    else if (IPSEC_OK == eError) {
        eError = AppendIpsecText(pcProposal, zProposalLength,
                                 pElement->pucValue,
                                 pElement->usValueLength, "-");
    }
    else {
        /* Preserve malformed VICI key-size data. */
    }
    return eError;
}

static IpsecError_t CollectIkeValue(
    SaCollector_t *pCollector,
    const ViciElement_t *pElement)
{
    IpsecIkeSaInfo_t *pInfo = pCollector->pCurrentIke;
    IpsecError_t eError = IPSEC_OK;

    if (NULL == pInfo) {
        return IPSEC_OK;
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength, "uniqueid")) {
        eError = ParseIpsecUint64(pElement->pucValue, pElement->usValueLength,
                                  &pInfo->ullUniqueId, 10U);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength, "state")) {
        eError = CopyIpsecString(pInfo->acState, sizeof(pInfo->acState),
                                 pElement->pucValue, pElement->usValueLength);
        if (IPSEC_OK == eError) {
            pInfo->bEstablished =
                MatchSaText(pElement->pucValue, pElement->usValueLength,
                            "ESTABLISHED");
        }
        else {
            /* Preserve copy error. */
        }
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "local-host")) {
        eError = CopyIpsecString(pInfo->acLocalAddress,
                                 sizeof(pInfo->acLocalAddress),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "remote-host")) {
        eError = CopyIpsecString(pInfo->acRemoteAddress,
                                 sizeof(pInfo->acRemoteAddress),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "local-id")) {
        eError = CopyIpsecString(pInfo->acLocalId, sizeof(pInfo->acLocalId),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "remote-id")) {
        eError = CopyIpsecString(pInfo->acRemoteId, sizeof(pInfo->acRemoteId),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "initiator")) {
        eError = ParseSaBoolean(pElement, &pInfo->bInitiator);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "nat-local")) {
        eError = ParseSaBoolean(pElement, &pInfo->bNatLocal);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "nat-remote")) {
        eError = ParseSaBoolean(pElement, &pInfo->bNatRemote);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "established")) {
        eError = ParseSaSeconds(pElement, &pInfo->ullEstablishedTimeMs);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "rekey-time")) {
        eError = ParseSaSeconds(pElement, &pInfo->ullRekeyTimeMs);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "encr-alg") ||
             MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "integ-alg") ||
             MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "prf-alg") ||
             MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "dh-group")) {
        eError = AppendSaProposal(pInfo->acProposal,
                                  sizeof(pInfo->acProposal), pElement);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "encr-keysize")) {
        eError = AppendSaKeySize(pInfo->acProposal,
                                 sizeof(pInfo->acProposal), pElement);
    }
    else {
        /* Ignore optional IKE fields. */
    }

    return eError;
}

static IpsecError_t CollectChildValue(
    SaCollector_t *pCollector,
    const ViciElement_t *pElement)
{
    IpsecChildSaInfo_t *pInfo = pCollector->pCurrentChild;
    IpsecError_t eError = IPSEC_OK;

    if (NULL == pInfo) {
        return IPSEC_OK;
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength, "name")) {
        eError = CopyIpsecString(pInfo->acName, sizeof(pInfo->acName),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength, "state")) {
        eError = CopyIpsecString(pInfo->acState, sizeof(pInfo->acState),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength, "reqid")) {
        eError = ParseIpsecUint32(pElement->pucValue, pElement->usValueLength,
                                  &pInfo->uiReqid, 10U);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength, "spi-in")) {
        eError = ParseIpsecUint32(pElement->pucValue, pElement->usValueLength,
                                  &pInfo->uiInboundSpi, 16U);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength, "spi-out")) {
        eError = ParseIpsecUint32(pElement->pucValue, pElement->usValueLength,
                                  &pInfo->uiOutboundSpi, 16U);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength, "mode")) {
        if (MatchSaText(pElement->pucValue, pElement->usValueLength,
                        "tunnel") ||
            MatchSaText(pElement->pucValue, pElement->usValueLength,
                        "TUNNEL")) {
            pInfo->eMode = IPSEC_MODE_TUNNEL;
        }
        else if (MatchSaText(pElement->pucValue, pElement->usValueLength,
                             "transport") ||
                 MatchSaText(pElement->pucValue, pElement->usValueLength,
                             "TRANSPORT")) {
            pInfo->eMode = IPSEC_MODE_TRANSPORT;
        }
        else if (MatchSaText(pElement->pucValue, pElement->usValueLength,
                             "beet") ||
                 MatchSaText(pElement->pucValue, pElement->usValueLength,
                             "BEET")) {
            pInfo->eMode = IPSEC_MODE_BEET;
        }
        else {
            pInfo->eMode = IPSEC_MODE_UNKNOWN;
        }
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength, "encap")) {
        eError = ParseSaBoolean(pElement, &pInfo->bUdpEncapsulation);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength, "esn")) {
        eError = ParseSaBoolean(pElement, &pInfo->bEsn);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "bytes-in")) {
        eError = ParseIpsecUint64(pElement->pucValue, pElement->usValueLength,
                                  &pInfo->ullBytesIn, 10U);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "bytes-out")) {
        eError = ParseIpsecUint64(pElement->pucValue, pElement->usValueLength,
                                  &pInfo->ullBytesOut, 10U);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "packets-in")) {
        eError = ParseIpsecUint64(pElement->pucValue, pElement->usValueLength,
                                  &pInfo->ullPacketsIn, 10U);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "packets-out")) {
        eError = ParseIpsecUint64(pElement->pucValue, pElement->usValueLength,
                                  &pInfo->ullPacketsOut, 10U);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "install-time")) {
        eError = ParseSaSeconds(pElement, &pInfo->ullInstallTimeMs);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "rekey-time")) {
        eError = ParseSaSeconds(pElement, &pInfo->ullRekeyTimeMs);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "life-time")) {
        eError = ParseSaSeconds(pElement, &pInfo->ullLifetimeMs);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "encr-alg") ||
             MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "integ-alg") ||
             MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "prf-alg") ||
             MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "dh-group")) {
        eError = AppendSaProposal(pInfo->acProposal,
                                  sizeof(pInfo->acProposal), pElement);
    }
    else if (MatchSaText(pElement->pucName, pElement->ucNameLength,
                         "encr-keysize")) {
        eError = AppendSaKeySize(pInfo->acProposal,
                                 sizeof(pInfo->acProposal), pElement);
    }
    else {
        /* Ignore optional CHILD fields. */
    }

    return eError;
}

static IpsecError_t CollectSaSectionStart(
    SaCollector_t *pCollector,
    const ViciElement_t *pElement)
{
    uint32_t uiIndex = pElement->uiDepth - 1U;
    IpsecError_t eError;

    eError = CopyIpsecString(pCollector->aacSections[uiIndex],
                             sizeof(pCollector->aacSections[uiIndex]),
                             pElement->pucName, pElement->ucNameLength);
    if ((IPSEC_OK == eError) && (1U == pElement->uiDepth)) {
        eError = CopyIpsecString(pCollector->acCurrentIkeName,
                                 sizeof(pCollector->acCurrentIkeName),
                                 pElement->pucName, pElement->ucNameLength);
        if (IPSEC_OK == eError) {
            eError = AppendIkeSa(pCollector);
        }
        else {
            /* Preserve name error. */
        }
        if ((IPSEC_OK == eError) && (NULL != pCollector->pCurrentIke)) {
            eError = CopyIpsecString(pCollector->pCurrentIke->acName,
                                     sizeof(pCollector->pCurrentIke->acName),
                                     pElement->pucName,
                                     pElement->ucNameLength);
        }
        else {
            /* IKE list was not requested or an error exists. */
        }
    }
    else if ((IPSEC_OK == eError) && (3U == pElement->uiDepth) &&
             (0 == strcmp(pCollector->aacSections[1], "child-sas"))) {
        eError = AppendChildSa(pCollector);
        if ((IPSEC_OK == eError) && (NULL != pCollector->pCurrentChild)) {
            eError = CopyIpsecString(
                pCollector->pCurrentChild->acIkeName,
                sizeof(pCollector->pCurrentChild->acIkeName),
                (const uint8_t *)pCollector->acCurrentIkeName,
                strnlen(pCollector->acCurrentIkeName,
                        sizeof(pCollector->acCurrentIkeName)));
            if ((IPSEC_OK == eError) && (IPSEC_OK != CopyIpsecString(
                    pCollector->pCurrentChild->acName,
                    sizeof(pCollector->pCurrentChild->acName),
                    pElement->pucName, pElement->ucNameLength))) {
                pCollector->pCurrentChild->acName[0] = '\0';
            }
            else {
                /* Section name is usable as a fallback. */
            }
        }
        else {
            /* CHILD list was not requested or an error exists. */
        }
    }
    else {
        /* Other sections only affect path tracking. */
    }

    return eError;
}

static IpsecError_t CollectSaElement(
    const ViciElement_t *pElement,
    void *pvUserData)
{
    SaCollector_t *pCollector = (SaCollector_t *)pvUserData;
    IpsecError_t eError = IPSEC_OK;

    if (VICI_ELEMENT_SECTION_START == pElement->eType) {
        eError = CollectSaSectionStart(pCollector, pElement);
    }
    else if (VICI_ELEMENT_SECTION_END == pElement->eType) {
        if ((0U == pElement->uiDepth) ||
            (VICI_MAX_SECTION_DEPTH < pElement->uiDepth)) {
            eError = IPSEC_ERR_VICI_PROTOCOL;
        }
        else {
            if (3U == pElement->uiDepth) {
                pCollector->pCurrentChild = NULL;
            }
            else if (1U == pElement->uiDepth) {
                pCollector->pCurrentIke = NULL;
                pCollector->acCurrentIkeName[0] = '\0';
            }
            else {
                /* No current object ends at this depth. */
            }
            pCollector->aacSections[pElement->uiDepth - 1U][0] = '\0';
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
             (3U == pElement->uiDepth) &&
             (NULL != pCollector->pCurrentChild)) {
        if (0 == strcmp(pCollector->acListName, "local-ts")) {
            eError = AppendIpsecText(
                pCollector->pCurrentChild->acLocalTrafficSelectors,
                sizeof(pCollector->pCurrentChild->acLocalTrafficSelectors),
                pElement->pucValue, pElement->usValueLength, ",");
        }
        else if (0 == strcmp(pCollector->acListName, "remote-ts")) {
            eError = AppendIpsecText(
                pCollector->pCurrentChild->acRemoteTrafficSelectors,
                sizeof(pCollector->pCurrentChild->acRemoteTrafficSelectors),
                pElement->pucValue, pElement->usValueLength, ",");
        }
        else {
            /* Ignore other lists. */
        }
    }
    else if ((VICI_ELEMENT_KEY_VALUE == pElement->eType) &&
             (1U == pElement->uiDepth)) {
        eError = CollectIkeValue(pCollector, pElement);
    }
    else if ((VICI_ELEMENT_KEY_VALUE == pElement->eType) &&
             (3U == pElement->uiDepth) &&
             (0 == strcmp(pCollector->aacSections[1], "child-sas"))) {
        eError = CollectChildValue(pCollector, pElement);
    }
    else {
        /* Ignore unrepresented data. */
    }

    return eError;
}

static IpsecError_t CollectSaEvent(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    void *pvUserData)
{
    return ParseViciMessage(pucMessage, uiMessageLength,
                            CollectSaElement, pvUserData);
}

static IpsecError_t QueryIpsecSas(
    IpsecContext_t *pContext,
    IpsecIkeSaList_t *pIkeList,
    IpsecChildSaList_t *pChildList)
{
    ViciBuffer_t Request = {0};
    ViciCommandResult_t Result = {0};
    SaCollector_t Collector;
    IpsecError_t eError;

    if ((NULL == pContext) || ((NULL == pIkeList) && (NULL == pChildList))) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        if (NULL != pIkeList) {
            memset(pIkeList, 0, sizeof(*pIkeList));
        }
        else {
            /* IKE list is not requested. */
        }
        if (NULL != pChildList) {
            memset(pChildList, 0, sizeof(*pChildList));
        }
        else {
            /* CHILD list is not requested. */
        }
        memset(&Collector, 0, sizeof(Collector));
        Collector.pIkeList = pIkeList;
        Collector.pChildList = pChildList;
        eError = InitializeViciBuffer(&Request, 1U, false);
    }
    if (IPSEC_OK == eError) {
        eError = ExecuteViciCommand(pContext, "list-sas", &Request,
                                    "list-sa", CollectSaEvent, NULL,
                                    &Collector, &Result);
    }
    else {
        /* Preserve argument or allocation error. */
    }
    DestroyViciBuffer(&Request);
    return eError;
}

IpsecError_t GetIpsecIkeSas(
    IpsecContext_t *pContext,
    IpsecIkeSaList_t *pList)
{
    IpsecError_t eError;

    if (NULL == pList) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = QueryIpsecSas(pContext, pList, NULL);
        if (IPSEC_OK != eError) {
            FreeIpsecIkeSaList(pList);
        }
        else {
            /* Return collected IKE SAs. */
        }
    }
    return eError;
}

void FreeIpsecIkeSaList(IpsecIkeSaList_t *pList)
{
    if (NULL != pList) {
        free(pList->pItems);
        memset(pList, 0, sizeof(*pList));
    }
    else {
        /* NULL free is safe. */
    }
}

IpsecError_t GetIpsecChildSas(
    IpsecContext_t *pContext,
    IpsecChildSaList_t *pList)
{
    IpsecError_t eError;

    if (NULL == pList) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = QueryIpsecSas(pContext, NULL, pList);
        if (IPSEC_OK != eError) {
            FreeIpsecChildSaList(pList);
        }
        else {
            /* Return collected CHILD SAs. */
        }
    }
    return eError;
}

void FreeIpsecChildSaList(IpsecChildSaList_t *pList)
{
    if (NULL != pList) {
        free(pList->pItems);
        memset(pList, 0, sizeof(*pList));
    }
    else {
        /* NULL free is safe. */
    }
}

IpsecError_t WaitIpsecIkeEstablished(
    IpsecContext_t *pContext,
    const char *pcIkeName,
    uint32_t uiTimeoutMs)
{
    IpsecIkeSaList_t List;
    uint64_t ullDeadlineMs;
    uint32_t uiIndex;
    bool bEstablished = false;
    IpsecError_t eError;

    if ((NULL == pContext) || (0U == uiTimeoutMs)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ValidateSaName(pcIkeName);
    }
    if (IPSEC_OK == eError) {
        ullDeadlineMs = GetIpsecMonotonicMilliseconds() + uiTimeoutMs;
        do {
            memset(&List, 0, sizeof(List));
            eError = GetIpsecIkeSas(pContext, &List);
            if (IPSEC_OK == eError) {
                for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
                    if ((0 == strcmp(pcIkeName, List.pItems[uiIndex].acName)) &&
                        List.pItems[uiIndex].bEstablished) {
                        bEstablished = true;
                        break;
                    }
                    else {
                        /* Continue searching. */
                    }
                }
            }
            else {
                /* Stop on query error. */
            }
            FreeIpsecIkeSaList(&List);
            if (!bEstablished && (IPSEC_OK == eError) &&
                (GetIpsecMonotonicMilliseconds() < ullDeadlineMs)) {
                eError = SleepIpsecMilliseconds(IPSEC_SA_POLL_INTERVAL_MS);
            }
            else {
                /* Established, failed, or timed out. */
            }
        } while (!bEstablished && (IPSEC_OK == eError) &&
                 (GetIpsecMonotonicMilliseconds() < ullDeadlineMs));

        if ((IPSEC_OK == eError) && !bEstablished) {
            eError = IPSEC_ERR_VICI_TIMEOUT;
        }
        else {
            /* Return success or query error. */
        }
    }
    else {
        /* Preserve validation error. */
    }
    return eError;
}

IpsecError_t WaitIpsecChildInstalled(
    IpsecContext_t *pContext,
    const char *pcChildName,
    uint32_t uiTimeoutMs)
{
    IpsecChildSaList_t List;
    uint64_t ullDeadlineMs;
    uint32_t uiIndex;
    bool bInstalled = false;
    IpsecError_t eError;

    if ((NULL == pContext) || (0U == uiTimeoutMs)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ValidateSaName(pcChildName);
    }
    if (IPSEC_OK == eError) {
        ullDeadlineMs = GetIpsecMonotonicMilliseconds() + uiTimeoutMs;
        do {
            memset(&List, 0, sizeof(List));
            eError = GetIpsecChildSas(pContext, &List);
            if (IPSEC_OK == eError) {
                for (uiIndex = 0U; uiIndex < List.uiCount; uiIndex++) {
                    if ((0 == strcmp(pcChildName,
                                     List.pItems[uiIndex].acName)) &&
                        (0 == strcmp("INSTALLED",
                                     List.pItems[uiIndex].acState))) {
                        bInstalled = true;
                        break;
                    }
                    else {
                        /* Continue searching. */
                    }
                }
            }
            else {
                /* Stop on query error. */
            }
            FreeIpsecChildSaList(&List);
            if (!bInstalled && (IPSEC_OK == eError) &&
                (GetIpsecMonotonicMilliseconds() < ullDeadlineMs)) {
                eError = SleepIpsecMilliseconds(IPSEC_SA_POLL_INTERVAL_MS);
            }
            else {
                /* Installed, failed, or timed out. */
            }
        } while (!bInstalled && (IPSEC_OK == eError) &&
                 (GetIpsecMonotonicMilliseconds() < ullDeadlineMs));

        if ((IPSEC_OK == eError) && !bInstalled) {
            eError = IPSEC_ERR_VICI_TIMEOUT;
        }
        else {
            /* Return success or query error. */
        }
    }
    else {
        /* Preserve validation error. */
    }
    return eError;
}
