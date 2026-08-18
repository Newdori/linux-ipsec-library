#include "vici_internal.h"

#include <string.h>

typedef struct DaemonStatusCollector {
    IpsecDaemonStatus_t *pStatus;
    char aacSections[VICI_MAX_SECTION_DEPTH][IPSEC_NAME_LENGTH];
} DaemonStatusCollector_t;

static bool MatchStatusText(
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

static IpsecError_t CollectStatusRootValue(
    DaemonStatusCollector_t *pCollector,
    const ViciElement_t *pElement)
{
    IpsecDaemonStatus_t *pStatus = pCollector->pStatus;
    IpsecError_t eError = IPSEC_OK;

    if (MatchStatusText(pElement->pucName, pElement->ucNameLength, "daemon")) {
        eError = CopyIpsecString(pStatus->acDaemon, sizeof(pStatus->acDaemon),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else if (MatchStatusText(pElement->pucName, pElement->ucNameLength,
                             "version")) {
        eError = CopyIpsecString(pStatus->acVersion,
                                 sizeof(pStatus->acVersion),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else if (MatchStatusText(pElement->pucName, pElement->ucNameLength,
                             "sysname")) {
        eError = CopyIpsecString(pStatus->acSystemName,
                                 sizeof(pStatus->acSystemName),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else if (MatchStatusText(pElement->pucName, pElement->ucNameLength,
                             "release")) {
        eError = CopyIpsecString(pStatus->acSystemRelease,
                                 sizeof(pStatus->acSystemRelease),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else if (MatchStatusText(pElement->pucName, pElement->ucNameLength,
                             "machine")) {
        eError = CopyIpsecString(pStatus->acMachine,
                                 sizeof(pStatus->acMachine),
                                 pElement->pucValue, pElement->usValueLength);
    }
    else {
        /* Ignore other root values. */
    }

    return eError;
}

static IpsecError_t CollectStatusNestedValue(
    DaemonStatusCollector_t *pCollector,
    const ViciElement_t *pElement)
{
    IpsecDaemonStatus_t *pStatus = pCollector->pStatus;
    const char *pcSection = pCollector->aacSections[0];
    IpsecError_t eError = IPSEC_OK;

    if ((0 == strcmp(pcSection, "uptime")) &&
        MatchStatusText(pElement->pucName, pElement->ucNameLength,
                        "running")) {
        IpsecError_t eDurationError = ParseIpsecDurationSeconds(
            pElement->pucValue, pElement->usValueLength,
            &pStatus->ullUptimeSeconds);

        if (IPSEC_OK != eDurationError) {
            pStatus->ullUptimeSeconds = 0U;
        }
        else {
            /* The human-readable uptime was converted to seconds. */
        }
    }
    else if ((0 == strcmp(pcSection, "workers")) &&
        MatchStatusText(pElement->pucName, pElement->ucNameLength, "total")) {
        eError = ParseIpsecUint32(pElement->pucValue,
                                  pElement->usValueLength,
                                  &pStatus->uiWorkerTotal, 10U);
    }
    else if ((0 == strcmp(pcSection, "workers")) &&
             MatchStatusText(pElement->pucName,
                             pElement->ucNameLength, "idle")) {
        eError = ParseIpsecUint32(pElement->pucValue,
                                  pElement->usValueLength,
                                  &pStatus->uiWorkerIdle, 10U);
    }
    else if ((0 == strcmp(pcSection, "ikesas")) &&
             MatchStatusText(pElement->pucName,
                             pElement->ucNameLength, "total")) {
        eError = ParseIpsecUint32(pElement->pucValue,
                                  pElement->usValueLength,
                                  &pStatus->uiIkeSaTotal, 10U);
    }
    else if ((0 == strcmp(pcSection, "ikesas")) &&
             MatchStatusText(pElement->pucName,
                             pElement->ucNameLength, "half-open")) {
        eError = ParseIpsecUint32(pElement->pucValue,
                                  pElement->usValueLength,
                                  &pStatus->uiIkeSaHalfOpen, 10U);
    }
    else {
        /* Ignore optional nested values. */
    }

    return eError;
}

static IpsecError_t CollectStatusElement(
    const ViciElement_t *pElement,
    void *pvUserData)
{
    DaemonStatusCollector_t *pCollector =
        (DaemonStatusCollector_t *)pvUserData;
    uint32_t uiIndex;
    IpsecError_t eError = IPSEC_OK;

    if (VICI_ELEMENT_SECTION_START == pElement->eType) {
        uiIndex = pElement->uiDepth - 1U;
        eError = CopyIpsecString(pCollector->aacSections[uiIndex],
                                 sizeof(pCollector->aacSections[uiIndex]),
                                 pElement->pucName,
                                 pElement->ucNameLength);
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
    else if ((VICI_ELEMENT_KEY_VALUE == pElement->eType) &&
             (0U == pElement->uiDepth)) {
        eError = CollectStatusRootValue(pCollector, pElement);
    }
    else if ((VICI_ELEMENT_KEY_VALUE == pElement->eType) &&
             (1U == pElement->uiDepth)) {
        eError = CollectStatusNestedValue(pCollector, pElement);
    }
    else {
        /* Ignore lists and deeper sections. */
    }

    return eError;
}

static IpsecError_t CollectStatusResponse(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    void *pvUserData)
{
    return ParseViciMessage(pucMessage, uiMessageLength,
                            CollectStatusElement, pvUserData);
}

static IpsecError_t QueryStatusCommand(
    IpsecContext_t *pContext,
    const char *pcCommand,
    DaemonStatusCollector_t *pCollector)
{
    ViciBuffer_t Request = {0};
    ViciCommandResult_t Result = {0};
    IpsecError_t eError;

    eError = InitializeViciBuffer(&Request, 1U, false);
    if (IPSEC_OK == eError) {
        eError = ExecuteViciCommand(pContext, pcCommand, &Request,
                                    NULL, NULL, CollectStatusResponse,
                                    pCollector, &Result);
    }
    else {
        /* Preserve allocation error. */
    }
    DestroyViciBuffer(&Request);
    return eError;
}

IpsecError_t GetIpsecDaemonStatus(
    IpsecContext_t *pContext,
    IpsecDaemonStatus_t *pStatus)
{
    DaemonStatusCollector_t Collector;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pStatus)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pStatus, 0, sizeof(*pStatus));
        memset(&Collector, 0, sizeof(Collector));
        Collector.pStatus = pStatus;
        eError = QueryStatusCommand(pContext, "version", &Collector);
    }
    if (IPSEC_OK == eError) {
        memset(Collector.aacSections, 0, sizeof(Collector.aacSections));
        eError = QueryStatusCommand(pContext, "stats", &Collector);
    }
    else {
        /* Preserve version query error. */
    }
    return eError;
}
