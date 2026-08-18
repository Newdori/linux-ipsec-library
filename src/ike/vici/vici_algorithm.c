#include "vici_internal.h"

#include <stdlib.h>
#include <string.h>

typedef struct AlgorithmCollector {
    IpsecAlgorithmList_t *pList;
    char acType[IPSEC_ALGORITHM_LENGTH];
} AlgorithmCollector_t;

static IpsecError_t AppendAlgorithm(
    AlgorithmCollector_t *pCollector,
    const ViciElement_t *pElement)
{
    IpsecAlgorithmInfo_t *pNewItems;
    IpsecAlgorithmInfo_t *pInfo;
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
            pNewItems = (IpsecAlgorithmInfo_t *)realloc(
                pCollector->pList->pItems, zAllocationSize);
            if (NULL == pNewItems) {
                eError = IPSEC_ERR_NO_MEMORY;
            }
            else {
                pCollector->pList->pItems = pNewItems;
                pCollector->pList->uiCount = uiNewCount;
                pInfo = &pNewItems[uiNewCount - 1U];
                memset(pInfo, 0, sizeof(*pInfo));
                eError = CopyIpsecString(
                    pInfo->acType, sizeof(pInfo->acType),
                    (const uint8_t *)pCollector->acType,
                    strlen(pCollector->acType));
                if (IPSEC_OK == eError) {
                    eError = CopyIpsecString(
                        pInfo->acName, sizeof(pInfo->acName),
                        pElement->pucName, pElement->ucNameLength);
                }
                else {
                    /* Preserve type copy error. */
                }
                if (IPSEC_OK == eError) {
                    eError = CopyIpsecString(
                        pInfo->acPlugin, sizeof(pInfo->acPlugin),
                        pElement->pucValue, pElement->usValueLength);
                }
                else {
                    /* Preserve algorithm copy error. */
                }
            }
        }
    }

    return eError;
}

static IpsecError_t CollectAlgorithmElement(
    const ViciElement_t *pElement,
    void *pvUserData)
{
    AlgorithmCollector_t *pCollector =
        (AlgorithmCollector_t *)pvUserData;
    IpsecError_t eError = IPSEC_OK;

    if ((VICI_ELEMENT_SECTION_START == pElement->eType) &&
        (1U == pElement->uiDepth)) {
        eError = CopyIpsecString(pCollector->acType,
                                 sizeof(pCollector->acType),
                                 pElement->pucName,
                                 pElement->ucNameLength);
    }
    else if ((VICI_ELEMENT_SECTION_END == pElement->eType) &&
             (1U == pElement->uiDepth)) {
        pCollector->acType[0] = '\0';
    }
    else if ((VICI_ELEMENT_KEY_VALUE == pElement->eType) &&
             (1U == pElement->uiDepth) &&
             ('\0' != pCollector->acType[0])) {
        eError = AppendAlgorithm(pCollector, pElement);
    }
    else {
        /* Ignore optional hierarchy. */
    }

    return eError;
}

static IpsecError_t CollectAlgorithmResponse(
    const uint8_t *pucMessage,
    uint32_t uiMessageLength,
    void *pvUserData)
{
    return ParseViciMessage(pucMessage, uiMessageLength,
                            CollectAlgorithmElement, pvUserData);
}

IpsecError_t GetIpsecAlgorithms(
    IpsecContext_t *pContext,
    IpsecAlgorithmList_t *pList)
{
    ViciBuffer_t Request = {0};
    ViciCommandResult_t Result = {0};
    AlgorithmCollector_t Collector;
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
        eError = ExecuteViciCommand(pContext, "get-algorithms", &Request,
                                    NULL, NULL, CollectAlgorithmResponse,
                                    &Collector, &Result);
    }
    else {
        /* Preserve argument or allocation error. */
    }
    DestroyViciBuffer(&Request);
    if (IPSEC_OK != eError) {
        FreeIpsecAlgorithmList(pList);
    }
    else {
        /* Return collected algorithms. */
    }
    return eError;
}

void FreeIpsecAlgorithmList(IpsecAlgorithmList_t *pList)
{
    if (NULL != pList) {
        free(pList->pItems);
        memset(pList, 0, sizeof(*pList));
    }
    else {
        /* NULL free is safe. */
    }
}
