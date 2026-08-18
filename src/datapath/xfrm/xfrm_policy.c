#include "xfrm_internal.h"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <string.h>

static IpsecAddressFamily_t MapPolicyAddressFamily(uint16_t usFamily)
{
    IpsecAddressFamily_t eFamily;

    if (AF_INET == usFamily) {
        eFamily = IPSEC_ADDRESS_FAMILY_IPV4;
    }
    else if (AF_INET6 == usFamily) {
        eFamily = IPSEC_ADDRESS_FAMILY_IPV6;
    }
    else {
        eFamily = IPSEC_ADDRESS_FAMILY_UNSPECIFIED;
    }
    return eFamily;
}

static IpsecXfrmDirection_t MapPolicyDirection(uint8_t ucDirection)
{
    IpsecXfrmDirection_t eDirection;

    if (XFRM_POLICY_IN == ucDirection) {
        eDirection = IPSEC_XFRM_DIRECTION_IN;
    }
    else if (XFRM_POLICY_OUT == ucDirection) {
        eDirection = IPSEC_XFRM_DIRECTION_OUT;
    }
    else if (XFRM_POLICY_FWD == ucDirection) {
        eDirection = IPSEC_XFRM_DIRECTION_FORWARD;
    }
    else {
        eDirection = IPSEC_XFRM_DIRECTION_UNKNOWN;
    }
    return eDirection;
}

static IpsecMode_t MapPolicyMode(uint8_t ucMode)
{
    IpsecMode_t eMode;

    if (XFRM_MODE_TUNNEL == ucMode) {
        eMode = IPSEC_MODE_TUNNEL;
    }
    else if (XFRM_MODE_TRANSPORT == ucMode) {
        eMode = IPSEC_MODE_TRANSPORT;
    }
    else if (XFRM_MODE_BEET == ucMode) {
        eMode = IPSEC_MODE_BEET;
    }
    else {
        eMode = IPSEC_MODE_UNKNOWN;
    }
    return eMode;
}

static IpsecError_t ConvertPolicyAddress(
    uint16_t usFamily,
    const xfrm_address_t *pAddress,
    char *pcDestination,
    size_t zDestinationLength)
{
    const void *pvAddress;
    IpsecError_t eError;

    if (AF_INET == usFamily) {
        pvAddress = &pAddress->a4;
    }
    else if (AF_INET6 == usFamily) {
        pvAddress = pAddress->a6;
    }
    else {
        pvAddress = NULL;
    }

    if (NULL == pvAddress) {
        pcDestination[0] = '\0';
        eError = IPSEC_ERR_NOT_SUPPORTED;
    }
    else if (NULL == inet_ntop(usFamily, pvAddress, pcDestination,
                               (socklen_t)zDestinationLength)) {
        pcDestination[0] = '\0';
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        eError = IPSEC_OK;
    }
    return eError;
}

static IpsecError_t AppendXfrmPolicy(
    IpsecXfrmPolicyList_t *pList,
    IpsecXfrmPolicyInfo_t **ppInfo)
{
    IpsecXfrmPolicyInfo_t *pNewItems;
    uint32_t uiNewCount;
    size_t zAllocationSize;
    IpsecError_t eError;

    if (UINT32_MAX == pList->uiCount) {
        eError = IPSEC_ERR_NO_MEMORY;
    }
    else {
        uiNewCount = pList->uiCount + 1U;
        if (!CalculateIpsecArraySize(uiNewCount, sizeof(*pNewItems),
                                    &zAllocationSize)) {
            eError = IPSEC_ERR_NO_MEMORY;
        }
        else {
            pNewItems = (IpsecXfrmPolicyInfo_t *)realloc(
                pList->pItems, zAllocationSize);
            if (NULL == pNewItems) {
                eError = IPSEC_ERR_NO_MEMORY;
            }
            else {
                pList->pItems = pNewItems;
                pList->uiCount = uiNewCount;
                *ppInfo = &pNewItems[uiNewCount - 1U];
                memset(*ppInfo, 0, sizeof(**ppInfo));
                (*ppInfo)->eMode = IPSEC_MODE_UNKNOWN;
                eError = IPSEC_OK;
            }
        }
    }
    return eError;
}

static IpsecError_t ParsePolicyTemplates(
    const struct rtattr *pAttribute,
    uint16_t usFamily,
    IpsecXfrmPolicyInfo_t *pInfo)
{
    const struct xfrm_user_tmpl *pTemplate;
    size_t zPayloadLength = (size_t)RTA_PAYLOAD(pAttribute);
    IpsecError_t eError;

    if ((0U == zPayloadLength) ||
        (0U != (zPayloadLength % sizeof(*pTemplate)))) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        pTemplate = (const struct xfrm_user_tmpl *)RTA_DATA(pAttribute);
        if ((AF_INET == pTemplate->family) ||
            (AF_INET6 == pTemplate->family)) {
            usFamily = pTemplate->family;
        }
        else {
            /* Fall back to the selector family for older kernel messages. */
        }
        pInfo->uiReqid = pTemplate->reqid;
        pInfo->eMode = MapPolicyMode(pTemplate->mode);
        pInfo->uiProtocol = pTemplate->id.proto;
        eError = ConvertPolicyAddress(usFamily, &pTemplate->saddr,
                                      pInfo->acTemplateSource,
                                      sizeof(pInfo->acTemplateSource));
        if (IPSEC_OK == eError) {
            eError = ConvertPolicyAddress(usFamily, &pTemplate->id.daddr,
                                          pInfo->acTemplateDestination,
                                          sizeof(pInfo->acTemplateDestination));
        }
        else {
            /* Preserve source conversion error. */
        }
    }
    return eError;
}

IpsecError_t ParseXfrmPolicyMessage(
    const struct nlmsghdr *pHeader,
    void *pvUserData)
{
    IpsecXfrmPolicyList_t *pList = (IpsecXfrmPolicyList_t *)pvUserData;
    const struct xfrm_userpolicy_info *pKernelInfo;
    IpsecXfrmPolicyInfo_t *pInfo = NULL;
    struct rtattr *pAttribute;
    int32_t iAttributeLength;
    IpsecError_t eError;

    if ((NULL == pHeader) || (NULL == pList) ||
        (XFRM_MSG_NEWPOLICY != pHeader->nlmsg_type) ||
        (NLMSG_PAYLOAD(pHeader, 0) < sizeof(*pKernelInfo))) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        pKernelInfo =
            (const struct xfrm_userpolicy_info *)NLMSG_DATA(pHeader);
        eError = AppendXfrmPolicy(pList, &pInfo);
    }

    if (IPSEC_OK == eError) {
        pInfo->eFamily = MapPolicyAddressFamily(pKernelInfo->sel.family);
        pInfo->eDirection = MapPolicyDirection(pKernelInfo->dir);
        pInfo->ucSourcePrefixLength = pKernelInfo->sel.prefixlen_s;
        pInfo->ucDestinationPrefixLength = pKernelInfo->sel.prefixlen_d;
        pInfo->uiPriority = pKernelInfo->priority;
        pInfo->uiIndex = pKernelInfo->index;
        eError = ConvertPolicyAddress(pKernelInfo->sel.family,
                                      &pKernelInfo->sel.saddr,
                                      pInfo->acSourceSelector,
                                      sizeof(pInfo->acSourceSelector));
    }
    else {
        /* Preserve header/allocation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ConvertPolicyAddress(pKernelInfo->sel.family,
                                      &pKernelInfo->sel.daddr,
                                      pInfo->acDestinationSelector,
                                      sizeof(pInfo->acDestinationSelector));
    }
    else {
        /* Preserve source conversion error. */
    }
    if (IPSEC_OK == eError) {
        iAttributeLength = (int32_t)pHeader->nlmsg_len -
                           (int32_t)NLMSG_LENGTH(sizeof(*pKernelInfo));
        pAttribute = (struct rtattr *)(
            (uint8_t *)pKernelInfo + NLMSG_ALIGN(sizeof(*pKernelInfo)));
        while (RTA_OK(pAttribute, iAttributeLength) &&
               (IPSEC_OK == eError)) {
            if (XFRMA_TMPL == pAttribute->rta_type) {
                eError = ParsePolicyTemplates(pAttribute,
                                              pKernelInfo->sel.family,
                                              pInfo);
            }
            else {
                /* Unknown attributes are forward-compatible. */
            }
            pAttribute = RTA_NEXT(pAttribute, iAttributeLength);
        }
        if ((IPSEC_OK == eError) && (0 != iAttributeLength)) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            /* Attribute stream is complete or already invalid. */
        }
    }
    else {
        /* Preserve selector conversion error. */
    }

    return eError;
}

IpsecError_t GetIpsecXfrmPolicies(
    IpsecContext_t *pContext,
    IpsecXfrmPolicyList_t *pList)
{
    struct xfrm_userpolicy_id Request;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pList)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pList, 0, sizeof(*pList));
        memset(&Request, 0, sizeof(Request));
        Request.sel.family = AF_UNSPEC;
        Request.dir = XFRM_POLICY_MAX;
        eError = ExecuteNetlinkDump(NETLINK_XFRM, XFRM_MSG_GETPOLICY,
                                    &Request, sizeof(Request),
                                    ParseXfrmPolicyMessage, pList);
    }
    if (IPSEC_OK != eError) {
        LogIpsec(pContext, IPSEC_LOG_ERROR,
                 "failed to query XFRM policies: %s",
                 GetIpsecErrorString(eError));
        FreeIpsecXfrmPolicyList(pList);
    }
    else {
        /* Return XFRM policies. */
    }
    return eError;
}

void FreeIpsecXfrmPolicyList(IpsecXfrmPolicyList_t *pList)
{
    if (NULL != pList) {
        free(pList->pItems);
        memset(pList, 0, sizeof(*pList));
    }
    else {
        /* NULL free is safe. */
    }
}
