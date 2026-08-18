#include "xfrm_internal.h"

#include <arpa/inet.h>
#include <linux/rtnetlink.h>
#include <stdlib.h>
#include <string.h>

static IpsecAddressFamily_t MapXfrmAddressFamily(uint16_t usFamily)
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

static IpsecMode_t MapXfrmMode(uint8_t ucMode)
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

static IpsecError_t ConvertXfrmAddress(
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

static IpsecError_t CopyXfrmAlgorithmName(
    char *pcDestination,
    size_t zDestinationLength,
    const char *pcAlgorithmName,
    size_t zAlgorithmNameLength)
{
    size_t zLength = strnlen(pcAlgorithmName, zAlgorithmNameLength);

    return CopyIpsecString(pcDestination, zDestinationLength,
                           (const uint8_t *)pcAlgorithmName, zLength);
}

static IpsecError_t ParseXfrmStateAttribute(
    const struct rtattr *pAttribute,
    IpsecXfrmStateInfo_t *pInfo)
{
    const struct xfrm_algo *pAlgorithm;
    const struct xfrm_algo_auth *pAuthAlgorithm;
    const struct xfrm_algo_aead *pAeadAlgorithm;
    const struct xfrm_replay_state_esn *pReplay;
    size_t zPayloadLength = (size_t)RTA_PAYLOAD(pAttribute);
    IpsecError_t eError = IPSEC_OK;

    switch (pAttribute->rta_type) {
    case XFRMA_ALG_CRYPT:
        if (sizeof(*pAlgorithm) > zPayloadLength) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            pAlgorithm = (const struct xfrm_algo *)RTA_DATA(pAttribute);
            eError = CopyXfrmAlgorithmName(
                pInfo->acEncryptionAlgorithm,
                sizeof(pInfo->acEncryptionAlgorithm),
                pAlgorithm->alg_name, sizeof(pAlgorithm->alg_name));
        }
        break;
    case XFRMA_ALG_AUTH:
        if (sizeof(*pAlgorithm) > zPayloadLength) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            pAlgorithm = (const struct xfrm_algo *)RTA_DATA(pAttribute);
            eError = CopyXfrmAlgorithmName(
                pInfo->acIntegrityAlgorithm,
                sizeof(pInfo->acIntegrityAlgorithm),
                pAlgorithm->alg_name, sizeof(pAlgorithm->alg_name));
        }
        break;
    case XFRMA_ALG_AUTH_TRUNC:
        if (sizeof(*pAuthAlgorithm) > zPayloadLength) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            pAuthAlgorithm =
                (const struct xfrm_algo_auth *)RTA_DATA(pAttribute);
            eError = CopyXfrmAlgorithmName(
                pInfo->acIntegrityAlgorithm,
                sizeof(pInfo->acIntegrityAlgorithm),
                pAuthAlgorithm->alg_name,
                sizeof(pAuthAlgorithm->alg_name));
        }
        break;
    case XFRMA_ALG_AEAD:
        if (sizeof(*pAeadAlgorithm) > zPayloadLength) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            pAeadAlgorithm =
                (const struct xfrm_algo_aead *)RTA_DATA(pAttribute);
            eError = CopyXfrmAlgorithmName(
                pInfo->acAeadAlgorithm,
                sizeof(pInfo->acAeadAlgorithm),
                pAeadAlgorithm->alg_name,
                sizeof(pAeadAlgorithm->alg_name));
        }
        break;
    case XFRMA_REPLAY_ESN_VAL:
        if (sizeof(*pReplay) > zPayloadLength) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            pReplay =
                (const struct xfrm_replay_state_esn *)RTA_DATA(pAttribute);
            pInfo->uiReplayWindow = pReplay->replay_window;
            pInfo->bEsn = true;
        }
        break;
    default:
        /* Unknown attributes are forward-compatible. */
        break;
    }

    return eError;
}

static IpsecError_t AppendXfrmState(
    IpsecXfrmStateList_t *pList,
    IpsecXfrmStateInfo_t **ppInfo)
{
    IpsecXfrmStateInfo_t *pNewItems;
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
            pNewItems = (IpsecXfrmStateInfo_t *)realloc(
                pList->pItems, zAllocationSize);
            if (NULL == pNewItems) {
                eError = IPSEC_ERR_NO_MEMORY;
            }
            else {
                pList->pItems = pNewItems;
                pList->uiCount = uiNewCount;
                *ppInfo = &pNewItems[uiNewCount - 1U];
                memset(*ppInfo, 0, sizeof(**ppInfo));
                eError = IPSEC_OK;
            }
        }
    }
    return eError;
}

IpsecError_t ParseXfrmStateMessage(
    const struct nlmsghdr *pHeader,
    void *pvUserData)
{
    IpsecXfrmStateList_t *pList = (IpsecXfrmStateList_t *)pvUserData;
    const struct xfrm_usersa_info *pKernelInfo;
    IpsecXfrmStateInfo_t *pInfo = NULL;
    struct rtattr *pAttribute;
    int32_t iAttributeLength;
    IpsecError_t eError;

    if ((NULL == pHeader) || (NULL == pList) ||
        (XFRM_MSG_NEWSA != pHeader->nlmsg_type) ||
        (NLMSG_PAYLOAD(pHeader, 0) < sizeof(*pKernelInfo))) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        pKernelInfo =
            (const struct xfrm_usersa_info *)NLMSG_DATA(pHeader);
        eError = AppendXfrmState(pList, &pInfo);
    }

    if (IPSEC_OK == eError) {
        pInfo->eFamily = MapXfrmAddressFamily(pKernelInfo->family);
        eError = ConvertXfrmAddress(pKernelInfo->family,
                                    &pKernelInfo->saddr,
                                    pInfo->acSource,
                                    sizeof(pInfo->acSource));
    }
    else {
        /* Preserve header/allocation error. */
    }
    if (IPSEC_OK == eError) {
        eError = ConvertXfrmAddress(pKernelInfo->family,
                                    &pKernelInfo->id.daddr,
                                    pInfo->acDestination,
                                    sizeof(pInfo->acDestination));
    }
    else {
        /* Preserve source conversion error. */
    }
    if (IPSEC_OK == eError) {
        pInfo->uiProtocol = pKernelInfo->id.proto;
        pInfo->uiSpi = ntohl(pKernelInfo->id.spi);
        pInfo->uiReqid = pKernelInfo->reqid;
        pInfo->eMode = MapXfrmMode(pKernelInfo->mode);
        pInfo->bEsn = 0U != (pKernelInfo->flags & XFRM_STATE_ESN);
        pInfo->uiReplayWindow = pKernelInfo->replay_window;
        pInfo->ullPacketCount = pKernelInfo->curlft.packets;
        pInfo->ullByteCount = pKernelInfo->curlft.bytes;
        pInfo->ullAddTimeSeconds = pKernelInfo->curlft.add_time;
        pInfo->ullUseTimeSeconds = pKernelInfo->curlft.use_time;
        pInfo->ullSoftByteLimit = pKernelInfo->lft.soft_byte_limit;
        pInfo->ullHardByteLimit = pKernelInfo->lft.hard_byte_limit;
        pInfo->ullSoftPacketLimit = pKernelInfo->lft.soft_packet_limit;
        pInfo->ullHardPacketLimit = pKernelInfo->lft.hard_packet_limit;

        iAttributeLength = (int32_t)pHeader->nlmsg_len -
                           (int32_t)NLMSG_LENGTH(sizeof(*pKernelInfo));
        pAttribute = (struct rtattr *)(
            (uint8_t *)pKernelInfo + NLMSG_ALIGN(sizeof(*pKernelInfo)));
        while (RTA_OK(pAttribute, iAttributeLength) &&
               (IPSEC_OK == eError)) {
            eError = ParseXfrmStateAttribute(pAttribute, pInfo);
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
        /* Preserve address conversion error. */
    }

    return eError;
}

IpsecError_t GetIpsecXfrmStates(
    IpsecContext_t *pContext,
    IpsecXfrmStateList_t *pList)
{
    struct xfrm_usersa_id Request;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pList)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pList, 0, sizeof(*pList));
        memset(&Request, 0, sizeof(Request));
        Request.family = AF_UNSPEC;
        eError = ExecuteNetlinkDump(NETLINK_XFRM, XFRM_MSG_GETSA,
                                    &Request, sizeof(Request),
                                    ParseXfrmStateMessage, pList);
    }
    if (IPSEC_OK != eError) {
        LogIpsec(pContext, IPSEC_LOG_ERROR,
                 "failed to query XFRM states: %s",
                 GetIpsecErrorString(eError));
        FreeIpsecXfrmStateList(pList);
    }
    else {
        /* Return XFRM states. */
    }
    return eError;
}

void FreeIpsecXfrmStateList(IpsecXfrmStateList_t *pList)
{
    if (NULL != pList) {
        free(pList->pItems);
        memset(pList, 0, sizeof(*pList));
    }
    else {
        /* NULL free is safe. */
    }
}
