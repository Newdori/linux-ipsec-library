#include "kernel_libipsec_internal.h"

#include <linux/if.h>
#include <linux/if_link.h>
#include <linux/if_tun.h>
#include <linux/rtnetlink.h>
#include <string.h>

/* Bounds checking is shared at every nesting level; unknown attributes are
 * ignored, but malformed/duplicate identity attributes are never accepted.
 */
static IpsecError_t FindTunAttribute(const uint8_t *pucData, size_t zLength,
    uint16_t usType, const uint8_t **ppucValue, size_t *pzLength)
{
    *ppucValue = NULL;
    *pzLength = 0U;
    while (zLength > 0U) {
        struct rtattr Attribute;
        size_t zStep;
        if (zLength < sizeof(Attribute)) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        memcpy(&Attribute, pucData, sizeof(Attribute));
        zStep = RTA_ALIGN(Attribute.rta_len);
        if ((Attribute.rta_len < sizeof(Attribute)) || (zStep > zLength)) {
            return IPSEC_ERR_NETLINK_PARSE;
        }
        if ((Attribute.rta_type & NLA_TYPE_MASK) == usType) {
            if (NULL != *ppucValue) {
                return IPSEC_ERR_NETLINK_PARSE;
            }
            *ppucValue = pucData + sizeof(Attribute);
            *pzLength = Attribute.rta_len - sizeof(Attribute);
        }
        pucData += zStep;
        zLength -= zStep;
    }
    return IPSEC_OK;
}

IpsecError_t ParseIpsecTunMessage(const struct nlmsghdr *pHeader, void *pvData)
{
    IpsecTunCandidates_t *pCandidates = (IpsecTunCandidates_t *)pvData;
    struct ifinfomsg Link;
    IpsecTunCandidate_t Candidate = {0};
    const uint8_t *pucAttributes;
    const uint8_t *pucValue;
    const uint8_t *pucNested;
    const uint8_t *pucKind;
    size_t zAttributes;
    size_t zLength;
    size_t zNested;
    size_t zKind;
    IpsecError_t eError;
    if ((NULL == pHeader) || (NULL == pCandidates) ||
        (RTM_NEWLINK != pHeader->nlmsg_type) ||
        (pHeader->nlmsg_len < NLMSG_LENGTH(sizeof(Link)))) {
        return IPSEC_ERR_NETLINK_PARSE;
    }
    memcpy(&Link, NLMSG_DATA(pHeader), sizeof(Link));
    if (Link.ifi_index <= 0) {
        return IPSEC_ERR_NETLINK_PARSE;
    }
    pucAttributes = (const uint8_t *)NLMSG_DATA(pHeader) + NLMSG_ALIGN(sizeof(Link));
    zAttributes = pHeader->nlmsg_len - NLMSG_LENGTH(sizeof(Link));
    eError = FindTunAttribute(pucAttributes, zAttributes, IFLA_IFNAME, &pucValue, &zLength);
    if ((IPSEC_OK != eError) || (NULL == pucValue) || (zLength < 2U) ||
        (zLength > sizeof(Candidate.acName)) || ('\0' != pucValue[zLength - 1U]) ||
        (NULL != memchr(pucValue, '\0', zLength - 1U))) {
        return IPSEC_ERR_NETLINK_PARSE;
    }
    memcpy(Candidate.acName, pucValue, zLength);
    Candidate.uiIndex = (uint32_t)Link.ifi_index;
    Candidate.bUp = 0U != (Link.ifi_flags & IFF_UP);
    eError = FindTunAttribute(pucAttributes, zAttributes, IFLA_LINKINFO, &pucNested, &zNested);
    if ((IPSEC_OK == eError) && (NULL != pucNested)) {
        eError = FindTunAttribute(pucNested, zNested, IFLA_INFO_KIND, &pucKind, &zKind);
        if ((IPSEC_OK == eError) && (4U == zKind) &&
            (0 == memcmp(pucKind, "tun", 4U))) {
            const uint8_t *pucTun;
            size_t zTun;
            eError = FindTunAttribute(pucNested, zNested, IFLA_INFO_DATA, &pucTun, &zTun);
            if ((IPSEC_OK == eError) && (NULL != pucTun)) {
                eError = FindTunAttribute(pucTun, zTun, IFLA_TUN_TYPE, &pucValue, &zLength);
                if ((IPSEC_OK == eError) && (NULL != pucValue)) {
                    if (1U != zLength) {
                        return IPSEC_ERR_NETLINK_PARSE;
                    }
                    Candidate.bTun = IFF_TUN == pucValue[0];
                }
            }
        }
    }
    if (IPSEC_OK == eError) {
        if (pCandidates->uiCount >= IPSEC_TUN_CANDIDATE_LIMIT) {
            return IPSEC_ERR_BUFFER_TOO_SMALL;
        }
        pCandidates->aItems[pCandidates->uiCount++] = Candidate;
    }
    return eError;
}

IpsecError_t SelectIpsecTun(const IpsecTunCandidates_t *pCandidates,
    const char *pcRequestedName, const char *pcExcludedName, IpsecDatapathStatus_t *pStatus)
{
    const IpsecTunCandidate_t *pSelected = NULL;
    uint32_t uiValid = 0U;
    uint32_t uiIndex;
    for (uiIndex = 0U; uiIndex < pCandidates->uiCount; uiIndex++) {
        const IpsecTunCandidate_t *pItem = &pCandidates->aItems[uiIndex];
        bool bExplicit = '\0' != pcRequestedName[0];
        if (bExplicit && (0 != strcmp(pcRequestedName, pItem->acName))) {
            continue;
        }
        if (0 == strcmp(pcExcludedName, pItem->acName)) {
            if (bExplicit) {
                return IPSEC_ERR_RESOURCE_CONFLICT;
            }
            continue;
        }
        if (!pItem->bTun || !pItem->bUp) {
            if (bExplicit) {
                return IPSEC_ERR_DATAPATH_UNAVAILABLE;
            }
            continue;
        }
        pSelected = pItem;
        uiValid++;
    }
    if (0U == uiValid) {
        return IPSEC_ERR_INTERFACE_NOT_FOUND;
    }
    if (uiValid > 1U) {
        /* A route alone does not prove charon ownership. Never guess which
         * of several UP TUNs belongs to the selected VICI daemon.
         */
        return IPSEC_ERR_INTERFACE_AMBIGUOUS;
    }
    pStatus->bTunInterfacePresent = true;
    pStatus->bTunInterfaceUp = true;
    pStatus->uiTunInterfaceIndex = pSelected->uiIndex;
    pStatus->uiTunRouteCount = pSelected->uiRouteCount;
    memcpy(pStatus->acTunInterfaceName, pSelected->acName, sizeof(pSelected->acName));
    pStatus->bReady = true;
    return IPSEC_OK;
}
