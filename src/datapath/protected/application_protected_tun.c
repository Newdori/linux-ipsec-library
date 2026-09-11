#include "application_protected_internal.h"
#include "../common/datapath_ops.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

static IpsecError_t MapProtectedApplicationError(IpsecError_t eDefault)
{
    return ((EPERM == errno) || (EACCES == errno)) ? IPSEC_ERR_PERMISSION : eDefault;
}

static void SetProtectedApplicationIfreqName(struct ifreq *pRequest, const char *pcName)
{
    memset(pRequest, 0, sizeof(*pRequest));
    memcpy(pRequest->ifr_name, pcName, strlen(pcName) + 1U);
}

static bool ResolveProtectedApplicationTunName(
    const IpsecProtectedApplicationState_t *pState, struct ifreq *pRequest)
{
    memset(pRequest, 0, sizeof(*pRequest));
    return (0 == ioctl(pState->iTunFd, TUNGETIFF, pRequest)) &&
        (0 != (pRequest->ifr_flags & IFF_TUN)) &&
        (NULL != memchr(pRequest->ifr_name, '\0', IFNAMSIZ)) &&
        (0 == strncmp(pRequest->ifr_name, pState->acTunName, IFNAMSIZ)) &&
        ('\0' != pRequest->ifr_name[0]) &&
        (NULL == strchr(pRequest->ifr_name, '/')) &&
        (0 != strcmp(pRequest->ifr_name, ".")) &&
        (0 != strcmp(pRequest->ifr_name, "..")) &&
        (0 != strcmp(pRequest->ifr_name, "all")) &&
        (0 != strcmp(pRequest->ifr_name, "default"));
}

static IpsecError_t ReadProtectedApplicationSysctl(int32_t iDirectory,
    const char *pcSetting, uint32_t *puiValue)
{
    char acValue[4] = {0};
    int32_t iSetting = (int32_t)openat(iDirectory, pcSetting,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    ssize_t lLength;
    if (iSetting < 0) {
        return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
    }
    do {
        lLength = read(iSetting, acValue, sizeof(acValue));
    } while ((lLength < 0) && (EINTR == errno));
    (void)close(iSetting);
    if ((2 != lLength) || (acValue[0] < '0') || (acValue[0] > '2') ||
        ('\n' != acValue[1])) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    *puiValue = (uint32_t)(acValue[0] - '0');
    return IPSEC_OK;
}

static IpsecError_t ConfigureProtectedApplicationReversePath(
    const IpsecProtectedApplicationState_t *pState, bool bConfigure)
{
    struct ifreq Request;
    int32_t iDirectory;
    int32_t iInterface;
    int32_t iAll;
    int32_t iSetting;
    uint32_t uiAll = 0U;
    uint32_t uiInterface = 0U;
    IpsecError_t eError;
    if (!ResolveProtectedApplicationTunName(pState, &Request)) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    iDirectory = (int32_t)open("/proc/sys/net/ipv4/conf",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (iDirectory < 0) {
        return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
    }
    /* all is read-only: Linux uses max(all, interface). Only the exclusively
     * created non-persistent TUN may be changed; never the NIC/charon TUN. */
    iAll = (int32_t)openat(iDirectory, "all",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    eError = (iAll < 0) ? MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE) :
        ReadProtectedApplicationSysctl(iAll, "rp_filter", &uiAll);
    if (iAll >= 0) {
        (void)close(iAll);
    }
    if (IPSEC_OK != eError) {
        (void)close(iDirectory);
        return eError;
    }
    iInterface = (int32_t)openat(iDirectory, Request.ifr_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (iInterface < 0) {
        eError = MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
        (void)close(iDirectory);
        return eError;
    }
    (void)close(iDirectory);
    eError = ReadProtectedApplicationSysctl(iInterface, "rp_filter", &uiInterface);
    if ((IPSEC_OK == eError) && bConfigure && (2U != uiInterface)) {
        iSetting = (int32_t)openat(iInterface, "rp_filter",
            O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
        if (iSetting < 0) {
            eError = MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
        }
        else {
            ssize_t lLength;
            do {
                lLength = write(iSetting, "2\n", 2U);
            } while ((lLength < 0) && (EINTR == errno));
            if (2 != lLength) {
                eError = MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
            }
            (void)close(iSetting);
        }
        if (IPSEC_OK == eError) {
            eError = ReadProtectedApplicationSysctl(iInterface, "rp_filter", &uiInterface);
            if ((IPSEC_OK == eError) && (2U != uiInterface)) {
                eError = IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
            }
        }
    }
    (void)close(iInterface);
    if ((IPSEC_OK == eError) && (1U == ((uiAll > uiInterface) ? uiAll : uiInterface))) {
        /* Fail early if another actor later restores strict filtering. */
        eError = IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    return eError;
}

static IpsecError_t ConfigureProtectedApplicationAddress(
    const IpsecProtectedApplicationState_t *pState, int32_t iSocket,
    bool bConfigure)
{
    struct ifreq Request;
    struct sockaddr_in Address = {0};
    const uint8_t aucLoopback[4] = {127U, 0U, 0U, 1U};
    const uint8_t aucMask[4] = {255U, 255U, 255U, 255U};
    if (!ResolveProtectedApplicationTunName(pState, &Request)) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    /* Linux fib_validate_source rejects an unnumbered ingress device even
     * with loose RPF when the reverse route uses another device. Give only
     * our private TUN a host-scoped loopback /32 anchor. It is NOT an ESP/TS
     * address. Do not duplicate the physical IP, route peers into this TUN,
     * enable route_localnet, or disable global reverse-path validation.
     * Linux assigns loopback addresses RT_SCOPE_HOST (no connected prefix).
     * Closing the non-persistent TUN removes its address/local route. */
    if (bConfigure) {
        if (0 == ioctl(iSocket, SIOCGIFADDR, &Request)) {
            /* Do not replace an address installed by another actor. */
            return IPSEC_ERR_RESOURCE_CONFLICT;
        }
        if (EADDRNOTAVAIL != errno) {
            return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
        }
        SetProtectedApplicationIfreqName(&Request, pState->acTunName);
        Address.sin_family = AF_INET;
        memcpy(&Address.sin_addr, aucLoopback, sizeof(aucLoopback));
        memcpy(&Request.ifr_addr, &Address, sizeof(Address));
        if (0 != ioctl(iSocket, SIOCSIFADDR, &Request)) {
            return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
        }
        memcpy(&Address.sin_addr, aucMask, sizeof(aucMask));
        memcpy(&Request.ifr_netmask, &Address, sizeof(Address));
        if (0 != ioctl(iSocket, SIOCSIFNETMASK, &Request)) {
            return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
        }
    }
    SetProtectedApplicationIfreqName(&Request, pState->acTunName);
    if (0 != ioctl(iSocket, SIOCGIFADDR, &Request)) {
        return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
    }
    memcpy(&Address, &Request.ifr_addr, sizeof(Address));
    if ((AF_INET != Address.sin_family) ||
        (0 != memcmp(&Address.sin_addr, aucLoopback, sizeof(aucLoopback)))) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    if (0 != ioctl(iSocket, SIOCGIFNETMASK, &Request)) {
        return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
    }
    memcpy(&Address, &Request.ifr_netmask, sizeof(Address));
    return ((AF_INET == Address.sin_family) &&
        (0 == memcmp(&Address.sin_addr, aucMask, sizeof(aucMask)))) ?
        IPSEC_OK : IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
}

static IpsecError_t DisableProtectedApplicationIpv6(
    const IpsecProtectedApplicationState_t *pState)
{
    struct ifreq Request;
    char acValue[4] = {0};
    int32_t iDirectory;
    int32_t iInterface;
    int32_t iSetting;
    int32_t iSavedErrno;
    ssize_t lLength;
    IpsecError_t eError = IPSEC_OK;

    /* Resolve from the exclusively created, non-persistent TUN fd. Never
     * modify conf/all, conf/default, the NIC or charon's TUN. */
    if (!ResolveProtectedApplicationTunName(pState, &Request)) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    iDirectory = (int32_t)open("/proc/sys/net/ipv6/conf",
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (iDirectory < 0) {
        if (ENOENT == errno) {
            int32_t iIpv6 = (int32_t)socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
            if (iIpv6 < 0) {
                /* IPv6 compiled out / disabled at boot needs no sysctl. */
                return (EAFNOSUPPORT == errno) ? IPSEC_OK :
                    MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
            }
            (void)close(iIpv6);
        }
        return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
    }
    iInterface = (int32_t)openat(iDirectory, Request.ifr_name,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    iSavedErrno = errno;
    (void)close(iDirectory);
    errno = iSavedErrno;
    if (iInterface < 0) {
        return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
    }
    iSetting = (int32_t)openat(iInterface, "disable_ipv6",
        O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (iSetting < 0) {
        eError = MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
    }
    else {
        do {
            lLength = write(iSetting, "1\n", 2U);
        } while ((lLength < 0) && (EINTR == errno));
        if (2 != lLength) {
            eError = MapProtectedApplicationError(
                IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
        }
        else {
            /* Reopen for verification; do not assume /proc sysctls are
             * seekable after a write. */
        }
        (void)close(iSetting);
    }
    if (IPSEC_OK == eError) {
        iSetting = (int32_t)openat(iInterface, "disable_ipv6",
            O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
        if (iSetting < 0) {
            eError = MapProtectedApplicationError(
                IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
        }
        else {
            do {
                lLength = read(iSetting, acValue, sizeof(acValue));
            } while ((lLength < 0) && (EINTR == errno));
            if ((2 != lLength) || ('1' != acValue[0]) ||
                ('\n' != acValue[1])) {
                eError = IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
            }
            (void)close(iSetting);
        }
    }
    else {
        /* Preserve the write/open error. */
    }
    (void)close(iInterface);
    return eError;
}

IpsecError_t CreateIpsecProtectedApplicationEndpoint(IpsecContext_t *pContext, IpsecProtectedApplicationState_t *pState)
{
    struct ifreq Request;
    const uint16_t usTunFlags = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL;
    int32_t iSocket = (int32_t)socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    IpsecError_t eError = IPSEC_OK;
    if (iSocket < 0) {
        return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
    }
    SetProtectedApplicationIfreqName(&Request, pState->acEgressName);
    if (0 != ioctl(iSocket, SIOCGIFINDEX, &Request)) {
        eError = MapProtectedApplicationError(IPSEC_ERR_INTERFACE_NOT_FOUND);
    }
    else {
        pState->uiEgressIndex = (uint32_t)Request.ifr_ifindex;
        if ((0 != ioctl(iSocket, SIOCGIFFLAGS, &Request)) ||
            (0 == (Request.ifr_flags & IFF_UP))) {
            eError = IPSEC_ERR_DATAPATH_UNAVAILABLE;
        }
        else if ((0 != ioctl(iSocket, SIOCGIFHWADDR, &Request)) ||
                 (ARPHRD_ETHER != Request.ifr_hwaddr.sa_family)) {
            eError = IPSEC_ERR_NOT_SUPPORTED;
        }
    }
    if (IPSEC_OK == eError) {
        eError = InspectIpsecProtectedApplicationFilters(pState, true);
    }
    if ((IPSEC_OK == eError) && (IPSEC_DATAPATH_KERNEL_XFRM == pContext->Datapath.eActiveType)) {
        eError = ValidateXfrmSoftwarePath();
    }
    if (IPSEC_OK == eError) {
        pState->iTunFd = (int32_t)open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
        if (pState->iTunFd < 0) {
            eError = MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
        }
        else {
            SetProtectedApplicationIfreqName(&Request, pState->acTunName);
            memcpy(&Request.ifr_flags, &usTunFlags, sizeof(usTunFlags));
            if (0 != ioctl(pState->iTunFd, TUNSETIFF, &Request)) {
                eError = ((EBUSY == errno) || (EEXIST == errno)) ?
                    IPSEC_ERR_RESOURCE_CONFLICT : MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
            }
            else if (0 != ioctl(pState->iTunFd, TUNSETOFFLOAD, 0UL)) {
                eError = MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
            }
            else if (0 != ioctl(iSocket, SIOCGIFINDEX, &Request)) {
                eError = IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
            }
            else {
                pState->uiTunIndex = (uint32_t)Request.ifr_ifindex;
                Request.ifr_mtu = IPSEC_PROTECTED_PACKET_CAPACITY;
                if (0 != ioctl(iSocket, SIOCSIFMTU, &Request)) {
                    eError = MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
                }
                else {
                    eError = DisableProtectedApplicationIpv6(pState);
                    if (IPSEC_OK == eError) {
                        eError = ConfigureProtectedApplicationReversePath(pState, true);
                        if (IPSEC_OK != eError) {
                            LogIpsec(pContext, IPSEC_LOG_ERROR,
                                "protected TUN %s: cannot configure/verify owned rp_filter=2: %s",
                                pState->acTunName, GetIpsecErrorString(eError));
                        }
                        else {
                            LogIpsec(pContext, IPSEC_LOG_INFO,
                                "protected TUN %s: rp_filter=2 (loose); global/NIC/charon settings unchanged",
                                pState->acTunName);
                        }
                    }
                    else {
                        LogIpsec(pContext, IPSEC_LOG_ERROR,
                            "protected TUN %s: cannot disable IPv6 on the owned endpoint "
                            "before interface UP: %s; check per-interface proc sysctl access",
                            pState->acTunName, GetIpsecErrorString(eError));
                    }
                    if (IPSEC_OK == eError) {
                        eError = ConfigureProtectedApplicationAddress(pState, iSocket, true);
                        if (IPSEC_OK != eError) {
                            LogIpsec(pContext, IPSEC_LOG_ERROR,
                                "protected TUN %s: cannot initialize/verify host-scoped IPv4 /32 anchor: %s",
                                pState->acTunName, GetIpsecErrorString(eError));
                        }
                    }
                    if (IPSEC_OK == eError) {
                        Request.ifr_flags = IFF_UP;
                        if (0 != ioctl(iSocket, SIOCSIFFLAGS, &Request)) {
                            eError = MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
                        }
                    }
                }
            }
        }
    }
    (void)close(iSocket);
    return eError;
}

IpsecError_t InspectIpsecProtectedApplicationEndpoint(const IpsecProtectedApplicationState_t *pState)
{
    struct ifreq Request;
    int32_t iSocket;
    IpsecError_t eError = IPSEC_OK;
    if (pState->iTunFd < 0) {
        return IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE;
    }
    iSocket = (int32_t)socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (iSocket < 0) {
        return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_RECEIVE);
    }
    SetProtectedApplicationIfreqName(&Request, pState->acTunName);
    if ((0 != ioctl(iSocket, SIOCGIFINDEX, &Request)) ||
        ((uint32_t)Request.ifr_ifindex != pState->uiTunIndex) ||
        (0 != ioctl(iSocket, SIOCGIFFLAGS, &Request)) ||
        (0 == (Request.ifr_flags & IFF_UP))) {
        eError = IPSEC_ERR_INTERFACE_NOT_FOUND;
    }
    if (IPSEC_OK == eError) {
        SetProtectedApplicationIfreqName(&Request, pState->acEgressName);
        if ((0 != ioctl(iSocket, SIOCGIFINDEX, &Request)) ||
            ((uint32_t)Request.ifr_ifindex != pState->uiEgressIndex) ||
            (0 != ioctl(iSocket, SIOCGIFFLAGS, &Request)) ||
            (0 == (Request.ifr_flags & IFF_UP))) {
            eError = IPSEC_ERR_INTERFACE_NOT_FOUND;
        }
    }
    if (IPSEC_OK == eError) {
        eError = ConfigureProtectedApplicationAddress(pState, iSocket, false);
    }
    (void)close(iSocket);
    if (IPSEC_OK == eError) {
        eError = ConfigureProtectedApplicationReversePath(pState, false);
    }
    return eError;
}

void DestroyIpsecProtectedApplicationEndpoint(IpsecContext_t *pContext, IpsecProtectedApplicationState_t *pState)
{
    IpsecError_t eError = RemoveIpsecProtectedApplicationFilters(pState);
    if (IPSEC_OK != eError) {
        LogIpsec(pContext, IPSEC_LOG_WARNING,
            "protected APPLICATION filter cleanup failed on %s: %s; inspect reserved TC priorities",
            pState->acEgressName, GetIpsecErrorString(eError));
    }
    if (pState->iTunFd >= 0) {
        (void)close(pState->iTunFd); /* Non-persistent, library-owned TUN only. */
        pState->iTunFd = -1;
    }
}

static IpsecError_t WaitProtectedApplicationDescriptor(int32_t iFd, int16_t sEvents,
                                         uint64_t ullDeadlineMs)
{
    struct pollfd Descriptor = {0};
    int32_t iResult;
    uint64_t ullNow;
    uint64_t ullRemaining;
    do {
        ullNow = GetIpsecMonotonicMilliseconds();
        ullRemaining = (ullNow < ullDeadlineMs) ? ullDeadlineMs - ullNow : 0U;
        Descriptor.fd = iFd;
        Descriptor.events = sEvents;
        Descriptor.revents = 0;
        iResult = (int32_t)poll(&Descriptor, 1U,
            (ullRemaining > INT_MAX) ? INT_MAX : (int32_t)ullRemaining);
    } while ((((iResult < 0) && (EINTR == errno)) ||
              ((0 == iResult) && (ullRemaining > INT_MAX))) &&
             (GetIpsecMonotonicMilliseconds() < ullDeadlineMs));
    if (0 == iResult) {
        return IPSEC_ERR_PACKET_TIMEOUT;
    }
    if ((iResult < 0) || (0 != (Descriptor.revents & (POLLERR | POLLHUP | POLLNVAL)))) {
        return IPSEC_ERR_PROTECTED_RECEIVE;
    }
    return (0 != (Descriptor.revents & sEvents)) ? IPSEC_OK : IPSEC_ERR_PROTECTED_RECEIVE;
}

IpsecError_t ReceiveIpsecProtectedApplicationPacket(IpsecProtectedApplicationState_t *pState,
    IpsecProtectedPacket_t *pPacket, uint32_t uiTimeoutMs)
{
    uint64_t ullDeadline = GetIpsecMonotonicMilliseconds() + uiTimeoutMs;
    ssize_t lLength;
    IpsecError_t eError;
    do {
        eError = WaitProtectedApplicationDescriptor(pState->iTunFd, POLLIN, ullDeadline);
        if (IPSEC_OK != eError) {
            return eError;
        }
        lLength = read(pState->iTunFd, pPacket->pucData, IPSEC_PROTECTED_PACKET_CAPACITY);
        if (lLength > 0) {
            pPacket->zLength = (size_t)lLength;
            return IPSEC_OK;
        }
        if ((lLength < 0) && ((EINTR == errno) || (EAGAIN == errno))) {
            continue;
        }
        return MapProtectedApplicationError(IPSEC_ERR_PROTECTED_RECEIVE);
    } while (GetIpsecMonotonicMilliseconds() < ullDeadline);
    return IPSEC_ERR_PACKET_TIMEOUT;
}

IpsecError_t SubmitIpsecProtectedApplicationPacket(IpsecProtectedApplicationState_t *pState,
    const IpsecProtectedPacket_t *pPacket)
{
    /* One non-blocking packet write. Never retry a partial packet. */
    ssize_t lLength = write(pState->iTunFd, pPacket->pucData, pPacket->zLength);
    if ((lLength < 0) && ((EAGAIN == errno) || (EINTR == errno))) {
        return IPSEC_ERR_PACKET_TIMEOUT;
    }
    return ((lLength >= 0) && ((size_t)lLength == pPacket->zLength)) ?
        IPSEC_OK : MapProtectedApplicationError(IPSEC_ERR_PROTECTED_SUBMIT);
}
