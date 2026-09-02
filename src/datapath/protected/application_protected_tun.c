#include "application_protected_internal.h"
#include "../common/datapath_ops.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/if.h>
#include <linux/if_arp.h>
#include <linux/if_tun.h>
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
    if ((IPSEC_OK == eError) && (IPSEC_DATAPATH_KERNEL_XFRM == pContext->eActiveDatapath)) {
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
                    Request.ifr_flags = IFF_UP;
                    if (0 != ioctl(iSocket, SIOCSIFFLAGS, &Request)) {
                        eError = MapProtectedApplicationError(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
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
    if ((pState->iTunFd < 0) || !pState->bRawFilter || !pState->bUdpFilter) {
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
    (void)close(iSocket);
    if (IPSEC_OK == eError) {
        eError = InspectIpsecProtectedApplicationFilters(pState, false);
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
