#include "vici_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

static uint64_t GetViciCommandDeadline(const IpsecContext_t *pContext)
{
    uint64_t ullDeadlineMs;
    uint64_t ullNowMs;

    if (0U != pContext->ullCommandDeadlineMs) {
        ullDeadlineMs = pContext->ullCommandDeadlineMs;
    }
    else {
        ullNowMs = GetIpsecMonotonicMilliseconds();
        if ((0U == ullNowMs) ||
            ((UINT64_MAX - pContext->uiCommandTimeoutMs) < ullNowMs)) {
            ullDeadlineMs = 0U;
        }
        else {
            ullDeadlineMs = ullNowMs + pContext->uiCommandTimeoutMs;
        }
    }

    return ullDeadlineMs;
}

static IpsecError_t WaitViciSocket(
    int32_t iSocket,
    int16_t sEvents,
    uint64_t ullDeadlineMs,
    int32_t iCancelFd)
{
    struct pollfd aPollDescriptors[2];
    uint64_t ullNowMs;
    uint64_t ullRemainingMs;
    int32_t iTimeoutMs;
    int32_t iResult;
    IpsecError_t eError;

    memset(aPollDescriptors, 0, sizeof(aPollDescriptors));
    aPollDescriptors[0].fd = iSocket;
    aPollDescriptors[0].events = sEvents;
    aPollDescriptors[1].fd = iCancelFd;
    aPollDescriptors[1].events = POLLIN;

    while (true) {
        ullNowMs = GetIpsecMonotonicMilliseconds();
        if ((0U == ullNowMs) || (ullDeadlineMs <= ullNowMs)) {
            eError = IPSEC_ERR_VICI_TIMEOUT;
            break;
        }
        else {
            ullRemainingMs = ullDeadlineMs - ullNowMs;
            iTimeoutMs = (INT32_MAX < ullRemainingMs) ? INT32_MAX :
                         (int32_t)ullRemainingMs;
            iResult = (int32_t)poll(aPollDescriptors, 2U, iTimeoutMs);
            if (0 < iResult) {
                if (0 != aPollDescriptors[1].revents) {
                    eError = IPSEC_ERR_CANCELLED;
                }
                else if (0 != (aPollDescriptors[0].revents & sEvents)) {
                    eError = IPSEC_OK;
                }
                else {
                    eError = IPSEC_ERR_VICI_TRANSPORT;
                }
                break;
            }
            else if (0 == iResult) {
                eError = IPSEC_ERR_VICI_TIMEOUT;
                break;
            }
            else if (EINTR != errno) {
                eError = IPSEC_ERR_VICI_TRANSPORT;
                break;
            }
            else {
                /* Retry interrupted poll with the original deadline. */
            }
        }
    }

    return eError;
}

static IpsecError_t TransferViciBytes(
    int32_t iSocket,
    uint8_t *pucData,
    uint32_t uiLength,
    bool bSend,
    uint64_t ullDeadlineMs,
    int32_t iCancelFd)
{
    uint32_t uiOffset = 0U;
    ssize_t lResult;
    IpsecError_t eError = IPSEC_OK;

    while ((uiOffset < uiLength) && (IPSEC_OK == eError)) {
        eError = WaitViciSocket(iSocket, bSend ? POLLOUT : POLLIN,
                                ullDeadlineMs, iCancelFd);
        if (IPSEC_OK == eError) {
            if (bSend) {
                lResult = send(iSocket, pucData + uiOffset,
                               (size_t)(uiLength - uiOffset), MSG_NOSIGNAL);
            }
            else {
                lResult = recv(iSocket, pucData + uiOffset,
                               (size_t)(uiLength - uiOffset), 0);
            }

            if (0 < lResult) {
                uiOffset += (uint32_t)lResult;
            }
            else if (0 == lResult) {
                eError = IPSEC_ERR_VICI_TRANSPORT;
            }
            else if ((EINTR == errno) || (EAGAIN == errno) ||
                     (EWOULDBLOCK == errno)) {
                /* Retry with the original deadline. */
            }
            else {
                eError = IPSEC_ERR_VICI_TRANSPORT;
            }
        }
        else {
            /* Preserve wait error. */
        }
    }

    return eError;
}

IpsecError_t ConnectViciTransport(IpsecContext_t *pContext)
{
    struct sockaddr_un Address;
    int32_t iFlags;
    int32_t iSocketError = 0;
    socklen_t zSocketErrorLength = sizeof(iSocketError);
    uint64_t ullDeadlineMs;
    int32_t iResult;
    IpsecError_t eError;

    if ((NULL == pContext) || ('\0' == pContext->acViciSocketPath[0])) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else if (0 <= pContext->iViciSocket) {
        eError = IPSEC_OK;
    }
    else {
        pContext->iViciSocket = (int32_t)socket(AF_UNIX,
                                                SOCK_STREAM | SOCK_CLOEXEC,
                                                0);
        if (0 > pContext->iViciSocket) {
            eError = (EACCES == errno) ? IPSEC_ERR_PERMISSION :
                     IPSEC_ERR_VICI_CONNECT;
        }
        else {
            iFlags = (int32_t)fcntl(pContext->iViciSocket, F_GETFL, 0);
            if ((0 > iFlags) ||
                (0 > fcntl(pContext->iViciSocket, F_SETFL, iFlags | O_NONBLOCK))) {
                eError = IPSEC_ERR_VICI_CONNECT;
            }
            else {
                memset(&Address, 0, sizeof(Address));
                Address.sun_family = AF_UNIX;
                eError = CopyIpsecString(
                    Address.sun_path,
                    sizeof(Address.sun_path),
                    (const uint8_t *)pContext->acViciSocketPath,
                    strnlen(pContext->acViciSocketPath,
                            sizeof(pContext->acViciSocketPath)));
                if (IPSEC_OK == eError) {
                    iResult = (int32_t)connect(
                        pContext->iViciSocket,
                        (const struct sockaddr *)&Address,
                        sizeof(Address));
                    if (0 == iResult) {
                        eError = IPSEC_OK;
                    }
                    else if (EINPROGRESS == errno) {
                        ullDeadlineMs = GetIpsecMonotonicMilliseconds() +
                                        pContext->uiConnectTimeoutMs;
                        if ((0U != pContext->ullCommandDeadlineMs) &&
                            (pContext->ullCommandDeadlineMs < ullDeadlineMs)) {
                            ullDeadlineMs = pContext->ullCommandDeadlineMs;
                        }
                        eError = WaitViciSocket(pContext->iViciSocket, POLLOUT,
                                                ullDeadlineMs, pContext->iTransportCancelFd);
                        if (IPSEC_OK == eError) {
                            iResult = (int32_t)getsockopt(
                                pContext->iViciSocket, SOL_SOCKET, SO_ERROR,
                                &iSocketError, &zSocketErrorLength);
                            if (0 != iResult) {
                                eError = (EACCES == errno) ?
                                         IPSEC_ERR_PERMISSION :
                                         IPSEC_ERR_VICI_CONNECT;
                            }
                            else if (0 != iSocketError) {
                                eError = (EACCES == iSocketError) ?
                                         IPSEC_ERR_PERMISSION :
                                         IPSEC_ERR_VICI_CONNECT;
                            }
                            else {
                                /* Connected. */
                            }
                        }
                        else {
                            /* Preserve wait error. */
                        }
                    }
                    else {
                        eError = (EACCES == errno) ? IPSEC_ERR_PERMISSION :
                                 IPSEC_ERR_VICI_CONNECT;
                    }
                }
                else {
                    /* Preserve socket path copy error. */
                }
            }
        }

        if (IPSEC_OK != eError) {
            DisconnectViciTransport(pContext);
        }
        else {
            /* Keep connected socket. */
        }
    }

    return eError;
}

void DisconnectViciTransport(IpsecContext_t *pContext)
{
    if ((NULL != pContext) && (0 <= pContext->iViciSocket)) {
        (void)close(pContext->iViciSocket);
        pContext->iViciSocket = -1;
    }
    else {
        /* Already disconnected. */
    }
}

IpsecError_t SendViciTransportPacket(
    IpsecContext_t *pContext,
    const ViciBuffer_t *pPacket)
{
    uint32_t uiNetworkLength;
    uint64_t ullDeadlineMs;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pPacket) ||
        (VICI_MAX_SEGMENT_LENGTH < pPacket->uiLength)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ConnectViciTransport(pContext);
        if (IPSEC_OK == eError) {
            ullDeadlineMs = GetViciCommandDeadline(pContext);
            uiNetworkLength = htonl(pPacket->uiLength);
            eError = TransferViciBytes(pContext->iViciSocket,
                                       (uint8_t *)&uiNetworkLength,
                                       sizeof(uiNetworkLength), true,
                                       ullDeadlineMs, pContext->iTransportCancelFd);
            if (IPSEC_OK == eError) {
                eError = TransferViciBytes(pContext->iViciSocket,
                                           pPacket->pucData,
                                           pPacket->uiLength, true,
                                           ullDeadlineMs, pContext->iTransportCancelFd);
            }
            else {
                /* Preserve header send error. */
            }
        }
        else {
            /* Preserve connect error. */
        }

        if (IPSEC_OK != eError) {
            DisconnectViciTransport(pContext);
        }
        else {
            /* Keep transport connected. */
        }
    }

    return eError;
}

IpsecError_t ReceiveViciTransportPacket(
    IpsecContext_t *pContext,
    ViciBuffer_t *pPacket)
{
    uint32_t uiNetworkLength;
    uint32_t uiPacketLength;
    uint64_t ullDeadlineMs;
    IpsecError_t eError;

    if ((NULL == pContext) || (NULL == pPacket) ||
        (0 > pContext->iViciSocket)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        ullDeadlineMs = GetViciCommandDeadline(pContext);
        eError = TransferViciBytes(pContext->iViciSocket,
                                   (uint8_t *)&uiNetworkLength,
                                   sizeof(uiNetworkLength), false,
                                   ullDeadlineMs, pContext->iTransportCancelFd);
        if (IPSEC_OK == eError) {
            uiPacketLength = ntohl(uiNetworkLength);
            if ((0U == uiPacketLength) ||
                (VICI_MAX_SEGMENT_LENGTH < uiPacketLength)) {
                eError = IPSEC_ERR_VICI_PROTOCOL;
            }
            else {
                eError = InitializeViciBuffer(pPacket, uiPacketLength, true);
                if (IPSEC_OK == eError) {
                    pPacket->uiLength = uiPacketLength;
                    eError = TransferViciBytes(pContext->iViciSocket,
                                               pPacket->pucData,
                                               uiPacketLength, false,
                                               ullDeadlineMs, pContext->iTransportCancelFd);
                }
                else {
                    /* Preserve allocation error. */
                }
            }
        }
        else {
            /* Preserve header receive error. */
        }

        if (IPSEC_OK != eError) {
            DestroyViciBuffer(pPacket);
            DisconnectViciTransport(pContext);
        }
        else {
            /* Return received packet. */
        }
    }

    return eError;
}


IpsecError_t WaitViciTransportReadable(
    IpsecContext_t *pContext,
    uint64_t ullDeadlineMs)
{
    return WaitViciSocket(pContext->iViciSocket, POLLIN, ullDeadlineMs,
                          pContext->iTransportCancelFd);
}
