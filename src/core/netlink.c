#include "../internal/netlink_internal.h"

#include <errno.h>
#include <poll.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

typedef struct NetlinkRequest {
    struct nlmsghdr Header;
    uint8_t aucPayload[IPSEC_NETLINK_MAX_REQUEST_PAYLOAD];
} NetlinkRequest_t;

static IpsecError_t MapNetlinkErrno(
    int32_t iError,
    IpsecError_t eDefault)
{
    IpsecError_t eError;

    if ((EACCES == iError) || (EPERM == iError)) {
        eError = IPSEC_ERR_PERMISSION;
    }
    else {
        eError = eDefault;
    }
    return eError;
}

static IpsecError_t WaitNetlinkData(int32_t iSocket)
{
    struct pollfd Descriptor;
    int32_t iResult;
    IpsecError_t eError;

    memset(&Descriptor, 0, sizeof(Descriptor));
    Descriptor.fd = iSocket;
    Descriptor.events = POLLIN;

    do {
        iResult = (int32_t)poll(&Descriptor, 1U,
                                (int32_t)IPSEC_NETLINK_TIMEOUT_MS);
    } while ((0 > iResult) && (EINTR == errno));

    if (0 == iResult) {
        eError = IPSEC_ERR_NETLINK_RECV;
    }
    else if (0 > iResult) {
        eError = MapNetlinkErrno(errno, IPSEC_ERR_NETLINK_RECV);
    }
    else if (0 != (Descriptor.revents & (POLLERR | POLLHUP | POLLNVAL))) {
        eError = IPSEC_ERR_NETLINK_RECV;
    }
    else if (0 != (Descriptor.revents & POLLIN)) {
        eError = IPSEC_OK;
    }
    else {
        eError = IPSEC_ERR_NETLINK_RECV;
    }

    return eError;
}

static IpsecError_t SendNetlinkRequest(
    int32_t iSocket,
    const NetlinkRequest_t *pRequest)
{
    struct sockaddr_nl KernelAddress;
    struct iovec IoVector;
    struct msghdr Message;
    ssize_t lSentLength;
    IpsecError_t eError;

    memset(&KernelAddress, 0, sizeof(KernelAddress));
    KernelAddress.nl_family = AF_NETLINK;
    memset(&IoVector, 0, sizeof(IoVector));
    IoVector.iov_base = (void *)&pRequest->Header;
    IoVector.iov_len = pRequest->Header.nlmsg_len;
    memset(&Message, 0, sizeof(Message));
    Message.msg_name = &KernelAddress;
    Message.msg_namelen = sizeof(KernelAddress);
    Message.msg_iov = &IoVector;
    Message.msg_iovlen = 1U;

    do {
        lSentLength = sendmsg(iSocket, &Message, 0);
    } while ((0 > lSentLength) && (EINTR == errno));

    if (0 > lSentLength) {
        eError = MapNetlinkErrno(errno, IPSEC_ERR_NETLINK_SEND);
    }
    else if ((size_t)lSentLength != pRequest->Header.nlmsg_len) {
        eError = IPSEC_ERR_NETLINK_SEND;
    }
    else {
        eError = IPSEC_OK;
    }

    return eError;
}

static IpsecError_t ProcessNetlinkError(
    const struct nlmsghdr *pHeader)
{
    const struct nlmsgerr *pError;
    int32_t iKernelError;
    IpsecError_t eError;

    if (NLMSG_PAYLOAD(pHeader, 0) < sizeof(*pError)) {
        eError = IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        pError = (const struct nlmsgerr *)NLMSG_DATA(pHeader);
        iKernelError = -pError->error;
        if (0 == iKernelError) {
            eError = IPSEC_OK;
        }
        else {
            eError = MapNetlinkErrno(iKernelError,
                                     IPSEC_ERR_NETLINK_RECV);
        }
    }
    return eError;
}

static IpsecError_t ReceiveNetlinkDump(
    int32_t iSocket,
    uint32_t uiSequence,
    NetlinkMessageCallback_t pCallback,
    void *pvUserData)
{
    uint8_t aucBuffer[IPSEC_NETLINK_RECEIVE_LENGTH];
    struct sockaddr_nl SenderAddress;
    struct iovec IoVector;
    struct msghdr Message;
    struct nlmsghdr *pHeader;
    ssize_t lReceivedLength;
    uint32_t uiRemainingLength;
    uint32_t uiAlignedLength;
    uint32_t uiDatagramCount = 0U;
    bool bComplete = false;
    IpsecError_t eError = IPSEC_OK;

    while (!bComplete && (IPSEC_OK == eError)) {
        eError = WaitNetlinkData(iSocket);
        if (IPSEC_OK != eError) {
            break;
        }
        else {
            memset(&SenderAddress, 0, sizeof(SenderAddress));
            memset(&IoVector, 0, sizeof(IoVector));
            IoVector.iov_base = aucBuffer;
            IoVector.iov_len = sizeof(aucBuffer);
            memset(&Message, 0, sizeof(Message));
            Message.msg_name = &SenderAddress;
            Message.msg_namelen = sizeof(SenderAddress);
            Message.msg_iov = &IoVector;
            Message.msg_iovlen = 1U;

            do {
                lReceivedLength = recvmsg(iSocket, &Message, 0);
            } while ((0 > lReceivedLength) && (EINTR == errno));
        }

        if (0 > lReceivedLength) {
            eError = MapNetlinkErrno(errno, IPSEC_ERR_NETLINK_RECV);
        }
        else if ((0 == lReceivedLength) ||
                 (0 != (Message.msg_flags & MSG_TRUNC)) ||
                 (0U != SenderAddress.nl_pid)) {
            eError = IPSEC_ERR_NETLINK_RECV;
        }
        else if (UINT32_MAX < (uint64_t)lReceivedLength) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            uiRemainingLength = (uint32_t)lReceivedLength;
            pHeader = (struct nlmsghdr *)aucBuffer;
            while ((sizeof(*pHeader) <= uiRemainingLength) &&
                   (IPSEC_OK == eError) && !bComplete) {
                if ((sizeof(*pHeader) > pHeader->nlmsg_len) ||
                    (uiRemainingLength < pHeader->nlmsg_len)) {
                    eError = IPSEC_ERR_NETLINK_PARSE;
                }
                else if ((0U != (pHeader->nlmsg_flags & NLM_F_DUMP_INTR))) {
                    eError = IPSEC_ERR_NETLINK_RECV;
                }
                else if (uiSequence != pHeader->nlmsg_seq) {
                    eError = IPSEC_ERR_NETLINK_PARSE;
                }
                else if (NLMSG_DONE == pHeader->nlmsg_type) {
                    bComplete = true;
                }
                else if (NLMSG_ERROR == pHeader->nlmsg_type) {
                    eError = ProcessNetlinkError(pHeader);
                }
                else if (NULL != pCallback) {
                    eError = pCallback(pHeader, pvUserData);
                }
                else {
                    /* Caller intentionally ignores payload messages. */
                }

                if ((IPSEC_OK == eError) && !bComplete) {
                    uiAlignedLength = NLMSG_ALIGN(pHeader->nlmsg_len);
                    if ((uiAlignedLength < pHeader->nlmsg_len) ||
                        (uiRemainingLength < uiAlignedLength)) {
                        eError = IPSEC_ERR_NETLINK_PARSE;
                    }
                    else {
                        uiRemainingLength -= uiAlignedLength;
                        pHeader = (struct nlmsghdr *)(
                            (uint8_t *)pHeader + uiAlignedLength);
                    }
                }
                else {
                    /* Stop on completion or malformed data. */
                }
            }

            if ((IPSEC_OK == eError) && !bComplete &&
                (0U != uiRemainingLength)) {
                eError = IPSEC_ERR_NETLINK_PARSE;
            }
            else {
                /* Datagram was fully consumed. */
            }
        }

        uiDatagramCount++;
        if ((IPSEC_OK == eError) && !bComplete &&
            (4096U < uiDatagramCount)) {
            eError = IPSEC_ERR_NETLINK_PARSE;
        }
        else {
            /* Continue or return. */
        }
    }

    return eError;
}

IpsecError_t ExecuteNetlinkDump(
    int32_t iProtocol,
    uint16_t usMessageType,
    const void *pvPayload,
    uint32_t uiPayloadLength,
    NetlinkMessageCallback_t pCallback,
    void *pvUserData)
{
    NetlinkRequest_t Request;
    struct sockaddr_nl LocalAddress;
    uint32_t uiSequence;
    int32_t iSocket;
    IpsecError_t eError;

    if (((NULL == pvPayload) && (0U != uiPayloadLength)) ||
        (sizeof(Request.aucPayload) < uiPayloadLength)) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        iSocket = (int32_t)socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC,
                                  iProtocol);
        if (0 > iSocket) {
            eError = MapNetlinkErrno(errno, IPSEC_ERR_NETLINK_SOCKET);
        }
        else {
            memset(&LocalAddress, 0, sizeof(LocalAddress));
            LocalAddress.nl_family = AF_NETLINK;
            if (0 != bind(iSocket, (const struct sockaddr *)&LocalAddress,
                          sizeof(LocalAddress))) {
                eError = MapNetlinkErrno(errno, IPSEC_ERR_NETLINK_SOCKET);
            }
            else {
                memset(&Request, 0, sizeof(Request));
                uiSequence = (uint32_t)GetIpsecMonotonicMilliseconds() ^
                             (uint32_t)getpid();
                Request.Header.nlmsg_len = NLMSG_LENGTH(uiPayloadLength);
                Request.Header.nlmsg_type = usMessageType;
                Request.Header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
                Request.Header.nlmsg_seq = uiSequence;
                Request.Header.nlmsg_pid = 0U;
                if (0U < uiPayloadLength) {
                    memcpy(Request.aucPayload, pvPayload, uiPayloadLength);
                }
                else {
                    /* Empty payload. */
                }

                eError = SendNetlinkRequest(iSocket, &Request);
                if (IPSEC_OK == eError) {
                    eError = ReceiveNetlinkDump(iSocket, uiSequence,
                                                pCallback, pvUserData);
                }
                else {
                    /* Preserve send error. */
                }
            }
            (void)close(iSocket);
        }
    }

    return eError;
}
