#include "ipsec_error.h"

const char *GetIpsecErrorString(IpsecError_t eError)
{
    const char *pcMessage;

    switch (eError) {
    case IPSEC_OK:
        pcMessage = "success";
        break;
    case IPSEC_ERR_INVALID_ARGUMENT:
        pcMessage = "invalid argument";
        break;
    case IPSEC_ERR_NO_MEMORY:
        pcMessage = "out of memory";
        break;
    case IPSEC_ERR_VICI_CONNECT:
        pcMessage = "VICI connection failed";
        break;
    case IPSEC_ERR_VICI_TRANSPORT:
        pcMessage = "VICI transport failed";
        break;
    case IPSEC_ERR_VICI_PROTOCOL:
        pcMessage = "invalid VICI protocol data";
        break;
    case IPSEC_ERR_VICI_TIMEOUT:
        pcMessage = "VICI operation timed out";
        break;
    case IPSEC_ERR_VICI_COMMAND:
        pcMessage = "VICI command failed";
        break;
    case IPSEC_ERR_DAEMON_NOT_RUNNING:
        pcMessage = "charon daemon is not running";
        break;
    case IPSEC_ERR_CONNECTION_NOT_FOUND:
        pcMessage = "IPsec connection was not found";
        break;
    case IPSEC_ERR_IKE_FAILED:
        pcMessage = "IKE operation failed";
        break;
    case IPSEC_ERR_CHILD_FAILED:
        pcMessage = "CHILD SA operation failed";
        break;
    case IPSEC_ERR_NETLINK_SOCKET:
        pcMessage = "Netlink socket failed";
        break;
    case IPSEC_ERR_NETLINK_SEND:
        pcMessage = "Netlink send failed";
        break;
    case IPSEC_ERR_NETLINK_RECV:
        pcMessage = "Netlink receive failed";
        break;
    case IPSEC_ERR_NETLINK_PARSE:
        pcMessage = "invalid Netlink data";
        break;
    case IPSEC_ERR_FILE_OPEN:
        pcMessage = "file open failed";
        break;
    case IPSEC_ERR_FILE_READ:
        pcMessage = "file read failed";
        break;
    case IPSEC_ERR_PERMISSION:
        pcMessage = "permission denied";
        break;
    case IPSEC_ERR_BUFFER_TOO_SMALL:
        pcMessage = "buffer is too small";
        break;
    case IPSEC_ERR_NOT_SUPPORTED:
        pcMessage = "operation is not supported";
        break;
    case IPSEC_ERR_FILE_WRITE:
        pcMessage = "file write failed";
        break;
    case IPSEC_ERR_FILE_EXISTS:
        pcMessage = "file already exists";
        break;
    case IPSEC_ERR_RANDOM:
        pcMessage = "secure random generation failed";
        break;
    case IPSEC_ERR_INTERNAL:
        pcMessage = "internal error";
        break;
    default:
        pcMessage = "unknown error";
        break;
    }

    return pcMessage;
}
