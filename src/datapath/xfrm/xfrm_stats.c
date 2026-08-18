#include "xfrm_internal.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define XFRM_STAT_INITIAL_BUFFER_LENGTH 4096U
#define XFRM_STAT_MAX_BUFFER_LENGTH 131072U
#define XFRM_STAT_LINE_LENGTH 256U

typedef struct XfrmStatisticMapping {
    const char *pcName;
    size_t zOffset;
    uint32_t uiBit;
} XfrmStatisticMapping_t;

static const XfrmStatisticMapping_t gaXfrmStatisticMappings[] = {
    {"XfrmInError", offsetof(IpsecXfrmStatistics_t, ullInError), 0U},
    {"XfrmInBufferError", offsetof(IpsecXfrmStatistics_t, ullInBufferError), 1U},
    {"XfrmInHdrError", offsetof(IpsecXfrmStatistics_t, ullInHeaderError), 2U},
    {"XfrmInNoStates", offsetof(IpsecXfrmStatistics_t, ullInNoStates), 3U},
    {"XfrmInStateProtoError", offsetof(IpsecXfrmStatistics_t, ullInStateProtocolError), 4U},
    {"XfrmInStateModeError", offsetof(IpsecXfrmStatistics_t, ullInStateModeError), 5U},
    {"XfrmInStateSeqError", offsetof(IpsecXfrmStatistics_t, ullInStateSequenceError), 6U},
    {"XfrmInStateExpired", offsetof(IpsecXfrmStatistics_t, ullInStateExpired), 7U},
    {"XfrmInStateMismatch", offsetof(IpsecXfrmStatistics_t, ullInStateMismatch), 8U},
    {"XfrmInStateInvalid", offsetof(IpsecXfrmStatistics_t, ullInStateInvalid), 9U},
    {"XfrmInTmplMismatch", offsetof(IpsecXfrmStatistics_t, ullInTemplateMismatch), 10U},
    {"XfrmOutError", offsetof(IpsecXfrmStatistics_t, ullOutError), 11U},
    {"XfrmOutBundleGenError", offsetof(IpsecXfrmStatistics_t, ullOutBundleGenerationError), 12U},
    {"XfrmOutBundleCheckError", offsetof(IpsecXfrmStatistics_t, ullOutBundleCheckError), 13U},
    {"XfrmOutNoStates", offsetof(IpsecXfrmStatistics_t, ullOutNoStates), 14U},
    {"XfrmOutStateProtoError", offsetof(IpsecXfrmStatistics_t, ullOutStateProtocolError), 15U},
    {"XfrmOutStateModeError", offsetof(IpsecXfrmStatistics_t, ullOutStateModeError), 16U},
    {"XfrmOutStateSeqError", offsetof(IpsecXfrmStatistics_t, ullOutStateSequenceError), 17U},
    {"XfrmOutStateExpired", offsetof(IpsecXfrmStatistics_t, ullOutStateExpired), 18U},
    {"XfrmOutPolBlock", offsetof(IpsecXfrmStatistics_t, ullOutPolicyBlock), 19U}
};

static const XfrmStatisticMapping_t *FindXfrmStatisticMapping(
    const char *pcName)
{
    size_t zIndex;
    const XfrmStatisticMapping_t *pMapping = NULL;

    for (zIndex = 0U;
         zIndex < (sizeof(gaXfrmStatisticMappings) /
                   sizeof(gaXfrmStatisticMappings[0]));
         zIndex++) {
        if (0 == strcmp(pcName, gaXfrmStatisticMappings[zIndex].pcName)) {
            pMapping = &gaXfrmStatisticMappings[zIndex];
            break;
        }
        else {
            /* Continue searching. */
        }
    }
    return pMapping;
}

static IpsecError_t ParseXfrmStatisticLine(
    const char *pcLine,
    size_t zLineLength,
    IpsecXfrmStatistics_t *pStatistics)
{
    char acLine[XFRM_STAT_LINE_LENGTH];
    char *pcName;
    char *pcValue;
    char *pcEnd;
    const XfrmStatisticMapping_t *pMapping;
    uint64_t ullMask;
    uint64_t ullValue;
    IpsecError_t eError;

    if ((0U == zLineLength) || (sizeof(acLine) <= zLineLength)) {
        eError = (0U == zLineLength) ? IPSEC_OK :
                 IPSEC_ERR_NETLINK_PARSE;
    }
    else {
        memcpy(acLine, pcLine, zLineLength);
        acLine[zLineLength] = '\0';
        pcName = acLine;
        while (isspace((unsigned char)*pcName)) {
            pcName++;
        }
        if ('\0' == *pcName) {
            eError = IPSEC_OK;
        }
        else {
            pcValue = pcName;
            while (('\0' != *pcValue) &&
                   !isspace((unsigned char)*pcValue)) {
                pcValue++;
            }
            if ('\0' == *pcValue) {
                eError = IPSEC_ERR_NETLINK_PARSE;
            }
            else {
                *pcValue = '\0';
                pcValue++;
                while (isspace((unsigned char)*pcValue)) {
                    pcValue++;
                }
                errno = 0;
                ullValue = (uint64_t)strtoull(pcValue, &pcEnd, 10);
                while (isspace((unsigned char)*pcEnd)) {
                    pcEnd++;
                }
                if ((0 != errno) || (pcEnd == pcValue) ||
                    ('\0' != *pcEnd)) {
                    eError = IPSEC_ERR_NETLINK_PARSE;
                }
                else {
                    pMapping = FindXfrmStatisticMapping(pcName);
                    if (NULL == pMapping) {
                        eError = IPSEC_OK;
                    }
                    else {
                        ullMask = UINT64_C(1) << pMapping->uiBit;
                        if (0U != (pStatistics->ullPresentMask & ullMask)) {
                            eError = IPSEC_ERR_NETLINK_PARSE;
                        }
                        else {
                            *(uint64_t *)((uint8_t *)pStatistics +
                                         pMapping->zOffset) =
                                (uint64_t)ullValue;
                            pStatistics->ullPresentMask |= ullMask;
                            eError = IPSEC_OK;
                        }
                    }
                }
            }
        }
    }

    SecureZeroIpsec(acLine, sizeof(acLine));
    return eError;
}

IpsecError_t ParseXfrmStatisticsText(
    const char *pcText,
    size_t zTextLength,
    IpsecXfrmStatistics_t *pStatistics)
{
    const char *pcLine;
    const char *pcEnd;
    size_t zRemaining;
    size_t zLineLength;
    IpsecError_t eError;

    if ((NULL == pStatistics) ||
        ((NULL == pcText) && (0U != zTextLength))) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        memset(pStatistics, 0, sizeof(*pStatistics));
        pcLine = pcText;
        zRemaining = zTextLength;
        eError = IPSEC_OK;

        while ((0U < zRemaining) && (IPSEC_OK == eError)) {
            pcEnd = (const char *)memchr(pcLine, '\n', zRemaining);
            if (NULL == pcEnd) {
                zLineLength = zRemaining;
            }
            else {
                zLineLength = (size_t)(pcEnd - pcLine);
            }
            if ((0U < zLineLength) && ('\r' == pcLine[zLineLength - 1U])) {
                zLineLength--;
            }
            else {
                /* No carriage return to trim. */
            }

            eError = ParseXfrmStatisticLine(pcLine, zLineLength,
                                            pStatistics);
            if (NULL == pcEnd) {
                zRemaining = 0U;
            }
            else {
                zRemaining -= (size_t)(pcEnd - pcLine) + 1U;
                pcLine = pcEnd + 1;
            }
        }
    }

    return eError;
}

static IpsecError_t ReadXfrmStatisticsFile(
    char **ppcText,
    size_t *pzLength)
{
    char *pcBuffer = NULL;
    char *pcNewBuffer;
    size_t zCapacity = XFRM_STAT_INITIAL_BUFFER_LENGTH;
    size_t zLength = 0U;
    size_t zNewCapacity;
    ssize_t lReadLength;
    int32_t iFile;
    IpsecError_t eError;

    iFile = (int32_t)open("/proc/net/xfrm_stat", O_RDONLY | O_CLOEXEC);
    if (0 > iFile) {
        eError = ((EACCES == errno) || (EPERM == errno)) ?
                 IPSEC_ERR_PERMISSION : IPSEC_ERR_FILE_OPEN;
    }
    else {
        pcBuffer = (char *)malloc(zCapacity + 1U);
        if (NULL == pcBuffer) {
            eError = IPSEC_ERR_NO_MEMORY;
        }
        else {
            eError = IPSEC_OK;
            while (IPSEC_OK == eError) {
                do {
                    lReadLength = read(iFile, pcBuffer + zLength,
                                       zCapacity - zLength);
                } while ((0 > lReadLength) && (EINTR == errno));

                if (0 > lReadLength) {
                    eError = IPSEC_ERR_FILE_READ;
                }
                else if (0 == lReadLength) {
                    break;
                }
                else {
                    zLength += (size_t)lReadLength;
                    if (zLength == zCapacity) {
                        if (XFRM_STAT_MAX_BUFFER_LENGTH == zCapacity) {
                            eError = IPSEC_ERR_BUFFER_TOO_SMALL;
                        }
                        else {
                            zNewCapacity = zCapacity * 2U;
                            if (XFRM_STAT_MAX_BUFFER_LENGTH <
                                zNewCapacity) {
                                zNewCapacity =
                                    XFRM_STAT_MAX_BUFFER_LENGTH;
                            }
                            else {
                                /* Geometric growth remains below the cap. */
                            }
                            pcNewBuffer = (char *)realloc(
                                pcBuffer, zNewCapacity + 1U);
                            if (NULL == pcNewBuffer) {
                                eError = IPSEC_ERR_NO_MEMORY;
                            }
                            else {
                                pcBuffer = pcNewBuffer;
                                zCapacity = zNewCapacity;
                            }
                        }
                    }
                    else {
                        /* Continue reading into available space. */
                    }
                }
            }
        }
        (void)close(iFile);
    }

    if (IPSEC_OK == eError) {
        pcBuffer[zLength] = '\0';
        *ppcText = pcBuffer;
        *pzLength = zLength;
    }
    else {
        free(pcBuffer);
    }
    return eError;
}

IpsecError_t GetIpsecXfrmStatistics(
    IpsecXfrmStatistics_t *pStatistics)
{
    char *pcText = NULL;
    size_t zLength = 0U;
    IpsecError_t eError;

    if (NULL == pStatistics) {
        eError = IPSEC_ERR_INVALID_ARGUMENT;
    }
    else {
        eError = ReadXfrmStatisticsFile(&pcText, &zLength);
    }
    if (IPSEC_OK == eError) {
        eError = ParseXfrmStatisticsText(pcText, zLength, pStatistics);
    }
    else {
        /* Preserve file error. */
    }
    free(pcText);
    return eError;
}
