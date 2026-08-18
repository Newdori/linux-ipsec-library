#include "xfrm_internal.h"

#include <stdio.h>

static int32_t ReportFailure(const char *pcMessage)
{
    (void)fprintf(stderr, "FAIL: %s\n", pcMessage);
    return 1;
}

static int32_t TestKnownAndUnknownStatistics(void)
{
    static const char acText[] =
        "XfrmInError 1\n"
        "XfrmInNoStates 2\n"
        "XfrmFutureKernelCounter 99\n"
        "XfrmOutPolBlock 3\n";
    IpsecXfrmStatistics_t Statistics;
    IpsecError_t eError;

    eError = ParseXfrmStatisticsText(acText, sizeof(acText) - 1U,
                                     &Statistics);
    if (IPSEC_OK != eError) {
        return ReportFailure("valid xfrm_stat text rejected");
    }
    else if ((1U != Statistics.ullInError) ||
             (2U != Statistics.ullInNoStates) ||
             (3U != Statistics.ullOutPolicyBlock)) {
        return ReportFailure("known xfrm_stat values not mapped");
    }
    else if ((0U == (Statistics.ullPresentMask & (UINT64_C(1) << 0U))) ||
             (0U == (Statistics.ullPresentMask & (UINT64_C(1) << 3U))) ||
             (0U == (Statistics.ullPresentMask & (UINT64_C(1) << 19U)))) {
        return ReportFailure("xfrm_stat presence mask not set");
    }
    else {
        return 0;
    }
}

static int32_t TestMalformedStatistics(void)
{
    static const char acInvalidNumber[] = "XfrmInError nope\n";
    static const char acDuplicate[] =
        "XfrmInError 1\n"
        "XfrmInError 2\n";
    IpsecXfrmStatistics_t Statistics;

    if (IPSEC_ERR_NETLINK_PARSE !=
        ParseXfrmStatisticsText(acInvalidNumber,
                                sizeof(acInvalidNumber) - 1U,
                                &Statistics)) {
        return ReportFailure("invalid xfrm_stat number accepted");
    }
    else if (IPSEC_ERR_NETLINK_PARSE !=
             ParseXfrmStatisticsText(acDuplicate,
                                     sizeof(acDuplicate) - 1U,
                                     &Statistics)) {
        return ReportFailure("duplicate xfrm_stat key accepted");
    }
    else {
        return 0;
    }
}

int main(void)
{
    int32_t iResult;

    iResult = TestKnownAndUnknownStatistics();
    if (0 == iResult) {
        iResult = TestMalformedStatistics();
    }
    else {
        /* Preserve first failure. */
    }
    return iResult;
}
