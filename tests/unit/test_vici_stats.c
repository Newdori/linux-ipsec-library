#include "vici_internal.h"

#include <stdio.h>
#include <string.h>

static int32_t ReportFailure(const char *pcMessage)
{
    (void)fprintf(stderr, "FAIL: %s\n", pcMessage);
    return 1;
}

static IpsecError_t BuildStatusMessage(ViciBuffer_t *pMessage)
{
    IpsecError_t eError;

    eError = InitializeViciBuffer(pMessage, 256U, false);
    if (IPSEC_OK == eError) {
        eError = AddViciSectionStart(pMessage, "uptime");
    }
    else {
        /* Preserve allocation error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "running",
                                       "1 minute, 2 seconds");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionEnd(pMessage);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionStart(pMessage, "workers");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "total", "16");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciKeyValueString(pMessage, "idle", "11");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciSectionEnd(pMessage);
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListStart(pMessage, "plugins");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListItemString(pMessage, "kernel-netlink");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListItemString(pMessage, "kernel-libipsec");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListItemString(pMessage, "aes");
    }
    else {
        /* Preserve message error. */
    }
    if (IPSEC_OK == eError) {
        eError = AddViciListEnd(pMessage);
    }
    else {
        /* Preserve message error. */
    }
    return eError;
}

static int32_t TestPluginStatusParsing(void)
{
    ViciBuffer_t Message = {0};
    IpsecDaemonStatus_t Status = {0};
    IpsecError_t eError;
    int32_t iResult = 0;

    eError = BuildStatusMessage(&Message);
    if (IPSEC_OK == eError) {
        eError = ParseViciDaemonStatusMessage(
            Message.pucData, Message.uiLength, &Status);
    }
    else {
        /* Preserve message construction error. */
    }
    if ((IPSEC_OK != eError) || (62U != Status.ullUptimeSeconds) ||
        (16U != Status.uiWorkerTotal) || (11U != Status.uiWorkerIdle) ||
        !Status.bKernelNetlinkLoaded || !Status.bKernelLibipsecLoaded) {
        iResult = ReportFailure("VICI datapath plugin status parsing");
    }
    else {
        /* All requested status fields were decoded. */
    }
    DestroyViciBuffer(&Message);
    return iResult;
}

int main(void)
{
    return TestPluginStatusParsing();
}
