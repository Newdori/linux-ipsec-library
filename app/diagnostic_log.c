#include "app_internal.h"

#include <errno.h>
#include <string.h>

static const char *GetNativeAppDiagnosticLevel(IpsecLogLevel_t eLevel)
{
    const char *pcLevel;

    switch (eLevel) {
    case IPSEC_LOG_ERROR:
        pcLevel = "error";
        break;

    case IPSEC_LOG_WARNING:
        pcLevel = "warning";
        break;

    case IPSEC_LOG_INFO:
        pcLevel = "info";
        break;

    default:
        pcLevel = "debug";
        break;
    }
    return pcLevel;
}

IpsecError_t InitializeNativeAppDiagnosticLog(NativeAppDiagnosticLog_t *pLog)
{
    if (NULL == pLog) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    memset(pLog, 0, sizeof(*pLog));
    if (0 != pthread_mutex_init(&pLog->Mutex, NULL)) {
        return IPSEC_ERR_INTERNAL;
    }
    pLog->bInitialized = true;
    return IPSEC_OK;
}

IpsecError_t OpenNativeAppDiagnosticLog(NativeAppDiagnosticLog_t *pLog,
    const char *pcPath)
{
    IpsecError_t eError = IPSEC_OK;
    if (NULL == pLog) {
        return IPSEC_OK; /* Non-CLI callers may omit the optional sink. */
    }
    if (!pLog->bInitialized || (NULL == pcPath) || ('\0' == pcPath[0])) {
        return IPSEC_ERR_INVALID_ARGUMENT;
    }
    if (0 != pthread_mutex_lock(&pLog->Mutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    if (NULL != pLog->pFile) {
        eError = IPSEC_ERR_RESOURCE_CONFLICT;
    }
    else {
        pLog->pFile = fopen(pcPath, "wx");
        pLog->bWriteFailed = false;
        if (NULL == pLog->pFile) {
            eError = IPSEC_ERR_FILE_OPEN;
        }
        else if ((fprintf(pLog->pFile,
                     "library packet diagnostics (header metadata only; no packet dump)\n") < 0) ||
                 (0 != fflush(pLog->pFile))) {
            (void)fclose(pLog->pFile);
            pLog->pFile = NULL;
            eError = IPSEC_ERR_FILE_WRITE;
        }
    }
    (void)pthread_mutex_unlock(&pLog->Mutex);
    return eError;
}

void WriteNativeAppDiagnosticLog(NativeAppDiagnosticLog_t *pLog,
    IpsecLogLevel_t eLevel, const char *pcMessage)
{
    const int32_t iSavedErrno = errno;
    /* Never turn VICI, credential or packet data into an implicit dump. */
    if ((NULL != pLog) && pLog->bInitialized && (NULL != pcMessage) &&
        (0 == strncmp(pcMessage, "protected TUN ", sizeof("protected TUN ") - 1U)) &&
        (0 == pthread_mutex_lock(&pLog->Mutex))) {
        if ((NULL != pLog->pFile) &&
            ((fprintf(pLog->pFile, "level=%s %s\n",
                      GetNativeAppDiagnosticLevel(eLevel), pcMessage) < 0) ||
             (0 != fflush(pLog->pFile)))) {
            pLog->bWriteFailed = true;
        }
        (void)pthread_mutex_unlock(&pLog->Mutex);
    }
    errno = iSavedErrno;
}

IpsecError_t CloseNativeAppDiagnosticLog(NativeAppDiagnosticLog_t *pLog)
{
    IpsecError_t eError = IPSEC_OK;
    if ((NULL == pLog) || !pLog->bInitialized) {
        return IPSEC_OK;
    }
    if (0 != pthread_mutex_lock(&pLog->Mutex)) {
        return IPSEC_ERR_INTERNAL;
    }
    if (NULL != pLog->pFile) {
        if (0 != fclose(pLog->pFile)) {
            pLog->bWriteFailed = true;
        }
        pLog->pFile = NULL;
        eError = pLog->bWriteFailed ? IPSEC_ERR_FILE_WRITE : IPSEC_OK;
    }
    (void)pthread_mutex_unlock(&pLog->Mutex);
    return eError;
}

void DeinitializeNativeAppDiagnosticLog(NativeAppDiagnosticLog_t *pLog)
{
    if ((NULL != pLog) && pLog->bInitialized) {
        (void)CloseNativeAppDiagnosticLog(pLog);
        (void)pthread_mutex_destroy(&pLog->Mutex);
        pLog->bInitialized = false;
    }
}
