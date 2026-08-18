#include "../internal/ipsec_internal.h"

#include <stdarg.h>
#include <stdio.h>

void LogIpsec(
    const IpsecContext_t *pContext,
    IpsecLogLevel_t eLevel,
    const char *pcFormat,
    ...)
{
    char acMessage[IPSEC_LOG_MESSAGE_LENGTH];
    va_list Arguments;
    int32_t iLength;

    if ((NULL == pContext) || (NULL == pContext->pLogCallback) ||
        (NULL == pcFormat)) {
        return;
    }
    else {
        va_start(Arguments, pcFormat);
        iLength = (int32_t)vsnprintf(acMessage, sizeof(acMessage), pcFormat, Arguments);
        va_end(Arguments);

        if (0 > iLength) {
            acMessage[0] = '\0';
        }
        else {
            acMessage[sizeof(acMessage) - 1U] = '\0';
        }

        pContext->pLogCallback(eLevel, acMessage, pContext->pvLogUserData);
    }
}
