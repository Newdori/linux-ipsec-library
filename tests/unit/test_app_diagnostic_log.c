#include "app_internal.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); exit(1); \
} } while (0)

int main(void)
{
    NativeAppDiagnosticLog_t Log;
    char acPath[128];
    char acText[512] = {0};
    size_t zLength;
    int32_t iLength;

    CHECK(IPSEC_OK == InitializeNativeAppDiagnosticLog(&Log));
    iLength = snprintf(acPath, sizeof(acPath), "test_app_diagnostic_%" PRIu32 ".tmp",
        (uint32_t)getpid());
    CHECK((iLength > 0) && ((size_t)iLength < sizeof(acPath)));
    Log.pFile = fopen(acPath, "w+b");
    CHECK(NULL != Log.pFile);
    WriteNativeAppDiagnosticLog(&Log, IPSEC_LOG_WARNING,
        "protected TUN packet rejected: bytes=48 class=unsupported_or_malformed");
    WriteNativeAppDiagnosticLog(&Log, IPSEC_LOG_INFO,
        "protected TUN test packet: stage=capture direction=outbound "
        "probe=1 bytes=148 spi=0x01020304 sequence=7 error=none");
    WriteNativeAppDiagnosticLog(&Log, IPSEC_LOG_WARNING,
        "credential value must not be copied into the packet diagnostic");
    CHECK(0 == fflush(Log.pFile));
    CHECK(0 == fseek(Log.pFile, 0L, SEEK_SET));
    zLength = fread(acText, 1U, sizeof(acText) - 1U, Log.pFile);
    CHECK(zLength > 0U);
    CHECK(NULL != strstr(acText, "protected TUN packet rejected"));
    CHECK(NULL != strstr(acText,
        "stage=capture direction=outbound probe=1 bytes=148"));
    CHECK(NULL != strstr(acText, "spi=0x01020304 sequence=7 error=none"));
    CHECK(NULL == strstr(acText, "credential value"));
    CHECK(IPSEC_OK == CloseNativeAppDiagnosticLog(&Log));
    DeinitializeNativeAppDiagnosticLog(&Log);
    CHECK(0 == remove(acPath));
    (void)puts("PASS: case diagnostic filters messages and closes cleanly");
    return 0;
}
