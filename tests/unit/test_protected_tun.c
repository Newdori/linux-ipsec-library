#define _DEFAULT_SOURCE
#include "../../src/datapath/protected/application_protected_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <netinet/in.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); exit(1); \
} } while (0)

static uint32_t guiAll;
static uint32_t guiOwned;
static uint32_t guiWrites;
static int32_t giOpenCount;
static int32_t giFailure;
static bool gbReadInterrupted;
static bool gbWriteInterrupted;
static char gacActualName[IFNAMSIZ];
static bool gbAddressAssigned;
static uint32_t guiAddressWrites;
static int32_t giAddressFailure;
static struct sockaddr_in gAddress;
static struct sockaddr_in gMask;

static int32_t OpenTestTunPath(const char *pcPath, int32_t iFlags, ...)
{
    CHECK(0 == strcmp(pcPath, "/proc/sys/net/ipv4/conf"));
    CHECK(0 != (iFlags & O_DIRECTORY));
    CHECK(0 != (iFlags & O_NOFOLLOW));
    if (1 == giFailure) {
        errno = ENOENT;
        return -1;
    }
    giOpenCount++;
    return 100;
}

static int32_t OpenTestTunSetting(int32_t iDirectory, const char *pcName,
    int32_t iFlags, ...)
{
    int32_t iFd;
    CHECK(0 != (iFlags & O_NOFOLLOW));
    if (100 == iDirectory) {
        CHECK(0 != (iFlags & O_DIRECTORY));
        CHECK(O_RDONLY == (iFlags & O_ACCMODE));
        CHECK((0 == strcmp(pcName, "all")) || (0 == strcmp(pcName, "esp-test0")));
        iFd = (0 == strcmp(pcName, "all")) ? 101 : 102;
    }
    else {
        CHECK(0 == strcmp(pcName, "rp_filter"));
        CHECK((101 == iDirectory) || (102 == iDirectory));
        if (101 == iDirectory) {
            CHECK(O_RDONLY == (iFlags & O_ACCMODE)); /* Never write all. */
            iFd = 103;
        }
        else if (O_WRONLY == (iFlags & O_ACCMODE)) {
            if (2 == giFailure) {
                errno = EACCES;
                return -1;
            }
            iFd = 105;
        }
        else {
            iFd = 104;
        }
    }
    giOpenCount++;
    return iFd;
}

static int32_t CloseTestTunFd(int32_t iFd)
{
    CHECK((iFd >= 100) && (iFd <= 105));
    CHECK(giOpenCount > 0);
    giOpenCount--;
    return 0;
}

static ssize_t ReadTestTunSetting(int32_t iFd, void *pvBuffer, size_t zLength)
{
    char *pcBuffer = pvBuffer;
    CHECK((103 == iFd) || (104 == iFd));
    CHECK(zLength >= 2U);
    if (gbReadInterrupted) {
        gbReadInterrupted = false;
        errno = EINTR;
        return -1;
    }
    pcBuffer[0] = (char)('0' + ((103 == iFd) ? guiAll : guiOwned));
    pcBuffer[1] = '\n';
    return (3 == giFailure) ? 1 : 2;
}

static ssize_t WriteTestTunSetting(int32_t iFd, const void *pvBuffer, size_t zLength)
{
    CHECK(105 == iFd); /* The exclusively created TUN is the only write target. */
    CHECK((2U == zLength) && (0 == memcmp(pvBuffer, "2\n", 2U)));
    if (gbWriteInterrupted) {
        gbWriteInterrupted = false;
        errno = EINTR;
        return -1;
    }
    guiWrites++;
    if (4 == giFailure) {
        errno = EROFS;
        return -1;
    }
    if (5 == giFailure) {
        return 1;
    }
    if (6 != giFailure) {
        guiOwned = 2U;
    }
    return 2;
}

static int32_t QueryTestTun(int32_t iFd, uint64_t ullRequest, ...)
{
    va_list Arguments;
    struct ifreq *pRequest;
    va_start(Arguments, ullRequest);
    pRequest = va_arg(Arguments, struct ifreq *);
    va_end(Arguments);
    if (8 == iFd) {
        CHECK(0 == strcmp(pRequest->ifr_name, "esp-test0"));
        if (SIOCGIFADDR == ullRequest) {
            if (1 == giAddressFailure) {
                errno = EACCES;
                return -1;
            }
            if (!gbAddressAssigned) {
                errno = EADDRNOTAVAIL;
                return -1;
            }
            memcpy(&pRequest->ifr_addr, &gAddress, sizeof(gAddress));
            return 0;
        }
        if ((SIOCSIFADDR == ullRequest) || (SIOCSIFNETMASK == ullRequest)) {
            guiAddressWrites++;
            if (((SIOCSIFADDR == ullRequest) && (2 == giAddressFailure)) ||
                ((SIOCSIFNETMASK == ullRequest) && (3 == giAddressFailure))) {
                errno = EPERM;
                return -1;
            }
            if (SIOCSIFADDR == ullRequest) {
                memcpy(&gAddress, &pRequest->ifr_addr, sizeof(gAddress));
                gbAddressAssigned = true;
                if (4 == giAddressFailure) {
                    gAddress.sin_family = AF_INET6;
                }
            }
            else {
                memcpy(&gMask, &pRequest->ifr_netmask, sizeof(gMask));
                if (5 == giAddressFailure) {
                    memset(&gMask.sin_addr, 0, sizeof(gMask.sin_addr));
                }
            }
            return 0;
        }
        CHECK(SIOCGIFNETMASK == ullRequest);
        if (6 == giAddressFailure) {
            errno = ENODEV;
            return -1;
        }
        memcpy(&pRequest->ifr_netmask, &gMask, sizeof(gMask));
        return 0;
    }
    CHECK(7 == iFd);
    CHECK(TUNGETIFF == ullRequest);
    memcpy(pRequest->ifr_name, gacActualName, IFNAMSIZ);
    pRequest->ifr_flags = IFF_TUN;
    if (7 == giFailure) {
        errno = EBADF;
        return -1;
    }
    return 0;
}

/* Exercise the actual private setup/verification routine without privileged
 * sysctls. These compile-time seams exist only in this test translation unit. */
#define open OpenTestTunPath
#define openat OpenTestTunSetting
#define close CloseTestTunFd
#define read ReadTestTunSetting
#define write WriteTestTunSetting
#define ioctl QueryTestTun
#include "../../src/datapath/protected/application_protected_tun.c"
#undef open
#undef openat
#undef close
#undef read
#undef write
#undef ioctl

static void VerifyTestTunAddress(IpsecProtectedApplicationState_t *pState)
{
    const uint8_t aucExpected[4] = {127U, 0U, 0U, 1U};
    giFailure = 0;
    for (giAddressFailure = 0; giAddressFailure <= 6; giAddressFailure++) {
        IpsecError_t eExpected = (0 == giAddressFailure) ? IPSEC_OK :
            ((giAddressFailure <= 3) ? IPSEC_ERR_PERMISSION :
             IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE);
        gbAddressAssigned = false;
        guiAddressWrites = 0U;
        CHECK(eExpected == ConfigureProtectedApplicationAddress(pState, 8, true));
        if (0 == giAddressFailure) {
            CHECK(2U == guiAddressWrites);
            CHECK(0 == memcmp(&gAddress.sin_addr, aucExpected, sizeof(aucExpected)));
            CHECK(IPSEC_OK == ConfigureProtectedApplicationAddress(pState, 8, false));
            CHECK(IPSEC_ERR_RESOURCE_CONFLICT ==
                ConfigureProtectedApplicationAddress(pState, 8, true));
            CHECK(2U == guiAddressWrites); /* Inspect and conflict never write. */
            gbAddressAssigned = false; /* Lost anchor fails readiness. */
            CHECK(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE ==
                ConfigureProtectedApplicationAddress(pState, 8, false));
        }
    }
    giAddressFailure = 0;
}

int main(void)
{
    IpsecProtectedApplicationState_t State = {.iTunFd = 7};
    int32_t iFailure;
    uint32_t uiAll;
    uint32_t uiOwned;
    const char *pacInvalid[] = {"all", "default", "..", ".", "a/b", ""};
    size_t zIndex;
    memcpy(State.acTunName, "esp-test0", sizeof("esp-test0"));
    memcpy(gacActualName, State.acTunName, sizeof("esp-test0"));
    VerifyTestTunAddress(&State);
    for (uiAll = 0U; uiAll <= 2U; uiAll++) {
        for (uiOwned = 0U; uiOwned <= 2U; uiOwned++) {
            guiAll = uiAll;
            guiOwned = uiOwned;
            guiWrites = 0U;
            CHECK(IPSEC_OK == ConfigureProtectedApplicationReversePath(&State, true));
            CHECK(2U == guiOwned);
            CHECK(uiAll == guiAll);
            CHECK(((2U == uiOwned) ? 0U : 1U) == guiWrites);
            CHECK(0 == giOpenCount);
            guiOwned = uiOwned;
            guiWrites = 0U;
            CHECK(((1U == ((uiAll > uiOwned) ? uiAll : uiOwned)) ?
                IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE : IPSEC_OK) ==
                ConfigureProtectedApplicationReversePath(&State, false));
            CHECK(0U == guiWrites);
            CHECK(0 == giOpenCount);
        }
    }
    for (iFailure = 1; iFailure <= 7; iFailure++) {
        giFailure = iFailure;
        guiOwned = 1U;
        errno = 0;
        CHECK(((2 == iFailure) ? IPSEC_ERR_PERMISSION :
            IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE) ==
            ConfigureProtectedApplicationReversePath(&State, true));
        CHECK(0 == giOpenCount);
    }
    giFailure = 0;
    guiOwned = 1U;
    gbReadInterrupted = true;
    gbWriteInterrupted = true;
    CHECK(IPSEC_OK == ConfigureProtectedApplicationReversePath(&State, true));
    CHECK(0 == giOpenCount);
    guiAll = 3U; /* Reject malformed/out-of-range sysctl data. */
    CHECK(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE ==
        ConfigureProtectedApplicationReversePath(&State, true));
    CHECK(0 == giOpenCount);
    memset(gacActualName, 'x', sizeof(gacActualName)); /* Non-terminated kernel name. */
    CHECK(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE ==
        ConfigureProtectedApplicationReversePath(&State, true));
    CHECK(0 == giOpenCount);
    memset(gacActualName, 0, sizeof(gacActualName));
    memcpy(gacActualName, "eth0", sizeof("eth0")); /* fd/name ownership mismatch. */
    CHECK(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE ==
        ConfigureProtectedApplicationReversePath(&State, true));
    CHECK(0 == giOpenCount);
    for (zIndex = 0U; zIndex < sizeof(pacInvalid) / sizeof(pacInvalid[0]); zIndex++) {
        memset(State.acTunName, 0, sizeof(State.acTunName));
        memset(gacActualName, 0, sizeof(gacActualName));
        memcpy(State.acTunName, pacInvalid[zIndex], strlen(pacInvalid[zIndex]));
        memcpy(gacActualName, State.acTunName, IFNAMSIZ);
        CHECK(IPSEC_ERR_PROTECTED_PATH_UNAVAILABLE ==
            ConfigureProtectedApplicationReversePath(&State, true));
        CHECK(0 == giOpenCount);
    }
    (void)puts("protected TUN IPv4 anchor/rp_filter ownership/failure paths: PASS");
    return 0;
}
