#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
/* Test the actual private initialization in a disposable network namespace.
 * No mock, charon, external command or change to the host namespace. */
#include "../../src/datapath/protected/application_protected_tun.c"

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s (errno=%d)\n", \
        __LINE__, #Expression, errno); exit(1); \
} } while (0)

static int32_t CreateTestTun(int32_t iSocket, const char *pcName,
    bool bPeer)
{
    struct ifreq Request;
    struct sockaddr_in Address = {.sin_family = AF_INET};
    const uint8_t aucAddress[4] = {192U, 0U, 2U, 2U};
    const uint8_t aucMask[4] = {255U, 255U, 255U, 0U};
    const uint16_t usFlags = IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL;
    int32_t iFd = open("/dev/net/tun", O_RDWR | O_CLOEXEC | O_NONBLOCK);
    CHECK(iFd >= 0);
    SetProtectedApplicationIfreqName(&Request, pcName);
    memcpy(&Request.ifr_flags, &usFlags, sizeof(usFlags));
    CHECK(0 == ioctl(iFd, TUNSETIFF, &Request));
    if (bPeer) {
        memcpy(&Address.sin_addr, aucAddress, sizeof(aucAddress));
        memcpy(&Request.ifr_addr, &Address, sizeof(Address));
        CHECK(0 == ioctl(iSocket, SIOCSIFADDR, &Request));
        memcpy(&Address.sin_addr, aucMask, sizeof(aucMask));
        memcpy(&Request.ifr_netmask, &Address, sizeof(Address));
        CHECK(0 == ioctl(iSocket, SIOCSIFNETMASK, &Request));
    }
    Request.ifr_flags = IFF_UP;
    CHECK(0 == ioctl(iSocket, SIOCSIFFLAGS, &Request));
    return iFd;
}

int main(void)
{
    IpsecProtectedApplicationState_t State = {.iTunFd = -1};
    struct sockaddr_in Destination = {.sin_family = AF_INET};
    struct pollfd Descriptor = {.events = POLLIN};
    uint8_t aucPacket[32] = {
        0x45U, 0U, 0U, 32U, 0U, 1U, 0U, 0U, 64U, 17U, 0U, 0U,
        192U, 0U, 2U, 1U, 192U, 0U, 2U, 2U,
        0xc0U, 0U, 0xbcU, 0x17U, 0U, 12U, 0U, 0U, 'R', 'P', 'F', '!'
    };
    uint8_t aucReceived[16];
    uint32_t uiSum = 0U;
    uint32_t uiIndex;
    int32_t iSocket;
    int32_t iPeer;
    int32_t iUdp;
    /* Fail before creating/changing anything if namespace isolation is denied. */
    if (0 != unshare(CLONE_NEWNET)) {
        (void)fprintf(stderr, "SKIP: isolated network namespace unavailable (errno=%d); run with sudo\n", errno);
        return 77;
    }
    iSocket = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(iSocket >= 0);
    iPeer = CreateTestTun(iSocket, "reverse-test0", true);
    memcpy(State.acTunName, "esp-test0", sizeof("esp-test0"));
    State.iTunFd = CreateTestTun(iSocket, State.acTunName, false);
    CHECK(IPSEC_OK == ConfigureProtectedApplicationReversePath(&State, true));
    iUdp = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    CHECK(iUdp >= 0);
    memcpy(&Destination.sin_addr, aucPacket + 16U, 4U);
    memcpy(&Destination.sin_port, aucPacket + 22U, 2U);
    CHECK(0 == bind(iUdp, (const struct sockaddr *)&Destination, sizeof(Destination)));
    for (uiIndex = 0U; uiIndex < 20U; uiIndex += 2U) {
        uiSum += ((uint32_t)aucPacket[uiIndex] << 8U) | aucPacket[uiIndex + 1U];
    }
    while (0U != (uiSum >> 16U)) {
        uiSum = (uiSum & 0xffffU) + (uiSum >> 16U);
    }
    uiSum = (~uiSum) & 0xffffU;
    aucPacket[10] = (uint8_t)(uiSum >> 8U);
    aucPacket[11] = (uint8_t)uiSum;
    Descriptor.fd = iUdp;
    CHECK((ssize_t)sizeof(aucPacket) == write(State.iTunFd, aucPacket, sizeof(aucPacket)));
    CHECK(0 == poll(&Descriptor, 1U, 250)); /* Reproduce unnumbered loose-RPF drop. */
    CHECK(IPSEC_OK == ConfigureProtectedApplicationAddress(&State, iSocket, true));
    CHECK(IPSEC_OK == ConfigureProtectedApplicationAddress(&State, iSocket, false));
    CHECK((ssize_t)sizeof(aucPacket) == write(State.iTunFd, aucPacket, sizeof(aucPacket)));
    CHECK(1 == poll(&Descriptor, 1U, 1000));
    CHECK(4 == recv(iUdp, aucReceived, sizeof(aucReceived), MSG_DONTWAIT));
    CHECK(0 == memcmp(aucReceived, "RPF!", 4U));
    CHECK(0 == close(iUdp));
    CHECK(0 == close(State.iTunFd));
    CHECK(0 == close(iPeer));
    CHECK(0 == close(iSocket));
    (void)puts("PASS: unnumbered TUN drops; initialized TUN delivers with loose RPF (isolated namespace)");
    return 0;
}
