#include "algorithm_packet.h"

#include <stdio.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define CHECK(Expression) do { if (!(Expression)) { \
    (void)fprintf(stderr, "FAIL line %d: %s\n", __LINE__, #Expression); return 1; \
} } while (0)

static atomic_bool gbStop;

bool IsNativeAppStopRequested(void)
{
    return atomic_load(&gbStop);
}

static void *SendTestFragments(void *pvSocket)
{
    const uint8_t aucFrame[] = {0U, 0U, 0U, 3U, 'a', 'b', 'c'};
    int32_t iSocket = *(int32_t *)pvSocket;
    size_t zIndex;
    for (zIndex = 0U; zIndex < sizeof(aucFrame); zIndex++) {
        struct timespec Delay = {.tv_sec = 0, .tv_nsec = 1000000};
        if (1 != send(iSocket, aucFrame + zIndex, 1U, MSG_NOSIGNAL)) {
            return (void *)1;
        }
        (void)nanosleep(&Delay, NULL);
    }
    return NULL;
}

int main(void)
{
    int32_t aiSockets[2];
    uint8_t aucData[32];
    uint8_t aucHeader[4];
    size_t zLength = 0U;
    pthread_t Thread;
    void *pvResult = NULL;
    NativeAppConfig_t Config = {0};
    CHECK(IPSEC_OK == ValidateNativeAppAlgorithmPacketConfig(&Config));
    Config.Datapath.eProtectedPacketPath = IPSEC_PACKET_PATH_APPLICATION;
    CHECK(IPSEC_ERR_PACKET_PATH_MISMATCH == ValidateNativeAppAlgorithmPacketConfig(&Config));
    Config.Datapath.ePlainPacketPath = IPSEC_PACKET_PATH_APPLICATION;
    Config.eMode = IPSEC_MODE_TUNNEL;
    memcpy(Config.acLocalAddress, "192.168.33.100", sizeof("192.168.33.100"));
    memcpy(Config.acRemoteAddress, "192.168.33.101", sizeof("192.168.33.101"));
    memcpy(Config.acLocalTrafficSelector, "172.16.10.1/32", sizeof("172.16.10.1/32"));
    memcpy(Config.acRemoteTrafficSelector, "172.16.20.1/32", sizeof("172.16.20.1/32"));
    CHECK(IPSEC_OK == ValidateNativeAppAlgorithmPacketConfig(&Config));
    Config.acRemoteTrafficSelector[12] = '4';
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == ValidateNativeAppAlgorithmPacketConfig(&Config));
    Config.acRemoteTrafficSelector[12] = '3';
    Config.ePlainNetfilterHook = NATIVE_APP_PLAIN_NETFILTER_FORWARD;
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == ValidateNativeAppAlgorithmPacketConfig(&Config));
    Config.ePlainNetfilterHook = NATIVE_APP_PLAIN_NETFILTER_INPUT;
    memcpy(Config.acLocalTrafficSelector, "192.168.33.100/32", sizeof("192.168.33.100/32"));
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == ValidateNativeAppAlgorithmPacketConfig(&Config));
    CHECK(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, aiSockets));
    CHECK(0 == pthread_create(&Thread, NULL, SendTestFragments, &aiSockets[0]));
    CHECK(IPSEC_OK == ReceiveNativeAppTestFrame(aiSockets[1], aucData,
        sizeof(aucData), &zLength, GetNativeAppPacketTestTime() + 2000U));
    CHECK((3U == zLength) && (0 == memcmp(aucData, "abc", 3U)));
    CHECK(0 == pthread_join(Thread, &pvResult));
    CHECK(NULL == pvResult);
    CHECK(IPSEC_ERR_PACKET_TIMEOUT == ReceiveNativeAppTestFrame(aiSockets[1], aucData,
        sizeof(aucData), &zLength, GetNativeAppPacketTestTime() + 10U));
    CHECK(IPSEC_OK == SendNativeAppTestFrame(aiSockets[0], (const uint8_t *)"one", 3U,
        GetNativeAppPacketTestTime() + 1000U));
    CHECK(IPSEC_OK == SendNativeAppTestFrame(aiSockets[0], (const uint8_t *)"two", 3U,
        GetNativeAppPacketTestTime() + 1000U));
    CHECK(IPSEC_OK == ReceiveNativeAppTestFrame(aiSockets[1], aucData, sizeof(aucData),
        &zLength, GetNativeAppPacketTestTime() + 1000U));
    CHECK(0 == memcmp(aucData, "one", 3U));
    CHECK(IPSEC_OK == ReceiveNativeAppTestFrame(aiSockets[1], aucData, sizeof(aucData),
        &zLength, GetNativeAppPacketTestTime() + 1000U));
    CHECK(0 == memcmp(aucData, "two", 3U));
    EncodeNativeAppTestLength(aucHeader, UINT32_MAX);
    CHECK(4 == send(aiSockets[0], aucHeader, 4U, MSG_NOSIGNAL));
    CHECK(IPSEC_ERR_PACKET_INVALID == ReceiveNativeAppTestFrame(aiSockets[1], aucData,
        sizeof(aucData), &zLength, GetNativeAppPacketTestTime() + 1000U));
    CHECK(0U == zLength);
    CHECK(0 == close(aiSockets[0]));
    CHECK(0 == close(aiSockets[1]));
    CHECK(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, aiSockets));
    CHECK(1 == send(aiSockets[0], aucHeader, 1U, MSG_NOSIGNAL));
    CHECK(IPSEC_ERR_VICI_PROTOCOL == ReceiveNativeAppTestFrame(aiSockets[1], aucData,
        sizeof(aucData), &zLength, GetNativeAppPacketTestTime() + 10U));
    CHECK(0 == close(aiSockets[0]));
    CHECK(0 == close(aiSockets[1]));
    CHECK(0 == socketpair(AF_UNIX, SOCK_STREAM, 0, aiSockets));
    CHECK(0 == close(aiSockets[0]));
    CHECK(IPSEC_ERR_VICI_TRANSPORT == ReceiveNativeAppTestFrame(aiSockets[1], aucData,
        sizeof(aucData), &zLength, GetNativeAppPacketTestTime() + 1000U));
    CHECK(0 == close(aiSockets[1]));
    atomic_store(&gbStop, true);
    CHECK(IPSEC_ERR_CANCELLED == ReceiveNativeAppTestFrame(-1, aucData,
        sizeof(aucData), &zLength, GetNativeAppPacketTestTime() + 1000U));
    (void)puts("algorithm packet transport: PASS");
    return 0;
}
