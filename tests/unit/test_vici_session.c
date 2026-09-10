#include "vici_internal.h"

#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define CHECK(Condition) do { if (!(Condition)) { \
    (void)fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #Condition); \
    exit(EXIT_FAILURE); } } while (false)
#define TEST_CLIENT_LIMIT 16U

typedef enum TestMode {
    TEST_EVENT,
    TEST_SILENT,
    TEST_UNKNOWN_EVENT,
    TEST_RECONNECT,
    TEST_BAD_STREAM,
    TEST_PARTIAL_FRAME,
    TEST_REJECT_SECRET,
    TEST_UNLOAD_ABSENT,
    TEST_UNLOAD_PRESENT
} TestMode_t;

typedef struct TestClient {
    int32_t iSocket;
    uint32_t uiRegistrations;
    bool bEvent;
    bool bChild;
} TestClient_t;

typedef struct TestServer {
    int32_t iListener;
    char acDirectory[64];
    char acSocketPath[108];
    pthread_t Thread;
    TestMode_t eMode;
    TestClient_t aClients[TEST_CLIENT_LIMIT];
    atomic_bool bStop;
    atomic_bool bHeld;
    atomic_uint uiQueries;
    atomic_uint uiAccepted;
    bool bReady;
    int32_t iHeldSocket;
    uint64_t ullReleaseMs;
} TestServer_t;

typedef struct TestCall {
    IpsecContext_t *pContext;
    IpsecError_t eError;
    bool bChild;
} TestCall_t;

static bool TransferTestBytes(int32_t iSocket, void *pvData, size_t zLength, bool bSend)
{
    uint8_t *pucData = (uint8_t *)pvData;
    ssize_t lCount;
    size_t zOffset = 0U;

    while (zOffset < zLength) {
        lCount = bSend ? send(iSocket, pucData + zOffset, zLength - zOffset, MSG_NOSIGNAL) :
                        recv(iSocket, pucData + zOffset, zLength - zOffset, 0);
        if (lCount > 0) {
            zOffset += (size_t)lCount;
        }
        else if ((lCount < 0) && (EINTR == errno)) {
            continue;
        }
        else {
            return false;
        }
    }
    return true;
}

static void SendTestPacket(int32_t iSocket, ViciPacketType_t eType,
                           const char *pcName, const ViciBuffer_t *pMessage)
{
    ViciBuffer_t Packet = {0};
    uint32_t uiNetworkLength;
    uint8_t ucType = (uint8_t)eType;

    if (NULL != pcName) {
        CHECK(IPSEC_OK == BuildViciNamedPacket(eType, pcName, pMessage, &Packet));
    }
    else {
        CHECK(IPSEC_OK == InitializeViciBuffer(&Packet, 64U, false));
        CHECK(IPSEC_OK == AppendViciBuffer(&Packet, &ucType, 1U));
        if (NULL != pMessage) {
            CHECK(IPSEC_OK == AppendViciBuffer(&Packet, pMessage->pucData, pMessage->uiLength));
        }
    }
    uiNetworkLength = htonl(Packet.uiLength);
    /* Cancellation can close the peer while a response is being sent. */
    if (TransferTestBytes(iSocket, &uiNetworkLength, sizeof(uiNetworkLength), true)) {
        (void)TransferTestBytes(iSocket, Packet.pucData, Packet.uiLength, true);
    }
    DestroyViciBuffer(&Packet);
}

static void SendTestSnapshot(TestServer_t *pServer, int32_t iSocket)
{
    ViciBuffer_t Message = {0};
    uint8_t ucBadElement = (uint8_t)VICI_ELEMENT_SECTION_END;

    CHECK(IPSEC_OK == InitializeViciBuffer(&Message, 256U, false));
    if ((TEST_BAD_STREAM == pServer->eMode) && (1U == atomic_load(&pServer->uiQueries))) {
        CHECK(IPSEC_OK == AppendViciBuffer(&Message, &ucBadElement, 1U));
    }
    else {
        CHECK(IPSEC_OK == AddViciSectionStart(&Message, pServer->bReady ? "vpn1" : "other"));
        CHECK(IPSEC_OK == AddViciKeyValueString(&Message, "state", "ESTABLISHED"));
        CHECK(IPSEC_OK == AddViciSectionStart(&Message, "child-sas"));
        CHECK(IPSEC_OK == AddViciSectionStart(&Message, "child-1"));
        CHECK(IPSEC_OK == AddViciKeyValueString(&Message, "name", pServer->bReady ? "child1" : "other-child"));
        CHECK(IPSEC_OK == AddViciKeyValueString(&Message, "state", "INSTALLED"));
        CHECK(IPSEC_OK == AddViciSectionEnd(&Message));
        CHECK(IPSEC_OK == AddViciSectionEnd(&Message));
        CHECK(IPSEC_OK == AddViciSectionEnd(&Message));
    }
    SendTestPacket(iSocket, VICI_PACKET_EVENT, "list-sa", &Message);
    DestroyViciBuffer(&Message);
}

static void EmitTestChanges(TestServer_t *pServer)
{
    uint32_t uiIndex;
    uint32_t uiLength = htonl(20U);

    for (uiIndex = 0U; uiIndex < TEST_CLIENT_LIMIT; uiIndex++) {
        TestClient_t *pClient = &pServer->aClients[uiIndex];
        if ((pClient->iSocket >= 0) && pClient->bEvent) {
            if (TEST_RECONNECT == pServer->eMode) {
                (void)close(pClient->iSocket);
                pClient->iSocket = -1;
            }
            else if (TEST_PARTIAL_FRAME == pServer->eMode) {
                (void)TransferTestBytes(pClient->iSocket, &uiLength, sizeof(uiLength), true);
            }
            else {
                SendTestPacket(pClient->iSocket, VICI_PACKET_EVENT,
                               pClient->bChild ? "child-updown" : "ike-updown", NULL);
            }
        }
    }
}

static bool MatchTestName(const ViciPacketView_t *pView, const char *pcName)
{
    return (strlen(pcName) == pView->ucNameLength) &&
           (0 == memcmp(pcName, pView->pucName, pView->ucNameLength));
}

static void HandleTestPacket(TestServer_t *pServer, TestClient_t *pClient,
                              const ViciPacketView_t *pView)
{
    bool bSaEvent = (VICI_PACKET_EVENT_REGISTER == pView->eType) &&
                   !MatchTestName(pView, "list-sa") && !MatchTestName(pView, "list-conn");
    ViciBuffer_t Message = {0};

    if ((VICI_PACKET_EVENT_REGISTER == pView->eType) ||
        (VICI_PACKET_EVENT_UNREGISTER == pView->eType)) {
        if (bSaEvent) {
            pClient->bEvent = true;
            pClient->bChild = (pView->ucNameLength >= 5U) &&
                             (0 == memcmp(pView->pucName, "child", 5U));
            pClient->uiRegistrations++;
            if ((2U == pClient->uiRegistrations) && (TEST_EVENT == pServer->eMode)) {
                SendTestPacket(pClient->iSocket, VICI_PACKET_EVENT,
                               pClient->bChild ? "child-updown" : "ike-updown", NULL);
            }
        }
        SendTestPacket(pClient->iSocket,
                       (bSaEvent && (TEST_UNKNOWN_EVENT == pServer->eMode)) ?
                       VICI_PACKET_EVENT_UNKNOWN : VICI_PACKET_EVENT_CONFIRM, NULL, NULL);
    }
    else if ((VICI_PACKET_COMMAND_REQUEST == pView->eType) && MatchTestName(pView, "list-sas")) {
        (void)atomic_fetch_add(&pServer->uiQueries, 1U);
        SendTestSnapshot(pServer, pClient->iSocket);
        if ((1U == atomic_load(&pServer->uiQueries)) &&
            ((TEST_EVENT == pServer->eMode) || (TEST_RECONNECT == pServer->eMode) ||
             (TEST_PARTIAL_FRAME == pServer->eMode))) {
            /* Deliberately signal before the snapshot command's final response. */
            pServer->bReady = true;
            EmitTestChanges(pServer);
        }
        if (TEST_BAD_STREAM == pServer->eMode) {
            pServer->bReady = true;
        }
        SendTestPacket(pClient->iSocket, VICI_PACKET_COMMAND_RESPONSE, NULL, NULL);
    }
    else if (((TEST_UNLOAD_ABSENT == pServer->eMode) || (TEST_UNLOAD_PRESENT == pServer->eMode)) &&
             MatchTestName(pView, "unload-conn")) {
        CHECK(IPSEC_OK == InitializeViciBuffer(&Message, 128U, false));
        CHECK(IPSEC_OK == AddViciKeyValueString(&Message, "success", "no"));
        CHECK(IPSEC_OK == AddViciKeyValueString(&Message, "errmsg", "unload refused"));
        SendTestPacket(pClient->iSocket, VICI_PACKET_COMMAND_RESPONSE, NULL, &Message);
        DestroyViciBuffer(&Message);
    }
    else if (MatchTestName(pView, "list-conns")) {
        if (TEST_UNLOAD_PRESENT == pServer->eMode) {
            CHECK(IPSEC_OK == InitializeViciBuffer(&Message, 128U, false));
            CHECK(IPSEC_OK == AddViciSectionStart(&Message, "vpn1"));
            CHECK(IPSEC_OK == AddViciSectionEnd(&Message));
            SendTestPacket(pClient->iSocket, VICI_PACKET_EVENT, "list-conn", &Message);
            DestroyViciBuffer(&Message);
        }
        SendTestPacket(pClient->iSocket, VICI_PACKET_COMMAND_RESPONSE, NULL, NULL);
    }
    else if (MatchTestName(pView, "hold")) {
        pServer->iHeldSocket = pClient->iSocket;
        pServer->ullReleaseMs = GetIpsecMonotonicMilliseconds() + 300U;
        atomic_store(&pServer->bHeld, true);
    }
    else if (MatchTestName(pView, "unsupported")) {
        SendTestPacket(pClient->iSocket, VICI_PACKET_COMMAND_UNKNOWN, NULL, NULL);
    }
    else if ((TEST_REJECT_SECRET == pServer->eMode) && MatchTestName(pView, "load-shared")) {
        CHECK(IPSEC_OK == InitializeViciBuffer(&Message, 64U, true));
        CHECK(IPSEC_OK == AddViciKeyValueString(&Message, "success", "no"));
        CHECK(IPSEC_OK == AddViciKeyValueString(&Message, "errmsg", "SECRET_TEST_VALUE"));
        SendTestPacket(pClient->iSocket, VICI_PACKET_COMMAND_RESPONSE, NULL, &Message);
        DestroyViciBuffer(&Message);
    }
    else {
        SendTestPacket(pClient->iSocket, VICI_PACKET_COMMAND_RESPONSE, NULL, NULL);
    }
}

static void *RunTestServer(void *pvData)
{
    TestServer_t *pServer = (TestServer_t *)pvData;
    struct pollfd aDescriptors[TEST_CLIENT_LIMIT + 1U];
    struct timeval SocketTimeout = {2, 0};
    uint8_t aucPacket[4096];
    uint32_t uiNetworkLength;
    uint32_t uiLength;
    uint32_t uiIndex;
    ViciPacketView_t View;

    while (!atomic_load(&pServer->bStop)) {
        if (atomic_load(&pServer->bHeld) &&
            (GetIpsecMonotonicMilliseconds() >= pServer->ullReleaseMs)) {
            SendTestPacket(pServer->iHeldSocket, VICI_PACKET_COMMAND_RESPONSE, NULL, NULL);
            atomic_store(&pServer->bHeld, false);
        }
        memset(aDescriptors, 0, sizeof(aDescriptors));
        aDescriptors[0].fd = pServer->iListener;
        aDescriptors[0].events = POLLIN;
        for (uiIndex = 0U; uiIndex < TEST_CLIENT_LIMIT; uiIndex++) {
            aDescriptors[uiIndex + 1U].fd = pServer->aClients[uiIndex].iSocket;
            aDescriptors[uiIndex + 1U].events = POLLIN;
        }
        if (poll(aDescriptors, TEST_CLIENT_LIMIT + 1U, 10) <= 0) {
            continue;
        }
        for (uiIndex = 0U; uiIndex < TEST_CLIENT_LIMIT; uiIndex++) {
            TestClient_t *pClient = &pServer->aClients[uiIndex];
            if ((pClient->iSocket < 0) || (0 == aDescriptors[uiIndex + 1U].revents)) {
                continue;
            }
            if (!TransferTestBytes(pClient->iSocket, &uiNetworkLength, sizeof(uiNetworkLength), false)) {
                (void)close(pClient->iSocket);
                pClient->iSocket = -1;
                continue;
            }
            uiLength = ntohl(uiNetworkLength);
            CHECK((uiLength > 0U) && (uiLength <= sizeof(aucPacket)));
            if (!TransferTestBytes(
                    pClient->iSocket, aucPacket, uiLength, false)) {
                /* A cancelled wait may close its transport after the length
                 * header was sent but before the request body was completed.
                 * A real VICI server drops only that truncated connection.
                 */
                (void)close(pClient->iSocket);
                pClient->iSocket = -1;
                continue;
            }
            CHECK(IPSEC_OK == DecodeViciPacket(aucPacket, uiLength, &View));
            HandleTestPacket(pServer, pClient, &View);
        }
        if (0 != (aDescriptors[0].revents & POLLIN)) {
            for (uiIndex = 0U; uiIndex < TEST_CLIENT_LIMIT; uiIndex++) {
                if (pServer->aClients[uiIndex].iSocket < 0) {
                    memset(&pServer->aClients[uiIndex], 0, sizeof(pServer->aClients[uiIndex]));
                    pServer->aClients[uiIndex].iSocket = accept(pServer->iListener, NULL, NULL);
                    CHECK(pServer->aClients[uiIndex].iSocket >= 0);
                    CHECK(0 == setsockopt(pServer->aClients[uiIndex].iSocket, SOL_SOCKET,
                                         SO_RCVTIMEO, &SocketTimeout, sizeof(SocketTimeout)));
                    (void)atomic_fetch_add(&pServer->uiAccepted, 1U);
                    break;
                }
            }
            CHECK(uiIndex < TEST_CLIENT_LIMIT);
        }
    }
    for (uiIndex = 0U; uiIndex < TEST_CLIENT_LIMIT; uiIndex++) {
        if (pServer->aClients[uiIndex].iSocket >= 0) {
            (void)close(pServer->aClients[uiIndex].iSocket);
        }
    }
    return NULL;
}

static IpsecContext_t *StartTestServer(TestServer_t *pServer, TestMode_t eMode)
{
    struct sockaddr_un Address = {0};
    IpsecConfig_t Config = {0};
    IpsecContext_t *pContext = NULL;
    uint32_t uiIndex;
    int32_t iLength;

    memset(pServer, 0, sizeof(*pServer));
    atomic_init(&pServer->bStop, false);
    atomic_init(&pServer->bHeld, false);
    atomic_init(&pServer->uiQueries, 0U);
    atomic_init(&pServer->uiAccepted, 0U);
    pServer->eMode = eMode;
    for (uiIndex = 0U; uiIndex < TEST_CLIENT_LIMIT; uiIndex++) {
        pServer->aClients[uiIndex].iSocket = -1;
    }
    (void)snprintf(pServer->acDirectory, sizeof(pServer->acDirectory), "/tmp/ipsecctrl-XXXXXX");
    CHECK(NULL != mkdtemp(pServer->acDirectory));
    iLength = snprintf(pServer->acSocketPath, sizeof(pServer->acSocketPath),
                       "%s/vici", pServer->acDirectory);
    CHECK((iLength > 0) && ((size_t)iLength < sizeof(pServer->acSocketPath)));
    pServer->iListener = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    CHECK(pServer->iListener >= 0);
    Address.sun_family = AF_UNIX;
    memcpy(Address.sun_path, pServer->acSocketPath, (size_t)iLength + 1U);
    CHECK(0 == bind(pServer->iListener, (const struct sockaddr *)&Address, sizeof(Address)));
    CHECK(0 == listen(pServer->iListener, 16));
    CHECK(0 == pthread_create(&pServer->Thread, NULL, RunTestServer, pServer));
    Config.uiStructSize = sizeof(Config);
    Config.pcViciSocketPath = pServer->acSocketPath;
    Config.uiCommandTimeoutMs = 500U;
    Config.uiConnectTimeoutMs = 200U;
    CHECK(IPSEC_OK == InitializeIpsec(&pContext, &Config));
    return pContext;
}

static void StopTestServer(TestServer_t *pServer, IpsecContext_t *pContext)
{
    DeinitializeIpsec(pContext);
    atomic_store(&pServer->bStop, true);
    CHECK(0 == pthread_join(pServer->Thread, NULL));
    CHECK(0 == close(pServer->iListener));
    CHECK(0 == unlink(pServer->acSocketPath));
    CHECK(0 == rmdir(pServer->acDirectory));
}

static void TestEventWait(bool bChild, TestMode_t eMode)
{
    TestServer_t Server;
    IpsecContext_t *pContext = StartTestServer(&Server, eMode);
    IpsecError_t eError = bChild ? WaitIpsecChildInstalled(pContext, "child1", 2000U) :
                                 WaitIpsecIkeEstablished(pContext, "vpn1", 2000U);

    CHECK(IPSEC_OK == eError);
    CHECK(2U == atomic_load(&Server.uiQueries));
    if (TEST_RECONNECT == eMode) {
        CHECK(atomic_load(&Server.uiAccepted) >= 3U);
    }
    StopTestServer(&Server, pContext);
}

static void TestWaitTimeout(TestMode_t eMode)
{
    TestServer_t Server;
    IpsecContext_t *pContext = StartTestServer(&Server, eMode);
    uint64_t ullStartMs = GetIpsecMonotonicMilliseconds();

    CHECK(IPSEC_ERR_VICI_TIMEOUT == WaitIpsecIkeEstablished(pContext, "vpn1", 600U));
    CHECK((GetIpsecMonotonicMilliseconds() - ullStartMs) < 1200U);
    if (TEST_UNKNOWN_EVENT != eMode) {
        CHECK(1U == atomic_load(&Server.uiQueries));
    }
    else {
        CHECK(atomic_load(&Server.uiQueries) >= 2U);
    }
    StopTestServer(&Server, pContext);
}

static void *RunTestWait(void *pvData)
{
    TestCall_t *pCall = (TestCall_t *)pvData;
    pCall->eError = pCall->bChild ? WaitIpsecChildInstalled(pCall->pContext, "child1", 5000U) :
                                  WaitIpsecIkeEstablished(pCall->pContext, "vpn1", 5000U);
    return NULL;
}

static void *RunTestHold(void *pvData)
{
    TestCall_t *pCall = (TestCall_t *)pvData;
    pCall->eError = ExecuteViciCommand(pCall->pContext, "hold", NULL, NULL,
                                      NULL, NULL, NULL, NULL);
    return NULL;
}

static void TestCancelAndClose(bool bClose)
{
    TestServer_t Server;
    IpsecContext_t *pContext = StartTestServer(&Server, TEST_SILENT);
    TestCall_t aCalls[2] = {{pContext, IPSEC_OK, false}, {pContext, IPSEC_OK, true}};
    pthread_t aThreads[2];
    uint64_t ullDeadlineMs = GetIpsecMonotonicMilliseconds() + 2000U;
    uint32_t uiIndex;

    for (uiIndex = 0U; uiIndex < 2U; uiIndex++) {
        CHECK(0 == pthread_create(&aThreads[uiIndex], NULL, RunTestWait, &aCalls[uiIndex]));
    }
    while ((atomic_load(&Server.uiQueries) < 2U) &&
           (GetIpsecMonotonicMilliseconds() < ullDeadlineMs)) {
        CHECK(IPSEC_OK == SleepIpsecMilliseconds(1U));
    }
    CHECK(2U == atomic_load(&Server.uiQueries));
    if (bClose) {
        DeinitializeIpsec(pContext);
        pContext = NULL;
    }
    else {
        CHECK(IPSEC_OK == CancelIpsecWaits(pContext));
    }
    for (uiIndex = 0U; uiIndex < 2U; uiIndex++) {
        CHECK(0 == pthread_join(aThreads[uiIndex], NULL));
        CHECK(IPSEC_ERR_CANCELLED == aCalls[uiIndex].eError);
    }
    if (!bClose) {
        /* Cancellation is not sticky for later waits. */
        CHECK(IPSEC_ERR_VICI_TIMEOUT == WaitIpsecChildInstalled(pContext, "child1", 100U));
    }
    StopTestServer(&Server, pContext);
}

static void TestQueueDeadline(void)
{
    TestServer_t Server;
    IpsecContext_t *pContext = StartTestServer(&Server, TEST_SILENT);
    TestCall_t Call = {pContext, IPSEC_OK, false};
    pthread_t Thread;
    uint64_t ullStartMs;
    uint64_t ullDeadlineMs = GetIpsecMonotonicMilliseconds() + 1000U;
    IpsecDiagnostic_t Diagnostic = {0};

    CHECK(0 == pthread_create(&Thread, NULL, RunTestHold, &Call));
    while (!atomic_load(&Server.bHeld) && (GetIpsecMonotonicMilliseconds() < ullDeadlineMs)) {
        CHECK(IPSEC_OK == SleepIpsecMilliseconds(1U));
    }
    CHECK(atomic_load(&Server.bHeld));
    ullStartMs = GetIpsecMonotonicMilliseconds();
    CHECK(IPSEC_ERR_VICI_TIMEOUT == WaitIpsecIkeEstablished(pContext, "vpn1", 60U));
    CHECK((GetIpsecMonotonicMilliseconds() - ullStartMs) < 250U);
    Diagnostic.uiStructSize = sizeof(Diagnostic);
    CHECK(IPSEC_OK == GetIpsecLastDiagnostic(pContext, &Diagnostic));
    CHECK(IPSEC_STAGE_QUEUE == Diagnostic.eStage);
    CHECK(!Diagnostic.bOutcomeUnknown);
    CHECK(0U == atomic_load(&Server.uiQueries));
    CHECK(0 == pthread_join(Thread, NULL));
    CHECK(IPSEC_OK == Call.eError);
    StopTestServer(&Server, pContext);
}

static void TestStreamRecovery(void)
{
    TestServer_t Server;
    IpsecContext_t *pContext = StartTestServer(&Server, TEST_BAD_STREAM);
    IpsecIkeSaList_t List = {0};
    IpsecDiagnostic_t Diagnostic = {0};

    CHECK(IPSEC_ERR_VICI_PROTOCOL == GetIpsecIkeSas(pContext, &List));
    CHECK(NULL == List.pItems);
    CHECK(pContext->iViciSocket < 0);
    Diagnostic.uiStructSize = sizeof(Diagnostic);
    CHECK(IPSEC_OK == GetIpsecLastDiagnostic(pContext, &Diagnostic));
    CHECK(IPSEC_STAGE_RECEIVE == Diagnostic.eStage);
    CHECK(Diagnostic.bOutcomeUnknown);
    CHECK(IPSEC_OK == GetIpsecIkeSas(pContext, &List));
    CHECK(1U == List.uiCount);
    CHECK(0 == strcmp("vpn1", List.pItems[0].acName));
    CHECK(2U == atomic_load(&Server.uiAccepted));
    FreeIpsecIkeSaList(&List);
    StopTestServer(&Server, pContext);
}

static void TestSensitiveDiagnostic(void)
{
    TestServer_t Server;
    IpsecContext_t *pContext = StartTestServer(&Server, TEST_REJECT_SECRET);
    IpsecPsk_t Psk = {0};
    IpsecDiagnostic_t Diagnostic = {0};

    Psk.uiStructSize = sizeof(Psk);
    Psk.pucData = (const uint8_t *)"SECRET_TEST_VALUE";
    Psk.uiDataLength = 17U;
    CHECK(IPSEC_ERR_INVALID_ARGUMENT == AddIpsecPsk(pContext, NULL));
    CHECK(IPSEC_ERR_VICI_COMMAND == AddIpsecPsk(pContext, &Psk));
    Diagnostic.uiStructSize = sizeof(Diagnostic);
    CHECK(IPSEC_OK == GetIpsecLastDiagnostic(pContext, &Diagnostic));
    CHECK(IPSEC_STAGE_DAEMON == Diagnostic.eStage);
    CHECK(!Diagnostic.bOutcomeUnknown);
    CHECK(NULL == strstr(Diagnostic.acMessage, "SECRET"));
    CHECK(IPSEC_ERR_NOT_SUPPORTED == ExecuteViciCommand(
        pContext, "unsupported", NULL, NULL, NULL, NULL, NULL, NULL));
    CHECK(IPSEC_OK == GetIpsecLastDiagnostic(pContext, &Diagnostic));
    CHECK(!Diagnostic.bOutcomeUnknown);
    /* A missing mandatory success field must not be accepted as success. */
    CHECK(IPSEC_ERR_VICI_PROTOCOL == InitiateIpsecIke(pContext, "vpn1", NULL));
    CHECK(IPSEC_OK == GetIpsecLastDiagnostic(pContext, &Diagnostic));
    CHECK(Diagnostic.bOutcomeUnknown);
    StopTestServer(&Server, pContext);
}

static void VerifyIdempotentUnload(bool bPresent)
{
    TestServer_t Server;
    IpsecDiagnostic_t Diagnostic = {.uiStructSize = sizeof(Diagnostic)};
    IpsecContext_t *pContext = StartTestServer(&Server,
        bPresent ? TEST_UNLOAD_PRESENT : TEST_UNLOAD_ABSENT);
    CHECK((bPresent ? IPSEC_ERR_VICI_COMMAND : IPSEC_OK) == RemoveIpsecConnection(pContext, "vpn1"));
    if (bPresent) {
        CHECK(IPSEC_OK == GetIpsecLastDiagnostic(pContext, &Diagnostic));
        CHECK(IPSEC_ERR_VICI_COMMAND == Diagnostic.eError);
        CHECK(IPSEC_STAGE_DAEMON == Diagnostic.eStage);
    }
    else {
        CHECK(IPSEC_OK == RemoveIpsecConnection(pContext, "vpn1"));
    }
    StopTestServer(&Server, pContext);
}

int main(void)
{
    TestEventWait(false, TEST_EVENT);
    TestEventWait(true, TEST_EVENT);
    TestEventWait(false, TEST_RECONNECT);
    TestWaitTimeout(TEST_SILENT);
    TestWaitTimeout(TEST_UNKNOWN_EVENT);
    TestWaitTimeout(TEST_PARTIAL_FRAME);
    TestCancelAndClose(false);
    TestCancelAndClose(true);
    TestQueueDeadline();
    TestStreamRecovery();
    TestSensitiveDiagnostic();
    VerifyIdempotentUnload(false);
    VerifyIdempotentUnload(true);
    return 0;
}
