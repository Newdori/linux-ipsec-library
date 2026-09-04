#ifndef NATIVE_APP_ALGORITHM_PACKET_H
#define NATIVE_APP_ALGORITHM_PACKET_H

#include "app_internal.h"
#include <stdio.h>

#define NATIVE_APP_RELAY_CAPACITY 4096U
#define NATIVE_APP_PROBE_LENGTH 128U
#define NATIVE_APP_PROBE_PORT 48150U
#define NATIVE_APP_PROBE_COUNT 2U
_Static_assert(NATIVE_APP_PACKET_EVIDENCE_CAPACITY == NATIVE_APP_PROBE_COUNT * 2U,
    "packet evidence must cover both probe directions");

bool IsNativeAppAlgorithmApplication(const NativeAppConfig_t *pConfig);
IpsecError_t ValidateNativeAppAlgorithmPacketConfig(const NativeAppConfig_t *pConfig);
IpsecError_t OpenNativeAppAlgorithmStream(const NativeAppConfig_t *pConfig,
    uint32_t uiPort, bool bServer, int32_t *piSocket);
IpsecError_t SendNativeAppTestFrame(int32_t iSocket, const uint8_t *pucData,
    size_t zLength, uint64_t ullDeadline);
IpsecError_t ReceiveNativeAppTestFrame(int32_t iSocket, uint8_t *pucData,
    size_t zCapacity, size_t *pzLength, uint64_t ullDeadline);
uint64_t GetNativeAppPacketTestTime(void);
void EncodeNativeAppTestLength(uint8_t *pucHeader, uint32_t uiLength);
IpsecError_t DecodeNativeAppTestLength(const uint8_t *pucHeader,
    size_t zCapacity, size_t *pzLength);
void BuildNativeAppTestProbe(uint8_t *pucProbe, const uint8_t *pucNonce,
    const char *pcCaseId, uint32_t uiSequence);
IpsecError_t ValidateNativeAppTestPlain(const uint8_t *pucData, size_t zLength,
    const uint8_t *pucSource, const uint8_t *pucDestination,
    const uint8_t *pucProbe);
IpsecError_t InspectNativeAppTestEsp(const uint8_t *pucData, size_t zLength,
    uint32_t uiExpectedSpi, NativeAppPacketEvidence_t *pEvidence);
bool VerifyNativeAppPacketTestProof(const NativeAppPacketTestResult_t *pResult);
IpsecError_t WriteNativeAppPacketEvidenceJson(FILE *pFile,
    const NativeAppPacketTestResult_t *pResult);
IpsecError_t WriteNativeAppPacketEvidenceText(FILE *pFile,
    const NativeAppPacketTestResult_t *pResult);
IpsecError_t WriteNativeAppPacketEvidenceCsv(FILE *pFile,
    const NativeAppPacketTestResult_t *pResult);
IpsecError_t RunNativeAppAlgorithmPacketTest(IpsecContext_t *pContext,
    const NativeAppConfig_t *pConfig, int32_t iSocket, const char *pcCaseId,
    bool bServer, const char *pcDirectory, NativeAppPacketTestResult_t *pResult);

#endif
