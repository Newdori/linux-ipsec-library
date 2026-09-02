#include "vici_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void *gpvTrackedAllocation;
static uint32_t guiTrackedCapacity;
static uint32_t guiWipedFrees;

void TrackTestFree(void *pvData)
{
    uint32_t uiIndex;
    const uint8_t *pucData = (const uint8_t *)pvData;

    if ((NULL != pvData) && (gpvTrackedAllocation == pvData)) {
        for (uiIndex = 0U; uiIndex < guiTrackedCapacity; uiIndex++) {
            if (0U != pucData[uiIndex]) {
                (void)fprintf(stderr, "sensitive allocation was freed without wiping\n");
                exit(EXIT_FAILURE);
            }
        }
        guiWipedFrees++;
        gpvTrackedAllocation = NULL;
    }
    free(pvData);
}

int main(void)
{
    ViciBuffer_t Buffer = {0};
    uint8_t aucSecret[64];
    uint32_t uiIndex;

    memset(aucSecret, 0x5a, sizeof(aucSecret));
    if ((IPSEC_OK != InitializeViciBuffer(&Buffer, 64U, true)) ||
        (IPSEC_OK != AppendViciBuffer(&Buffer, aucSecret, sizeof(aucSecret)))) {
        return 1;
    }
    gpvTrackedAllocation = Buffer.pucData;
    guiTrackedCapacity = Buffer.uiCapacity;
    if ((IPSEC_OK != AppendViciBuffer(&Buffer, aucSecret, sizeof(aucSecret))) ||
        (1U != guiWipedFrees) || (128U != Buffer.uiLength)) {
        return 1;
    }
    for (uiIndex = 0U; uiIndex < Buffer.uiLength; uiIndex++) {
        if (0x5aU != Buffer.pucData[uiIndex]) {
            return 1;
        }
    }
    gpvTrackedAllocation = Buffer.pucData;
    guiTrackedCapacity = Buffer.uiCapacity;
    DestroyViciBuffer(&Buffer);
    return (2U == guiWipedFrees) ? 0 : 1;
}
