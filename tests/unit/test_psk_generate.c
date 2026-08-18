#include "ipsec.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TEST_PSK_TEXT_LENGTH \
    ((IPSEC_GENERATED_PSK_BYTE_LENGTH * 2U) + 1U)

static bool IsTestHexCharacter(char cValue)
{
    return (((cValue >= '0') && (cValue <= '9')) ||
            ((cValue >= 'a') && (cValue <= 'f')));
}

static int32_t VerifyTestPskFile(const char *pcPath)
{
    struct stat Status;
    char acText[TEST_PSK_TEXT_LENGTH];
    FILE *pFile;
    size_t zRead;
    uint32_t uiIndex;

    if ((0 != stat(pcPath, &Status)) ||
        ((S_IRUSR | S_IWUSR) !=
         (Status.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO))) ||
        ((off_t)sizeof(acText) != Status.st_size)) {
        return 1;
    }
    else {
        pFile = fopen(pcPath, "rb");
    }
    if (NULL == pFile) {
        return 1;
    }
    else {
        zRead = fread(acText, 1U, sizeof(acText), pFile);
        (void)fclose(pFile);
    }
    if ((sizeof(acText) != zRead) || ('\n' != acText[zRead - 1U])) {
        return 1;
    }
    else {
        /* Validate the 96-character hexadecimal payload. */
    }
    for (uiIndex = 0U; uiIndex < (sizeof(acText) - 1U); uiIndex++) {
        if (!IsTestHexCharacter(acText[uiIndex])) {
            return 1;
        }
        else {
            /* Continue checking the generated text. */
        }
    }
    return 0;
}

int main(void)
{
    char acDirectory[] = "/tmp/libipsec_psk_XXXXXX";
    char acPath[256];
    IpsecError_t eError;
    int32_t iLength;
    int32_t iResult = 1;

    if (NULL == mkdtemp(acDirectory)) {
        return 1;
    }
    else {
        iLength = (int32_t)snprintf(acPath, sizeof(acPath),
                                    "%s/generated.psk", acDirectory);
    }
    if ((0 > iLength) || ((int32_t)sizeof(acPath) <= iLength)) {
        (void)rmdir(acDirectory);
        return 1;
    }
    else {
        eError = GenerateIpsecPskFile(acPath);
    }
    if ((IPSEC_OK == eError) && (0 == VerifyTestPskFile(acPath)) &&
        (IPSEC_ERR_FILE_EXISTS == GenerateIpsecPskFile(acPath))) {
        iResult = 0;
    }
    else {
        (void)fprintf(stderr, "PSK generation test failed: %s\n",
                      GetIpsecErrorString(eError));
    }
    (void)unlink(acPath);
    (void)rmdir(acDirectory);
    return iResult;
}
