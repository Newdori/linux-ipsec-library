#include <stddef.h>
#include <stdint.h>

void SecureZeroIpsec(void *pvMemory, size_t zLength)
{
    volatile uint8_t *pucByte = (volatile uint8_t *)pvMemory;

    if (NULL != pucByte) {
        while (0U < zLength) {
            *pucByte = 0U;
            pucByte++;
            zLength--;
        }
    }
    else {
        /* Nothing to clear. */
    }
}
