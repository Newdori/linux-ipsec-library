#include "../internal/buffer_validate.h"

#include <stdint.h>

bool CalculateIpsecArraySize(
    uint32_t uiCount,
    size_t zItemSize,
    size_t *pzAllocationSize)
{
    bool bValid;

    if ((NULL == pzAllocationSize) || (0U == zItemSize) ||
        ((0U != uiCount) && ((SIZE_MAX / uiCount) < zItemSize))) {
        bValid = false;
    }
    else {
        *pzAllocationSize = (size_t)uiCount * zItemSize;
        bValid = true;
    }

    return bValid;
}
