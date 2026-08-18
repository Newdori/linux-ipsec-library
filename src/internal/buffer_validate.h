#ifndef BUFFER_VALIDATE_H
#define BUFFER_VALIDATE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

bool CalculateIpsecArraySize(
    uint32_t uiCount,
    size_t zItemSize,
    size_t *pzAllocationSize);

#endif
