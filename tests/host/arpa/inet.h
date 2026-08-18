#ifndef IPSEC_TEST_ARPA_INET_H
#define IPSEC_TEST_ARPA_INET_H

#if defined(_WIN32)

#include <winsock2.h>
#include <ws2tcpip.h>

#ifndef inet_pton
#define inet_pton InetPtonA
#endif

#else

#include <stdint.h>

static inline uint16_t htons(uint16_t usValue)
{
    return (uint16_t)((uint16_t)(usValue << 8U) |
                      (uint16_t)(usValue >> 8U));
}

static inline uint16_t ntohs(uint16_t usValue)
{
    return htons(usValue);
}

#endif

#endif
