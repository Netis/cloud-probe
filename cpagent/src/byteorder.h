#ifndef CPAGENT_BYTEORDER_H
#define CPAGENT_BYTEORDER_H

#include "config.h"

// clang-format off

/* This catches all modern GCCs (>= 4.6) and Clang (>=3.2) */
#if defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
    #define ENDIANNESS_LE 1
    #define ENDIANNESS_BE 0
#elif defined(__BYTE_ORDER__) && __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
    #define ENDIANNESS_LE 0
    #define ENDIANNESS_BE 1
#else
    #if defined(OS_LINUX)
        #include <endian.h>
    #elif defined(OS_BSD)
        #include <sys/endian.h>
    #elif defined(OS_MACOS)
        #include <machine/endian.h>
    #endif
#endif

#ifndef ENDIANNESS_LE
#undef ENDIANNESS_BE
#if defined(__BYTE_ORDER) && defined(__LITTLE_ENDIAN)
    #if __BYTE_ORDER == __LITTLE_ENDIAN
        #define ENDIANNESS_LE 1
        #define ENDIANNESS_BE 0
    #elif __BYTE_ORDER == __BIG_ENDIAN
        #define ENDIANNESS_LE 0
        #define ENDIANNESS_BE 1
    #endif
#elif defined(BYTE_ORDER) && defined(LITTLE_ENDIAN)
    #if BYTE_ORDER == LITTLE_ENDIAN
        #define ENDIANNESS_LE 1
        #define ENDIANNESS_BE 0
    #elif BYTE_ORDER == BIG_ENDIAN
        #define ENDIANNESS_LE 0
        #define ENDIANNESS_BE 1
    #endif
#endif
#endif

#if defined(ENDIANNESS_LE) && !(defined(ENDIANNESS_BE))
    #if ENDIANNESS_LE == 0
        #define ENDIANNESS_BE 1
    #else
        #define ENDIANNESS_BE 0
    #endif
#elif defined(ENDIANNESS_BE) && !(defined(ENDIANNESS_LE))
    #if ENDIANNESS_BE == 0
        #define ENDIANNESS_LE 1
    #else
        #define ENDIANNESS_LE 0
    #endif
#endif

#if !(defined(ENDIANNESS_LE))
#error "Sorry, we couldn't detect endiannes for your system! Please set -DENDIANNESS_LE=1 or 0"
#endif

#endif /* CPAGENT_BYTEORDER_H */
