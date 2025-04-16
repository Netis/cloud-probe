#ifndef CPAGENT_STATS_H
#define CPAGENT_STATS_H

#include <stdint.h>

#define EIB_IN_BYTES (1024ULL * 1024 * 1024 * 1024 * 1024 * 1024) // 1 EiB = 2^60 bytes
#define PETA_IN_PACKETS 10000000000000000ULL                      // 1 Peta = 10^16 packets

typedef struct
{
    uint64_t bytes;
    uint64_t eib;
} bytes_stats_t;

typedef struct
{
    uint64_t packets;
    uint64_t peta;
} packets_stats_t;

void bytes_stats_add(bytes_stats_t *stat, uint64_t bytes);
void packets_stats_add(packets_stats_t *stat, uint64_t packets);

#endif /* CPAGENT_STATS_H */