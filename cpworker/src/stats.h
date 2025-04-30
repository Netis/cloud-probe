#ifndef CPWORKER_STATS_H
#define CPWORKER_STATS_H

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
void bytes_stats_merge(bytes_stats_t *dst, bytes_stats_t *src);
void packets_stats_add(packets_stats_t *stat, uint64_t packets);
void packets_stats_merge(packets_stats_t *stat, packets_stats_t *src);

#endif /* CPWORKER_STATS_H */