#include "stats.h"

void bytes_stats_add(bytes_stats_t *stat, uint64_t bytes)
{
    uint64_t new_eib = bytes / EIB_IN_BYTES;
    uint64_t new_bytes = bytes % EIB_IN_BYTES;

    stat->bytes += new_bytes;
    if (stat->bytes >= EIB_IN_BYTES)
    {
        stat->bytes -= EIB_IN_BYTES;
        new_eib += 1;
    }

    stat->eib += new_eib;
}

void bytes_stats_merge(bytes_stats_t *dst, bytes_stats_t *src)
{
    uint64_t total_bytes = dst->bytes + src->bytes;
    uint64_t carry = total_bytes / EIB_IN_BYTES;
    dst->bytes = total_bytes % EIB_IN_BYTES;
    dst->eib += src->eib + carry;
}

void packets_stats_add(packets_stats_t *stat, uint64_t packets)
{
    uint64_t new_peta = packets / PETA_IN_PACKETS;
    uint64_t new_packets = packets % PETA_IN_PACKETS;

    stat->packets += new_packets;
    if (stat->packets >= PETA_IN_PACKETS)
    {
        stat->packets -= PETA_IN_PACKETS;
        new_peta += 1;
    }

    stat->peta += new_peta;
}

void packets_stats_merge(packets_stats_t *dst, packets_stats_t *src)
{
    uint64_t total_packets = dst->packets + src->packets;
    uint64_t carry = total_packets / PETA_IN_PACKETS;
    dst->packets = total_packets % PETA_IN_PACKETS;
    dst->peta += src->peta + carry;
}