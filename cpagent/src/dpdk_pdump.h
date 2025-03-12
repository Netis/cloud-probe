#ifndef CPAGENT_DPDK_PDUMP_H
#define CPAGENT_DPDK_PDUMP_H

#include "capturer.h"
#include <rte_mempool.h>
#include <rte_ring.h>
#include <stdint.h>

struct DpdkCaptureParams
{
    char *interface;
    uint32_t snaplen;
    bool promiscuous_mode;
    char *filter_str;

    char *pool_name;
    char *ring_name;
    uint32_t ring_size;
    size_t num_mbufs;
};

typedef struct DpdkCapturer
{
    PacketCapturerBase base;

    uint16_t port;
    bool promiscuous_mode;
    uint32_t snaplen;

    struct rte_bpf_prm *bpf_prm;
    struct rte_ring *ring;
    struct rte_mempool *mp;
} dpdk_capturer_t;

dpdk_capturer_t *new_dpdk_capturer(struct DpdkCaptureParams params, char *errbuf);
void free_dpdk_capturer(PacketCapturerBase *self);

#endif /* CPAGENT_DPDKDUMP_H */