#ifndef CPAGENT_DPDK_PDUMP_H
#define CPAGENT_DPDK_PDUMP_H

#include "capturer.h"
#include <rte_mempool.h>
#include <rte_ring.h>
#include <stdint.h>

typedef struct DpdkPdumpOptions
{
    char *interface;
    uint32_t snaplen;
    bool promiscuous_mode;
    char *bpf_filter;

    char *pool_name;
    char *ring_name;
    uint32_t ring_size;
    size_t num_mbufs;
} dpdk_pdump_options_t;

typedef struct DpdkCapturer
{
    capturer_base_t base;

    uint16_t port;
    bool promiscuous_mode;
    uint32_t snaplen;

    struct rte_bpf_prm *bpf_prm;
    struct rte_ring *ring;
    struct rte_mempool *mp;
} dpdk_capturer_t;

int dpdk_init(char *errbuf);
dpdk_capturer_t *new_dpdk_capturer(dpdk_pdump_options_t opts, char *errbuf);
void free_dpdk_capturer(capturer_base_t *capturer);

#endif /* CPAGENT_DPDKDUMP_H */