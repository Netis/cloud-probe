#ifndef CPAGENT_DPDK_PDUMP_H
#define CPAGENT_DPDK_PDUMP_H

#include <stdint.h>

#include <rte_mempool.h>
#include <rte_ring.h>

#include "capturer.h"
#include "common.h"
#include "req_pattern.h"
#include "taskconf.h"

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

    ReqPatternConfig req_pattern;
} dpdk_pdump_options_t;

typedef struct DpdkCapturer
{
    capturer_base_t base;

    req_pattern_t *req_pattern;

    uint16_t port;
    bool promiscuous_mode;
    uint32_t snaplen;

    struct rte_bpf_prm *bpf_prm;
    struct rte_ring *ring;
    struct rte_mempool *mp;

} dpdk_capturer_t;

int dpdk_init(char *errbuf);
capturer_base_t *dpdk_capture_new_from_cfg(TaskConfig *task_cfg, char *errbuf);
dpdk_capturer_t *dpdk_capturer_new(dpdk_pdump_options_t opts, char *errbuf);
void dpdk_capturer_destory(capturer_base_t *capturer);

#endif /* CPAGENT_DPDKDUMP_H */