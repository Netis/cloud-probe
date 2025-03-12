/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2019-2020 Microsoft Corporation
 *
 * DPDK application to dump network traffic
 * This is designed to look and act like the Wireshark
 * dumpcap program.
 */

#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <time.h>
#include <unistd.h>

#include <rte_alarm.h>
#include <rte_bpf.h>
#include <rte_config.h>
#include <rte_debug.h>
#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ethdev.h>
#include <rte_lcore.h>
#include <rte_malloc.h>
#include <rte_mbuf.h>
#include <rte_mempool.h>
#include <rte_pcapng.h>
#include <rte_pdump.h>
#include <rte_ring.h>
#include <rte_string_fns.h>
#include <rte_time.h>
#include <rte_version.h>

#include <pcap/bpf.h>
#include <pcap/pcap.h>

#include "error.h"

#define MONITOR_INTERVAL (500 * 1000)
#define MBUF_POOL_CACHE_SIZE 32
#define BURST_SIZE 32
#define SLEEP_THRESHOLD 1000

static bool quit_signal;

struct interface
{
    uint16_t port;
    char name[RTE_ETH_NAME_MAX_LEN];
};

/* Can do either pcap or pcapng format output */
typedef union
{
    rte_pcapng_t *pcapng;
    pcap_dumper_t *dumper;
} dumpcap_out_t;

static struct rte_bpf_prm *compile_filter(const char *filter_str, char *errbuf)
{
    struct bpf_program bf;
    pcap_t *pcap;

    pcap = pcap_open_dead(DLT_EN10MB, 2048);
    if (!pcap)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "can not open pcap");
        return NULL;
    }

    if (pcap_compile(pcap, &bf, filter_str, 1, PCAP_NETMASK_UNKNOWN) != 0)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "pcap filter string not valid (%s)", pcap_geterr(pcap));
        return NULL;
    }

    struct rte_bpf_prm *bpf_prm = rte_bpf_convert(&bf);
    if (bpf_prm == NULL)
    {
        snprintf(
            errbuf, ERROR_BUFFER_SIZE, "convert a bpf program to dpdk bpf code error: %s", rte_strerror(rte_errno));
        pcap_freecode(&bf);
        pcap_close(pcap);
        return NULL;
    }

    /* Don't care about original program any more */
    pcap_freecode(&bf);
    pcap_close(pcap);
    return bpf_prm;
}

/* Return the time since 1/1/1970 in nanoseconds */
static uint64_t create_timestamp(void)
{
    struct timespec now;

    clock_gettime(CLOCK_MONOTONIC, &now);
    return rte_timespec_to_ns(&now);
}

static void cleanup_pdump_resources(struct interface *intf, bool promiscuous_mode)
{
    rte_pdump_disable(intf->port, RTE_PDUMP_ALL_QUEUES, RTE_PDUMP_FLAG_RXTX);
    if (promiscuous_mode)
        rte_eth_promiscuous_disable(intf->port);
}

/* Alarm signal handler, used to check that primary process */
static void monitor_primary(void *arg __rte_unused)
{
    if (__atomic_load_n(&quit_signal, __ATOMIC_RELAXED))
        return;

    if (rte_eal_primary_proc_alive(NULL))
    {
        rte_eal_alarm_set(MONITOR_INTERVAL, monitor_primary, NULL);
    }
    else
    {
        fprintf(stderr, "Primary process is no longer active, exiting...\n");
        __atomic_store_n(&quit_signal, true, __ATOMIC_RELAXED);
    }
}

/* Setup handler to check when primary exits. */
static void enable_primary_monitor(void)
{
    int ret;

    /* Once primary exits, so will pdump. */
    ret = rte_eal_alarm_set(MONITOR_INTERVAL, monitor_primary, NULL);
    if (ret < 0)
        fprintf(stderr, "Fail to enable monitor:%d\n", ret);
}

static void disable_primary_monitor(void)
{
    int ret;

    ret = rte_eal_alarm_cancel(monitor_primary, NULL);
    if (ret < 0)
        fprintf(stderr, "Fail to disable monitor:%d\n", ret);
}

/*
 * Start DPDK EAL with arguments.
 * Unlike most DPDK programs, this application does not use the
 * typical EAL command line arguments.
 * We don't want to expose all the DPDK internals to the user.
 */
static int dpdk_init(char *errbuf)
{
    static const char *const args[] = {"dumpcap", "--proc-type", "secondary", "--log-level", "notice"};
    const int eal_argc = RTE_DIM(args);
    char **eal_argv;
    unsigned int i;

    /* DPDK API requires mutable versions of command line arguments. */
    eal_argv = calloc(eal_argc + 1, sizeof(char *));
    if (eal_argv == NULL)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "EAL init failed: : no memory");
        return -1;
    }

    eal_argv[0] = strdup("cpagent");
    for (i = 1; i < RTE_DIM(args); i++)
        eal_argv[i] = strdup(args[i]);

    if (rte_eal_init(eal_argc, eal_argv) < 0)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "EAL init failed: is primary process running?");
        return -1;
    }
    return 0;
}

/* Create packet ring shared between callbacks and process */
static struct rte_ring *create_ring(const char *ring_name, unsigned int ring_size, char *errbuf)
{
    struct rte_ring *ring;
    size_t size, log2;

    /* Find next power of 2 >= size. */
    size = ring_size;
    log2 = sizeof(size) * 8 - __builtin_clzl(size - 1);
    size = 1u << log2;

    if (size != ring_size)
    {
        fprintf(stderr, "ring size %u rounded up to %zu\n", ring_size, size);
        ring_size = size;
    }

    ring = rte_ring_lookup(ring_name);
    if (ring == NULL)
    {
        ring = rte_ring_create(ring_name, ring_size, rte_socket_id(), 0);
        if (ring == NULL)
        {
            snprintf(errbuf, ERROR_BUFFER_SIZE, "could not create ring :%s", rte_strerror(rte_errno));
            return NULL;
        }
    }
    return ring;
}

static struct rte_mempool *create_mempool(const char *pool_name, uint32_t ring_size, uint32_t snaplen, char *errbuf)
{
    size_t num_mbufs = 2 * ring_size;
    struct rte_mempool *mp;

    mp = rte_mempool_lookup(pool_name);
    if (mp)
        return mp;

    mp = rte_pktmbuf_pool_create_by_ops(
        pool_name, num_mbufs, MBUF_POOL_CACHE_SIZE, 0, rte_pcapng_mbuf_size(snaplen), rte_socket_id(), "ring_mp_sc");
    if (mp == NULL)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "mempool (%s) creation failed: %s\n", pool_name, rte_strerror(rte_errno));
        return NULL;
    }

    return mp;
}

static int enable_pdump(struct interface *intf,
    struct rte_ring *r,
    struct rte_mempool *mp,
    struct rte_bpf_prm *bpf_prm,
    bool promiscuous_mode,
    uint32_t snaplen,
    bool use_pcapng,
    char *errbuf)
{
    uint32_t flags;
    flags = RTE_PDUMP_FLAG_RXTX;
    if (use_pcapng)
        flags |= RTE_PDUMP_FLAG_PCAPNG;

    if (promiscuous_mode)
        rte_eth_promiscuous_enable(intf->port);

    int ret = rte_pdump_enable_bpf(intf->port, RTE_PDUMP_ALL_QUEUES, flags, snaplen, r, mp, bpf_prm);
    if (ret < 0)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "Packet dump enable failed: %s", rte_strerror(-ret));
        return -1;
    }
    return 0;
}

/*
 * Show current count of captured packets
 * with backspaces to overwrite last value.
 */
static void show_count(uint64_t count)
{
    unsigned int i;
    static unsigned int bt;

    for (i = 0; i < bt; i++)
        fputc('\b', stderr);

    bt = fprintf(stderr, "%" PRIu64 " ", count);
}

/* Write multiple packets in older pcap format */
static ssize_t pcap_write_packets(pcap_dumper_t *dumper, struct rte_mbuf *pkts[], uint16_t num_pkts, uint32_t snaplen)
{
    uint8_t temp_data[snaplen];
    struct pcap_pkthdr header;
    uint16_t i;
    size_t total = 0;

    gettimeofday(&header.ts, NULL);

    for (i = 0; i < num_pkts; i++)
    {
        struct rte_mbuf *m = pkts[i];

        header.len = rte_pktmbuf_pkt_len(m);
        header.caplen = RTE_MIN(header.len, snaplen);

        pcap_dump((u_char *)dumper, &header, rte_pktmbuf_read(m, 0, header.caplen, temp_data));

        total += sizeof(header) + header.len;
    }

    return total;
}

/* Process all packets in ring and dump to capture file */
static int process_ring(dumpcap_out_t out, struct rte_ring *r, uint32_t snaplen, bool use_pcapng)
{
    struct rte_mbuf *pkts[BURST_SIZE];
    unsigned int avail, n;
    static unsigned int empty_count;
    ssize_t written;

    n = rte_ring_sc_dequeue_burst(r, (void **)pkts, BURST_SIZE, &avail);
    if (n == 0)
    {
        /* don't consume endless amounts of cpu if idle */
        if (empty_count < SLEEP_THRESHOLD)
            ++empty_count;
        else
            usleep(10);
        return 0;
    }

    empty_count = (avail == 0);

    if (use_pcapng)
        written = rte_pcapng_write_packets(out.pcapng, pkts, n);
    else
        written = pcap_write_packets(out.dumper, pkts, n, snaplen);

    rte_pktmbuf_free_bulk(pkts, n);

    if (written < 0)
        return -1;

    return 0;
}
