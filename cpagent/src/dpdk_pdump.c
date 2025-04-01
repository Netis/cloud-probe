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

#include "common.h"
#include "dpdk_pdump.h"
#include "error.h"
#include "log.h"

#define MONITOR_INTERVAL (500 * 1000)
#define MBUF_POOL_CACHE_SIZE 32
#define BURST_SIZE 32

static bool quit_signal;

static struct rte_bpf_prm *compile_filter(const char *filter_str, uint32_t snaplen, char *errbuf)
{
    struct bpf_program bf;
    pcap_t *pcap;

    pcap = pcap_open_dead(DLT_EN10MB, snaplen);
    if (!pcap)
    {
        error_format(errbuf, "can not open pcap");
        return NULL;
    }

    if (pcap_compile(pcap, &bf, filter_str, 1, PCAP_NETMASK_UNKNOWN) != 0)
    {
        error_format(errbuf, "pcap filter string not valid (%s)", pcap_geterr(pcap));
        return NULL;
    }

    struct rte_bpf_prm *bpf_prm = rte_bpf_convert(&bf);
    if (bpf_prm == NULL)
    {
        error_format(errbuf, "convert a bpf program to dpdk bpf code error: %s", rte_strerror(rte_errno));
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

static void cleanup_pdump_resources(uint16_t port, bool promiscuous_mode)
{
    rte_pdump_disable(port, RTE_PDUMP_ALL_QUEUES, RTE_PDUMP_FLAG_RXTX);
    if (promiscuous_mode)
        rte_eth_promiscuous_disable(port);
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
int dpdk_init(char *errbuf)
{
    static const char *const args[] = {"dumpcap", "--proc-type", "secondary", "--log-level", "notice"};
    const int eal_argc = RTE_DIM(args);
    char **eal_argv;
    unsigned int i;

    /* DPDK API requires mutable versions of command line arguments. */
    eal_argv = calloc(eal_argc + 1, sizeof(char *));
    if (eal_argv == NULL)
    {
        error_format(errbuf, "EAL init failed: : no memory");
        return -1;
    }

    eal_argv[0] = strdup("cpagent");
    for (i = 1; i < RTE_DIM(args); i++)
        eal_argv[i] = strdup(args[i]);

    if (rte_eal_init(eal_argc, eal_argv) < 0)
    {
        error_format(errbuf, "EAL init failed: is primary process running?");
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
        log_info("ring size %u rounded up to %zu", ring_size, size);
        ring_size = size;
    }

    ring = rte_ring_lookup(ring_name);
    if (ring == NULL)
    {
        ring = rte_ring_create(ring_name, ring_size, rte_socket_id(), 0);
        if (ring == NULL)
        {
            error_format(errbuf, "could not create ring :%s", rte_strerror(rte_errno));
            return NULL;
        }
    }
    return ring;
}

static struct rte_mempool *create_mempool(const char *pool_name, uint32_t num_mbufs, uint32_t snaplen, char *errbuf)
{
    struct rte_mempool *mp;
    mp = rte_mempool_lookup(pool_name);
    if (mp)
        return mp;

    mp = rte_pktmbuf_pool_create_by_ops(pool_name, num_mbufs, MBUF_POOL_CACHE_SIZE, 0, rte_pcapng_mbuf_size(snaplen),
                                        rte_socket_id(), "ring_mp_sc");
    if (mp == NULL)
    {
        error_format(errbuf, "mempool (%s) creation failed: %s", pool_name, rte_strerror(rte_errno));
        return NULL;
    }

    return mp;
}

static int enable_pdump(uint16_t port, struct rte_ring *ring, struct rte_mempool *mp, struct rte_bpf_prm *bpf_prm,
                        bool promiscuous_mode, uint32_t snaplen, bool use_pcapng, char *errbuf)
{
    uint32_t flags;
    flags = RTE_PDUMP_FLAG_RXTX;
    if (use_pcapng)
        flags |= RTE_PDUMP_FLAG_PCAPNG;

    if (promiscuous_mode)
        rte_eth_promiscuous_enable(port);

    log_info("enter rte_pdump_enable_bpf, port %d", port);
    int ret = rte_pdump_enable_bpf(port, RTE_PDUMP_ALL_QUEUES, flags, snaplen, ring, mp, bpf_prm);
    if (ret < 0)
    {
        error_format(errbuf, "Packet dump enable failed: %s", rte_strerror(-ret));
        return -1;
    }
    log_info("exit rte_pdump_enable_bpf, port %d", port);
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

uint64_t dpdk_do_capture(capturer_base_t *self, PacketHandler handler, void *user)
{
    dpdk_capturer_t *capturer = (dpdk_capturer_t *)self;

    struct rte_mbuf *pkts[BURST_SIZE];
    unsigned int avail, n;
    uint8_t temp_data[capturer->snaplen];
    uint16_t i;

    n = rte_ring_sc_dequeue_burst(capturer->ring, (void **)pkts, BURST_SIZE, &avail);
    if (n == 0)
        return 0;

    struct pcap_pkthdr header;
    gettimeofday(&header.ts, NULL);

    for (i = 0; i < n; ++i)
    {
        struct rte_mbuf *m = pkts[i];

        header.len = rte_pktmbuf_pkt_len(m);
        header.caplen = RTE_MIN(header.len, capturer->snaplen);
        uint8_t *pkt_data = rte_pktmbuf_read(m, 0, header.caplen, temp_data);

        bytes_stats_add(&capturer->base.stats.cap_bytes, header.caplen);
        packets_stats_add(&capturer->base.stats.cap_packets, 1);

        int direction = PKT_DIR_UNKNOWN;
        if (capturer->req_pattern == NULL)
            direction = PKT_DIR_NONCHECK;
        else
            direction = req_pattern_judge_pkt_direction(capturer->req_pattern, &header, pkt_data);

        handler(&header, pkt_data, PKT_DIR_NONCHECK, user);
    }
    rte_pktmbuf_free_bulk(pkts, n);
    return n;
}

dpdk_capturer_t *dpdk_capturer_new(dpdk_pdump_options_t opts, char *errbuf)
{
    req_pattern_t *req_pattern = req_pattern_new_from_cfg(opts.req_pattern, opts.interface, errbuf);
    if (!req_pattern)
    {
        error_wrap_format(errbuf, "create req_pattern_t error");
        return NULL;
    }

    uint16_t port;
    if (rte_eth_dev_get_port_by_name(opts.interface, &port) != 0)
    {
        error_format(errbuf, "interface %s not found", opts.interface);
        req_pattern_destory(req_pattern);
        return NULL;
    }

    struct rte_bpf_prm *bpf_prm = NULL;
    if (opts.bpf_filter && strcmp(opts.bpf_filter, "") != 0)
    {
        bpf_prm = compile_filter(opts.bpf_filter, opts.snaplen, errbuf);
        if (!bpf_prm)
        {
            req_pattern_destory(req_pattern);
            return NULL;
        }
    }

    struct rte_ring *ring = create_ring(opts.ring_name, opts.ring_size, errbuf);
    if (!ring)
    {
        req_pattern_destory(req_pattern);
        return NULL;
    }

    struct rte_mempool *mp = create_mempool(opts.pool_name, opts.num_mbufs, opts.snaplen, errbuf);
    if (!mp)
    {

        req_pattern_destory(req_pattern);
        rte_free(bpf_prm);
        rte_ring_free(ring);
        return NULL;
    }

    if (enable_pdump(port, ring, mp, bpf_prm, opts.promiscuous_mode, opts.snaplen, false, errbuf) != 0)
    {
        req_pattern_destory(req_pattern);
        rte_free(bpf_prm);
        rte_ring_free(ring);
        rte_mempool_free(mp);
        return NULL;
    }

    dpdk_capturer_t *capturer = (dpdk_capturer_t *)calloc(1, sizeof(dpdk_capturer_t));
    if (!capturer)
    {
        req_pattern_destory(req_pattern);
        rte_free(bpf_prm);
        rte_ring_free(ring);
        rte_mempool_free(mp);

        log_info("call cleanup_pdump_resources");
        cleanup_pdump_resources(port, opts.promiscuous_mode);

        error_format(errbuf, "failed to allocate memory for dpdk_capturer_t");
        return NULL;
    }
    capturer->base.capture = dpdk_do_capture;
    capturer->base.destory = dpdk_capturer_destory;
    capturer->port = port;
    capturer->promiscuous_mode = opts.promiscuous_mode;
    capturer->snaplen = opts.snaplen;

    capturer->bpf_prm = bpf_prm;
    capturer->ring = ring;
    capturer->mp = mp;
    capturer->req_pattern = req_pattern;
    return capturer;
}

capturer_base_t *dpdk_capture_new_from_cfg(TaskConfig *task_cfg, char *errbuf)
{

    dpdk_pdump_options_t opts = {
        .interface = task_cfg->interface,
        .snaplen = task_cfg->snaplen,
        .promiscuous_mode = true,
        .bpf_filter = task_cfg->capturer.config.dpdk_pdump.bpf_filter,
        .pool_name = "cpagent_capture_mbufs",
        .ring_name = "cpagent_capture_ring",
        .ring_size = task_cfg->capturer.config.dpdk_pdump.ring_size,
        .num_mbufs = 2 * task_cfg->capturer.config.dpdk_pdump.ring_size,
        .req_pattern = task_cfg->req_pattern,
    };
    log_info("dpdk_pdump options, interface %s, snaplen %d, ring_size: %d, num_mbufs: %d, bpf_filter: `%s`",
             opts.interface, opts.snaplen, opts.ring_size, opts.num_mbufs, opts.bpf_filter);

    return (capturer_base_t *)dpdk_capturer_new(opts, errbuf);
}

void dpdk_capturer_destory(capturer_base_t *self)
{
    if (!self)
        return;

    log_info("free dpdk capturer");
    dpdk_capturer_t *capturer = (dpdk_capturer_t *)self;

    rte_free(capturer->bpf_prm);
    rte_ring_free(capturer->ring);
    rte_mempool_free(capturer->mp);

    log_info("call cleanup_pdump_resources");
    cleanup_pdump_resources(capturer->port, capturer->promiscuous_mode);

    free(capturer);
}