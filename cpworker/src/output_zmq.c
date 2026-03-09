#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

#include <pcap/pcap.h>
#include <zmq.h>

#include "errorf.h"
#include "log.h"
#include "mpls.h"
#include "output.h"
#include "output_zmq.h"
#include "pkt_dir.h"
#include "stats.h"
#include "vlan.h"

static uint32_t make_mpls_hdr(int direct, uint32_t service_tag)
{
    uint32_t flag = 0;
    mpls_header *hdr = (mpls_header *)&flag;
    hdr->magic_number = 1;
    hdr->rra = direct;

    hdr->service_tag_h = service_tag >> 4;
    hdr->service_tag_l = service_tag & 0x0f;

    hdr->bottom = 1;
    hdr->reserved2 = 0xff;
    return flag;
}

static bool uuid_to_bytes(const char *uuid, uint8_t uuid_bytes[16])
{
    char clean[32];
    int clean_index = 0;
    const char *p = uuid;

    while (*p != '\0')
    {
        if (*p != '-')
        {
            if (clean_index >= 32)
                return false;
            clean[clean_index++] = *p;
        }
        p++;
    }

    if (clean_index != 32)
        return false;

    for (int i = 0; i < 32; i += 2)
    {
        char byte_str[3] = {clean[i], clean[i + 1], '\0'};
        char *endptr;
        unsigned long val = strtoul(byte_str, &endptr, 16);

        if (endptr != byte_str + 2 || val > 0xFF)
        {
            return false;
        }

        uuid_bytes[i / 2] = (uint8_t)val;
    }

    return true;
}

#define ERROR_INFO_FLUSH_MAX_DUR_SEC 5

static void flush_error_info(zmq_output_t *output)
{
    output->error_info.first_pktsec = 0;

    if (output->error_info.nb_too_small_packets > 0)
    {
        log_warn("zmq output: nb_too_small_packets=%lu (dropped)", output->error_info.nb_too_small_packets);
        output->error_info.nb_too_small_packets = 0;
    }

    if (output->error_info.nb_drop_batches > 0 || output->error_info.nb_drop_packets > 0)
    {
        log_error("zmq output error: nb_drop_batches=%lu, nb_drop_packets=%lu, detail: %s",
                  output->error_info.nb_drop_batches, output->error_info.nb_drop_packets,
                  output->error_info.send_error);

        output->error_info.nb_drop_batches = 0;
        output->error_info.nb_drop_packets = 0;
        output->error_info.send_error[0] = '\0';
    }
}

int zmq_flush_packet(zmq_output_t *output)
{
    zmq_pkts_buf_t *pkts_buf = &output->pkts_buf;

    uint16_t send_num = pkts_buf->batch_hdr.pkts_num;
    pkts_buf->batch_hdr.pkts_num = htons(send_num);
    memcpy((&(pkts_buf->buf[0])), &pkts_buf->batch_hdr, sizeof(pkts_buf->batch_hdr));

    // check error_info
    if (output->error_info.first_pktsec == 0)
        output->error_info.first_pktsec = pkts_buf->first_pktsec;
    else if (pkts_buf->first_pktsec > output->error_info.first_pktsec + ERROR_INFO_FLUSH_MAX_DUR_SEC)
    {
        flush_error_info(output);
        output->error_info.first_pktsec = pkts_buf->first_pktsec;
    }

    int rc = zmq_send(output->pusher, &(pkts_buf->buf[0]), pkts_buf->batch_bufpos, ZMQ_DONTWAIT);
    if (rc != -1)
    {
        bytes_stats_add(&output->base.stats->fwd_bytes, pkts_buf->batch_bufpos);
        packets_stats_add(&output->base.stats->fwd_packets, send_num);
    }
    else
    {
        if (output->error_info.nb_drop_batches == 0)
            snprintf(output->error_info.send_error, ERROR_BUFFER_SIZE, "zmq_send failed: %s", zmq_strerror(errno));

        output->error_info.nb_drop_batches++;
        output->error_info.nb_drop_packets += send_num;

        bytes_stats_add(&output->base.stats->error_drop_bytes, pkts_buf->batch_bufpos);
        packets_stats_add(&output->base.stats->error_drop_packets, send_num);
    }

    pkts_buf->first_pktsec = 0;
    pkts_buf->batch_bufpos = sizeof(zmq_pkt_batch_hdr_t);
    pkts_buf->batch_hdr.pkts_num = 0;
    return 0;
}

static inline void zmq_flush_if_stale(zmq_output_t *output, time_t now)
{
    zmq_pkts_buf_t *pkts_buf = &output->pkts_buf;
    if (pkts_buf->batch_hdr.pkts_num > 0 && pkts_buf->first_pktsec != 0 &&
        now > pkts_buf->first_pktsec + ZMQ_PKTS_FLUSH_MAX_DUR_SEC)
    {
        zmq_flush_packet(output);
    }
}

int zmq_send_packet(output_base_t *self, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct)
{
    zmq_output_t *output = (zmq_output_t *)self;

    int32_t caplen = header->caplen;
    if (output->slice > 0 && output->slice < caplen)
        caplen = output->slice;

    // Minimum caplen: ethernet header (14) + optional VLAN tag (4) must fit
    // to avoid underflow in payload_copy_len calculation
    if (caplen < (int32_t)(sizeof(struct ether_header) + sizeof(struct vlan_header)))
    {
        output->error_info.nb_too_small_packets++;
        return -1;
    }

    uint16_t length = (uint16_t)(caplen <= 65531 ? caplen : 65531) + sizeof(mpls_header);
    zmq_pkts_buf_t *pkts_buf = &output->pkts_buf;

    if (direct == PKT_DIR_UNKNOWN)
    {
        bytes_stats_add(&output->base.stats->direction_drop_bytes, length);
        packets_stats_add(&output->base.stats->direction_drop_packets, 1);

        zmq_flush_if_stale(output, header->ts.tv_sec);
        return -1;
    }

    if (output->rate_limit_mbps > 0 && !token_bucket_consume(&output->throttle, length, header->ts))
    {
        bytes_stats_add(&output->base.stats->ratelimit_drop_bytes, length);
        packets_stats_add(&output->base.stats->ratelimit_drop_packets, 1);

        zmq_flush_if_stale(output, header->ts.tv_sec);
        return -1;
    }

    if (pkts_buf->batch_hdr.pkts_num == 0)
        pkts_buf->first_pktsec = header->ts.tv_sec;

    zmq_pkt_hdr_t pkt_hdr = {
        .tv_sec = htonl((uint32_t)header->ts.tv_sec),
        .tv_usec = htonl((uint32_t)header->ts.tv_usec),
        .caplen = htonl((uint32_t)length),
        .len = htonl((uint32_t)header->len + sizeof(mpls_header)),
    };

    const bool is_pkt_num_exceeded = (pkts_buf->batch_hdr.pkts_num >= ZMQ_PKTS_FLUSH_MAX_NUM);

    const bool is_time_diff_exceeded =
        (pkts_buf->first_pktsec != 0 && header->ts.tv_sec > pkts_buf->first_pktsec + ZMQ_PKTS_FLUSH_MAX_DUR_SEC);

    const bool is_buffer_full =
        (pkts_buf->batch_bufpos + sizeof(length) + sizeof(pkt_hdr) + length > ZMQ_MAX_BATCH_BUF_SIZE);

    if (is_pkt_num_exceeded || is_time_diff_exceeded || is_buffer_full)
    {
        zmq_flush_packet(output);
        pkts_buf->first_pktsec = header->ts.tv_sec;
    }

    if (pkts_buf->first_pktsec == 0)
        pkts_buf->first_pktsec = header->ts.tv_sec;

    uint16_t hlen = htons(length);
    uint32_t buff_pos = pkts_buf->batch_bufpos;

    memcpy(&(pkts_buf->buf[buff_pos]), &hlen, ZMQ_PKT_DATA_LEN_SIZE);
    buff_pos += ZMQ_PKT_DATA_LEN_SIZE;

    memcpy(&(pkts_buf->buf[buff_pos]), &pkt_hdr, sizeof(pkt_hdr));
    buff_pos += sizeof(pkt_hdr);

    // Copy ethernet header locally to avoid modifying the caller's packet data
    struct ether_header eth_hdr_copy;
    memcpy(&eth_hdr_copy, pkt_data, sizeof(struct ether_header));

    // Calculate total VLAN header size by looping through stacked VLANs
    uint16_t ether_type = ntohs(eth_hdr_copy.ether_type);
    size_t vlan_total_size = 0;

    while (ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_DOT1AD || ether_type == ETHERTYPE_VLAN_9100 ||
           ether_type == ETHERTYPE_VLAN_9200)
    {
        size_t vlan_offset = sizeof(struct ether_header) + vlan_total_size;
        if (vlan_offset + sizeof(struct vlan_header) > length)
            break;
        struct vlan_header *vlan_hdr = (struct vlan_header *)(pkt_data + vlan_offset);
        ether_type = ntohs(vlan_hdr->ether_type);
        vlan_total_size += sizeof(struct vlan_header);
    }

    const bool has_vlan = (vlan_total_size > 0);

    // Write Ethernet header (keep original EtherType if has VLAN, else set MPLS)
    if (!has_vlan)
        eth_hdr_copy.ether_type = htons(ETHER_TYPE_MPLS);

    memcpy(&(pkts_buf->buf[buff_pos]), &eth_hdr_copy, sizeof(struct ether_header));
    buff_pos += sizeof(struct ether_header);

    if (has_vlan)
    {
        // Copy all VLAN tags
        memcpy(&(pkts_buf->buf[buff_pos]), pkt_data + sizeof(struct ether_header), vlan_total_size);
        // Overwrite the innermost VLAN's ether_type with MPLS
        size_t last_vlan_etype_offset = buff_pos + vlan_total_size - sizeof(uint16_t);
        uint16_t mpls_type = htons(ETHER_TYPE_MPLS);
        memcpy(&(pkts_buf->buf[last_vlan_etype_offset]), &mpls_type, sizeof(uint16_t));
        buff_pos += vlan_total_size;
    }

    // Write MPLS header
    uint32_t mpls_hdr_uint32 = make_mpls_hdr(direct, output->service_tag);
    memcpy(&(pkts_buf->buf[buff_pos]), &mpls_hdr_uint32, sizeof(mpls_header));
    buff_pos += sizeof(mpls_header);

    // Copy payload (everything after Ethernet + all VLANs)
    const size_t payload_offset = sizeof(struct ether_header) + vlan_total_size;
    const size_t payload_copy_len = length - sizeof(struct ether_header) - sizeof(mpls_header) - vlan_total_size;
    memcpy(&(pkts_buf->buf[buff_pos]), pkt_data + payload_offset, payload_copy_len);
    buff_pos += payload_copy_len;

    pkts_buf->batch_bufpos = buff_pos;
    pkts_buf->batch_hdr.pkts_num++;

    output->last_pkt_tv.tv_sec = header->ts.tv_sec;
    output->last_pkt_tv.tv_usec = header->ts.tv_usec;

    return 0;
}

static void zmq_send_heartbeat_packet(zmq_output_t *output, struct timeval *tv)
{
    zmq_pkts_buf_t *pkts_buf = &output->pkts_buf;

    // Heartbeat: minimal Ethernet frame (14 bytes) with all-zero MACs and EtherType=0xFFFF
    const uint16_t pkt_len = sizeof(struct ether_header);

    // Check buffer space
    if (pkts_buf->batch_bufpos + sizeof(uint16_t) + sizeof(zmq_pkt_hdr_t) + pkt_len > ZMQ_MAX_BATCH_BUF_SIZE)
    {
        zmq_flush_packet(output);
    }

    if (pkts_buf->batch_hdr.pkts_num == 0)
        pkts_buf->first_pktsec = tv->tv_sec;

    // Packet header with current timestamp
    zmq_pkt_hdr_t pkt_hdr = {
        .tv_sec = htonl((uint32_t)tv->tv_sec),
        .tv_usec = htonl((uint32_t)tv->tv_usec),
        .caplen = htonl((uint32_t)pkt_len),
        .len = htonl((uint32_t)pkt_len),
    };

    uint32_t pos = pkts_buf->batch_bufpos;

    // pkt_data_len
    uint16_t hlen = htons(pkt_len);
    memcpy(&pkts_buf->buf[pos], &hlen, sizeof(hlen));
    pos += sizeof(hlen);

    // zmq_pkt_hdr
    memcpy(&pkts_buf->buf[pos], &pkt_hdr, sizeof(pkt_hdr));
    pos += sizeof(pkt_hdr);

    // Ethernet header: all-zero MACs, sentinel EtherType for heartbeat
    static const struct ether_header eth = {{0}, {0}, 0};
    memcpy(&pkts_buf->buf[pos], &eth, sizeof(eth));
    // Overwrite ether_type separately (static const initializer needs compile-time value)
    uint16_t hb_etype = htons(ZMQ_HEARTBEAT_ETHER_TYPE);
    memcpy(&pkts_buf->buf[pos + offsetof(struct ether_header, ether_type)], &hb_etype, sizeof(hb_etype));
    pos += sizeof(eth);

    pkts_buf->batch_bufpos = pos;
    pkts_buf->batch_hdr.pkts_num++;

    // Flush immediately - heartbeat triggers batch flush
    zmq_flush_packet(output);

    // Update heartbeat stats and last packet time
    packets_stats_add(&output->base.stats->heartbeat_packets, 1);
    output->last_pkt_tv = *tv;
}

void zmq_heartbeat(output_base_t *self, time_t now)
{
    zmq_output_t *output = (zmq_output_t *)self;

    // Flush pending real packets if time exceeded
    zmq_flush_if_stale(output, now);

    // Generate heartbeat packet if enabled and interval exceeded
    if (output->heartbeat_ms <= 0)
        return;

    // Coarse pre-gate: skip gettimeofday when clearly not due yet
    long coarse_elapsed_s = now - output->last_pkt_tv.tv_sec;
    if (coarse_elapsed_s * 1000 < output->heartbeat_ms - 1000)
        return;

    struct timeval now_tv;
    gettimeofday(&now_tv, NULL);

    long elapsed_ms =
        (now_tv.tv_sec - output->last_pkt_tv.tv_sec) * 1000 + (now_tv.tv_usec - output->last_pkt_tv.tv_usec) / 1000;

    if (elapsed_ms >= output->heartbeat_ms)
    {
        log_debug("zmq output: generating heartbeat packet (elapsed=%ldms, interval=%dms)", elapsed_ms,
                  output->heartbeat_ms);
        zmq_send_heartbeat_packet(output, &now_tv);
    }
}

zmq_output_t *zmq_output_new(zmq_options_t opts, output_stats_t *stats, char *errbuf)
{
    uint8_t uuid[16];
    memset(uuid, 0, sizeof(uuid));
    if (!uuid_to_bytes(opts.uuid, uuid))
    {
        error_format(errbuf, "invalid uuid: %s", opts.uuid);
        return NULL;
    }

    void *context = zmq_ctx_new();
    if (context == NULL)
    {
        error_format(errbuf, "zmq_ctx_new() error: %s", zmq_strerror(errno));
        return NULL;
    }

    void *pusher = zmq_socket(context, ZMQ_PUSH);
    if (pusher == NULL)
    {
        error_format(errbuf, "zmq_socket() error: %s", zmq_strerror(errno));
        zmq_ctx_destroy(context);
        return NULL;
    }

    if (zmq_setsockopt(pusher, ZMQ_SNDHWM, &opts.hwm, sizeof(opts.hwm)) != 0)
    {
        error_format(errbuf, "set hwm error: %s", zmq_strerror(errno));
        zmq_close(pusher);
        zmq_ctx_destroy(context);
        return NULL;
    }

    int linger = 5 * 1000; // 5s
    if (zmq_setsockopt(pusher, ZMQ_LINGER, &linger, sizeof(linger)) != 0)
    {
        error_format(errbuf, "set linger error: %s", zmq_strerror(errno));
        zmq_close(pusher);
        zmq_ctx_destroy(context);
        return NULL;
    }

    char address[256];
    snprintf(address, sizeof(address), "tcp://%s:%d", opts.host, opts.port);

    if (zmq_connect(pusher, address) != 0)
    {
        error_format(errbuf, "zmq connect address %s error: %s", address, zmq_strerror(errno));
        zmq_close(pusher);
        zmq_ctx_destroy(context);
        return NULL;
    }

    zmq_output_t *output = (zmq_output_t *)calloc(1, sizeof(zmq_output_t));
    if (!output)
    {
        error_format(errbuf, "failed to allocate memory for zmq_output_t");
        zmq_close(pusher);
        zmq_ctx_destroy(context);
        return NULL;
    }

    output->base.send_packet = zmq_send_packet;
    output->base.heartbeat = zmq_heartbeat;
    output->base.destory = zmq_output_destory;
    output->base.stats = stats;

    output->context = context;
    output->pusher = pusher;

    if (opts.rate_limit_mbps > 0)
    {
        token_bucket_init(&output->throttle, opts.rate_limit_mbps * 1000000);
    }
    output->rate_limit_mbps = opts.rate_limit_mbps;
    output->slice = opts.slice;

    output->service_tag = opts.service_tag;
    output->pkts_buf.first_pktsec = 0;
    output->pkts_buf.batch_bufpos = sizeof(zmq_pkt_batch_hdr_t);

    output->heartbeat_ms = opts.heartbeat_ms;
    gettimeofday(&output->last_pkt_tv, NULL);

    output->pkts_buf.batch_hdr.pkts_num = 0;
    output->pkts_buf.batch_hdr.version = htons(ZMQ_BATCH_PKTS_VERSION);
    output->pkts_buf.batch_hdr.keybit = htonl(opts.service_tag);

    memcpy(output->pkts_buf.batch_hdr.uuid, uuid, sizeof(uuid));

    output->error_info.send_error[0] = '\0';

    if (output->heartbeat_ms > 0)
        log_info("zmq output: heartbeat enabled, interval=%dms", output->heartbeat_ms);

    return output;
}

output_base_t *zmq_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, output_stats_t *stats,
                                       char *errbuf)
{
    zmq_options_t opts = {
        .host = output_cfg->config.zmq.host,
        .port = output_cfg->config.zmq.port,
        .hwm = output_cfg->config.zmq.hwm,
        .service_tag = output_cfg->config.zmq.service_tag,
        .uuid = output_cfg->config.zmq.uuid,
        .rate_limit_mbps = output_cfg->rate_limit_mbps,
        .slice = output_cfg->slice,
        .heartbeat_ms = output_cfg->config.zmq.heartbeat_ms,
    };
    log_info("zmq output options: host=%s, port=%d, hwm=%d, service_tag=%d, uuid=%s, rate_limit_mbps=%d, slice=%d, "
             "heartbeat_ms=%d",
             opts.host, opts.port, opts.hwm, opts.service_tag, opts.uuid, opts.rate_limit_mbps, opts.slice,
             opts.heartbeat_ms);
    return (output_base_t *)zmq_output_new(opts, stats, errbuf);
}

void zmq_output_destory(output_base_t *self)
{
    if (!self)
        return;

    log_info("call zmq_output_destory");
    zmq_output_t *output = (zmq_output_t *)self;

    if (output->pusher)
        zmq_close(output->pusher);
    if (output->context)
        zmq_ctx_destroy(output->context);

    free(output);
}