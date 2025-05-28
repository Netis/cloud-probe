#include <net/ethernet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <pcap/pcap.h>
#include <pcap/vlan.h>
#include <zmq.h>

#include "errorf.h"
#include "log.h"
#include "mpls.h"
#include "output.h"
#include "output_zmq.h"
#include "pkt_dir.h"
#include "stats.h"

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

int zmq_flush_packet(zmq_output_t *output)
{
    zmq_pkts_buf_t *pkts_buf = &output->pkts_buf;

    uint64_t send_num = pkts_buf->batch_hdr.pkts_num;
    pkts_buf->batch_hdr.pkts_num = htons(send_num);
    memcpy((&(pkts_buf->buf[0])), &pkts_buf->batch_hdr, sizeof(pkts_buf->batch_hdr));

    int rc = zmq_send(output->pusher, &(pkts_buf->buf[0]), pkts_buf->batch_bufpos, ZMQ_DONTWAIT);
    if (rc != -1)
    {
        bytes_stats_add(&output->base.stats.fwd_bytes, pkts_buf->batch_bufpos);
        packets_stats_add(&output->base.stats.fwd_packets, send_num);
    }
    else
    {
        bytes_stats_add(&output->base.stats.error_drop_bytes, pkts_buf->batch_bufpos);
        packets_stats_add(&output->base.stats.error_drop_packets, send_num);
        // TODO: log error
    }

    pkts_buf->first_pktsec = 0;
    pkts_buf->batch_bufpos = sizeof(zmq_pkt_batch_hdr_t);
    pkts_buf->batch_hdr.pkts_num = 0;
    return 0;
}

int zmq_send_packet(output_base_t *self, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct)
{
    zmq_output_t *output = (zmq_output_t *)self;

    int32_t caplen = header->caplen;
    if (output->slice > 0 && output->slice < caplen)
    {
        caplen = output->slice;
    }

    uint16_t length = (uint16_t)(caplen <= 65531 ? caplen : 65531) + sizeof(mpls_header);

    if (direct == PKT_DIR_UNKNOWN)
    {
        bytes_stats_add(&output->base.stats.direction_drop_bytes, length);
        packets_stats_add(&output->base.stats.direction_drop_packets, 1);
        return -1;
    }

    if (output->rate_limit_mbps > 0)
    {
        if (token_bucket_consume(&output->throttle, length) != 0)
        {
            bytes_stats_add(&output->base.stats.ratelimit_drop_bytes, length);
            packets_stats_add(&output->base.stats.ratelimit_drop_packets, 1);
            return -1;
        }
    }

    zmq_pkts_buf_t *pkts_buf = &output->pkts_buf;
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
        log_debug("send zmq message, last packet time: %lu, first packet_time: %lu", header->ts.tv_sec,
                  pkts_buf->first_pktsec);
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

    struct ether_header *eth_hdr = (struct ether_header *)pkt_data;
    struct vlan_tag *vlan_hdr = NULL;

    const bool has_vlan = (ntohs(eth_hdr->ether_type) == ETHERTYPE_VLAN);
    if (has_vlan)
    {
        vlan_hdr = (struct vlan_tag *)(pkt_data + sizeof(struct ether_header));
        vlan_hdr->vlan_tci = htons(ETHER_TYPE_MPLS);
    }
    else
    {
        eth_hdr->ether_type = htons(ETHER_TYPE_MPLS);
    }

    memcpy(&(pkts_buf->buf[buff_pos]), pkt_data, sizeof(struct ether_header));
    buff_pos += sizeof(struct ether_header);

    if (has_vlan)
    {
        memcpy(&(pkts_buf->buf[buff_pos]), vlan_hdr, sizeof(struct vlan_tag));
        buff_pos += sizeof(struct vlan_tag);
    }

    mpls_header mpls_hdr;
    uint32_t mpls_hdr_uint32 = make_mpls_hdr(direct, output->service_tag);
    memcpy(&mpls_hdr, &mpls_hdr_uint32, sizeof(mpls_header));

    memcpy(&(pkts_buf->buf[buff_pos]), &mpls_hdr, sizeof(mpls_header));
    buff_pos += sizeof(mpls_header);

    const size_t eth_header_size = sizeof(struct ether_header);
    const size_t vlan_size = has_vlan ? sizeof(struct vlan_tag) : 0;
    const size_t payload_offset = eth_header_size + vlan_size;
    const size_t payload_copy_len = length - eth_header_size - sizeof(mpls_header) - vlan_size;
    memcpy(&(pkts_buf->buf[buff_pos]), pkt_data + payload_offset, payload_copy_len);
    buff_pos += payload_copy_len;

    pkts_buf->batch_bufpos = buff_pos;
    pkts_buf->batch_hdr.pkts_num++;
    return 0;
}

void zmq_heartbeat(output_base_t *self, uint64_t now_sec, uint64_t now_nsec)
{
    zmq_output_t *output = (zmq_output_t *)self;
    zmq_pkts_buf_t *pkts_buf = &output->pkts_buf;
    if (pkts_buf->batch_hdr.pkts_num > 0 && pkts_buf->first_pktsec != 0 &&
        now_sec > pkts_buf->first_pktsec + ZMQ_PKTS_FLUSH_MAX_DUR_SEC)
    {
        log_debug("send zmq message by heartbeat, now time: %lu, first packet_time: %lu", now_sec,
                  pkts_buf->first_pktsec);
        zmq_flush_packet(output);
    }
}

zmq_output_t *zmq_output_new(zmq_options_t opts, char *errbuf)
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

    int linger = 10 * 1000; // 10s
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

    output->pkts_buf.batch_hdr.pkts_num = 0;
    output->pkts_buf.batch_hdr.version = htons(ZMQ_BATCH_PKTS_VERSION);
    output->pkts_buf.batch_hdr.keybit = htonl(opts.service_tag);

    memcpy(output->pkts_buf.batch_hdr.uuid, uuid, sizeof(uuid));
    return output;
}

output_base_t *zmq_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf)
{
    zmq_options_t opts = {
        .host = output_cfg->config.zmq.host,
        .port = output_cfg->config.zmq.port,
        .hwm = output_cfg->config.zmq.hwm,
        .service_tag = output_cfg->config.zmq.service_tag,
        .uuid = output_cfg->config.zmq.uuid,
        .rate_limit_mbps = output_cfg->rate_limit_mbps,
        .slice = output_cfg->slice,
    };
    log_info("zmq output options: host=%s, port=%d, hwm=%d, service_tag=%d, uuid=%s, rate_limit_mbps=%d, slice=%d",
             opts.host, opts.port, opts.hwm, opts.service_tag, opts.uuid, opts.rate_limit_mbps, opts.slice);
    return (output_base_t *)zmq_output_new(opts, errbuf);
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