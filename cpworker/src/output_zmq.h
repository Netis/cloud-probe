#ifndef CPWORKER_OUTPUT_ZMQ_H
#define CPWORKER_OUTPUT_ZMQ_H

#include <stdint.h>

#include <zmq.h>

#include "output.h"
#include "ratelimit.h"
#include "taskconf.h"

#define ZMQ_MAX_BATCH_BUF_SIZE 1048576 // 1 * 1024 * 1024;
#define ZMQ_PKTS_FLUSH_MAX_DUR_SEC 1
#define ZMQ_BATCH_PKTS_VERSION 2
#define ZMQ_PKT_DATA_LEN_SIZE 2

typedef struct
{
    uint32_t tv_sec;  // epoc seconds.  caution: unix 2038 problem
    uint32_t tv_usec; // and microseconds
    uint32_t caplen;  // actual capture length
    uint32_t len;     // wire packet length
} zmq_pkt_hdr_t;

typedef struct
{
    uint16_t version;
    uint16_t pkts_num;
    uint32_t keybit;
    uint8_t uuid[16];
} zmq_pkt_batch_hdr_t;

typedef struct
{
    zmq_pkt_batch_hdr_t batch_hdr;
    // buf format as below:
    // | batch_hdr | (pkt_data length  + pkt_hdr  + pkt_data) | (pkt_data_length  + pkt_hdr  + pkt_data) | ...
    // | 8 bytes   | (2 bytes          + 16 bytes + n bytes ) | (2 bytes          + 16 bytes + n bytes ) | ...
    char buf[ZMQ_MAX_BATCH_BUF_SIZE];
    uint32_t batch_bufpos;
    long int first_pktsec;
} zmq_pkts_buf_t;

typedef struct ZmqOptions
{
    char *host;
    int port;
    int hwm;
    uint32_t service_tag;
    char *uuid;
    uint64_t rate_limit_mbps;
    int slice;
} zmq_options_t;

typedef struct ZmqOutput
{
    output_base_t base;

    uint64_t rate_limit_mbps;
    token_bucket_t throttle;
    int slice;

    void *context; // zmq_ctx_new
    void *pusher;  // zmq_socket(context, ZMQ_PUSH);
    uint16_t service_tag;
    zmq_pkts_buf_t pkts_buf;
} zmq_output_t;

output_base_t *zmq_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf);
zmq_output_t *zmq_output_new(zmq_options_t opts, char *errbuf);
void zmq_output_destory(output_base_t *self);

#endif /* CPWORKER_OUTPUT_ZMQ_H */