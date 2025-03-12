#ifndef CPAGENT_OUTPUT_ZMQ_H
#define CPAGENT_OUTPUT_ZMQ_H

#include "output_common.h"
#include <stdint.h>
#include <zmq.h>

#define MAX_BATCH_BUF_LENGTH 1048576 // 1 * 1024 * 1024;
#define MAX_PKTS_TIMEDIFF_SEC 1
#define BATCH_PKTS_VERSION 2

typedef struct PmrPktHdr
{
    uint32_t tv_sec;  // epoc seconds.  caution: unix 2038 problem
    uint32_t tv_usec; // and microseconds
    uint32_t caplen;  // actual capture length
    uint32_t len;     // wire packet length
} pmr_pkt_hdr_t;

typedef struct BatchPktsHdr
{
    uint16_t version;
    uint16_t pkts_num;
    uint32_t keybit;
    uint8_t uuid[16];
} batch_pkts_hdr_t;

typedef struct BatchPktsBuf
{
    batch_pkts_hdr_t batch_hdr;
    // buf format as below:
    // | batch_hdr | (pkt_data length  + pkt_hdr  + pkt_data) | (pkt_data_length  + pkt_hdr  + pkt_data) | ...
    // | 8 bytes   | (2 bytes          + 16 bytes + n bytes ) | (2 bytes          + 16 bytes + n bytes ) | ...
    char buf[MAX_BATCH_BUF_LENGTH];
    uint32_t batch_bufpos;
    long int first_pktsec;
} batch_pkts_buf_t;

typedef struct ZmqOutput
{
    OutputBase base;
    void *context; // zmq_ctx_new
    void *pusher;  // zmq_socket(context, ZMQ_PUSH);
    uint16_t keybit;
    batch_pkts_buf_t pkts_buf;

    OutputStats stats;
} zmq_output_t;

zmq_output_t *new_zmq_output(const char *host, int port, int hwm, char *errbuf);
void free_zmq_output(OutputBase *output);

#endif /* CPAGENT_OUTPUT_ZMQ_H */