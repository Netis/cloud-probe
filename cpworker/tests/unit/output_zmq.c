#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zmq.h>

#include "unity/src/unity.h"

#include "output.h"
#include "output_zmq.h"
#include "pkt_dir.h"

extern int zmq_flush_packet(zmq_output_t *output);

#define BATCH_HDR_SIZE sizeof(zmq_pkt_batch_hdr_t)
#define RECORD_HDR_SIZE (ZMQ_PKT_DATA_LEN_SIZE + sizeof(zmq_pkt_hdr_t))
#define MPLS_HDR_SIZE 4
#define RECV_TIMEOUT_MS 2000
#define RECV_BUF_SIZE 65536

static const char *VALID_UUID = "550e8400-e29b-41d4-a716-446655440000";

static void *recv_ctx;
static void *receiver;
static uint16_t receiver_port;
static output_stats_t stats;
static uint8_t recv_buf[RECV_BUF_SIZE];

void setUp(void)
{
    memset(&stats, 0, sizeof(stats));

    recv_ctx = zmq_ctx_new();
    TEST_ASSERT_NOT_NULL(recv_ctx);
    receiver = zmq_socket(recv_ctx, ZMQ_PULL);
    TEST_ASSERT_NOT_NULL(receiver);
    int timeout = RECV_TIMEOUT_MS;
    TEST_ASSERT_EQUAL_INT(0, zmq_setsockopt(receiver, ZMQ_RCVTIMEO, &timeout, sizeof(timeout)));
    TEST_ASSERT_EQUAL_INT(0, zmq_bind(receiver, "tcp://127.0.0.1:*"));

    char endpoint[64];
    size_t endpoint_len = sizeof(endpoint);
    TEST_ASSERT_EQUAL_INT(0, zmq_getsockopt(receiver, ZMQ_LAST_ENDPOINT, endpoint, &endpoint_len));
    const char *colon = strrchr(endpoint, ':');
    TEST_ASSERT_NOT_NULL(colon);
    receiver_port = (uint16_t)atoi(colon + 1);
}

void tearDown(void)
{
    int linger = 0;
    zmq_setsockopt(receiver, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_close(receiver);
    zmq_ctx_destroy(recv_ctx);
}

static zmq_output_t *new_output(int slice, char *uuid, char *errbuf)
{
    zmq_options_t opts = {
        .host = "127.0.0.1",
        .port = receiver_port,
        .hwm = 100,
        .service_tag = 1,
        .uuid = uuid,
        .rate_limit_mbps = 0,
        .slice = slice,
        .heartbeat_ms = 0,
    };
    return zmq_output_new(opts, &stats, errbuf);
}

static int send_frame(zmq_output_t *output, const uint8_t *frame, uint32_t caplen)
{
    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = 1;
    hdr.caplen = caplen;
    hdr.len = caplen;
    return output_send_packet(&output->base, &hdr, frame, PKT_DIR_INCOMING);
}

// Returns the received batch size, or -1 on timeout.
static int recv_batch(void) { return zmq_recv(receiver, recv_buf, sizeof(recv_buf), 0); }

static uint16_t batch_pkts_num(void)
{
    uint16_t num;
    memcpy(&num, recv_buf + 2, sizeof(num));
    return ntohs(num);
}

/* ---- #249: uuid is optional, default "" ---- */

void test_default_empty_uuid_accepted(void)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_output(0, "", errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    const uint8_t zero_uuid[16] = {0};
    TEST_ASSERT_EQUAL_UINT8_ARRAY(zero_uuid, output->pkts_buf.batch_hdr.uuid, 16);

    zmq_output_destroy(&output->base);
}

void test_invalid_uuid_rejected(void)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_output(0, "xyz", errbuf);
    TEST_ASSERT_NULL(output);
    TEST_ASSERT_NOT_NULL(strstr(errbuf, "invalid uuid"));
}

/* ---- #253: graceful stop must not discard the pending batch ---- */

void test_destroy_flushes_pending_batch(void)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_output(0, (char *)VALID_UUID, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    uint8_t frame[64];
    memset(frame, 0, sizeof(frame));
    frame[12] = 0x08; // IPv4
    for (int i = 0; i < 3; i++)
        TEST_ASSERT_EQUAL_INT(0, send_frame(output, frame, sizeof(frame)));
    TEST_ASSERT_EQUAL_UINT16(3, output->pkts_buf.batch_hdr.pkts_num);

    zmq_output_destroy(&output->base);

    TEST_ASSERT_GREATER_THAN_INT_MESSAGE(0, recv_batch(), "pending batch was not sent on destroy");
    TEST_ASSERT_EQUAL_UINT16(3, batch_pkts_num());
}

void test_destroy_empty_batch_sends_nothing(void)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_output(0, (char *)VALID_UUID, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    zmq_output_destroy(&output->base);

    TEST_ASSERT_EQUAL_INT(-1, recv_batch());
}

/* ---- #231: VLAN walk must stay within the captured data ---- */

// Sends one frame, flushes, and checks the record: Ethernet + VLAN tags (innermost
// EtherType rewritten to MPLS) + MPLS header + remaining payload, all within caplen.
static void assert_vlan_record(const uint8_t *frame, uint32_t caplen, int slice, size_t expected_vlan_size)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_output(slice, (char *)VALID_UUID, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    const uint32_t data_len = (slice > 0 && (uint32_t)slice < caplen) ? (uint32_t)slice : caplen;
    TEST_ASSERT_EQUAL_INT(0, send_frame(output, frame, caplen));
    TEST_ASSERT_EQUAL_UINT32(BATCH_HDR_SIZE + RECORD_HDR_SIZE + data_len + MPLS_HDR_SIZE,
                             output->pkts_buf.batch_bufpos);

    zmq_flush_packet(output);
    zmq_output_destroy(&output->base);

    int n = recv_batch();
    TEST_ASSERT_EQUAL_INT(BATCH_HDR_SIZE + RECORD_HDR_SIZE + data_len + MPLS_HDR_SIZE, n);

    const uint8_t *rec = recv_buf + BATCH_HDR_SIZE + RECORD_HDR_SIZE;
    const size_t l2_size = 14 + expected_vlan_size;
    // Ethernet header and VLAN tags, except the innermost EtherType
    TEST_ASSERT_EQUAL_UINT8_ARRAY(frame, rec, l2_size - 2);
    TEST_ASSERT_EQUAL_HEX8(0x88, rec[l2_size - 2]);
    TEST_ASSERT_EQUAL_HEX8(0x47, rec[l2_size - 1]);
    // Payload after the MPLS header is the rest of the captured data
    const size_t payload_len = data_len - l2_size;
    if (payload_len > 0)
        TEST_ASSERT_EQUAL_UINT8_ARRAY(frame + l2_size, rec + l2_size + MPLS_HDR_SIZE, payload_len);
}

void test_vlan_stack_cut_by_slice(void)
{
    // Reproducer from #231: 0x9200 -> 0x8100 -> 0x9100 -> 0x9200 -> 0x86dd, slice cuts the stack
    static uint8_t frame[1500];
    memset(frame, 0, sizeof(frame));
    frame[12] = 0x92;
    frame[13] = 0x00;
    frame[16] = 0x81;
    frame[17] = 0x00;
    frame[20] = 0x91;
    frame[21] = 0x00;
    frame[24] = 0x92;
    frame[25] = 0x00;
    frame[28] = 0x86;
    frame[29] = 0xdd;

    // 26 captured bytes hold the Ethernet header and 3 complete tags
    assert_vlan_record(frame, sizeof(frame), 26, 12);
}

void test_vlan_only_frame_without_slice(void)
{
    // A minimum-size frame filled with 0x8100 tags: no slice needed to overrun the walk
    uint8_t frame[60];
    memset(frame, 0xaa, 12);
    for (size_t i = 12; i + 1 < sizeof(frame); i += 4)
    {
        frame[i] = 0x81;
        frame[i + 1] = 0x00;
        frame[i + 2] = 0x00;
        frame[i + 3] = 0x01;
    }

    // 60 captured bytes hold the Ethernet header and 11 complete tags, 2 bytes left
    assert_vlan_record(frame, sizeof(frame), 0, 44);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_default_empty_uuid_accepted);
    RUN_TEST(test_invalid_uuid_rejected);

    RUN_TEST(test_destroy_flushes_pending_batch);
    RUN_TEST(test_destroy_empty_batch_sends_nothing);

    RUN_TEST(test_vlan_stack_cut_by_slice);
    RUN_TEST(test_vlan_only_frame_without_slice);

    return UNITY_END();
}
