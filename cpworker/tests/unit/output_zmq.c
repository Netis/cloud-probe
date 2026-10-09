#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <zmq.h>

#include "unity/src/unity.h"

#include "output.h"
#include "output_zmq.h"
#include "pkt_dir.h"

extern int zmq_flush_packet(zmq_output_t *output);
extern void zmq_heartbeat(output_base_t *self, time_t now);

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

/* ---- #231/#271: VLAN walk and slice keep the whole L2 header stack ---- */

// Sends one frame, flushes, and checks the record: Ethernet + VLAN tags (innermost
// EtherType rewritten to MPLS) + MPLS header + remaining payload. `data_len` is the
// number of captured bytes the record must carry.
static void assert_vlan_record(const uint8_t *frame, uint32_t caplen, int slice, uint32_t data_len,
                               size_t expected_vlan_size)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_output(slice, (char *)VALID_UUID, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

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

    TEST_ASSERT_EQUAL_UINT64(1, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(0, stats.error_drop_packets.packets);
}

// Sends one frame that cannot form a record and checks that it is counted as an error drop.
static void assert_error_drop(const uint8_t *frame, uint32_t caplen, int slice)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_output(slice, (char *)VALID_UUID, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    TEST_ASSERT_EQUAL_INT(-1, send_frame(output, frame, caplen));
    TEST_ASSERT_EQUAL_UINT16(0, output->pkts_buf.batch_hdr.pkts_num);
    TEST_ASSERT_EQUAL_UINT64(1, stats.error_drop_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(caplen, stats.error_drop_bytes.bytes);

    zmq_output_destroy(&output->base);
    TEST_ASSERT_EQUAL_INT(-1, recv_batch());
    TEST_ASSERT_EQUAL_UINT64(0, stats.fwd_packets.packets);
}

// Writes an 802.1Q tag at `offset` (TCI, then the EtherType that follows it).
static void put_tag(uint8_t *frame, size_t offset, uint16_t vid, uint16_t next_type)
{
    frame[offset] = (uint8_t)(vid >> 8);
    frame[offset + 1] = (uint8_t)vid;
    frame[offset + 2] = (uint8_t)(next_type >> 8);
    frame[offset + 3] = (uint8_t)next_type;
}

void test_slice_keeps_whole_vlan_stack(void)
{
    // Reproducer from #231: 0x9200 -> 0x8100 -> 0x9100 -> 0x9200 -> 0x86dd
    static uint8_t frame[1500];
    memset(frame, 0, sizeof(frame));
    frame[12] = 0x92;
    frame[13] = 0x00;
    put_tag(frame, 14, 1, 0x8100);
    put_tag(frame, 18, 2, 0x9100);
    put_tag(frame, 22, 3, 0x9200);
    put_tag(frame, 26, 4, 0x86dd);

    // slice 26 would cut the 4th tag: the record keeps Ethernet + 4 tags = 30 bytes
    assert_vlan_record(frame, sizeof(frame), 26, 30, 16);
}

void test_slice_below_ethernet_and_vlan_keeps_one_tag(void)
{
    // #271 comment: slice 10 used to drop every packet
    uint8_t frame[100];
    memset(frame, 0x5a, sizeof(frame));
    frame[12] = 0x81;
    frame[13] = 0x00;
    put_tag(frame, 14, 100, 0x0800);

    assert_vlan_record(frame, sizeof(frame), 10, 18, 4);
}

void test_slice_keeps_both_qinq_tags(void)
{
    // 802.1ad outer + 802.1Q inner: slice 18 would cut the inner tag
    uint8_t frame[100];
    memset(frame, 0x5a, sizeof(frame));
    frame[12] = 0x88;
    frame[13] = 0xa8;
    put_tag(frame, 14, 100, 0x8100);
    put_tag(frame, 18, 200, 0x0800);

    assert_vlan_record(frame, sizeof(frame), 18, 22, 8);
}

void test_slice_below_ethernet_keeps_untagged_header(void)
{
    uint8_t frame[100];
    memset(frame, 0x5a, sizeof(frame));
    frame[12] = 0x08;
    frame[13] = 0x00;

    assert_vlan_record(frame, sizeof(frame), 4, 14, 0);
}

void test_untagged_14_byte_frame_is_sent(void)
{
    uint8_t frame[14];
    memset(frame, 0x5a, sizeof(frame));
    frame[12] = 0x08;
    frame[13] = 0x00;

    assert_vlan_record(frame, sizeof(frame), 0, 14, 0);
}

void test_frame_shorter_than_ethernet_is_error_drop(void)
{
    uint8_t frame[13];
    memset(frame, 0x5a, sizeof(frame));

    assert_error_drop(frame, sizeof(frame), 0);
}

void test_frame_with_cut_vlan_tag_is_error_drop(void)
{
    // 16 bytes: Ethernet header with 0x8100, then only half of the tag
    uint8_t frame[16];
    memset(frame, 0x5a, sizeof(frame));
    frame[12] = 0x81;
    frame[13] = 0x00;

    assert_error_drop(frame, sizeof(frame), 0);
}

void test_vlan_stack_running_past_caplen_is_error_drop(void)
{
    // A minimum-size frame filled with 0x8100 tags: the stack never ends within caplen
    uint8_t frame[60];
    memset(frame, 0xaa, 12);
    for (size_t i = 12; i + 1 < sizeof(frame); i += 4)
    {
        frame[i] = 0x81;
        frame[i + 1] = 0x00;
        frame[i + 2] = 0x00;
        frame[i + 3] = 0x01;
    }

    assert_error_drop(frame, sizeof(frame), 0);
}

void test_runt_and_normal_frame_both_accounted(void)
{
    // #271: a runt followed by a normal frame must give fwd + error_drop == 2
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_output(0, (char *)VALID_UUID, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    uint8_t runt[16];
    memset(runt, 0x5a, sizeof(runt));
    runt[12] = 0x81;
    runt[13] = 0x00;
    uint8_t frame[64];
    memset(frame, 0x5a, sizeof(frame));
    frame[12] = 0x08;
    frame[13] = 0x00;

    TEST_ASSERT_EQUAL_INT(-1, send_frame(output, runt, sizeof(runt)));
    TEST_ASSERT_EQUAL_INT(0, send_frame(output, frame, sizeof(frame)));
    zmq_output_destroy(&output->base);

    TEST_ASSERT_GREATER_THAN_INT(0, recv_batch());
    TEST_ASSERT_EQUAL_UINT16(1, batch_pkts_num());
    TEST_ASSERT_EQUAL_UINT64(1, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(1, stats.error_drop_packets.packets);
}

/* ---- #299: heartbeats are not forwarded packets ---- */

#define HEARTBEAT_RECORD_SIZE (RECORD_HDR_SIZE + 14)

static zmq_output_t *new_heartbeat_output(uint16_t port, int hwm, char *errbuf)
{
    zmq_options_t opts = {
        .host = "127.0.0.1",
        .port = port,
        .hwm = hwm,
        .service_tag = 1,
        .uuid = (char *)VALID_UUID,
        .rate_limit_mbps = 0,
        .slice = 0,
        .heartbeat_ms = 1000,
    };
    return zmq_output_new(opts, &stats, errbuf);
}

// Makes the last packet one second old, so the next zmq_heartbeat() sends a heartbeat
// without flushing a batch whose first packet is from that same second.
static time_t make_heartbeat_due(zmq_output_t *output)
{
    time_t now = time(NULL);
    output->last_pkt_tv.tv_sec = now - 1;
    output->last_pkt_tv.tv_usec = 0;
    return now;
}

static void send_frame_at(zmq_output_t *output, time_t sec)
{
    uint8_t frame[64];
    memset(frame, 0x5a, sizeof(frame));
    frame[12] = 0x08;
    frame[13] = 0x00;

    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = sec;
    hdr.caplen = sizeof(frame);
    hdr.len = sizeof(frame);
    TEST_ASSERT_EQUAL_INT(0, output_send_packet(&output->base, &hdr, frame, PKT_DIR_INCOMING));
}

static void destroy_without_linger(zmq_output_t *output)
{
    int linger = 0;
    zmq_setsockopt(output->pusher, ZMQ_LINGER, &linger, sizeof(linger));
    zmq_output_destroy(&output->base);
}

void test_heartbeat_on_idle_output_is_not_forwarded(void)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_heartbeat_output(receiver_port, 100, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    zmq_heartbeat(&output->base, make_heartbeat_due(output));

    TEST_ASSERT_EQUAL_INT(BATCH_HDR_SIZE + HEARTBEAT_RECORD_SIZE, recv_batch());
    TEST_ASSERT_EQUAL_UINT16(1, batch_pkts_num());
    TEST_ASSERT_EQUAL_UINT64(1, stats.heartbeat_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(0, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(0, stats.fwd_bytes.bytes);

    zmq_output_destroy(&output->base);
}

void test_heartbeat_in_batch_with_data_counts_only_the_data(void)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_heartbeat_output(receiver_port, 100, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    time_t now = time(NULL);
    send_frame_at(output, now - 1);
    zmq_heartbeat(&output->base, make_heartbeat_due(output));

    TEST_ASSERT_GREATER_THAN_INT(0, recv_batch());
    TEST_ASSERT_EQUAL_UINT16(2, batch_pkts_num());
    TEST_ASSERT_EQUAL_UINT64(1, stats.heartbeat_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(1, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(64, stats.fwd_bytes.bytes);

    zmq_output_destroy(&output->base);
}

void test_failed_heartbeat_is_not_counted(void)
{
    // Nothing listens on port 1. With hwm 1 the unconnected pipe holds one batch, so the
    // first heartbeat is queued and the second send fails.
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_heartbeat_output(1, 1, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    zmq_heartbeat(&output->base, make_heartbeat_due(output));
    TEST_ASSERT_EQUAL_UINT64(1, stats.heartbeat_packets.packets);

    zmq_heartbeat(&output->base, make_heartbeat_due(output));
    TEST_ASSERT_EQUAL_UINT64(1, output->error_info.nb_drop_batches);
    TEST_ASSERT_EQUAL_UINT64(1, stats.heartbeat_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(0, stats.error_drop_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(0, stats.error_drop_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(0, stats.fwd_packets.packets);

    destroy_without_linger(output);
}

void test_failed_batch_with_heartbeat_drops_only_the_data(void)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_heartbeat_output(1, 1, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    zmq_heartbeat(&output->base, make_heartbeat_due(output)); // fills the pipe

    time_t now = time(NULL);
    send_frame_at(output, now - 1);
    zmq_heartbeat(&output->base, make_heartbeat_due(output));

    TEST_ASSERT_EQUAL_UINT64(1, output->error_info.nb_drop_batches);
    TEST_ASSERT_EQUAL_UINT64(1, stats.heartbeat_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(1, stats.error_drop_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(64, stats.error_drop_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(0, stats.fwd_packets.packets);

    destroy_without_linger(output);
}

/* ---- #308: counters count each packet once, with its sliced frame length ---- */

static uint64_t bucket_packets(void)
{
    return stats.fwd_packets.packets + stats.direction_drop_packets.packets + stats.ratelimit_drop_packets.packets +
           stats.error_drop_packets.packets;
}

static uint64_t bucket_bytes(void)
{
    return stats.fwd_bytes.bytes + stats.direction_drop_bytes.bytes + stats.ratelimit_drop_bytes.bytes +
           stats.error_drop_bytes.bytes;
}

static int send_frame_dir(zmq_output_t *output, const uint8_t *frame, uint32_t caplen, int direct)
{
    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = 1;
    hdr.caplen = caplen;
    hdr.len = caplen;
    return output_send_packet(&output->base, &hdr, frame, direct);
}

void test_counters_use_sliced_frame_length_without_headers(void)
{
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = new_output(40, (char *)VALID_UUID, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    uint8_t frame[100];
    memset(frame, 0x5a, sizeof(frame));
    frame[12] = 0x08;
    frame[13] = 0x00;

    TEST_ASSERT_EQUAL_INT(0, send_frame_dir(output, frame, sizeof(frame), PKT_DIR_INCOMING));
    TEST_ASSERT_EQUAL_INT(0, send_frame_dir(output, frame, 30, PKT_DIR_OUTGOING));
    TEST_ASSERT_EQUAL_INT(-1, send_frame_dir(output, frame, sizeof(frame), PKT_DIR_UNKNOWN));
    zmq_output_destroy(&output->base);

    TEST_ASSERT_GREATER_THAN_INT(0, recv_batch());
    TEST_ASSERT_EQUAL_UINT64(2, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(40 + 30, stats.fwd_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(1, stats.direction_drop_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(40, stats.direction_drop_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(3, bucket_packets());
    TEST_ASSERT_EQUAL_UINT64(40 + 30 + 40, bucket_bytes());
}

void test_rate_limit_charges_and_counts_sliced_frame_length(void)
{
    // 1 Mbit/s gives a 125000-byte bucket. 125 frames sliced to 1000 bytes fit exactly; one
    // more is rejected. Charging the 4-byte MPLS label as well would reject the 125th.
    zmq_options_t opts = {
        .host = "127.0.0.1",
        .port = receiver_port,
        .hwm = 100,
        .service_tag = 1,
        .uuid = (char *)VALID_UUID,
        .rate_limit_mbps = 1,
        .slice = 1000,
        .heartbeat_ms = 0,
    };
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    zmq_output_t *output = zmq_output_new(opts, &stats, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    static uint8_t frame[1500];
    memset(frame, 0x5a, sizeof(frame));
    frame[12] = 0x08;
    frame[13] = 0x00;

    for (int i = 0; i < 125; i++)
        TEST_ASSERT_EQUAL_INT(0, send_frame_dir(output, frame, sizeof(frame), PKT_DIR_INCOMING));
    TEST_ASSERT_EQUAL_INT(-1, send_frame_dir(output, frame, sizeof(frame), PKT_DIR_INCOMING));
    zmq_output_destroy(&output->base);

    TEST_ASSERT_GREATER_THAN_INT(0, recv_batch());
    TEST_ASSERT_EQUAL_UINT64(125, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(125000, stats.fwd_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(1, stats.ratelimit_drop_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(1000, stats.ratelimit_drop_bytes.bytes);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_default_empty_uuid_accepted);
    RUN_TEST(test_invalid_uuid_rejected);

    RUN_TEST(test_destroy_flushes_pending_batch);
    RUN_TEST(test_destroy_empty_batch_sends_nothing);

    RUN_TEST(test_slice_keeps_whole_vlan_stack);
    RUN_TEST(test_slice_below_ethernet_and_vlan_keeps_one_tag);
    RUN_TEST(test_slice_keeps_both_qinq_tags);
    RUN_TEST(test_slice_below_ethernet_keeps_untagged_header);
    RUN_TEST(test_untagged_14_byte_frame_is_sent);
    RUN_TEST(test_frame_shorter_than_ethernet_is_error_drop);
    RUN_TEST(test_frame_with_cut_vlan_tag_is_error_drop);
    RUN_TEST(test_vlan_stack_running_past_caplen_is_error_drop);
    RUN_TEST(test_runt_and_normal_frame_both_accounted);

    RUN_TEST(test_heartbeat_on_idle_output_is_not_forwarded);
    RUN_TEST(test_heartbeat_in_batch_with_data_counts_only_the_data);
    RUN_TEST(test_failed_heartbeat_is_not_counted);
    RUN_TEST(test_failed_batch_with_heartbeat_drops_only_the_data);

    RUN_TEST(test_counters_use_sliced_frame_length_without_headers);
    RUN_TEST(test_rate_limit_charges_and_counts_sliced_frame_length);

    return UNITY_END();
}
