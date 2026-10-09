#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include "unity/src/unity.h"

#include "output.h"
#include "output_gre.h"
#include "output_vxlan.h"
#include "pkt_dir.h"

/* #308: every output counts each packet it is handed once, in exactly one of fwd /
 * direction_drop / ratelimit_drop / error_drop, with its length after slice and without
 * any encapsulation. */

#define FRAME_HDRS_LEN (14 + 20 + 20)

static int receiver_fd;
static uint16_t receiver_port;
static output_stats_t stats;

void setUp(void)
{
    memset(&stats, 0, sizeof(stats));

    receiver_fd = socket(AF_INET, SOCK_DGRAM, 0);
    TEST_ASSERT_NOT_EQUAL(-1, receiver_fd);
    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    TEST_ASSERT_EQUAL_INT(0, bind(receiver_fd, (struct sockaddr *)&addr, sizeof(addr)));
    socklen_t len = sizeof(addr);
    TEST_ASSERT_EQUAL_INT(0, getsockname(receiver_fd, (struct sockaddr *)&addr, &len));
    receiver_port = ntohs(addr.sin_port);

    struct timeval tv = {.tv_sec = 1, .tv_usec = 0};
    setsockopt(receiver_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
}

void tearDown(void) { close(receiver_fd); }

static vxlan_output_t *new_vxlan(vxlan_options_t opts)
{
    opts.host = "127.0.0.1";
    opts.port = receiver_port;
    opts.vni_version = 2;
    opts.vni = 100;
    opts.pmtudisc = -1;
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    vxlan_output_t *output = vxlan_output_new(opts, &stats, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);
    return output;
}

// Ethernet + IPv4 + TCP frame of `len` bytes, with a consistent IP total length
static void build_tcp_frame(uint8_t *frame, uint32_t len)
{
    memset(frame, 0x5a, len);
    frame[12] = 0x08;
    frame[13] = 0x00;

    uint8_t *ip = frame + 14;
    ip[0] = 0x45;
    ip[1] = 0;
    uint16_t tot_len = htons((uint16_t)(len - 14));
    memcpy(ip + 2, &tot_len, 2);
    ip[6] = 0x40; // DF, offset 0
    ip[7] = 0;
    ip[8] = 64;
    ip[9] = 6; // TCP

    uint8_t *tcp = ip + 20;
    tcp[12] = 0x50; // data offset 5
}

static int send_at(output_base_t *output, const uint8_t *frame, uint32_t caplen, int direct, time_t sec)
{
    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = sec;
    hdr.caplen = caplen;
    hdr.len = caplen;
    return output_send_packet(output, &hdr, frame, direct);
}

static int recv_count(void)
{
    static uint8_t buf[70000];
    int n = 0;
    while (recv(receiver_fd, buf, sizeof(buf), 0) > 0)
        n++;
    return n;
}

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

void test_vxlan_counts_sliced_length_without_header_or_capture_time(void)
{
    vxlan_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.capture_time = true;
    opts.slice = 60;
    vxlan_output_t *output = new_vxlan(opts);

    static uint8_t frame[200];
    build_tcp_frame(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_INT(0, send_at(&output->base, frame, sizeof(frame), PKT_DIR_INCOMING, 1));
    TEST_ASSERT_EQUAL_INT(0, send_at(&output->base, frame, 50, PKT_DIR_INCOMING, 1));
    TEST_ASSERT_EQUAL_INT(-1, send_at(&output->base, frame, sizeof(frame), PKT_DIR_UNKNOWN, 1));
    vxlan_output_destroy(&output->base);

    TEST_ASSERT_EQUAL_INT(2, recv_count());
    TEST_ASSERT_EQUAL_UINT64(2, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(60 + 50, stats.fwd_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(1, stats.direction_drop_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(60, stats.direction_drop_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(3, bucket_packets());
    TEST_ASSERT_EQUAL_UINT64(60 + 50 + 60, bucket_bytes());
}

void test_vxlan_split_packet_counts_once(void)
{
    vxlan_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.split.max_payload_size = 300;
    vxlan_output_t *output = new_vxlan(opts);

    static uint8_t frame[FRAME_HDRS_LEN + 1000];
    build_tcp_frame(frame, sizeof(frame));
    TEST_ASSERT_EQUAL_INT(0, send_at(&output->base, frame, sizeof(frame), PKT_DIR_INCOMING, 1));
    vxlan_output_destroy(&output->base);

    TEST_ASSERT_EQUAL_INT(4, recv_count());
    TEST_ASSERT_EQUAL_UINT64(1, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(sizeof(frame), stats.fwd_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(1, bucket_packets());
}

void test_vxlan_send_error_counts_whole_packet_as_error_drop(void)
{
    // A 65535-byte frame plus the VXLAN header exceeds the largest IPv4 UDP datagram, so
    // sendto fails with EMSGSIZE
    vxlan_options_t opts;
    memset(&opts, 0, sizeof(opts));
    vxlan_output_t *output = new_vxlan(opts);

    static uint8_t frame[65535];
    memset(frame, 0x5a, sizeof(frame));
    TEST_ASSERT_EQUAL_INT(-1, send_at(&output->base, frame, sizeof(frame), PKT_DIR_INCOMING, 1));
    vxlan_output_destroy(&output->base);

    TEST_ASSERT_EQUAL_UINT64(0, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(0, stats.fwd_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(1, stats.error_drop_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(sizeof(frame), stats.error_drop_bytes.bytes);
}

void test_vxlan_rate_limit_charges_sliced_length(void)
{
    // 1 Mbit/s gives a 125000-byte bucket. 125 frames sliced to 1000 bytes fit exactly;
    // charging the 8-byte VXLAN header as well would reject the 125th.
    vxlan_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.rate_limit_mbps = 1;
    opts.slice = 1000;
    vxlan_output_t *output = new_vxlan(opts);

    static uint8_t frame[1500];
    build_tcp_frame(frame, sizeof(frame));
    for (int i = 0; i < 125; i++)
        TEST_ASSERT_EQUAL_INT(0, send_at(&output->base, frame, sizeof(frame), PKT_DIR_INCOMING, 1));
    TEST_ASSERT_EQUAL_INT(-1, send_at(&output->base, frame, sizeof(frame), PKT_DIR_INCOMING, 1));
    vxlan_output_destroy(&output->base);

    TEST_ASSERT_EQUAL_UINT64(125, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(125000, stats.fwd_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(1, stats.ratelimit_drop_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(1000, stats.ratelimit_drop_bytes.bytes);
}

void test_gre_counts_sliced_length_without_header(void)
{
    gre_options_t opts;
    memset(&opts, 0, sizeof(opts));
    opts.host = "127.0.0.1";
    opts.service_tag = 1;
    opts.pmtudisc = -1;
    opts.rate_limit_mbps = 1;
    opts.slice = 1000;
    char errbuf[ERROR_BUFFER_SIZE] = {0};
    gre_output_t *output = gre_output_new(opts, &stats, errbuf);
    if (!output)
        TEST_IGNORE_MESSAGE("raw GRE socket unavailable (needs CAP_NET_RAW)");

    // Same bucket arithmetic as the VXLAN test: the GRE header must not be charged
    static uint8_t frame[1500];
    build_tcp_frame(frame, sizeof(frame));
    for (int i = 0; i < 125; i++)
        TEST_ASSERT_EQUAL_INT(0, send_at(&output->base, frame, sizeof(frame), PKT_DIR_INCOMING, 1));
    TEST_ASSERT_EQUAL_INT(-1, send_at(&output->base, frame, sizeof(frame), PKT_DIR_INCOMING, 1));
    TEST_ASSERT_EQUAL_INT(-1, send_at(&output->base, frame, sizeof(frame), PKT_DIR_UNKNOWN, 1));
    gre_output_destroy(&output->base);

    TEST_ASSERT_EQUAL_UINT64(125, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(125000, stats.fwd_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(1000, stats.ratelimit_drop_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(1000, stats.direction_drop_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(127, bucket_packets());
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_vxlan_counts_sliced_length_without_header_or_capture_time);
    RUN_TEST(test_vxlan_split_packet_counts_once);
    RUN_TEST(test_vxlan_send_error_counts_whole_packet_as_error_drop);
    RUN_TEST(test_vxlan_rate_limit_charges_sliced_length);
    RUN_TEST(test_gre_counts_sliced_length_without_header);

    return UNITY_END();
}
