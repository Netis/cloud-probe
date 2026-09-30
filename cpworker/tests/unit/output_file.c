#define _XOPEN_SOURCE 500

#include <ftw.h>
#include <glob.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "unity/src/unity.h"

#include "output.h"
#include "output_file.h"
#include "output_rotating_file.h"
#include "pkt_dir.h"

#define SNAPLEN 65535

// Rate-limit scenario: 1000 x 1250-byte frames, 5 ms apart in capture time = 10 Mbit over 5 s
#define RL_FRAMES 1000
#define RL_FRAME_LEN 1250
#define RL_GAP_USEC 5000
#define RL_MBPS 1

static char tmp_dir[64];
static output_stats_t stats;
static char errbuf[PCAP_ERRBUF_SIZE];
static uint8_t frame[1600];

typedef struct
{
    int count;
    int snaplen;
    uint64_t written_bits;
    struct pcap_pkthdr first_hdr;
    uint8_t first_data[256];
} pcap_summary_t;

static int remove_entry(const char *path, const struct stat *sb, int flag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)flag;
    (void)ftwbuf;
    return remove(path);
}

void setUp(void)
{
    memset(&stats, 0, sizeof(stats));
    for (size_t i = 0; i < sizeof(frame); i++)
        frame[i] = (uint8_t)i;

    strcpy(tmp_dir, "/tmp/cpworker_ut_file_XXXXXX");
    TEST_ASSERT_NOT_NULL(mkdtemp(tmp_dir));
}

void tearDown(void) { nftw(tmp_dir, remove_entry, 16, FTW_DEPTH | FTW_PHYS); }

static struct pcap_pkthdr make_hdr(uint32_t len, long usec_offset)
{
    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.ts.tv_sec = 1700000000 + usec_offset / 1000000;
    hdr.ts.tv_usec = usec_offset % 1000000;
    hdr.caplen = len;
    hdr.len = len;
    return hdr;
}

static pcap_summary_t read_pcap(const char *path)
{
    pcap_summary_t sum;
    memset(&sum, 0, sizeof(sum));

    pcap_t *p = pcap_open_offline(path, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(p, errbuf);
    sum.snaplen = pcap_snapshot(p);

    struct pcap_pkthdr *hdr;
    const u_char *data;
    while (pcap_next_ex(p, &hdr, &data) == 1)
    {
        if (sum.count == 0)
        {
            sum.first_hdr = *hdr;
            memcpy(sum.first_data, data, hdr->caplen < sizeof(sum.first_data) ? hdr->caplen : sizeof(sum.first_data));
        }
        sum.count++;
        sum.written_bits += (uint64_t)hdr->caplen * 8;
    }
    pcap_close(p);
    return sum;
}

static output_base_t *new_file_output(int slice, uint64_t rate_limit_mbps, char *path)
{
    snprintf(path, 128, "%s/out.pcap", tmp_dir);
    file_options_t opts = {
        .name = path,
        .snaplen = SNAPLEN,
        .slice = slice,
        .rate_limit_mbps = rate_limit_mbps,
    };
    file_output_t *out = file_output_new(opts, &stats, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(out, errbuf);
    return &out->base;
}

static output_base_t *new_rotating_output(int slice, uint64_t rate_limit_mbps)
{
    rotating_file_options_t opts = {
        .file_root = tmp_dir,
        .max_file_interval = 3600,
        .snaplen = SNAPLEN,
        .slice = slice,
        .rate_limit_mbps = rate_limit_mbps,
    };
    rotating_file_output_t *out = rotating_file_output_new(opts, &stats, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(out, errbuf);
    return &out->base;
}

static void rotating_file_path(char *path)
{
    char pattern[128];
    snprintf(pattern, sizeof(pattern), "%s/*/*.pcap", tmp_dir);
    glob_t g;
    TEST_ASSERT_EQUAL_INT(0, glob(pattern, 0, NULL, &g));
    TEST_ASSERT_EQUAL_UINT(1, g.gl_pathc);
    snprintf(path, 128, "%s", g.gl_pathv[0]);
    globfree(&g);
}

static void send_one(output_base_t *out, uint32_t len)
{
    struct pcap_pkthdr hdr = make_hdr(len, 0);
    TEST_ASSERT_EQUAL_INT(0, out->send_packet(out, &hdr, frame, PKT_DIR_NONCHECK));
}

static void send_rate_limit_burst(output_base_t *out)
{
    for (int i = 0; i < RL_FRAMES; i++)
    {
        struct pcap_pkthdr hdr = make_hdr(RL_FRAME_LEN, (long)i * RL_GAP_USEC);
        out->send_packet(out, &hdr, frame, PKT_DIR_NONCHECK);
    }
}

// pcap-savefile(5): a truncated record has incl_len = slice and orig_len = the wire length
static void assert_sliced(const pcap_summary_t *sum, int slice, uint32_t wire_len)
{
    TEST_ASSERT_EQUAL_INT(1, sum->count);
    TEST_ASSERT_EQUAL_INT(slice, sum->snaplen);
    TEST_ASSERT_EQUAL_UINT32(slice, sum->first_hdr.caplen);
    TEST_ASSERT_EQUAL_UINT32(wire_len, sum->first_hdr.len);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(frame, sum->first_data, slice);
    TEST_ASSERT_EQUAL_UINT64(slice, stats.fwd_bytes.bytes);
}

// 1 Mbit/s over 5 s plus the 1 Mbit initial bucket: at most 6 Mbit (plus one frame of rounding) is written
static void assert_rate_limited(const pcap_summary_t *sum)
{
    const uint64_t frame_bits = (uint64_t)RL_FRAME_LEN * 8;
    TEST_ASSERT_LESS_OR_EQUAL_UINT64(6000000 + frame_bits, sum->written_bits);
    TEST_ASSERT_GREATER_OR_EQUAL_UINT64(5000000, sum->written_bits);
    TEST_ASSERT_EQUAL_UINT64(sum->count, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(RL_FRAMES - sum->count, stats.ratelimit_drop_packets.packets);
    TEST_ASSERT_EQUAL_UINT64((uint64_t)(RL_FRAMES - sum->count) * RL_FRAME_LEN, stats.ratelimit_drop_bytes.bytes);
}

void test_file_slice_truncates_record(void)
{
    char path[128];
    output_base_t *out = new_file_output(64, 0, path);
    send_one(out, 200);
    out->destroy(out);

    pcap_summary_t sum = read_pcap(path);
    assert_sliced(&sum, 64, 200);
}

void test_file_slice_larger_than_packet_keeps_it_whole(void)
{
    char path[128];
    output_base_t *out = new_file_output(1500, 0, path);
    send_one(out, 200);
    out->destroy(out);

    pcap_summary_t sum = read_pcap(path);
    TEST_ASSERT_EQUAL_INT(1, sum.count);
    TEST_ASSERT_EQUAL_INT(1500, sum.snaplen);
    TEST_ASSERT_EQUAL_UINT32(200, sum.first_hdr.caplen);
    TEST_ASSERT_EQUAL_UINT32(200, sum.first_hdr.len);
}

void test_file_no_slice_keeps_capture_snaplen(void)
{
    char path[128];
    output_base_t *out = new_file_output(0, 0, path);
    send_one(out, 200);
    out->destroy(out);

    pcap_summary_t sum = read_pcap(path);
    TEST_ASSERT_EQUAL_INT(SNAPLEN, sum.snaplen);
    TEST_ASSERT_EQUAL_UINT32(200, sum.first_hdr.caplen);
}

void test_file_rate_limit_caps_output(void)
{
    char path[128];
    output_base_t *out = new_file_output(0, RL_MBPS, path);
    send_rate_limit_burst(out);
    out->destroy(out);

    pcap_summary_t sum = read_pcap(path);
    assert_rate_limited(&sum);
}

void test_file_no_rate_limit_writes_everything(void)
{
    char path[128];
    output_base_t *out = new_file_output(0, 0, path);
    send_rate_limit_burst(out);
    out->destroy(out);

    pcap_summary_t sum = read_pcap(path);
    TEST_ASSERT_EQUAL_INT(RL_FRAMES, sum.count);
    TEST_ASSERT_EQUAL_UINT64(0, stats.ratelimit_drop_packets.packets);
}

void test_rotating_file_slice_truncates_record(void)
{
    output_base_t *out = new_rotating_output(64, 0);
    send_one(out, 200);
    out->destroy(out);

    char path[128];
    rotating_file_path(path);
    pcap_summary_t sum = read_pcap(path);
    assert_sliced(&sum, 64, 200);
}

void test_rotating_file_rate_limit_caps_output(void)
{
    output_base_t *out = new_rotating_output(0, RL_MBPS);
    send_rate_limit_burst(out);
    out->destroy(out);

    char path[128];
    rotating_file_path(path);
    pcap_summary_t sum = read_pcap(path);
    assert_rate_limited(&sum);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_file_slice_truncates_record);
    RUN_TEST(test_file_slice_larger_than_packet_keeps_it_whole);
    RUN_TEST(test_file_no_slice_keeps_capture_snaplen);
    RUN_TEST(test_file_rate_limit_caps_output);
    RUN_TEST(test_file_no_rate_limit_writes_everything);

    RUN_TEST(test_rotating_file_slice_truncates_record);
    RUN_TEST(test_rotating_file_rate_limit_caps_output);

    return UNITY_END();
}
