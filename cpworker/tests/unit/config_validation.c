#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "unity/src/unity.h"

#include "config.h"

void setUp(void) {}

void tearDown(void) {}

static char config_buf[2048];

// Builds a single-task libpcap config whose only output is `output_json`.
static const char *config_with_output(const char *output_json)
{
    snprintf(config_buf, sizeof(config_buf),
             "{\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\"}}, "
             "\"outputs\": [%s]}]}",
             output_json);
    return config_buf;
}

static const char *vxlan_output_with_port(const char *port)
{
    static char buf[256];
    snprintf(buf, sizeof(buf), "{\"type\": \"vxlan\", \"vxlan\": {\"host\": \"10.0.0.1\", \"port\": %s, \"vni1\": 1}}",
             port);
    return buf;
}

static const char *zmq_output_with_port(const char *port)
{
    static char buf[256];
    snprintf(buf, sizeof(buf), "{\"type\": \"zmq\", \"zmq\": {\"host\": \"10.0.0.1\", \"port\": %s}}", port);
    return buf;
}

static void assert_rejected(const char *json, const char *expected_msg)
{
    cJSONParseError err = {0};
    Config *config = parse_config_data(json, &err);
    TEST_ASSERT_NULL_MESSAGE(config, json);
    if (config)
        free_config(config);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err.message, expected_msg), err.message);
}

static OutputConfig *parse_single_output(const char *json, Config **config_out)
{
    cJSONParseError err = {0};
    Config *config = parse_config_data(json, &err);
    TEST_ASSERT_NOT_NULL_MESSAGE(config, err.message);
    *config_out = config;
    return config->tasks_cfg->tasks[0]->outputs[0];
}

void test_vxlan_port_out_of_range_rejected(void)
{
    const char *bad[] = {"70000", "65536", "-1", "0", "1.5"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(config_with_output(vxlan_output_with_port(bad[i])), "invalid vxlan.port");
}

void test_vxlan_port_not_number_rejected(void)
{
    assert_rejected(config_with_output(vxlan_output_with_port("\"4789\"")), "invalid vxlan.port");
}

void test_vxlan_port_bounds_accepted(void)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(vxlan_output_with_port("1")), &config);
    TEST_ASSERT_EQUAL_UINT16(1, output->config.vxlan.port);
    free_config(config);

    output = parse_single_output(config_with_output(vxlan_output_with_port("65535")), &config);
    TEST_ASSERT_EQUAL_UINT16(65535, output->config.vxlan.port);
    free_config(config);
}

void test_vxlan_port_default(void)
{
    Config *config;
    OutputConfig *output = parse_single_output(
        config_with_output("{\"type\": \"vxlan\", \"vxlan\": {\"host\": \"10.0.0.1\", \"vni1\": 1}}"), &config);
    TEST_ASSERT_EQUAL_UINT16(4789, output->config.vxlan.port);
    free_config(config);
}

void test_vxlan_port_error_message_names_range(void)
{
    assert_rejected(config_with_output(vxlan_output_with_port("70000")),
                    "invalid vxlan.port: 70000, must be an integer in [1, 65535]");
}

void test_zmq_port_out_of_range_rejected(void)
{
    const char *bad[] = {"70000", "65536", "-1", "0", "1.5"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(config_with_output(zmq_output_with_port(bad[i])), "invalid zmq.port");
}

void test_zmq_port_not_number_rejected(void)
{
    assert_rejected(config_with_output(zmq_output_with_port("\"5555\"")), "invalid zmq.port");
}

void test_zmq_port_bounds_accepted(void)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(zmq_output_with_port("1")), &config);
    TEST_ASSERT_EQUAL_UINT16(1, output->config.zmq.port);
    free_config(config);

    output = parse_single_output(config_with_output(zmq_output_with_port("65535")), &config);
    TEST_ASSERT_EQUAL_UINT16(65535, output->config.zmq.port);
    free_config(config);
}

void test_zmq_port_missing_rejected(void)
{
    assert_rejected(config_with_output("{\"type\": \"zmq\", \"zmq\": {\"host\": \"10.0.0.1\"}}"), "missing zmq.port");
}

static const char *pipeline_config_with_buffer_size(const char *buffer_size_mb)
{
    snprintf(config_buf, sizeof(config_buf),
             "{\"execution_model\": \"pipeline\", \"pipeline\": {\"buffer_size_mb\": %s}, "
             "\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\"}}, "
             "\"outputs\": [{\"type\": \"null\"}]}]}",
             buffer_size_mb);
    return config_buf;
}

void test_pipeline_buffer_size_invalid_rejected(void)
{
    // 17592186044416 == SIZE_MAX / 1 MiB + 1 on 64-bit platforms
    const char *bad[] = {"0", "-1", "1.5", "17592186044416", "\"256\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(pipeline_config_with_buffer_size(bad[i]), "invalid pipeline.buffer_size_mb");
}

void test_pipeline_buffer_size_missing_rejected(void)
{
    assert_rejected("{\"execution_model\": \"pipeline\", \"pipeline\": {}, "
                    "\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\"}}, "
                    "\"outputs\": [{\"type\": \"null\"}]}]}",
                    "missing pipeline.buffer_size_mb");
}

// task.c converts buffer_size_mb to bytes with `buffer_size_mb * 1024 * 1024`; that must not overflow at >= 2048.
void test_pipeline_buffer_size_large_value_in_bytes(void)
{
    cJSONParseError err = {0};
    Config *config = parse_config_data(pipeline_config_with_buffer_size("4096"), &err);
    TEST_ASSERT_NOT_NULL_MESSAGE(config, err.message);
    TEST_ASSERT_EQUAL_UINT64(4096, config->pipeline.buffer_size_mb);
    TEST_ASSERT_EQUAL_UINT64(4294967296ULL, config->pipeline.buffer_size_mb * 1024 * 1024);
    free_config(config);
}

static const char *libpcap_config_with_snaplen(const char *snaplen)
{
    snprintf(config_buf, sizeof(config_buf),
             "{\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\", "
             "\"snaplen\": %s}}, \"outputs\": [{\"type\": \"null\"}]}]}",
             snaplen);
    return config_buf;
}

static const char *dpdk_config_with_snaplen(const char *snaplen)
{
    snprintf(config_buf, sizeof(config_buf),
             "{\"tasks\": [{\"capturer\": {\"type\": \"dpdk_pdump\", \"dpdk_pdump\": {\"interface\": \"0000:00:00.0\", "
             "\"snaplen\": %s}}, \"outputs\": [{\"type\": \"null\"}]}]}",
             snaplen);
    return config_buf;
}

static CapturerConfig *parse_capturer(const char *json, Config **config_out)
{
    cJSONParseError err = {0};
    Config *config = parse_config_data(json, &err);
    TEST_ASSERT_NOT_NULL_MESSAGE(config, err.message);
    *config_out = config;
    return &config->tasks_cfg->tasks[0]->capturer;
}

static void assert_libpcap_snaplen(const char *configured, int expected)
{
    Config *config;
    CapturerConfig *capturer = parse_capturer(libpcap_config_with_snaplen(configured), &config);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, capturer->config.libpcap.snaplen, configured);
    free_config(config);
}

static void assert_dpdk_snaplen(const char *configured, int expected)
{
    Config *config;
    CapturerConfig *capturer = parse_capturer(dpdk_config_with_snaplen(configured), &config);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, capturer->config.dpdk_pdump.snaplen, configured);
    free_config(config);
}

void test_libpcap_snaplen_in_range_kept(void)
{
    assert_libpcap_snaplen("1", 1);
    assert_libpcap_snaplen("2048", 2048);
    assert_libpcap_snaplen("262144", 262144);
}

// libpcap 1.6.2 (bundled) captures 0 bytes for 0, fails for negatives and hangs in pcap_activate for INT_MAX.
void test_libpcap_snaplen_out_of_range_uses_maximum(void)
{
    const char *values[] = {"0", "-1", "-2147483649", "262145", "2147483647", "2147483648", "1e12"};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        assert_libpcap_snaplen(values[i], 262144);
}

void test_libpcap_snaplen_default(void)
{
    Config *config;
    CapturerConfig *capturer =
        parse_capturer("{\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\"}}, "
                       "\"outputs\": [{\"type\": \"null\"}]}]}",
                       &config);
    TEST_ASSERT_EQUAL_INT(2048, capturer->config.libpcap.snaplen);
    free_config(config);
}

void test_libpcap_snaplen_invalid_rejected(void)
{
    assert_rejected(libpcap_config_with_snaplen("1.5"), "invalid libpcap.snaplen: 1.5, must be an integer");
    assert_rejected(libpcap_config_with_snaplen("\"2048\""), "invalid libpcap.snaplen");
}

void test_dpdk_snaplen(void)
{
    assert_dpdk_snaplen("1", 1);
    assert_dpdk_snaplen("262144", 262144);
    assert_dpdk_snaplen("262145", 262144);
    assert_dpdk_snaplen("2147483648", 262144);
}

void test_dpdk_snaplen_invalid_rejected(void)
{
    const char *bad[] = {"0", "-1", "1.5", "\"2048\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(dpdk_config_with_snaplen(bad[i]), "invalid dpdk_pdump.snaplen");
}

static const char *libpcap_config_with_buffer_size(const char *buffer_size_mb)
{
    snprintf(config_buf, sizeof(config_buf),
             "{\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\", "
             "\"buffer_size_mb\": %s}}, \"outputs\": [{\"type\": \"null\"}]}]}",
             buffer_size_mb);
    return config_buf;
}

static void assert_libpcap_buffer_size(const char *configured, int expected)
{
    Config *config;
    CapturerConfig *capturer = parse_capturer(libpcap_config_with_buffer_size(configured), &config);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, capturer->config.libpcap.buffer_size_mb, configured);
    free_config(config);
}

void test_libpcap_buffer_size_in_range_kept(void)
{
    assert_libpcap_buffer_size("1", 1);
    assert_libpcap_buffer_size("2047", 2047);
}

// pcap_set_buffer_size() takes an int byte count, so 2047 MB is the largest whole-MB value it accepts.
void test_libpcap_buffer_size_above_limit_uses_limit(void)
{
    assert_libpcap_buffer_size("2048", 2047);
    assert_libpcap_buffer_size("8192", 2047);
    assert_libpcap_buffer_size("1e12", 2047);
}

void test_libpcap_buffer_size_default(void)
{
    Config *config;
    CapturerConfig *capturer =
        parse_capturer("{\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\"}}, "
                       "\"outputs\": [{\"type\": \"null\"}]}]}",
                       &config);
    TEST_ASSERT_EQUAL_INT(256, capturer->config.libpcap.buffer_size_mb);
    free_config(config);
}

// libpcap 1.6.2 (bundled) maps a ~4 GB ring for a negative size; 0 silently falls back to its 2 MB default.
void test_libpcap_buffer_size_invalid_rejected(void)
{
    const char *bad[] = {"0", "-1", "1.5", "\"256\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(libpcap_config_with_buffer_size(bad[i]), "invalid libpcap.buffer_size_mb");
}

static const char *null_output_with_slice(const char *slice)
{
    static char buf[128];
    snprintf(buf, sizeof(buf), "{\"type\": \"null\", \"slice\": %s}", slice);
    return buf;
}

static void assert_slice(const char *configured, int expected)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(null_output_with_slice(configured)), &config);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, output->slice, configured);
    free_config(config);
}

void test_slice_non_negative_kept(void)
{
    assert_slice("0", 0);
    assert_slice("1", 1);
    assert_slice("64", 64);
    assert_slice("262144", 262144);
}

// Any slice >= the packet length means "no truncation", so values beyond int are stored as INT_MAX.
void test_slice_above_int_stored_as_int_max(void) { assert_slice("2147483648", INT_MAX); }

void test_slice_default(void)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output("{\"type\": \"null\"}"), &config);
    TEST_ASSERT_EQUAL_INT(0, output->slice);
    free_config(config);
}

void test_slice_invalid_rejected(void)
{
    assert_rejected(config_with_output(null_output_with_slice("-1")), "invalid slice: -1, must be >= 0");
    assert_rejected(config_with_output(null_output_with_slice("1.5")), "invalid slice");
    assert_rejected(config_with_output(null_output_with_slice("\"64\"")), "invalid slice");
}

static const char *vxlan_output_with_vni(const char *vni_fields)
{
    static char buf[256];
    snprintf(buf, sizeof(buf), "{\"type\": \"vxlan\", \"vxlan\": {\"host\": \"10.0.0.1\", %s}}", vni_fields);
    return buf;
}

static void assert_vni(const char *vni_fields, uint8_t expected_version, uint32_t expected_vni)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(vxlan_output_with_vni(vni_fields)), &config);
    TEST_ASSERT_EQUAL_UINT8_MESSAGE(expected_version, output->config.vxlan.vni_version, vni_fields);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(expected_vni, output->config.vxlan.vni, vni_fields);
    free_config(config);
}

void test_vni1_in_range_kept(void)
{
    assert_vni("\"vni1\": 0", 1, 0);
    assert_vni("\"vni1\": 16777215", 1, 0xFFFFFF);
}

// The wire only carries the low 24 bits (vni << 8); cpdaemon may send uint32(serviceTag) beyond that.
void test_vni1_above_24_bits_keeps_low_24_bits(void)
{
    assert_vni("\"vni1\": 16777216", 1, 0);
    assert_vni("\"vni1\": 28036591", 1, 0xABCDEF);
    assert_vni("\"vni1\": 4294967295", 1, 0xFFFFFF);
}

void test_vni1_invalid_rejected(void)
{
    const char *bad[] = {"\"vni1\": -1", "\"vni1\": 4294967296", "\"vni1\": 1.5", "\"vni1\": \"1\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(config_with_output(vxlan_output_with_vni(bad[i])), "invalid vxlan.vni1");
}

void test_vni2_in_range_kept(void)
{
    assert_vni("\"vni2\": 0", 2, 0);
    assert_vni("\"vni2\": 4294967295", 2, 0xFFFFFFFF);
}

void test_vni2_invalid_rejected(void)
{
    const char *bad[] = {"\"vni2\": -1", "\"vni2\": 4294967296", "\"vni2\": 1.5", "\"vni2\": \"1\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(config_with_output(vxlan_output_with_vni(bad[i])), "invalid vxlan.vni2");
}

void test_vni1_and_vni2_mutually_exclusive(void)
{
    assert_rejected(config_with_output(vxlan_output_with_vni("\"vni1\": 1, \"vni2\": 2")),
                    "vxlan.vni1 and vxlan.vni2 are mutually exclusive");
}

void test_vni_missing_rejected(void)
{
    assert_rejected(config_with_output("{\"type\": \"vxlan\", \"vxlan\": {\"host\": \"10.0.0.1\"}}"),
                    "require vxlan.vni1 or vxlan.vni2");
}

static const char *vxlan_output_with_split(const char *split_json)
{
    static char buf[256];
    snprintf(buf, sizeof(buf), "{\"type\": \"vxlan\", \"vxlan\": {\"host\": \"10.0.0.1\", \"vni1\": 1, \"split\": %s}}",
             split_json);
    return buf;
}

static const char *split_with_max_payload_size(const char *max_payload_size)
{
    static char buf[128];
    snprintf(buf, sizeof(buf), "{\"max_payload_size\": %s}", max_payload_size);
    return vxlan_output_with_split(buf);
}

static void assert_max_payload_size(const char *vxlan_output_json, uint16_t expected)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(vxlan_output_json), &config);
    TEST_ASSERT_EQUAL_UINT16_MESSAGE(expected, output->config.vxlan.split.max_payload_size, vxlan_output_json);
    free_config(config);
}

void test_split_max_payload_size_in_range_kept(void)
{
    assert_max_payload_size(split_with_max_payload_size("0"), 0);
    assert_max_payload_size(split_with_max_payload_size("1"), 1);
    assert_max_payload_size(split_with_max_payload_size("65535"), 65535);
}

void test_split_max_payload_size_default(void)
{
    assert_max_payload_size(vxlan_output_with_vni("\"vni1\": 1"), 0);
    assert_max_payload_size(vxlan_output_with_split("{}"), 0);
}

void test_split_max_payload_size_invalid_rejected(void)
{
    const char *bad[] = {"-1", "65536", "1.5", "-0.5", "1e20", "\"100\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(config_with_output(split_with_max_payload_size(bad[i])),
                        "invalid vxlan.split.max_payload_size");
}

static const char *zmq_output_with_service_tag(const char *service_tag)
{
    static char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"type\": \"zmq\", \"zmq\": {\"host\": \"10.0.0.1\", \"port\": 5555, \"service_tag\": %s}}",
             service_tag);
    return buf;
}

static const char *gre_output_with_service_tag(const char *service_tag)
{
    static char buf[256];
    snprintf(buf, sizeof(buf), "{\"type\": \"gre\", \"gre\": {\"host\": \"10.0.0.1\", \"service_tag\": %s}}",
             service_tag);
    return buf;
}

static void assert_zmq_service_tag(const char *output_json, uint32_t expected)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(output_json), &config);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(expected, output->config.zmq.service_tag, output_json);
    free_config(config);
}

static void assert_gre_service_tag(const char *output_json, uint32_t expected)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(output_json), &config);
    TEST_ASSERT_EQUAL_HEX32_MESSAGE(expected, output->config.gre.service_tag, output_json);
    free_config(config);
}

// 12 bits reach the per-packet MPLS label; values beyond that are kept (with a warning) because the batch
// header's keybit carries all 32 bits and cpdaemon may send uint32(serviceTag).
void test_zmq_service_tag_uint32_kept(void)
{
    const char *values[] = {"0", "4095", "4096", "4294967295"};
    const uint32_t expected[] = {0, 4095, 4096, 0xFFFFFFFF};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        assert_zmq_service_tag(zmq_output_with_service_tag(values[i]), expected[i]);
}

void test_zmq_service_tag_default(void) { assert_zmq_service_tag(zmq_output_with_port("5555"), 0xFFFFFFFF); }

void test_zmq_service_tag_invalid_rejected(void)
{
    const char *bad[] = {"-1", "4294967296", "1.5", "\"1\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(config_with_output(zmq_output_with_service_tag(bad[i])), "invalid zmq.service_tag");
}

// The high 4 bits of the GRE key carry the direction; larger tags are kept (with a warning) as cpdaemon may send them.
void test_gre_service_tag_uint32_kept(void)
{
    const char *values[] = {"0", "268435455", "268435456", "4294967295"};
    const uint32_t expected[] = {0, 0x0FFFFFFF, 0x10000000, 0xFFFFFFFF};
    for (size_t i = 0; i < sizeof(values) / sizeof(values[0]); i++)
        assert_gre_service_tag(gre_output_with_service_tag(values[i]), expected[i]);
}

void test_gre_service_tag_default(void)
{
    assert_gre_service_tag("{\"type\": \"gre\", \"gre\": {\"host\": \"10.0.0.1\"}}", 0xFFFFFFFF);
}

void test_gre_service_tag_invalid_rejected(void)
{
    const char *bad[] = {"-1", "4294967296", "1.5", "\"1\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(config_with_output(gre_output_with_service_tag(bad[i])), "invalid gre.service_tag");
}

static const char *zmq_output_with_hwm(const char *hwm)
{
    static char buf[256];
    snprintf(buf, sizeof(buf), "{\"type\": \"zmq\", \"zmq\": {\"host\": \"10.0.0.1\", \"port\": 5555, \"hwm\": %s}}",
             hwm);
    return buf;
}

static void assert_zmq_hwm(const char *output_json, int expected)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(output_json), &config);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, output->config.zmq.hwm, output_json);
    free_config(config);
}

// 0 is libzmq's "no limit" and is kept (with a warning); values beyond int are equally unbounded in practice.
void test_zmq_hwm_non_negative_kept(void)
{
    assert_zmq_hwm(zmq_output_with_hwm("0"), 0);
    assert_zmq_hwm(zmq_output_with_hwm("1"), 1);
    assert_zmq_hwm(zmq_output_with_hwm("1000"), 1000);
    assert_zmq_hwm(zmq_output_with_hwm("2147483648"), INT_MAX);
}

void test_zmq_hwm_default(void) { assert_zmq_hwm(zmq_output_with_port("5555"), 100); }

// libzmq rejects a negative ZMQ_SNDHWM with EINVAL.
void test_zmq_hwm_invalid_rejected(void)
{
    assert_rejected(config_with_output(zmq_output_with_hwm("-1")), "invalid zmq.hwm: -1, must be >= 0");
    assert_rejected(config_with_output(zmq_output_with_hwm("1.5")), "invalid zmq.hwm");
    assert_rejected(config_with_output(zmq_output_with_hwm("\"100\"")), "invalid zmq.hwm");
}

static const char *rotating_file_output_with_interval(const char *interval)
{
    static char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"type\": \"rotating_file\", \"rotating_file\": {\"file_root\": \"/tmp\", \"max_file_interval\": %s}}",
             interval);
    return buf;
}

static void assert_max_file_interval(const char *output_json, int expected)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(output_json), &config);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, output->config.rotating_file.max_file_interval, output_json);
    free_config(config);
}

void test_max_file_interval_non_negative_kept(void)
{
    assert_max_file_interval(rotating_file_output_with_interval("0"), 0);
    assert_max_file_interval(rotating_file_output_with_interval("1"), 1);
    assert_max_file_interval(rotating_file_output_with_interval("3600"), 3600);
    assert_max_file_interval(rotating_file_output_with_interval("2147483648"), INT_MAX);
}

// Unset used to be -1, which rotated (and truncated) the file on every packet.
void test_max_file_interval_default(void)
{
    assert_max_file_interval("{\"type\": \"rotating_file\", \"rotating_file\": {\"file_root\": \"/tmp\"}}", 60);
}

void test_max_file_interval_invalid_rejected(void)
{
    assert_rejected(config_with_output(rotating_file_output_with_interval("-1")),
                    "invalid rotating_file.max_file_interval: -1, must be >= 0");
    assert_rejected(config_with_output(rotating_file_output_with_interval("1.5")),
                    "invalid rotating_file.max_file_interval");
    assert_rejected(config_with_output(rotating_file_output_with_interval("\"60\"")),
                    "invalid rotating_file.max_file_interval");
}

static const char *dpdk_config_with_ring_size(const char *ring_size)
{
    snprintf(config_buf, sizeof(config_buf),
             "{\"tasks\": [{\"capturer\": {\"type\": \"dpdk_pdump\", \"dpdk_pdump\": {\"interface\": \"0000:00:00.0\", "
             "\"ring_size\": %s}}, \"outputs\": [{\"type\": \"null\"}]}]}",
             ring_size);
    return config_buf;
}

static void assert_dpdk_ring_size(const char *json, int expected)
{
    Config *config;
    CapturerConfig *capturer = parse_capturer(json, &config);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, capturer->config.dpdk_pdump.ring_size, json);
    free_config(config);
}

// The ring is rounded up to a power of two; 2^30 is the largest one rte_ring_create() accepts.
void test_dpdk_ring_size_in_range_kept(void)
{
    assert_dpdk_ring_size(dpdk_config_with_ring_size("2"), 2);
    assert_dpdk_ring_size(dpdk_config_with_ring_size("1000"), 1000);
    assert_dpdk_ring_size(dpdk_config_with_ring_size("1073741824"), 1073741824);
}

void test_dpdk_ring_size_default(void)
{
    assert_dpdk_ring_size("{\"tasks\": [{\"capturer\": {\"type\": \"dpdk_pdump\", \"dpdk_pdump\": "
                          "{\"interface\": \"0000:00:00.0\"}}, \"outputs\": [{\"type\": \"null\"}]}]}",
                          2048);
}

void test_dpdk_ring_size_invalid_rejected(void)
{
    const char *bad[] = {"0", "1", "-1", "1073741825", "1.5", "\"2048\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(dpdk_config_with_ring_size(bad[i]), "invalid dpdk_pdump.ring_size");
}

static const char *null_output_with_rate_limit(const char *rate_limit_mbps)
{
    static char buf[128];
    snprintf(buf, sizeof(buf), "{\"type\": \"null\", \"rate_limit_mbps\": %s}", rate_limit_mbps);
    return buf;
}

static void assert_rate_limit(const char *output_json, uint64_t expected)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(output_json), &config);
    TEST_ASSERT_EQUAL_UINT64_MESSAGE(expected, output->rate_limit_mbps, output_json);
    free_config(config);
}

// Values beyond int are stored as INT_MAX Mbps, which is unlimited in practice (as before).
void test_rate_limit_non_negative_kept(void)
{
    assert_rate_limit(null_output_with_rate_limit("0"), 0);
    assert_rate_limit(null_output_with_rate_limit("1"), 1);
    assert_rate_limit(null_output_with_rate_limit("10000"), 10000);
    assert_rate_limit(null_output_with_rate_limit("2147483648"), INT_MAX);
}

void test_rate_limit_default(void) { assert_rate_limit("{\"type\": \"null\"}", 0); }

void test_rate_limit_invalid_rejected(void)
{
    assert_rejected(config_with_output(null_output_with_rate_limit("-1")), "invalid rate_limit_mbps: -1, must be >= 0");
    const char *bad[] = {"1.5", "-0.5", "\"10\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(config_with_output(null_output_with_rate_limit(bad[i])), "invalid rate_limit_mbps");
}

static const char *libpcap_config_with_timeout(const char *timeout_ms)
{
    snprintf(config_buf, sizeof(config_buf),
             "{\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\", "
             "\"timeout_ms\": %s}}, \"outputs\": [{\"type\": \"null\"}]}]}",
             timeout_ms);
    return config_buf;
}

static void assert_timeout(const char *json, int expected)
{
    Config *config;
    CapturerConfig *capturer = parse_capturer(json, &config);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, capturer->config.libpcap.timeout_ms, json);
    free_config(config);
}

void test_timeout_non_negative_kept(void)
{
    assert_timeout(libpcap_config_with_timeout("0"), 0);
    assert_timeout(libpcap_config_with_timeout("10"), 10);
    assert_timeout(libpcap_config_with_timeout("2147483648"), INT_MAX);
}

void test_timeout_default(void)
{
    assert_timeout("{\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\"}}, "
                   "\"outputs\": [{\"type\": \"null\"}]}]}",
                   0);
}

void test_timeout_invalid_rejected(void)
{
    assert_rejected(libpcap_config_with_timeout("-1"), "invalid libpcap.timeout_ms: -1, must be >= 0");
    const char *bad[] = {"1.5", "-0.5", "\"10\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(libpcap_config_with_timeout(bad[i]), "invalid libpcap.timeout_ms");
}

static const char *zmq_output_with_heartbeat(const char *heartbeat_ms)
{
    static char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"type\": \"zmq\", \"zmq\": {\"host\": \"10.0.0.1\", \"port\": 5555, \"heartbeat_ms\": %s}}",
             heartbeat_ms);
    return buf;
}

static void assert_heartbeat(const char *output_json, int expected)
{
    Config *config;
    OutputConfig *output = parse_single_output(config_with_output(output_json), &config);
    TEST_ASSERT_EQUAL_INT_MESSAGE(expected, output->config.zmq.heartbeat_ms, output_json);
    free_config(config);
}

void test_heartbeat_in_range_kept(void)
{
    assert_heartbeat(zmq_output_with_heartbeat("0"), 0);
    assert_heartbeat(zmq_output_with_heartbeat("2000"), 2000);
    assert_heartbeat(zmq_output_with_heartbeat("60000"), 60000);
}

void test_heartbeat_default(void) { assert_heartbeat(zmq_output_with_port("5555"), 0); }

void test_heartbeat_invalid_rejected(void)
{
    assert_rejected(config_with_output(zmq_output_with_heartbeat("60001")),
                    "invalid zmq.heartbeat_ms: 60001, must be an integer in [0, 60000]");
    const char *bad[] = {"-1", "1.5", "-0.5", "2147483648", "\"2000\""};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
        assert_rejected(config_with_output(zmq_output_with_heartbeat(bad[i])), "invalid zmq.heartbeat_ms");
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_vxlan_port_out_of_range_rejected);
    RUN_TEST(test_vxlan_port_not_number_rejected);
    RUN_TEST(test_vxlan_port_bounds_accepted);
    RUN_TEST(test_vxlan_port_default);
    RUN_TEST(test_vxlan_port_error_message_names_range);
    RUN_TEST(test_zmq_port_out_of_range_rejected);
    RUN_TEST(test_zmq_port_not_number_rejected);
    RUN_TEST(test_zmq_port_bounds_accepted);
    RUN_TEST(test_zmq_port_missing_rejected);
    RUN_TEST(test_pipeline_buffer_size_invalid_rejected);
    RUN_TEST(test_pipeline_buffer_size_missing_rejected);
    RUN_TEST(test_pipeline_buffer_size_large_value_in_bytes);
    RUN_TEST(test_libpcap_snaplen_in_range_kept);
    RUN_TEST(test_libpcap_snaplen_out_of_range_uses_maximum);
    RUN_TEST(test_libpcap_snaplen_default);
    RUN_TEST(test_libpcap_snaplen_invalid_rejected);
    RUN_TEST(test_dpdk_snaplen);
    RUN_TEST(test_dpdk_snaplen_invalid_rejected);
    RUN_TEST(test_libpcap_buffer_size_in_range_kept);
    RUN_TEST(test_libpcap_buffer_size_above_limit_uses_limit);
    RUN_TEST(test_libpcap_buffer_size_default);
    RUN_TEST(test_libpcap_buffer_size_invalid_rejected);
    RUN_TEST(test_slice_non_negative_kept);
    RUN_TEST(test_slice_above_int_stored_as_int_max);
    RUN_TEST(test_slice_default);
    RUN_TEST(test_slice_invalid_rejected);
    RUN_TEST(test_vni1_in_range_kept);
    RUN_TEST(test_vni1_above_24_bits_keeps_low_24_bits);
    RUN_TEST(test_vni1_invalid_rejected);
    RUN_TEST(test_vni2_in_range_kept);
    RUN_TEST(test_vni2_invalid_rejected);
    RUN_TEST(test_vni1_and_vni2_mutually_exclusive);
    RUN_TEST(test_vni_missing_rejected);
    RUN_TEST(test_split_max_payload_size_in_range_kept);
    RUN_TEST(test_split_max_payload_size_default);
    RUN_TEST(test_split_max_payload_size_invalid_rejected);
    RUN_TEST(test_zmq_service_tag_uint32_kept);
    RUN_TEST(test_zmq_service_tag_default);
    RUN_TEST(test_zmq_service_tag_invalid_rejected);
    RUN_TEST(test_gre_service_tag_uint32_kept);
    RUN_TEST(test_gre_service_tag_default);
    RUN_TEST(test_gre_service_tag_invalid_rejected);
    RUN_TEST(test_zmq_hwm_non_negative_kept);
    RUN_TEST(test_zmq_hwm_default);
    RUN_TEST(test_zmq_hwm_invalid_rejected);
    RUN_TEST(test_max_file_interval_non_negative_kept);
    RUN_TEST(test_max_file_interval_default);
    RUN_TEST(test_max_file_interval_invalid_rejected);
    RUN_TEST(test_dpdk_ring_size_in_range_kept);
    RUN_TEST(test_dpdk_ring_size_default);
    RUN_TEST(test_dpdk_ring_size_invalid_rejected);
    RUN_TEST(test_rate_limit_non_negative_kept);
    RUN_TEST(test_rate_limit_default);
    RUN_TEST(test_rate_limit_invalid_rejected);
    RUN_TEST(test_timeout_non_negative_kept);
    RUN_TEST(test_timeout_default);
    RUN_TEST(test_timeout_invalid_rejected);
    RUN_TEST(test_heartbeat_in_range_kept);
    RUN_TEST(test_heartbeat_default);
    RUN_TEST(test_heartbeat_invalid_rejected);

    return UNITY_END();
}
