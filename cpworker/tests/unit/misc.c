#include "affinity.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>

#include "unity/src/unity.h"

#include "bpf_util.h"
#include "config.h"
#include "errorf.h"
#include "ip.h"
#include "output_gre.h"
#include "output_vxlan.h"
#include "output_zmq.h"

void setUp(void) {}

void tearDown(void) {}

const char *config_libpcap_gre =
    "{\"tasks\": [{\"req_pattern\": {\"type\": \"auto\"}, \"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
    "{\"interface\": \"eth0\", \"snaplen\": 2048, \"buffer_size_mb\": 256}}, \"outputs\": [{\"type\": \"gre\", "
    "\"rate_limit_mbps\": 10, \"gre\": {\"host\": \"172.16.1.201\", \"bind_device\": \"eth1\"}}]}]}";

const char *config_libpcap_zmq_heartbeat =
    "{\"tasks\": [{\"req_pattern\": {\"type\": \"auto\"}, \"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
    "{\"interface\": \"eth0\", \"snaplen\": 2048, \"buffer_size_mb\": 256}}, \"outputs\": [{\"type\": \"zmq\", "
    "\"zmq\": {\"host\": \"10.0.0.1\", \"port\": 5555, \"hwm\": 100, \"service_tag\": 1, "
    "\"uuid\": \"550e8400-e29b-41d4-a716-446655440000\", \"heartbeat_ms\": 2000}}]}]}";

const char *config_libpcap_zmq_heartbeat_default =
    "{\"tasks\": [{\"req_pattern\": {\"type\": \"auto\"}, \"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
    "{\"interface\": \"eth0\", \"snaplen\": 2048, \"buffer_size_mb\": 256}}, \"outputs\": [{\"type\": \"zmq\", "
    "\"zmq\": {\"host\": \"10.0.0.1\", \"port\": 5555, \"hwm\": 100, \"service_tag\": 1, "
    "\"uuid\": \"550e8400-e29b-41d4-a716-446655440000\"}}]}]}";

const char *config_libpcap_zmq_heartbeat_disabled =
    "{\"tasks\": [{\"req_pattern\": {\"type\": \"auto\"}, \"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
    "{\"interface\": \"eth0\", \"snaplen\": 2048, \"buffer_size_mb\": 256}}, \"outputs\": [{\"type\": \"zmq\", "
    "\"zmq\": {\"host\": \"10.0.0.1\", \"port\": 5555, \"hwm\": 100, \"service_tag\": 1, "
    "\"uuid\": \"550e8400-e29b-41d4-a716-446655440000\", \"heartbeat_ms\": 0}}]}]}";

const char *config_libpcap_gre_vxlan =
    "{\"tasks\": [{\"req_pattern\": {\"type\": \"auto\"}, \"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
    "{\"interface\": \"eth0\", \"snaplen\": 2048, \"buffer_size_mb\": 256}}, "
    "\"outputs\": [{\"type\": \"gre\", \"rate_limit_mbps\": 10, \"gre\": {\"host\": \"172.16.1.201\", \"bind_device\": "
    "\"eth1\"}}, {\"type\": \"vxlan\", \"rate_limit_mbps\": 10, \"vxlan\": {\"host\": \"172.16.1.202\", \"port\": "
    "4789, \"vni1\": 11259375, \"bind_device\": \"eth1\"}}]}]}";

const char *config_libpcap_two_tasks_vxlan =
    "{\"tasks\": ["
    "{\"req_pattern\": {\"type\": \"auto\"}, \"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
    "{\"interface\": \"ens192\", \"snaplen\": 65535, \"buffer_size_mb\": 256}}, "
    "\"outputs\": [{\"type\": \"vxlan\", \"vxlan\": {\"host\": \"172.16.206.40\", \"port\": 4788, \"vni1\": 123}}]},"
    "{\"req_pattern\": {\"type\": \"auto\"}, \"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
    "{\"interface\": \"ens192\", \"snaplen\": 65535, \"buffer_size_mb\": 256}}, "
    "\"outputs\": [{\"type\": \"vxlan\", \"vxlan\": {\"host\": \"172.16.206.24\", \"port\": 4788, \"vni1\": 234}}]}"
    "]}";

const char *config_libpcap_two_tasks_shared_host =
    "{\"tasks\": ["
    "{\"req_pattern\": {\"type\": \"auto\"}, \"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
    "{\"interface\": \"eth0\", \"snaplen\": 2048, \"buffer_size_mb\": 256}}, "
    "\"outputs\": [{\"type\": \"gre\", \"gre\": {\"host\": \"172.16.1.201\", \"bind_device\": \"eth1\"}}]},"
    "{\"req_pattern\": {\"type\": \"auto\"}, \"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
    "{\"interface\": \"eth0\", \"snaplen\": 2048, \"buffer_size_mb\": 256}}, "
    "\"outputs\": [{\"type\": \"gre\", \"gre\": {\"host\": \"172.16.1.201\", \"bind_device\": \"eth1\"}}]}"
    "]}";

void test_parse_config_data_for_libpcap_gre_vxlan(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_gre_vxlan, &err);
    TEST_ASSERT_NOT_NULL(config);

    OutputConfig *vxlan_output = config->tasks_cfg->tasks[0]->outputs[1];
    TEST_ASSERT_EQUAL_UINT32(0xABCDEF, vxlan_output->config.vxlan.vni);
}

void test_bpf_filter_exclude_task_output_hosts_1(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_gre, &err);
    TEST_ASSERT_NOT_NULL(config);

    char errbuf[ERROR_BUFFER_SIZE];
    char *bpf_filter = bpf_filter_exclude_task_output_hosts("", config->tasks_cfg, errbuf);
    TEST_ASSERT_NOT_NULL(bpf_filter);
    TEST_ASSERT_EQUAL_STRING("not host 172.16.1.201", bpf_filter);
    free(bpf_filter);
}

void test_bpf_filter_exclude_task_output_hosts_2(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_gre, &err);
    TEST_ASSERT_NOT_NULL(config);

    char errbuf[ERROR_BUFFER_SIZE];
    char *bpf_filter = bpf_filter_exclude_task_output_hosts("host 10.1.1.1 and port 8011", config->tasks_cfg, errbuf);
    TEST_ASSERT_NOT_NULL(bpf_filter);
    TEST_ASSERT_EQUAL_STRING("(host 10.1.1.1 and port 8011) and not host 172.16.1.201", bpf_filter);
    free(bpf_filter);
}

void test_bpf_filter_exclude_task_output_hosts_3(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_gre_vxlan, &err);
    TEST_ASSERT_NOT_NULL(config);

    char errbuf[ERROR_BUFFER_SIZE];
    char *bpf_filter = bpf_filter_exclude_task_output_hosts("", config->tasks_cfg, errbuf);
    TEST_ASSERT_NOT_NULL(bpf_filter);
    TEST_ASSERT_EQUAL_STRING("not host 172.16.1.201 and not host 172.16.1.202", bpf_filter);
    free(bpf_filter);
}

void test_bpf_filter_exclude_task_output_hosts_4(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_gre_vxlan, &err);
    TEST_ASSERT_NOT_NULL(config);

    char errbuf[ERROR_BUFFER_SIZE];
    char *bpf_filter = bpf_filter_exclude_task_output_hosts("host 10.1.1.1 and port 8011", config->tasks_cfg, errbuf);
    TEST_ASSERT_NOT_NULL(bpf_filter);
    TEST_ASSERT_EQUAL_STRING("(host 10.1.1.1 and port 8011) and not host 172.16.1.201 and not host 172.16.1.202",
                             bpf_filter);
    free(bpf_filter);
}

// Cross-task: when two tasks share a capture interface, each task's BPF must
// exclude every output host across all tasks, not just its own.
void test_bpf_filter_exclude_task_output_hosts_5(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_two_tasks_vxlan, &err);
    TEST_ASSERT_NOT_NULL(config);

    char errbuf[ERROR_BUFFER_SIZE];
    char *bpf_filter = bpf_filter_exclude_task_output_hosts("", config->tasks_cfg, errbuf);
    TEST_ASSERT_NOT_NULL(bpf_filter);
    TEST_ASSERT_EQUAL_STRING("not host 172.16.206.40 and not host 172.16.206.24", bpf_filter);
    free(bpf_filter);
}

// Cross-task: duplicate output hosts across tasks must be emitted only once.
void test_bpf_filter_exclude_task_output_hosts_6(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_two_tasks_shared_host, &err);
    TEST_ASSERT_NOT_NULL(config);

    char errbuf[ERROR_BUFFER_SIZE];
    char *bpf_filter = bpf_filter_exclude_task_output_hosts("", config->tasks_cfg, errbuf);
    TEST_ASSERT_NOT_NULL(bpf_filter);
    TEST_ASSERT_EQUAL_STRING("not host 172.16.1.201", bpf_filter);
    free(bpf_filter);
}

int mock_get_if_ip_addr(const char *ifname, ip_addr_t *addr, char *errbuf)
{
    if (strcmp(ifname, "eth0") == 0)
    {
        addr->type = IP_TYPE_IPv4;
        inet_pton(AF_INET, "172.16.1.1", &addr->data.v4);
        return 0;
    }
    error_format(errbuf, "interface '%s' not exists", ifname);
    return -1;
}

void test_bpf_filter_replace_nic(void)
{
    char *result;
    char errbuf[ERROR_BUFFER_SIZE];

    result = bpf_filter_replace_nic("src host nic.eth0 and port 80", mock_get_if_ip_addr, errbuf);
    TEST_ASSERT_EQUAL_STRING("src host 172.16.1.1 and port 80", result);
    free(result);

    result = bpf_filter_replace_nic("src host 10.1.1.1 and port 80", mock_get_if_ip_addr, errbuf);
    TEST_ASSERT_EQUAL_STRING("src host 10.1.1.1 and port 80", result);
    free(result);
}

// A 39-character IPv6 address replaces an 8-character token, so the output outgrows 2 * strlen(bpf).
int mock_get_if_ipv6_addr(const char *ifname, ip_addr_t *addr, char *errbuf)
{
    if (strcmp(ifname, "v6if") == 0)
    {
        addr->type = IP_TYPE_IPv6;
        inet_pton(AF_INET6, "2001:db8:1234:5678:9abc:def0:1234:5678", &addr->data.v6);
        return 0;
    }
    return mock_get_if_ip_addr(ifname, addr, errbuf);
}

void test_bpf_filter_replace_nic_address_longer_than_token(void)
{
    char errbuf[ERROR_BUFFER_SIZE];
    // Plain text after the second address runs past the buffer before the third token is reached.
    char *result =
        bpf_filter_replace_nic("host nic.v6if and host nic.v6if and host nic.v6if", mock_get_if_ipv6_addr, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(result, errbuf);
    TEST_ASSERT_EQUAL_STRING(
        "host 2001:db8:1234:5678:9abc:def0:1234:5678 and host 2001:db8:1234:5678:9abc:def0:1234:5678 "
        "and host 2001:db8:1234:5678:9abc:def0:1234:5678",
        result);
    free(result);

    result = bpf_filter_replace_nic("nic.v6if", mock_get_if_ipv6_addr, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(result, errbuf);
    TEST_ASSERT_EQUAL_STRING("2001:db8:1234:5678:9abc:def0:1234:5678", result);
    free(result);
}

void test_bpf_filter_replace_nic_token_ends_at_paren(void)
{
    char errbuf[ERROR_BUFFER_SIZE];
    char *result = bpf_filter_replace_nic("(host nic.eth0)", mock_get_if_ip_addr, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(result, errbuf);
    TEST_ASSERT_EQUAL_STRING("(host 172.16.1.1)", result);
    free(result);

    result = bpf_filter_replace_nic("(src host nic.eth0 or dst host nic.eth0)and port 80", mock_get_if_ip_addr, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(result, errbuf);
    TEST_ASSERT_EQUAL_STRING("(src host 172.16.1.1 or dst host 172.16.1.1)and port 80", result);
    free(result);
}

void test_bpf_filter_replace_nic_only_whole_tokens(void)
{
    char errbuf[ERROR_BUFFER_SIZE];
    char *result = bpf_filter_replace_nic("host panic.example.com and port 80", mock_get_if_ip_addr, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(result, errbuf);
    TEST_ASSERT_EQUAL_STRING("host panic.example.com and port 80", result);
    free(result);
}

void test_bpf_filter_replace_nic_unknown_interface(void)
{
    char errbuf[ERROR_BUFFER_SIZE];
    TEST_ASSERT_NULL(bpf_filter_replace_nic("host nic.eth9", mock_get_if_ip_addr, errbuf));
    TEST_ASSERT_EQUAL_STRING("no ip found for interface eth9", errbuf);

    TEST_ASSERT_NULL(bpf_filter_replace_nic("host nic. and port 80", mock_get_if_ip_addr, errbuf));
    TEST_ASSERT_NULL(
        bpf_filter_replace_nic("host nic.an-interface-name-far-longer-than-if-namesize", mock_get_if_ip_addr, errbuf));
}

void test_parse_zmq_heartbeat_ms_explicit(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_zmq_heartbeat, &err);
    TEST_ASSERT_NOT_NULL(config);
    OutputConfig *zmq_output = config->tasks_cfg->tasks[0]->outputs[0];
    TEST_ASSERT_EQUAL_INT(2000, zmq_output->config.zmq.heartbeat_ms);
    free_config(config);
}

void test_parse_zmq_heartbeat_ms_default(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_zmq_heartbeat_default, &err);
    TEST_ASSERT_NOT_NULL(config);
    OutputConfig *zmq_output = config->tasks_cfg->tasks[0]->outputs[0];
    TEST_ASSERT_EQUAL_INT(0, zmq_output->config.zmq.heartbeat_ms);
    free_config(config);
}

void test_parse_zmq_heartbeat_ms_disabled(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_zmq_heartbeat_disabled, &err);
    TEST_ASSERT_NOT_NULL(config);
    OutputConfig *zmq_output = config->tasks_cfg->tasks[0]->outputs[0];
    TEST_ASSERT_EQUAL_INT(0, zmq_output->config.zmq.heartbeat_ms);
    free_config(config);
}

void test_zmq_heartbeat_packet_generation(void)
{
    output_stats_t stats;
    memset(&stats, 0, sizeof(stats));

    char errbuf[256];
    zmq_options_t opts = {
        .host = "127.0.0.1",
        .port = 15555,
        .hwm = 100,
        .service_tag = 42,
        .uuid = "550e8400-e29b-41d4-a716-446655440000",
        .rate_limit_mbps = 0,
        .slice = 0,
        .heartbeat_ms = 1000,
    };

    zmq_output_t *output = zmq_output_new(opts, &stats, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);
    TEST_ASSERT_EQUAL_INT(1000, output->heartbeat_ms);

    // Simulate heartbeat: set last_pkt_tv to 2 seconds ago
    struct timeval now_tv;
    gettimeofday(&now_tv, NULL);
    output->last_pkt_tv.tv_sec = now_tv.tv_sec - 2;
    output->last_pkt_tv.tv_usec = now_tv.tv_usec;

    // Call heartbeat - should generate a heartbeat packet
    output_heartbeat((output_base_t *)output, now_tv.tv_sec);

    // The heartbeat is queued on the not-yet-connected pipe, so the send succeeds
    TEST_ASSERT_EQUAL_UINT64(1, stats.heartbeat_packets.packets);

    // A heartbeat is not a captured packet: it is neither forwarded nor dropped
    TEST_ASSERT_EQUAL_UINT64(0, stats.fwd_packets.packets);
    TEST_ASSERT_EQUAL_UINT64(0, stats.fwd_bytes.bytes);
    TEST_ASSERT_EQUAL_UINT64(0, stats.error_drop_packets.packets);

    zmq_output_destroy((output_base_t *)output);
}

void test_zmq_heartbeat_not_generated_when_disabled(void)
{
    output_stats_t stats;
    memset(&stats, 0, sizeof(stats));

    char errbuf[256];
    zmq_options_t opts = {
        .host = "127.0.0.1",
        .port = 15556,
        .hwm = 100,
        .service_tag = 42,
        .uuid = "550e8400-e29b-41d4-a716-446655440000",
        .rate_limit_mbps = 0,
        .slice = 0,
        .heartbeat_ms = 0,
    };

    zmq_output_t *output = zmq_output_new(opts, &stats, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    // Set last_pkt_tv to 10 seconds ago
    struct timeval now_tv;
    gettimeofday(&now_tv, NULL);
    output->last_pkt_tv.tv_sec = now_tv.tv_sec - 10;

    // Call heartbeat - should NOT generate a heartbeat packet (disabled)
    output_heartbeat((output_base_t *)output, now_tv.tv_sec);

    TEST_ASSERT_EQUAL_UINT64(0, stats.heartbeat_packets.packets);

    zmq_output_destroy((output_base_t *)output);
}

void test_zmq_heartbeat_not_generated_when_recent_packet(void)
{
    output_stats_t stats;
    memset(&stats, 0, sizeof(stats));

    char errbuf[256];
    zmq_options_t opts = {
        .host = "127.0.0.1",
        .port = 15557,
        .hwm = 100,
        .service_tag = 42,
        .uuid = "550e8400-e29b-41d4-a716-446655440000",
        .rate_limit_mbps = 0,
        .slice = 0,
        .heartbeat_ms = 1000,
    };

    zmq_output_t *output = zmq_output_new(opts, &stats, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    // last_pkt_tv was just set by zmq_output_new (gettimeofday), so elapsed < 1000ms
    struct timeval now_tv;
    gettimeofday(&now_tv, NULL);

    // Call heartbeat - should NOT generate (interval not exceeded)
    output_heartbeat((output_base_t *)output, now_tv.tv_sec);

    TEST_ASSERT_EQUAL_UINT64(0, stats.heartbeat_packets.packets);

    zmq_output_destroy((output_base_t *)output);
}

#if OS_LINUX
void test_cpu_set_parse(void)
{
    cpu_set_t mask;
    TEST_ASSERT_EQUAL(0, cpu_set_parse(&mask, "1"));
    TEST_ASSERT_EQUAL(1, CPU_COUNT(&mask));
    TEST_ASSERT_EQUAL(0, cpu_set_parse(&mask, "0,1,2"));
    TEST_ASSERT_EQUAL(3, CPU_COUNT(&mask));
    TEST_ASSERT_EQUAL(0, cpu_set_parse(&mask, "0-1"));
    TEST_ASSERT_EQUAL(2, CPU_COUNT(&mask));
    TEST_ASSERT_EQUAL(0, cpu_set_parse(&mask, "0-1,2"));
    TEST_ASSERT_EQUAL(3, CPU_COUNT(&mask));
    TEST_ASSERT_EQUAL(0, cpu_set_parse(&mask, "2,0-1"));
    TEST_ASSERT_EQUAL(3, CPU_COUNT(&mask));

    // edge cases: invalid inputs should return -1
    TEST_ASSERT_EQUAL(-1, cpu_set_parse(&mask, ","));
    TEST_ASSERT_EQUAL(-1, cpu_set_parse(&mask, ",1"));
    TEST_ASSERT_EQUAL(-1, cpu_set_parse(&mask, "1-,2"));
    TEST_ASSERT_EQUAL(-1, cpu_set_parse(&mask, "1,,2"));
    TEST_ASSERT_EQUAL(-1, cpu_set_parse(&mask, "-1"));
    TEST_ASSERT_EQUAL(-1, cpu_set_parse(&mask, "abc"));
    TEST_ASSERT_EQUAL(-1, cpu_set_parse(&mask, "3-1"));

    // edge case: trailing comma is tolerated (strtoul on '\0' yields end==pos)
    // after the fix, trailing comma now correctly returns -1
    TEST_ASSERT_EQUAL(-1, cpu_set_parse(&mask, "1,"));

    // edge case: empty string should return 0 with empty mask
    TEST_ASSERT_EQUAL(0, cpu_set_parse(&mask, ""));
    TEST_ASSERT_EQUAL(0, CPU_COUNT(&mask));
}

static int socket_pmtudisc(int fd)
{
    int val = -1;
    socklen_t len = sizeof(val);
    TEST_ASSERT_EQUAL(0, getsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &val, &len));
    return val;
}

void test_gre_pmtudisc_applied(void)
{
    const int modes[] = {IP_PMTUDISC_DONT, IP_PMTUDISC_DO};
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
    {
        output_stats_t stats;
        memset(&stats, 0, sizeof(stats));
        char errbuf[ERROR_BUFFER_SIZE];
        gre_options_t opts = {
            .host = "127.0.0.1",
            .pmtudisc = modes[i],
        };

        gre_output_t *output = gre_output_new(opts, &stats, errbuf);
        // GRE uses a raw socket, which requires CAP_NET_RAW
        if (!output && strstr(errbuf, strerror(EPERM)))
            TEST_IGNORE_MESSAGE("raw socket not permitted; run as root to cover GRE pmtudisc");
        TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

        TEST_ASSERT_EQUAL(modes[i], socket_pmtudisc(output->socket_fd));
        gre_output_destroy((output_base_t *)output);
    }
}

void test_vxlan_pmtudisc_applied(void)
{
    const int modes[] = {IP_PMTUDISC_DONT, IP_PMTUDISC_DO};
    for (size_t i = 0; i < sizeof(modes) / sizeof(modes[0]); i++)
    {
        output_stats_t stats;
        memset(&stats, 0, sizeof(stats));
        char errbuf[ERROR_BUFFER_SIZE];
        vxlan_options_t opts = {
            .host = "127.0.0.1",
            .port = 4789,
            .vni_version = 1,
            .vni = 1,
            .pmtudisc = modes[i],
        };

        vxlan_output_t *output = vxlan_output_new(opts, &stats, errbuf);
        TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

        TEST_ASSERT_EQUAL(modes[i], socket_pmtudisc(output->socket_fd));
        vxlan_output_destroy((output_base_t *)output);
    }
}
#endif

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_parse_config_data_for_libpcap_gre_vxlan);

    RUN_TEST(test_bpf_filter_replace_nic);
    RUN_TEST(test_bpf_filter_replace_nic_address_longer_than_token);
    RUN_TEST(test_bpf_filter_replace_nic_token_ends_at_paren);
    RUN_TEST(test_bpf_filter_replace_nic_only_whole_tokens);
    RUN_TEST(test_bpf_filter_replace_nic_unknown_interface);

    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_1);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_2);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_3);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_4);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_5);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_6);

    RUN_TEST(test_parse_zmq_heartbeat_ms_explicit);
    RUN_TEST(test_parse_zmq_heartbeat_ms_default);
    RUN_TEST(test_parse_zmq_heartbeat_ms_disabled);

    RUN_TEST(test_zmq_heartbeat_packet_generation);
    RUN_TEST(test_zmq_heartbeat_not_generated_when_disabled);
    RUN_TEST(test_zmq_heartbeat_not_generated_when_recent_packet);

#if OS_LINUX
    RUN_TEST(test_cpu_set_parse);
    RUN_TEST(test_gre_pmtudisc_applied);
    RUN_TEST(test_vxlan_pmtudisc_applied);
#endif

    return UNITY_END();
}