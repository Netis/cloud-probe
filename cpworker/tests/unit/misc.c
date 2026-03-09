#include "affinity.h"

#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "unity/src/unity.h"

#include "bpf_util.h"
#include "config.h"
#include "errorf.h"
#include "ip.h"
#include "output_zmq.h"
#include "req_pattern.h"

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
    "4789, \"vni1\": 2147483648, \"bind_device\": \"eth1\"}}]}]}";

void test_parse_config_data_for_libpcap_gre_vxlan(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_gre_vxlan, &err);
    TEST_ASSERT_NOT_NULL(config);

    OutputConfig *vxlan_output = config->tasks_cfg->tasks[0]->outputs[1];
    TEST_ASSERT_EQUAL_UINT32(2147483648, vxlan_output->config.vxlan.vni);
}

void test_bpf_filter_exclude_task_output_hosts_1(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(config_libpcap_gre, &err);
    TEST_ASSERT_NOT_NULL(config);

    char errbuf[ERROR_BUFFER_SIZE];
    char *bpf_filter = bpf_filter_exclude_task_output_hosts("", config->tasks_cfg->tasks[0], errbuf);
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
    char *bpf_filter =
        bpf_filter_exclude_task_output_hosts("host 10.1.1.1 and port 8011", config->tasks_cfg->tasks[0], errbuf);
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
    char *bpf_filter = bpf_filter_exclude_task_output_hosts("", config->tasks_cfg->tasks[0], errbuf);
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
    char *bpf_filter =
        bpf_filter_exclude_task_output_hosts("host 10.1.1.1 and port 8011", config->tasks_cfg->tasks[0], errbuf);
    TEST_ASSERT_NOT_NULL(bpf_filter);
    TEST_ASSERT_EQUAL_STRING("(host 10.1.1.1 and port 8011) and not host 172.16.1.201 and not host 172.16.1.202",
                             bpf_filter);
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

void test_req_pattern_custom_multi_host_and_one_port(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "(host 172.16.1.1 or host 172.16.1.2) and port 8011",
                                              mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip1;
    ip1.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "172.16.1.1", &ip1.data.v4);

    ip_addr_t ip2;
    ip2.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "172.16.1.2", &ip2.data.v4);

    ip_addr_t ip3;
    ip3.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "172.16.1.3", &ip3.data.v4);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 8011));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 8012));
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 8011));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 8012));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip3, 8011));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_one_host_and_multi_port(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret =
        req_pattern_custom_matcher_init(&matcher, "host 172.16.1.1 and (port 8011 or port 8012)", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip1;
    ip1.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "172.16.1.1", &ip1.data.v4);

    ip_addr_t ip2;
    ip2.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "172.16.1.2", &ip2.data.v4);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 8011));
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 8012));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 8013));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 8011));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 8012));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_multi_host_and_multi_port(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "(host 172.16.1.1 or host 172.16.1.2) and port 8011",
                                              mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip1;
    ip1.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "172.16.1.1", &ip1.data.v4);

    ip_addr_t ip2;
    ip2.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "172.16.1.2", &ip2.data.v4);

    ip_addr_t ip3;
    ip3.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "172.16.1.3", &ip3.data.v4);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 8011));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 8012));
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 8011));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 8012));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip3, 8011));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_host_ifname(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, " host nic.eth0 and port 8011", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip1;
    ip1.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "172.16.1.1", &ip1.data.v4);

    ip_addr_t ip2;
    ip2.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "172.16.1.2", &ip2.data.v4);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 8011));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 8012));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 8011));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 8012));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_invalid(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "not host nic.eth0", mock_get_if_ip_addr);

    TEST_ASSERT_EQUAL_INT(-1, ret);
}

void test_req_pattern_custom_simple_host_only(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "host 10.0.0.1", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip_match;
    ip_match.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.1", &ip_match.data.v4);

    ip_addr_t ip_no_match;
    ip_no_match.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.2", &ip_no_match.data.v4);

    // host-only pattern: any port should match as long as host matches
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip_match, 0));
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip_match, 12345));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip_no_match, 0));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_simple_port_only(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "port 443", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip;
    ip.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "1.2.3.4", &ip.data.v4);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip, 443));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip, 80));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip, 0));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_or_hosts(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "host 10.0.0.1 or host 10.0.0.2", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip1, ip2, ip3;
    ip1.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.1", &ip1.data.v4);
    ip2.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.2", &ip2.data.v4);
    ip3.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.3", &ip3.data.v4);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 0));
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 0));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip3, 0));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_or_ports(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "port 80 or port 443", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip;
    ip.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "1.2.3.4", &ip.data.v4);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip, 80));
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip, 443));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip, 8080));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_nested_parens(void)
{
    // ((host 10.0.0.1 or host 10.0.0.2) and port 80) or port 443
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "((host 10.0.0.1 or host 10.0.0.2) and port 80) or port 443",
                                              mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip1, ip2, ip3;
    ip1.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.1", &ip1.data.v4);
    ip2.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.2", &ip2.data.v4);
    ip3.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.3", &ip3.data.v4);

    // ip1 + port 80 => matches left side
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 80));
    // ip2 + port 80 => matches left side
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 80));
    // ip1 + port 443 => matches right side (or port 443)
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 443));
    // ip3 + port 443 => matches right side (or port 443)
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip3, 443));
    // ip1 + port 8080 => no match
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 8080));
    // ip3 + port 80 => no match (ip3 not in host list, port 80 not 443)
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip3, 80));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_ipv6(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "host ::1 and port 8080", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip_v6;
    ip_v6.type = IP_TYPE_IPv6;
    inet_pton(AF_INET6, "::1", &ip_v6.data.v6);

    ip_addr_t ip_v6_other;
    ip_v6_other.type = IP_TYPE_IPv6;
    inet_pton(AF_INET6, "::2", &ip_v6_other.data.v6);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip_v6, 8080));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip_v6, 80));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip_v6_other, 8080));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_ipv6_full(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "host 2001:db8::1 and port 443", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip;
    ip.type = IP_TYPE_IPv6;
    inet_pton(AF_INET6, "2001:db8::1", &ip.data.v6);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip, 443));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip, 80));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_invalid_port_non_numeric(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "port abc", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(-1, ret);
}

void test_req_pattern_invalid_port_out_of_range(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "port 99999", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(-1, ret);
}

void test_req_pattern_invalid_port_negative(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "port -1", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(-1, ret);
}

void test_req_pattern_invalid_host(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "host not_an_ip", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(-1, ret);
}

void test_req_pattern_invalid_nic_not_exist(void)
{
    req_pattern_custom_matcher_t matcher;
    // mock only knows "eth0", so "eth999" should fail
    int ret = req_pattern_custom_matcher_init(&matcher, "host nic.eth999", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(-1, ret);
}

void test_req_pattern_invalid_empty_pattern(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(-1, ret);
}

void test_req_pattern_invalid_unmatched_paren(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "(host 10.0.0.1 and port 80", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(-1, ret);
}

void test_req_pattern_invalid_missing_value(void)
{
    req_pattern_custom_matcher_t matcher;
    // "host and port 80" — host missing its value
    int ret = req_pattern_custom_matcher_init(&matcher, "host and port 80", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(-1, ret);
}

void test_req_pattern_custom_port_zero(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "port 0", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip;
    ip.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "1.2.3.4", &ip.data.v4);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip, 0));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip, 1));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_port_65535(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "port 65535", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip;
    ip.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "1.2.3.4", &ip.data.v4);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip, 65535));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip, 65534));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_and_precedence_over_or(void)
{
    // "host 10.0.0.1 or host 10.0.0.2 and port 80"
    // should parse as: host 10.0.0.1 or (host 10.0.0.2 and port 80)
    req_pattern_custom_matcher_t matcher;
    int ret =
        req_pattern_custom_matcher_init(&matcher, "host 10.0.0.1 or host 10.0.0.2 and port 80", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip1, ip2, ip3;
    ip1.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.1", &ip1.data.v4);
    ip2.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.2", &ip2.data.v4);
    ip3.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.3", &ip3.data.v4);

    // ip1 matches regardless of port (left side of OR)
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 0));
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip1, 9999));
    // ip2 only matches with port 80 (right side: host 10.0.0.2 AND port 80)
    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 80));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip2, 81));
    // ip3 never matches
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip3, 80));

    req_pattern_custom_matcher_destroy(&matcher);
}

void test_req_pattern_custom_extra_whitespace(void)
{
    req_pattern_custom_matcher_t matcher;
    int ret = req_pattern_custom_matcher_init(&matcher, "  host   10.0.0.1   and   port   80  ", mock_get_if_ip_addr);
    TEST_ASSERT_EQUAL_INT(0, ret);

    ip_addr_t ip;
    ip.type = IP_TYPE_IPv4;
    inet_pton(AF_INET, "10.0.0.1", &ip.data.v4);

    TEST_ASSERT_TRUE(req_pattern_custom_match_by_ipport(&matcher, &ip, 80));
    TEST_ASSERT_FALSE(req_pattern_custom_match_by_ipport(&matcher, &ip, 81));

    req_pattern_custom_matcher_destroy(&matcher);
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

    // Verify heartbeat stats were incremented
    TEST_ASSERT_EQUAL_UINT64(1, stats.heartbeat_packets.packets);

    // The ZMQ send may fail (no receiver) but the packet was still generated
    // Either forwarded or error-dropped (depends on ZMQ connection state)
    uint64_t total = stats.fwd_packets.packets + stats.error_drop_packets.packets;
    TEST_ASSERT_EQUAL_UINT64(1, total);

    zmq_output_destory((output_base_t *)output);
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

    zmq_output_destory((output_base_t *)output);
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

    zmq_output_destory((output_base_t *)output);
}

#if defined(OS_LINUX)
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
#endif

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_parse_config_data_for_libpcap_gre_vxlan);

    RUN_TEST(test_bpf_filter_replace_nic);

    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_1);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_2);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_3);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_4);

    RUN_TEST(test_req_pattern_custom_multi_host_and_one_port);
    RUN_TEST(test_req_pattern_custom_one_host_and_multi_port);
    RUN_TEST(test_req_pattern_custom_multi_host_and_multi_port);
    RUN_TEST(test_req_pattern_custom_host_ifname);
    RUN_TEST(test_req_pattern_invalid);

    RUN_TEST(test_req_pattern_custom_simple_host_only);
    RUN_TEST(test_req_pattern_custom_simple_port_only);
    RUN_TEST(test_req_pattern_custom_or_hosts);
    RUN_TEST(test_req_pattern_custom_or_ports);
    RUN_TEST(test_req_pattern_custom_nested_parens);
    RUN_TEST(test_req_pattern_custom_ipv6);
    RUN_TEST(test_req_pattern_custom_ipv6_full);
    RUN_TEST(test_req_pattern_invalid_port_non_numeric);
    RUN_TEST(test_req_pattern_invalid_port_out_of_range);
    RUN_TEST(test_req_pattern_invalid_port_negative);
    RUN_TEST(test_req_pattern_invalid_host);
    RUN_TEST(test_req_pattern_invalid_nic_not_exist);
    RUN_TEST(test_req_pattern_invalid_empty_pattern);
    RUN_TEST(test_req_pattern_invalid_unmatched_paren);
    RUN_TEST(test_req_pattern_invalid_missing_value);
    RUN_TEST(test_req_pattern_custom_port_zero);
    RUN_TEST(test_req_pattern_custom_port_65535);
    RUN_TEST(test_req_pattern_custom_and_precedence_over_or);
    RUN_TEST(test_req_pattern_custom_extra_whitespace);

    RUN_TEST(test_parse_zmq_heartbeat_ms_explicit);
    RUN_TEST(test_parse_zmq_heartbeat_ms_default);
    RUN_TEST(test_parse_zmq_heartbeat_ms_disabled);

    RUN_TEST(test_zmq_heartbeat_packet_generation);
    RUN_TEST(test_zmq_heartbeat_not_generated_when_disabled);
    RUN_TEST(test_zmq_heartbeat_not_generated_when_recent_packet);

#if defined(OS_LINUX)
    RUN_TEST(test_cpu_set_parse);
#endif

    return UNITY_END();
}