#include <arpa/inet.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "unity/src/unity.h"

#include "bpf_util.h"
#include "config.h"
#include "errorf.h"
#include "ip.h"
#include "req_pattern.h"

void setUp(void) {}

void tearDown(void) {}

const char *config_libpcap_gre =
    "{\"tasks\": [{\"req_pattern\": {\"type\": \"auto\"}, \"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
    "{\"interface\": \"eth0\", \"snaplen\": 2048, \"buffer_size_mb\": 256}}, \"outputs\": [{\"type\": \"gre\", "
    "\"rate_limit_mbps\": 10, \"gre\": {\"host\": \"172.16.1.201\", \"bind_device\": \"eth1\"}}]}]}";

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

    return UNITY_END();
}