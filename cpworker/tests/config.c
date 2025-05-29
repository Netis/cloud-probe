#include <stdlib.h>

#include "unity/src/unity.h"

#include "config.h"
#include "errorf.h"

void setUp(void) {}

void tearDown(void) {}

const char *libpcap_gre =
    "{\"tasks\": [{\"interface\": \"eth0\", \"snaplen\": 2048, \"req_pattern\": {\"type\": \"auto\"}, \"capturer\": "
    "{\"type\": \"libpcap\", \"libpcap\": {\"buffer_size_mb\": 256}}, \"outputs\": [{\"type\": \"gre\", "
    "\"rate_limit_mbps\": 10, \"gre\": {\"host\": \"172.16.1.201\", \"bind_device\": \"eth1\"}}]}]}";

const char *libpcap_gre_vxlan =
    "{\"tasks\": [{\"interface\": \"eth0\", \"snaplen\": 2048, \"req_pattern\": {\"type\": \"auto\"}, \"capturer\": "
    "{\"type\": \"libpcap\", \"libpcap\": {\"buffer_size_mb\": 256}}, \"outputs\": [{\"type\": \"gre\", "
    "\"rate_limit_mbps\": 10, \"gre\": {\"host\": \"172.16.1.201\", \"bind_device\": \"eth1\"}}, {\"type\": \"vxlan\", "
    "\"rate_limit_mbps\": 10, \"vxlan\": {\"host\": \"172.16.1.202\", \"port\": 4789, \"vni1\": 1, \"bind_device\": "
    "\"eth1\"}}]}]}";

void test_bpf_filter_exclude_task_output_hosts_1(void)
{
    cJSONParseError err;
    Config *config = parse_config_data(libpcap_gre, &err);
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
    Config *config = parse_config_data(libpcap_gre, &err);
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
    Config *config = parse_config_data(libpcap_gre_vxlan, &err);
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
    Config *config = parse_config_data(libpcap_gre_vxlan, &err);
    TEST_ASSERT_NOT_NULL(config);

    char errbuf[ERROR_BUFFER_SIZE];
    char *bpf_filter =
        bpf_filter_exclude_task_output_hosts("host 10.1.1.1 and port 8011", config->tasks_cfg->tasks[0], errbuf);
    TEST_ASSERT_NOT_NULL(bpf_filter);
    TEST_ASSERT_EQUAL_STRING("(host 10.1.1.1 and port 8011) and not host 172.16.1.201 and not host 172.16.1.202",
                             bpf_filter);
    free(bpf_filter);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_1);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_2);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_3);
    RUN_TEST(test_bpf_filter_exclude_task_output_hosts_4);
    return UNITY_END();
}