#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

#include "unity/src/unity.h"

#include "errorf.h"
#include "ip.h"
#include "req_pattern.h"

void setUp(void) {}

void tearDown(void) {}

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

void test_req_pattern_custom_multi_host_and_one_port(void)
{
    req_pattern_custom_matcher_t matcher;
    req_pattern_custom_matcher_init(&matcher, "(host 172.16.1.1 or host 172.16.1.2) and port 8011",
                                    mock_get_if_ip_addr);

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
    req_pattern_custom_matcher_init(&matcher, "host 172.16.1.1 and (port 8011 or port 8012)", mock_get_if_ip_addr);

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
    req_pattern_custom_matcher_init(&matcher, "(host 172.16.1.1 or host 172.16.1.2) and port 8011",
                                    mock_get_if_ip_addr);

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
    req_pattern_custom_matcher_init(&matcher, " host nic.eth0 and port 8011", mock_get_if_ip_addr);

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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_req_pattern_custom_multi_host_and_one_port);
    RUN_TEST(test_req_pattern_custom_one_host_and_multi_port);
    RUN_TEST(test_req_pattern_custom_multi_host_and_multi_port);
    return UNITY_END();
}