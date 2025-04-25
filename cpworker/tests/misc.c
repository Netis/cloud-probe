#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#include "unity/src/unity.h"

#include "bpf_util.h"
#include "errorf.h"
#include "ip.h"

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

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_bpf_filter_replace_nic);
    return UNITY_END();
}