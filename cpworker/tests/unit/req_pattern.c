#include <arpa/inet.h>
#include <net/ethernet.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <pcap/pcap.h>

#include "unity/src/unity.h"

#include "errorf.h"
#include "pkt_dir.h"
#include "req_pattern.h"
#include "vlan.h"

#define CLIENT_PORT 40000
#define SERVER_PORT 80
#define VXLAN_PORT 4789

static req_pattern_t pattern;
static uint8_t frame[2048];

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

void setUp(void)
{
    memset(frame, 0, sizeof(frame));
    pattern.type = REQ_PATTERN_TYPE_CUSTOM;
    pattern.matcher.custom.node = NULL;
}

void tearDown(void) { req_pattern_custom_matcher_destroy(&pattern.matcher.custom); }

/*
 * Expression grammar and matching: req_pattern_custom_matcher_init / req_pattern_custom_match_by_ipport
 */

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

// Ports are plain decimal: no sign, and no leading zero (BPF would read "010" as octal 8).
void test_req_pattern_custom_port_rejects_sign_and_leading_zero(void)
{
    const char *bad[] = {"port -0", "port +80", "port 010", "port 00", "port 080"};
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++)
    {
        req_pattern_custom_matcher_t matcher;
        TEST_ASSERT_EQUAL_INT_MESSAGE(-1, req_pattern_custom_matcher_init(&matcher, bad[i], mock_get_if_ip_addr),
                                      bad[i]);
    }
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

/*
 * Direction of captured frames: req_pattern_judge_pkt_direction with the pattern "port 80"
 */

static size_t put_u16(uint8_t *p, uint16_t v)
{
    p[0] = v >> 8;
    p[1] = v & 0xff;
    return 2;
}

// Writes the MAC addresses and the first EtherType; returns the offset after them.
static size_t put_eth(uint8_t *p, uint16_t ether_type)
{
    memset(p, 0x11, 12);
    return 12 + put_u16(p + 12, ether_type);
}

// Writes one 4-byte tag (TCI + next EtherType); the tag's own TPID is the preceding EtherType.
static size_t put_tag(uint8_t *p, uint16_t vid, uint16_t next_type)
{
    return put_u16(p, vid) + put_u16(p + 2, next_type);
}

static size_t put_tcp_ports(uint8_t *p, uint16_t sport, uint16_t dport)
{
    put_u16(p, sport);
    put_u16(p + 2, dport);
    p[12] = 5 << 4;
    return 20;
}

static size_t put_ipv4_tcp(uint8_t *p, uint16_t sport, uint16_t dport)
{
    p[0] = 0x45;
    put_u16(p + 2, 40);
    p[8] = 64;
    p[9] = IPPROTO_TCP;
    inet_pton(AF_INET, "10.0.0.1", p + 12);
    inet_pton(AF_INET, "10.0.0.2", p + 16);
    return 20 + put_tcp_ports(p + 20, sport, dport);
}

static size_t put_ipv6_tcp(uint8_t *p, uint16_t sport, uint16_t dport)
{
    p[0] = 0x60;
    put_u16(p + 4, 20);
    p[6] = IPPROTO_TCP;
    p[7] = 64;
    inet_pton(AF_INET6, "2001:db8::1", p + 8);
    inet_pton(AF_INET6, "2001:db8::2", p + 24);
    return 40 + put_tcp_ports(p + 40, sport, dport);
}

// Ethernet, a tag stack whose TPIDs are tpids[0..ntags-1], then IPv4/TCP.
static size_t build_tagged_ipv4_tcp(uint8_t *p, const uint16_t *tpids, int ntags, uint16_t sport, uint16_t dport)
{
    size_t off = put_eth(p, ntags > 0 ? tpids[0] : ETHERTYPE_IP);
    for (int i = 0; i < ntags; i++)
        off += put_tag(p + off, 100 + i, i + 1 < ntags ? tpids[i + 1] : ETHERTYPE_IP);
    return off + put_ipv4_tcp(p + off, sport, dport);
}

static int judge(const uint8_t *data, size_t caplen)
{
    if (!pattern.matcher.custom.node)
        TEST_ASSERT_EQUAL_INT(0,
                              req_pattern_custom_matcher_init(&pattern.matcher.custom, "port 80", mock_get_if_ip_addr));

    struct pcap_pkthdr hdr;
    memset(&hdr, 0, sizeof(hdr));
    hdr.caplen = caplen;
    hdr.len = caplen;
    return req_pattern_judge_pkt_direction(&pattern, &hdr, data);
}

// A request (to port 80) is judged INCOMING and its reply (from port 80) OUTGOING.
static void assert_both_directions(const uint16_t *tpids, int ntags)
{
    size_t len = build_tagged_ipv4_tcp(frame, tpids, ntags, CLIENT_PORT, SERVER_PORT);
    TEST_ASSERT_EQUAL_INT(PKT_DIR_INCOMING, judge(frame, len));

    len = build_tagged_ipv4_tcp(frame, tpids, ntags, SERVER_PORT, CLIENT_PORT);
    TEST_ASSERT_EQUAL_INT(PKT_DIR_OUTGOING, judge(frame, len));
}

void test_untagged(void) { assert_both_directions(NULL, 0); }

void test_single_8021q_tag(void)
{
    const uint16_t tpids[] = {ETHERTYPE_VLAN};
    assert_both_directions(tpids, 1);
}

void test_double_8021q_tags(void)
{
    const uint16_t tpids[] = {ETHERTYPE_VLAN, ETHERTYPE_VLAN};
    assert_both_directions(tpids, 2);
}

void test_qinq_8021ad_outer_tag(void)
{
    const uint16_t tpids[] = {ETHERTYPE_DOT1AD, ETHERTYPE_VLAN};
    assert_both_directions(tpids, 2);
}

void test_qinq_9100_outer_tag(void)
{
    const uint16_t tpids[] = {ETHERTYPE_VLAN_9100, ETHERTYPE_VLAN};
    assert_both_directions(tpids, 2);
}

void test_qinq_9200_outer_tag(void)
{
    const uint16_t tpids[] = {ETHERTYPE_VLAN_9200, ETHERTYPE_VLAN};
    assert_both_directions(tpids, 2);
}

void test_single_8021ad_tag(void)
{
    const uint16_t tpids[] = {ETHERTYPE_DOT1AD};
    assert_both_directions(tpids, 1);
}

void test_mixed_tag_stack(void)
{
    const uint16_t tpids[] = {ETHERTYPE_DOT1AD, ETHERTYPE_VLAN_9100, ETHERTYPE_VLAN_9200, ETHERTYPE_VLAN};
    assert_both_directions(tpids, 4);
}

void test_qinq_ipv6(void)
{
    size_t off = put_eth(frame, ETHERTYPE_DOT1AD);
    off += put_tag(frame + off, 100, ETHERTYPE_VLAN);
    off += put_tag(frame + off, 200, ETHERTYPE_IPV6);
    size_t len = off + put_ipv6_tcp(frame + off, CLIENT_PORT, SERVER_PORT);
    TEST_ASSERT_EQUAL_INT(PKT_DIR_INCOMING, judge(frame, len));
}

// The inner frame of a VXLAN packet goes through the same Ethernet parser.
void test_qinq_inside_vxlan(void)
{
    size_t off = put_eth(frame, ETHERTYPE_IP);
    uint8_t *ip = frame + off;
    ip[0] = 0x45;
    ip[9] = IPPROTO_UDP;
    inet_pton(AF_INET, "192.168.0.1", ip + 12);
    inet_pton(AF_INET, "192.168.0.2", ip + 16);
    off += 20;
    put_u16(frame + off, 50000);
    put_u16(frame + off + 2, VXLAN_PORT);
    off += 8;
    frame[off] = 0x08; // VXLAN flags: VNI present
    off += 8;

    const uint16_t tpids[] = {ETHERTYPE_DOT1AD, ETHERTYPE_VLAN};
    size_t len = off + build_tagged_ipv4_tcp(frame + off, tpids, 2, CLIENT_PORT, SERVER_PORT);
    TEST_ASSERT_EQUAL_INT(PKT_DIR_INCOMING, judge(frame, len));
}

// A tag stack cut by caplen must not be read past caplen, even if the bytes beyond it look valid.
void test_tag_stack_truncated_by_caplen(void)
{
    const uint16_t tpids[] = {ETHERTYPE_DOT1AD, ETHERTYPE_VLAN};
    build_tagged_ipv4_tcp(frame, tpids, 2, CLIENT_PORT, SERVER_PORT);
    TEST_ASSERT_EQUAL_INT(PKT_DIR_UNKNOWN, judge(frame, 14 + 4 + 2));
}

void test_ip_header_truncated_after_tags(void)
{
    const uint16_t tpids[] = {ETHERTYPE_DOT1AD, ETHERTYPE_VLAN};
    build_tagged_ipv4_tcp(frame, tpids, 2, CLIENT_PORT, SERVER_PORT);
    TEST_ASSERT_EQUAL_INT(PKT_DIR_UNKNOWN, judge(frame, 14 + 8 + 19));
}

// A frame that is nothing but tags is walked to caplen without recursion and judged unknown.
void test_frame_of_only_tags(void)
{
    size_t off = put_eth(frame, ETHERTYPE_VLAN);
    while (off + 4 <= sizeof(frame))
        off += put_tag(frame + off, 1, ETHERTYPE_VLAN);
    TEST_ASSERT_EQUAL_INT(PKT_DIR_UNKNOWN, judge(frame, off));
}

void test_is_vlan_ethertype(void)
{
    TEST_ASSERT_TRUE(is_vlan_ethertype(ETHERTYPE_VLAN));
    TEST_ASSERT_TRUE(is_vlan_ethertype(ETHERTYPE_DOT1AD));
    TEST_ASSERT_TRUE(is_vlan_ethertype(ETHERTYPE_VLAN_9100));
    TEST_ASSERT_TRUE(is_vlan_ethertype(ETHERTYPE_VLAN_9200));
    TEST_ASSERT_FALSE(is_vlan_ethertype(ETHERTYPE_IP));
    TEST_ASSERT_FALSE(is_vlan_ethertype(ETHERTYPE_IPV6));
}

int main(void)
{
    UNITY_BEGIN();
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
    RUN_TEST(test_req_pattern_custom_port_rejects_sign_and_leading_zero);
    RUN_TEST(test_req_pattern_custom_and_precedence_over_or);
    RUN_TEST(test_req_pattern_custom_extra_whitespace);

    RUN_TEST(test_untagged);
    RUN_TEST(test_single_8021q_tag);
    RUN_TEST(test_double_8021q_tags);
    RUN_TEST(test_qinq_8021ad_outer_tag);
    RUN_TEST(test_qinq_9100_outer_tag);
    RUN_TEST(test_qinq_9200_outer_tag);
    RUN_TEST(test_single_8021ad_tag);
    RUN_TEST(test_mixed_tag_stack);
    RUN_TEST(test_qinq_ipv6);
    RUN_TEST(test_qinq_inside_vxlan);
    RUN_TEST(test_tag_stack_truncated_by_caplen);
    RUN_TEST(test_ip_header_truncated_after_tags);
    RUN_TEST(test_frame_of_only_tags);
    RUN_TEST(test_is_vlan_ethertype);
    return UNITY_END();
}
