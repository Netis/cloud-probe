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

static int no_nic(const char *ifname, ip_addr_t *addr, char *errbuf)
{
    (void)addr;
    error_format(errbuf, "interface '%s' not exists", ifname);
    return -1;
}

void setUp(void)
{
    memset(frame, 0, sizeof(frame));
    pattern.type = REQ_PATTERN_TYPE_CUSTOM;
    TEST_ASSERT_EQUAL_INT(0, req_pattern_custom_matcher_init(&pattern.matcher.custom, "port 80", no_nic));
}

void tearDown(void) { req_pattern_custom_matcher_destroy(&pattern.matcher.custom); }

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
