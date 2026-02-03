#include "unity/src/unity.h"

#include "packet_split.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <string.h>

void setUp(void) {}

void tearDown(void) {}

/* ======================================================================
 * Helper: build raw Ethernet + IPv4 + TCP packet
 * Returns total packet length. Checksum fields are set to 0.
 * ====================================================================== */
static int build_ipv4_tcp_packet(uint8_t *buf, const uint8_t *payload, uint16_t payload_len, uint32_t saddr,
                                 uint32_t daddr, uint16_t sport, uint16_t dport, uint32_t seq)
{
    memset(buf, 0, 2048);
    int offset = 0;

    /* Ethernet header */
    struct ether_header *eth = (struct ether_header *)buf;
    memset(eth->ether_dhost, 0xAA, ETH_ALEN);
    memset(eth->ether_shost, 0xBB, ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_IP);
    offset += sizeof(struct ether_header);

    /* IPv4 header (20 bytes, no options) */
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(buf + offset);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = saddr;
    ip->daddr = daddr;
    ip->check = 0;

    uint16_t tcp_hdr_len = 20; /* offx2 = 5 << 4 */
    uint16_t ip_total = 20 + tcp_hdr_len + payload_len;
    ip->tot_len = htons(ip_total);
    ip->id = htons(0x1234);
    ip->frag_off = 0;
    offset += 20;

    /* TCP header (20 bytes, no options) */
    struct tcphdr *tcp = (struct tcphdr *)(buf + offset);
    tcp->sport = htons(sport);
    tcp->dport = htons(dport);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(0);
    tcp->offx2 = (5 << 4); /* data offset = 5 (20 bytes) */
    tcp->flags = 0x10;     /* ACK */
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;
    offset += tcp_hdr_len;

    /* Payload */
    if (payload && payload_len > 0)
    {
        memcpy(buf + offset, payload, payload_len);
    }
    offset += payload_len;

    return offset;
}

/* ======================================================================
 * Helper: build raw Ethernet + IPv4 + UDP packet
 * ====================================================================== */
static int build_ipv4_udp_packet(uint8_t *buf, const uint8_t *payload, uint16_t payload_len, uint32_t saddr,
                                 uint32_t daddr, uint16_t sport, uint16_t dport)
{
    memset(buf, 0, 2048);
    int offset = 0;

    struct ether_header *eth = (struct ether_header *)buf;
    memset(eth->ether_dhost, 0xAA, ETH_ALEN);
    memset(eth->ether_shost, 0xBB, ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_IP);
    offset += sizeof(struct ether_header);

    struct ipv4_hdr *ip = (struct ipv4_hdr *)(buf + offset);
    ip->version = 4;
    ip->ihl = 5;
    ip->tos = 0;
    ip->ttl = 64;
    ip->protocol = IPPROTO_UDP;
    ip->saddr = saddr;
    ip->daddr = daddr;
    ip->check = 0;

    uint16_t udp_len = sizeof(struct udphdr) + payload_len;
    ip->tot_len = htons(20 + udp_len);
    ip->id = htons(0x5678);
    ip->frag_off = 0;
    offset += 20;

    struct udphdr *udp = (struct udphdr *)(buf + offset);
    udp->source = htons(sport);
    udp->dest = htons(dport);
    udp->len = htons(udp_len);
    udp->check = 0;
    offset += sizeof(struct udphdr);

    if (payload && payload_len > 0)
    {
        memcpy(buf + offset, payload, payload_len);
    }
    offset += payload_len;

    return offset;
}

/* ======================================================================
 * Helper: build raw Ethernet + IPv6 + TCP packet
 * ====================================================================== */
static int build_ipv6_tcp_packet(uint8_t *buf, const uint8_t *payload, uint16_t payload_len,
                                 const struct in6_addr *saddr, const struct in6_addr *daddr, uint16_t sport,
                                 uint16_t dport, uint32_t seq)
{
    memset(buf, 0, 2048);
    int offset = 0;

    struct ether_header *eth = (struct ether_header *)buf;
    memset(eth->ether_dhost, 0xAA, ETH_ALEN);
    memset(eth->ether_shost, 0xBB, ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_IPV6);
    offset += sizeof(struct ether_header);

    struct ipv6_hdr *ip6 = (struct ipv6_hdr *)(buf + offset);
    ip6->version = 6;
    ip6->priority = 0;
    memset(ip6->flow_lbl, 0, 3);
    uint16_t tcp_hdr_len = 20;
    ip6->payload_len = htons(tcp_hdr_len + payload_len);
    ip6->nexthdr = IPPROTO_TCP;
    ip6->hop_limit = 64;
    memcpy(&ip6->saddr, saddr, sizeof(struct in6_addr));
    memcpy(&ip6->daddr, daddr, sizeof(struct in6_addr));
    offset += sizeof(struct ipv6_hdr);

    struct tcphdr *tcp = (struct tcphdr *)(buf + offset);
    tcp->sport = htons(sport);
    tcp->dport = htons(dport);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(0);
    tcp->offx2 = (5 << 4);
    tcp->flags = 0x10;
    tcp->window = htons(65535);
    tcp->check = 0;
    tcp->urg_ptr = 0;
    offset += tcp_hdr_len;

    if (payload && payload_len > 0)
    {
        memcpy(buf + offset, payload, payload_len);
    }
    offset += payload_len;

    return offset;
}

/* ======================================================================
 * Helper: build raw Ethernet + IPv6 + UDP packet
 * ====================================================================== */
static int build_ipv6_udp_packet(uint8_t *buf, const uint8_t *payload, uint16_t payload_len,
                                 const struct in6_addr *saddr, const struct in6_addr *daddr, uint16_t sport,
                                 uint16_t dport)
{
    memset(buf, 0, 2048);
    int offset = 0;

    struct ether_header *eth = (struct ether_header *)buf;
    memset(eth->ether_dhost, 0xAA, ETH_ALEN);
    memset(eth->ether_shost, 0xBB, ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_IPV6);
    offset += sizeof(struct ether_header);

    struct ipv6_hdr *ip6 = (struct ipv6_hdr *)(buf + offset);
    ip6->version = 6;
    ip6->priority = 0;
    memset(ip6->flow_lbl, 0, 3);
    uint16_t udp_total = sizeof(struct udphdr) + payload_len;
    ip6->payload_len = htons(udp_total);
    ip6->nexthdr = IPPROTO_UDP;
    ip6->hop_limit = 64;
    memcpy(&ip6->saddr, saddr, sizeof(struct in6_addr));
    memcpy(&ip6->daddr, daddr, sizeof(struct in6_addr));
    offset += sizeof(struct ipv6_hdr);

    struct udphdr *udp = (struct udphdr *)(buf + offset);
    udp->source = htons(sport);
    udp->dest = htons(dport);
    udp->len = htons(udp_total);
    udp->check = 0;
    offset += sizeof(struct udphdr);

    if (payload && payload_len > 0)
    {
        memcpy(buf + offset, payload, payload_len);
    }
    offset += payload_len;

    return offset;
}

/* ======================================================================
 * Helper: build Ethernet + VLAN + IPv4 + TCP packet
 * ====================================================================== */
static int build_vlan_ipv4_tcp_packet(uint8_t *buf, const uint8_t *payload, uint16_t payload_len, uint16_t vlan_id)
{
    memset(buf, 0, 2048);
    int offset = 0;

    struct ether_header *eth = (struct ether_header *)buf;
    memset(eth->ether_dhost, 0xAA, ETH_ALEN);
    memset(eth->ether_shost, 0xBB, ETH_ALEN);
    eth->ether_type = htons(ETHERTYPE_VLAN);
    offset += sizeof(struct ether_header);

    /* VLAN header */
    struct vlan_header *vlan = (struct vlan_header *)(buf + offset);
    vlan->vlan_tci = htons(vlan_id);
    vlan->ether_type = htons(ETHERTYPE_IP);
    offset += sizeof(struct vlan_header);

    /* IPv4 */
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(buf + offset);
    ip->version = 4;
    ip->ihl = 5;
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = htonl(0xC0A80001); /* 192.168.0.1 */
    ip->daddr = htonl(0xC0A80002); /* 192.168.0.2 */
    ip->check = 0;
    uint16_t tcp_hdr_len = 20;
    ip->tot_len = htons(20 + tcp_hdr_len + payload_len);
    offset += 20;

    /* TCP */
    struct tcphdr *tcp = (struct tcphdr *)(buf + offset);
    tcp->sport = htons(12345);
    tcp->dport = htons(80);
    tcp->seq = htonl(1000);
    tcp->offx2 = (5 << 4);
    tcp->flags = 0x10;
    tcp->window = htons(65535);
    tcp->check = 0;
    offset += tcp_hdr_len;

    if (payload && payload_len > 0)
    {
        memcpy(buf + offset, payload, payload_len);
    }
    offset += payload_len;

    return offset;
}

/* ======================================================================
 * Checksum verification helper:
 * Compute checksum, write it back, compute again — should yield 0.
 * ====================================================================== */
static uint16_t verify_ip_checksum_roundtrip(uint8_t *pkt, uint16_t ip_offset)
{
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(pkt + ip_offset);
    ip->check = 0;
    ip->check = calculate_ip_checksum(ip);
    /* Re-calculate over the header with correct checksum — must be 0 */
    return calculate_ip_checksum(ip);
}

/* ======================================================================
 * Tests: calculate_ip_checksum
 * ====================================================================== */
void test_ip_checksum_basic(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "Hello";
    build_ipv4_tcp_packet(pkt, payload, sizeof(payload) - 1, htonl(0x0A000001), htonl(0x0A000002), 1234, 80, 100);

    struct ipv4_hdr *ip = (struct ipv4_hdr *)(pkt + sizeof(struct ether_header));
    ip->check = 0;

    uint16_t cksum = calculate_ip_checksum(ip);
    TEST_ASSERT_NOT_EQUAL_HEX16(0, cksum);

    /* Write checksum and verify roundtrip */
    ip->check = cksum;
    uint16_t verify = calculate_ip_checksum(ip);
    TEST_ASSERT_EQUAL_HEX16(0, verify);
}

void test_ip_checksum_different_addresses(void)
{
    uint8_t pkt1[2048], pkt2[2048];
    uint8_t payload[] = "Test";

    build_ipv4_tcp_packet(pkt1, payload, 4, htonl(0xC0A80001), htonl(0xC0A80002), 80, 80, 0);
    build_ipv4_tcp_packet(pkt2, payload, 4, htonl(0xAC100001), htonl(0xAC100002), 80, 80, 0);

    struct ipv4_hdr *ip1 = (struct ipv4_hdr *)(pkt1 + sizeof(struct ether_header));
    struct ipv4_hdr *ip2 = (struct ipv4_hdr *)(pkt2 + sizeof(struct ether_header));

    uint16_t cksum1 = calculate_ip_checksum(ip1);
    uint16_t cksum2 = calculate_ip_checksum(ip2);

    /* Different source/dest addresses should produce different checksums */
    TEST_ASSERT_NOT_EQUAL_HEX16(cksum1, cksum2);

    /* Both should pass roundtrip */
    ip1->check = cksum1;
    TEST_ASSERT_EQUAL_HEX16(0, calculate_ip_checksum(ip1));
    ip2->check = cksum2;
    TEST_ASSERT_EQUAL_HEX16(0, calculate_ip_checksum(ip2));
}

void test_ip_checksum_with_options(void)
{
    /* Build a packet with IPv4 options (ihl=6, 24 bytes header) */
    uint8_t pkt[2048];
    memset(pkt, 0, sizeof(pkt));

    struct ether_header *eth = (struct ether_header *)pkt;
    eth->ether_type = htons(ETHERTYPE_IP);
    int offset = sizeof(struct ether_header);

    struct ipv4_hdr *ip = (struct ipv4_hdr *)(pkt + offset);
    ip->version = 4;
    ip->ihl = 6; /* 24 bytes */
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = htonl(0x0A000001);
    ip->daddr = htonl(0x0A000002);
    ip->tot_len = htons(24 + 20); /* IP header with options + TCP header */
    ip->check = 0;

    /* Fill 4 bytes of options (NOP + NOP + NOP + EOL) */
    uint8_t *options = pkt + offset + 20;
    options[0] = 0x01; /* NOP */
    options[1] = 0x01; /* NOP */
    options[2] = 0x01; /* NOP */
    options[3] = 0x00; /* EOL */

    uint16_t cksum = calculate_ip_checksum(ip);
    TEST_ASSERT_NOT_EQUAL_HEX16(0, cksum);

    ip->check = cksum;
    TEST_ASSERT_EQUAL_HEX16(0, calculate_ip_checksum(ip));
}

/* RFC 1071 Section 3 example verification */
void test_ip_checksum_rfc1071_example(void)
{
    /* RFC 1071 example: data = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}
     * Expected checksum = 0x220d */
    uint8_t data[] = {0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7};

    /* We can't call internet_checksum directly (it's static), but we can
     * construct a minimal IPv4 header using these bytes to verify the algorithm.
     * Instead, use a full header and verify the roundtrip property. */

    /* Build a known IPv4 header from a real captured packet:
     * 45 00 00 3c 1c 46 40 00 40 06 b1 e6 ac 10 0a 63 ac 10 0a 0c
     * This is a real IPv4 header where checksum = 0xb1e6 */
    uint8_t ip_bytes[] = {0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06,
                          0xb1, 0xe6, 0xac, 0x10, 0x0a, 0x63, 0xac, 0x10, 0x0a, 0x0c};

    struct ipv4_hdr *ip = (struct ipv4_hdr *)ip_bytes;

    /* Verify: checksum over header with correct checksum should be 0 */
    TEST_ASSERT_EQUAL_HEX16(0, calculate_ip_checksum(ip));

    /* Zero out checksum and recalculate.
     * calculate_ip_checksum returns the value in host byte order (ready to
     * assign to ip->check), while 0xb1e6 is the network-byte-order
     * representation seen on the wire.  Use htons() so the comparison is
     * correct on both little-endian and big-endian machines. */
    ip->check = 0;
    uint16_t cksum = calculate_ip_checksum(ip);
    TEST_ASSERT_EQUAL_HEX16(htons(0xb1e6), cksum);
}

/* ======================================================================
 * Tests: calculate_tcp_checksum (IPv4)
 * ====================================================================== */
void test_tcp_checksum_ipv4_roundtrip(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "Hello, TCP checksum test!";
    uint16_t payload_len = sizeof(payload) - 1;

    int pkt_len =
        build_ipv4_tcp_packet(pkt, payload, payload_len, htonl(0x0A000001), htonl(0x0A000002), 12345, 80, 1000);
    (void)pkt_len;

    uint16_t ip_offset = sizeof(struct ether_header);
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(pkt + ip_offset);
    struct tcphdr *tcp = (struct tcphdr *)(pkt + ip_offset + 20);
    uint16_t tcp_len = 20 + payload_len;

    tcp->check = 0;
    uint16_t cksum = calculate_tcp_checksum(ip, NULL, tcp, tcp_len);
    TEST_ASSERT_NOT_EQUAL_HEX16(0, cksum);

    /* Write checksum and verify roundtrip */
    tcp->check = cksum;
    uint16_t verify = calculate_tcp_checksum(ip, NULL, tcp, tcp_len);
    TEST_ASSERT_EQUAL_HEX16(0, verify);
}

void test_tcp_checksum_ipv4_empty_payload(void)
{
    uint8_t pkt[2048];
    int pkt_len = build_ipv4_tcp_packet(pkt, NULL, 0, htonl(0x0A000001), htonl(0x0A000002), 12345, 80, 0);
    (void)pkt_len;

    uint16_t ip_offset = sizeof(struct ether_header);
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(pkt + ip_offset);
    struct tcphdr *tcp = (struct tcphdr *)(pkt + ip_offset + 20);
    uint16_t tcp_len = 20; /* header only */

    tcp->check = 0;
    uint16_t cksum = calculate_tcp_checksum(ip, NULL, tcp, tcp_len);
    tcp->check = cksum;
    TEST_ASSERT_EQUAL_HEX16(0, calculate_tcp_checksum(ip, NULL, tcp, tcp_len));
}

void test_tcp_checksum_ipv4_odd_payload(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "ODD"; /* 3 bytes — odd length */
    int pkt_len = build_ipv4_tcp_packet(pkt, payload, 3, htonl(0x0A000001), htonl(0x0A000002), 4444, 8080, 500);
    (void)pkt_len;

    uint16_t ip_offset = sizeof(struct ether_header);
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(pkt + ip_offset);
    struct tcphdr *tcp = (struct tcphdr *)(pkt + ip_offset + 20);
    uint16_t tcp_len = 20 + 3;

    tcp->check = 0;
    uint16_t cksum = calculate_tcp_checksum(ip, NULL, tcp, tcp_len);
    tcp->check = cksum;
    TEST_ASSERT_EQUAL_HEX16(0, calculate_tcp_checksum(ip, NULL, tcp, tcp_len));
}

/* ======================================================================
 * Tests: calculate_tcp_checksum (IPv6)
 * ====================================================================== */
void test_tcp_checksum_ipv6_roundtrip(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "IPv6 TCP checksum test!";
    uint16_t payload_len = sizeof(payload) - 1;

    struct in6_addr saddr, daddr;
    inet_pton(AF_INET6, "2001:db8::1", &saddr);
    inet_pton(AF_INET6, "2001:db8::2", &daddr);

    build_ipv6_tcp_packet(pkt, payload, payload_len, &saddr, &daddr, 12345, 80, 1000);

    uint16_t ip_offset = sizeof(struct ether_header);
    struct ipv6_hdr *ip6 = (struct ipv6_hdr *)(pkt + ip_offset);
    struct tcphdr *tcp = (struct tcphdr *)(pkt + ip_offset + sizeof(struct ipv6_hdr));
    uint16_t tcp_len = 20 + payload_len;

    tcp->check = 0;
    uint16_t cksum = calculate_tcp_checksum(NULL, ip6, tcp, tcp_len);
    TEST_ASSERT_NOT_EQUAL_HEX16(0, cksum);

    tcp->check = cksum;
    TEST_ASSERT_EQUAL_HEX16(0, calculate_tcp_checksum(NULL, ip6, tcp, tcp_len));
}

/* ======================================================================
 * Tests: calculate_udp_checksum (IPv4)
 * ====================================================================== */
void test_udp_checksum_ipv4_roundtrip(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "UDP checksum test payload";
    uint16_t payload_len = sizeof(payload) - 1;

    build_ipv4_udp_packet(pkt, payload, payload_len, htonl(0x0A000001), htonl(0x0A000002), 53, 1234);

    uint16_t ip_offset = sizeof(struct ether_header);
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(pkt + ip_offset);
    struct udphdr *udp = (struct udphdr *)(pkt + ip_offset + 20);
    uint16_t udp_len = sizeof(struct udphdr) + payload_len;

    udp->check = 0;
    uint16_t cksum = calculate_udp_checksum(ip, NULL, udp, udp_len);
    TEST_ASSERT_NOT_EQUAL_HEX16(0, cksum);

    udp->check = cksum;
    TEST_ASSERT_EQUAL_HEX16(0, calculate_udp_checksum(ip, NULL, udp, udp_len));
}

void test_udp_checksum_ipv4_empty_payload(void)
{
    uint8_t pkt[2048];
    build_ipv4_udp_packet(pkt, NULL, 0, htonl(0x0A000001), htonl(0x0A000002), 53, 1234);

    uint16_t ip_offset = sizeof(struct ether_header);
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(pkt + ip_offset);
    struct udphdr *udp = (struct udphdr *)(pkt + ip_offset + 20);
    uint16_t udp_len = sizeof(struct udphdr);

    udp->check = 0;
    uint16_t cksum = calculate_udp_checksum(ip, NULL, udp, udp_len);
    udp->check = cksum;
    TEST_ASSERT_EQUAL_HEX16(0, calculate_udp_checksum(ip, NULL, udp, udp_len));
}

/* ======================================================================
 * Tests: calculate_udp_checksum (IPv6)
 * ====================================================================== */
void test_udp_checksum_ipv6_roundtrip(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "IPv6 UDP test";
    uint16_t payload_len = sizeof(payload) - 1;

    struct in6_addr saddr, daddr;
    inet_pton(AF_INET6, "fd00::1", &saddr);
    inet_pton(AF_INET6, "fd00::2", &daddr);

    build_ipv6_udp_packet(pkt, payload, payload_len, &saddr, &daddr, 5353, 5353);

    uint16_t ip_offset = sizeof(struct ether_header);
    struct ipv6_hdr *ip6 = (struct ipv6_hdr *)(pkt + ip_offset);
    struct udphdr *udp = (struct udphdr *)(pkt + ip_offset + sizeof(struct ipv6_hdr));
    uint16_t udp_len = sizeof(struct udphdr) + payload_len;

    udp->check = 0;
    uint16_t cksum = calculate_udp_checksum(NULL, ip6, udp, udp_len);
    udp->check = cksum;
    TEST_ASSERT_EQUAL_HEX16(0, calculate_udp_checksum(NULL, ip6, udp, udp_len));
}

/* ======================================================================
 * Tests: parse_packet
 * ====================================================================== */
void test_parse_packet_ipv4_tcp(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "parse test";
    int pkt_len = build_ipv4_tcp_packet(pkt, payload, 10, htonl(0x0A000001), htonl(0x0A000002), 1111, 2222, 0);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    TEST_ASSERT_TRUE(result.is_ipv4);
    TEST_ASSERT_FALSE(result.is_ipv6);
    TEST_ASSERT_TRUE(result.is_tcp);
    TEST_ASSERT_FALSE(result.is_udp);
    TEST_ASSERT_FALSE(result.has_vlan);

    TEST_ASSERT_EQUAL_UINT16(0, result.eth_offset);
    TEST_ASSERT_EQUAL_UINT16(sizeof(struct ether_header), result.ip_offset);
    TEST_ASSERT_EQUAL_UINT16(20, result.ip_hdr_len);
    TEST_ASSERT_EQUAL_UINT16(20, result.l4_hdr_len);
    TEST_ASSERT_EQUAL_UINT16(10, result.payload_len);

    TEST_ASSERT_NOT_NULL(result.eth_hdr);
    TEST_ASSERT_NOT_NULL(result.ipv4_hdr);
    TEST_ASSERT_NOT_NULL(result.tcp_hdr);
    TEST_ASSERT_EQUAL_HEX16(htons(1111), result.tcp_hdr->sport);
    TEST_ASSERT_EQUAL_HEX16(htons(2222), result.tcp_hdr->dport);
}

void test_parse_packet_ipv4_udp(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "udp data";
    int pkt_len = build_ipv4_udp_packet(pkt, payload, 8, htonl(0x0A000001), htonl(0x0A000002), 53, 1234);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    TEST_ASSERT_TRUE(result.is_ipv4);
    TEST_ASSERT_TRUE(result.is_udp);
    TEST_ASSERT_FALSE(result.is_tcp);
    TEST_ASSERT_EQUAL_UINT16(sizeof(struct udphdr), result.l4_hdr_len);
    TEST_ASSERT_EQUAL_UINT16(8, result.payload_len);
}

void test_parse_packet_ipv6_tcp(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "v6 tcp";
    struct in6_addr saddr, daddr;
    inet_pton(AF_INET6, "::1", &saddr);
    inet_pton(AF_INET6, "::2", &daddr);

    int pkt_len = build_ipv6_tcp_packet(pkt, payload, 6, &saddr, &daddr, 80, 443, 0);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    TEST_ASSERT_TRUE(result.is_ipv6);
    TEST_ASSERT_FALSE(result.is_ipv4);
    TEST_ASSERT_TRUE(result.is_tcp);
    TEST_ASSERT_EQUAL_UINT16(sizeof(struct ipv6_hdr), result.ip_hdr_len);
    TEST_ASSERT_EQUAL_UINT16(6, result.payload_len);
}

void test_parse_packet_with_vlan(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "vlan";
    int pkt_len = build_vlan_ipv4_tcp_packet(pkt, payload, 4, 100);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    TEST_ASSERT_TRUE(result.has_vlan);
    TEST_ASSERT_TRUE(result.is_ipv4);
    TEST_ASSERT_TRUE(result.is_tcp);
    TEST_ASSERT_EQUAL_UINT16(sizeof(struct ether_header), result.vlan_offset);
    TEST_ASSERT_EQUAL_UINT16(sizeof(struct ether_header) + sizeof(struct vlan_header), result.ip_offset);
}

void test_parse_packet_truncated(void)
{
    uint8_t pkt[2048];
    uint8_t payload[] = "data";
    build_ipv4_tcp_packet(pkt, payload, 4, htonl(0x0A000001), htonl(0x0A000002), 80, 80, 0);

    packet_parse_result_t result;

    /* Too short for Ethernet header */
    TEST_ASSERT_FALSE(parse_packet(pkt, 10, &result));

    /* Enough for Ethernet but not for IP */
    TEST_ASSERT_FALSE(parse_packet(pkt, sizeof(struct ether_header) + 5, &result));

    /* Enough for IP but not for TCP */
    TEST_ASSERT_FALSE(parse_packet(pkt, sizeof(struct ether_header) + 20 + 10, &result));
}

void test_parse_packet_non_ip(void)
{
    uint8_t pkt[2048];
    memset(pkt, 0, sizeof(pkt));

    struct ether_header *eth = (struct ether_header *)pkt;
    eth->ether_type = htons(0x0806); /* ARP */

    packet_parse_result_t result;
    TEST_ASSERT_FALSE(parse_packet(pkt, 64, &result));
}

/* ======================================================================
 * Tests: calculate_fragment_count
 * ====================================================================== */
void test_fragment_count_no_split(void)
{
    uint8_t pkt[2048];
    uint8_t payload[50];
    memset(payload, 'A', 50);
    int pkt_len = build_ipv4_tcp_packet(pkt, payload, 50, htonl(0x0A000001), htonl(0x0A000002), 80, 80, 0);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    TEST_ASSERT_EQUAL_INT(1, calculate_fragment_count(&result, 50));
    TEST_ASSERT_EQUAL_INT(1, calculate_fragment_count(&result, 100));
    TEST_ASSERT_EQUAL_INT(1, calculate_fragment_count(&result, 0));
}

void test_fragment_count_split(void)
{
    uint8_t pkt[2048];
    uint8_t payload[100];
    memset(payload, 'B', 100);
    int pkt_len = build_ipv4_tcp_packet(pkt, payload, 100, htonl(0x0A000001), htonl(0x0A000002), 80, 80, 0);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    TEST_ASSERT_EQUAL_INT(3, calculate_fragment_count(&result, 40));  /* 100/40 = 2.5 → 3 */
    TEST_ASSERT_EQUAL_INT(2, calculate_fragment_count(&result, 50));  /* 100/50 = 2 */
    TEST_ASSERT_EQUAL_INT(10, calculate_fragment_count(&result, 10)); /* 100/10 = 10 */
    TEST_ASSERT_EQUAL_INT(1, calculate_fragment_count(&result, 100)); /* exact fit */
}

/* ======================================================================
 * Tests: build_fragment
 * ====================================================================== */
void test_build_fragment_single(void)
{
    uint8_t pkt[2048];
    uint8_t payload[30];
    memset(payload, 'X', 30);
    int pkt_len = build_ipv4_tcp_packet(pkt, payload, 30, htonl(0x0A000001), htonl(0x0A000002), 80, 80, 1000);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    uint8_t out[2048];
    int frag_len = build_fragment(&result, pkt, 0, 30, true, out);
    TEST_ASSERT_EQUAL_INT(pkt_len, frag_len);

    /* Verify IP checksum in output */
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(out + sizeof(struct ether_header));
    TEST_ASSERT_EQUAL_HEX16(0, calculate_ip_checksum(ip));

    /* Verify TCP checksum in output */
    struct tcphdr *tcp = (struct tcphdr *)(out + sizeof(struct ether_header) + 20);
    TEST_ASSERT_EQUAL_HEX16(0, calculate_tcp_checksum(ip, NULL, tcp, 20 + 30));
}

void test_build_fragment_tcp_split_checksums(void)
{
    uint8_t pkt[2048];
    uint8_t payload[100];
    int i;
    for (i = 0; i < 100; i++)
        payload[i] = (uint8_t)(i & 0xFF);

    int pkt_len = build_ipv4_tcp_packet(pkt, payload, 100, htonl(0x0A000001), htonl(0x0A000002), 8080, 443, 5000);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    int max_payload = 40;
    int frag_count = calculate_fragment_count(&result, max_payload);
    TEST_ASSERT_EQUAL_INT(3, frag_count);

    int frag_idx;
    for (frag_idx = 0; frag_idx < frag_count; frag_idx++)
    {
        uint8_t out[2048];
        int frag_len = build_fragment(&result, pkt, frag_idx, max_payload, true, out);
        TEST_ASSERT_TRUE(frag_len > 0);

        /* Verify IP checksum */
        struct ipv4_hdr *ip = (struct ipv4_hdr *)(out + sizeof(struct ether_header));
        TEST_ASSERT_EQUAL_HEX16(0, calculate_ip_checksum(ip));

        /* Determine actual fragment payload size */
        int expected_payload;
        if (frag_idx < frag_count - 1)
            expected_payload = max_payload;
        else
            expected_payload = 100 - frag_idx * max_payload; /* last fragment: remainder */

        /* Verify TCP checksum */
        struct tcphdr *tcp = (struct tcphdr *)(out + sizeof(struct ether_header) + 20);
        uint16_t tcp_total = 20 + expected_payload;
        TEST_ASSERT_EQUAL_HEX16(0, calculate_tcp_checksum(ip, NULL, tcp, tcp_total));

        /* Verify IP total length */
        TEST_ASSERT_EQUAL_UINT16(20 + tcp_total, ntohs(ip->tot_len));
    }
}

void test_build_fragment_tcp_seq_increment(void)
{
    uint8_t pkt[2048];
    uint8_t payload[100];
    memset(payload, 'S', 100);

    uint32_t original_seq = 10000;
    int pkt_len = build_ipv4_tcp_packet(pkt, payload, 100, htonl(0x0A000001), htonl(0x0A000002), 80, 80, original_seq);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    int max_payload = 30;
    int frag_count = calculate_fragment_count(&result, max_payload);
    /* 100/30 = 3.33 → 4 fragments */
    TEST_ASSERT_EQUAL_INT(4, frag_count);

    int frag_idx;
    for (frag_idx = 0; frag_idx < frag_count; frag_idx++)
    {
        uint8_t out[2048];
        build_fragment(&result, pkt, frag_idx, max_payload, false, out);

        struct tcphdr *tcp = (struct tcphdr *)(out + sizeof(struct ether_header) + 20);
        uint32_t expected_seq = original_seq + frag_idx * max_payload;
        TEST_ASSERT_EQUAL_UINT32(expected_seq, ntohl(tcp->seq));
    }
}

void test_build_fragment_udp_split_checksums(void)
{
    uint8_t pkt[2048];
    uint8_t payload[80];
    int i;
    for (i = 0; i < 80; i++)
        payload[i] = (uint8_t)((i * 7) & 0xFF);

    int pkt_len = build_ipv4_udp_packet(pkt, payload, 80, htonl(0x0A000001), htonl(0x0A000002), 53, 1234);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    int max_payload = 30;
    int frag_count = calculate_fragment_count(&result, max_payload);
    TEST_ASSERT_EQUAL_INT(3, frag_count); /* 80/30 = 2.67 → 3 */

    int frag_idx;
    for (frag_idx = 0; frag_idx < frag_count; frag_idx++)
    {
        uint8_t out[2048];
        int frag_len = build_fragment(&result, pkt, frag_idx, max_payload, true, out);
        TEST_ASSERT_TRUE(frag_len > 0);

        struct ipv4_hdr *ip = (struct ipv4_hdr *)(out + sizeof(struct ether_header));
        TEST_ASSERT_EQUAL_HEX16(0, calculate_ip_checksum(ip));

        int expected_payload;
        if (frag_idx < frag_count - 1)
            expected_payload = max_payload;
        else
            expected_payload = 80 - frag_idx * max_payload;

        struct udphdr *udp = (struct udphdr *)(out + sizeof(struct ether_header) + 20);
        uint16_t udp_total = sizeof(struct udphdr) + expected_payload;
        TEST_ASSERT_EQUAL_HEX16(0, calculate_udp_checksum(ip, NULL, udp, udp_total));

        /* Verify UDP length field */
        TEST_ASSERT_EQUAL_UINT16(udp_total, ntohs(udp->len));
    }
}

void test_build_fragment_ipv6_tcp_checksums(void)
{
    uint8_t pkt[2048];
    uint8_t payload[60];
    int i;
    for (i = 0; i < 60; i++)
        payload[i] = (uint8_t)(i);

    struct in6_addr saddr, daddr;
    inet_pton(AF_INET6, "2001:db8::1", &saddr);
    inet_pton(AF_INET6, "2001:db8::2", &daddr);

    int pkt_len = build_ipv6_tcp_packet(pkt, payload, 60, &saddr, &daddr, 8080, 443, 2000);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    int max_payload = 25;
    int frag_count = calculate_fragment_count(&result, max_payload);
    TEST_ASSERT_EQUAL_INT(3, frag_count); /* 60/25 = 2.4 → 3 */

    int frag_idx;
    for (frag_idx = 0; frag_idx < frag_count; frag_idx++)
    {
        uint8_t out[2048];
        int frag_len = build_fragment(&result, pkt, frag_idx, max_payload, true, out);
        TEST_ASSERT_TRUE(frag_len > 0);

        int expected_payload;
        if (frag_idx < frag_count - 1)
            expected_payload = max_payload;
        else
            expected_payload = 60 - frag_idx * max_payload;

        struct ipv6_hdr *ip6 = (struct ipv6_hdr *)(out + sizeof(struct ether_header));
        struct tcphdr *tcp = (struct tcphdr *)(out + sizeof(struct ether_header) + sizeof(struct ipv6_hdr));
        uint16_t tcp_total = 20 + expected_payload;

        /* Verify IPv6 payload length */
        TEST_ASSERT_EQUAL_UINT16(tcp_total, ntohs(ip6->payload_len));

        /* Verify TCP checksum */
        TEST_ASSERT_EQUAL_HEX16(0, calculate_tcp_checksum(NULL, ip6, tcp, tcp_total));
    }
}

void test_build_fragment_no_checksum_recalc(void)
{
    uint8_t pkt[2048];
    uint8_t payload[60];
    memset(payload, 'N', 60);

    int pkt_len = build_ipv4_tcp_packet(pkt, payload, 60, htonl(0x0A000001), htonl(0x0A000002), 80, 80, 0);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    uint8_t out[2048];
    /* recalculate_checksum = false: checksum fields should remain 0 */
    build_fragment(&result, pkt, 0, 30, false, out);

    struct ipv4_hdr *ip = (struct ipv4_hdr *)(out + sizeof(struct ether_header));
    /* IP checksum should still be 0 (original was 0, not recalculated) */
    TEST_ASSERT_EQUAL_HEX16(0, ip->check);

    struct tcphdr *tcp = (struct tcphdr *)(out + sizeof(struct ether_header) + 20);
    TEST_ASSERT_EQUAL_HEX16(0, tcp->check);
}

void test_build_fragment_payload_content(void)
{
    uint8_t pkt[2048];
    uint8_t payload[100];
    int i;
    for (i = 0; i < 100; i++)
        payload[i] = (uint8_t)i;

    int pkt_len = build_ipv4_tcp_packet(pkt, payload, 100, htonl(0x0A000001), htonl(0x0A000002), 80, 80, 0);

    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    int max_payload = 40;

    /* Fragment 0: payload bytes 0..39 */
    uint8_t out0[2048];
    int len0 = build_fragment(&result, pkt, 0, max_payload, false, out0);
    TEST_ASSERT_TRUE(len0 > 0);
    uint8_t *frag0_payload = out0 + result.payload_offset;
    for (i = 0; i < 40; i++)
        TEST_ASSERT_EQUAL_UINT8(i, frag0_payload[i]);

    /* Fragment 1: payload bytes 40..79 */
    uint8_t out1[2048];
    int len1 = build_fragment(&result, pkt, 1, max_payload, false, out1);
    TEST_ASSERT_TRUE(len1 > 0);
    uint8_t *frag1_payload = out1 + result.payload_offset;
    for (i = 0; i < 40; i++)
        TEST_ASSERT_EQUAL_UINT8(40 + i, frag1_payload[i]);

    /* Fragment 2: payload bytes 80..99 (last, 20 bytes) */
    uint8_t out2[2048];
    int len2 = build_fragment(&result, pkt, 2, max_payload, false, out2);
    TEST_ASSERT_TRUE(len2 > 0);
    uint8_t *frag2_payload = out2 + result.payload_offset;
    for (i = 0; i < 20; i++)
        TEST_ASSERT_EQUAL_UINT8(80 + i, frag2_payload[i]);
}

/* Verify build_fragment produces correct checksums when the original packet
 * already carries non-zero (valid) checksum values — regression test for
 * the bug where checksum fields were not zeroed before recalculation. */
void test_build_fragment_nonzero_original_checksum(void)
{
    uint8_t pkt[2048];
    uint8_t payload[100];
    int i;
    for (i = 0; i < 100; i++)
        payload[i] = (uint8_t)(i + 0x30);

    int pkt_len = build_ipv4_tcp_packet(pkt, payload, 100, htonl(0xC0A80001), htonl(0xC0A80002), 12345, 80, 5000);

    /* Set valid checksums on the original packet (simulating a real capture) */
    uint16_t ip_offset = sizeof(struct ether_header);
    struct ipv4_hdr *ip = (struct ipv4_hdr *)(pkt + ip_offset);
    struct tcphdr *tcp = (struct tcphdr *)(pkt + ip_offset + 20);
    uint16_t tcp_total = 20 + 100;

    ip->check = 0;
    ip->check = calculate_ip_checksum(ip);
    TEST_ASSERT_NOT_EQUAL_HEX16(0, ip->check); /* must be non-zero */

    tcp->check = 0;
    tcp->check = calculate_tcp_checksum(ip, NULL, tcp, tcp_total);
    TEST_ASSERT_NOT_EQUAL_HEX16(0, tcp->check); /* must be non-zero */

    /* Now parse and split — the source packet has non-zero checksums */
    packet_parse_result_t result;
    TEST_ASSERT_TRUE(parse_packet(pkt, pkt_len, &result));

    int max_payload = 40;
    int frag_count = calculate_fragment_count(&result, max_payload);
    TEST_ASSERT_EQUAL_INT(3, frag_count);

    /* Each fragment's checksums must verify correctly */
    int frag_idx;
    for (frag_idx = 0; frag_idx < frag_count; frag_idx++)
    {
        uint8_t out[2048];
        int flen = build_fragment(&result, pkt, frag_idx, max_payload, true, out);
        TEST_ASSERT_TRUE(flen > 0);

        struct ipv4_hdr *frag_ip = (struct ipv4_hdr *)(out + result.ip_offset);
        /* IP checksum roundtrip: re-computing over the header (with correct
         * checksum already in place) must yield 0. */
        TEST_ASSERT_EQUAL_HEX16(0, calculate_ip_checksum(frag_ip));

        struct tcphdr *frag_tcp = (struct tcphdr *)(out + result.l4_offset);
        int this_payload = (frag_idx < frag_count - 1) ? max_payload : (100 - frag_idx * max_payload);
        uint16_t frag_tcp_len = 20 + this_payload;

        /* TCP checksum roundtrip */
        TEST_ASSERT_EQUAL_HEX16(0, calculate_tcp_checksum(frag_ip, NULL, frag_tcp, frag_tcp_len));
    }
}

/* ======================================================================
 * Main
 * ====================================================================== */
int main(void)
{
    UNITY_BEGIN();

    /* IP checksum */
    RUN_TEST(test_ip_checksum_basic);
    RUN_TEST(test_ip_checksum_different_addresses);
    RUN_TEST(test_ip_checksum_with_options);
    RUN_TEST(test_ip_checksum_rfc1071_example);

    /* TCP checksum */
    RUN_TEST(test_tcp_checksum_ipv4_roundtrip);
    RUN_TEST(test_tcp_checksum_ipv4_empty_payload);
    RUN_TEST(test_tcp_checksum_ipv4_odd_payload);
    RUN_TEST(test_tcp_checksum_ipv6_roundtrip);

    /* UDP checksum */
    RUN_TEST(test_udp_checksum_ipv4_roundtrip);
    RUN_TEST(test_udp_checksum_ipv4_empty_payload);
    RUN_TEST(test_udp_checksum_ipv6_roundtrip);

    /* parse_packet */
    RUN_TEST(test_parse_packet_ipv4_tcp);
    RUN_TEST(test_parse_packet_ipv4_udp);
    RUN_TEST(test_parse_packet_ipv6_tcp);
    RUN_TEST(test_parse_packet_with_vlan);
    RUN_TEST(test_parse_packet_truncated);
    RUN_TEST(test_parse_packet_non_ip);

    /* calculate_fragment_count */
    RUN_TEST(test_fragment_count_no_split);
    RUN_TEST(test_fragment_count_split);

    /* build_fragment */
    RUN_TEST(test_build_fragment_single);
    RUN_TEST(test_build_fragment_tcp_split_checksums);
    RUN_TEST(test_build_fragment_tcp_seq_increment);
    RUN_TEST(test_build_fragment_udp_split_checksums);
    RUN_TEST(test_build_fragment_ipv6_tcp_checksums);
    RUN_TEST(test_build_fragment_no_checksum_recalc);
    RUN_TEST(test_build_fragment_payload_content);
    RUN_TEST(test_build_fragment_nonzero_original_checksum);

    return UNITY_END();
}