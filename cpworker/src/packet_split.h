#ifndef CPWORKER_PACKET_SPLIT_H
#define CPWORKER_PACKET_SPLIT_H

#include <net/ethernet.h>
#include <stdbool.h>
#include <stdint.h>

#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "vlan.h"

typedef struct
{
    bool is_ipv4;
    bool is_ipv6;
    bool is_tcp;
    bool is_udp;
    bool has_vlan;

    uint16_t eth_offset;
    uint16_t vlan_offset;
    uint16_t ip_offset;
    uint16_t l4_offset;
    uint16_t payload_offset;

    uint16_t ip_hdr_len;
    uint16_t ipv6_ext_len;
    uint16_t l4_hdr_len;
    uint16_t payload_len;

    struct ether_header *eth_hdr;
    struct vlan_header *vlan_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct ipv6_hdr *ipv6_hdr;
    struct tcphdr *tcp_hdr;
    struct udphdr *udp_hdr;
    const uint8_t *payload;
} packet_parse_result_t;

/**
 * Parse a packet and extract layer information
 * @param pkt_data Packet data
 * @param caplen Packet capture length
 * @param result Output parse result structure
 * @return true if parsing succeeded, false otherwise
 */
bool parse_packet(const uint8_t *pkt_data, uint32_t caplen, packet_parse_result_t *result);

/**
 * Calculate how many fragments are needed for a packet
 * @param parse_result Parsed packet information
 * @param max_payload_size Maximum payload size per fragment
 * @return Number of fragments needed (1 means no splitting needed)
 */
int calculate_fragment_count(const packet_parse_result_t *parse_result, int max_payload_size);

/**
 * Build a single fragment from the original packet
 * @param parse_result Parsed packet information
 * @param pkt_data Original packet data
 * @param fragment_index Fragment index (0-based)
 * @param max_payload_size Maximum payload size per fragment
 * @param recalculate_checksum Whether to recalculate IP/TCP/UDP checksums (default: false)
 * @param output_buf Output buffer for the fragment
 * @return Length of the built fragment, or -1 on error
 */
int build_fragment(const packet_parse_result_t *parse_result, const uint8_t *pkt_data, int fragment_index,
                   int max_payload_size, bool recalculate_checksum, uint8_t *output_buf);

/**
 * Calculate IPv4 header checksum
 * @param ip_hdr IPv4 header
 * @return Checksum value
 */
uint16_t calculate_ip_checksum(const struct ipv4_hdr *ip_hdr);

/**
 * Calculate TCP checksum
 * @param ip_hdr IPv4 header (can be NULL if using IPv6)
 * @param ipv6_hdr IPv6 header (can be NULL if using IPv4)
 * @param tcp_hdr TCP header
 * @param tcp_len Total TCP length (header + payload)
 * @return Checksum value
 */
uint16_t calculate_tcp_checksum(const struct ipv4_hdr *ip_hdr, const struct ipv6_hdr *ipv6_hdr,
                                const struct tcphdr *tcp_hdr, uint16_t tcp_len);

/**
 * Calculate UDP checksum
 * @param ip_hdr IPv4 header (can be NULL if using IPv6)
 * @param ipv6_hdr IPv6 header (can be NULL if using IPv4)
 * @param udp_hdr UDP header
 * @param udp_len Total UDP length (header + payload)
 * @return Checksum value
 */
uint16_t calculate_udp_checksum(const struct ipv4_hdr *ip_hdr, const struct ipv6_hdr *ipv6_hdr,
                                const struct udphdr *udp_hdr, uint16_t udp_len);

#endif /* CPWORKER_PACKET_SPLIT_H */
