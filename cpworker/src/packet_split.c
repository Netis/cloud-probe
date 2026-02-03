#include "packet_split.h"
#include "vlan.h"

#include <arpa/inet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <string.h>

#ifdef __SSE2__
#include <emmintrin.h>
#endif

/* ======================================================================
 * Optimized checksum core (RFC 1071)
 *
 * Key optimizations vs. naive 16-bit-at-a-time loop:
 *   1. 8× loop unrolling — processes 16 bytes per iteration
 *   2. SSE2 SIMD fast path — processes 32 bytes per iteration using
 *      128-bit vector adds (x86_64 always has SSE2, works with GCC 4.8)
 *   3. Fixed 2-pass carry fold instead of while-loop
 *   4. Specialized 20-byte fast path for the common ihl==5 IPv4 header
 *   5. All internal helpers are static inline
 * ====================================================================== */

/**
 * Fold a uint32_t partial sum into a 16-bit one's complement result.
 * Two passes are sufficient because the max carry after folding once is 1.
 */
static inline uint16_t cksum_fold(uint32_t sum)
{
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum = (sum >> 16) + (sum & 0xFFFF);
    return (uint16_t)sum;
}

/**
 * Accumulate 16-bit one's complement sum over `len` bytes.
 * Returns a partial (un-folded, un-complemented) uint32_t sum that can be
 * combined with other partial sums before the final fold + complement.
 *
 * `initial_sum` allows chaining with a pseudo-header sum.
 */
static inline uint32_t cksum_accumulate(const void *buf, size_t len, uint32_t initial_sum)
{
    const uint16_t *u16 = (const uint16_t *)buf;
    uint32_t sum = initial_sum;

#ifdef __SSE2__
    /* SSE2 fast path: accumulate 32 bytes (16 × uint16_t) per iteration
     * into four 32-bit lanes, then horizontally reduce. */
    if (len >= 32)
    {
        __m128i vsum = _mm_setzero_si128();
        const __m128i vzero = _mm_setzero_si128();

        while (len >= 32)
        {
            __m128i v0 = _mm_loadu_si128((const __m128i *)u16);
            __m128i v1 = _mm_loadu_si128((const __m128i *)(u16 + 8));

            /* Unpack uint16_t → uint32_t and add to avoid overflow:
             * 65535 * (65536/2 lanes) = 2^31 - 32768, fits in uint32_t
             * with plenty of room for thousands of iterations. */
            vsum = _mm_add_epi32(vsum, _mm_unpacklo_epi16(v0, vzero));
            vsum = _mm_add_epi32(vsum, _mm_unpackhi_epi16(v0, vzero));
            vsum = _mm_add_epi32(vsum, _mm_unpacklo_epi16(v1, vzero));
            vsum = _mm_add_epi32(vsum, _mm_unpackhi_epi16(v1, vzero));

            u16 += 16;
            len -= 32;
        }

        /* Horizontal reduce: 4 × uint32_t → scalar */
        __m128i hi64 = _mm_shuffle_epi32(vsum, _MM_SHUFFLE(1, 0, 3, 2));
        vsum = _mm_add_epi32(vsum, hi64);
        __m128i hi32 = _mm_shuffle_epi32(vsum, _MM_SHUFFLE(2, 3, 0, 1));
        vsum = _mm_add_epi32(vsum, hi32);

        /* _mm_cvtsi128_si32 extracts lane 0 as int32 */
        sum += (uint32_t)_mm_cvtsi128_si32(vsum);
    }
#endif /* __SSE2__ */

    /* Scalar path: 8× unrolled (16 bytes per iteration) */
    while (len >= 16)
    {
        sum += u16[0];
        sum += u16[1];
        sum += u16[2];
        sum += u16[3];
        sum += u16[4];
        sum += u16[5];
        sum += u16[6];
        sum += u16[7];
        u16 += 8;
        len -= 16;
    }

    /* 4× unrolled remainder (8 bytes) */
    if (len >= 8)
    {
        sum += u16[0];
        sum += u16[1];
        sum += u16[2];
        sum += u16[3];
        u16 += 4;
        len -= 8;
    }

    /* Remaining 16-bit words */
    while (len >= 2)
    {
        sum += *u16++;
        len -= 2;
    }

    /* Trailing odd byte */
    if (len)
    {
        sum += *(const uint8_t *)u16;
    }

    return sum;
}

/**
 * Full checksum: accumulate + fold + complement.
 */
static inline uint16_t cksum_finish(uint32_t partial_sum) { return ~cksum_fold(partial_sum); }

/* ======================================================================
 * Public API: IP checksum
 * ====================================================================== */

uint16_t calculate_ip_checksum(const struct ipv4_hdr *ip_hdr)
{
    const uint16_t *p = (const uint16_t *)ip_hdr;

    /* Fast path for the common case: standard 20-byte IPv4 header (ihl == 5).
     * Fully unrolled — no loop, no branches, 10 additions. */
    if (__builtin_expect(ip_hdr->ihl == 5, 1))
    {
        uint32_t sum = (uint32_t)p[0] + p[1] + p[2] + p[3] + p[4] + p[5] + p[6] + p[7] + p[8] + p[9];
        return cksum_finish(sum);
    }

    return cksum_finish(cksum_accumulate(ip_hdr, ip_hdr->ihl * 4, 0));
}

/* ======================================================================
 * Internal: pseudo-header sum (inline, returns partial sum)
 * ====================================================================== */

static inline uint32_t calculate_pseudo_header_sum(const struct ipv4_hdr *ip_hdr, const struct ipv6_hdr *ipv6_hdr,
                                                   uint8_t protocol, uint16_t l4_len)
{
    uint32_t sum = 0;

    if (ip_hdr)
    {
        const uint16_t *s = (const uint16_t *)&ip_hdr->saddr;
        const uint16_t *d = (const uint16_t *)&ip_hdr->daddr;

        sum = (uint32_t)s[0] + s[1] + d[0] + d[1] + htons(protocol) + htons(l4_len);
    }
    else if (ipv6_hdr)
    {
        const uint16_t *s = (const uint16_t *)&ipv6_hdr->saddr;
        const uint16_t *d = (const uint16_t *)&ipv6_hdr->daddr;

        sum = (uint32_t)s[0] + s[1] + s[2] + s[3] + s[4] + s[5] + s[6] + s[7] + d[0] + d[1] + d[2] + d[3] + d[4] +
              d[5] + d[6] + d[7] + htons(l4_len) + htons(protocol);
    }

    return sum;
}

/* ======================================================================
 * Public API: TCP / UDP checksums
 * ====================================================================== */

uint16_t __attribute__((hot)) calculate_tcp_checksum(const struct ipv4_hdr *ip_hdr, const struct ipv6_hdr *ipv6_hdr,
                                                     const struct tcphdr *tcp_hdr, uint16_t tcp_len)
{
    uint32_t sum = calculate_pseudo_header_sum(ip_hdr, ipv6_hdr, IPPROTO_TCP, tcp_len);
    return cksum_finish(cksum_accumulate(tcp_hdr, tcp_len, sum));
}

uint16_t __attribute__((hot)) calculate_udp_checksum(const struct ipv4_hdr *ip_hdr, const struct ipv6_hdr *ipv6_hdr,
                                                     const struct udphdr *udp_hdr, uint16_t udp_len)
{
    uint32_t sum = calculate_pseudo_header_sum(ip_hdr, ipv6_hdr, IPPROTO_UDP, udp_len);
    return cksum_finish(cksum_accumulate(udp_hdr, udp_len, sum));
}

bool parse_packet(const uint8_t *pkt_data, uint32_t caplen, packet_parse_result_t *result)
{
    memset(result, 0, sizeof(packet_parse_result_t));

    if (caplen < sizeof(struct ether_header))
    {
        return false;
    }

    // Parse Ethernet header
    result->eth_offset = 0;
    result->eth_hdr = (struct ether_header *)pkt_data;
    uint16_t ether_type = ntohs(result->eth_hdr->ether_type);
    uint16_t offset = sizeof(struct ether_header);

    // Check for VLAN tag
    while (ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_DOT1AD || ether_type == ETHERTYPE_VLAN_9100 ||
           ether_type == ETHERTYPE_VLAN_9200)
    {
        if (caplen < offset + sizeof(struct vlan_header))
        {
            return false;
        }

        if (!result->has_vlan)
        {
            result->has_vlan = true;
            result->vlan_offset = offset;
            result->vlan_hdr = (struct vlan_header *)(pkt_data + offset);
        }

        struct vlan_header *vlan_hdr = (struct vlan_header *)(pkt_data + offset);
        ether_type = ntohs(vlan_hdr->ether_type);
        offset += sizeof(struct vlan_header);
    }

    // Parse IP header
    result->ip_offset = offset;

    if (ether_type == ETHERTYPE_IP)
    {
        // IPv4
        if (caplen < offset + sizeof(struct ipv4_hdr))
        {
            return false;
        }

        result->is_ipv4 = true;
        result->ipv4_hdr = (struct ipv4_hdr *)(pkt_data + offset);
        result->ip_hdr_len = result->ipv4_hdr->ihl * 4;

        if (caplen < offset + result->ip_hdr_len)
        {
            return false;
        }

        offset += result->ip_hdr_len;
        result->l4_offset = offset;

        // Parse L4 protocol
        if (result->ipv4_hdr->protocol == IPPROTO_TCP)
        {
            if (caplen < offset + sizeof(struct tcphdr))
            {
                return false;
            }

            result->is_tcp = true;
            result->tcp_hdr = (struct tcphdr *)(pkt_data + offset);
            result->l4_hdr_len = (result->tcp_hdr->offx2 >> 4) * 4;

            if (caplen < offset + result->l4_hdr_len)
            {
                return false;
            }

            offset += result->l4_hdr_len;
        }
        else if (result->ipv4_hdr->protocol == IPPROTO_UDP)
        {
            if (caplen < offset + sizeof(struct udphdr))
            {
                return false;
            }

            result->is_udp = true;
            result->udp_hdr = (struct udphdr *)(pkt_data + offset);
            result->l4_hdr_len = sizeof(struct udphdr);
            offset += result->l4_hdr_len;
        }
        else
        {
            // Other L4 protocol - not supported for splitting
            return false;
        }

        result->payload_offset = offset;
        result->payload = pkt_data + offset;

        uint16_t ip_tot_len = ntohs(result->ipv4_hdr->tot_len);
        uint16_t headers_len = result->ip_hdr_len + result->l4_hdr_len;
        if (ip_tot_len < headers_len)
            return false;
        result->payload_len = ip_tot_len - headers_len;
    }
    else if (ether_type == ETHERTYPE_IPV6)
    {
        // IPv6
        if (caplen < offset + sizeof(struct ipv6_hdr))
        {
            return false;
        }

        result->is_ipv6 = true;
        result->ipv6_hdr = (struct ipv6_hdr *)(pkt_data + offset);
        result->ip_hdr_len = sizeof(struct ipv6_hdr);
        result->ipv6_ext_len = 0;
        offset += sizeof(struct ipv6_hdr);

        // Skip IPv6 extension headers
        uint8_t nexthdr = result->ipv6_hdr->nexthdr;
        while (nexthdr == IPPROTO_HOPOPTS || nexthdr == IPPROTO_ROUTING || nexthdr == IPPROTO_DSTOPTS ||
               nexthdr == IPPROTO_DSTOPTS)
        {
            if (caplen < offset + 2)
                return false;

            uint8_t ext_nexthdr = pkt_data[offset];
            uint8_t ext_len = pkt_data[offset + 1];
            uint16_t ext_total = (ext_len + 1) * 8;

            if (caplen < offset + ext_total)
                return false;

            offset += ext_total;
            result->ipv6_ext_len += ext_total;
            nexthdr = ext_nexthdr;
        }

        // Fragment header (fixed 8 bytes, not supported for splitting)
        if (nexthdr == IPPROTO_FRAGMENT)
            return false;

        result->l4_offset = offset;

        // Parse L4 protocol
        if (nexthdr == IPPROTO_TCP)
        {
            if (caplen < offset + sizeof(struct tcphdr))
            {
                return false;
            }

            result->is_tcp = true;
            result->tcp_hdr = (struct tcphdr *)(pkt_data + offset);
            result->l4_hdr_len = (result->tcp_hdr->offx2 >> 4) * 4;

            if (caplen < offset + result->l4_hdr_len)
            {
                return false;
            }

            offset += result->l4_hdr_len;
        }
        else if (nexthdr == IPPROTO_UDP)
        {
            if (caplen < offset + sizeof(struct udphdr))
            {
                return false;
            }

            result->is_udp = true;
            result->udp_hdr = (struct udphdr *)(pkt_data + offset);
            result->l4_hdr_len = sizeof(struct udphdr);
            offset += result->l4_hdr_len;
        }
        else
        {
            // Other L4 protocol - not supported for splitting
            return false;
        }

        result->payload_offset = offset;
        result->payload = pkt_data + offset;

        uint16_t ipv6_payload_len = ntohs(result->ipv6_hdr->payload_len);
        if (ipv6_payload_len < result->ipv6_ext_len + result->l4_hdr_len)
            return false;
        result->payload_len = ipv6_payload_len - result->ipv6_ext_len - result->l4_hdr_len;
    }
    else
    {
        // Not IP packet
        return false;
    }

    // Validate payload length against actual captured data
    if (result->payload_offset > caplen)
        return false;

    uint16_t max_payload = caplen - result->payload_offset;
    if (result->payload_len > max_payload)
        result->payload_len = max_payload;

    return true;
}

int calculate_fragment_count(const packet_parse_result_t *parse_result, int max_payload_size)
{
    if (max_payload_size <= 0 || parse_result->payload_len <= max_payload_size)
    {
        return 1;
    }

    return (parse_result->payload_len + max_payload_size - 1) / max_payload_size;
}

int build_fragment(const packet_parse_result_t *parse_result, const uint8_t *pkt_data, int fragment_index,
                   int max_payload_size, bool recalculate_checksum, uint8_t *output_buf)
{
    // Calculate fragment payload size
    int payload_offset = fragment_index * max_payload_size;
    int remaining = parse_result->payload_len - payload_offset;
    int frag_payload_size = (remaining > max_payload_size) ? max_payload_size : remaining;

    if (frag_payload_size <= 0)
    {
        return -1;
    }

    // Copy headers up to payload
    int header_len = parse_result->payload_offset;
    memcpy(output_buf, pkt_data, header_len);

    // Copy fragment payload
    memcpy(output_buf + header_len, parse_result->payload + payload_offset, frag_payload_size);

    int total_len = header_len + frag_payload_size;

    // Update IP layer
    if (parse_result->is_ipv4)
    {
        struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(output_buf + parse_result->ip_offset);
        uint16_t new_ip_total_len = parse_result->ip_hdr_len + parse_result->l4_hdr_len + frag_payload_size;
        ip_hdr->tot_len = htons(new_ip_total_len);

        // Recalculate IP checksum only if requested
        if (recalculate_checksum)
        {
            ip_hdr->check = 0;
            ip_hdr->check = calculate_ip_checksum(ip_hdr);
        }
    }
    else if (parse_result->is_ipv6)
    {
        struct ipv6_hdr *ip_hdr = (struct ipv6_hdr *)(output_buf + parse_result->ip_offset);
        uint16_t new_payload_len = parse_result->ipv6_ext_len + parse_result->l4_hdr_len + frag_payload_size;
        ip_hdr->payload_len = htons(new_payload_len);
    }

    // Update L4 layer
    if (parse_result->is_tcp)
    {
        struct tcphdr *tcp_hdr = (struct tcphdr *)(output_buf + parse_result->l4_offset);

        // Update sequence number
        uint32_t original_seq = ntohl(tcp_hdr->seq);
        tcp_hdr->seq = htonl(original_seq + payload_offset);

        // Recalculate TCP checksum only if requested
        if (recalculate_checksum)
        {
            uint16_t tcp_len = parse_result->l4_hdr_len + frag_payload_size;
            tcp_hdr->check = 0;

            if (parse_result->is_ipv4)
            {
                struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(output_buf + parse_result->ip_offset);
                tcp_hdr->check = calculate_tcp_checksum(ip_hdr, NULL, tcp_hdr, tcp_len);
            }
            else if (parse_result->is_ipv6)
            {
                struct ipv6_hdr *ip_hdr = (struct ipv6_hdr *)(output_buf + parse_result->ip_offset);
                tcp_hdr->check = calculate_tcp_checksum(NULL, ip_hdr, tcp_hdr, tcp_len);
            }
        }
    }
    else if (parse_result->is_udp)
    {
        struct udphdr *udp_hdr = (struct udphdr *)(output_buf + parse_result->l4_offset);

        // Update UDP length
        uint16_t udp_len = parse_result->l4_hdr_len + frag_payload_size;
        udp_hdr->len = htons(udp_len);

        // Recalculate UDP checksum only if requested
        if (recalculate_checksum)
        {
            udp_hdr->check = 0;

            if (parse_result->is_ipv4)
            {
                struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(output_buf + parse_result->ip_offset);
                udp_hdr->check = calculate_udp_checksum(ip_hdr, NULL, udp_hdr, udp_len);
            }
            else if (parse_result->is_ipv6)
            {
                struct ipv6_hdr *ip_hdr = (struct ipv6_hdr *)(output_buf + parse_result->ip_offset);
                udp_hdr->check = calculate_udp_checksum(NULL, ip_hdr, udp_hdr, udp_len);
            }
        }
    }

    return total_len;
}
