#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "errorf.h"
#include "ether.h"
#include "if_util.h"
#include "ip.h"
#include "log.h"
#include "pkt_dir.h"
#include "req_pattern.h"
#include "tcp.h"
#include "udp.h"
#include "vlan.h"
#include "vxlan.h"

typedef enum
{
    COND_HOST,
    COND_PORT
} ConditionType;

typedef enum
{
    OP_AND,
    OP_OR
} OperatorType;

typedef struct Node Node;

typedef enum
{
    NODE_CONDITION,
    NODE_OPERATOR
} NodeType;

struct Node
{
    NodeType type;
    union
    {
        struct
        {
            ConditionType cond_type;
            ip_addr_t addr;
            uint16_t port;
        } condition;
        struct
        {
            OperatorType op_type;
            Node *left;
            Node *right;
        } operator;
    } data;
};

typedef enum
{
    TOKEN_HOST,
    TOKEN_PORT,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_LPAREN,
    TOKEN_RPAREN,
    TOKEN_VALUE,
    TOKEN_EOF,
    TOKEN_ERROR
} TokenType;

typedef struct
{
    TokenType type;
    char *value;
} Token;

// 词法分析函数
static Token get_next_token(char **input)
{
    while (isspace(**input))
        (*input)++;
    if (**input == '\0')
        return (Token){TOKEN_EOF, NULL};

    // 检查关键字和操作符
    if (strncmp(*input, "host", 4) == 0 && !isalnum((*input)[4]))
    {
        *input += 4;
        return (Token){TOKEN_HOST, NULL};
    }
    else if (strncmp(*input, "port", 4) == 0 && !isalnum((*input)[4]))
    {
        *input += 4;
        return (Token){TOKEN_PORT, NULL};
    }
    else if (strncmp(*input, "and", 3) == 0 && !isalnum((*input)[3]))
    {
        *input += 3;
        return (Token){TOKEN_AND, NULL};
    }
    else if (strncmp(*input, "or", 2) == 0 && !isalnum((*input)[2]))
    {
        *input += 2;
        return (Token){TOKEN_OR, NULL};
    }
    else if (**input == '(')
    {
        (*input)++;
        return (Token){TOKEN_LPAREN, NULL};
    }
    else if (**input == ')')
    {
        (*input)++;
        return (Token){TOKEN_RPAREN, NULL};
    }

    // 读取值
    char *start = *input;
    while (**input && !isspace(**input) && **input != '(' && **input != ')' && strncmp(*input, "and", 3) != 0 &&
           strncmp(*input, "or", 2) != 0)
    {
        (*input)++;
    }
    size_t len = *input - start;
    char *value = malloc(len + 1);
    strncpy(value, start, len);
    value[len] = '\0';
    return (Token){TOKEN_VALUE, value};
}

static Node *create_condition_node(ConditionType type, const char *value, get_if_ip_addr_fn get_ip)
{
    Node *node = malloc(sizeof(Node));
    node->type = NODE_CONDITION;
    node->data.condition.cond_type = type;
    if (type == TOKEN_HOST)
    {
        if (strlen(value) >= 4 && strncmp(value, "nic.", 4) == 0)
        {
            char errbuf[ERROR_BUFFER_SIZE];
            if (get_ip(value + 4, &node->data.condition.addr, errbuf) == 0)
            {
                char buf[INET6_ADDRSTRLEN];
                format_ip_addr(&node->data.condition.addr, buf, sizeof(buf));
                log_info("req_pattern interface %s addresss is %s", value + 4, buf);
                return node;
            }

            log_error("get interface ip error: %s", errbuf);
            goto error;
        }

        if (inet_pton(AF_INET, value, &node->data.condition.addr.data.v4) == 1)
        {
            node->data.condition.addr.type = IP_TYPE_IPv4;
            return node;
        }
        if (inet_pton(AF_INET6, value, &node->data.condition.addr.data.v6) == 1)
        {
            node->data.condition.addr.type = IP_TYPE_IPv6;
            return node;
        }
    }
    else if (type == TOKEN_PORT)
    {
        int port = atoi(value);
        if (port < 0 || port > 65535)
        {
            log_error("invalid port: %s", value);
            goto error;
        }
        node->data.condition.port = port;
        return node;
    }

error:
    free(node);
    return NULL;
}

static Node *create_operator_node(OperatorType type, Node *left, Node *right)
{
    Node *node = malloc(sizeof(Node));
    node->type = NODE_OPERATOR;
    node->data.operator.op_type = type;
    node->data.operator.left = left;
    node->data.operator.right = right;
    return node;
}

static void free_ast(Node *node)
{
    if (!node)
        return;

    if (node->type == NODE_OPERATOR)
    {
        free_ast(node->data.operator.left);
        free_ast(node->data.operator.right);
    }
    free(node);
}

// 语法分析函数
static Node *parse_expression(char **input, Token *current_token, get_if_ip_addr_fn get_ip);
static Node *parse_term(char **input, Token *current_token, get_if_ip_addr_fn get_ip);
static Node *parse_factor(char **input, Token *current_token, get_if_ip_addr_fn get_ip);
static Node *parse_condition(char **input, Token *current_token, get_if_ip_addr_fn get_ip);

static void next_token(char **input, Token *current_token) { *current_token = get_next_token(input); }

static Node *parse_expression(char **input, Token *current_token, get_if_ip_addr_fn get_ip)
{
    Node *left = parse_term(input, current_token, get_ip);
    if (!left)
        return NULL;

    while (current_token->type == TOKEN_OR)
    {
        next_token(input, current_token);
        Node *right = parse_term(input, current_token, get_ip);
        if (!right)
        {
            free_ast(left);
            return NULL;
        }
        left = create_operator_node(OP_OR, left, right);
    }
    return left;
}

static Node *parse_term(char **input, Token *current_token, get_if_ip_addr_fn get_ip)
{
    Node *left = parse_factor(input, current_token, get_ip);
    if (!left)
        return NULL;

    while (current_token->type == TOKEN_AND)
    {
        next_token(input, current_token);
        Node *right = parse_factor(input, current_token, get_ip);
        if (!right)
        {
            free_ast(left);
            return NULL;
        }
        left = create_operator_node(OP_AND, left, right);
    }
    return left;
}

static Node *parse_factor(char **input, Token *current_token, get_if_ip_addr_fn get_ip)
{
    if (current_token->type == TOKEN_LPAREN)
    {
        next_token(input, current_token);
        Node *expr = parse_expression(input, current_token, get_ip);
        if (current_token->type != TOKEN_RPAREN)
        {
            free_ast(expr);
            return NULL;
        }
        next_token(input, current_token);
        return expr;
    }
    else
    {
        return parse_condition(input, current_token, get_ip);
    }
}

static Node *parse_condition(char **input, Token *current_token, get_if_ip_addr_fn get_ip)
{
    if (current_token->type == TOKEN_HOST)
    {
        next_token(input, current_token);
        if (current_token->type != TOKEN_VALUE)
        {
            return NULL;
        }
        char *value = current_token->value;
        next_token(input, current_token);
        Node *node = create_condition_node(COND_HOST, value, get_ip);
        free(value);
        return node;
    }
    else if (current_token->type == TOKEN_PORT)
    {
        next_token(input, current_token);
        if (current_token->type != TOKEN_VALUE)
        {
            return NULL;
        }
        char *value = current_token->value;
        next_token(input, current_token);
        Node *node = create_condition_node(COND_PORT, value, get_ip);
        free(value);
        return node;
    }
    return NULL;
}

static bool evaluate(Node *node, const ip_addr_t *ip, uint16_t port)
{
    if (!node)
        return false;

    if (node->type == NODE_CONDITION)
    {
        if (node->data.condition.cond_type == COND_HOST)
            return ip_addr_equal(&node->data.condition.addr, ip);
        else
            return node->data.condition.port == port;
    }
    else
    {
        bool left = evaluate(node->data.operator.left, ip, port);
        bool right = evaluate(node->data.operator.right, ip, port);
        switch (node->data.operator.op_type)
        {
        case OP_AND:
            return left && right;
        case OP_OR:
            return left || right;
        default:
            return false;
        }
    }
}

#define IPPORT_FLAGS_IP 0x01
#define IPPORT_FLAGS_PORT 0x02

static int extract_ipport_from_ipv4_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data, size_t data_offset,
                                          int encap_level, ip_addr_t *sip, uint16_t *sport, ip_addr_t *dip,
                                          uint16_t *dport);
static int extract_ipport_from_ipv6_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data, size_t data_offset,
                                          int encap_level, ip_addr_t *sip, uint16_t *sport, ip_addr_t *dip,
                                          uint16_t *dport);
static int extract_ipport_from_tcp_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data, size_t data_offset,
                                         int encap_level, ip_addr_t *sip, uint16_t *sport, ip_addr_t *dip,
                                         uint16_t *dport);
static int extract_ipport_from_udp_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data, size_t data_offset,
                                         int encap_level, ip_addr_t *sip, uint16_t *sport, ip_addr_t *dip,
                                         uint16_t *dport);
static int extract_ipport_from_maybe_vxlan_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                                                 size_t data_offset, int encap_level, ip_addr_t *sip, uint16_t *sport,
                                                 ip_addr_t *dip, uint16_t *dport);

static int extract_ipport_from_ether_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                                           size_t data_offset, int encap_level, ip_addr_t *sip, uint16_t *sport,
                                           ip_addr_t *dip, uint16_t *dport)
{
    size_t eth_hdr_len = sizeof(struct ether_header);
    if (header->caplen < data_offset + eth_hdr_len)
        return 0;

    struct ether_header *eth_hdr = (struct ether_header *)(pkt_data + data_offset);
    uint16_t eth_type = ntohs(eth_hdr->ether_type);

    size_t ip_hdr_offset = data_offset + eth_hdr_len;
    if (eth_type == ETHERTYPE_VLAN)
    {
        if (header->caplen < data_offset + eth_hdr_len + sizeof(struct vlan_header))
            return 0;

        struct vlan_header *vlan_hdr = (struct vlan_header *)(pkt_data + data_offset + eth_hdr_len);
        eth_type = ntohs(vlan_hdr->ether_type);
        ip_hdr_offset += sizeof(struct vlan_header);
    }

    if (eth_type == ETHERTYPE_IP)
        return extract_ipport_from_ipv4_layer(header, pkt_data, ip_hdr_offset, encap_level, sip, sport, dip, dport);
    else if (eth_type == ETHERTYPE_IPV6)
        return extract_ipport_from_ipv6_layer(header, pkt_data, ip_hdr_offset, encap_level, sip, sport, dip, dport);

    return 0;
}

static int extract_ipport_from_ipv4_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data, size_t data_offset,
                                          int encap_level, ip_addr_t *sip, uint16_t *sport, ip_addr_t *dip,
                                          uint16_t *dport)
{
    if (header->caplen < data_offset + sizeof(struct ipv4_hdr))
        return 0;

    int flags = 0;
    struct ipv4_hdr *ip_hdr = (struct ipv4_hdr *)(pkt_data + data_offset);
    size_t ip_hdr_len = ip_hdr->ihl * 4;

    sip->type = IP_TYPE_IPv4;
    sip->data.v4.s_addr = ip_hdr->saddr;
    dip->type = IP_TYPE_IPv4;
    dip->data.v4.s_addr = ip_hdr->daddr;
    *sport = 0;
    *dport = 0;
    flags |= IPPORT_FLAGS_IP;

    if (ip_hdr->protocol == IPPROTO_TCP)
    {
        flags |= extract_ipport_from_tcp_layer(header, pkt_data, data_offset + ip_hdr_len, encap_level, sip, sport, dip,
                                               dport);
    }
    else if (ip_hdr->protocol == IPPROTO_UDP)
    {
        flags |= extract_ipport_from_udp_layer(header, pkt_data, data_offset + ip_hdr_len, encap_level, sip, sport, dip,
                                               dport);
    }
    return flags;
}

static int extract_ipport_from_ipv6_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data, size_t data_offset,
                                          int encap_level, ip_addr_t *sip, uint16_t *sport, ip_addr_t *dip,
                                          uint16_t *dport)
{
    if (header->caplen < data_offset + sizeof(struct ipv6_hdr))
        return 0;

    int flags = 0;
    struct ipv6_hdr *ip_hdr = (struct ipv6_hdr *)(pkt_data + data_offset);
    size_t ip_hdr_len = sizeof(struct ipv6_hdr);

    sip->type = IP_TYPE_IPv6;
    sip->data.v6 = ip_hdr->saddr;
    dip->type = IP_TYPE_IPv6;
    dip->data.v6 = ip_hdr->daddr;
    *sport = 0;
    *dport = 0;
    flags |= IPPORT_FLAGS_IP;

    if (ip_hdr->nexthdr == IPPROTO_TCP)
    {
        flags |= extract_ipport_from_tcp_layer(header, pkt_data, data_offset + ip_hdr_len, encap_level, sip, sport, dip,
                                               dport);
    }
    else if (ip_hdr->nexthdr == IPPROTO_UDP)
    {
        flags |= extract_ipport_from_udp_layer(header, pkt_data, data_offset + ip_hdr_len, encap_level, sip, sport, dip,
                                               dport);
    }
    return flags;
}

static int extract_ipport_from_tcp_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data, size_t data_offset,
                                         int encap_level, ip_addr_t *sip, uint16_t *sport, ip_addr_t *dip,
                                         uint16_t *dport)
{
    if (header->caplen < data_offset + sizeof(struct tcphdr))
        return 0;

    struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_data + data_offset);
    *sport = ntohs(tcp_hdr->sport);
    *dport = ntohs(tcp_hdr->dport);
    return IPPORT_FLAGS_PORT;
}

static int extract_ipport_from_udp_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data, size_t data_offset,
                                         int encap_level, ip_addr_t *sip, uint16_t *sport, ip_addr_t *dip,
                                         uint16_t *dport)
{
    if (header->caplen < data_offset + sizeof(struct udphdr))
        return 0;

    int flags = 0;
    struct udphdr *udp_hdr = (struct udphdr *)(pkt_data + data_offset);
    *sport = ntohs(udp_hdr->source);
    *dport = ntohs(udp_hdr->dest);
    flags |= IPPORT_FLAGS_PORT;

    // check vxlan
    if (udp_hdr->dest >= 4700 && udp_hdr->dest < 4800)
    {
        // Determine the port range of VXLAN: UDP 4700-4799
        // see: VTAP-108
        flags |= extract_ipport_from_maybe_vxlan_layer(header, pkt_data, data_offset + sizeof(struct udphdr),
                                                       encap_level, sip, sport, dip, dport);
    }
    return flags;
}

static int extract_ipport_from_maybe_vxlan_layer(const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                                                 size_t data_offset, int encap_level, ip_addr_t *sip, uint16_t *sport,
                                                 ip_addr_t *dip, uint16_t *dport)
{
    if (header->caplen <
        data_offset + sizeof(struct vxlan_header) + sizeof(struct ether_header) + sizeof(struct ipv4_hdr))
        return 0;

    return extract_ipport_from_ether_layer(header, pkt_data, data_offset + sizeof(struct vxlan_header), encap_level + 1,
                                           sip, sport, dip, dport);
}

void req_pattern_destory(req_pattern_t *req_pattern)
{
    if (!req_pattern)
        return;

    if (req_pattern->type == REQ_PATTERN_TYPE_CUSTOM)
        free_ast(req_pattern->matcher.custom.node);

    free(req_pattern);
}

void req_pattern_custom_matcher_destroy(req_pattern_custom_matcher_t *matcher)
{
    if (!matcher)
        return;

    if (matcher->node)
        free_ast(matcher->node);
}

int req_pattern_custom_matcher_init(req_pattern_custom_matcher_t *matcher, const char *pattern,
                                    get_if_ip_addr_fn get_ip)
{
    // pattern example:
    // 1. host nic.eth0 and port 8011
    // 2. (host 172.16.1.1 or host 172.16.1.2) and port 8011
    // 3. host 172.16.1.1 and (port 8011 or port 8012)
    // 4. (host 172.16.1.1 or host 172.16.1.2) and (port 8011 or port 8012)

    char *pos = (char *)pattern;
    Token token;
    next_token(&pos, &token);
    Node *ast = parse_expression(&pos, &token, get_ip);
    if (!ast)
        return -1;

    matcher->node = ast;
    return 0;
}

req_pattern_t *req_pattern_new_from_cfg_adv(ReqPatternConfig cfg, const char *ifname, get_if_mac_addr_fn get_mac,
                                            get_if_ip_addr_fn get_ip, char *errbuf)
{
    req_pattern_t *req_pattern = (req_pattern_t *)calloc(1, sizeof(req_pattern_t *));
    if (!req_pattern)
    {
        error_format(errbuf, "failed to allocate memory for req_pattern_t");
        return NULL;
    }

    if (strcmp(cfg.type, REQ_PATTERN_TYPE_NONE_STR) == 0)
        req_pattern->type = REQ_PATTERN_TYPE_NONE;
    else if (strcmp(cfg.type, REQ_PATTERN_TYPE_AUTO_STR) == 0)
    {
        if (get_mac(ifname, req_pattern->matcher._auto.mac_addr, errbuf) != 0)
            goto error;

        req_pattern->type = REQ_PATTERN_TYPE_AUTO;

        char mac_addr_str[MAC_ADDR_STR_BUFSIZE];
        format_mac_addr(req_pattern->matcher._auto.mac_addr, mac_addr_str);
        log_info("interface '%s' mac addr: %s", ifname, mac_addr_str);
    }
    else if (strcmp(cfg.type, REQ_PATTERN_TYPE_CUSTOM_STR) == 0)
    {
        if (req_pattern_custom_matcher_init(&req_pattern->matcher.custom, cfg.custom.pattern, get_ip) != 0)
        {
            error_format(errbuf, "invalid pattern: %s", cfg.custom.pattern);
            goto error;
        }

        req_pattern->type = REQ_PATTERN_TYPE_CUSTOM;
    }
    return req_pattern;

error:
    req_pattern_destory(req_pattern);
    return NULL;
}

req_pattern_t *req_pattern_new_from_cfg(ReqPatternConfig cfg, const char *ifname, char *errbuf)
{
    return req_pattern_new_from_cfg_adv(cfg, ifname, get_if_mac_addr, get_if_ip_addr, errbuf);
}

bool req_pattern_custom_match_by_ipport(req_pattern_custom_matcher_t *matcher, const ip_addr_t *ip, uint16_t port)
{
    return evaluate((Node *)matcher->node, ip, port);
}

int req_pattern_judge_pkt_direction(req_pattern_t *req_pattern, const struct pcap_pkthdr *header,
                                    const uint8_t *pkt_data)
{
    if (req_pattern->type == REQ_PATTERN_TYPE_NONE)
        return PKT_DIR_NONCHECK;

    else if (req_pattern->type == REQ_PATTERN_TYPE_AUTO)
    {
        size_t eth_hdr_len = sizeof(struct ether_header);
        if (header->caplen < eth_hdr_len)
            return PKT_DIR_UNKNOWN;

        struct ether_header *eth_hdr = (struct ether_header *)pkt_data;
        if (memcmp(eth_hdr->ether_shost, req_pattern->matcher._auto.mac_addr, ETHER_ADDR_LEN) == 0)
            return PKT_DIR_OUTGOING;
        else
            return PKT_DIR_INCOMING;
    }
    else if (req_pattern->type == REQ_PATTERN_TYPE_CUSTOM)
    {
        ip_addr_t sip;
        uint16_t sport = 0;
        ip_addr_t dip;
        uint16_t dport = 0;
        int flags = extract_ipport_from_ether_layer(header, pkt_data, 0, 0, &sip, &sport, &dip, &dport);
        if (flags & IPPORT_FLAGS_IP)
        {
            if (req_pattern_custom_match_by_ipport(&req_pattern->matcher.custom, &sip, sport))
                return PKT_DIR_OUTGOING;
            else if (req_pattern_custom_match_by_ipport(&req_pattern->matcher.custom, &dip, dport))
                return PKT_DIR_INCOMING;
            else
                return PKT_DIR_UNKNOWN;
        }
        return PKT_DIR_UNKNOWN;
    }

    return PKT_DIR_UNKNOWN;
}
