#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <linux/if_ether.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap/pcap.h>
#include <pcap/vlan.h>

#include "common.h"
#include "error.h"
#include "log.h"
#include "req_pattern.h"

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
            uint32_t port;
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

typedef struct ReqPatternCustomMatcher
{
    struct Node *node;
} req_pattern_custom_matcher_t;

typedef struct ReqPatternAutoMatcher
{
    uint8_t mac_addr[ETH_ALEN];
} req_pattern_auto_matcher_t;

typedef struct ReqPattern
{
    int type;
    union
    {
        req_pattern_auto_matcher_t _auto;
        req_pattern_custom_matcher_t custom;
    } matcher;
} req_pattern_t;

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

static Node *create_condition_node(ConditionType type, const char *value)
{
    Node *node = malloc(sizeof(Node));
    node->type = NODE_CONDITION;
    node->data.condition.cond_type = type;
    if (type == TOKEN_HOST)
    {
        if (strlen(value) >= 4 && strncmp(value, "nic.", 4) == 0)
        {
            char errbuf[ERROR_BUFFER_SIZE];
            if (get_if_addr(value + 4, &node->data.condition.addr, errbuf) == 0)
            {
                char buf[INET6_ADDRSTRLEN];
                format_ip_addr(&node->data.condition.addr, buf, sizeof(buf));
                log_info("req_pattern interface %s addresss is %s", value + 4, buf);
                return node;
            }

            log_error("get_if_addr error: %s", errbuf);
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
        node->data.condition.port = atoi(value);
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
static Node *parse_expression(char **input, Token *current_token);
static Node *parse_term(char **input, Token *current_token);
static Node *parse_factor(char **input, Token *current_token);
static Node *parse_condition(char **input, Token *current_token);

static void next_token(char **input, Token *current_token) { *current_token = get_next_token(input); }

static Node *parse_expression(char **input, Token *current_token)
{
    Node *left = parse_term(input, current_token);
    if (!left)
        return NULL;

    while (current_token->type == TOKEN_OR)
    {
        next_token(input, current_token);
        Node *right = parse_term(input, current_token);
        if (!right)
        {
            free_ast(left);
            return NULL;
        }
        left = create_operator_node(OP_OR, left, right);
    }
    return left;
}

static Node *parse_term(char **input, Token *current_token)
{
    Node *left = parse_factor(input, current_token);
    if (!left)
        return NULL;

    while (current_token->type == TOKEN_AND)
    {
        next_token(input, current_token);
        Node *right = parse_factor(input, current_token);
        if (!right)
        {
            free_ast(left);
            return NULL;
        }
        left = create_operator_node(OP_AND, left, right);
    }
    return left;
}

static Node *parse_factor(char **input, Token *current_token)
{
    if (current_token->type == TOKEN_LPAREN)
    {
        next_token(input, current_token);
        Node *expr = parse_expression(input, current_token);
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
        return parse_condition(input, current_token);
    }
}

static Node *parse_condition(char **input, Token *current_token)
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
        Node *node = create_condition_node(COND_HOST, value);
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
        Node *node = create_condition_node(COND_PORT, value);
        free(value);
        return node;
    }
    return NULL;
}

static bool evaluate(Node *node, const struct in_addr *ip, uint32_t port)
{
    if (!node)
        return false;

    if (node->type == NODE_CONDITION)
    {
        if (node->data.condition.cond_type == COND_HOST)
        {
            if (node->data.condition.addr.type == IP_TYPE_IPv4)
                return node->data.condition.addr.data.v4.s_addr == ip->s_addr;
            else
                return false;
        }
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

void req_pattern_destory(req_pattern_t *req_pattern)
{
    if (!req_pattern)
        return;

    if (req_pattern->type == REQ_PATTERN_TYPE_CUSTOM)
        free_ast(req_pattern->matcher.custom.node);

    free(req_pattern);
}

static int req_pattern_custom_matcher_init(req_pattern_custom_matcher_t *matcher, const char *pattern)
{
    // pattern example:
    // 1. host nic.eth0 and port 8011
    // 2. (host 172.16.1.1 or host 172.16.1.2) and port 8011
    // 3. host 172.16.1.1 and (port 8011 or port 8012)
    // 4. (host 172.16.1.1 or host 172.16.1.2) and (port 8011 or port 8012)

    char *pos = (char *)pattern;
    Token token;
    next_token(&pos, &token);
    Node *ast = parse_expression(&pos, &token);
    if (!ast)
        return -1;

    matcher->node = ast;
    return 0;
}

req_pattern_t *req_pattern_new_from_cfg(ReqPatternConfig cfg, const char *interface, char *errbuf)
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
        if (get_mac_addr(interface, req_pattern->matcher._auto.mac_addr, errbuf) != 0)
            goto error;

        req_pattern->type = REQ_PATTERN_TYPE_AUTO;

        char mac_addr_str[MAC_ADDR_STR_BUFSIZE];
        format_mac_addr(req_pattern->matcher._auto.mac_addr, mac_addr_str);
        log_info("interface '%s' mac addr: %s", interface, mac_addr_str);
    }
    else if (strcmp(cfg.type, REQ_PATTERN_TYPE_CUSTOM_STR) == 0)
    {
        if (req_pattern_custom_matcher_init(&req_pattern->matcher.custom, cfg.custom.pattern) != 0)
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

static bool req_pattern_custom_match_by_ipport(req_pattern_custom_matcher_t *matcher, const struct in_addr *ip,
                                               const uint16_t port)
{
    return evaluate(matcher->node, ip, port);
}

static int req_pattern_custom_judge_pkt_dir(req_pattern_custom_matcher_t *matcher, const struct pcap_pkthdr *header,
                                            const uint8_t *pkt_data, size_t ip_hdr_offset)
{
    struct iphdr *ip_hdr = (struct iphdr *)(pkt_data + ip_hdr_offset);
    size_t ip_hdr_len = ip_hdr->ihl * 4;
    uint16_t sport = 0;
    uint16_t dport = 0;

    switch (ip_hdr->protocol)
    {
    case IPPROTO_TCP:
        struct tcphdr *tcp_hdr = (struct tcphdr *)(pkt_data + ip_hdr_offset + ip_hdr_len);
        sport = ntohs(tcp_hdr->source);
        dport = ntohs(tcp_hdr->dest);
        break;
    case IPPROTO_UDP:
        struct udphdr *udp_hdr = (struct udphdr *)(pkt_data + ip_hdr_offset + ip_hdr_len);
        sport = ntohs(udp_hdr->source);
        dport = ntohs(udp_hdr->dest);

        // TODO: check vxlan
        break;
    }

    if (req_pattern_custom_match_by_ipport(matcher, (const struct in_addr *)&ip_hdr->saddr, sport))
        return PKT_DIR_OUTGOING;
    else if (req_pattern_custom_match_by_ipport(matcher, (const struct in_addr *)&ip_hdr->daddr, dport))
        return PKT_DIR_INCOMING;
    else
        return PKT_DIR_UNKNOWN;
}

int req_pattern_judge_pkt_direction(req_pattern_t *req_pattern, const struct pcap_pkthdr *header,
                                    const uint8_t *pkt_data)
{
    struct ether_header *eth_hdr;
    eth_hdr = (struct ether_header *)pkt_data;

    if (req_pattern->type == REQ_PATTERN_TYPE_AUTO)
    {
        if (memcmp(eth_hdr->ether_shost, req_pattern->matcher._auto.mac_addr, ETH_ALEN) == 0)
            return PKT_DIR_OUTGOING;
        else
            return PKT_DIR_INCOMING;
    }

    size_t eth_hdr_len = sizeof(struct ether_header);
    uint16_t eth_type = ntohs(eth_hdr->ether_type);
    switch (eth_type)
    {
    case ETHERTYPE_IP:
        if (req_pattern->type == REQ_PATTERN_TYPE_NONE)
            return PKT_DIR_NONCHECK;

        if (req_pattern->type == REQ_PATTERN_TYPE_CUSTOM)
            return req_pattern_custom_judge_pkt_dir(&req_pattern->matcher.custom, header, pkt_data, eth_hdr_len);
    case ETHERTYPE_VLAN:
        if (req_pattern->type == REQ_PATTERN_TYPE_NONE)
            return PKT_DIR_NONCHECK;

        if (req_pattern->type == REQ_PATTERN_TYPE_CUSTOM)
        {
            struct vlanhdr *vlan_hdr = (struct vlanhdr *)(pkt_data + eth_hdr_len);
            uint16_t h_proto = ntohs(vlan_hdr->h_proto);
            switch (h_proto)
            {
            case ETHERTYPE_IP:
                return req_pattern_custom_judge_pkt_dir(&req_pattern->matcher.custom, header, pkt_data,
                                                        eth_hdr_len + VLAN_TAG_LEN);
            default:
                break;
            }
        }
        break;
    default:
        // other protocols
        break;
    }
    return PKT_DIR_UNKNOWN;
}
