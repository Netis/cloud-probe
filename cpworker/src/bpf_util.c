#include <ctype.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_util.h"
#include "errorf.h"
#include "log.h"

#define NIC_TOKEN_PREFIX "nic."
#define NIC_TOKEN_PREFIX_LEN (sizeof(NIC_TOKEN_PREFIX) - 1)

typedef struct
{
    char *data;
    size_t len;
    size_t cap;
} bpf_buf_t;

// Appends n bytes and keeps the buffer NUL-terminated, growing it as needed.
static bool bpf_buf_append(bpf_buf_t *buf, const char *s, size_t n)
{
    if (buf->len + n + 1 > buf->cap)
    {
        size_t cap = buf->cap;
        while (buf->len + n + 1 > cap)
            cap *= 2;
        char *data = realloc(buf->data, cap);
        if (!data)
            return false;
        buf->data = data;
        buf->cap = cap;
    }
    memcpy(buf->data + buf->len, s, n);
    buf->len += n;
    buf->data[buf->len] = '\0';
    return true;
}

// A nic.<if> token is delimited by whitespace or parentheses. Linux allows parentheses in interface names, but
// such a name cannot be written in a BPF expression anyway: the BPF lexer also treats them as syntax.
static bool is_token_delim(char c) { return c == '\0' || isspace((unsigned char)c) || c == '(' || c == ')'; }

static bool is_nic_token_start(const char *bpf, const char *p)
{
    return strncmp(p, NIC_TOKEN_PREFIX, NIC_TOKEN_PREFIX_LEN) == 0 && (p == bpf || is_token_delim(p[-1]));
}

char *bpf_filter_replace_nic(const char *bpf, get_if_ip_addr_fn get_ip, char *errbuf)
{
    bpf_buf_t out = {.len = 0, .cap = strlen(bpf) + 1};
    out.data = malloc(out.cap);
    if (!out.data)
    {
        error_format(errbuf, "bpf_filter: out of memory");
        return NULL;
    }
    out.data[0] = '\0';

    const char *in_ptr = bpf;
    while (*in_ptr)
    {
        // Copy the plain text up to the next token in one go
        const char *plain = in_ptr;
        while (*in_ptr && !is_nic_token_start(bpf, in_ptr))
            in_ptr++;
        if (!bpf_buf_append(&out, plain, in_ptr - plain))
            goto oom;
        if (!*in_ptr)
            break;

        const char *name = in_ptr + NIC_TOKEN_PREFIX_LEN;
        const char *end = name;
        while (!is_token_delim(*end))
            end++;

        size_t ifname_len = end - name;
        if (ifname_len == 0 || ifname_len >= IF_NAMESIZE)
        {
            error_format(errbuf, "invalid interface name in bpf_filter: %.*s", (int)(end - in_ptr), in_ptr);
            free(out.data);
            return NULL;
        }
        char ifname[IF_NAMESIZE];
        memcpy(ifname, name, ifname_len);
        ifname[ifname_len] = '\0';

        ip_addr_t addr;
        if (get_ip(ifname, &addr, errbuf) != 0)
        {
            error_format(errbuf, "no ip found for interface %s", ifname);
            free(out.data);
            return NULL;
        }
        char ip_str[INET6_ADDRSTRLEN];
        format_ip_addr(&addr, ip_str, sizeof(ip_str));
        log_info("bpf_filter interface %s address is %s", ifname, ip_str);

        if (!bpf_buf_append(&out, ip_str, strlen(ip_str)))
            goto oom;
        in_ptr = end;
    }
    return out.data;

oom:
    error_format(errbuf, "bpf_filter: out of memory");
    free(out.data);
    return NULL;
}
