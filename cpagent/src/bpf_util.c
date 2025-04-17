#include <ctype.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_util.h"
#include "errorf.h"
#include "log.h"

char *bpf_filter_replace_nic(const char *bpf, get_if_ip_addr_fn get_ip, char *errbuf)
{
    size_t buf_size = strlen(bpf) * 2;
    char *output = malloc(buf_size);
    char *out_ptr = output;
    const char *in_ptr = bpf;

    while (*in_ptr)
    {
        if (strncmp(in_ptr, "nic.", 4) != 0)
        {
            *out_ptr++ = *in_ptr++;
            continue;
        }

        const char *end = in_ptr + 4;
        while (*end && !isspace(*end))
            end++;

        int ifname_len = end - (in_ptr + 4);
        char ifname[ifname_len + 1];
        strncpy(ifname, in_ptr + 4, ifname_len);
        ifname[ifname_len] = '\0';

        char errbuf[ERROR_BUFFER_SIZE];
        ip_addr_t addr;
        if (get_ip(ifname, &addr, errbuf) != 0)
        {
            error_format(errbuf, "no ip found for interface %s", ifname);
            free(output);
            return NULL;
        }
        char ip_str[INET6_ADDRSTRLEN];
        format_ip_addr(&addr, ip_str, sizeof(ip_str));
        log_info("bpf_filter interface %s addresss is %s", ifname, ip_str);

        size_t ip_len = strlen(ip_str);
        size_t offset = out_ptr - output;
        size_t remaining = buf_size - offset - 1;
        if (ip_len > remaining)
        {
            buf_size += ip_len * 2;
            output = realloc(output, buf_size);
            out_ptr = output + offset;
        }

        strncpy(out_ptr, ip_str, ip_len);
        out_ptr += ip_len;
        in_ptr = end;
    }
    *out_ptr = '\0';
    return output;
}
