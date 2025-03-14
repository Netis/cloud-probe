#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <pcap/pcap.h>

#include "error.h"
#include "libpcap.h"
#include "log.h"

int libpcap_do_capture(capturer_base_t *self, PacketHandler handler, void *user)
{
    libpcap_capturer_t *capturer = (libpcap_capturer_t *)self;

    struct pcap_pkthdr *hdr;
    const u_char *data;
    int ret = pcap_next_ex(capturer->p, &hdr, &data);
    switch (ret)
    {
    case 1:
        handler(hdr, data, user);
        return 1;
    case 0:
        // timeout
        return 0;
    default:
        // error
        return 0;
    }
}

libpcap_capturer_t *new_libpcap_capturer(libpcap_options_t opts, char *errbuf)
{
    char pcap_errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_create(opts.interface, pcap_errbuf);
    if (!p)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "call pcap_create(%s) error: %s", opts.interface, pcap_errbuf);
        return NULL;
    }

    pcap_set_snaplen(p, opts.snaplen);
    pcap_set_timeout(p, opts.timeout_ms);
    pcap_set_promisc(p, opts.promisc);
    pcap_set_buffer_size(p, opts.buffer_size);

    if (pcap_activate(p) != 0)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "call pcap_activate error: %s", pcap_geterr(p));
        goto error;
    }

    if (opts.timeout_ms == 0)
    {
        if (pcap_setnonblock(p, 1, pcap_errbuf) != 0)
        {
            snprintf(errbuf, ERROR_BUFFER_SIZE, "pcap_setnonblock error: %s", pcap_errbuf);
            goto error;
        }
    }

    if (opts.bpf_filter && strcmp(opts.bpf_filter, "") != 0)
    {
        struct bpf_program bpf_prog;
        if (pcap_compile(p, &bpf_prog, opts.bpf_filter, 0, 0) != 0)
        {
            snprintf(errbuf, ERROR_BUFFER_SIZE, "compile bpf filter '%s' error: %s", opts.bpf_filter, pcap_geterr(p));
            goto error;
        }
        if (pcap_setfilter(p, &bpf_prog) != 0)
        {
            snprintf(errbuf, ERROR_BUFFER_SIZE, "call pcap_setfilter error: %s", pcap_geterr(p));
            goto error;
        }
    }

    libpcap_capturer_t *capturer = (libpcap_capturer_t *)calloc(1, sizeof(libpcap_capturer_t));
    if (!capturer)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "failed to allocate memory for libpcap_capturer_t");
        goto error;
    }
    capturer->base.capture = libpcap_do_capture;
    capturer->base.destory = free_libpcap_capturer;
    capturer->p = p;
    return capturer;

error:
    pcap_close(p);
    return NULL;
}

void free_libpcap_capturer(capturer_base_t *self)
{
    if (!self)
        return;

    libpcap_capturer_t *capturer = (libpcap_capturer_t *)self;

    log_info("free libpcap capturer");
    pcap_close(capturer->p);
    free(capturer);
}