#include "utils.h"
#include "error.h"
#include <pcap/bpf.h>
#include <pcap/pcap.h>
#include <stdio.h>
#include <stdlib.h>

int compile_filter(const char *filter_str, char *errbuf)
{
    struct bpf_program bf;
    pcap_t *pcap;

    pcap = pcap_open_dead(DLT_EN10MB, 2048);
    if (!pcap)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "can not open pcap");
        return -1;
    }

    if (pcap_compile(pcap, &bf, filter_str, 1, PCAP_NETMASK_UNKNOWN) != 0)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "pcap filter string not valid (%s)", pcap_geterr(pcap));
        return -1;
    }

    /* Don't care about original program any more */
    pcap_freecode(&bf);
    pcap_close(pcap);
}