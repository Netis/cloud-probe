#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include <pcap/pcap.h>

#include "error.h"
#include "log.h"
#include "output_file.h"

int file_write_packet(output_base_t *self, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct)
{
    file_output_t *output = (file_output_t *)self;
    pcap_dump((u_char *)output->dumper, header, pkt_data);
    return 0;
}

file_output_t *new_file_output(const char *name, uint32_t snaplen, char *errbuf)
{
    FILE *fp = fopen(name, "w+");
    if (!fp)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "open file %s error: %s", name, strerror(errno));
        return NULL;
    }
    rewind(fp);

    pcap_t *pcap;
    pcap = pcap_open_dead_with_tstamp_precision(DLT_EN10MB, snaplen, PCAP_TSTAMP_PRECISION_NANO);
    if (!pcap)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "pcap_open_dead failed");
        fclose(fp);
        return NULL;
    }

    pcap_dumper_t *dumper = pcap_dump_fopen(pcap, fp);
    if (!dumper)
    {
        fclose(fp);
        snprintf(errbuf, ERROR_BUFFER_SIZE, "pcap_dump_fopen failed: %s", pcap_geterr(pcap));
        return NULL;
    }

    file_output_t *output = (file_output_t *)calloc(1, sizeof(file_output_t));
    if (!output)
    {
        snprintf(errbuf, ERROR_BUFFER_SIZE, "failed to allocate memory for file_output_t");
        pcap_dump_close(dumper);
        return NULL;
    }

    output->base.send_packet = file_write_packet;
    output->base.destory = free_file_output;

    output->fp = fp;
    output->dumper = dumper;
    return output;
}

void free_file_output(output_base_t *self)
{
    if (!self)
        return;

    log_info("call free_file_output");
    file_output_t *output = (file_output_t *)self;

    pcap_dump_close(output->dumper);
    free(output);
}