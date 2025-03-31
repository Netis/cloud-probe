#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "common.h"
#include "error.h"
#include "log.h"
#include "output_rotating_file.h"

static int generate_path(const char *root_dir, struct tm *ptm, char *filepath, char *errbuf)
{
    char date[15];
    sprintf(date, "%04d%02d%02d%02d%02d%02d", ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour,
            ptm->tm_min, ptm->tm_sec);

    char subPath[11];
    sprintf(subPath, "%04d%02d%02d%02d", ptm->tm_year + 1900, ptm->tm_mon + 1, ptm->tm_mday, ptm->tm_hour);

    size_t root_len = strlen(root_dir);
    const char *separator = "";
    if (root_len > 0 && root_dir[root_len - 1] != '/')
        separator = "/";

    char currDir[PATH_MAX];
    snprintf(currDir, sizeof(currDir), "%s%s%s/", root_dir, separator, subPath);

    struct stat st;
    if (stat(currDir, &st) != 0)
    {
        if (mkdir(currDir, 0755) != 0)
        {
            error_format(errbuf, "create path %s error: %s", currDir, strerror(errno));
            return -1;
        }
    }

    snprintf(filepath, PATH_MAX, "%s/pktminerg_dump_%s.pcap", currDir, date);
    return 0;
}

static int create_dumper(rotating_file_output_t *output, char *errbuf)
{
    struct tm tm_buf;
    struct tm *ptm = localtime_r(&output->file_time, &tm_buf);
    char filepath[PATH_MAX];
    if (generate_path(output->file_root, ptm, filepath, errbuf) != 0)
    {
        return -1;
    }

    FILE *fp = fopen(filepath, "w+");
    if (!fp)
    {
        return -1;
    }
    rewind(fp);

    pcap_dumper_t *dumper = pcap_dump_fopen(output->pcap, fp);
    if (!dumper)
    {
        fclose(fp);
        return -1;
    }

    output->dumper = dumper;
    output->fp = fp;
    return 0;
}

int rotating_file_write_packet(output_base_t *self, const struct pcap_pkthdr *header, const uint8_t *pkt_data,
                               int direct)
{
    rotating_file_output_t *output = (rotating_file_output_t *)self;

    if (direct == PKT_DIR_UNKNOWN)
    {
        bytes_stats_add(&output->base.stats.direction_drop_bytes, header->caplen);
        packets_stats_add(&output->base.stats.direction_drop_packets, 1);
        return -1;
    }

    if (output->dumper_error)
    {
        // avoid frequent creation
        time_t now = time(NULL);
        if (difftime(now, output->file_time) < output->max_file_interval)
        {
            bytes_stats_add(&output->base.stats.error_drop_bytes, header->caplen);
            packets_stats_add(&output->base.stats.error_drop_packets, 1);
            return -1;
        }
    }
    else if (output->dumper == NULL)
    {
        time(&output->file_time);
        char errbuf[ERROR_BUFFER_SIZE];
        if (create_dumper(output, errbuf) != 0)
        {
            output->dumper_error = true;
            bytes_stats_add(&output->base.stats.error_drop_bytes, header->caplen);
            packets_stats_add(&output->base.stats.error_drop_packets, 1);
            return -1;
        }
        output->dumper_error = false;
    }
    else
    {
        time_t now = time(NULL);
        if (difftime(now, output->file_time) >= output->max_file_interval)
        {
            pcap_dump_close(output->dumper);
            output->file_time = now;
            output->dumper = NULL;
            output->fp = NULL;

            char errbuf[ERROR_BUFFER_SIZE];
            if (create_dumper(output, errbuf) != 0)
            {
                output->dumper_error = true;
                bytes_stats_add(&output->base.stats.error_drop_bytes, header->caplen);
                packets_stats_add(&output->base.stats.error_drop_packets, 1);
                return -1;
            }
            output->dumper_error = false;
        }
    }

    pcap_dump((u_char *)output->dumper, header, pkt_data);
    return 0;
}

rotating_file_output_t *rotating_file_output_new(rotating_file_options_t opts, char *errbuf)
{
    struct stat st;
    if (stat(opts.file_root, &st) != 0)
    {
        error_format(errbuf, "stat file_root %s error: %s", opts.file_root, strerror(errno));
        return NULL;
    }

    pcap_t *pcap;
    pcap = pcap_open_dead(DLT_EN10MB, opts.snaplen);
    if (!pcap)
    {
        error_format(errbuf, "pcap_open_dead failed");
        return NULL;
    }

    rotating_file_output_t *output = (rotating_file_output_t *)calloc(1, sizeof(rotating_file_output_t));
    if (!output)
    {
        error_format(errbuf, "failed to allocate memory for rotating_file_output_t");
        return NULL;
    }
    output->base.send_packet = rotating_file_write_packet;
    output->base.destory = rotating_file_output_destory;

    output->slice = opts.slice;
    output->file_root = strdup(opts.file_root);
    output->max_file_interval = opts.max_file_interval;
    output->pcap = pcap;
    return output;
}

output_base_t *rotating_file_output_new_from_cfg(TaskConfig *task_cfg, OutputConfig *output_cfg, char *errbuf)
{
    rotating_file_options_t opts = {
        .file_root = output_cfg->config.rotating_file.file_root,
        .max_file_interval = output_cfg->config.rotating_file.max_file_interval,
        .snaplen = task_cfg->snaplen,
        .slice = output_cfg->slice,
    };
    return (output_base_t *)rotating_file_output_new(opts, errbuf);
}

void rotating_file_output_destory(output_base_t *self)
{
    if (!self)
        return;

    log_info("call rotating_file_output_destory");
    rotating_file_output_t *output = (rotating_file_output_t *)self;

    free(output->file_root);

    if (output->dumper)
        pcap_dump_close(output->dumper);

    pcap_close(output->pcap);
    free(output);
}
