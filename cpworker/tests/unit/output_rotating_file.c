#define _XOPEN_SOURCE 700

#include <dirent.h>
#include <ftw.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "unity/src/unity.h"

#include "output.h"
#include "output_rotating_file.h"
#include "pkt_dir.h"

static char file_root[64];
static output_stats_t stats;

void setUp(void)
{
    memset(&stats, 0, sizeof(stats));
    strcpy(file_root, "/tmp/cpworker_rotating_XXXXXX");
    TEST_ASSERT_NOT_NULL(mkdtemp(file_root));
}

static int remove_entry(const char *path, const struct stat *sb, int typeflag, struct FTW *ftwbuf)
{
    (void)sb;
    (void)typeflag;
    (void)ftwbuf;
    return remove(path);
}

void tearDown(void) { nftw(file_root, remove_entry, 16, FTW_DEPTH | FTW_PHYS); }

static void write_packets(int max_file_interval, int count)
{
    char errbuf[256];
    rotating_file_options_t opts = {
        .file_root = file_root,
        .max_file_interval = max_file_interval,
        .snaplen = 2048,
        .slice = 0,
    };
    rotating_file_output_t *output = rotating_file_output_new(opts, &stats, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(output, errbuf);

    uint8_t pkt[64] = {0};
    struct pcap_pkthdr hdr = {.caplen = sizeof(pkt), .len = sizeof(pkt)};
    for (int i = 0; i < count; i++)
        TEST_ASSERT_EQUAL_INT(0, output_send_packet(&output->base, &hdr, pkt, PKT_DIR_NONCHECK));

    destroy_output(&output->base);
}

static int count_packets_in_file(const char *path)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_open_offline(path, errbuf);
    TEST_ASSERT_NOT_NULL_MESSAGE(p, errbuf);
    struct pcap_pkthdr *hdr;
    const u_char *data;
    int n = 0;
    while (pcap_next_ex(p, &hdr, &data) == 1)
        n++;
    pcap_close(p);
    return n;
}

// Files are written as <file_root>/<YYYYMMDDHH>/pktminerg_dump_<YYYYMMDDHHMMSS>.pcap.
static void count_files_and_packets(int *files, int *packets)
{
    *files = 0;
    *packets = 0;
    DIR *root = opendir(file_root);
    TEST_ASSERT_NOT_NULL(root);
    struct dirent *hour;
    while ((hour = readdir(root)) != NULL)
    {
        if (hour->d_name[0] == '.')
            continue;
        char hour_path[512];
        snprintf(hour_path, sizeof(hour_path), "%s/%s", file_root, hour->d_name);
        DIR *dir = opendir(hour_path);
        TEST_ASSERT_NOT_NULL(dir);
        struct dirent *file;
        while ((file = readdir(dir)) != NULL)
        {
            if (file->d_name[0] == '.')
                continue;
            char file_path[1024];
            snprintf(file_path, sizeof(file_path), "%s/%s", hour_path, file->d_name);
            (*files)++;
            *packets += count_packets_in_file(file_path);
        }
        closedir(dir);
    }
    closedir(root);
}

// 0 means never rotate: every packet goes to the one file.
void test_interval_zero_never_rotates(void)
{
    write_packets(0, 5);

    int files, packets;
    count_files_and_packets(&files, &packets);
    TEST_ASSERT_EQUAL_INT(1, files);
    TEST_ASSERT_EQUAL_INT(5, packets);
}

void test_interval_keeps_packets_within_interval(void)
{
    write_packets(60, 5);

    int files, packets;
    count_files_and_packets(&files, &packets);
    TEST_ASSERT_EQUAL_INT(5, packets);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_interval_zero_never_rotates);
    RUN_TEST(test_interval_keeps_packets_within_interval);

    return UNITY_END();
}
