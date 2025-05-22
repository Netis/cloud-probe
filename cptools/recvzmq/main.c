#include <getopt.h>
#include <signal.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <arpa/inet.h>

#include <pcap/pcap.h>
#include <zmq.h>

static const char *progname;
static const char *bind_address = "tcp://*:5555";
static const char *out_file = "";

static bool quit_signal;

static void usage(void)
{
    printf("Usage: %s [options] ...\n\n", progname);
    printf("  -b --bind <address>    specify zmq bind address\n");
    printf("  -o --output <file>     write packets to file\n");
    printf("  -h, --help             display this help and exit\n");
}

static void parse_opts(int argc, char **argv)
{
    struct option long_options[] = {
        {"bind", required_argument, NULL, 'b'},
        {"output", required_argument, NULL, 'o'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int c;
    while ((c = getopt_long(argc, argv, "b:o:h", long_options, NULL)) != -1)
    {
        switch (c)
        {
        case 'b':
            bind_address = optarg;
            break;
        case 'o':
            out_file = optarg;
            break;
        case 'h':
            usage();
            exit(0);
        default:
            fprintf(stderr, "Invalid option: %s\n", argv[optind - 1]);
            usage();
            exit(EXIT_FAILURE);
        }
    }

    /* 检查是否有未处理的参数 */
    if (optind < argc)
    {
        fprintf(stderr, "Non-option arguments: ");
        while (optind < argc)
            fprintf(stderr, "%s ", argv[optind++]);
        fprintf(stderr, "\n");
        usage();
        exit(EXIT_FAILURE);
    }
}

#define UUID_STR_BUFSIZE 37
char uuid_str[UUID_STR_BUFSIZE];

void bytes_to_uuid(const uint8_t uuid_bytes[16], char *uuid)
{
    char hex_chars[32];
    for (int i = 0; i < 16; i++)
    {
        hex_chars[i * 2] = "0123456789abcdef"[uuid_bytes[i] >> 4];
        hex_chars[i * 2 + 1] = "0123456789abcdef"[uuid_bytes[i] & 0x0F];
    }

    memcpy(&uuid[0], &hex_chars[0], 8);
    uuid[8] = '-';
    memcpy(&uuid[9], &hex_chars[8], 4);
    uuid[13] = '-';
    memcpy(&uuid[14], &hex_chars[12], 4);
    uuid[18] = '-';
    memcpy(&uuid[19], &hex_chars[16], 4);
    uuid[23] = '-';
    memcpy(&uuid[24], &hex_chars[20], 12);
    uuid[36] = '\0';
}

typedef struct OutputBase
{
    int (*send_packet)(struct OutputBase *output, const struct pcap_pkthdr *header, const uint8_t *pkt_data);
    void (*destory)(struct OutputBase *output);
} output_base_t;

typedef struct FileOutput
{
    output_base_t base;

    pcap_t *pcap;
    FILE *fp;
    pcap_dumper_t *dumper;
} file_output_t;

int file_write_packet(output_base_t *self, const struct pcap_pkthdr *header, const uint8_t *pkt_data)
{
    file_output_t *output = (file_output_t *)self;
    pcap_dump((u_char *)output->dumper, header, pkt_data);
    return 0;
}

void file_output_destory(output_base_t *self)
{
    if (!self)
        return;

    file_output_t *output = (file_output_t *)self;

    pcap_dump_close(output->dumper);
    pcap_close(output->pcap);
    free(output);
}

file_output_t *file_output_new(const char *file_name)
{
    FILE *fp = fopen(file_name, "w+");
    if (!fp)
    {
        printf("open file %s error: %s\n", file_name, strerror(errno));
        return NULL;
    }
    rewind(fp);

    pcap_t *pcap;
    pcap = pcap_open_dead(DLT_EN10MB, 65535);
    if (!pcap)
    {
        printf("pcap_open_dead failed\n");
        fclose(fp);
        return NULL;
    }

    pcap_dumper_t *dumper = pcap_dump_fopen(pcap, fp);
    if (!dumper)
    {
        fclose(fp);
        pcap_close(pcap);
        printf("pcap_dump_fopen failed: %s\n", pcap_geterr(pcap));
        return NULL;
    }

    file_output_t *output = (file_output_t *)calloc(1, sizeof(file_output_t));
    if (!output)
    {
        printf("failed to allocate memory for file_output_t\n");
        pcap_dump_close(dumper);
        pcap_close(pcap);
        return NULL;
    }

    output->base.send_packet = file_write_packet;
    output->base.destory = file_output_destory;

    output->pcap = pcap;
    output->fp = fp;
    output->dumper = dumper;
    return output;
}

#define ZMQ_PKT_DATA_LEN_SIZE 2

typedef struct
{
    uint32_t tv_sec;  // epoc seconds.  caution: unix 2038 problem
    uint32_t tv_usec; // and microseconds
    uint32_t caplen;  // actual capture length
    uint32_t len;     // wire packet length
} zmq_pkt_hdr_t;

typedef struct
{
    uint16_t version;
    uint16_t pkts_num;
    uint32_t keybit;
    uint8_t uuid[16];
} zmq_pkt_batch_hdr_t;

#define HANDLE_ERROR_SIZE 256
char handle_error[HANDLE_ERROR_SIZE];

int handle_zmq_msg(zmq_msg_t *msg, output_base_t *output)
{

    size_t msg_size = zmq_msg_size(msg);
    if (msg_size < sizeof(zmq_pkt_batch_hdr_t))
    {
        snprintf(handle_error, HANDLE_ERROR_SIZE, "msg_size less than sizeof(zmq_pkt_batch_hdr_t)");
        return -1;
    }
    uint8_t *msg_data = zmq_msg_data(msg);
    zmq_pkt_batch_hdr_t *batch_hdr = (zmq_pkt_batch_hdr_t *)msg_data;

    uint16_t pkts_num = ntohs(batch_hdr->pkts_num);
    bytes_to_uuid(batch_hdr->uuid, uuid_str);

    printf("zmq message: size=%ld, packets=%d, uuid=%s\n", msg_size, pkts_num, uuid_str);

    struct pcap_pkthdr header;
    size_t msg_offset = sizeof(zmq_pkt_batch_hdr_t);
    for (int i = 0; i < pkts_num; ++i)
    {
        if ((msg_size - msg_offset) < ZMQ_PKT_DATA_LEN_SIZE + sizeof(zmq_pkt_hdr_t))
        {
            snprintf(handle_error, HANDLE_ERROR_SIZE, "packet %d: remain_size %ld less than 2 + sizeof(zmq_pkt_hdr_t)", i + 1, msg_size - msg_offset);
            return -1;
        }
        uint16_t pkt_data_len;
        memcpy(&pkt_data_len, msg_data + msg_offset, ZMQ_PKT_DATA_LEN_SIZE);
        pkt_data_len = ntohs(pkt_data_len);
        msg_offset += ZMQ_PKT_DATA_LEN_SIZE;

        zmq_pkt_hdr_t *pkt_hdr = (zmq_pkt_hdr_t *)(msg_data + msg_offset);
        msg_offset += sizeof(zmq_pkt_hdr_t);

        if (msg_size - msg_offset < pkt_data_len)
        {
            snprintf(handle_error, HANDLE_ERROR_SIZE, "packet %d: remain_size: %ld less than pkt_data length", i + 1, msg_size - msg_offset);
            return -1;
        }

        header.ts.tv_sec = ntohl(pkt_hdr->tv_sec);
        header.ts.tv_usec = ntohl(pkt_hdr->tv_usec);
        header.caplen = ntohl(pkt_hdr->caplen);
        header.len = ntohl(pkt_hdr->len);
        if (output)
        {
            if (output->send_packet(output, &header, msg_data + msg_offset) != 0)
            {
                snprintf(handle_error, HANDLE_ERROR_SIZE, "packet %d: send_packet error", i + 1);
                return -1;
            }
        }
        msg_offset += pkt_data_len;
    }
    return 0;
}

static void signal_handler(int sig_num) { __atomic_store_n(&quit_signal, true, __ATOMIC_RELAXED); }

int main(int argc, char **argv)
{
    progname = argv[0];
    parse_opts(argc, argv);

    // 1. 初始化 ZeroMQ 上下文
    void *context = zmq_ctx_new();
    if (!context)
    {
        fprintf(stderr, "Failed to create context: %s\n", zmq_strerror(errno));
        return EXIT_FAILURE;
    }

    // 2. 创建 PULL 类型的套接字（接收端）
    void *puller = zmq_socket(context, ZMQ_PULL);
    if (!puller)
    {
        fprintf(stderr, "Failed to create socket: %s\n", zmq_strerror(errno));
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }

    // 3. 绑定到 TCP 地址
    if (zmq_bind(puller, bind_address) != 0)
    {
        fprintf(stderr, "Failed to bind to %s: %s\n", bind_address, zmq_strerror(errno));
        zmq_close(puller);
        zmq_ctx_destroy(context);
        return EXIT_FAILURE;
    }

    printf("waiting for messages from PUSH senders on %s...\n", bind_address);

    output_base_t *output = NULL;
    if (strcmp(out_file, "") != 0)
    {
        output = (output_base_t *)file_output_new(out_file);
        if (output == NULL)
            exit(EXIT_FAILURE);
    }

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    while (!__atomic_load_n(&quit_signal, __ATOMIC_RELAXED))
    {
        zmq_msg_t msg;
        zmq_msg_init(&msg);

        int recv_size = zmq_msg_recv(&msg, puller, 0);
        if (recv_size == -1)
        {
            fprintf(stderr, "failed to receive message: %s\n", zmq_strerror(errno));
            zmq_msg_close(&msg);
            break;
        }

        if (handle_zmq_msg(&msg, output) != 0)
        {
            fprintf(stderr, "%s\n", handle_error);
            zmq_msg_close(&msg);
            break;
        }

        zmq_msg_close(&msg);
    }

    if (output)
        output->destory(output);

    zmq_close(puller);
    zmq_ctx_destroy(context);
    return EXIT_SUCCESS;
}