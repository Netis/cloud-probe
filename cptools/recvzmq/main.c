#include <getopt.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <zmq.h>

/* command line flags */
static const char *progname;
static const char *bind_address = "tcp://*:5555";

static void usage(void)
{
    printf("Usage: %s [options] ...\n\n", progname);
    printf("  -b --bind <address>    specify zmq bind address\n");
    printf("  -h, --help             display this help and exit\n");
}

static void parse_opts(int argc, char **argv)
{
    struct option long_options[] = {
        {"bind", required_argument, NULL, 'b'},
        {"help", no_argument, NULL, 'h'},
        {NULL, 0, NULL, 0},
    };

    int c;
    while ((c = getopt_long(argc, argv, "b:h", long_options, NULL)) != -1)
    {
        switch (c)
        {
        case 'b':
            bind_address = optarg;
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

    while (1)
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

        printf("received message size: %d\n", recv_size);
        zmq_msg_close(&msg);
    }

    zmq_close(puller);
    zmq_ctx_destroy(context);
    return EXIT_SUCCESS;
}