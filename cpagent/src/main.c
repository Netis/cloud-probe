#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "dpdk_pdump.h"
#include "error.h"
#include "log.h"
#include "task.h"
#include "taskconf.h"
#include <unistd.h>

/* command line flags */
static const char *progname;
static const char *tasks_file = NULL;
static bool enable_dpdk_dumpcap = false;
static const char *cpu_set = NULL;
static const char *unix_socket = "control.socket";

static bool quit_signal;
static const char *version(void)
{
    static char str[128];

    snprintf(str, sizeof(str), "%s 1.0\n", progname);
    return str;
}

static void usage(void)
{
    printf("Usage: %s [options] ...\n\n", progname);
    printf("  -T, --tasks <file>      specify tasks config file\n");
    printf("  --enable-dpdk-dumpcap   enable dpdk-dumpcap\n");
    printf("  --cpu-set <cpu1,cpu2>   include only these CPUs in affinity settings\n");
    printf("  --unix-socket <file>    use unix socket to control suricata work\n");
    printf("  -v, --version           print version information and exit\n");
    printf("  -h, --help              display this help and exit\n");
}

/* 定义长选项的标识符 */
enum
{
    OPT_ENABLE_DPDK_DUMPCAP = 256,
    OPT_CPU_SET,
    OPT_UNIX_SOCKET
};

static void parse_opts(int argc, char **argv)
{
    struct option long_options[] = {
        {"tasks", required_argument, NULL, 'T'},
        {"enable-dpdk-dumpcap", no_argument, NULL, OPT_ENABLE_DPDK_DUMPCAP},
        {"cpu-set", required_argument, NULL, OPT_CPU_SET},
        {"unix-socket", required_argument, NULL, OPT_UNIX_SOCKET},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0},
    };

    int c;
    while ((c = getopt_long(argc, argv, "T:hv", long_options, NULL)) != -1)
    {
        switch (c)
        {
        case 'T':
            tasks_file = optarg;
            break;
        case OPT_ENABLE_DPDK_DUMPCAP:
            enable_dpdk_dumpcap = true;
            break;
        case OPT_CPU_SET:
            cpu_set = optarg;
            break;
        case OPT_UNIX_SOCKET:
            unix_socket = optarg;
            break;
        case 'h':
            printf("%s\n\n", version());
            usage();
            exit(0);
        case 'v':
            printf("%s\n", version());
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

    if (tasks_file == NULL)
    {
        fprintf(stderr, "Error: tasks config file must be specified.\n");
        usage();
        exit(EXIT_FAILURE);
    }
}

static void signal_handler(int sig_num) { __atomic_store_n(&quit_signal, true, __ATOMIC_RELAXED); }

int main(int argc, char **argv)
{
    char errbuf[ERROR_BUFFER_SIZE];
    progname = argv[0];

    parse_opts(argc, argv);

    if (enable_dpdk_dumpcap)
    {
        if (dpdk_init(errbuf) != 0)
        {
            log_fatal(errbuf);
            exit(EXIT_FAILURE);
        }
    }

    cJSONParseError err;
    TasksAllConfig *config = parse_tasks_file(tasks_file, &err);
    if (!config)
    {
        log_fatal(err.message);
        exit(EXIT_FAILURE);
    }

    int num_tasks = config->num_tasks;
    capture_task_t **tasks = (capture_task_t **)calloc(num_tasks, sizeof(capture_task_t *));
    if (!tasks)
    {
        log_fatal("memory allocation failed");
        exit(EXIT_FAILURE);
    }

    log_info("find tasks %d\n", num_tasks);
    for (int i = 0; i < num_tasks; ++i)
    {
        capture_task_t *task = new_capture_task(config->tasks[i], errbuf);
        if (!task)
        {
            for (int j = 0; j < i; ++j)
                free_capture_task(tasks[j]);

            free(tasks);
            log_fatal("new task-%d error: %s", i, errbuf);
            exit(EXIT_FAILURE);
        }
        log_info("create task-%d success", i);
        tasks[i] = task;
    }

    free_tasks_config(config);

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    while (!__atomic_load_n(&quit_signal, __ATOMIC_RELAXED))
    {
        int num_pkts = 0;
        for (int i = 0; i < num_tasks; ++i)
        {
            num_pkts += task_poll_packets(tasks[i]);
        }

        if (num_pkts == 0)
            usleep(10);
    }

    log_info("quit");
    for (int i = 0; i < num_tasks; ++i)
    {
        log_info("free task: %d", i);
        free_capture_task(tasks[i]);
    }
    free(tasks);

    return 0;
}