#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "common.h"
#include "error.h"
#include "log.h"
#include "task.h"
#include "taskconf.h"
#include "unix-manager.h"

#ifdef ENABLE_DPDK
#include "dpdk_pdump.h"
#endif

/* command line flags */
static const char *progname;
static const char *tasks_file = NULL;
static bool enable_dpdk_dumpcap = false;
static int cpu_id = -1;
static const char *unix_socket = "/var/run/cpagent/cpagent.sock";

static bool quit_signal;
static const char *version(void)
{
    static char str[128];

    snprintf(str, sizeof(str), "%s 1.0\n", progname);
    return str;
}

static unsigned long get_uint(const char *arg, const char *name, unsigned int limit)
{
    unsigned long u;
    char *endp;

    u = strtoul(arg, &endp, 0);
    if (*arg == '\0' || *endp != '\0')
    {
        fprintf(stderr, "Specified %s \"%s\" is not a valid number\n", name, arg);
        exit(EXIT_FAILURE);
    }

    if (limit && u > limit)
    {
        fprintf(stderr, "Specified %s \"%s\" is too large (greater than %u)\n", name, arg, limit);
        exit(EXIT_FAILURE);
    }

    return u;
}

static void usage(void)
{
    printf("Usage: %s [options] ...\n\n", progname);
    printf("  -T, --tasks <file>      specify tasks config file\n");
#ifdef ENABLE_DPDK
    printf("  --enable-dpdk-dumpcap   enable dpdk-dumpcap\n");
#endif
    printf("  --cpu <cpu1>            set cpu affinity\n");
    printf("  --unix-socket <file>    use unix socket to control suricata work\n");
    printf("  -v, --version           print version information and exit\n");
    printf("  -h, --help              display this help and exit\n");
}

/* 定义长选项的标识符 */
enum
{
    OPT_ENABLE_DPDK_DUMPCAP = 256,
    OPT_CPU_ID,
    OPT_UNIX_SOCKET
};

static void parse_opts(int argc, char **argv)
{
    struct option long_options[] = {
        {"tasks", required_argument, NULL, 'T'},
        {"enable-dpdk-dumpcap", no_argument, NULL, OPT_ENABLE_DPDK_DUMPCAP},
        {"cpu", required_argument, NULL, OPT_CPU_ID},
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
        case OPT_CPU_ID:
            cpu_id = get_uint(optarg, "cpu", 0);
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

#ifdef ENABLE_DPDK
    if (enable_dpdk_dumpcap)
    {
        if (dpdk_init(errbuf) != 0)
        {
            log_fatal(errbuf);
            exit(EXIT_FAILURE);
        }
    }
#endif

    if (cpu_id >= 0)
    {
        if (set_cpu_affinity(cpu_id) != 0)
        {
            log_fatal("set cpu affinity fail");
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

    task_manager_init(config);

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    if (unix_manager_init(unix_socket) != 0)
    {
        log_fatal("init unix socket failed");
        task_manager_destory();
        exit(EXIT_FAILURE);
    }
    if (unix_manager_thread_spawn() != 0)
    {
        log_fatal("create unix socket thread failed");
        task_manager_destory();
        exit(EXIT_FAILURE);
    }

    unix_manager_register_command("collect_stats", task_manager_collect_stats_command, NULL);

    time_t last_tm = time(NULL);
    while (!__atomic_load_n(&quit_signal, __ATOMIC_RELAXED))
    {
        uint64_t num_pkts = task_manager_poll_packets();
        if (num_pkts == 0)
            usleep(10);

        time_t now = time(NULL);
        // every 5 seconds
        if (difftime(now, last_tm) >= 5)
        {
            task_manager_update_stats();
            last_tm = now;
        }
    }

    log_info("quit");
    task_manager_destory();
    return 0;
}