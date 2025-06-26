#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "affinity.h"
#include "build_config.h"
#include "config.h"
#include "errorf.h"
#include "log.h"
#include "task.h"
#include "unix-manager.h"

/* command line flags */
static const char *progname;
static const char *config_file = NULL;

static bool quit_signal;

static const char *version(void)
{
    static char str[128];
    snprintf(str, sizeof(str), "version %s (Git-%s)\n", CPWORKER_VERSION, CPWORKER_GIT_COMMIT_HASH);
    return str;
}

static void usage(void)
{
    printf("Usage: %s [options] ...\n\n", progname);
    printf("  -c, --config <file>     specify config file\n");
    printf("  -v, --version           print version information and exit\n");
    printf("  -h, --help              display this help and exit\n");
}

static void parse_opts(int argc, char **argv)
{
    struct option long_options[] = {
        {"config", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {"version", no_argument, NULL, 'v'},
        {NULL, 0, NULL, 0},
    };

    int c;
    while ((c = getopt_long(argc, argv, "c:hv", long_options, NULL)) != -1)
    {
        switch (c)
        {
        case 'c':
            config_file = optarg;
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

    if (config_file == NULL)
    {
        fprintf(stderr, "Error: config file must be specified.\n");
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

    cJSONParseError err;
    Config *config = parse_config_file(config_file, &err);
    if (!config)
    {
        log_fatal(err.message);
        exit(EXIT_FAILURE);
    }

    log_set_level(config->log_level);
    if (strcmp(config->cpu_affinity, "") != 0)
    {
        if (set_cpu_affinity(config->cpu_affinity) != 0)
        {
            log_fatal("set cpu affinity fail: %s", config->cpu_affinity);
            exit(EXIT_FAILURE);
        }
        log_info("set cpu affinity to %d", config->cpu_affinity);
    }

    int total_num_tasks = config->tasks_cfg->num_tasks;
    int inited_num_tasks = task_manager_init(config->tasks_cfg);
    if (inited_num_tasks < 0)
    {
        log_fatal("init tasks failed");
        exit(EXIT_FAILURE);
    }

    log_info("init %d tasks, total %d tasks", inited_num_tasks, total_num_tasks);
    if (inited_num_tasks == 0)
    {
        log_fatal("no task was successfully initialized");
        exit(EXIT_FAILURE);
    }
    // tasks_cfg owned by task_manager
    config->tasks_cfg = NULL;

    bool control_enabled = config->control != NULL;
    bool control_unix_enabled = control_enabled && strcmp(config->control->type, CONTROL_TYPE_UNIX) == 0;
    if (control_unix_enabled)
    {
        if (unix_manager_init(config->control->config.unix_socket.path) != 0)
        {
            log_fatal("init unix socket failed");
            task_manager_destory();
            exit(EXIT_FAILURE);
        }
        log_info("listen on unix socket %s", config->control->config.unix_socket.path);

        unix_manager_register_command("collect_stats_summary", task_manager_collect_stats_summary_command, NULL);
        unix_manager_register_command("collect_stats_detail", task_manager_collect_stats_detail_command, NULL);

        if (unix_manager_thread_spawn() != 0)
        {
            log_fatal("create unix socket thread failed");
            task_manager_destory();
            exit(EXIT_FAILURE);
        }
    }

    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);

    log_info("start poll packets");
    time_t last_tm = time(NULL);
    while (!__atomic_load_n(&quit_signal, __ATOMIC_RELAXED))
    {
        uint64_t num_pkts = task_manager_poll_packets();
        if (num_pkts == 0)
            usleep(10);

        if (control_enabled || inited_num_tasks < total_num_tasks)
        {
            time_t now = time(NULL);
            double delta = difftime(now, last_tm);

            if (control_enabled && delta >= 5)
                task_manager_update_stats();

            if (delta > 60)
                task_manager_print_errors();

            last_tm = now;
        }
    }

    log_info("quit");
    task_manager_destory();
    return 0;
}