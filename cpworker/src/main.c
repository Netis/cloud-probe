#include <getopt.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define PATH_MAX 4096

#include "affinity.h"
#include "build_config.h"
#include "config.h"
#include "errorf.h"
#include "log.h"
#include "task.h"
#include "unix-manager.h"
#include "unix_rpc_basic.h"

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

static void signal_quit_handler(int sig_num) { __atomic_store_n(&quit_signal, true, __ATOMIC_RELAXED); }

static void signal_reload_handler(int sig_num) { task_manager_reload_signal(); }

void register_signals()
{
    signal(SIGINT, signal_quit_handler);
    signal(SIGTERM, signal_quit_handler);
    signal(SIGHUP, signal_reload_handler);
    signal(SIGPIPE, SIG_IGN);
}

int main(int argc, char **argv)
{
    char errbuf[ERROR_BUFFER_SIZE];
    progname = argv[0];
    parse_opts(argc, argv);

    unix_rpc_basic_set_started_at(time(NULL));
    unix_rpc_basic_set_config_path(config_file);

    char cwdbuf[PATH_MAX];
    if (getcwd(cwdbuf, sizeof(cwdbuf)) != NULL)
        unix_rpc_basic_set_working_dir(cwdbuf);

    cJSONParseError err;
    Config *config = parse_config_file(config_file, &err);
    if (!config)
    {
        log_fatal(err.message);
        exit(EXIT_FAILURE);
    }

    log_set_level(config->log_level);
    char *cpu_affinity = strdup(config->cpu_affinity);
    if (strcmp(cpu_affinity, "") != 0)
    {
        if (set_cpu_affinity(cpu_affinity) != 0)
        {
            log_fatal("set cpu affinity to '%s' fail", cpu_affinity);
            exit(EXIT_FAILURE);
        }
        log_info("set cpu affinity to '%s'", cpu_affinity);
    }

    int total_num_tasks = config->tasks_cfg->num_tasks;

    ControlConfig *control = config->control;
    config->control = NULL; // prevent free in task_manager_destroy

    // config moved to task_manager
    int inited_num_tasks = task_manager_init(config);
    if (inited_num_tasks < 0)
    {
        log_fatal("init tasks failed");
        exit(EXIT_FAILURE);
    }

    log_info("init %d tasks, total %d tasks", inited_num_tasks, total_num_tasks);

    bool control_enabled = control != NULL;
    bool control_unix_enabled = control_enabled && strcmp(control->type, CONTROL_TYPE_UNIX) == 0;
    if (control_unix_enabled)
    {
        if (unix_manager_init(control->config.unix_socket.path) != 0)
        {
            log_fatal("init unix socket failed");
            task_manager_destroy();
            exit(EXIT_FAILURE);
        }
        log_info("listen on unix socket %s", control->config.unix_socket.path);

        unix_manager_register_command("collect_stats_summary", task_manager_collect_stats_summary_command, NULL);
        unix_manager_register_command("ping", unix_rpc_ping_command, NULL);
        unix_manager_register_command("info", unix_rpc_info_command, NULL);
        unix_manager_register_command("reload_config", task_manager_reload_config_command, (void *)config_file);

        if (unix_manager_thread_spawn() != 0)
        {
            log_fatal("create unix socket thread failed");
            task_manager_destroy();
            exit(EXIT_FAILURE);
        }
    }

    if (task_manager_start(cpu_affinity) != 0)
    {
        task_manager_destroy();
        exit(EXIT_FAILURE);
    }

    if (task_manager_start_reload_thread(config_file) != 0)
    {
        task_manager_destroy();
        exit(EXIT_FAILURE);
    }

    register_signals();

    log_info("start poll packets");
    time_t last_stats_tm = time(NULL);
    time_t last_error_tm = time(NULL);
    time_t last_reload_tm = time(NULL);
    while (!__atomic_load_n(&quit_signal, __ATOMIC_RELAXED))
    {
        uint64_t num_pkts = task_manager_poll_packets();
        if (num_pkts == 0)
        {
            task_manager_reload_cycle();
            usleep(10);
        }

        time_t now = time(NULL);
        if (control_enabled && difftime(now, last_stats_tm) >= 5)
        {
            task_manager_update_stats();
            last_stats_tm = now;
        }

        if (difftime(now, last_error_tm) >= 60)
        {
            task_manager_print_errors();
            last_error_tm = now;
        }

        if (difftime(now, last_reload_tm) >= 1)
        {
            task_manager_reload_cycle();
            last_reload_tm = now;
        }
    }

    log_info("quit");
    task_manager_stop_reload_thread();
    task_manager_stop();
    task_manager_destroy();
    return 0;
}