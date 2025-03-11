#include "taskconf.h"
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

/* command line flags */
static const char *progname;
static const char *tasks_file = NULL;
static int enable_dpdk_dumpcap = 0;
static const char *cpu_set = NULL;
static const char *unix_socket = "control.socket";

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
        {NULL},
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
            enable_dpdk_dumpcap = 1;
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
            fprintf(stderr, "Invalid option: %s\n",
                    argv[optind - 1]);
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

static void print_opts()
{
    printf("Task file: %s\n", tasks_file ? tasks_file : "None");
    printf("Enable dpdk dumpcap: %s\n", enable_dpdk_dumpcap ? "Yes" : "No");
    printf("CPU set: %s\n", cpu_set ? cpu_set : "None");
    printf("Unix socket: %s\n", unix_socket ? unix_socket : "None");
}

int main(int argc, char **argv)
{
    progname = argv[0];
    parse_opts(argc, argv);
    print_opts();

    cJSONParseError err;
    TaskSetConfig *config = parse_tasks_file(tasks_file, &err);
    if (!config)
    {
        printf(err.message);
        printf("\n");
        exit(EXIT_FAILURE);
    }
    return 0;
}