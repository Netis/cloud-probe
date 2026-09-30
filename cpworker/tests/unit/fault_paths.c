/* Error and cleanup paths that normal operation never reaches: allocation failures,
 * a failing setns, and stopping a thread before it has run. The hooks in fault_hooks.c
 * make each of them deterministic. */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <pcap/pcap.h>

#include "unity/src/unity.h"

#include "cJSON/cJSON.h"
#include "config.h"
#include "fault_hooks.h"
#include "libpcap.h"
#include "stats.h"
#include "task.h"

void setUp(void) {}

void tearDown(void)
{
    fault_alloc_fail_nth(-1);
    fault_setns_fail_nth(-1);
    fault_thread_start_delay_ms(0);
}

/* ---------- #262: free_config releases everything parsing allocates ---------- */

static void assert_parse_and_free_does_not_leak(const char *json)
{
    long before = fault_alloc_live();

    cJSONParseError err = {0};
    Config *config = parse_config_data(json, &err);
    TEST_ASSERT_NOT_NULL_MESSAGE(config, err.message);
    free_config(config);

    TEST_ASSERT_EQUAL_INT64(before, fault_alloc_live());
}

void test_free_config_releases_task_fingerprint(void)
{
    assert_parse_and_free_does_not_leak(
        "{\"tasks\": [{\"fingerprint\": \"fp-1\", "
        "\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\"}}, "
        "\"outputs\": [{\"type\": \"null\"}]}]}");
}

void test_free_config_releases_rotating_file_root(void)
{
    assert_parse_and_free_does_not_leak(
        "{\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": {\"interface\": \"eth0\"}}, "
        "\"outputs\": [{\"type\": \"rotating_file\", \"rotating_file\": {\"file_root\": \"/tmp\"}}]}]}");
}

void test_duplicate_fingerprint_rejected_without_leak(void)
{
    long before = fault_alloc_live();

    cJSONParseError err = {0};
    Config *config = parse_config_data("{\"tasks\": ["
                                       "{\"fingerprint\": \"same\", \"capturer\": {\"type\": \"libpcap\", "
                                       "\"libpcap\": {\"interface\": \"eth0\"}}, \"outputs\": [{\"type\": \"null\"}]},"
                                       "{\"fingerprint\": \"same\", \"capturer\": {\"type\": \"libpcap\", "
                                       "\"libpcap\": {\"interface\": \"eth1\"}}, \"outputs\": [{\"type\": \"null\"}]}"
                                       "]}",
                                       &err);
    TEST_ASSERT_NULL(config);
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err.message, "duplicate fingerprint 'same'"), err.message);

    TEST_ASSERT_EQUAL_INT64(before, fault_alloc_live());
}

/* ---------- #268: a failed netns restore does not return into the wrong namespace ---------- */

#define CHILD_SKIP 77
#define CHILD_EXITED_ON_ERROR_PATH 3

/* errbuf stays empty until the constructor fails. An exit() with a non-empty errbuf came from
 * the restore on the error path, not the one on the success path this test is about. */
static char child_errbuf[ERROR_BUFFER_SIZE];

static void check_exit_came_from_success_path(void)
{
    if (child_errbuf[0] != '\0')
    {
        fprintf(stderr, "exited after an earlier failure: %s\n", child_errbuf);
        _exit(CHILD_EXITED_ON_ERROR_PATH);
    }
}

static bool can_capture_on_lo(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *p = pcap_create("lo", errbuf);
    if (!p)
        return false;
    int ret = pcap_activate(p);
    pcap_close(p);
    return ret >= 0;
}

void test_libpcap_netns_restore_failure_exits(void)
{
    /* The child exits through exit(), which would print Unity's buffered output a second time. */
    fflush(stdout);
    pid_t pid = fork();
    TEST_ASSERT_NOT_EQUAL(-1, pid);
    if (pid == 0)
    {
        if (!can_capture_on_lo())
            _exit(CHILD_SKIP);

        /* setns #0 enters the namespace (faked), setns #1 restores it and fails. */
        fault_setns_fail_nth(1);

        libpcap_options_t opts = {
            .interface = "lo",
            .snaplen = 2048,
            .timeout_ms = 10,
            .buffer_size = 1024 * 1024,
            .bpf_filter = "",
            .netns = "/proc/self/ns/net",
            .req_pattern = {.type = REQ_PATTERN_TYPE_NONE_STR},
        };
        capture_stats_t stats;
        memset(&stats, 0, sizeof(stats));
        child_errbuf[0] = '\0';
        atexit(check_exit_came_from_success_path);
        libpcap_capturer_new(opts, &stats, child_errbuf);
        _exit(0);
    }

    int status;
    TEST_ASSERT_EQUAL(pid, waitpid(pid, &status, 0));
    if (WIFEXITED(status) && WEXITSTATUS(status) == CHILD_SKIP)
        TEST_IGNORE_MESSAGE("needs CAP_NET_RAW to open lo");

    TEST_ASSERT_TRUE_MESSAGE(WIFEXITED(status), "child was killed by a signal");
    TEST_ASSERT_NOT_EQUAL_MESSAGE(CHILD_EXITED_ON_ERROR_PATH, WEXITSTATUS(status),
                                  "the constructor failed before the success-path restore");
    TEST_ASSERT_EQUAL_INT(EXIT_FAILURE, WEXITSTATUS(status));
}

/* ---------- #272: collect_stats_summary under allocation failure ---------- */

void test_stats_summary_survives_every_allocation_failure(void)
{
    for (long n = 0;; n++)
    {
        long before = fault_alloc_live();
        cJSON *server_msg = cJSON_CreateObject();
        TEST_ASSERT_NOT_NULL(server_msg);

        fault_alloc_fail_nth(n);
        int ret = task_manager_collect_stats_summary_command(NULL, server_msg, NULL);
        bool fired = fault_alloc_fired();
        fault_alloc_fail_nth(-1);

        cJSON_Delete(server_msg);

        char msg[64];
        snprintf(msg, sizeof(msg), "allocation #%ld failed", n);
        TEST_ASSERT_EQUAL_INT64_MESSAGE(before, fault_alloc_live(), msg);
        if (!fired)
        {
            TEST_ASSERT_EQUAL_INT(0, ret);
            break;
        }
        TEST_ASSERT_EQUAL_INT_MESSAGE(-1, ret, msg);
    }
}

/* ---------- #273: stop right after start stops the thread ---------- */

void test_output_thread_stop_right_after_start_joins_it(void)
{
    cJSONParseError err = {0};
    Config *config = parse_config_data(
        "{\"execution_model\": \"pipeline\", \"pipeline\": {\"buffer_size_mb\": 1}, \"tasks\": []}", &err);
    TEST_ASSERT_NOT_NULL_MESSAGE(config, err.message);
    TEST_ASSERT_EQUAL_INT(0, task_manager_init(config));

    int finished = fault_threads_finished();
    fault_thread_start_delay_ms(100);
    TEST_ASSERT_EQUAL_INT(0, task_manager_start(NULL));
    task_manager_stop();
    fault_thread_start_delay_ms(0);

    TEST_ASSERT_EQUAL_INT(finished + 1, fault_threads_finished());
    task_manager_destroy();
}

void test_reload_thread_stop_right_after_start_joins_it(void)
{
    int finished = fault_threads_finished();
    fault_thread_start_delay_ms(100);
    TEST_ASSERT_EQUAL_INT(0, task_manager_start_reload_thread("/nonexistent/cpworker.json"));
    task_manager_stop_reload_thread();
    fault_thread_start_delay_ms(0);

    TEST_ASSERT_EQUAL_INT(finished + 1, fault_threads_finished());

    /* The thread is really gone, so a new one can be started. */
    TEST_ASSERT_EQUAL_INT(0, task_manager_start_reload_thread("/nonexistent/cpworker.json"));
    task_manager_stop_reload_thread();
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_free_config_releases_task_fingerprint);
    RUN_TEST(test_free_config_releases_rotating_file_root);
    RUN_TEST(test_duplicate_fingerprint_rejected_without_leak);
    RUN_TEST(test_libpcap_netns_restore_failure_exits);
    RUN_TEST(test_stats_summary_survives_every_allocation_failure);
    RUN_TEST(test_output_thread_stop_right_after_start_joins_it);
    RUN_TEST(test_reload_thread_stop_right_after_start_joins_it);
    return UNITY_END();
}
