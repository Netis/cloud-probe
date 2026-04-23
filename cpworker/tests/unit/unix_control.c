/* Tests for the unix-socket control plane:
 *   - unix_rpc_basic: ping / info command handlers
 *   - unix-manager:   SO_SNDTIMEO hardening against a slow reader stalling
 *                     the manager thread in send()
 *
 * Merged into one test binary so the cpworker sources only get compiled once
 * per test run instead of per-file. */

#include <errno.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "unity/src/unity.h"

#include "cJSON/cJSON.h"
#include "unix-manager.h"
#include "unix_rpc_basic.h"

void setUp(void) {}
void tearDown(void) {}

/* ---------- unix_rpc_basic: ping / info ---------- */

void test_ping_command_adds_ts_ms(void)
{
    cJSON *resp = cJSON_CreateObject();
    TEST_ASSERT_NOT_NULL(resp);

    int ret = unix_rpc_ping_command(NULL, resp, NULL);
    TEST_ASSERT_EQUAL(0, ret);

    cJSON *ts = cJSON_GetObjectItemCaseSensitive(resp, "ts_ms");
    TEST_ASSERT_TRUE(cJSON_IsNumber(ts));
    /* should be a recent millisecond timestamp (> year 2020) */
    TEST_ASSERT_GREATER_THAN_INT64(1577836800000LL, (int64_t)ts->valuedouble);

    cJSON_Delete(resp);
}

void test_info_command_returns_expected_fields(void)
{
    time_t fake_start = time(NULL) - 60; /* 60s uptime */
    unix_rpc_basic_set_started_at(fake_start);
    unix_rpc_basic_set_config_path("/tmp/fake-cpworker.json");
    unix_rpc_basic_set_working_dir("/opt/cpworker");

    cJSON *resp = cJSON_CreateObject();
    TEST_ASSERT_NOT_NULL(resp);

    int ret = unix_rpc_info_command(NULL, resp, NULL);
    TEST_ASSERT_EQUAL(0, ret);

    cJSON *version = cJSON_GetObjectItemCaseSensitive(resp, "version");
    TEST_ASSERT_TRUE(cJSON_IsString(version));

    cJSON *pid = cJSON_GetObjectItemCaseSensitive(resp, "pid");
    TEST_ASSERT_TRUE(cJSON_IsNumber(pid));
    TEST_ASSERT_EQUAL(getpid(), (int)pid->valuedouble);

    cJSON *uptime = cJSON_GetObjectItemCaseSensitive(resp, "uptime_sec");
    TEST_ASSERT_TRUE(cJSON_IsNumber(uptime));
    /* uptime should be ~60 (allow drift up to a few seconds) */
    TEST_ASSERT_GREATER_OR_EQUAL_INT(60, (int)uptime->valuedouble);
    TEST_ASSERT_LESS_OR_EQUAL_INT(65, (int)uptime->valuedouble);

    cJSON *started = cJSON_GetObjectItemCaseSensitive(resp, "started_at_sec");
    TEST_ASSERT_TRUE(cJSON_IsNumber(started));
    TEST_ASSERT_EQUAL((int64_t)fake_start, (int64_t)started->valuedouble);

    cJSON *path = cJSON_GetObjectItemCaseSensitive(resp, "config_path");
    TEST_ASSERT_TRUE(cJSON_IsString(path));
    TEST_ASSERT_EQUAL_STRING("/tmp/fake-cpworker.json", path->valuestring);

    cJSON *wd = cJSON_GetObjectItemCaseSensitive(resp, "working_dir");
    TEST_ASSERT_TRUE(cJSON_IsString(wd));
    TEST_ASSERT_EQUAL_STRING("/opt/cpworker", wd->valuestring);

    cJSON *log_dst = cJSON_GetObjectItemCaseSensitive(resp, "log_destination");
    TEST_ASSERT_TRUE(cJSON_IsString(log_dst));
    TEST_ASSERT_EQUAL_STRING("stderr", log_dst->valuestring);

    cJSON_Delete(resp);
}

void test_info_command_handles_unset_config_path(void)
{
    unix_rpc_basic_set_config_path(NULL);
    unix_rpc_basic_set_working_dir(NULL);
    unix_rpc_basic_set_started_at(0);

    cJSON *resp = cJSON_CreateObject();
    TEST_ASSERT_NOT_NULL(resp);

    int ret = unix_rpc_info_command(NULL, resp, NULL);
    TEST_ASSERT_EQUAL(0, ret);

    cJSON *path = cJSON_GetObjectItemCaseSensitive(resp, "config_path");
    TEST_ASSERT_TRUE(cJSON_IsString(path));
    TEST_ASSERT_EQUAL_STRING("", path->valuestring);

    cJSON *wd = cJSON_GetObjectItemCaseSensitive(resp, "working_dir");
    TEST_ASSERT_TRUE(cJSON_IsString(wd));
    TEST_ASSERT_EQUAL_STRING("", wd->valuestring);

    cJSON *uptime = cJSON_GetObjectItemCaseSensitive(resp, "uptime_sec");
    TEST_ASSERT_TRUE(cJSON_IsNumber(uptime));
    TEST_ASSERT_EQUAL(0, (int)uptime->valuedouble);

    cJSON_Delete(resp);
}

/* The setter takes ownership of a heap copy, so calling it a second time must
 * replace (not append) the previous value. A leak here would only surface under
 * ASan; functionally we just confirm the latest value wins. */
void test_info_command_working_dir_updates_on_reset(void)
{
    unix_rpc_basic_set_started_at(time(NULL));
    unix_rpc_basic_set_config_path("/tmp/fake-cpworker.json");
    unix_rpc_basic_set_working_dir("/first");
    unix_rpc_basic_set_working_dir("/second");

    cJSON *resp = cJSON_CreateObject();
    TEST_ASSERT_NOT_NULL(resp);

    int ret = unix_rpc_info_command(NULL, resp, NULL);
    TEST_ASSERT_EQUAL(0, ret);

    cJSON *wd = cJSON_GetObjectItemCaseSensitive(resp, "working_dir");
    TEST_ASSERT_TRUE(cJSON_IsString(wd));
    TEST_ASSERT_EQUAL_STRING("/second", wd->valuestring);

    cJSON_Delete(resp);
}

/* ---------- unix-manager: SO_SNDTIMEO hardening ---------- */

static int make_socketpair(int fds[2])
{
    return socketpair(AF_UNIX, SOCK_STREAM, 0, fds);
}

/* SO_SNDTIMEO must actually land on the kernel side, not just be a no-op. */
void test_set_send_timeout_readable_via_getsockopt(void)
{
    int fds[2];
    TEST_ASSERT_EQUAL(0, make_socketpair(fds));

    TEST_ASSERT_EQUAL(0, unix_manager_set_send_timeout(fds[0], 3));

    struct timeval tv;
    socklen_t len = sizeof(tv);
    TEST_ASSERT_EQUAL(0, getsockopt(fds[0], SOL_SOCKET, SO_SNDTIMEO, &tv, &len));
    TEST_ASSERT_EQUAL(3, tv.tv_sec);

    close(fds[0]);
    close(fds[1]);
}

/* End-to-end proof the timeout bounds a stalled write. Without SO_SNDTIMEO
 * this send loop would block indefinitely once the kernel buffer fills. */
void test_send_timeout_fires_on_unread_peer(void)
{
    int fds[2];
    TEST_ASSERT_EQUAL(0, make_socketpair(fds));

    /* Tight socket buffers so the test finishes in well under a second. */
    int small = 4096;
    (void)setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &small, sizeof(small));
    (void)setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &small, sizeof(small));

    /* 200ms send timeout. We never read from fds[1], so send() must fail
     * with EAGAIN/EWOULDBLOCK once the buffer is full. */
    struct timeval tv = {.tv_sec = 0, .tv_usec = 200 * 1000};
    TEST_ASSERT_EQUAL(0, setsockopt(fds[0], SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)));

    char payload[8192];
    memset(payload, 'A', sizeof(payload));

    int timed_out = 0;
    for (int i = 0; i < 64; i++) /* hard cap prevents an infinite loop if timeout ever breaks */
    {
        ssize_t n = send(fds[0], payload, sizeof(payload), 0);
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK))
        {
            timed_out = 1;
            break;
        }
        if (n < 0)
            break; /* other error — test below will fail */
    }
    TEST_ASSERT_TRUE_MESSAGE(timed_out, "send() should have returned EAGAIN once the buffer filled");

    close(fds[0]);
    close(fds[1]);
}

int main(void)
{
    UNITY_BEGIN();
    RUN_TEST(test_ping_command_adds_ts_ms);
    RUN_TEST(test_info_command_returns_expected_fields);
    RUN_TEST(test_info_command_handles_unset_config_path);
    RUN_TEST(test_info_command_working_dir_updates_on_reset);
    RUN_TEST(test_set_send_timeout_readable_via_getsockopt);
    RUN_TEST(test_send_timeout_fires_on_unread_peer);
    return UNITY_END();
}
