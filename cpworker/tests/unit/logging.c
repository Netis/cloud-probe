#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "unity/src/unity.h"

#include "log.h"

#define NUM_THREADS 4
#define LINES_PER_THREAD 20000
#define PAYLOAD "abcdefghijklmnopqrstuvwxyz"

static char capture_path[64];
static int saved_stderr = -1;

// Points fd 2 at a temporary file so the test can read back what log_log wrote.
static void capture_stderr_begin(void)
{
    strcpy(capture_path, "/tmp/cpworker_ut_log_XXXXXX");
    int fd = mkstemp(capture_path);
    TEST_ASSERT_TRUE(fd >= 0);
    fflush(stderr);
    saved_stderr = dup(STDERR_FILENO);
    TEST_ASSERT_TRUE(saved_stderr >= 0);
    TEST_ASSERT_TRUE(dup2(fd, STDERR_FILENO) >= 0);
    close(fd);
}

// Restores fd 2 and returns the captured output; the caller frees it.
static char *capture_stderr_end(size_t *len)
{
    fflush(stderr);
    dup2(saved_stderr, STDERR_FILENO);
    close(saved_stderr);
    saved_stderr = -1;

    FILE *fp = fopen(capture_path, "rb");
    TEST_ASSERT_NOT_NULL(fp);
    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    char *buf = malloc(size + 1);
    TEST_ASSERT_NOT_NULL(buf);
    TEST_ASSERT_EQUAL(size, fread(buf, 1, size, fp));
    buf[size] = '\0';
    fclose(fp);
    unlink(capture_path);
    *len = (size_t)size;
    return buf;
}

static size_t count_occurrences(const char *s, size_t len, const char *needle)
{
    size_t n = 0, needle_len = strlen(needle);
    for (const char *p = s; (p = memmem(p, len - (p - s), needle, needle_len)) != NULL; p += needle_len)
        n++;
    return n;
}

void setUp(void) { log_set_level(LOG_TRACE); }

void tearDown(void) {}

static void *log_from_thread(void *arg)
{
    long id = (long)arg;
    for (int i = 0; i < LINES_PER_THREAD; i++)
        log_info("thread=%ld seq=%d payload=" PAYLOAD, id, i);
    return NULL;
}

// Each line must be "<time> INFO  <file>:<line>: thread=<t> seq=<s> payload=...": exactly one prefix and one message.
static void assert_line_intact(const char *line, size_t len)
{
    char msg[512]; // __FILE__ is an absolute path
    TEST_ASSERT_TRUE_MESSAGE(len < sizeof(msg), "line too long, lines interleaved");
    memcpy(msg, line, len);
    msg[len] = '\0';
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1, count_occurrences(msg, len, " INFO  "), msg);
    TEST_ASSERT_EQUAL_size_t_MESSAGE(1, count_occurrences(msg, len, "thread="), msg);
    const char *tail = "payload=" PAYLOAD;
    TEST_ASSERT_TRUE_MESSAGE(len >= strlen(tail) && strcmp(msg + len - strlen(tail), tail) == 0, msg);
}

void test_concurrent_log_lines_do_not_interleave(void)
{
    capture_stderr_begin();
    pthread_t threads[NUM_THREADS];
    for (long i = 0; i < NUM_THREADS; i++)
        TEST_ASSERT_EQUAL(0, pthread_create(&threads[i], NULL, log_from_thread, (void *)i));
    for (int i = 0; i < NUM_THREADS; i++)
        pthread_join(threads[i], NULL);
    size_t len;
    char *out = capture_stderr_end(&len);

    size_t lines = 0;
    for (char *line = out, *nl; (nl = memchr(line, '\n', len - (line - out))) != NULL; line = nl + 1)
    {
        assert_line_intact(line, nl - line);
        lines++;
    }
    TEST_ASSERT_EQUAL_size_t(NUM_THREADS * LINES_PER_THREAD, lines);
    TEST_ASSERT_EQUAL_CHAR('\n', out[len - 1]);
    free(out);
}

void test_long_message_is_written_in_full_on_one_line(void)
{
    static char long_msg[10001];
    memset(long_msg, 'x', sizeof(long_msg) - 1);
    long_msg[sizeof(long_msg) - 1] = '\0';

    capture_stderr_begin();
    log_info("%s", long_msg);
    size_t len;
    char *out = capture_stderr_end(&len);

    TEST_ASSERT_EQUAL_size_t(1, count_occurrences(out, len, "\n"));
    TEST_ASSERT_EQUAL_CHAR('\n', out[len - 1]);
    out[len - 1] = '\0';
    TEST_ASSERT_NOT_NULL(strstr(out, long_msg));
    free(out);
}

void test_line_has_timestamp_level_and_location(void)
{
    capture_stderr_begin();
    log_warn("hello %d", 42);
    size_t len;
    char *out = capture_stderr_end(&len);

    // 2026-10-08T10:00:00 WARN  .../logging.c:N: hello 42
    TEST_ASSERT_TRUE(len > 20);
    TEST_ASSERT_EQUAL_CHAR('T', out[10]);
    TEST_ASSERT_EQUAL_CHAR(' ', out[19]);
    TEST_ASSERT_EQUAL_STRING_LEN("WARN  ", out + 20, 6);
    TEST_ASSERT_NOT_NULL(strstr(out, "logging.c:"));
    TEST_ASSERT_EQUAL_STRING(": hello 42\n", out + len - strlen(": hello 42\n"));
    free(out);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_concurrent_log_lines_do_not_interleave);
    RUN_TEST(test_long_message_is_written_in_full_on_one_line);
    RUN_TEST(test_line_has_timestamp_level_and_location);

    return UNITY_END();
}
