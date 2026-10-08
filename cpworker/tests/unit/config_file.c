#include <pthread.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "unity/src/unity.h"

#include "atomic_util.h"
#include "cJSON/cJSON.h"
#include "config.h"

void setUp(void) {}

void tearDown(void) {}

static char tmp_path[64];

static const char *write_tmp_file(const char *content)
{
    strcpy(tmp_path, "/tmp/cpworker_ut_cfg_XXXXXX");
    int fd = mkstemp(tmp_path);
    TEST_ASSERT_TRUE(fd >= 0);
    size_t len = strlen(content);
    TEST_ASSERT_EQUAL(len, write(fd, content, len));
    close(fd);
    return tmp_path;
}

static void assert_message_contains(const cJSONParseError *err, const char *expected)
{
    TEST_ASSERT_NOT_NULL_MESSAGE(strstr(err->message, expected), err->message);
}

// read_file_contents

void test_config_path_naming_a_directory_is_rejected(void)
{
    char dir[] = "/tmp/cpworker_ut_cfgdir_XXXXXX";
    TEST_ASSERT_NOT_NULL(mkdtemp(dir));

    cJSONParseError err = {0};
    TEST_ASSERT_NULL(parse_config_file(dir, &err));
    assert_message_contains(&err, "not a regular file");
    assert_message_contains(&err, dir);

    err = (cJSONParseError){0};
    TEST_ASSERT_NULL(parse_tasks_file(dir, &err));
    assert_message_contains(&err, "not a regular file");

    rmdir(dir);
}

void test_empty_config_file_is_rejected(void)
{
    const char *path = write_tmp_file("");
    cJSONParseError err = {0};
    TEST_ASSERT_NULL(parse_config_file(path, &err));
    assert_message_contains(&err, "empty file");
    unlink(path);
}

void test_missing_config_file_is_rejected(void)
{
    cJSONParseError err = {0};
    TEST_ASSERT_NULL(parse_config_file("/nonexistent/cpworker.json", &err));
    assert_message_contains(&err, "failed to open file");
}

void test_regular_config_file_is_parsed(void)
{
    const char *path = write_tmp_file("{\"tasks\": [{\"capturer\": {\"type\": \"libpcap\", \"libpcap\": "
                                      "{\"interface\": \"eth0\"}}, \"outputs\": [{\"type\": \"null\"}]}]}");
    cJSONParseError err = {0};
    Config *config = parse_config_file(path, &err);
    TEST_ASSERT_NOT_NULL_MESSAGE(config, err.message);
    TEST_ASSERT_EQUAL(1, config->tasks_cfg->num_tasks);
    free_config(config);
    unlink(path);
}

// JSON syntax errors

void test_syntax_error_reports_line_column_and_snippet(void)
{
    cJSONParseError err = {0};
    TEST_ASSERT_NULL(parse_config_data("{\"tasks\": oops}", &err));
    TEST_ASSERT_EQUAL_STRING("JSON parse error at line 1, column 11 near 'oops}'", err.message);
}

void test_syntax_error_snippet_stops_at_end_of_line(void)
{
    cJSONParseError err = {0};
    TEST_ASSERT_NULL(parse_config_data("{\n  \"tasks\": [\n    oops,\n    {}\n  ]\n}\n", &err));
    TEST_ASSERT_EQUAL_STRING("JSON parse error at line 3, column 5 near 'oops,'", err.message);
}

void test_syntax_error_in_config_file_names_the_position(void)
{
    const char *path = write_tmp_file("{\n  \"tasks\": [}\n");
    cJSONParseError err = {0};
    TEST_ASSERT_NULL(parse_config_file(path, &err));
    TEST_ASSERT_EQUAL_STRING("JSON parse error at line 2, column 13 near '}'", err.message);

    err = (cJSONParseError){0};
    TEST_ASSERT_NULL(parse_tasks_file(path, &err));
    TEST_ASSERT_EQUAL_STRING("JSON parse error at line 2, column 13 near '}'", err.message);
    unlink(path);
}

// The control thread parses handshakes and commands while the reload thread parses the config. cJSON records the
// last error position in a process-wide variable; the config error must not depend on it.
static bool stop_parsing;

static void *parse_like_control_thread(void *arg)
{
    (void)arg;
    while (!atomic_load_acquire(&stop_parsing))
    {
        const char *end = NULL;
        cJSON *msg = cJSON_ParseWithOpts("{\"version\": \"v1\"}", &end, false);
        cJSON_Delete(msg);
        msg = cJSON_ParseWithOpts("{\"command\": ", &end, false);
        cJSON_Delete(msg);
    }
    return NULL;
}

void test_syntax_error_is_not_affected_by_concurrent_parsing(void)
{
    pthread_t control;
    atomic_store_release(&stop_parsing, false);
    TEST_ASSERT_EQUAL(0, pthread_create(&control, NULL, parse_like_control_thread, NULL));

    int wrong = 0;
    char first_wrong[CJSON_ERRBUF_SIZE] = "";
    for (int i = 0; i < 200000; i++)
    {
        cJSONParseError err = {0};
        TEST_ASSERT_NULL(parse_config_data("{\"tasks\": oops}", &err));
        if (strcmp(err.message, "JSON parse error at line 1, column 11 near 'oops}'") != 0 && wrong++ == 0)
            strcpy(first_wrong, err.message);
    }

    atomic_store_release(&stop_parsing, true);
    pthread_join(control, NULL);
    TEST_ASSERT_EQUAL_INT_MESSAGE(0, wrong, first_wrong);
}

int main(void)
{
    UNITY_BEGIN();

    RUN_TEST(test_config_path_naming_a_directory_is_rejected);
    RUN_TEST(test_empty_config_file_is_rejected);
    RUN_TEST(test_missing_config_file_is_rejected);
    RUN_TEST(test_regular_config_file_is_parsed);

    RUN_TEST(test_syntax_error_reports_line_column_and_snippet);
    RUN_TEST(test_syntax_error_snippet_stops_at_end_of_line);
    RUN_TEST(test_syntax_error_in_config_file_names_the_position);
    RUN_TEST(test_syntax_error_is_not_affected_by_concurrent_parsing);

    return UNITY_END();
}
