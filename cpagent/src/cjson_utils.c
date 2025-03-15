#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "cJSON/cJSON.h"

#include "cjson_utils.h"

void set_cjson_parse_error(cJSONParseError *err, const char *format, ...)
{
    if (!err)
        return;

    err->code = CJSON_PARSE_FAILED;
    va_list args;
    va_start(args, format);
    vsnprintf(err->message, sizeof(err->message), format, args);
    va_end(args);
}

void wrap_cjson_parse_error(cJSONParseError *err, const char *format, ...)
{
    if (!err)
        return;

    err->code = CJSON_PARSE_FAILED;

    char old_msg[CJSON_ERRBUF_SIZE];
    strncpy(old_msg, err->message, sizeof(old_msg));
    old_msg[sizeof(old_msg) - 1] = '\0';

    va_list args;
    va_start(args, format);
    int written = vsnprintf(err->message, sizeof(err->message), format, args);
    va_end(args);

    if (old_msg[0] == '\0')
        return;

    size_t new_len = (written >= (int)sizeof(err->message)) ? sizeof(err->message) - 1 : written;
    size_t remaining_space = sizeof(err->message) - new_len - 1;

    if (remaining_space >= 2)
    {
        err->message[new_len] = ':';
        err->message[new_len + 1] = ' ';
        new_len += 2;
        remaining_space -= 2;
    }
    else
    {
        return;
    }

    size_t old_len = strlen(old_msg);
    size_t copy_len = (old_len <= remaining_space) ? old_len : remaining_space;

    if (copy_len > 0)
    {
        memcpy(err->message + new_len, old_msg, copy_len);
        new_len += copy_len;
    }
    err->message[new_len] = '\0';
}
