#include <stdarg.h>
#include <stdio.h>

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
    va_list args;
    va_start(args, format);
    vsnprintf(err->message, sizeof(err->message), format, args);
    va_end(args);
}
