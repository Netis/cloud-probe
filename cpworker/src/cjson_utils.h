#ifndef CPWORKER_CJSON_UTILS_H
#define CPWORKER_CJSON_UTILS_H

#include <stdarg.h>
#include <stdio.h>

#include "cJSON/cJSON.h"

#define CJSON_ERRBUF_SIZE 256

typedef enum
{
    CJSON_PARSE_OK = 0,
    CJSON_PARSE_FAILED
} cJSONParseCode;

typedef struct
{
    cJSONParseCode code;
    char message[CJSON_ERRBUF_SIZE];
} cJSONParseError;

void cjson_set_parse_error(cJSONParseError *err, const char *format, ...);
void cjson_wrap_parse_error(cJSONParseError *err, const char *format, ...);

#endif /* CPWORKER_CJSON_UTILS_H */