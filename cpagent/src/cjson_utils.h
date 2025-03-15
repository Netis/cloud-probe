#ifndef cJSON_Common__h
#define cJSON_Common__h

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

void set_cjson_parse_error(cJSONParseError *err, const char *format, ...);
void wrap_cjson_parse_error(cJSONParseError *err, const char *format, ...);

#endif /* cJSON_Common__h */