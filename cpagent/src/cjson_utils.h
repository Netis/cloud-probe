#ifndef cJSON_Common__h
#define cJSON_Common__h

#include "cJSON/cJSON.h"
#include <stdarg.h>
#include <stdio.h>

typedef enum
{
    CJSON_PARSE_OK = 0,
    CJSON_PARSE_FAILED
} cJSONParseCode;

typedef struct
{
    cJSONParseCode code;
    char message[256];
} cJSONParseError;

void set_cjson_parse_error(cJSONParseError *err, const char *format, ...);
void wrap_cjson_parse_error(cJSONParseError *err, const char *format, ...);

#endif /* cJSON_Common__h */