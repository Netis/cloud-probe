#ifndef CPWORKER_CJSON_UTILS_H
#define CPWORKER_CJSON_UTILS_H

#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
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

// Parses the NUL-terminated `json`. On a syntax error, returns NULL and sets err to
// "JSON parse error at line L, column C near '<snippet>'". The position comes from this call's own parse end, not from
// cJSON_GetErrorPtr(), whose process-wide state another thread's parse can overwrite.
cJSON *cjson_parse(const char *json, cJSONParseError *err);

void cjson_set_parse_error(cJSONParseError *err, const char *format, ...);
void cjson_wrap_parse_error(cJSONParseError *err, const char *format, ...);

// Reads `item` as an integer in [min, max]. Fails with "invalid <name>..." if item is not a number, has a
// fractional part, or is out of range. The range is checked on the double before conversion, so an out-of-range
// value never reaches an undefined integer conversion.
bool cjson_get_int64_range(const cJSON *item, const char *name, int64_t min, int64_t max, int64_t *out,
                           cJSONParseError *err);

// Reads `item` as an integer of any magnitude, for callers that clamp instead of rejecting out-of-range values.
// Fails with "invalid <name>..." if item is not a number or has a fractional part.
bool cjson_get_integer(const cJSON *item, const char *name, double *out, cJSONParseError *err);

#endif /* CPWORKER_CJSON_UTILS_H */