#ifndef CPWORKER_LOG_H
#define CPWORKER_LOG_H

#include <stdarg.h>
#include <time.h>

typedef struct
{
    va_list ap;
    const char *fmt;
    const char *file;
    struct tm *time;
    int line;
    int level;
} log_event_t;

enum
{
    LOG_TRACE,
    LOG_DEBUG,
    LOG_INFO,
    LOG_WARN,
    LOG_ERROR,
    LOG_FATAL
};

#define log_trace(...) log_log(LOG_TRACE, __FILE__, __LINE__, __VA_ARGS__)
#define log_debug(...) log_log(LOG_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#define log_info(...) log_log(LOG_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define log_warn(...) log_log(LOG_WARN, __FILE__, __LINE__, __VA_ARGS__)
#define log_error(...) log_log(LOG_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define log_fatal(...) log_log(LOG_FATAL, __FILE__, __LINE__, __VA_ARGS__)

void log_log(int level, const char *file, int line, const char *fmt, ...);
void log_set_level(int level);

#endif /* LOGGER_H */