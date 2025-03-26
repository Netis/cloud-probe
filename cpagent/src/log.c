#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "log.h"

static struct
{
    int level;
} L;

static const char *level_strings[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};

const char *log_level_string(int level) { return level_strings[level]; }

void log_set_level(int level) { L.level = level; }

static void stderr_callback(log_event_t *ev)
{
    char buf[64];
    buf[strftime(buf, sizeof(buf), "[%Y-%m-%d %H:%M:%S]", ev->time)] = '\0';
    fprintf(stderr, "%s %-5s %s:%d: ", buf, level_strings[ev->level], ev->file, ev->line);
    vfprintf(stderr, ev->fmt, ev->ap);
    fprintf(stderr, "\n");
    fflush(stderr);
}

void log_log(int level, const char *file, int line, const char *fmt, ...)
{
    if (level < L.level)
        return;

    log_event_t ev = {
        .fmt = fmt,
        .file = file,
        .line = line,
        .level = level,
    };
    time_t t = time(NULL);
    ev.time = localtime(&t);

    va_start(ev.ap, fmt);
    stderr_callback(&ev);
    va_end(ev.ap);
}