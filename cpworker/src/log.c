#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "log.h"

// Lines that fit are formatted on the stack; longer ones go to the heap, or are truncated if that fails.
#define LOG_LINE_STACK_SIZE 1024

static struct
{
    int level;
} L;

static const char *level_strings[] = {"TRACE", "DEBUG", "INFO", "WARN", "ERROR", "FATAL"};

const char *log_level_string(int level) { return level_strings[level]; }

void log_set_level(int level) { L.level = level; }

// Several threads log at once, and stdio locks each call rather than each line. The whole line is therefore
// formatted first and written with a single fwrite, so lines from different threads never interleave.
static void stderr_callback(log_event_t *ev)
{
    char stack_line[LOG_LINE_STACK_SIZE];
    char *line = stack_line;
    size_t size = sizeof(stack_line);

    char ts[32];
    if (!ev->time || strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", ev->time) == 0)
        snprintf(ts, sizeof(ts), "<time-unavailable>");
    int prefix_len = snprintf(line, size, "%s %-5s %s:%d: ", ts, log_level_string(ev->level), ev->file, ev->line);
    if (prefix_len < 0)
        return;
    if ((size_t)prefix_len > size - 2)
        prefix_len = (int)size - 2;

    va_list ap;
    va_copy(ap, ev->ap);
    int msg_len = vsnprintf(line + prefix_len, size - prefix_len, ev->fmt, ap);
    va_end(ap);
    if (msg_len < 0)
        msg_len = 0;

    // Room for the message, '\n' and the terminating '\0'.
    size_t need = (size_t)prefix_len + (size_t)msg_len + 2;
    if (need > size)
    {
        char *heap_line = malloc(need);
        if (heap_line)
        {
            memcpy(heap_line, line, prefix_len);
            vsnprintf(heap_line + prefix_len, need - prefix_len, ev->fmt, ev->ap);
            line = heap_line;
        }
        else
            msg_len = (int)(size - prefix_len - 2);
    }

    size_t len = (size_t)prefix_len + (size_t)msg_len;
    line[len++] = '\n';
    fwrite(line, 1, len, stderr);
    fflush(stderr);

    if (line != stack_line)
        free(line);
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
    struct tm tm_buf;
    ev.time = localtime_r(&t, &tm_buf);

    va_start(ev.ap, fmt);
    stderr_callback(&ev);
    va_end(ev.ap);
}
