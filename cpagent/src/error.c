#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include "error.h"

void error_format(char *errbuf, const char *format, ...)
{
    va_list args;
    va_start(args, format);
    vsnprintf(errbuf, ERROR_BUFFER_SIZE, format, args);
    va_end(args);
}

void error_wrap_format(char *errbuf, const char *format, ...)
{
    char old_msg[ERROR_BUFFER_SIZE];
    strncpy(old_msg, errbuf, sizeof(old_msg));
    old_msg[sizeof(old_msg) - 1] = '\0';

    va_list args;
    va_start(args, format);
    int written = vsnprintf(errbuf, ERROR_BUFFER_SIZE, format, args);
    va_end(args);

    if (old_msg[0] == '\0')
        return;

    size_t new_len = (written >= ERROR_BUFFER_SIZE) ? ERROR_BUFFER_SIZE - 1 : written;
    size_t remaining_space = ERROR_BUFFER_SIZE - new_len - 1;

    if (remaining_space >= 2)
    {
        errbuf[new_len] = ':';
        errbuf[new_len + 1] = ' ';
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
        memcpy(errbuf + new_len, old_msg, copy_len);
        new_len += copy_len;
    }
    errbuf[new_len] = '\0';
}