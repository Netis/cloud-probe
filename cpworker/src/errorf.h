#ifndef CPWORKER_ERRORF_H
#define CPWORKER_ERRORF_H

#define ERROR_BUFFER_SIZE 256

void error_format(char *errbuf, const char *format, ...);
void error_wrap_format(char *errbuf, const char *format, ...);

#endif /* CPWORKER_ERRORF_H */