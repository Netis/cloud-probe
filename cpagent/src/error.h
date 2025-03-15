#ifndef CPAGENT_ERROR_H
#define CPAGENT_ERROR_H

#define ERROR_BUFFER_SIZE 256

void error_format(char *errbuf, const char *format, ...);
void error_wrap_format(char *errbuf, const char *format, ...);

#endif /* CPAGENT_ERROR_H */