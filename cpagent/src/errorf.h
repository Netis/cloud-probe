#ifndef CPAGENT_ERRORF_H
#define CPAGENT_ERRORF_H

#define ERROR_BUFFER_SIZE 256

void error_format(char *errbuf, const char *format, ...);
void error_wrap_format(char *errbuf, const char *format, ...);

#endif /* CPAGENT_ERRORF_H */