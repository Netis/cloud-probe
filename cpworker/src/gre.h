#ifndef CPWORKER_GRE_H
#define CPWORKER_GRE_H

#include <stdint.h>

struct gre_header
{
    uint16_t flags;
    uint16_t protocol;
    uint32_t keybit;
};

#define GRE_HEADER_LEN 8

#endif /* CPWORKER_GRE_H */