#ifndef CPWORKER_VLAN_H
#define CPWORKER_VLAN_H

#include <stdint.h>

struct vlanhdr
{
    uint16_t tci;
    uint16_t h_proto;
};

#endif /* CPWORKER_VLAN_H */
