#ifndef CPAGENT_VLAN_H
#define CPAGENT_VLAN_H

#include <stdint.h>

struct vlanhdr
{
    uint16_t tci;
    uint16_t h_proto;
};

#endif /* CPAGENT_VLAN_H */
