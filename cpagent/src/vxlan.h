#ifndef CPAGENT_VXLAN_H
#define CPAGENT_VXLAN_H

#include <stdint.h>

struct vxlanhdr
{
    uint32_t vx_flags;
    uint32_t vx_vni;
};

#define VXLAN_HEADER_LEN 8

#endif /* CPAGENT_VXLAN_H */