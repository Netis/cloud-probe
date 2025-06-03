#ifndef CPWORKER_VXLAN_H
#define CPWORKER_VXLAN_H

#include <stdint.h>

struct vxlan_header
{
    uint32_t vx_flags;
    uint32_t vx_vni;
};

#define VXLAN_HEADER_LEN 8

#endif /* CPWORKER_VXLAN_H */