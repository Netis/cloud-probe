#ifndef CPWORKER_VLAN_H
#define CPWORKER_VLAN_H

#include <stdint.h>

struct vlan_header
{
    uint16_t vlan_tci;
    uint16_t ether_type;
};

struct vlan_tag
{
    uint16_t vlan_tpid; /* ETH_P_8021Q */
    uint16_t vlan_tci;  /* VLAN TCI */
};

#define VLAN_TAG_LEN 4

#endif /* CPWORKER_VLAN_H */
