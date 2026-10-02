#ifndef CPWORKER_VLAN_H
#define CPWORKER_VLAN_H

#include <net/ethernet.h>
#include <stdbool.h>
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

#define ETHERTYPE_DOT1AD 0x88a8
#define ETHERTYPE_VLAN_9100 0x9100
#define ETHERTYPE_VLAN_9200 0x9200

// 802.1Q, 802.1ad and the legacy 0x9100/0x9200 QinQ TPIDs all carry a 4-byte tag (TCI + next EtherType)
static inline bool is_vlan_ethertype(uint16_t ether_type)
{
    return ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_DOT1AD || ether_type == ETHERTYPE_VLAN_9100 ||
           ether_type == ETHERTYPE_VLAN_9200;
}

#endif /* CPWORKER_VLAN_H */
