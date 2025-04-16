#ifndef CPAGENT_MPLS_H
#define CPAGENT_MPLS_H

#include "byteorder.h"

typedef struct
{
#if ENDIANNESS_LE
    unsigned int reserved0 : 3;    // MPLS Label
    unsigned int rra : 4;          // MPLS Label
    unsigned int magic_number : 1; // MPLS Label

    unsigned int service_tag_h : 8; // MPLS Label

    unsigned int bottom : 1;        // MPLS Bottom of Label Stack
    unsigned int reserved1 : 3;     // MPLS Experimental Bits;
    unsigned int service_tag_l : 4; // MPLS Label

    unsigned int reserved2 : 8; // MPLS TTL
#elif ENDIANNESS_BE
    unsigned int magic_number : 1; // MPLS Label
    unsigned int rra : 4;          // MPLS Label
    unsigned int reserved0 : 3;    // MPLS Label

    unsigned int service_tag_h : 8; // MPLS Label

    unsigned int service_tag_l : 4; // MPLS Label
    unsigned int reserved1 : 3;     // MPLS Experimental Bits;
    unsigned int bottom : 1;        // MPLS Bottom of Label Stack

    unsigned int reserved2 : 8; // MPLS TTL
#else
#error "Please fix byteorder.h"
#endif
} mpls_header;

#define ETHER_TYPE_MPLS 0x8847

#endif /* */