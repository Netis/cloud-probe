#include <iostream>
#include <netinet/in.h>
#include "packet_agent_ext.h"

// using namespace std;


#ifdef __cplusplus
extern "C"
{
#endif

#define ETHERNET_TYPE_ERSPAN_TYPE2    0x88be


typedef struct _ERSpanType23GREHdr {
    uint16_t flags;
    uint16_t protocol;
    uint32_t sequence;
} ERSpanType23GREHdr;

typedef struct _ERSpanType2Hdr {
    uint16_t ver_vlan;
    uint16_t flags_spanId;
    uint32_t pad;
} ERSpanType2Hdr;



int get_proto_header_size(void* ctx, uint8_t* packet, uint32_t* len) {
    return 0;
}

int get_proto_default_header(void* ctx, uint8_t *dst, uint32_t* len) {
    if (!dst || !len) {
        std::cout << "proto_erspan_type2: get_proto_header: invalid param." << std::endl;
        return 1;
    }
    if (*len < sizeof(ERSpanType23GREHdr) + sizeof(ERSpanType2Hdr)) {
        std::cout << "proto_erspan_type2: get_proto_header: buffer len is too small" << std::endl;
        return 1;
    }

    ERSpanType23GREHdr *hdr = reinterpret_cast<ERSpanType23GREHdr *>(dst);
    hdr->flags = htons(0x1000);  // S bit
    hdr->protocol = htons(ETHERNET_TYPE_ERSPAN_TYPE2);
    hdr->sequence = 0;

    ERSpanType2Hdr* erspan_hdr = reinterpret_cast<ERSpanType2Hdr*>(dst + sizeof(ERSpanType23GREHdr));
    erspan_hdr->ver_vlan = htons(0x1000);  // ver = 1
    erspan_hdr->flags_spanId = 0; // not support
    erspan_hdr->pad = 0;
    *len = sizeof(ERSpanType23GREHdr) + sizeof(ERSpanType2Hdr);
    return 0;
}


int terminate(void* ctx) {
    return 0;
}


int packet_agent_proto_extionsion_entry(void* ctx) {
    if (!ctx) {
        return 0;
    }
    PacketAgentProtoExtension* pe = (PacketAgentProtoExtension* )ctx;
    pe->get_proto_header_size_func = get_proto_header_size;
    pe->get_proto_default_header_func = get_proto_default_header;
    pe->terminate_func = terminate;
    return 0;
}




#ifdef __cplusplus
}
#endif