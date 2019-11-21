#include <iostream>
#include <netinet/in.h>

#include "packet_agent_ext.h"

// using namespace std;


#ifdef __cplusplus
extern "C"
{
#endif

#define ETHERNET_TYPE_ERSPAN_TYPE3    0x22eb

typedef struct _ERSpanType23GREHdr {
    uint16_t flags;
    uint16_t protocol;
    uint32_t sequence;
} ERSpanType23GREHdr;

typedef struct _ERSpanType3Hdr {
    uint16_t ver_vlan;
    uint16_t flags_spanId;
    uint32_t timestamp;
    uint16_t pad0;
    uint16_t pad1;
} ERSpanType3Hdr;


int get_proto_header_size(void* ctx, uint8_t* packet, uint32_t* len) {
    return 20;
}

int get_proto_default_header(void* ctx, uint8_t* dst, uint32_t* len) {
    if (!dst || !len) {
        std::cerr << "proto_erspan_type3: get_proto_header: invalid param." << std::endl;
        return 1;
    }

    if (*len < sizeof(ERSpanType23GREHdr) + sizeof(ERSpanType3Hdr)) {
        std::cerr << "proto_erspan_type3: get_proto_header: buffer len is too small" << std::endl;
        return 1;
    }

    ERSpanType23GREHdr *hdr = reinterpret_cast<ERSpanType23GREHdr*>(dst);
    hdr->flags = htons(0x1000);  // S bit
    hdr->protocol = htons(ETHERNET_TYPE_ERSPAN_TYPE3);
    hdr->sequence = 0;

    ERSpanType3Hdr* erspan_hdr = reinterpret_cast<ERSpanType3Hdr*>(dst + sizeof(ERSpanType23GREHdr));
    erspan_hdr->ver_vlan = htons(0x2000);  // ver = 2
    erspan_hdr->flags_spanId = 0;
    erspan_hdr->timestamp = 0;
    erspan_hdr->pad0 = 0;
    erspan_hdr->pad1 = 0;

    *len = sizeof(ERSpanType23GREHdr) + sizeof(ERSpanType3Hdr);
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