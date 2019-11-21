#include <iostream>
#include <netinet/in.h>

#include "packet_agent_ext.h"

// using namespace std;


#ifdef __cplusplus
extern "C"
{
#endif

#define GRE_TYPE_TRANS_BRIDGING 0x6558
#define ETHERNET_TYPE_ERSPAN_TYPE1   0x88be  // ERSPAN Type I is obsolete




typedef struct _ERSpanType1GREHdr {
    uint16_t flags;
    uint16_t protocol;
} ERSpanType1GREHdr;



int get_proto_header_size(void* ctx, uint8_t* packet, uint32_t* len) {
    return 0;
}

int get_proto_default_header(void* ctx, uint8_t *dst, uint32_t* len) {
    if (!dst || !len) {
        std::cout << "proto_erspan_type1: get_proto_header: invalid param." << std::endl;
        return 1;
    }
    if (*len < sizeof(ERSpanType1GREHdr)) {
        std::cout << "proto_erspan_type1: get_proto_header: buffer len is too small" << std::endl;
        return 1;
    }
    ERSpanType1GREHdr *hdr = reinterpret_cast<ERSpanType1GREHdr *>(dst);
    hdr->flags = 0; // all zero
    hdr->protocol = htons(ETHERNET_TYPE_ERSPAN_TYPE1);
    *len = sizeof(ERSpanType1GREHdr);
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