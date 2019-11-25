#include <iostream>
#include <netinet/in.h>

#include "packet_agent_ext.h"

// using namespace std;


#ifdef __cplusplus
extern "C"
{
#endif

#define ETHERNET_TYPE_ERSPAN_TYPE1   0x88be  // ERSPAN Type I is obsolete,
#define GRE_TYPE_TRANS_BRIDGING 0x6558



typedef struct _ERSpanType1GREHdr {
    uint16_t flags;
    uint16_t protocol;
} ERSpanType1GREHdr;


int get_proto_header_size(void* ext_handle, uint8_t* dst, uint32_t* len) {
    // TBD: support optional header fields
    return sizeof(ERSpanType1GREHdr);
}


int get_proto_initial_header(void* ext_handle, uint8_t* dst, uint32_t* len) {
    uint32_t ret_len = sizeof(ERSpanType1GREHdr);
    if (!dst || !len) {
        std::cout << "proto_erspan_type1: get_proto_header: invalid param." << std::endl;
        return 1;
    }
    if (*len < sizeof(ERSpanType1GREHdr)) {
        std::cout << "proto_erspan_type1: get_proto_header: buffer len is too small" << std::endl;
        *len = ret_len;
        return 1;
    }

    ERSpanType1GREHdr *hdr = reinterpret_cast<ERSpanType1GREHdr *>(dst);
    hdr->flags = 0; // all zero
    hdr->protocol = htons(ETHERNET_TYPE_ERSPAN_TYPE1);
    *len = ret_len;
    return 0;
}


int update_proto_header_check(void* ext_handle) {
    // type 1 is fix header
    return 0;
}
int update_proto_header(void* ext_handle, uint8_t* dst, uint32_t* len) {
    // type 1 is fix header
    uint32_t ret_len = sizeof(ERSpanType1GREHdr);
    *len = ret_len;
    return 0;
}

int terminate(void* ext_handle) {
    // no context to clean
    return 0;
}

int packet_agent_proto_extionsion_entry(void* ext_handle) {
    if (!ext_handle) {
        std::cerr << "proto_erspan_type1: entry: The ext_handle is not ready!" << std::endl;
        return -1;
    }
    PacketAgentProtoExtension* proto_extension = (PacketAgentProtoExtension* )ext_handle;
    proto_extension->get_proto_header_size_func = get_proto_header_size;
    proto_extension->get_proto_initial_header_func = get_proto_initial_header;
    proto_extension->update_proto_header_check_func = update_proto_header_check;
    proto_extension->update_proto_header_func = update_proto_header;
    proto_extension->terminate_func = terminate;
    return 0;
}


#ifdef __cplusplus
}
#endif