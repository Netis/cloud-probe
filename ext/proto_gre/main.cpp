#include <iostream>
#include <netinet/in.h>
#include "packet_agent_ext.h"


// using namespace std;


#ifdef __cplusplus
extern "C"
{
#endif

#define GRE_TYPE_TRANS_BRIDGING 0x6558
/* GRE related stuff */
typedef struct _GREHdr {
    uint8_t flags;
    uint8_t version;
    uint16_t ether_type;
} GREHdr;

typedef struct _GREKeybitHdr {
    uint8_t flags;
    uint8_t version;
    uint16_t ether_type;
    uint32_t keybit;
} GREKeybitHdr;




int get_proto_header_size(void* session, uint8_t* packet, uint32_t* len) {
    return 0;
}
/*
0                   1                   2                   3
0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|C|R|K|S|s|Recur|  Flags  | Ver |         Protocol Type         |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|      Checksum (optional)      |       Offset (optional)       |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Key (optional)                        |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                    Sequence Number (optional)                 |
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
|                         Routing (optional)
+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

int get_proto_default_header(void* session, uint8_t *dst, uint32_t* len) {
    if (!dst || !len) {
        std::cout << "proto_gre_with_keybit: get_proto_dummy_header: invalid param." << std::endl;
        return 1;
    }
    if (*len < sizeof(GREHdr)) {
        std::cout << "proto_gre_with_keybit: get_proto_dummy_header: buffer len is too small" << std::endl;
        return 1;
    }
    GREHdr *hdr = reinterpret_cast<GREHdr *>(dst);
    hdr->flags = 0;
    hdr->version = 0;
    hdr->ether_type = htons(GRE_TYPE_TRANS_BRIDGING);
    *len = sizeof(GREHdr);
    return 0;
}


int get_proto_header(void* session, uint8_t *dst, uint32_t* len, void* params) {
    if (!params) {
        return get_proto_default_header(session, dst, len);
    }

    if (!dst || !len) {
        std::cout << "proto_gre_with_keybit: get_proto_header: invalid param." << std::endl;
        return 1;
    }
    if (*len < sizeof(GREKeybitHdr)) {
        std::cout << "proto_gre_with_keybit: get_proto_header: buffer len is too small" << std::endl;
        return 1;
    }
    uint32_t keybit = *(static_cast<uint32_t*>(params));
    GREKeybitHdr *hdr = reinterpret_cast<GREKeybitHdr *>(dst);
    hdr->flags = 0x20;
    hdr->version = 0;
    hdr->ether_type = htons(GRE_TYPE_TRANS_BRIDGING);
    hdr->keybit = htonl(keybit);
    *len = sizeof(GREKeybitHdr);
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