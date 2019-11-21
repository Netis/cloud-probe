//
// Created by root on 11/20/19.
//

#ifndef PKTMINERG_PACKET_AGENT_EXT_H
#define PKTMINERG_PACKET_AGENT_EXT_H

#include <cstdint>
#include <string>
#include <boost/property_tree/ptree.hpp>

#if defined(__cplusplus)
extern "C" {
#endif

typedef int (*get_proto_header_size_func_t)(void* ctx, uint8_t* packet, uint32_t* len);
typedef int (*get_proto_default_header_func_t)(void* ctx, uint8_t *dst, uint32_t* len);
typedef int (*terminate_func_t)(void* ctx);
typedef int (*entry_func_t)(void* ctx);

typedef struct  _PacketAgentProtoExtension {
    std::string ext_title;
    void* handle;
    boost::property_tree::ptree pt;
    get_proto_header_size_func_t get_proto_header_size_func;
    get_proto_default_header_func_t get_proto_default_header_func;
    terminate_func_t terminate_func;
}PacketAgentProtoExtension;

#if defined(__cplusplus)
}
#endif

#endif //PKTMINERG_PACKET_AGENT_EXT_H
