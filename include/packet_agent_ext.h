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

typedef int (*get_proto_header_size_func_t)(void* ext_handle, uint8_t* packet, uint32_t* len);
typedef int (*get_proto_initial_header_func_t)(void* ext_handle, uint8_t *dst, uint32_t* len);
typedef int (*update_proto_header_check_func_t)(void* ext_handle);
typedef int (*update_proto_header_func_t)(void* ext_handle, uint8_t* dst, uint32_t* len);
typedef int (*terminate_func_t)(void* ext_handle);
typedef int (*entry_func_t)(void* ext_handle);

typedef struct  _PacketAgentProtoExtension {
    std::string ext_file_path;
    boost::property_tree::ptree json_config;
    uint8_t need_update_header;
    void* handle;
    void* ctx;
    get_proto_header_size_func_t get_proto_header_size_func;
    get_proto_initial_header_func_t get_proto_initial_header_func;
    update_proto_header_check_func_t update_proto_header_check_func;
    update_proto_header_func_t update_proto_header_func;
    terminate_func_t terminate_func;
}PacketAgentProtoExtension;

#if defined(__cplusplus)
}
#endif

#endif //PKTMINERG_PACKET_AGENT_EXT_H
