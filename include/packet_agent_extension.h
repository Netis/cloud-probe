

#ifndef PKTMINERG_PACKET_AGENT_EXTENSION_H
#define PKTMINERG_PACKET_AGENT_EXTENSION_H

#include <cstdint>

#define ENTRY_POINT "packet_agent_proto_extionsion_entry"

// common config str
#define PROTO_CONFIG_KEY_LIBRARY_PATH "ext_file_path"
#define PROTO_CONFIG_KEY_EXTERN_PARAMS "ext_params"

#define SOCKET_CONFIG_KEY_SO_BINDTODEVICE "SO_BINDTODEVICE"
#define SOCKET_CONFIG_KEY_IP_MTU_DISCOVER "IP_MTU_DISCOVER"

#if defined(__cplusplus)
extern "C" {
#endif

typedef int (*pf_get_proto_header_size_t)(void* ext_handle, uint8_t* packet, uint32_t* len);
typedef int (*pf_init_export_t)(void* ext_handle);
typedef int (*pf_export_packet_t)(void* ext_handle, const uint8_t *packet, uint32_t len);
typedef int (*pf_close_export_t)(void* ext_handle);
typedef int (*pf_terminate_t)(void* ext_handle);
typedef int (*pf_entry_t)(void* ext_handle);

typedef struct  _PacketAgentProtoExtension {
    const char* ext_file_path;
    const char* remoteip_config;
    const char* socket_config;
    const char* proto_config;
    void* handle;
    void* ctx;
    pf_get_proto_header_size_t get_proto_header_size_func;
    pf_init_export_t init_export_func;
    pf_export_packet_t export_packet_func;
    pf_close_export_t close_export_func;
    pf_terminate_t terminate_func;
}PacketAgentProtoExtension;

#if defined(__cplusplus)
}
#endif

#endif //PKTMINERG_PACKET_AGENT_EXT_H
