#ifndef PKTMINERG_PACKET_AGENT_EXTENSION_H
#define PKTMINERG_PACKET_AGENT_EXTENSION_H

#include <cstdint>

// common config key title
#define EXT_EXTRY_POINT "packet_agent_extension_entry"
#define EXT_CONFIG_KEY_OF_LIBRARY_PATH "ext_file_path"
#define EXT_CONFIG_KEY_OF_EXTERN_PARAMS "ext_params"


#if defined(__cplusplus)
extern "C" {
#endif

typedef int (*pf_init_export_t)(void* ext_handle, const char* ext_config);
typedef int (*pf_export_packet_t)(void* ext_handle, const void* pkthdr, const uint8_t *packet);
typedef int (*pf_close_export_t)(void* ext_handle);
typedef int (*pf_terminate_t)(void* ext_handle);
typedef int (*pf_entry_t)(void* ext_handle);

typedef struct  _packet_agent_extension_itf {
    void* ctx;
    pf_init_export_t init_export_func; 
    pf_export_packet_t export_packet_func; 
    pf_close_export_t close_export_func; 
    pf_terminate_t terminate_func; 
}packet_agent_extension_itf_t;

#if defined(__cplusplus)
}
#endif

#endif //PKTMINERG_PACKET_AGENT_EXT_H
