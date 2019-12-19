#include <iostream>
#include <cstring>
#include <string>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <pcap/pcap.h>

#include <netdb.h>

#include "packet_agent_extension.h"
#include "utils.h"


// using namespace std;
#ifdef __cplusplus
extern "C"
{
#endif
/*
# monitor_netflow 
JSON_STR=$(cat << EOF
{
    "ext_file_path": "libmonitor_netflow.so",
    "ext_params": {
        "collectors_ipport": [
            {
                "ip": "10.1.1.37",
                "port": 2003
            },
            {
                "ip": "10.1.1.38",
                "port": 2003
            }
        ],
        "interface": "eth0"
    }
}
EOF
)
./pktminerg -i eno16777984 -r 10.1.1.37 --monitor-config "${JSON_STR}"
*/

extern void pcap_callback(u_char *useless,
    const struct pcap_pkthdr* pkthdr, const u_char *packet);


#define EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT "collectors_ipport"
#define EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT_IP "ip"
#define EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT_PORT "port"
#define EXT_CONFIG_KEY_OF_INTERFACE "interface"

#define LOG_MODULE_NAME "monitor_netflow: "


typedef struct _ip_port {
	std::string ip;
	uint16_t port;
}ip_port_t;


typedef struct _extension_ctx {
	std::vector<ip_port_t> collectors_ipport;
    std::vector<struct AddressV4V6> remote_addrs;
    std::string interface;
}extension_ctx_t;


int _reset_context(extension_ctx_t* ctx) {
    ctx->collectors_ipport.clear();
    ctx->remote_addrs.clear();
    ctx->interface = "";
    return 0;
}

int _init_monitor_config(extension_ctx_t* ctx, std::string& monitor_config) {
    std::stringstream ss(monitor_config);
    boost::property_tree::ptree monitor_config_tree;

    try {
        boost::property_tree::read_json(ss, monitor_config_tree);
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << LOG_MODULE_NAME << "Parse monitor_config json string failed!" << std::endl;
        return -1;
    }

    // ext_params
    if (monitor_config_tree.get_child_optional(EXT_CONFIG_KEY_OF_EXTERN_PARAMS)) {
        boost::property_tree::ptree& config_items = monitor_config_tree.get_child(EXT_CONFIG_KEY_OF_EXTERN_PARAMS);

        // ext_params.collectors_ipport[]
        if (config_items.get_child_optional(EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT)) {
        	boost::property_tree::ptree& collectors_ipport = config_items.get_child(EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT);

        	ip_port_t ipport;
		    for (auto it = collectors_ipport.begin(); it != collectors_ipport.end(); it++) {
		    	ipport.port = 0;

		    	// ext_params.collectors_ipport[].ip
		    	if (it->second.get_child_optional(EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT_IP)) {
		    		ipport.ip = it->second.get<std::string>(EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT_IP);
		    	}

		    	// ext_params.collectors_ipport[].port
		    	if (it->second.get_child_optional(EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT_PORT)) {
		    		ipport.port = it->second.get<uint16_t>(EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT_PORT);
		    	}
		    	ctx->collectors_ipport.push_back(ipport);
		    }
        }

        // ext_params.interface
        if (config_items.get_child_optional(EXT_CONFIG_KEY_OF_INTERFACE)) {
            ctx->interface = config_items.get<std::string>(EXT_CONFIG_KEY_OF_INTERFACE);
        }
    }


    return 0;
}

int _init_context(extension_ctx_t* ctx, std::string& monitor_config) {
    _reset_context(ctx);

    if (_init_monitor_config(ctx, monitor_config)) {
        return 1;
    }

    // ctx log
    std::cout << LOG_MODULE_NAME << "The context values:" << std::endl;
    for (auto &item : ctx->collectors_ipport) {
        std::cout << "ip: " << item.ip << std::endl;
        std::cout << "port: " << item.port << std::endl;
    }
    std::cout << "interface: " << ctx->interface << std::endl;
    return 0;
}

int init_export(void* ext_handle, const char* ext_config) {
    if (!ext_handle) {
        return 1;
    }

    packet_agent_extension_itf_t* extension_itf = reinterpret_cast<packet_agent_extension_itf_t*>(ext_handle);
    if (!extension_itf->ctx) {
        return 1;
    }
    extension_ctx_t* ctx = reinterpret_cast<extension_ctx_t*>(extension_itf->ctx);

	std::string monitor_config{};
    if (ext_config) {
        monitor_config = ext_config;
    }
    std::cout << LOG_MODULE_NAME << "monitor_config is " << monitor_config <<  std::endl;

    _init_context(ctx, monitor_config);

    // fprobe init

    return 0;
}


int export_packet(void* ext_handle, const void* pkthdr, const uint8_t *packet) {
    if (!ext_handle) {
        return 1;
    }
    packet_agent_extension_itf_t* extension_itf = reinterpret_cast<packet_agent_extension_itf_t*>(ext_handle);
    if (!extension_itf->ctx) {
        return 1;
    }
    extension_ctx_t* ctx = reinterpret_cast<extension_ctx_t*>(extension_itf->ctx);
    if (!pkthdr || !packet) {
        std::cerr << LOG_MODULE_NAME << "pkthdr or pkt is null. " << std::endl;
        return 1;
    }


    // fprobe export
    u_char useless = 0;
    pcap_callback(&useless, reinterpret_cast<const struct pcap_pkthdr*>(pkthdr), packet);

	return 0;
}



int close_export(void* ext_handle) {
    if (!ext_handle) {
        return 1;
    }
    packet_agent_extension_itf_t* extension_itf = reinterpret_cast<packet_agent_extension_itf_t*>(ext_handle);
    if (!extension_itf->ctx) {
        return 1;
    }
    extension_ctx_t* ctx = reinterpret_cast<extension_ctx_t*>(extension_itf->ctx);

    // fprobe close

    return 0;
}

// 
int terminate(void* ext_handle) {
    if (ext_handle) {
        packet_agent_extension_itf_t* extension_itf = reinterpret_cast<packet_agent_extension_itf_t*>(ext_handle);
        if (extension_itf->ctx) {
            delete reinterpret_cast<extension_ctx_t*>(extension_itf->ctx);
        }
    }
    return 0;
}

int packet_agent_extension_entry(void* ext_handle) {
    if (!ext_handle) {
        std::cerr << LOG_MODULE_NAME << "The ext_handle is not ready!" << std::endl;
        return -1;
    }

    extension_ctx_t* ctx = new extension_ctx_t();
    if (!ctx) {
        std::cerr << LOG_MODULE_NAME << "malloc context failed!" << std::endl;
        return -1;
    }

    packet_agent_extension_itf_t* extension_itf = (packet_agent_extension_itf_t* )ext_handle;
    extension_itf->init_export_func = init_export;
    extension_itf->export_packet_func = export_packet;
    extension_itf->close_export_func = close_export;
    extension_itf->terminate_func = terminate;
    extension_itf->ctx = ctx;
    return 0;
}

#ifdef __cplusplus
}
#endif