#include <iostream>
#include <cstring>
#include <string>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <pcap/pcap.h>

#include <netdb.h>

#include "packet_agent_extension.h"
#include "utils.h"
#include "my_getopt.h"


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
        "interface": "eth0",
        "netflow_version": 5
    }
}
EOF
)
./pktminerg -i eno16777984 -r 10.1.1.37 --monitor-config "${JSON_STR}"
*/

extern void pcap_callback(u_char *useless, const struct pcap_pkthdr* pkthdr, const u_char *packet);
extern int init_fprobe(getopt_parms *argv, int addrc, char **addrv);
extern int close_fprobe();


#define EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT "collectors_ipport"
#define EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT_IP "ip"
#define EXT_CONFIG_KEY_OF_COLLECTORS_IPPORT_PORT "port"
#define EXT_CONFIG_KEY_OF_INTERFACE "interface"
#define EXT_CONFIG_KEY_OF_NETFLOW_VERSION "netflow_version"

#define LOG_MODULE_NAME "monitor_netflow: "


typedef struct _ip_port {
	std::string ip;
	uint16_t port;
}ip_port_t;


typedef struct _extension_ctx {
	std::vector<ip_port_t> collectors_ipport;
    std::vector<struct AddressV4V6> remote_addrs;
    std::string interface;
    uint16_t netflow_version;
    char ** addrv;
}extension_ctx_t;


int _reset_context(extension_ctx_t* ctx) {
    ctx->collectors_ipport.clear();
    ctx->remote_addrs.clear();
    ctx->interface = "";
    ctx->netflow_version = 5; // default is ver. 5
    ctx->addrv = nullptr;
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
        // ext_params.netflow_version
        if (config_items.get_child_optional(EXT_CONFIG_KEY_OF_NETFLOW_VERSION)) {
            ctx->netflow_version = config_items.get<uint16_t>(EXT_CONFIG_KEY_OF_NETFLOW_VERSION);
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
    std::cout << "collectors_ipport: " << std::endl;
    for (auto &item : ctx->collectors_ipport) {
        std::cout << "  ip: " << item.ip << "; port: " << item.port << std::endl;
    }
    std::cout << "interface: " << ctx->interface << std::endl;
    std::cout << "netflow_version: " << ctx->netflow_version << std::endl;
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

    // init getopt_parms
    enum {
        aflag,
        Bflag,
        bflag,
        cflag,
        dflag,
        eflag,
        fflag,
        gflag,
        hflag,
        iflag,
        Kflag,
        kflag,
        lflag,
        mflag,
        nflag,
        pflag,
        qflag,
        rflag,
        Sflag,
        sflag,
        tflag,
        uflag,
        vflag,
        xflag,
    };
    static struct getopt_parms parms[] = {
        {'a', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'B', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'b', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'c', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'d', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'e', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'f', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'g', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'h', 0, 0, 0},
        {'i', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'K', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'k', 0, 0, 0},
        {'l', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'m', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'n', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'p', 0, 0, 0},
        {'q', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'r', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'S', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'s', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'t', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'u', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'v', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {'x', MY_GETOPT_ARG_REQUIRED, 0, 0},
        {0, 0, 0, 0}
    };

    // build option params
    parms[nflag].count = 1;
    parms[nflag].arg = new char[50];
    if (!parms[nflag].arg) {
        std::cout << LOG_MODULE_NAME << "init_export： allocate parms[].arg failed." << std::endl;
        return 1;
    }
    memset(parms[nflag].arg, 0, 50);
    snprintf(parms[nflag].arg, 50, "%d", ctx->netflow_version);

    // build collector ip/port params
    if (ctx->collectors_ipport.size() == 0) {
        std::cout << LOG_MODULE_NAME << "init_export： no collector ip and port found." << std::endl;
        return 1;
    }
    std::string ipport_str;
    uint16_t collector_size = ctx->collectors_ipport.size();
    ctx->addrv = new char*[collector_size];
    if (!ctx->addrv) {
        std::cout << LOG_MODULE_NAME << "init_export： allocate addrv failed." << std::endl;
        return 1;
    }
    memset(ctx->addrv, 0, collector_size * sizeof(char*));
    for (uint16_t i = 0; i < collector_size; i++) {
        ctx->addrv[i] = new char[50];
        if (!ctx->addrv[i]) {
            std::cout << LOG_MODULE_NAME << "init_export： allocate addrv[i] failed." << std::endl;
            return 1;
        }
        memset(ctx->addrv[i], 0, 50);
        ipport_str = ctx->collectors_ipport[i].ip;
        ipport_str += ":";
        ipport_str += std::to_string(ctx->collectors_ipport[i].port);
        memcpy(ctx->addrv[i], ipport_str.c_str(), ipport_str.size());
        // std::cout << LOG_MODULE_NAME << ctx->addrv[i] << std::endl;
    }

    // fprobe init
    init_fprobe(parms, (int)collector_size, ctx->addrv);

    // clean memory
    for (uint16_t i = 0; i < collector_size; i++) {
        delete [] ctx->addrv[i];
        ctx->addrv[i] = 0;
    }
    delete [] ctx->addrv;
    ctx->addrv = 0;

    delete [] parms[nflag].arg;

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
    /*
    if (!ext_handle) {
        return 1;
    }
    packet_agent_extension_itf_t* extension_itf = reinterpret_cast<packet_agent_extension_itf_t*>(ext_handle);
    if (!extension_itf->ctx) {
        return 1;
    }
    extension_ctx_t* ctx = reinterpret_cast<extension_ctx_t*>(extension_itf->ctx);
    */

    // fprobe close
    close_fprobe();


    return 0;
}

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