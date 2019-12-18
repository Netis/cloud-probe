#include <iostream>
#include <cstring>
#include <string>

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <netdb.h>

#include "packet_agent_extension.h"
#include "utils.h"

// using namespace std;


#ifdef __cplusplus
extern "C"
{
#endif


/*
# proto_erspan_type1
JSON_STR=$(cat << EOF
{
    "ext_file_path": "libproto_erspan_type1.so",
    "ext_params": {
        "remoteips": [
            "10.1.1.37"
        ],
        "bind_device": "eno16777984",
        "pmtudisc_option": "dont"
    }
}
EOF
)
./pktminerg -i eno16777984 --proto-config "${JSON_STR}"
*/

#define ETHERNET_TYPE_ERSPAN_TYPE1   0x88be  // ERSPAN Type I is obsolete,
#define GRE_TYPE_TRANS_BRIDGING 0x6558

#define INVALIDE_SOCKET_FD  -1


#define EXT_CONFIG_KEY_OF_EXT_PARAMS_REMOTE_IPS         "remoteips"
#define EXT_CONFIG_KEY_OF_EXT_PARAMS_BIND_DEVICE        "bind_device"
#define EXT_CONFIG_KEY_OF_EXT_PARAMS_PMTUDISC_OPTION    "pmtudisc_option"


#define LOG_MODULE_NAME "proto_erspan_type1: "

typedef struct _ERSpanType1GREHdr {
    uint16_t flags;
    uint16_t protocol;
} ERSpanType1GREHdr;

typedef struct _extension_ctx {
    std::vector<std::string> remoteips;
    std::vector<int> socketfds;
    std::vector<struct AddressV4V6> remote_addrs;
    std::vector<std::vector<char>> buffers;
    uint32_t proto_header_len;
    std::string bind_device;
    int pmtudisc;
}extension_ctx_t;

// tunnel header in outer L3 payload
int get_proto_header_size(void* ext_handle, uint8_t* packet, uint32_t* len) {
    // TBD: support optional header fields
    return sizeof(ERSpanType1GREHdr);
}

int _reset_context(extension_ctx_t* ctx) {    
    ctx->remoteips.clear();
    ctx->socketfds.clear();
    ctx->remote_addrs.clear();
    ctx->buffers.clear();
    ctx->proto_header_len = 0;
    ctx->bind_device = "";
    ctx->pmtudisc = -1;
    return 0;
}

int _init_proto_config(extension_ctx_t* ctx, std::string& proto_config) {
    std::stringstream ss(proto_config);
    boost::property_tree::ptree proto_config_tree;

    try {
        boost::property_tree::read_json(ss, proto_config_tree);
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << LOG_MODULE_NAME << "Parse proto_config json string failed!" << std::endl;
        return -1;
    }

    if (proto_config_tree.get_child_optional(EXT_CONFIG_KEY_OF_EXTERN_PARAMS)) {
        boost::property_tree::ptree& config_items = proto_config_tree.get_child(EXT_CONFIG_KEY_OF_EXTERN_PARAMS);

        // ext_params.remoteips[]
        if (config_items.get_child_optional(EXT_CONFIG_KEY_OF_EXT_PARAMS_REMOTE_IPS)) {
            boost::property_tree::ptree& remote_ip_tree = config_items.get_child(EXT_CONFIG_KEY_OF_EXT_PARAMS_REMOTE_IPS);

            for (auto it = remote_ip_tree.begin(); it != remote_ip_tree.end(); it++) {
                ctx->remoteips.push_back(it->second.get_value<std::string>());
            }
        }

        // ext_params.bind_device
        if (config_items.get_child_optional(EXT_CONFIG_KEY_OF_EXT_PARAMS_BIND_DEVICE)) {
            ctx->bind_device = config_items.get<std::string>(EXT_CONFIG_KEY_OF_EXT_PARAMS_BIND_DEVICE);
        }

        // ext_params.pmtudisc
        if (config_items.get_child_optional(EXT_CONFIG_KEY_OF_EXT_PARAMS_PMTUDISC_OPTION)) {
            std::string pmtudisc_option = config_items.get<std::string>(EXT_CONFIG_KEY_OF_EXT_PARAMS_PMTUDISC_OPTION);
            if (pmtudisc_option == "do") {
                ctx->pmtudisc = IP_PMTUDISC_DO;
            } else if (pmtudisc_option == "dont") {
                ctx->pmtudisc = IP_PMTUDISC_DONT;
            } else if (pmtudisc_option == "want") {
                ctx->pmtudisc = IP_PMTUDISC_WANT;
            } else {
                std::cerr << LOG_MODULE_NAME << "pmtudisc_option config invalid. Reset to -1." << std::endl;
                ctx->pmtudisc = -1;
            }
        }
    }

    return 0;
}


int _init_context(extension_ctx_t* ctx, std::string& proto_config) {
    _reset_context(ctx);

    if (_init_proto_config(ctx, proto_config)) {
        return 1;
    }

    std::cout << LOG_MODULE_NAME << "The context values: " << std::endl;
    std::cout << "remote ips: " << std::endl;
    for (auto& item : ctx->remoteips) {
        std::cout << "  " << item << std::endl;
    }
    std::cout << "bind_device " << ctx->bind_device <<std::endl;
    std::cout << "pmtudisc_option " << ctx->pmtudisc <<std::endl;

    // allocate space for socket
    unsigned long remote_ips_size = ctx->remoteips.size();
    ctx->remote_addrs.resize(remote_ips_size);
    ctx->socketfds.resize(remote_ips_size);
    ctx->buffers.resize(remote_ips_size);
    for (size_t i = 0; i < remote_ips_size; ++i) {
        ctx->socketfds[i] = INVALIDE_SOCKET_FD;
        ctx->buffers[i].resize(65535 + sizeof(ERSpanType1GREHdr), '\0'); // original packet, plus tunnel header in outer L3 payload
    }

    return 0;
}



int _init_proto_header(std::vector<char>& buffer) {
    ERSpanType1GREHdr *hdr = reinterpret_cast<ERSpanType1GREHdr*>(&(buffer[0]));
    hdr->flags = 0; // all zero
    hdr->protocol = htons(ETHERNET_TYPE_ERSPAN_TYPE1);
    return sizeof(ERSpanType1GREHdr);
}


int _init_sockets(std::string& remote_ip, AddressV4V6& remote_addr, int& socketfd,
                  std::string& bind_device, int pmtudisc) {
    if (socketfd == INVALIDE_SOCKET_FD) {
        int err = remote_addr.buildAddr(remote_ip.c_str());
        if (err != 0) {
            std::cerr <<  LOG_MODULE_NAME << "buildAddr failed, ip is " << remote_ip.c_str()
            << std::endl;
            return err;
        }

        int domain = remote_addr.getDomainAF_NET();
        if ((socketfd = socket(domain, SOCK_RAW, IPPROTO_GRE)) == INVALIDE_SOCKET_FD) {
            std::cerr <<  LOG_MODULE_NAME << "Create socket failed, error code is " << errno
            << ", error is " << strerror(errno) << "."
            << std::endl;
            return -1;
        }

        if (bind_device.length() > 0) {
            if (setsockopt(socketfd, SOL_SOCKET, SO_BINDTODEVICE,
                           bind_device.c_str(), static_cast<socklen_t>(bind_device.length())) < 0) {
                std::cerr <<  LOG_MODULE_NAME << "SO_BINDTODEVICE failed, error code is " << errno
                << ", error is " << strerror(errno) << "."
                << std::endl;
                return -1;
            }
        }

        if (pmtudisc >= 0) {
            if (setsockopt(socketfd, SOL_IP, IP_MTU_DISCOVER, &pmtudisc, sizeof(pmtudisc)) == -1) {
                std::cerr <<  LOG_MODULE_NAME << "IP_MTU_DISCOVER failed, error code is " << errno
                << ", error is " << strerror(errno) << "."
                << std::endl;
                return -1;
            }
        }
    }
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
    std::string proto_config{};
    if (ext_config) {
        proto_config = ext_config;
    }
    std::cout << LOG_MODULE_NAME << "proto_config is " << proto_config <<  std::endl;

    _init_context(ctx, proto_config);


    for (size_t i = 0; i < ctx->remoteips.size(); ++i) {
        ctx->proto_header_len = static_cast<uint32_t>(_init_proto_header(ctx->buffers[i]));
        int ret = _init_sockets(ctx->remoteips[i], ctx->remote_addrs[i], ctx->socketfds[i],
                                ctx->bind_device, ctx->pmtudisc);
        if (ret != 0) {
            std::cerr << LOG_MODULE_NAME << "Failed with index: " << i << std::endl;
            return ret;
        }
    }
    return 0;
}




int _export_packet_in_one_socket(AddressV4V6& remote_addr_v4v6, int& socketfd, std::vector<char>& buffer,
                                 uint32_t content_offset, const uint8_t *packet, uint32_t len) {

    struct sockaddr* remote_addr = remote_addr_v4v6.getSockAddr();
    size_t socklen = remote_addr_v4v6.getSockLen();
    size_t length = (size_t) (len <= 65535 ? len : 65535);


    std::memcpy(reinterpret_cast<void*>(&(buffer[content_offset])),
                reinterpret_cast<const void*>(packet), length);
    ssize_t nSend = sendto(socketfd, &(buffer[0]), length + content_offset, 0, remote_addr,
                           static_cast<socklen_t>(socklen));
    while (nSend == -1 && errno == ENOBUFS) {
        usleep(1000);
        nSend = static_cast<int>(sendto(socketfd, &(buffer[0]), length + content_offset, 0, remote_addr,
                                        static_cast<socklen_t>(socklen)));
    }
    if (nSend == -1) {
        std::cerr <<  LOG_MODULE_NAME << "Send to socket failed, error code is " << errno
        << ", error is " << strerror(errno) << "."
        << std::endl;
        return -1;
    }
    if (nSend < (ssize_t) (length + content_offset)) {
        std::cerr <<  LOG_MODULE_NAME << "Send socket " << length + content_offset
        << " bytes, but only " << nSend <<
        " bytes are sent success." << std::endl;
        return 1;
    }
    return 0;
}


int export_packet(void* ext_handle, const uint8_t *packet, uint32_t len) {
    if (!ext_handle) {
        return 1;
    }
    packet_agent_extension_itf_t* extension_itf = reinterpret_cast<packet_agent_extension_itf_t*>(ext_handle);
    if (!extension_itf->ctx) {
        return 1;
    }
    extension_ctx_t* ctx = reinterpret_cast<extension_ctx_t*>(extension_itf->ctx);

    int ret = 0;
    for (size_t i = 0; i < ctx->remoteips.size(); ++i) {
        ret |= _export_packet_in_one_socket(ctx->remote_addrs[i], ctx->socketfds[i], ctx->buffers[i],
                                            ctx->proto_header_len, packet, len);
    }
    return ret;
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

    for (size_t i = 0; i < ctx->remoteips.size(); ++i) {
        if (ctx->socketfds[i] != INVALIDE_SOCKET_FD) {
            close(ctx->socketfds[i]);
            ctx->socketfds[i] = INVALIDE_SOCKET_FD;
        }
    }
    return 0;
}

// 
int terminate(void* ext_handle) {
    if (ext_handle) {
        packet_agent_extension_itf_t* handle = reinterpret_cast<packet_agent_extension_itf_t*>(ext_handle);
        if (handle->ctx) {
            delete reinterpret_cast<extension_ctx_t*>(handle->ctx);
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