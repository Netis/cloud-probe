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

#define VXLAN_DST_PORT   4789
#define INVALIDE_SOCKET_FD  -1
#define UDP_HEADER_LENGTH  8

#define PROTO_CONFIG_KEY_EXT_PARAMS_USE_DEFAULT "use_default_header"
#define PROTO_CONFIG_KEY_EXT_PARAMS_VNI "vni"


#define LOG_MODULE_NAME "proto_vxlan: "

typedef struct _VxLANHdr {
    uint32_t flag_rsv;
    uint32_t vni_rsv;
} VxLANHdr;

typedef struct _proto_extension_ctx {
    uint8_t use_default_header;
    uint8_t pad0;
    uint16_t pad1;
    uint32_t vni;
    std::vector<std::string> remoteips;
    std::vector<int> socketfds;
    std::vector<struct AddressV4V6> remote_addrs;
    std::vector<std::vector<char>> buffers;
    uint32_t proto_header_len;
    std::string bind_device;
    int pmtudisc;
}ProtoExtensionCtx;

// tunnel header in outer L3 payload
int get_proto_header_size(void* ext_handle, uint8_t* packet, uint32_t* len) {
    // TBD: support optional header fields
    return sizeof(VxLANHdr) + UDP_HEADER_LENGTH;
}



int _init_proto_header(std::vector<char>& buffer, uint32_t vni) {
    VxLANHdr *hdr = reinterpret_cast<VxLANHdr*>(&(buffer[0]));
    hdr->flag_rsv = htonl(0x08000000);
    hdr->vni_rsv = htonl(vni << 8);
    return sizeof(VxLANHdr);
}


int _init_sockets(std::string& remote_ip, AddressV4V6& remote_addr, int& socketfd,
                  std::string& bind_device, int pmtudisc) {
    if (socketfd == INVALIDE_SOCKET_FD) {
        int err = remote_addr.buildAddr(remote_ip.c_str(), VXLAN_DST_PORT);
        if (err != 0) {
            std::cerr <<  LOG_MODULE_NAME << "buildAddr failed, ip is " << remote_ip.c_str()
            << std::endl;
            return err;
        }

        int domain = remote_addr.getDomainAF_NET();
        if ((socketfd = socket(domain, SOCK_DGRAM, 0)) == INVALIDE_SOCKET_FD) {
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

int init_export(void* ext_handle) {
    if (!ext_handle) {
        return 1;
    }

    PacketAgentProtoExtension* proto_extension = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
    if (!proto_extension->ctx) {
        return 1;
    }

    ProtoExtensionCtx* ctx = reinterpret_cast<ProtoExtensionCtx*>(proto_extension->ctx);

    for (size_t i = 0; i < ctx->remoteips.size(); ++i) {
        ctx->proto_header_len = static_cast<uint32_t>(_init_proto_header(ctx->buffers[i], ctx->vni));
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
    PacketAgentProtoExtension* proto_extension = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
    if (!proto_extension->ctx) {
        return 1;
    }
    ProtoExtensionCtx* ctx = reinterpret_cast<ProtoExtensionCtx*>(proto_extension->ctx);

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
    PacketAgentProtoExtension* proto_extension = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
    if (!proto_extension->ctx) {
        return 1;
    }
    ProtoExtensionCtx* ctx = reinterpret_cast<ProtoExtensionCtx*>(proto_extension->ctx);

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
        PacketAgentProtoExtension* handle = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
        if (handle->ctx) {
            delete reinterpret_cast<ProtoExtensionCtx*>(handle->ctx);
        }
    }
    return 0;
}



int _reset_context(ProtoExtensionCtx* ctx) {
    ctx->use_default_header = 0;
    ctx->pad0 = 0;
    ctx->pad1 = 0;
    ctx->vni = 0;
    ctx->pmtudisc = -1;
    ctx->proto_header_len = 0;
    ctx->remoteips.clear();
    ctx->socketfds.clear();
    ctx->remote_addrs.clear();
    ctx->buffers.clear();
    ctx->bind_device = "";
    return 0;
}

int _init_remote_ips(ProtoExtensionCtx* ctx, std::string& remoteip_config) {
    std::vector<std::string>& ipref = ctx->remoteips;
    std::stringstream ss(remoteip_config);
    boost::property_tree::ptree remote_ip_tree;

    try {
        boost::property_tree::read_json(ss, remote_ip_tree);
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << LOG_MODULE_NAME << "Parse remote_ips json string failed!" << std::endl;
        return -1;
    }

    for (auto it = remote_ip_tree.begin(); it != remote_ip_tree.end(); it++) {
        ipref.push_back(it->second.get_value<std::string>());
    }

    return 0;
}

int _init_socket_configs(ProtoExtensionCtx* ctx, std::string& socket_config) {
    std::stringstream ss(socket_config);
    boost::property_tree::ptree socket_config_tree;
    try {
        boost::property_tree::read_json(ss, socket_config_tree);
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << LOG_MODULE_NAME << "Parse socket_config json string failed!" << std::endl;
        return -1;
    }

    if (socket_config_tree.get_child_optional(SOCKET_CONFIG_KEY_SO_BINDTODEVICE)) {
        ctx->bind_device = socket_config_tree.get<std::string>(SOCKET_CONFIG_KEY_SO_BINDTODEVICE);
    }

    if (socket_config_tree.get_child_optional(SOCKET_CONFIG_KEY_IP_MTU_DISCOVER)) {
        ctx->pmtudisc = socket_config_tree.get<int>(SOCKET_CONFIG_KEY_IP_MTU_DISCOVER);
    }

    return 0;
}


int _init_proto_config(ProtoExtensionCtx* ctx, std::string& proto_config) {
    std::stringstream ss(proto_config);
    boost::property_tree::ptree proto_config_tree;

    try {
        boost::property_tree::read_json(ss, proto_config_tree);
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << LOG_MODULE_NAME << "Parse proto_config json string failed!" << std::endl;
        return -1;
    }

    if (proto_config_tree.get_child_optional(PROTO_CONFIG_KEY_EXTERN_PARAMS)) {
        boost::property_tree::ptree& config_items = proto_config_tree.get_child(PROTO_CONFIG_KEY_EXTERN_PARAMS);
        if (config_items.get_child_optional(PROTO_CONFIG_KEY_EXT_PARAMS_USE_DEFAULT)) {
            ctx->use_default_header = static_cast<uint8_t>(config_items.get<bool>(PROTO_CONFIG_KEY_EXT_PARAMS_USE_DEFAULT));
            if (ctx->use_default_header) {
                return 0;
            }
        }

        if (config_items.get_child_optional(PROTO_CONFIG_KEY_EXT_PARAMS_VNI)) {
            ctx->vni = config_items.get<uint32_t>(PROTO_CONFIG_KEY_EXT_PARAMS_VNI);
            if (ctx->vni >= 0x1000000) {
                std::cerr << LOG_MODULE_NAME << "Invalid VNI value (greater than 2 ^ 24)!" << std::endl;
                ctx->vni = 0;
            }
        }
    }

    return 0;
}


int _init_context(ProtoExtensionCtx* ctx, std::string& remoteip_config, std::string& socket_config, std::string& proto_config) {
    _reset_context(ctx);
    ctx->use_default_header = 1;

    if (_init_remote_ips(ctx, remoteip_config)) {
        return 1;
    }

    if (_init_socket_configs(ctx, socket_config)) {
        return 1;
    }

    if (_init_proto_config(ctx, proto_config)) {
        return 1;
    }

    // allocate space for socket
    unsigned long remote_ips_size = ctx->remoteips.size();
    ctx->remote_addrs.resize(remote_ips_size);
    ctx->socketfds.resize(remote_ips_size);
    ctx->buffers.resize(remote_ips_size);
    for (size_t i = 0; i < remote_ips_size; ++i) {
        ctx->socketfds[i] = INVALIDE_SOCKET_FD;
        ctx->buffers[i].resize(65535 + sizeof(VxLANHdr) + UDP_HEADER_LENGTH, '\0'); // original packet, plus tunnel header in outer L3 payload
    }

    return 0;
}


int packet_agent_proto_extionsion_entry(void* ext_handle) {
    if (!ext_handle) {
        std::cerr << LOG_MODULE_NAME << "The ext_handle is not ready!" << std::endl;
        return -1;
    }

    ProtoExtensionCtx* ctx = new ProtoExtensionCtx();
    if (!ctx) {
        std::cerr << LOG_MODULE_NAME << "malloc context failed!" << std::endl;
        return -1;
    }

    PacketAgentProtoExtension* proto_extension = (PacketAgentProtoExtension* )ext_handle;
    std::string remoteip_config{};
    if (proto_extension->remoteip_config) {
        remoteip_config = proto_extension->remoteip_config;
    }
    std::cout << LOG_MODULE_NAME << "remoteip_config is " << remoteip_config <<  std::endl;

    std::string socket_config{};
    if (proto_extension->socket_config) {
        socket_config = proto_extension->socket_config;
    }
    std::cout << LOG_MODULE_NAME << "socket_config is " << socket_config <<  std::endl;

    std::string proto_config{};
    if (proto_extension->proto_config) {
        proto_config = proto_extension->proto_config;
    }
    std::cout << LOG_MODULE_NAME << "proto_config is " << proto_config <<  std::endl;

    _init_context(ctx, remoteip_config, socket_config, proto_config);

    proto_extension->get_proto_header_size_func = get_proto_header_size;
    proto_extension->init_export_func = init_export;
    proto_extension->export_packet_func = export_packet;
    proto_extension->close_export_func = close_export;
    proto_extension->terminate_func = terminate;
    proto_extension->ctx = ctx;

    std::cout << LOG_MODULE_NAME << "The context values: " << std::endl;
    std::cout << "use_default_header " << (uint32_t)ctx->use_default_header << std::endl;
    std::cout << "vni " << (uint32_t)ctx->vni << std::endl;

    return 0;
}



#ifdef __cplusplus
}
#endif