#include <iostream>
#include <netinet/in.h>

#include "packet_agent_ext.h"


// using namespace std;


#ifdef __cplusplus
extern "C"
{
#endif

#define GRE_TYPE_TRANS_BRIDGING 0x6558
#define GRE_STANDARD_MAX_HEADER_LENGTH 20

/* GRE related stuff */
typedef struct _GREHdr {
    uint8_t flags;
    uint8_t version;
    uint16_t ether_type;
} GREHdr;

typedef struct _proto_gre_ctx {
    uint8_t use_default_header;
    uint8_t enable_sequence;
    uint8_t enable_key;
    uint8_t pad;
    uint32_t sequence;
    uint32_t key;
}ProtoGreCtx;



int get_proto_header_size(void* ext_handle, uint8_t* dst, uint32_t* len) {

    return sizeof(GREHdr);
}


uint32_t get_optional_header_size(void* ext_handle) {
    uint32_t ret_len = sizeof(GREHdr);
    if (ext_handle) {
        PacketAgentProtoExtension* handle = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
        if (handle->ctx) {
            ProtoGreCtx* ctx = reinterpret_cast<ProtoGreCtx*>(handle->ctx);

            if (ctx->enable_key) {
                ret_len += 4;
            }
            if (ctx->enable_sequence) {
                ret_len += 4;
            }
        }
    }
    return ret_len;
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


int get_proto_initial_header(void* ext_handle, uint8_t* dst, uint32_t* len) {
    uint32_t ret_len = get_optional_header_size(ext_handle);
    if (!dst || !len) {
        std::cerr << "proto_gre: get_proto_initial_header: invalid param." << std::endl;
        return 1;
    }
    if (*len < ret_len) {
        std::cerr << "proto_gre: get_proto_initial_header: buffer len is too small" << std::endl;
        *len = ret_len;
        return 1;
    }
    ProtoGreCtx* ctx = nullptr;
    if (ext_handle) {
        PacketAgentProtoExtension* handle = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
        ctx = reinterpret_cast<ProtoGreCtx*>(handle->ctx);
    }

    GREHdr *hdr = reinterpret_cast<GREHdr*>(dst);
    hdr->flags = 0;
    hdr->version = 0;
    hdr->ether_type = htons(GRE_TYPE_TRANS_BRIDGING);
    uint32_t offset = sizeof(GREHdr);
    if (ctx) {
        uint8_t flags = 0;
        if (ctx->enable_key) {
            flags = 0x20;
            hdr->flags |=flags;
            *((uint32_t*)(dst + offset)) = htonl(ctx->key);
            offset += 4;
        }
        if (ctx->enable_sequence) {
            flags = 0x10;
            hdr->flags |=flags;
            *((uint32_t*)(dst + offset)) = htonl(ctx->sequence);
            offset += 4;
        }
    }
    *len = ret_len;
    return 0;
}

int update_proto_header_check(void* ext_handle) {
    if (ext_handle) {
        PacketAgentProtoExtension* handle = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
        if (handle->ctx) {
            ProtoGreCtx* ctx = reinterpret_cast<ProtoGreCtx*>(handle->ctx);
            if (ctx->use_default_header) {
                return 0;
            } else {
                return ctx->enable_sequence;
            }
        }
    }
    return 0;
}

int update_proto_header(void* ext_handle, uint8_t* dst, uint32_t* len) {
    uint32_t ret_len = get_optional_header_size(ext_handle);
    if (ext_handle) {
        PacketAgentProtoExtension* handle = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
        if (handle->ctx) {
            ProtoGreCtx *ctx = reinterpret_cast<ProtoGreCtx *>(handle->ctx);
            if (!dst || !len) {
                std::cerr << "proto_gre: update_proto_header: invalid param." << std::endl;
                return -1;
            }
            if (*len < ret_len) {
                std::cerr << "proto_gre: update_proto_header: buffer len is too small" << std::endl;
                *len = ret_len;
                return -1;
            }
            uint32_t offset = sizeof(GREHdr);
            if (ctx->enable_sequence) {
                if (ctx->key) {
                    *((uint32_t*)(dst + offset + 4)) = htonl(ctx->sequence);
                } else {
                    *((uint32_t*)(dst + offset)) = htonl(ctx->sequence);
                }
                ctx->sequence++;
            }
        }
    }
    *len = ret_len;
    return 0;
}

int terminate(void* ext_handle) {
    if (ext_handle) {
        PacketAgentProtoExtension* handle = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
        if (handle->ctx) {
            delete reinterpret_cast<ProtoGreCtx*>(handle->ctx);
        }
    }
    return 0;
}


int init_config(ProtoGreCtx* ctx, boost::property_tree::ptree& json_config ) {

    memset(ctx, 0, sizeof(ProtoGreCtx));
    ctx->use_default_header = 1;

    auto entry_opt = json_config.get_child_optional("ext_params");
    if (json_config.get_child_optional("ext_params")) {
        boost::property_tree::ptree& config_items = json_config.get_child("ext_params");
        if (config_items.get_child_optional("use_default_header")) {
            ctx->use_default_header = config_items.get<bool>("use_default_header");
        }
        if (config_items.get_child_optional("enable_key")) {
            ctx->enable_key = config_items.get<bool>("enable_key");
        }
        if (config_items.get_child_optional("enable_sequence")) {
            ctx->enable_sequence = config_items.get<bool>("enable_sequence");
        }

        if (config_items.get_child_optional("key")) {
            ctx->key = config_items.get<uint16_t>("key");
        }

        if (config_items.get_child_optional("sequence_begin")) {
            ctx->sequence = config_items.get<uint32_t>("sequence_begin");
        }
    }
    return 0;
}


int packet_agent_proto_extionsion_entry(void* ext_handle) {
    if (!ext_handle) {
        std::cerr << "proto_gre: entry: The ext_handle is not ready!" << std::endl;
        return -1;
    }

    ProtoGreCtx* ctx = new ProtoGreCtx();
    if (!ctx) {
        std::cerr << "proto_gre: entry: malloc context failed!" << std::endl;
        return -1;
    }

    PacketAgentProtoExtension* proto_extension = (PacketAgentProtoExtension* )ext_handle;
    init_config(ctx, proto_extension->json_config);

    std::cout << "use_default_header " << (uint32_t)ctx->use_default_header <<std::endl;
    std::cout << "enable_sequence " << (uint32_t)ctx->enable_sequence <<std::endl;
    std::cout << "enable_key " << (uint32_t)ctx->enable_key <<std::endl;
    std::cout << "sequence " << (uint32_t)ctx->sequence <<std::endl;
    std::cout << "key " << (uint32_t)ctx->key <<std::endl;

    proto_extension->get_proto_header_size_func = get_proto_header_size;
    proto_extension->get_proto_initial_header_func = get_proto_initial_header;
    proto_extension->update_proto_header_check_func = update_proto_header_check;
    proto_extension->update_proto_header_func = update_proto_header;
    proto_extension->terminate_func = terminate;
    proto_extension->ctx = ctx;
    return 0;
}




#ifdef __cplusplus
}
#endif