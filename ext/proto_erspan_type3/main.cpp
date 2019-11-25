#include <iostream>
#include <netinet/in.h>
#include <chrono>

#include "packet_agent_ext.h"

// using namespace std;


#ifdef __cplusplus
extern "C"
{
#endif

#define ETHERNET_TYPE_ERSPAN_TYPE3    0x22eb

typedef struct _ERSpanType23GREHdr {
    uint16_t flags;
    uint16_t protocol;
    uint32_t sequence;
} ERSpanType23GREHdr;

typedef struct _ERSpanType3Hdr {
    uint16_t ver_vlan;
    uint16_t flags_spanId;
    uint32_t timestamp;
    uint16_t pad0;
    uint16_t pad1;
} ERSpanType3Hdr;

typedef struct _proto_erspan_type3_ctx {
    uint8_t use_default_header;
    uint8_t enable_sequence;
    uint8_t enable_vlan;
    uint8_t enable_timestamp;  // granularity : 100 microseconds
    uint32_t sequence;
    uint16_t vlan;
    uint16_t pad;
    std::chrono::high_resolution_clock::time_point time_begin;
}ProtoErspanType3Ctx;


int get_proto_header_size(void* ext_handle, uint8_t* packet, uint32_t* len) {
    // TBD: support optional header fields
    return sizeof(ERSpanType23GREHdr) + sizeof(ERSpanType3Hdr);
}


int get_proto_initial_header(void* ext_handle, uint8_t* dst, uint32_t* len) {
    uint32_t ret_len = sizeof(ERSpanType23GREHdr) + sizeof(ERSpanType3Hdr);
    if (!dst || !len) {
        std::cerr << "proto_erspan_type3: get_proto_initial_header: invalid param." << std::endl;
        return 1;
    }
    if (*len < sizeof(ERSpanType23GREHdr) + sizeof(ERSpanType3Hdr)) {
        std::cerr << "proto_erspan_type3: get_proto_initial_header: buffer len is too small" << std::endl;
        *len = ret_len;
        return 1;
    }
    ProtoErspanType3Ctx* ctx = nullptr;
    if (ext_handle) {
        PacketAgentProtoExtension* handle = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
        ctx = reinterpret_cast<ProtoErspanType3Ctx*>(handle->ctx);
    }

    ERSpanType23GREHdr *hdr = reinterpret_cast<ERSpanType23GREHdr*>(dst);
    hdr->flags = htons(0x1000);  // S bit
    hdr->protocol = htons(ETHERNET_TYPE_ERSPAN_TYPE3);
    hdr->sequence = htonl(ctx ? ctx->sequence : 0);

    ERSpanType3Hdr* erspan_hdr = reinterpret_cast<ERSpanType3Hdr*>(dst + sizeof(ERSpanType23GREHdr));
    uint16_t ver_vlan = 0x2000; // ver = 2
    ver_vlan |= static_cast<uint16_t>(ctx ? ctx->vlan : 0);
    erspan_hdr->ver_vlan = htons(ver_vlan);
    erspan_hdr->flags_spanId = 0;
    erspan_hdr->timestamp = 0;  // granularity : 100 microseconds
    erspan_hdr->pad0 = 0;
    erspan_hdr->pad1 = 0;
    *len = ret_len;
    return 0;
}

int update_proto_header_check(void* ext_handle) {
    if (ext_handle) {
        PacketAgentProtoExtension* handle = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
        if (handle->ctx) {
            ProtoErspanType3Ctx* ctx = reinterpret_cast<ProtoErspanType3Ctx*>(handle->ctx);
            if (ctx->use_default_header) {
                return 0;
            } else {
                return ctx->enable_sequence | ctx->enable_timestamp;
            }
        }
    }
    return 0;
}

int update_proto_header(void* ext_handle, uint8_t* dst, uint32_t* len) {
    uint32_t ret_len = sizeof(ERSpanType23GREHdr) + sizeof(ERSpanType3Hdr);
    if (ext_handle) {
        PacketAgentProtoExtension* handle = reinterpret_cast<PacketAgentProtoExtension*>(ext_handle);
        if (handle->ctx) {
            ProtoErspanType3Ctx *ctx = reinterpret_cast<ProtoErspanType3Ctx *>(handle->ctx);
            if (!dst || !len) {
                std::cerr << "proto_erspan_type3: update_proto_header: invalid param." << std::endl;
                return -1;
            }
            if (*len < sizeof(ERSpanType23GREHdr) + sizeof(ERSpanType3Hdr)) {
                std::cerr << "proto_erspan_type3: update_proto_header: buffer len is too small" << std::endl;
                *len = ret_len;
                return -1;
            }
            if (ctx->enable_sequence) {
                ERSpanType23GREHdr *hdr = reinterpret_cast<ERSpanType23GREHdr *>(dst);
                hdr->sequence = htonl(ctx->sequence);
                ctx->sequence++;
            }
            if (ctx->enable_timestamp) {
                ERSpanType3Hdr *erspan_hdr = reinterpret_cast<ERSpanType3Hdr *>(dst + sizeof(ERSpanType23GREHdr));
                std::chrono::high_resolution_clock::time_point time_now = std::chrono::high_resolution_clock::now();
                std::chrono::microseconds micro_seconds =
                        std::chrono::duration_cast<std::chrono::microseconds>(time_now - ctx->time_begin);
                erspan_hdr->timestamp = htonl(static_cast<uint32_t>(micro_seconds.count() / 100));
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
            delete reinterpret_cast<ProtoErspanType3Ctx*>(handle->ctx);
        }
    }
    return 0;
}


int init_config(ProtoErspanType3Ctx* ctx, boost::property_tree::ptree& json_config ) {

    memset(ctx, 0, sizeof(ProtoErspanType3Ctx));
    ctx->use_default_header = 1;

    auto entry_opt = json_config.get_child_optional("ext_params");
    std::cout << "init_config called " <<std::endl;
    if (json_config.get_child_optional("ext_params")) {
        boost::property_tree::ptree& config_items = json_config.get_child("ext_params");
        if (config_items.get_child_optional("use_default_header")) {
            ctx->use_default_header = config_items.get<bool>("use_default_header");
        }
        if (config_items.get_child_optional("enable_vlan")) {
            ctx->enable_vlan = config_items.get<bool>("enable_vlan");
        }

        if (config_items.get_child_optional("enable_sequence")) {
            ctx->enable_sequence = config_items.get<bool>("enable_sequence");
        }

        if (config_items.get_child_optional("enable_timestamp")) {
            ctx->enable_timestamp = config_items.get<bool>("enable_timestamp");
            if (ctx->enable_timestamp ) {
                ctx->time_begin = std::chrono::high_resolution_clock::now();
            }
        }

        if (config_items.get_child_optional("vlan")) {
            ctx->vlan = config_items.get<uint16_t>("vlan");
        }

        if (config_items.get_child_optional("sequence_begin")) {
            ctx->sequence = config_items.get<uint32_t>("sequence_begin");
        }
    }
    return 0;
}


int packet_agent_proto_extionsion_entry(void* ext_handle) {
    if (!ext_handle) {
        std::cerr << "proto_erspan_type3: The ext_handle is not ready!" << std::endl;
        return -1;
    }

    ProtoErspanType3Ctx* ctx = new ProtoErspanType3Ctx();
    if (!ctx) {
        std::cerr << "proto_erspan_type3: malloc context failed!" << std::endl;
        return -1;
    }

    PacketAgentProtoExtension* proto_extension = (PacketAgentProtoExtension* )ext_handle;
    init_config(ctx, proto_extension->json_config);

    std::cout << "use_default_header " << (uint32_t)ctx->use_default_header <<std::endl;
    std::cout << "enable_sequence " << (uint32_t)ctx->enable_sequence <<std::endl;
    std::cout << "enable_vlan " << (uint32_t)ctx->enable_vlan <<std::endl;
    std::cout << "enable_timestamp " << (uint32_t)ctx->enable_timestamp <<std::endl;
    std::cout << "sequence " << (uint32_t)ctx->sequence <<std::endl;
    std::cout << "vlan " << (uint32_t)ctx->vlan <<std::endl;

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