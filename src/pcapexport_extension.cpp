//
// Created by root on 11/15/19.
//
#include <iostream>
#include <cstring>
#include <sstream>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include <dlfcn.h>
#include <pcap/pcap.h>

#include "pcapexport_extension.h"
#include "statislog.h"



PcapExportExtension::PcapExportExtension(const std::vector<std::string>& remoteips, const std::string& proto_config,
                                   const std::string& bind_device, const int pmtudisc) :
        _remoteips(remoteips),
        _proto_config(proto_config),
        _bind_device(bind_device),
        _pmtudisc(pmtudisc) {
    _type = exporttype::extension;
}

PcapExportExtension::~PcapExportExtension() {
    closeExport();
}


int PcapExportExtension::initConfigString() {
    std::stringstream ss;

    // general & init remote ips json string
    ss.clear();
    ss.str("");
    ss << "[ ";
    for (auto& ip: _remoteips) {
        ss << "\"" << ip << "\", ";
    }
    ss.seekp(-2, std::ios_base::cur); // remove last comma
    ss << " ]";
    _remoteips_config = ss.str();
    // std::cout << _remoteips_config << std::endl;
    _proto_extension.remoteip_config = _remoteips_config.c_str();

    // general & init socket configurations json string
    ss.clear();
    ss.str("");
    ss  << "{ "
            << "\"" << SOCKET_CONFIG_KEY_SO_BINDTODEVICE << "\": \"" << _bind_device << "\","
            << "\"" << SOCKET_CONFIG_KEY_IP_MTU_DISCOVER << "\": " << _pmtudisc
        << " }";

    _socket_config = ss.str();
    // std::cout << _socket_config << std::endl;
    _proto_extension.socket_config = _socket_config.c_str();

    // general & init protocol configurations json string
    // std::cout << _proto_config << std::endl;
    _proto_extension.proto_config = _proto_config.c_str();
    return 0;
}


int PcapExportExtension::loadLibrary() {
    // there is no class object in PacketAgentProtoExtension
    memset(&_proto_extension, 0, sizeof(_proto_extension));

    if (initConfigString()) {
        std::cerr << StatisLogContext::getTimeString() << "Init Config String Failed!" << std::endl;
        return -1;
    }

    // parse json
    std::stringstream ss(_proto_config);
    boost::property_tree::ptree pt;
    try {
        boost::property_tree::read_json(ss, pt);
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << StatisLogContext::getTimeString() << "Parse proto config failed!" << std::endl;
        return -1;
    }

    // load ext handle
    if (pt.get_child_optional(PROTO_CONFIG_KEY_LIBRARY_PATH)) {
        std::string ext_file_path = pt.get<std::string>(PROTO_CONFIG_KEY_LIBRARY_PATH);

        _proto_extension.ext_file_path = ext_file_path.c_str();
        const char* dl_err = dlerror();
        _proto_extension.handle = dlopen(ext_file_path.c_str(), RTLD_LAZY);
        dl_err = dlerror();
        if (dl_err) {
            std::cerr  << dl_err << std::endl;
            return -1;
        }
        if (!_proto_extension.handle) {
            std::cerr << StatisLogContext::getTimeString() << "Load plugin " <<  ext_file_path << " failed!" << std::endl;
            return -1;
        }
    } else {
        std::cerr << StatisLogContext::getTimeString() << "Missing ext_file_path in config" << std::endl;
        return -1;
    }

    // call entry func for initialization
    const char* dl_err = dlerror();
    pf_entry_t entry_func = (pf_entry_t)dlsym(_proto_extension.handle, ENTRY_POINT);
    dl_err = dlerror();
    if (dl_err) {
        std::cerr << StatisLogContext::getTimeString() << "Load func " << ENTRY_POINT << " error: " << dl_err << std::endl;
        return -1;
    }    
    entry_func(&_proto_extension);
    return 0;
}

int PcapExportExtension::initExport() {

    if (loadLibrary()) {
        std::cerr << StatisLogContext::getTimeString() << "Load Extension Failed!" << std::endl;
        return -1;
    }

    int ret = 0;
    if (_proto_extension.init_export_func) {
       ret = _proto_extension.init_export_func(&_proto_extension);
    }
    return ret;
}




int PcapExportExtension::closeExport() {
    int ret = 0;
    if (_proto_extension.close_export_func) {
        ret = _proto_extension.close_export_func(&_proto_extension);
        _proto_extension.close_export_func = nullptr;
    }

    // terminate
    if (_proto_extension.terminate_func) {
        ret |= _proto_extension.terminate_func(&_proto_extension);
        _proto_extension.terminate_func = nullptr;
    }

    // unload library
    if (_proto_extension.handle) {
        dlclose(_proto_extension.handle);
        _proto_extension.handle = nullptr;
    }

    return ret;
}


int PcapExportExtension::exportPacket(const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    int ret = 0;
    if (_proto_extension.export_packet_func) {
       ret = _proto_extension.export_packet_func(&_proto_extension, pkt_data, header->caplen);
    } else {
        std::cerr << StatisLogContext::getTimeString() << "export_packet_func not exist" << std::endl;
        return -1;
    }
    return ret;
}



