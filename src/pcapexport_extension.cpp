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



PcapExportExtension::PcapExportExtension(const ext_type_t ext_type, const std::string& ext_config) :
        _ext_type(ext_type),
        _ext_config(ext_config) {
    _type = exporttype::extension;
    _handle = nullptr;
}

PcapExportExtension::~PcapExportExtension() {
    closeExport();
}

int PcapExportExtension::loadLibrary() {

    memset(&_extension_itf, 0, sizeof(_extension_itf));

    // parse json
    std::stringstream ss(_ext_config);
    boost::property_tree::ptree pt;
    try {
        boost::property_tree::read_json(ss, pt);
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << StatisLogContext::getTimeString() << "Parse ext config failed!" << std::endl;
        return -1;
    }

    // load ext handle
    if (pt.get_child_optional(EXT_CONFIG_KEY_OF_LIBRARY_PATH)) {
        std::string ext_file_path = pt.get<std::string>(EXT_CONFIG_KEY_OF_LIBRARY_PATH);

        const char* dl_err = dlerror();
        _handle = dlopen(ext_file_path.c_str(), RTLD_LAZY);
        dl_err = dlerror();
        if (dl_err) {
            std::cerr  << dl_err << std::endl;
            return -1;
        }
        if (!_handle) {
            std::cerr << StatisLogContext::getTimeString() << "Load plugin " <<  ext_file_path << " failed!" << std::endl;
            return -1;
        }
    } else {
        std::cerr << StatisLogContext::getTimeString() << "Missing ext_file_path in config" << std::endl;
        return -1;
    }

    // call entry func for initialization
    const char* dl_err = dlerror();
    pf_entry_t entry_func = (pf_entry_t)dlsym(_handle, EXT_EXTRY_POINT);
    dl_err = dlerror();
    if (dl_err) {
        std::cerr << StatisLogContext::getTimeString() << "Load func " << EXT_EXTRY_POINT << " error: " << dl_err << std::endl;
        return -1;
    }    
    entry_func(&_extension_itf);



    return 0;
}

int PcapExportExtension::initExport() {
    if (loadLibrary()) {
        std::cerr << StatisLogContext::getTimeString() << "Load Extension Failed!" << std::endl;
        return -1;
    }

    int ret = 0;
    if (_extension_itf.init_export_func) {
       ret = _extension_itf.init_export_func(&_extension_itf, _ext_config.c_str());
    }
    return ret;
}




int PcapExportExtension::closeExport() {
    int ret = 0;
    if (_extension_itf.close_export_func) {
        ret = _extension_itf.close_export_func(&_extension_itf);
        _extension_itf.close_export_func = nullptr;
    }

    // terminate
    if (_extension_itf.terminate_func) {
        ret |= _extension_itf.terminate_func(&_extension_itf);
        _extension_itf.terminate_func = nullptr;
    }

    // unload library
    if (_handle) {
        dlclose(_handle);
        _handle = nullptr;
    }


    return ret;
}


int PcapExportExtension::exportPacket(const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    int ret = 0;
    if (_extension_itf.export_packet_func) {
        ret = _extension_itf.export_packet_func(&_extension_itf, header, pkt_data);
    } else {
        std::cerr << StatisLogContext::getTimeString() << "export_packet_func not exist" << std::endl;
        return -1;
    }
    return ret;
}



