//
// Created by root on 11/15/19.
//
#include <iostream>
#include <cstring>
#include <pcap/pcap.h>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>


#ifdef WIN32
    #include <WinSock2.h>
    #include <BaseTsd.h>
    #include <windows.h>
    typedef SSIZE_T ssize_t;
    #define usleep Sleep
    #define IPPROTO_GRE 47
#else
    #include <arpa/inet.h>
    #include <unistd.h>
    #include <netdb.h>
    #include <dlfcn.h>
#endif


#include "pcapexportplugin.h"
#include "statislog.h"

const int INVALIDE_SOCKET_FD = -1;
const int EXT_HEADER_LENGTH_MAX = 256;

PcapExportPlugin::PcapExportPlugin(const std::vector<std::string>& remoteips, const std::string& proto_config,
                                   const std::string& bind_device, const int pmtudisc) :
        _remoteips(remoteips),
        _socketfds(remoteips.size()),
        _remote_addrs(remoteips.size()),
        _buffers(remoteips.size()),
        _proto_config(proto_config),
        _bind_device(bind_device),
        _pmtudisc(pmtudisc) {

    _type = exporttype::by_plugin;

    _proto_header_len = 0;

    for (size_t i = 0; i < remoteips.size(); ++i) {
        _socketfds[i] = INVALIDE_SOCKET_FD;
        _buffers[i].resize(65535 + EXT_HEADER_LENGTH_MAX, '\0');
    }
}

PcapExportPlugin::~PcapExportPlugin() {
    closeExport();


}

int PcapExportPlugin::initSockets(size_t index) {
    auto& socketfd = _socketfds[index];
    auto& grebuffer = _buffers[index];

    if (socketfd == INVALIDE_SOCKET_FD) {
#ifdef WIN32
        grehdr_t grehdr;
        grehdr.flags = htons(0x2000);
        grehdr.protocol = htons(0x6558);
        grehdr.keybit = htonl(0);
        std::memcpy(reinterpret_cast<void*>(&(grebuffer[0])), &grehdr, sizeof(grehdr_t));
        _proto_header_len = sizeof(grehdr_t);
#else
        uint32_t tmp_len = 0;
        for (size_t i = 0; i < _proto_extension.size(); ++i) {
            if (_proto_extension[i].get_proto_initial_header_func) {
                tmp_len = 65535 + EXT_HEADER_LENGTH_MAX - _proto_header_len;
                _proto_extension[i].get_proto_initial_header_func(&_proto_extension[i],
                                         reinterpret_cast<uint8_t*>(&(grebuffer[_proto_header_len])),
                                         &tmp_len);
                _proto_header_len += tmp_len;
            }
            if (_proto_extension[i].update_proto_header_check_func) {
                _proto_extension[i].need_update_header =
                        static_cast<uint8_t>(_proto_extension[i].update_proto_header_check_func(&_proto_extension[i]));
            }
        }
#endif

        int err = _remote_addrs[index].buildAddr(_remoteips[index].c_str());
        if (err != 0) {
            std::cerr << StatisLogContext::getTimeString() << "buildAddr failed, ip is " << _remoteips[index].c_str()
            << std::endl;
            return err;
        }

        int domain = _remote_addrs[index].getDomainAF_NET();
        if ((socketfd = socket(domain, SOCK_RAW, IPPROTO_GRE)) == INVALIDE_SOCKET_FD) {
            std::cerr << StatisLogContext::getTimeString() << "Create socket failed, error code is " << errno
            << ", error is " << strerror(errno) << "."
            << std::endl;
            return -1;
        }

        if (_bind_device.length() > 0) {
#ifdef WIN32
            //TODO: bind device on WIN32
#else
            if (setsockopt(socketfd, SOL_SOCKET, SO_BINDTODEVICE, _bind_device.c_str(), _bind_device.length()) < 0) {
                std::cerr << StatisLogContext::getTimeString() << "SO_BINDTODEVICE failed, error code is " << errno
                << ", error is " << strerror(errno) << "."
                << std::endl;
                return -1;
            }
#endif // WIN32
        }

#ifdef WIN32
        //TODO: bind device on WIN32
#else
        if (_pmtudisc >= 0) {
            if (setsockopt(socketfd, SOL_IP, IP_MTU_DISCOVER, &_pmtudisc, sizeof(_pmtudisc)) == -1) {
                std::cerr << StatisLogContext::getTimeString() << "IP_MTU_DISCOVER failed, error code is " << errno
                << ", error is " << strerror(errno) << "."
                << std::endl;
                return -1;
            }
        }
#endif // WIN32
    }
    return 0;
}

int PcapExportPlugin::loadLibrary() {
#ifdef WIN32
#else
    // parse json
    std::stringstream ss(_proto_config);
    boost::property_tree::ptree pt;
    try {
        boost::property_tree::read_json(ss, pt);
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << "Parse json string failed!" << std::endl;
        return -1;
    }
    // load library
    for (auto & item : pt) {
        PacketAgentProtoExtension proto_ext;
        proto_ext.need_update_header = 0;
        proto_ext.ext_title = "";
        proto_ext.handle = nullptr;
        proto_ext.ctx = nullptr;
        proto_ext.get_proto_header_size_func = nullptr;
        proto_ext.get_proto_initial_header_func = nullptr;
        proto_ext.terminate_func = nullptr;
        proto_ext.update_proto_header_check_func = nullptr;
        proto_ext.update_proto_header_func = nullptr;

        // load ext handle
        if (item.second.get_child_optional("ext_title")) {
            std::string ext_title = item.second.get<std::string>("ext_title");
            std::string module_name = "lib" + ext_title + ".so";
            proto_ext.ext_title = ext_title;
            proto_ext.handle = dlopen(module_name.c_str(), RTLD_LAZY);
            if (!proto_ext.handle) {
                std::cerr << "Load plugin " <<  module_name << " failed!" << std::endl;
                return -1;
            }
        } else {
            std::cerr << "Missing ext_title" << std::endl;
            return -1;
        }

        // call entry func for initialization
        if (item.second.get_child_optional("entry")) {
            std::string entry = item.second.get<std::string>("entry");
            const char* dl_err = dlerror();
            entry_func_t entry_func = (entry_func_t)dlsym(proto_ext.handle, entry.c_str());
            dl_err = dlerror();
            if (dl_err) {
                std::cerr << "Load func " << entry << " error: " << dl_err << std::endl;
                return -1;
            }

            proto_ext.json_config = item.second; // init ptree of json config first
            entry_func(&proto_ext);
        } else {
            std::cerr << "Missing ext_title" << std::endl;
            return -1;
        }

        _proto_extension.push_back(proto_ext);
    }
#endif
    return 0;
}

int PcapExportPlugin::initExport() {
    if (loadLibrary()) {
        std::cerr << "Load Extension Failed!" << std::endl;
    }

    for (size_t i = 0; i < _remoteips.size(); ++i) {
        int ret = initSockets(i);
        if (ret != 0) {
            std::cerr << "Failed with index: " << i << std::endl;
            return ret;
        }
    }
    return 0;
}

int PcapExportPlugin::closeExport() {
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        if (_socketfds[i] != INVALIDE_SOCKET_FD) {
#ifdef WIN32
            shutdown(_socketfds[i], SD_BOTH);
#else
            close(_socketfds[i]);
#endif // WIN32
            _socketfds[i] = INVALIDE_SOCKET_FD;
        }
    }
#ifdef WIN32
#else
    for (size_t i = 0; i < _proto_extension.size(); ++i) {
        // terminate
        if (_proto_extension[i].terminate_func) {
            _proto_extension[i].terminate_func(&_proto_extension[i]);
            _proto_extension[i].terminate_func = nullptr;
        }
        // unload library
        if (_proto_extension[i].handle) {
            dlclose(_proto_extension[i].handle);
            _proto_extension[i].handle = nullptr;
        }
    }
#endif


    return 0;
}

int PcapExportPlugin::exportPacket(const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    int ret = 0;
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        ret |= exportPacket(i, header, pkt_data);
    }
    return ret;
}

int PcapExportPlugin::exportPacket(size_t index, const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    auto& grebuffer = _buffers[index];
    int socketfd = _socketfds[index];

    auto& addrV4V6 = _remote_addrs[index];
    struct sockaddr* remote_addr = addrV4V6.getSockAddr();
    size_t socklen = addrV4V6.getSockLen();

    size_t length = (size_t) (header->caplen <= 65535 ? header->caplen : 65535);
#ifdef WIN32
#else
    uint32_t offset_tmp = 0;
    uint32_t input_tmp = 0;
    for (size_t i = 0; i < _proto_extension.size(); ++i) {
        input_tmp = _proto_header_len;
        if (_proto_extension[i].need_update_header && _proto_extension[i].update_proto_header_func) {
            _proto_extension[i].update_proto_header_func(&_proto_extension[i],
                                                         reinterpret_cast<uint8_t*>(&(grebuffer[offset_tmp])),
                                                         &input_tmp);
            offset_tmp += input_tmp;
            input_tmp = _proto_header_len;
        }
    }
#endif
    std::memcpy(reinterpret_cast<void*>(&(grebuffer[_proto_header_len])),
                reinterpret_cast<const void*>(pkt_data), length);
    ssize_t nSend = sendto(socketfd, &(grebuffer[0]), length + _proto_header_len, 0, remote_addr,
                           socklen);
    while (nSend == -1 && errno == ENOBUFS) {
        usleep(1000);
        nSend = static_cast<int>(sendto(socketfd, &(grebuffer[0]), length + _proto_header_len, 0, remote_addr,
                                        socklen));
    }
    if (nSend == -1) {
        std::cerr << StatisLogContext::getTimeString() << "Send to socket failed, error code is " << errno
        << ", error is " << strerror(errno) << "."
        << std::endl;
        return -1;
    }
    if (nSend < (ssize_t) (length + _proto_header_len)) {
        std::cerr << StatisLogContext::getTimeString() << "Send socket " << length + _proto_header_len
        << " bytes, but only " << nSend <<
        " bytes are sent success." << std::endl;
        return 1;
    }
    return 0;
}
