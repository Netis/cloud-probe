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
    #include <dlfcn.h>
#endif


#include "pcapexportplugin.h"
#include "statislog.h"

const int INVALIDE_SOCKET_FD = -1;
const int EXT_HEADER_LENGTH_MAX = 256;

PcapExportPlugin::PcapExportPlugin(const std::vector<std::string>& remoteips, const std::string& jsonstr,
                                   const std::string& bind_device, const int pmtudisc) :
        _remoteips(remoteips),
        _socketfds(remoteips.size()),
        _remote_addrs(remoteips.size()),
        _buffers(remoteips.size()),
        _json_str(jsonstr),
        _bind_device(bind_device),
        _pmtudisc(pmtudisc) {

    _type = exporttype::by_plugin;

    //_proto_header_buffer.resize(EXT_HEADER_LENGTH_MAX, '\0');
    _proto_header_len = 0;

    for (size_t i = 0; i < remoteips.size(); ++i) {
        _socketfds[i] = INVALIDE_SOCKET_FD;
        _buffers[i].resize(65535 + EXT_HEADER_LENGTH_MAX, '\0');
    }
}

PcapExportPlugin::~PcapExportPlugin() {
    closeExport();
#ifdef WIN32
#else
    for (size_t i = 0; i < _proto_extension.size(); ++i) {
        if (_proto_extension[i].handle) {
            dlclose(_proto_extension[i].handle);
        }
    }
#endif
}

int PcapExportPlugin::initSockets(size_t index) {
    auto& socketfd = _socketfds[index];
    auto& grebuffer = _buffers[index];

    if (socketfd == INVALIDE_SOCKET_FD) {
        uint32_t tmp_len = 0;
        for (size_t i = 0; i < _proto_extension.size(); ++i) {
            if (_proto_extension[i].get_proto_default_header_func) {
                tmp_len = 65535 + EXT_HEADER_LENGTH_MAX - _proto_header_len;
                _proto_extension[i].get_proto_default_header_func(&_proto_extension[i],
                                         reinterpret_cast<uint8_t*>(&(grebuffer[_proto_header_len])),
                                         &tmp_len);
                _proto_header_len += tmp_len;
            }
        }

        _remote_addrs[index].sin_family = AF_INET;
        _remote_addrs[index].sin_addr.s_addr = inet_addr(_remoteips[index].c_str());

        if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE)) == INVALIDE_SOCKET_FD) {
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

int PcapExportPlugin::initExport() {

#ifdef WIN32
    grehdr_t grehdr;
    grehdr.flags = htons(0x2000);
    grehdr.protocol = htons(0x6558);
    grehdr.keybit = htonl(0);
    std::memcpy(reinterpret_cast<void*>(&(_proto_header_buffer[0])), &grehdr, sizeof(grehdr_t));
    _proto_header_buffer_data_len = sizeof(grehdr_t);
#else
    // load library
    std::stringstream ss(_json_str);
    boost::property_tree::ptree pt;
    try {
        boost::property_tree::read_json(ss, pt);        //parse json
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << "Parse json string failed!" << std::endl;
        return -1;
    }

    for (auto & item : pt) {
        auto ext_title_opt = item.second.get_child_optional("ext_title");
        if (!ext_title_opt) {
            std::cerr << "Missing ext_title" << std::endl;
            return -1;
        }
        std::string ext_title = item.second.get<std::string>("ext_title");

        std::string module_name = "lib" + ext_title + ".so";
        PacketAgentProtoExtension ctx;
        ctx.ext_title = ext_title;
        ctx.handle = dlopen(module_name.c_str(), RTLD_LAZY);
        if (!ctx.handle) {
            std::cerr << "Load plugin " <<  module_name << " failed!" << std::endl;
            return -1;
        }

        auto entry_opt = item.second.get_child_optional("entry");
        if (!entry_opt) {
            std::cerr << "Missing ext_title" << std::endl;
            return -1;
        }
        std::string entry = item.second.get<std::string>("entry");
        const char* dl_err = dlerror();
        entry_func_t entry_func = (entry_func_t)dlsym(ctx.handle, entry.c_str());
        dl_err = dlerror();
        if (dl_err) {
            std::cerr << "Load func " << entry << " error: " << dl_err << std::endl;
            return -1;
        }
        ctx.pt = item.second;
        entry_func(&ctx);
        _proto_extension.push_back(ctx);
    }
#endif

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
    auto& remote_addr = _remote_addrs[index];

    size_t length = (size_t) (header->caplen <= 65535 ? header->caplen : 65535);
    std::memcpy(reinterpret_cast<void*>(&(grebuffer[_proto_header_len])),
                reinterpret_cast<const void*>(pkt_data), length);
    ssize_t nSend = sendto(socketfd, &(grebuffer[0]), length + _proto_header_len, 0,
                           (struct sockaddr*) &remote_addr, sizeof(struct sockaddr));
    while (nSend == -1 && errno == ENOBUFS) {
        usleep(1000);
        nSend = static_cast<int>(sendto(socketfd, &(grebuffer[0]), length + _proto_header_len, 0,
                                        (struct sockaddr*) &remote_addr,
                                        sizeof(struct sockaddr)));
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

