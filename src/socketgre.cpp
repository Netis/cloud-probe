#include "socketgre.h"
#include <iostream>
#include <cstring>
#include "dep.h"
#include "statislog.h"

const int INVALIDE_SOCKET_FD = -1;

PcapExportGre::PcapExportGre(const std::vector<std::string>& remoteips, uint32_t keybit, const std::string& bind_device,
                             const int pmtudisc, double mbps, LogFileContext& ctx) :
        _remoteips(remoteips),
        _keybit(keybit),
        _bind_device(bind_device),
        _pmtudisc(pmtudisc),
        _socketfds(remoteips.size()),
        _remote_addrs(remoteips.size()),
        _grebuffers(remoteips.size()),
        _ctx(ctx) {
    setExportTypeAndMbps(exporttype::gre, mbps);
    for (size_t i = 0; i < remoteips.size(); ++i) {
        _socketfds[i] = INVALIDE_SOCKET_FD;
        _grebuffers[i].resize(65535 + sizeof(grehdr_t), '\0');
    }
}

PcapExportGre::~PcapExportGre() {
    closeExport();
}

int PcapExportGre::initSockets(size_t index, uint32_t keybit) {
    auto& socketfd = _socketfds[index];
    auto& grebuffer = _grebuffers[index];

    grehdr_t grehdr;
    if (socketfd == INVALIDE_SOCKET_FD) {
        grehdr.flags = htons(0x2000);
        grehdr.protocol = htons(0x6558);
        grehdr.keybit = htonl(keybit);
        std::memcpy(reinterpret_cast<void*>(&(grebuffer[0])), &grehdr, sizeof(grehdr_t));

        _remote_addrs[index].sin_family = AF_INET;
        inet_pton(AF_INET, _remoteips[index].c_str(), &_remote_addrs[index].sin_addr.s_addr);
        if ((socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE)) == INVALIDE_SOCKET_FD) {
            output_buffer = std::string("Create socket failed, error code is ") + std::to_string(errno)
                        + ", error is " + strerror(errno) + ".";
            _ctx.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
            return -1;
        }

        if (_bind_device.length() > 0) {
#ifdef WIN32
            //TODO: bind device on WIN32
#else
            if (setsockopt(socketfd, SOL_SOCKET, SO_BINDTODEVICE, _bind_device.c_str(), _bind_device.length()) < 0) {
                output_buffer = std::string("SO_BINDTODEVICE failed, error code is ") + std::to_string(errno)
                            + ", error is " + strerror(errno) + ".";
                _ctx.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
                return -1;
            }
#endif // WIN32
        }

#ifdef WIN32
        //TODO: bind device on WIN32
#else
        if (_pmtudisc >= 0) {
            if (setsockopt(socketfd, SOL_IP, IP_MTU_DISCOVER, &_pmtudisc, sizeof(_pmtudisc)) == -1) {
                output_buffer = std::string("IP_MTU_DISCOVER failed, error code is ") + std::to_string(errno)
                            + ", error is " + strerror(errno) + ".";
                _ctx.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
                return -1;
            }
        }
#endif // WIN32
    }
    return 0;
}

int PcapExportGre::initExport() {
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        int ret = initSockets(i, _keybit);
        if (ret != 0) {
            output_buffer = std::string("Failed with index: ") + std::to_string(i);
            _ctx.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << output_buffer << std::endl;
            return ret;
        }
    }
    return 0;
}

int PcapExportGre::closeExport() {
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        if (_socketfds[i] != INVALIDE_SOCKET_FD) {
            socket_close(_socketfds[i]);
            _socketfds[i] = INVALIDE_SOCKET_FD;
        }
    }
    return 0;
}

int PcapExportGre::exportPacket(const struct pcap_pkthdr* header, const uint8_t* pkt_data, int direct) {
    int ret = 0;
    uint64_t us;

    if(direct == PKTD_UNKNOWN)
        return -1;

    us = tv2us(&header->ts);
    if(_check_mbps_cb(us, header->caplen) < 0)
        return -1;

    for (size_t i = 0; i < _remoteips.size(); ++i) {
        ret |= exportPacket(i, header, pkt_data, direct);
    }
    return ret;
}

int PcapExportGre::exportPacket(size_t index, const struct pcap_pkthdr* header, const uint8_t* pkt_data, int direct) {
    auto& grebuffer = _grebuffers[index];
    socket_t socketfd = _socketfds[index];
    auto& remote_addr = _remote_addrs[index];

    size_t length = (size_t) (header->caplen <= 65535 ? header->caplen : 65535);
    grehdr_t* hdr;

    hdr = (grehdr_t*)&*grebuffer.begin();
    
    hdr->keybit = htonl(_keybit | (direct<<28));
    ;
    std::memcpy(reinterpret_cast<void*>(&(grebuffer[sizeof(grehdr_t)])),
                reinterpret_cast<const void*>(pkt_data), length);
    

    ssize_t nSend = sendto(socketfd, &(grebuffer[0]), int(length + sizeof(grehdr_t)), 0, (struct sockaddr*) &remote_addr,
                           sizeof(struct sockaddr));
    while (nSend == -1 && errno == ENOBUFS) {
        usleep(1000);
        nSend = static_cast<int>(sendto(socketfd, &(grebuffer[0]), int(length + sizeof(grehdr_t)), 0,
                                        (struct sockaddr*) &remote_addr,
                                        sizeof(struct sockaddr)));
    }
    if (nSend == -1) {
        output_buffer = std::string("Send to socket failed, error code is ") + std::to_string(errno) 
                    + ", error is " + strerror(errno) + ".";
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
        return -1;
    }
    if (nSend < (ssize_t) (length + sizeof(grehdr_t))) {
        output_buffer = std::string("Send socket ") + std::to_string(length + sizeof(grehdr_t))
                    + " bytes, but only " + std::to_string(nSend) + " bytes are sent success.";
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
        return 1;
    }
    return 0;
}

