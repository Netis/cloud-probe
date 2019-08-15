#include "socketgre.h"

#include <iostream>
#include <cstring>
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
#endif
#include <pcap/pcap.h>
#include "statislog.h"

const int INVALIDE_SOCKET_FD = -1;

PcapExportGre::PcapExportGre(const std::vector<std::string>& remoteips, uint32_t keybit, const std::string& bind_device) :
        _remoteips(remoteips),
        _keybit(keybit),
        _bind_device(bind_device),
        _socketfds(remoteips.size()),
        _remote_addrs(remoteips.size()),
        _grebuffers(remoteips.size()) {
    _type = exporttype::gre;
    for (size_t i = 0; i < remoteips.size(); ++i) {
        _socketfds[i] = INVALIDE_SOCKET_FD;
        _grebuffers[i].resize(65535 + sizeof(grehdr_t), '\0');
    }
}

PcapExportGre::~PcapExportGre() {
    closeExport();
}

int PcapExportGre::initSockets(size_t index, uint32_t keybit, const std::string& bind_device) {
    auto& socketfd = _socketfds[index];
    auto& grebuffer = _grebuffers[index];

    grehdr_t grehdr;
    if (socketfd == INVALIDE_SOCKET_FD) {
        grehdr.flags = htons(0x2000);
        grehdr.protocol = htons(0x6558);
        grehdr.keybit = htonl(keybit);
        std::memcpy(reinterpret_cast<void*>(&(grebuffer[0])), &grehdr, sizeof(grehdr_t));

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
    }
    return 0;
}

int PcapExportGre::initExport() {
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        int ret = initSockets(i, _keybit, _bind_device);
        if (ret != 0) {
            std::cerr << "Failed with index: " << i << std::endl;
            return ret;
        }
    }
    return 0;
}

int PcapExportGre::closeExport() {
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        if (_socketfds[i] != INVALIDE_SOCKET_FD) {
#ifdef WIN32
            shutdown(_socketfd, SD_BOTH);
#else
            close(_socketfds[i]);
#endif // WIN32
            _socketfds[i] = INVALIDE_SOCKET_FD;
        }
    }
    return 0;
}

int PcapExportGre::exportPacket(const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    int ret = 0;
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        ret |= exportPacket(i, header, pkt_data);
    }
    return ret;
}

int PcapExportGre::exportPacket(size_t index, const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    auto& grebuffer = _grebuffers[index];
    int socketfd = _socketfds[index];
    auto& remote_addr = _remote_addrs[index];

    size_t length = (size_t) (header->caplen <= 65535 ? header->caplen : 65535);
    std::memcpy(reinterpret_cast<void*>(&(grebuffer[sizeof(grehdr_t)])),
                reinterpret_cast<const void*>(pkt_data), length);
    ssize_t nSend = sendto(socketfd, &(grebuffer[0]), length + sizeof(grehdr_t), 0, (struct sockaddr*) &remote_addr,
                           sizeof(struct sockaddr));
    while (nSend == -1 && errno == ENOBUFS) {
        usleep(1000);
        nSend = static_cast<int>(sendto(socketfd, &(grebuffer[0]), length + sizeof(grehdr_t), 0,
                                        (struct sockaddr*) &remote_addr,
                                        sizeof(struct sockaddr)));
    }
    if (nSend == -1) {
        std::cerr << StatisLogContext::getTimeString() << "Send to socket failed, error code is " << errno
                  << ", error is " << strerror(errno) << "."
                  << std::endl;
        return -1;
    }
    if (nSend < (ssize_t) (length + sizeof(grehdr_t))) {
        std::cerr << StatisLogContext::getTimeString() << "Send socket " << length + sizeof(grehdr_t)
                  << " bytes, but only " << nSend <<
                  " bytes are sent success." << std::endl;
        return 1;
    }
    return 0;
}

