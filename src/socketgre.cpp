#include "socketgre.h"

#include <iostream>
#include <cstring>

#include <arpa/inet.h>
#include <unistd.h>
#include <pcap/pcap.h>
#include "statislog.h"

const int INVALIDE_SOCKET_FD = -1;

PcapExportGre::PcapExportGre(const std::string& remoteip, uint32_t keybit) :
        _remoteip(remoteip),
        _keybit(keybit),
        _socketfd(INVALIDE_SOCKET_FD) {
    _type = exporttype::gre;
    std::memset(_grebuffer, 0, sizeof(_grebuffer));
}

PcapExportGre::~PcapExportGre() {
    closeExport();
}

int PcapExportGre::initExport() {
    grehdr_t grehdr;
    if (_socketfd == INVALIDE_SOCKET_FD) {
        grehdr.flags = htons(0x2000);
        grehdr.protocol = htons(0x6558);
        grehdr.keybit = htonl(_keybit);
        std::memcpy(reinterpret_cast<void*>(_grebuffer), &grehdr, sizeof(grehdr_t));

        _remote_addr.sin_family = AF_INET;
        _remote_addr.sin_addr.s_addr = inet_addr(_remoteip.c_str());

        if ((_socketfd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE)) == INVALIDE_SOCKET_FD) {
            std::cerr << StatisLogContext::getTimeString() << "Create socket failed, error code is " << errno
                      << ", error is" << strerror(errno) << "."
                      << std::endl;
            return -1;
        }
    }
    return 0;
}

int PcapExportGre::closeExport() {
    if (_socketfd != INVALIDE_SOCKET_FD) {
        close(_socketfd);
        _socketfd = INVALIDE_SOCKET_FD;
    }
    return 0;
}

int PcapExportGre::exportPacket(const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    size_t length = (size_t) (header->caplen <= 65535 ? header->caplen : 65535);
    std::memcpy(reinterpret_cast<void*>(_grebuffer + sizeof(grehdr_t)),
                reinterpret_cast<const void*>(pkt_data), length);
    ssize_t nSend = sendto(_socketfd, _grebuffer, length + sizeof(grehdr_t), 0, (struct sockaddr*) &_remote_addr,
                           sizeof(struct sockaddr));
    while (nSend == -1 && errno == ENOBUFS) {
        usleep(1000);
        nSend = static_cast<int>(sendto(_socketfd, _grebuffer, length + sizeof(grehdr_t), 0,
                                        (struct sockaddr*) &_remote_addr,
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

