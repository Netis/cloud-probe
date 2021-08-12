#include "socketvxlan.h"

#include <iostream>
#include <cstring>
#ifdef WIN32
	#include <WinSock2.h>
	#include <BaseTsd.h>
	#include <windows.h>
	typedef SSIZE_T ssize_t;
	#define usleep Sleep
#else
#include <arpa/inet.h>
#include <unistd.h>
#endif
#include <pcap/pcap.h>
#include "statislog.h"

#define VXLAN_PORT 4789

typedef struct {
    uint32_t vx_flags;
    uint32_t vx_vni;
}vxlan_hdr_t;

const int INVALIDE_SOCKET_FD = -1;

PcapExportVxlan::PcapExportVxlan(const std::vector<std::string>& remoteips, uint32_t vni, const std::string& bind_device,
                             const int pmtudisc) :
        _remoteips(remoteips),
        _vni(vni),
        _bind_device(bind_device),
        _pmtudisc(pmtudisc),
        _socketfds(remoteips.size()),
        _remote_addrs(remoteips.size()),
        _vxlanbuffers(remoteips.size()) {
    _type = exporttype::vxlan;
    for (size_t i = 0; i < remoteips.size(); ++i) {
        _socketfds[i] = INVALIDE_SOCKET_FD;
        _vxlanbuffers[i].resize(65535 + sizeof(vxlan_hdr_t), '\0');
    }
}

PcapExportVxlan::~PcapExportVxlan() {
    closeExport();
}

int PcapExportVxlan::initSockets(size_t index) {
    auto& socketfd = _socketfds[index];

    if (socketfd == INVALIDE_SOCKET_FD) {

        _remote_addrs[index].sin_family = AF_INET;
        _remote_addrs[index].sin_port = htons(VXLAN_PORT);
        _remote_addrs[index].sin_addr.s_addr = inet_addr(_remoteips[index].c_str());

        if ((socketfd = socket(AF_INET, SOCK_DGRAM, 0)) == INVALIDE_SOCKET_FD) {
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

int PcapExportVxlan::initExport() {
    for (size_t i = 0; i < _remoteips.size(); ++i) {
        int ret = initSockets(i);
        if (ret != 0) {
            std::cerr << "Failed with index: " << i << std::endl;
            return ret;
        }
    }
    return 0;
}

int PcapExportVxlan::closeExport() {
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

int PcapExportVxlan::exportPacket(const struct pcap_pkthdr* header, const uint8_t* pkt_data, int direct) {
    int ret = 0;
    if(direct == PKTD_UNKNOWN) {
        return -1;
    }

    for (size_t i = 0; i < _remoteips.size(); ++i) {
        ret |= exportPacket(i, header, pkt_data, direct);
    }
    return ret;
}

int PcapExportVxlan::exportPacket(size_t index, const struct pcap_pkthdr* header, const uint8_t* pkt_data, int direct) {
    auto& vxlanbuffer = _vxlanbuffers[index];
    int socketfd = _socketfds[index];
    auto& remote_addr = _remote_addrs[index];

    size_t length = (size_t) (header->caplen <= 65535 ? header->caplen : 65535);

    vxlan_hdr_t* hdr;
    hdr = (vxlan_hdr_t*)&*vxlanbuffer.begin();
    hdr->vx_flags = htonl(0x08000000);
    hdr->vx_vni = htonl(_vni | (direct << 28));

    std::memcpy(reinterpret_cast<void*>(&(vxlanbuffer[sizeof(vxlan_hdr_t)])),
                reinterpret_cast<const void*>(pkt_data), length);
    ssize_t nSend = sendto(socketfd, &(vxlanbuffer[0]), length + sizeof(vxlan_hdr_t), 0, (struct sockaddr*) &remote_addr,
                           sizeof(struct sockaddr));
    while (nSend == -1 && errno == ENOBUFS) {
        usleep(1000);
        nSend = static_cast<int>(sendto(socketfd, &(vxlanbuffer[0]), length + sizeof(vxlan_hdr_t), 0,
                                        (struct sockaddr*) &remote_addr,
                                        sizeof(struct sockaddr)));
    }
    if (nSend == -1) {
        std::cerr << StatisLogContext::getTimeString() << "Send to socket failed, error code is " << errno
                  << ", error is " << strerror(errno) << "."
                  << std::endl;
        return -1;
    }
    if (nSend < (ssize_t) (length + sizeof(vxlan_hdr_t))) {
        std::cerr << StatisLogContext::getTimeString() << "Send socket " << length + sizeof(vxlan_hdr_t)
                  << " bytes, but only " << nSend <<
                  " bytes are sent success." << std::endl;
        return 1;
    }
    return 0;
}

