#ifndef SRC_SOCKETGRE_H_
#define SRC_SOCKETGRE_H_

#ifndef WIN32
	#include <netinet/in.h>
#endif
#include <string>
#include <vector>
#include "pcapexport.h"
#include "gredef.h"



class AddressV4V6 {
public:
    AddressV4V6();

	int buildAddr(const char* addr);

	struct sockaddr_in* getAddressV4() { return &svrAddr4_; }

	struct sockaddr_in6* getAddressV6() { return &svrAddr6_; }

    int getDomainAF_NET();

	struct sockaddr* getSockAddr();

	size_t getSockLen();

    bool isIpV6() { return sinFamily_ == AF_INET6; }
private:
    union {
		struct sockaddr_in svrAddr4_;
		struct sockaddr_in6 svrAddr6_;
	};
    uint16_t sinFamily_;
};


class PcapExportGre : public PcapExportBase {
protected:
    std::vector<std::string> _remoteips;
    uint32_t _keybit;
    std::string _bind_device;
    int _pmtudisc;
    std::vector<int> _socketfds;
    std::vector<AddressV4V6> _remote_addrs;
	std::vector<std::vector<char>> _grebuffers;

private:
	int initSockets(size_t index, uint32_t keybit);
    int exportPacket(size_t index, const struct pcap_pkthdr *header, const uint8_t *pkt_data);

public:
    PcapExportGre(const std::vector<std::string>& remoteips, uint32_t keybit, const std::string& bind_device,
            const int pmtudisc);
    ~PcapExportGre();
    int initExport();
    int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data);
    int closeExport();
};

#endif // SRC_SOCKETGRE_H_
