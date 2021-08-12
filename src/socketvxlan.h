#ifndef SRC_SOCKETVXLAN_H_
#define SRC_SOCKETVXLAN_H_

#ifndef WIN32
	#include <netinet/in.h>
#endif
#include <string>
#include <vector>
#include "pcapexport.h"


class PcapExportVxlan : public PcapExportBase {
protected:
    std::vector<std::string> _remoteips;
    uint32_t _vni;
    std::string _bind_device;
    int _pmtudisc;
    std::vector<int> _socketfds;
    std::vector<struct sockaddr_in> _remote_addrs;
	std::vector<std::vector<char>> _vxlanbuffers;

private:
	int initSockets(size_t index);
    int exportPacket(size_t index, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct);

public:
    PcapExportVxlan(const std::vector<std::string>& remoteips, uint32_t vni, const std::string& bind_device,
            const int pmtudisc);
    ~PcapExportVxlan();
    int initExport();
    int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct);
    int closeExport();
};

#endif // SRC_SOCKETVXLAN_H_
