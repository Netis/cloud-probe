#ifndef PKTMINERG_SOCKETVXLAN_H
#define PKTMINERG_SOCKETVXLAN_H

#include <string>
#include <vector>
#include "pcapexport.h"
#include "gredef.h"



class PcapExportVxlan : public PcapExportBase {
protected:
    std::vector<std::string> _remoteips;
    uint32_t _vni;
    uint8_t _vni_version;
    int _vxlan_port;
    std::string _bind_device;
    int _pmtudisc;
    std::vector<socket_t> _socketfds;
    std::vector<struct sockaddr_in> _remote_addrs;
    std::vector<std::vector<char>> _vxlanbuffers;
    LogFileContext _ctx;
    std::string output_buffer;

private:
    int initSockets(size_t index, uint32_t vni);
    int exportPacket(size_t index, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct);

public:
    PcapExportVxlan(const std::vector<std::string>& remoteips, uint32_t vni, const std::string& bind_device,
                    const int pmtudisc, const int vxlan_port, double mbps,uint8_t vni_version, LogFileContext& ctx);
    ~PcapExportVxlan();
    int initExport();
    int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct);
    int closeExport();
};

#endif //PKTMINERG_SOCKETVXLAN_H
