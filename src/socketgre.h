#ifndef SRC_SOCKETGRE_H_
#define SRC_SOCKETGRE_H_

#include <string>
#include <vector>
#include "pcapexport.h"
#include "gredef.h"


class PcapExportGre : public PcapExportBase {
protected:
    std::vector<std::string> _remoteips;
    uint32_t _keybit;
    std::string _bind_device;
    int _pmtudisc;
    std::vector<socket_t> _socketfds;
    std::vector<struct sockaddr_in> _remote_addrs;
	std::vector<std::vector<char>> _grebuffers;
    LogFileContext _ctx;
    std::string output_buffer;

private:
	int initSockets(size_t index, uint32_t keybit);
    int exportPacket(size_t index, const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct);

public:
    PcapExportGre(const std::vector<std::string>& remoteips, uint32_t keybit, const std::string& bind_device,
            const int pmtudisc, double mbps, LogFileContext& ctx);
    ~PcapExportGre();
    int initExport();
    int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct);
    int closeExport();
};

#endif // SRC_SOCKETGRE_H_
