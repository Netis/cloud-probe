
#ifndef PKTMINERG_PCAPEXPORTEXTENSION_H
#define PKTMINERG_PCAPEXPORTEXTENSION_H


#include <string>
#include <vector>

#include "pcapexport.h"
#include "packet_agent_extension.h"


class PcapExportExtension : public PcapExportBase {
protected:
    // sockets
    std::vector<std::string> _remoteips;
    std::string _proto_config;
    std::string _bind_device;
    int _pmtudisc;

    PacketAgentProtoExtension _proto_extension;
    std::string _remoteips_config;
    std::string _socket_config;

private:
    int loadLibrary();
    int initConfigString();

public:
    PcapExportExtension(const std::vector<std::string>& remoteips, const std::string& proto_config,
                     const std::string& bind_device, const int pmtudisc);
    ~PcapExportExtension();
    int initExport();
    int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data);
    int closeExport();
};



#endif //PKTMINERG_PCAPEXPORTPLUGIN_H
