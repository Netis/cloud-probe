//
// Created by root on 11/15/19.
//

#ifndef PKTMINERG_PCAPEXPORTPLUGIN_H
#define PKTMINERG_PCAPEXPORTPLUGIN_H

#ifndef WIN32
    #include <netinet/in.h>
#endif
#include <string>
#include <vector>

#include "pcapexport.h"
#include "gredef.h"
#include "utils.h"
#include "packet_agent_ext.h"





class PcapExportPlugin : public PcapExportBase {
protected:
    // sockets
    std::vector<std::string> _remoteips;
    std::vector<int> _socketfds;
    std::vector<struct AddressV4V6> _remote_addrs;
    std::vector<std::vector<char>> _buffers;

    // common params
    std::string _proto_config;
    std::vector<PacketAgentProtoExtension> _proto_extension;

    // std::vector<uint8_t> _proto_header_buffer;
    uint32_t _proto_header_len;

    std::string _bind_device;
    int _pmtudisc;


private:
    int initSockets(size_t index);
    int exportPacket(size_t index, const struct pcap_pkthdr *header, const uint8_t *pkt_data);
    int loadLibrary();

public:
    PcapExportPlugin(const std::vector<std::string>& remoteips, const std::string& proto_config,
                     const std::string& bind_device, const int pmtudisc);
    ~PcapExportPlugin();
    int initExport();
    int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data);
    int closeExport();
};



#endif //PKTMINERG_PCAPEXPORTPLUGIN_H
