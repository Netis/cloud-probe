
#ifndef PKTMINERG_PCAPEXPORTEXTENSION_H
#define PKTMINERG_PCAPEXPORTEXTENSION_H


#include <string>
#include <vector>

#include "pcapexport.h"
#include "packet_agent_extension.h"

class PcapExportExtension : public PcapExportBase {
public:
    typedef enum _ext_type {
        EXT_TYPE_PORT_MIRROR = 0,
        EXT_TYPE_TRAFFIC_MONITOR
    } ext_type_t;

private:
    ext_type_t _ext_type;
    std::string _ext_config;
    packet_agent_extension_itf_t _extension_itf;
    void* _handle;

private:
    int loadLibrary();

public:
    PcapExportExtension(const ext_type_t ext_type, const std::string& ext_config);
    ~PcapExportExtension();
    
    int initExport();
    int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data);
    int closeExport();
};



#endif //PKTMINERG_PCAPEXPORTPLUGIN_H
