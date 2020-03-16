#ifndef SRC_PCAPEXPORT_H_
#define SRC_PCAPEXPORT_H_

#include <pcap/pcap.h>

enum class exporttype : uint8_t {
    gre = 0,
    file = 1,
    zmq = 2
};

class PcapExportBase {
protected:
    exporttype _type;
public:
    exporttype getExportType() const {
        return _type;
    }
    virtual int initExport() = 0;
    virtual int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data) = 0;
    virtual int closeExport() = 0;
};

#endif // SRC_PCAPEXPORT_H_
