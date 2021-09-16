#ifndef SRC_PCAPEXPORT_H_
#define SRC_PCAPEXPORT_H_

#include <pcap/pcap.h>

#define PKTD_UNKNOWN -1
#define PKTD_IC 1
#define PKTD_OG 2
#define PKTD_NONCHECK 0

enum class exporttype : uint8_t {
    gre = 0,
    file = 1,
    zmq = 2,
    vxlan = 3
};

class PcapExportBase {
protected:
    exporttype _type;
public:
    exporttype getExportType() const {
        return _type;
    }
    virtual int initExport() = 0;
    virtual int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data, int direct) = 0;
    virtual int closeExport() = 0;
};

#endif // SRC_PCAPEXPORT_H_
