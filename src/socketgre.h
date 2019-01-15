#ifndef SRC_SOCKETGRE_H_
#define SRC_SOCKETGRE_H_

#ifndef WIN32
	#include <netinet/in.h>
#endif
#include <string>
#include "pcapexport.h"
#include "gredef.h"

class PcapExportGre : public PcapExportBase {
protected:
    std::string _remoteip;
    uint32_t _keybit;
    int _socketfd;
    struct sockaddr_in _remote_addr;
    char _grebuffer[65535 + sizeof(grehdr_t)];
public:
    PcapExportGre(const std::string &remoteip, uint32_t keybit);
    ~PcapExportGre();
    int initExport();
    int exportPacket(const struct pcap_pkthdr *header, const uint8_t *pkt_data);
    int closeExport();
};

#endif // SRC_SOCKETGRE_H_
