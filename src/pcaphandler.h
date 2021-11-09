#ifndef SRC_PCAPHANDLER_H_
#define SRC_PCAPHANDLER_H_

#include <string>
#include <vector>
#include <memory>

#include <chrono>

#include <netinet/in.h>


#include "pcapexport.h"
#include "statislog.h"

typedef struct PcapInit {
    int snaplen;
    int timeout;
    int promisc;
    int buffer_size;
    int need_update_status;
} pcap_init_t;

bool replaceWithIfIp(std::string& expression, std::vector<std::string> &ips);

class IpPortAddr {
public:
    void init(const std::string express);
    bool matchIpPort (const in_addr *ip, const uint16_t port);
    bool isInited() {return _inited;};

private:
    std::vector<in_addr> _ips;
    std::vector<uint32_t> _ports;
    bool _inited = false;
};

class PcapHandler {
protected:
    pcap_t*_pcap_handle;
    pcap_dumper_t* _pcap_dumpter;
    char _errbuf[PCAP_ERRBUF_SIZE];
    std::vector<std::shared_ptr<PcapExportBase>> _exports;
    std::shared_ptr<GreSendStatisLog> _statislog;
    uint64_t _gre_count;
    uint64_t _gre_drop_count;

    std::string _dumpDir;
    std::int16_t _dumpInterval;
    std::time_t _timeStamp;

    int _need_update_status;

    std::vector<in_addr> _ipv4s;
    std::vector<in6_addr> _ipv6s;

    IpPortAddr _addr;

protected:
    int openPcapDumper(pcap_t *pcap_handle);
    void closePcapDumper();

    int checkPktDirectionV4(const in_addr* sip, const in_addr* dip);
    int checkPktDirectionV6(const in6_addr* sip, const in6_addr* dip);
public:
    PcapHandler(std::string dumpDir, int16_t dumpInterval);
    virtual ~PcapHandler();
    void packetHandler(const struct pcap_pkthdr *header, const uint8_t *pkt_data);
    void addExport(std::shared_ptr<PcapExportBase> pcapExport);
    int startPcapLoop(int count);
    void stopPcapLoop();
    virtual int openPcap(const std::string &dev, const pcap_init_t &param, const std::string &expression,
                         bool dumpfile=false) = 0;
    void closePcap();
};

class PcapOfflineHandler : public PcapHandler {
public:
    PcapOfflineHandler(std::string dumpDir, int16_t dumpInterval):
            PcapHandler(dumpDir, dumpInterval) {};
    int openPcap(const std::string &dev, const pcap_init_t &param, const std::string &expression,
                 bool dumpfile=false);
};

class PcapLiveHandler : public PcapHandler {
public:
    PcapLiveHandler(std::string dumpDir, int16_t dumpInterval):
            PcapHandler(dumpDir, dumpInterval) {};
    int openPcap(const std::string &dev, const pcap_init_t &param, const std::string &expression,
                 bool dumpfile=false);
};

#endif // SRC_PCAPHANDLER_H_
