#ifndef SRC_PCAPHANDLER_H_
#define SRC_PCAPHANDLER_H_

#include <string>
#include <vector>
#include <memory>
#include <chrono>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <fstream>

#include <boost/algorithm/string.hpp>
#include <boost/format.hpp>
#include "pcapexport.h"
#include "statislog.h"
#include "logfilecontext.h"



typedef struct PcapInit {
    int snaplen;
    int timeout;
    int promisc;
    int buffer_size;
    int need_update_status;
} pcap_init_t;

class HandleParam {
    public:
        HandleParam(std::string dump,int interval, int slice,std::string dev, std::string processId, pcap_init_t param,  
                std::string filter, std::string dirStr, std::string machineName, LogFileContext& ctx);
        HandleParam(HandleParam &param);
        std::string & getDump() {return _dump;};
        int getInterval() {return _interval;};
        uint32_t getSlice() {return _slice;};
        std::string & getDev(){return _dev;};
        std::string & getProcessId(){return _processId;};
        std::string & getDirStr(){return _dirStr;};
        std::string & getFilter(){return _filter;};
        pcap_init_t getPcapParam(){return _pcapParam;};
        std::string getMachineName(){return _machineName;};
        LogFileContext& getLogFileContext(){return _ctx;};
    private:
        std::string _dump;
        int _interval;
        int _slice;
        std::string _dev;
        std::string _processId;
        std::string _dirStr;
        std::string _filter;
        pcap_init_t _pcapParam;
        std::string _machineName;
        LogFileContext _ctx;
};

bool replaceWithIfIp(std::string& expression, std::vector<std::string> &ips, LogFileContext& ctx);
uint32_t makeMplsHdr(int direct, int serviceTag);

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
    HandleParam _param;
    char _errbuf[PCAP_ERRBUF_SIZE];
    std::shared_ptr<PcapExportBase> _export;
    std::shared_ptr<GreSendStatisLog> _statislog;
    static uint64_t _fwd_count;
    static uint64_t _cap_count;
    static uint64_t _fwd_byte;
    static uint64_t _cap_byte;
    int _need_update_status;
    
    std::string _dumpDir;
    std::time_t _timeStamp;
    IpPortAddr _addr;
    u_int8_t  _macAddr[ETH_ALEN] ={0};
    bool _autoDirection = false;
    long long _handlerCheckTime = -1;
    std::string output_buffer;
    LogFileContext _ctx;
#ifdef _WIN32
    std::unordered_map<std::string, std::string> _interfaces;
    std::time_t _intfaceTimeStamp = 0;
#endif  
protected:
    uint32_t getPacketLen (uint32_t length);
    int checkPktDirection(const in_addr *sip, const in_addr *dip, const uint16_t sport, const uint16_t dport);
    int setMacAddr(std::string dev,std::string machineName);
    void closePcap();
    void closeExport();
    void closePcapDumper();

public:
    PcapHandler(HandleParam &param);
    int openPcap();
    virtual ~PcapHandler();
    void packetHandler(const struct pcap_pkthdr *header, const uint8_t *pkt_data);
    void addExport(std::shared_ptr<PcapExportBase> pcapExport);
    void clearHandler();
    
    int initExport();
    int handlePacket();
    
    void setDirIPPorts(std::string str) {_addr.init(str);};
    int openPcapDumper(pcap_t *pcap_handle);  
    void setHandlerCheckTime (long long t) {_handlerCheckTime = t;};
    long long getHandlerCheckTime () {return _handlerCheckTime;};

    LogFileContext& getLogFileContext() {return _ctx;};
};

#endif // SRC_PCAPHANDLER_H_
