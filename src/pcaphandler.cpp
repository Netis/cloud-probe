#include <iostream>
#include <algorithm>
#include <boost/filesystem.hpp>
#include <boost/algorithm/string.hpp>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include "pcaphandler.h"
#include "scopeguard.h"
#include "agent_status.h"
#include "vlan.h"

bool replaceWithIfIp(std::string& expression, std::vector<std::string> &ips) {
    std::string name = expression.substr(strlen("nic."));
    expression = "";
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_addr *addr;
    char err_buf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, err_buf) < 0)
        return false;
    for (d = alldevs; d; d = d->next) {
        if (strcmp(d->name, (char*)name.data()) == 0) {
            for (addr = d->addresses; addr; addr = addr->next) {
                if (!addr->addr) {
                    continue;
                }

                if (addr->addr->sa_family == AF_INET) {
                    char str[INET_ADDRSTRLEN];
                    inet_ntop(AF_INET, &(((sockaddr_in *) addr->addr)->sin_addr), str, sizeof(str));
                    expression +=std::string(str);
                    ips.push_back(std::string(str));
                }
                else if (addr->addr->sa_family == AF_INET6) {
                    char str[INET6_ADDRSTRLEN];
                    inet_ntop(AF_INET6, &(((sockaddr_in6 *) addr->addr)->sin6_addr), str, sizeof(str));
                    expression += std::string(str);
                }
                else {
                    continue;
                }
                if (addr->next != nullptr) {
                    expression += " or host ";
                }
            }
            pcap_freealldevs(alldevs);
            return true;
        }
    }

    pcap_freealldevs(alldevs);
    return false;
}

PcapHandler::PcapHandler(std::string dumpDir, int16_t dumpInterval):
    _dumpDir(dumpDir),
    _dumpInterval(dumpInterval) {
    _gre_count = 0;
    _gre_drop_count = 0;
    _pcap_handle = NULL;
    _pcap_dumpter = NULL;

    if (dumpInterval != -1) {
        _dumpDir = dumpDir + "/";
        _timeStamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        if(!boost::filesystem::is_directory(_dumpDir))
            boost::filesystem::create_directories(_dumpDir);
    }

    std::memset(_errbuf, 0, sizeof(_errbuf));
}

PcapHandler::~PcapHandler() {
    closePcapDumper();
    closePcap();
}

int PcapHandler::openPcapDumper(pcap_t* pcap_handle) {
    closePcapDumper();
    char date[60] = {0};
    std::string filepath;
    if (_dumpInterval >0) {
        struct tm* ptm = localtime(&_timeStamp);
        sprintf(date, "%d%02d%02d%02d%02d%02d",
                (int)ptm->tm_year + 1900,(int)ptm->tm_mon + 1,(int)ptm->tm_mday,
                (int)ptm->tm_hour, (int)ptm->tm_min, (int)ptm->tm_sec);
        filepath = _dumpDir + "pktminerg_dump_"+std::string(date) + ".pcap";
    }
    else {
        filepath = _dumpDir + "pktminerg_dump.pcap";
    }
    if (boost::filesystem::exists(filepath)) {
        boost::filesystem::remove(filepath);
    }
    _pcap_dumpter = pcap_dump_open(pcap_handle, filepath.c_str());
    if (_pcap_dumpter == NULL) {
        std::cerr << StatisLogContext::getTimeString() << "Call pcap_dump_open failed, error is "
                  << pcap_geterr(pcap_handle) << "." << std::endl;
        return -1;
    }
    return 0;
}

void PcapHandler::closePcapDumper() {
    if (_pcap_dumpter != NULL) {
        pcap_dump_close(_pcap_dumpter);
        _pcap_dumpter = NULL;
    }
}

void PcapHandler::closePcap() {
    if (_pcap_handle != NULL) {
        pcap_close(_pcap_handle);
        _pcap_handle = NULL;
    }
}

bool PcapHandler::handlePacket() {
    if (_pcap_handle == NULL) {
        std::cerr << StatisLogContext::getTimeString() << "The pcap has not created." << std::endl;
        return false;
    }
    struct pcap_pkthdr * hdr;
    const u_char * data;

    int ret = pcap_next_ex(_pcap_handle, &hdr, &data);
    if (1 == ret) {
        packetHandler(hdr, data);

    } else if (-1 == ret){
        return false;
    }
    return true;
}

void PcapHandler::closeExports() {
    for (auto & ex: _exports) {
        ex->closeExport();
    }

    return;
}
uint32_t PcapHandler::getPacketLen (uint32_t length) {
    if (_sliceLen == 0) {
        return length;
    }
    else{
        return (_sliceLen < length)? _sliceLen : length;
    }
};
void PcapHandler::packetHandler(const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    ether_header* eth;
    iphdr* ip;
    ip6_hdr* ipv6;
    vlan_tag *vlan_hdr;
    udphdr *udp_hdr;
    tcphdr *tcp_hdr;
    uint16_t eth_type;
    uint16_t sport = 0;
    uint16_t dport = 0;
    _sliceLen = 0;
    int direct;
    int cap_len = header->len;

    if(header->caplen < sizeof(ether_header))
        return;
    eth = (ether_header*)pkt_data;
    eth_type = ntohs(eth->ether_type);
    direct = PKTD_UNKNOWN;

    switch(eth_type) {
        case ETHERTYPE_IP:
            ip = (iphdr*)(pkt_data + sizeof(ether_header));
            if (ip->protocol == 17) {
                udp_hdr = (udphdr*) (pkt_data + sizeof(ether_header)+sizeof(iphdr));
                sport = ntohs(udp_hdr->source);
                dport = ntohs(udp_hdr->dest);
            }
            else if (ip->protocol == 6) {
                tcp_hdr = (tcphdr*) (pkt_data + sizeof(ether_header)+sizeof(iphdr));
                sport = ntohs(tcp_hdr->source);
                dport = ntohs(tcp_hdr->dest);
            }
            direct = checkPktDirection((const in_addr*)&ip->saddr, (const in_addr*)&ip->daddr, sport, dport);

        case ETHERTYPE_VLAN: {
            vlan_hdr = (vlan_tag*) (pkt_data + sizeof(ether_header));
            uint16_t vlan_type = ntohs(vlan_hdr->vlan_tci);
            switch(vlan_type) {
                case ETHERTYPE_IP:
                    ip = (iphdr*)(pkt_data + sizeof(ether_header)+sizeof(vlan_tag));
                    if (ip->protocol == 17) {
                        udp_hdr = (udphdr*) (pkt_data + sizeof(ether_header) + sizeof(iphdr) + sizeof(vlan_tag)) ;
                        sport = ntohs(udp_hdr->source);
                        dport = ntohs(udp_hdr->dest);
                    }
                    else if (ip->protocol == 6) {
                        tcp_hdr = (tcphdr*) (pkt_data + sizeof(ether_header)+sizeof(iphdr) + sizeof(vlan_tag));
                        sport = ntohs(tcp_hdr->source);
                        dport = ntohs(tcp_hdr->dest);
                    }
                    direct = checkPktDirection((const in_addr*)&ip->saddr, (const in_addr*)&ip->daddr, sport, dport);
                    break;

                default:
                    break;
            }
        }
        default:
            break;
    }
    ((struct pcap_pkthdr*)header)->caplen = getPacketLen(header->caplen);
    std::for_each(_exports.begin(), _exports.end(),
                  [header, pkt_data, this, direct](std::shared_ptr<PcapExportBase> pcapExport) {
                      int ret = pcapExport->exportPacket(header, pkt_data, direct);
                      if (pcapExport->getExportType() == exporttype::gre) {
                          if (ret == 0) {
                              this->_gre_count++;
                          } else {
                              this->_gre_drop_count++;
                          }
                      }
                  });
    if (_pcap_dumpter) {
        auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        if( _dumpInterval > 0 && tt-_timeStamp > _dumpInterval ) {
            _timeStamp = tt;

            if (openPcapDumper(_pcap_handle) != 0) {
                std::cerr << StatisLogContext::getTimeString() << "Call openPcapDumper failed." << std::endl;
            }
        }

        pcap_dump(reinterpret_cast<u_char*>(_pcap_dumpter), header, pkt_data);
    }
    if (_statislog == nullptr) {
        _statislog = std::make_shared<GreSendStatisLog>(false);
        _statislog->initSendLog("pktminerg");
    }
    _statislog->logSendStatis((uint64_t) (header->ts.tv_sec), header->caplen, _gre_count, _gre_drop_count, 0,
                              _pcap_handle);
    if (_need_update_status) {
        AgentStatus::get_instance()->update_capture_status((uint64_t) (header->ts.tv_sec), header->caplen,
                                                           _gre_count, _gre_drop_count, _pcap_handle);
    }
}

void PcapHandler::addExport(std::shared_ptr<PcapExportBase> pcapExport) {
    _exports.push_back(pcapExport);
}

int PcapHandler::startPcapLoop(int count) {
    if (_pcap_handle == NULL) {
        std::cerr << StatisLogContext::getTimeString() << "The pcap has not created." << std::endl;
        return -1;
    }
    int ret = pcap_loop(_pcap_handle, count, [](uint8_t* user, const struct pcap_pkthdr* h, const uint8_t* data) {
        PcapHandler* p = static_cast<PcapHandler*>(static_cast<void*>(user));
        p->packetHandler(h, data);
    }, reinterpret_cast<uint8_t*>(this));
    if (_statislog == nullptr) {
        _statislog = std::make_shared<GreSendStatisLog>(false);
        _statislog->initSendLog("pktminerg");
    }
    _statislog->logSendStatisGre(std::time(NULL), (uint64_t) std::time(NULL), _gre_count, _gre_drop_count, 0,
                                 _pcap_handle);
    return ret;
}

void PcapHandler::stopPcapLoop() {
    if (_pcap_handle == NULL) {
        std::cerr << StatisLogContext::getTimeString() << "The pcap has not created." << std::endl;
        return;
    }
    pcap_breakloop(_pcap_handle);
}

int PcapHandler::checkPktDirection(const in_addr *sip, const in_addr *dip, const uint16_t sport, const uint16_t dport) {
    if (!_addr.isInited()) {
        return PKTD_NONCHECK;
    }

    if (_addr.matchIpPort(sip, sport)) {
        return PKTD_OG;
    }

    if (_addr.matchIpPort(dip, dport)) {
        return PKTD_IC;
    }

    return PKTD_UNKNOWN;
}

int PcapOfflineHandler::openPcap(const std::string& dev, const pcap_init_t& param, const std::string& expression,
                                 bool dumpfile) {
    pcap_t* pcap_handle = pcap_open_offline(dev.c_str(), _errbuf);
    if (!pcap_handle) {
        std::cerr << StatisLogContext::getTimeString() << "Call pcap_open_offline failed, error is " << _errbuf << "."
                  << std::endl;
        return -1;
    }
    auto pcapGuard = MakeGuard([pcap_handle]() {
        pcap_close(pcap_handle);
    });
    _need_update_status = param.need_update_status;

    if (dumpfile) {
        if (openPcapDumper(pcap_handle) != 0) {
            std::cerr << StatisLogContext::getTimeString() << "Call openPcapDumper failed." << std::endl;
            return -1;
        }
    }
    pcapGuard.Dismiss();
    _pcap_handle = pcap_handle;
    return 0;
}

int PcapLiveHandler::openPcap(const std::string& dev, const pcap_init_t& param, const std::string& expression,
                              bool dumpfile) {
    int ret;
    struct bpf_program filter;
    bpf_u_int32 mask = 0;
    bpf_u_int32 net = 0;
    _need_update_status = param.need_update_status;

    {
        struct ifaddrs* ifaddr;

        _ipv4s.clear();
        _ipv6s.clear();
        if (::getifaddrs(&ifaddr) < 0) {
            return -1;
        }

        for (auto ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
            if(!ifa->ifa_name || dev != ifa->ifa_name || !ifa->ifa_addr)
                continue;
            if(ifa->ifa_addr->sa_family == AF_INET)
            {
                _ipv4s.push_back(((sockaddr_in*)ifa->ifa_addr)->sin_addr);
            }
            else if(ifa->ifa_addr->sa_family == AF_INET6)
            {
                _ipv6s.push_back(((sockaddr_in6*)ifa->ifa_addr)->sin6_addr);
            }
        }
        freeifaddrs(ifaddr);
    }
    pcap_t* pcap_handle = pcap_create(dev.c_str(), _errbuf);
    if (!pcap_handle) {
        std::cerr << StatisLogContext::getTimeString() << "Call pcap_create failed, error is " << _errbuf << "."
                  << std::endl;
        return -1;
    }
    auto pcapGuard = MakeGuard([pcap_handle]() {
        pcap_close(pcap_handle);
    });

    pcap_set_snaplen(pcap_handle, param.snaplen);
    pcap_set_timeout(pcap_handle, param.timeout);
    pcap_set_promisc(pcap_handle, param.promisc);
    ret = pcap_set_buffer_size(pcap_handle, param.buffer_size);
    if (ret != 0) {
        std::cerr << StatisLogContext::getTimeString() << "Call pcap_set_buffer_size to " << param.buffer_size
                  << " failed." << std::endl;
        return -1;
    }
    ret = pcap_activate(pcap_handle);
    if (ret != 0) {
        std::cerr << StatisLogContext::getTimeString() << "Call pcap_activate failed  error is "
                  << pcap_statustostr(ret) << "." << std::endl;
        return -1;
    }

    if (expression.length() > 0) {
        std::cout << StatisLogContext::getTimeString() << "Set pcap filter as \"" << expression << "\"." << std::endl;
        if (pcap_lookupnet(dev.c_str(), &net, &mask, _errbuf) == -1) {
            std::cerr << StatisLogContext::getTimeString() << " Call pcap_lookupnet failed, error is " << _errbuf << "."
                      << std::endl;
            return -1;
        }

        ret = pcap_compile(pcap_handle, &filter, expression.c_str(), 0, net);
        if (ret != 0) {
            std::cerr << StatisLogContext::getTimeString() << "Call pcap_compile failed, error is "
                      << pcap_statustostr(ret) << "." << std::endl;
            return -1;
        }

        ret = pcap_setfilter(pcap_handle, &filter);
        if (ret != 0) {
            std::cerr << StatisLogContext::getTimeString() << "Call pcap_setfilter failed, error is "
                      << pcap_statustostr(ret) << "." << std::endl;
            return -1;
        }
    }

    if (dumpfile) {
        if (openPcapDumper(pcap_handle) != 0) {
            std::cerr << StatisLogContext::getTimeString() << "Call openPcapDumper failed." << std::endl;
            return -1;
        }
    }
    pcapGuard.Dismiss();
    _pcap_handle = pcap_handle;
    return 0;
}

void IpPortAddr::init(std::string express) {
    std::vector<std::string> strs;
    boost::split(strs, express, boost::is_any_of("_"));
    for (int i = 0; i < strs.size()-1; i++) {
        if (strs[i] == "host" || strs[i] == "(host") {
            int len = strs[i+1].length();
            if (strs[i+1][len-1] ==')') {
                strs[i+1].erase(strs[i+1].end() - 1);
            }
            if (strs[i+1].find("nic.") == 0) {
                std::vector<std::string> ips;
                replaceWithIfIp(strs[i+1], ips);
                for (auto i: ips) {
                    struct in_addr ipV4;
                    if (1 == inet_pton(AF_INET, i.c_str(), &ipV4)) {
                        _ips.push_back(ipV4);
                    }
                }
            }
            else {
                struct in_addr ipV4;

                if (1 == inet_pton(AF_INET, strs[i+1].c_str(), &ipV4)) {
                    _ips.push_back(ipV4);
                }
            }
        }
        else if (strs[i] == "port" || strs[i] == "(port") {
            _ports.push_back(stoi(strs[i+1]));
        }
    }
    _inited = true;
    return;
}
bool IpPortAddr::matchIpPort (const in_addr *ip, const uint16_t port) {
    bool ret = false;

    for (auto ipv4: _ips) {
        if (ipv4.s_addr == ip->s_addr) {
            ret = true;
            break;
        }
    }

    if (ret) {
        for (auto p : _ports) {
            if (p == port) {
                return true;
            }
            ret = false;
        }
    }
    return ret;
}