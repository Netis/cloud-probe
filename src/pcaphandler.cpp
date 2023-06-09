#include "pcaphandler.h"
#include <iostream>
#include <algorithm>
#include <boost/filesystem.hpp>
#include <stdint.h>

#ifdef _WIN32
#include <pcap.h>
#include <stdio.h>
#include <winsock2.h>
#include <iphlpapi.h>
#include <conio.h> 
#include <packet32.h> 
#include <ntddndis.h>
#else
#include <sys/ioctl.h>
#include <net/if.h>
#endif

#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/SimpleLayout.hh"
#include "log4cpp/PropertyConfigurator.hh"

#include "pcap/vlan.h"
#include "scopeguard.h"
#include "agent_status.h"

uint32_t makeMplsHdr(int direct, int serviceTag) {
    uint32_t flag = 0;
    mplsHdr* hdr = (mplsHdr*)&flag;
    hdr->magic_number = 1;
    hdr->rra = direct;

    hdr->service_tag_h = serviceTag >> 4;
    hdr->service_tag_l = serviceTag & 0x0f;

    hdr->bottom = 1;
    hdr->reserved2 = 0xff;
    return flag;
}

bool replaceWithIfIp(std::string& expression, std::vector<std::string> &ips, LogFileContext& ctx) {
    
    std::string name = expression.substr(strlen("nic."));
    expression = "";
    pcap_if_t *alldevs;
    pcap_if_t *d;
    struct pcap_addr *addr;
    char err_buf[PCAP_ERRBUF_SIZE];
    std::string output_buffer = "";
#ifdef _WIN32
            std::unordered_map<std::string, std::string> interfaces;
            std::unordered_map<std::string, std::string>::iterator it;
            if (getLocalInterfacesWin(interfaces) < 0) {
                ctx.log("Call getLocalInterfacesWin failed in replaceWithIfIp.", log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << "Call getLocalInterfacesWin failed in replaceWithIfIp." << std::endl;
                return 1;
            }
            
            name = u16ToUtf8(gb2312ToU16(name));
            
            if ((it = interfaces.find(name)) == interfaces.end()) {
                output_buffer = std::string("not interface match (") + expression + ") failed, reference follow list:\n";
                // std::cerr << "not interface match ("<< expression << ") failed, reference follow list:" << std::endl;
                for (auto &m : interfaces) {
                    output_buffer += std::string("\t") + m.second + "\t" + u16ToGb2312(utf8ToU16(m.first)) + "\n";
                    // std::cerr << "\t" << m.second << "\t" << u16ToGb2312(utf8ToU16(m.first)) << std::endl;
                }
                ctx.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << output_buffer << std::endl;
                return 1;
            }
            name = it->second;
            
#endif
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

HandleParam::HandleParam(std::string dump,int interval, int slice,std::string dev, std::string processId, 
        pcap_init_t param,  std::string filter, std::string dirStr, std::string machineName,
        LogFileContext& ctx):
            _dump(dump),
            _interval(interval),
            _slice(slice),
            _dev(dev),
            _processId(processId),_dirStr(dirStr),
            _filter(filter),
            _machineName(machineName),
            _ctx(ctx){
    
    memcpy(&_pcapParam, &param,sizeof(param));
   
}

HandleParam::HandleParam(HandleParam &param) {
    _dump = param._dump;
    _interval = param._interval;
    _slice = param._slice;
    _dev = param._dev;
    _processId = param._processId;
    _dirStr = param._dirStr;
    _filter = param._filter;
    _machineName = param._machineName;
    _ctx = param._ctx;
    memcpy(&_pcapParam, &param._pcapParam,sizeof(_pcapParam));
}


uint64_t PcapHandler::_fwd_count = 0;
uint64_t PcapHandler::_cap_count = 0;
uint64_t PcapHandler::_fwd_byte = 0;
uint64_t PcapHandler::_cap_byte = 0;

PcapHandler::PcapHandler(HandleParam & param):
    _param(param){

    _pcap_handle = NULL;
    _pcap_dumpter = NULL;
    _need_update_status = 0;
    _ctx = param.getLogFileContext();

    if (_param.getInterval() != -1) {
        if (_param.getProcessId().length() != 0) {
            _dumpDir = _param.getDump() + _param.getProcessId() + "/";
        } else {
            _dumpDir = _param.getDump() + _param.getDev() + (_param.getDev().empty()? "":"/");
        }

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

uint32_t PcapHandler::getPacketLen (uint32_t length) {
    if (_param.getSlice() == 0) {
        return length;
    }
    else{
        return (_param.getSlice() < length)? _param.getSlice() : length;
    }
};

int PcapHandler::openPcapDumper(pcap_t* pcap_handle) {
    closePcapDumper();
	char date[60] = {0};
	char subPath[60] = {0};
    std::string filepath;
    if (_param.getInterval() >0) {
        struct tm* ptm = localtime(&_timeStamp);
	    sprintf(date, "%d%02d%02d%02d%02d%02d",
		    (int)ptm->tm_year + 1900,(int)ptm->tm_mon + 1,(int)ptm->tm_mday,
		    (int)ptm->tm_hour, (int)ptm->tm_min, (int)ptm->tm_sec);
	    sprintf(subPath, "%d%02d%02d%02d",
                (int)ptm->tm_year + 1900,(int)ptm->tm_mon + 1,(int)ptm->tm_mday,
                (int)ptm->tm_hour);
        std::string currDir = _dumpDir + subPath + "/";
        if(!boost::filesystem::is_directory(currDir))
            boost::filesystem::create_directories(currDir);
        filepath = currDir + "pktminerg_dump_"+std::string(date) + ".pcap";
    }
    else {
        if(!boost::filesystem::is_directory(_dumpDir))
            boost::filesystem::create_directories(_dumpDir);
        filepath = _dumpDir + "pktminerg_dump.pcap";
    }
    if (boost::filesystem::exists(filepath)) {
        boost::filesystem::remove(filepath);
    }
    _pcap_dumpter = pcap_dump_open(pcap_handle, filepath.c_str());
    if (_pcap_dumpter == NULL) {
        output_buffer = std::string("Call pcap_dump_open failed, error is ") + 
                    pcap_geterr(pcap_handle) + ".";
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
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

void PcapHandler::packetHandler(const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
    ether_header* eth;
    iphdr* ip;
    vlan_tag *vlan_hdr;
    udphdr *udp_hdr;
    tcphdr *tcp_hdr;
    uint16_t eth_type;
    uint16_t sport = 0;
    uint16_t dport = 0;
    int direct = PKTD_UNKNOWN;
    int cap_len = header->len;
    _cap_count++;
    _cap_byte += header->caplen;
    if(header->caplen < sizeof(ether_header))
        return;
    eth = (ether_header*)pkt_data;
    eth_type = ntohs(eth->ether_type);

    if(_autoDirection) {
        if(memcmp(eth->ether_shost, _macAddr, ETH_ALEN)==0) {
                direct = PKTD_OG;
        } else {
            direct = PKTD_IC;
        }
    }
    
    if (direct == PKTD_UNKNOWN) {
        switch(eth_type) {
        case ETHERTYPE_IP:
            ip = (iphdr*)(pkt_data + sizeof(ether_header));
            if (ip->protocol == 17) {
                udp_hdr = (udphdr*) (pkt_data + sizeof(ether_header)+sizeof(iphdr));
                sport = ntohs(udp_hdr->source);
                dport = ntohs(udp_hdr->dest);
                // check vxlan
                if (dport >= 4700 && dport < 4800 && header->len > 2*sizeof(ether_header)
                        + 2*sizeof(iphdr) + sizeof(udp_hdr) + sizeof(vxlan_hdr_t)) {
                    iphdr* sub_ip =  (iphdr*)((uint8_t*)udp_hdr + sizeof(ether_header) + sizeof(udp_hdr) + sizeof(vxlan_hdr_t));

                    if (sub_ip->protocol == 17 && (uint8_t*)sub_ip + sizeof(iphdr) + sizeof(udp_hdr) < pkt_data + cap_len) {
                        udp_hdr = (udphdr *) ((uint8_t*)sub_ip + sizeof(iphdr));

                        sport = ntohs(udp_hdr->source);
                        dport = ntohs(udp_hdr->dest);
                        ip = sub_ip;
                    }  else if (sub_ip->protocol == 6 &&  (uint8_t*)sub_ip + sizeof(iphdr) + sizeof(tcp_hdr) < pkt_data + cap_len) {
                        tcp_hdr = (tcphdr*) ((uint8_t*)sub_ip + sizeof(iphdr));

                        sport = ntohs(tcp_hdr->source);
                        dport = ntohs(tcp_hdr->dest);
                        ip = sub_ip;
                    }
                }
            }
            else if (ip->protocol == 6) {
                tcp_hdr = (tcphdr*) (pkt_data + sizeof(ether_header)+sizeof(iphdr));
                sport = ntohs(tcp_hdr->source);
                dport = ntohs(tcp_hdr->dest);
            }
            direct = checkPktDirection((const in_addr*)&ip->saddr, (const in_addr*)&ip->daddr, sport, dport);
            break;
        
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
            break;
        default:
            break;
    }
    }
    
    ((struct pcap_pkthdr*)header)->caplen = getPacketLen(header->caplen);

    

    int ret = _export->exportPacket(header, pkt_data, direct);
    if (_export->getExportType() == exporttype::gre || _export->getExportType() == exporttype::vxlan) {
        if (ret == 0) {
            _fwd_count++;
            uint32_t len = header->caplen + (_export->getExportType() == exporttype::gre? __GRE_LEN:__VXLAN_LEN);//gre
            len += ((__ETH_LEN + __IP_LEN) * (len / __MTU_IP_PAYLOAD + ((len % __MTU_IP_PAYLOAD) ? 1 : 0)));//fragments append ethernet + ip
            _fwd_byte += len;
        }
        else if (_export->getExportType() == exporttype::zmq) {
            if (ret == 0) {
                _fwd_count += _export->getForwardCnt();
                _fwd_byte += _export->getForwardByte();
            }
        }
    }
    if (_pcap_dumpter && (direct != PKTD_UNKNOWN)) {
        auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        if( _param.getInterval() > 0 && tt-_timeStamp > _param.getInterval() ) {
            _timeStamp = tt;

            if (openPcapDumper(_pcap_handle) != 0) {
                _ctx.log("Call openPcapDumper failed.", log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << "Call openPcapDumper failed." << std::endl;
            }
        }

        pcap_dump(reinterpret_cast<u_char *>(_pcap_dumpter), header, pkt_data);
    }
    if (_statislog == nullptr) {
        _statislog = std::make_shared<GreSendStatisLog>(_ctx, false);
        _statislog->initSendLog("pktminerg");
    }

#ifndef _WIN32
    _statislog->logSendStatis((uint64_t) (header->ts.tv_sec), header->caplen, _cap_count, _fwd_count, 0,
                              _pcap_handle);
#endif
        
    if (_need_update_status) {
        AgentStatus::get_instance()->update_capture_status((uint64_t) (header->ts.tv_sec), _cap_byte, _fwd_byte,
                                                            _fwd_count, _cap_count,_pcap_handle);
    }
}

void PcapHandler::addExport(std::shared_ptr<PcapExportBase> pcapExport) {
    _export = pcapExport;
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


int PcapHandler::openPcap() {
    int ret;
    struct bpf_program filter;
    bpf_u_int32 net = 0;

    _need_update_status = _param.getPcapParam().need_update_status;

    std::string dev = _param.getDev();
    
#ifndef _WIN32
    int fd = -1;
    if (_param.getProcessId() != "") {
        std::string path = "/proc/" + _param.getProcessId() + "/ns/net";
        fd = open(path.c_str(), O_RDONLY); /* Get file descriptor for namespace */

        if (fd == -1) {
            output_buffer = std::string("Can not open the namespace:") + path;
            _ctx.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() << output_buffer <<std::endl;
            return -1;
        }
        if (setns(fd, 0) == -1) {
            output_buffer = std::string("Can not set the namespace:") + path;
            _ctx.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() << output_buffer <<std::endl;
            return -1;
        }
    }
#else
    auto tt = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    if(_intfaceTimeStamp == 0|| tt - _intfaceTimeStamp > 60)
    {
        _intfaceTimeStamp = tt;
        std::unordered_map<std::string, std::string> interfaces;
        
        if (getLocalInterfacesWin(interfaces) < 0) {
            _ctx.log("Call getLocalInterfacesWin failed.", log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() << "Call getLocalInterfacesWin failed." << std::endl;
            return -1;
        }
        for(auto item: interfaces) {
            _interfaces[item.first] = item.second;
        }

    }

    dev = u16ToUtf8(gb2312ToU16(dev));
    std::unordered_map<std::string, std::string>::iterator it;
    if ((it = _interfaces.find(dev)) == _interfaces.end()) {
        
        return -1;
    }
    
    dev = it->second;
#endif
    pcap_t* pcap_handle = pcap_create(dev.c_str(), _errbuf);
    if (!pcap_handle) {
        output_buffer = std::string("Call pcap_create(") + dev + ") failed, error is " + _errbuf + ".";
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);    
        std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
        return -1;
    }
    
    auto pcapGuard = MakeGuard([pcap_handle]() {
        pcap_close(pcap_handle);
    });

    pcap_set_snaplen(pcap_handle, _param.getPcapParam().snaplen);
    pcap_set_timeout(pcap_handle, _param.getPcapParam().timeout);
    pcap_set_promisc(pcap_handle, _param.getPcapParam().promisc);
    

    ret = pcap_set_buffer_size(pcap_handle, _param.getPcapParam().buffer_size);
    if (ret != 0) {
        output_buffer = std::string("Call pcap_set_buffer_size to ") + 
                    std::to_string(_param.getPcapParam().buffer_size) + " failed.";
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);  
        std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
        return -1;
    }
    
    ret = pcap_activate(pcap_handle);
    if (ret != 0) {
        output_buffer = std::string("Call pcap_activate failed  error is ") + pcap_geterr(pcap_handle) + ".";
        _ctx.log(output_buffer, log4cpp::Priority::ERROR); 
        std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
        return -1;
    }
    if (_param.getPcapParam().timeout == 0) {
        ret = pcap_setnonblock(pcap_handle, 1, _errbuf);
        if (ret != 0) {
            output_buffer = std::string("Set non-block mode failed,") + std::to_string(ret) + ":" + _errbuf;
            _ctx.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
        }
    }
    ret = pcap_getnonblock(pcap_handle, _errbuf);
    
    if (!_param.getDirStr().empty()) {
        
        if (_param.getDirStr() == "auto") {
            _autoDirection = true;
            if (setMacAddr(dev, _param.getMachineName())<0) {
                return -1;
            }    

        } else {            
            setDirIPPorts(_param.getDirStr());
        }
    }

    if (_param.getFilter().length() > 0) {
        output_buffer = std::string("Set pcap filter as \"") + _param.getFilter() + "\".";
        _ctx.log(output_buffer, log4cpp::Priority::INFO);
        std::cout << StatisLogContext::getTimeString() << output_buffer << std::endl;

        ret = pcap_compile(pcap_handle, &filter, _param.getFilter().c_str(), 0, net);
        if (ret != 0) {
            output_buffer = std::string("Call pcap_compile failed, error is ")
                      + pcap_strerror(ret) + ".";
            _ctx.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
            return -1;
        }

        ret = pcap_setfilter(pcap_handle, &filter);
        if (ret != 0) {
            output_buffer = std::string("Call pcap_setfilter failed, error is ")
                          + pcap_strerror(ret) + ".";
            _ctx.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
            return -1;
        }
    }
#ifndef _WIN32
    if (_param.getProcessId() != "") {
        close(fd);
    }
#endif
    if (_param.getInterval() >= 0) {
        if (openPcapDumper(pcap_handle) != 0) {
            _ctx.log("Call openPcapDumper failed.", log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() << "Call openPcapDumper failed." << std::endl;
            return -1;
        }
    }
    pcapGuard.Dismiss();
    _pcap_handle = pcap_handle;
    
    return 0;
}

int PcapHandler::setMacAddr(std::string dev, std::string machineName) {
#ifdef _WIN32

    LPADAPTER lpAdapter = PacketOpenAdapter((char*)dev.data()); 

    if (!lpAdapter || (lpAdapter->hFile == INVALID_HANDLE_VALUE)) 
    { 
        output_buffer = std::string("Fail to open the adapter of ") + dev;
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
        return -1; 
    } 

    PPACKET_OID_DATA OidData = (PPACKET_OID_DATA) new char [6 + sizeof(PACKET_OID_DATA)];
    if (OidData == NULL) 
    {
        output_buffer = std::string("Fail to allocate memory for the adapter of ") + dev;
        _ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
        PacketCloseAdapter(lpAdapter); 
        return -1; 
    } 

    OidData->Oid = OID_802_3_CURRENT_ADDRESS; 

    OidData->Length = 6; 
    memset(OidData->Data, 0, 6); 
    BOOLEAN Status = PacketRequest(lpAdapter, FALSE, OidData); 
    if(Status) 
    { 
        memcpy(&_macAddr,(u_char*)(OidData->Data),6); 
    } 
    delete OidData ; 
    PacketCloseAdapter(lpAdapter);
#else
    if(machineName.empty()) {
        struct ifreq ifr;
        int sockfd = socket(AF_INET, SOCK_STREAM, 0);
        if(sockfd < 0)
        {
            _ctx.log("Can't init socket for mac address.", log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() << "Can't init socket for mac address." <<std::endl;
            return -1;
        }
        memset(&ifr, 0x00, sizeof(ifr));

        strcpy(ifr.ifr_name, dev.c_str());
        
        int nRes = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
        if(nRes < 0)
        {
            output_buffer = std::string("Can't get mac address of the interface: ") + dev;
            _ctx.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << output_buffer << std::endl;
            return -1;
        }
        else
        {          
            memcpy(&_macAddr,ifr.ifr_hwaddr.sa_data,ETH_ALEN);
        }
    } else {
            FILE *fp;
	        char buffer[80] = {0};
                   
            const auto cmd = boost::str(
                boost::format("sh get_mac_with_name.sh %1%") % machineName);
	        fp=popen(cmd.c_str(),"r");
	        fgets(buffer,sizeof(buffer),fp);
            pclose(fp);
            if (strlen(buffer) == 0) {
                output_buffer = std::string("Can't get mac address for KVM:") + machineName;
                _ctx.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
                return -1;
            }	
            std::string macStr = std::string(buffer, strlen(buffer) - 1);
            std::vector<std::string> strs;
            boost::split(strs, macStr, boost::is_any_of(":"));
            if (strs.size() != ETH_ALEN) {
                output_buffer = std::string("get wrong mac address for KVM:") + machineName + " " + macStr;
                _ctx.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
                return -1;
            }
            for (uint8_t i = 0; i<ETH_ALEN; i++) {
                _macAddr[i] = (uint8_t)stoi(strs[i],0,16);
            }
    }
    
#endif
    output_buffer = std::string("get mac address of dev:") + dev + "=";
    char mac_buf[20] = {0};
    std::snprintf(mac_buf, sizeof(mac_buf) - 1, "%02X:%02X:%02X:%02X:%02X:%02X", 
        (unsigned)_macAddr[0],
        (unsigned)_macAddr[1],
        (unsigned)_macAddr[2],
        (unsigned)_macAddr[3],
        (unsigned)_macAddr[4],
        (unsigned)_macAddr[5]
    );
    output_buffer += mac_buf;
    _ctx.log(output_buffer, log4cpp::Priority::INFO);
    std::cout << StatisLogContext::getTimeString() << output_buffer << std::endl;
    
    return 0;
}

void PcapHandler::clearHandler() {
    closeExport();
    closePcapDumper();
    closePcap();
    setHandlerStatus(HANDLER_DOWN);
}

void PcapHandler::closeExport() {
    _export->closeExport();
    
    return;
}

int PcapHandler::initExport() {
    return _export->initExport();
}

int PcapHandler::handlePacket() {
    if (_pcap_handle == NULL) {
        _ctx.log("The pcap has not created.", log4cpp::Priority::ERROR);
        std::cerr << StatisLogContext::getTimeString() << "The pcap has not created." << std::endl;
        return -1;
    }
    struct pcap_pkthdr * hdr;
    const u_char * data;
 
    int ret = pcap_next_ex(_pcap_handle, &hdr, &data);
    if (1 == ret) {
       packetHandler(hdr, data);
    } else if(0 == ret){
        _export->checkSendBuf();
        _fwd_byte += _export->getForwardByte();
        _fwd_count += _export->getForwardCnt();
        return 0;
    }
    else {
        return -1;
    }
    return 0;
}

void IpPortAddr::init(std::string express) {
    if (express == "auto") {
        return;
    }
    LogFileContext ctx(false, "");
    std::vector<std::string> strs;
    boost::split(strs, express, boost::is_any_of("_"));
    for (unsigned int i = 0; i < strs.size()-1; i++) {
        if (strs[i] == "host" || strs[i] == "(host") {
            size_t len = strs[i+1].length();
            if (len > 0 && strs[i+1][len-1] ==')') {
                strs[i+1].erase(strs[i+1].end() - 1);
            }
            if (strs[i+1].find("nic.") == 0) {
                std::vector<std::string> ips;
                std::string devName = "";
                unsigned int j = i+1;
                
                while (j<strs.size() && strs[j]!="and" && strs[j]!="port") {
                    if(j != i+1) {
                        devName +=' ';
                    }
                    devName += strs[j];
                    j++;
                }
                
                replaceWithIfIp(devName, ips, ctx);
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
