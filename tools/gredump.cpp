#ifdef _WIN32
	#include <WinSock2.h>
#else
	#include <arpa/inet.h>
#endif
#include <iostream>
#include <csignal>
#include <ctime>
#include <pcap/pcap.h>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include "../src/scopeguard.h"
#include "../src/versioninfo.h"

const int32_t PROT_ETH_MINLEN = 14;
const int32_t PROT_IPV4_MINLEN = 20;
const int32_t PROT_IPPACKET_MINLEN = PROT_ETH_MINLEN + PROT_IPV4_MINLEN;

typedef struct IpFragCache {
    pcap_pkthdr pkthdr;
    uint8_t ipfrag_buff[65536];
} ipfrag_cache_t;

typedef struct GreHandleBuff {
    pcap_dumper_t *dumper;
    uint32_t srcip;
    uint32_t dstip;
    uint32_t grekey;
    std::map<std::tuple<uint32_t, uint32_t, uint16_t>, std::shared_ptr<ipfrag_cache_t>> ipfrags_cache;
    uint64_t captureCount;
    uint64_t ipfragCount;
    uint64_t dropNotGreCount;
    uint64_t dropFilterCount;
    uint64_t dropIpFragCount;
    uint64_t dumpCount;
    std::time_t lasttime;
} gre_handle_buff_t;

void PcapHanler(GreHandleBuff *buff, const struct pcap_pkthdr *h, const uint8_t *data) {
    uint8_t* p = (uint8_t*)data;
    int nCount = h->len;

    buff->captureCount++;
    if (nCount < PROT_IPPACKET_MINLEN) {
//        std::cerr << "Not IP Packet, drop it! len: " << nCount << std::endl;
        buff->dropNotGreCount++;
        return;
    }
    // ethernet
    uint8_t* eth = p;
    uint16_t etherType = ntohs(*((uint16_t*)(eth + 12)));
    if (etherType != 0x0800) {
//        std::cerr << "Ether Type not IP, drop it! ether type: " << etherType << std::endl;
        buff->dropNotGreCount++;
        return;
    }
    p += 14;
    nCount -= 14;

    // ip
    uint8_t* ipdata = p;

    uint8_t ihl = (*ipdata) & (uint8_t)0x0f;
    uint32_t iphdrlen = (uint32_t)ihl * 4;

    uint16_t iplength = ntohs(*((uint16_t*)(ipdata + 2)));
    uint16_t ipidenti = ntohs(*((uint16_t*)(ipdata+4)));
    uint8_t moreFrags = *(ipdata + 6) & (uint8_t)0x20;
    uint16_t fragOffset = ntohs(*((uint16_t*)(ipdata + 6))) & (uint16_t)0x1fff;
    uint8_t protocol = *(ipdata + 9);
    uint32_t ip_src = ntohl(*((uint32_t*)(ipdata+12)));
    uint32_t ip_dst = ntohl(*((uint32_t*)(ipdata+16)));

    if (protocol != 47) {
//        std::cout << "Ip Protocol not GRE, drop it! ip prot: " << (uint16_t)protocol << std::endl;
        buff->dropNotGreCount++;
        return;
    }

    if(buff->srcip != 0xffffffff && buff->srcip != ip_src) {
        buff->dropFilterCount++;
        return;
    }
    if(buff->dstip != 0xffffffff && buff->dstip != ip_dst) {
        buff->dropFilterCount++;
        return;
    }

    if (nCount>iplength) {
        nCount = iplength;
    }
    p += iphdrlen;
    nCount -= iphdrlen;

    uint32_t keybit;
    uint32_t cache_ul = 0;
    bool bHasCache;
    std::shared_ptr<ipfrag_cache_t> cache=nullptr;
    std::tuple<uint32_t, uint32_t, uint16_t> key = std::make_tuple(ip_src, ip_dst, ipidenti);
    auto got = buff->ipfrags_cache.find(key);
    if (got != buff->ipfrags_cache.end()) {
        bHasCache = true;
        cache = got->second;
    } else {
        bHasCache = false;
    }
    if ( moreFrags == 0 ) {
        if (fragOffset == 0) {
            pcap_pkthdr pkthdr = *h;
            pkthdr.len = (bpf_u_int32)nCount - 8;
            pkthdr.caplen = (bpf_u_int32)nCount - 8;
            keybit = ntohl(*((uint32_t*)(p+4)));
            if (buff->grekey==0 || buff->grekey==keybit) {
                pcap_dump((u_char *) buff->dumper, &pkthdr, p + 8);
                buff->dumpCount++;
            } else {
                buff->dropFilterCount++;
            }
        } else {
            if (bHasCache) {
                // last pkt of ip frag
                std::memcpy((void*)(cache->ipfrag_buff + fragOffset * 8), p, (size_t)nCount);
                cache->pkthdr.len += nCount - 8;
                cache->pkthdr.caplen += nCount - 8;
                memcpy(&cache_ul, cache->ipfrag_buff + 4, sizeof(cache_ul));
                keybit = ntohl(cache_ul);
                if (buff->grekey==0 || buff->grekey==keybit) {
                    pcap_dump((u_char*)buff->dumper, &cache->pkthdr, (const uint8_t*)(cache->ipfrag_buff + 8));
                    buff->dumpCount++;
                } else {
                    buff->dropFilterCount++;
                }
                buff->ipfrags_cache.erase(key);
            } else {
                std::cerr << "Find Ip Frag! but has not frag in buffer! drop it!! dump count:" << buff->dumpCount << std::endl;
                buff->dropIpFragCount++;
                return;
            }
        }
    } else {
        if (fragOffset == 0) {
            // first pkt of ip frag
            buff->ipfragCount++;
            std::shared_ptr<ipfrag_cache_t> newcache = std::make_shared<ipfrag_cache_t>();
            newcache->pkthdr = *h;
            newcache->pkthdr.len = (bpf_u_int32)nCount;
            newcache->pkthdr.caplen = (bpf_u_int32)nCount;
            std::memcpy((void*)(newcache->ipfrag_buff), p, (size_t)nCount);
            buff->ipfrags_cache[key] = newcache;
        } else {
            buff->ipfragCount++;
            if (bHasCache) {
                std::memcpy((void*)(cache->ipfrag_buff + fragOffset * 8), p, (size_t)nCount);
                cache->pkthdr.len += nCount;
                cache->pkthdr.caplen += nCount;
            } else {
                std::cerr << "Find Ip Frag! but has not frag in buffer! drop it!! " << std::endl;
                buff->dropIpFragCount++;
                return;
            }
        }
    }

    std::time_t current = std::time(NULL);
    if(current - buff->lasttime >= 10) {
        buff->lasttime = current;
        std::cout << current << ": captured " << buff->captureCount << " pkts, dumped " <<
        buff->dumpCount << " pkts." << std::endl;
    }
}

pcap_t* g_pcap_handle;
int main(int argc, const char* argv[]) {
    boost::program_options::options_description generic("Generic options");
    generic.add_options()
        ("version,v", "show version.")
        ("help,h", "show help.");

    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
        ("interface,i", boost::program_options::value<std::string>()->value_name("NIC"), "interface to capture packets.")
        ("pcapfile,f", boost::program_options::value<std::string>()->value_name("PATH"), "specify pcap file for offline mode, mostly for test.")
        ("sourceip,s", boost::program_options::value<std::string>()->value_name("SRC_IP"), "source ip filter.")
        ("remoteip,r", boost::program_options::value<std::string>()->value_name("DST_IP"), "gre remote ip filter.")
        ("keybit,k", boost::program_options::value<uint32_t>()->value_name("BIT"), "gre key bit filter.")
        ("output,o", boost::program_options::value<std::string>()->value_name("OUT_PCAP"), "output pcap file")
        ("count,c", boost::program_options::value<int>()->default_value(0)->value_name("MAX_NUM"), "Exit after receiving count packets. Default=0, No limit if count<=0.");

    boost::program_options::options_description all;
    all.add(generic).add(desc);

    boost::program_options::variables_map vm;
    try {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, all), vm);
        boost::program_options::notify(vm);
    } catch (boost::program_options::error& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    // help
    if (vm.count("help")) {
        std::cout << all << std::endl;
        return 0;
    }

    // version
    if (vm.count("version")) {
        showVersion();
        return 0;
    }

    // check options
    if (vm.count("interface") && vm.count("pcapfile")) {
        std::cerr << "please choice only one snoop mode: from interface or from pcap file!" << std::endl;
        return 1;
    }

    if (!vm.count("output")) {
        std::cerr << "must set output option!" << std::endl;
        return 1;
    }

    std::string dumpfile = vm["output"].as<std::string>();
    if (boost::filesystem::exists(dumpfile)) {
        std::cerr << "dump file has exist! file: " << dumpfile << std::endl;
        return 1;
    }

    int ret;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* pcap_handle;

    if (vm.count("interface")) {
        std::string intfdev = vm["interface"].as<std::string>();
        pcap_handle = pcap_create(intfdev.c_str(), errbuf);
        if (!pcap_handle) {
            std::cerr << "pcap_create failed, err: " << errbuf << std::endl;
            return 1;
        }
        auto pcapGuard = MakeGuard([pcap_handle]() {
            pcap_close(pcap_handle);
        });
        ret = pcap_activate(pcap_handle);
        if (ret != 0) {
            std::cerr << "Capture error: " << pcap_geterr(pcap_handle) << std::endl;
            return 1;
        }
        pcapGuard.Dismiss();
    } else if (vm.count("pcapfile")){
        std::string pcapfile = vm["pcapfile"].as<std::string>();
        pcap_handle = pcap_open_offline(pcapfile.c_str(), errbuf);
        if (!pcap_handle) {
            std::cerr << "pcap_open_offline failed, err: " << errbuf << std::endl;
            return 1;
        }
    } else {
        std::cerr << "Please choice snoop mode: from interface or from pcap file!" << std::endl;
        return 1;
    }

    g_pcap_handle = pcap_handle;
    auto pcapGuard = MakeGuard([pcap_handle]() {
        pcap_close(pcap_handle);
    });

    pcap_dumper_t* pcap_dumper_handler = pcap_dump_open(pcap_handle, dumpfile.c_str());
    if (pcap_dumper_handler==NULL) {
        std::cerr << "pcap_dump_open failed! error text: " << pcap_geterr(pcap_handle) << std::endl;
        return -1;
    }
    auto pcapDumpGuard = MakeGuard([pcap_dumper_handler]() {
        pcap_dump_close(pcap_dumper_handler);
    });

    GreHandleBuff grehandlebuff;
    grehandlebuff.dumper = pcap_dumper_handler;
    grehandlebuff.ipfrags_cache.clear();
    if (vm.count("sourceip")) {
        in_addr addr;
        std::string sourceip = vm["sourceip"].as<std::string>();
        if(inet_pton(AF_INET, sourceip.c_str(), &addr)==0) {
            std::cerr << "sourceip option is valid! sourceip: " << sourceip << std::endl;
            grehandlebuff.srcip=0xffffffff;
        } else {
            grehandlebuff.srcip=ntohl(addr.s_addr);
        }
    } else {
        grehandlebuff.srcip=0xffffffff;
    }

    if (vm.count("remoteip")) {
        in_addr addr;
        std::string remoteip = vm["remoteip"].as<std::string>();
        if(inet_pton(AF_INET,remoteip.c_str(), &addr)==0) {
            std::cerr << "remoteip option is valid! remoteip: " << remoteip << std::endl;
            grehandlebuff.dstip=0xffffffff;
        } else {
            grehandlebuff.dstip=ntohl(addr.s_addr);
        }
    } else {
        grehandlebuff.dstip=0xffffffff;
    }

    if (vm.count("keybit")) {
        grehandlebuff.grekey = vm["keybit"].as<uint32_t>();
    } else {
        grehandlebuff.grekey = 0;
    }

    grehandlebuff.lasttime = std::time(NULL);
    grehandlebuff.captureCount=0;
    grehandlebuff.dropFilterCount = 0;
    grehandlebuff.dropIpFragCount = 0;
    grehandlebuff.dropNotGreCount = 0;
    grehandlebuff.dumpCount = 0;
    grehandlebuff.ipfragCount = 0;

    // signal
    std::signal(SIGINT, [](int){
        pcap_breakloop(g_pcap_handle);
    });
    std::signal(SIGTERM, [](int){
        pcap_breakloop(g_pcap_handle);
    });

    int nCount=0;
    if (vm.count("count")) {
        nCount = vm["count"].as<int>();
    }

    ret = pcap_loop(pcap_handle, nCount, [](uint8_t *user, const struct pcap_pkthdr *h, const uint8_t *data) {
        GreHandleBuff* buff = (GreHandleBuff*)user;
        PcapHanler(buff, h, data);
    }, (uint8_t*)&grehandlebuff);

    std::cout << "Statis Result:" << std::endl;
    std::cout << "Capture Packets Count:      " << grehandlebuff.captureCount << std::endl;
    std::cout << "Drop Not Gre Packets Count: " << grehandlebuff.dropNotGreCount << std::endl;
    std::cout << "Drop IpFrags Packets Count: " << grehandlebuff.dropIpFragCount << std::endl;
    std::cout << "Drop Filter Packets Count:  " << grehandlebuff.dropFilterCount << std::endl;
    std::cout << "Ip Frags Packets Count:     " << grehandlebuff.ipfragCount << std::endl;
    std::cout << "Dump Packets Count:         " << grehandlebuff.dumpCount << std::endl;
    return 0;
}
