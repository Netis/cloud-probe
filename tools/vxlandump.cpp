#ifdef WIN32
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
#include "../src/dep.h"

#define VXLAN_PORT 4789
int g_break_loop = 0;

int vxlan_frame_match(const void* data, int size, uint32_t vni)
{
    if(size < 8)
        return -1;
    if(ntohl(((uint32_t*)data)[0]) == 0x08000000 &&
    (ntohl(((uint32_t*)data)[1]) >> 8) == vni)
        return 0;
    return -1;
}

int main(int argc, const char* argv[]) {
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
    ("version,v", "show version.")
    ("help,h", "show help.")
    ("vni,n", boost::program_options::value<uint32_t>()->value_name("VNI"), "vxlan vni filter.")
    ("output,o", boost::program_options::value<std::string>()->value_name("OUT_PCAP"), "output pcap file");

    boost::program_options::variables_map vm;
    uint32_t vni;
    int sock;
    pcap_t* cap;
    pcap_dumper_t* dump;
    sockaddr_in addr;
    int noblock;
    socklen_t addr_len;
    timeval timeout;
    fd_set rset;
    std::vector<uint8_t> buff;
    int ret;
    pcap_pkthdr hdr;
    uint64_t capture_cnt;
    uint64_t drop_cnt;
    uint64_t dump_cnt;

    try {
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
        boost::program_options::notify(vm);
    } catch (boost::program_options::error& e) {
        std::cerr << "error: " << e.what() << std::endl;
        return 1;
    }

    // help
    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 0;
    }

    // version
    if (vm.count("version")) {
        showVersion();
        return 0;
    }

    if(!vm.count("vni"))
    {
        std::cerr << "must set vni option!" << std::endl;
        return -1;
    }
    vni = vm["vni"].as<uint32_t>();

    if (!vm.count("output")) {
        std::cerr << "must set output option!" << std::endl;
        return -1;
    }

    if(!(cap = pcap_open_dead(DLT_EN10MB, UINT16_MAX)))
    {
        std::cerr << "pcap_open_dead() failed!" << std::endl;
        return -1;
    }
    if(!(dump = pcap_dump_open(cap, vm["output"].as<std::string>().c_str())))
    {
        pcap_close(cap);
        std::cerr << "pcap_dump_open() failed!" << std::endl;
        return -1;
    }
    if((sock = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        pcap_dump_close(dump);
        pcap_close(cap);
        std::cerr << "socket() failed!" << std::endl;
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_port = htons(VXLAN_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_family = AF_INET;
    if(bind(sock, (const sockaddr*)&addr, sizeof(addr)) < 0)
    {
        close(sock);
        pcap_dump_close(dump);
        pcap_close(cap);
        return -1;
    }

    noblock = 1;
#ifdef WIN32
    ret = ioctlsocket(sock, FIONBIO, (unsigned long*)&noblock);
#else
    setsockopt(sock, SOL_SOCKET, SOCK_NONBLOCK, &noblock, sizeof(noblock));
#endif

    buff.resize(UINT16_MAX);

    std::signal(SIGINT, [](int){
        g_break_loop = 1;
    });
    std::signal(SIGTERM, [](int){
        g_break_loop = 1;
    });

    capture_cnt = 0;
    drop_cnt = 0;
    dump_cnt = 0;

    for(;!g_break_loop;)
    {
        timeout.tv_sec = 0;
        timeout.tv_usec = 50000;
        FD_ZERO(&rset);
        FD_SET(sock, &rset);
        if(select(sock + 1, &rset, 0, 0, &timeout) > 0)
        {
            addr_len = sizeof(addr);
            if((ret = recvfrom(sock, (char*)&*buff.begin(), UINT16_MAX, 0, (sockaddr*)&addr, &addr_len)) > 0)
            {
                ++capture_cnt;
                if(vxlan_frame_match(&*buff.begin(), ret, vni) < 0)
                {
                    ++drop_cnt;
                }
                else
                {
                    ++dump_cnt;
                    ret -= 8;
                    hdr.caplen = hdr.len = ret;
                    gettimeofday(&hdr.ts, 0);
                    pcap_dump((u_char*)dump, &hdr, &*buff.begin() + 8);
                }
            }
        }
    }
    std::cout << "Statis Result:" << std::endl;
    std::cout << "Capture Packets Count:                " << capture_cnt << std::endl;
    std::cout << "Drop Not Udp(vxlan) Packets Count:    " << drop_cnt << std::endl;
    std::cout << "Dump Packets Count:                   " << dump_cnt << std::endl;
    return 0;
}