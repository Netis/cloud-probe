#include <iostream>
#include <fstream>
#include <pcap/pcap.h>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include "../src/scopeguard.h"
#include "../src/versioninfo.h"

int main(int argc, const char* argv[]) {
    boost::program_options::options_description generic("Generic options");
    generic.add_options()
        ("version,v", "show version.")
        ("help,h", "show help.");

    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
        ("lpcap", boost::program_options::value<std::string>()->value_name("PCAP_PATH"), "pcap file 1")
        ("rpcap", boost::program_options::value<std::string>()->value_name("PCAP_PATH"), "pcap file 2");
    boost::program_options::positional_options_description position;
    position.add("lpcap", 1);
    position.add("rpcap", 2);

    boost::program_options::options_description all;
    all.add(generic).add(desc);

    boost::program_options::variables_map vm;
    try {
        boost::program_options::parsed_options parsed = boost::program_options::command_line_parser(argc,argv)
            .options(all).positional(position).run();
        boost::program_options::store(parsed, vm);
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

    if (!vm.count("lpcap") || !vm.count("rpcap")) {
        std::cerr << "missing compare files!!" << std::endl;
        std::cerr << desc << std::endl;
        return 1;
    }

    std::string lpcap = vm["lpcap"].as<std::string>();
    std::string rpcap = vm["rpcap"].as<std::string>();

    if (!boost::filesystem::exists(lpcap) || !boost::filesystem::exists(rpcap)) {
        std::cerr << "pcap file not exists!!" << std::endl;
        return 1;
    }

    if (!boost::filesystem::is_regular_file(lpcap)) {
        std::cerr << lpcap << " is not regular file!" << std::endl;
        return 1;
    }

    if (!boost::filesystem::is_regular_file(rpcap)) {
        std::cerr << rpcap << " is not regular file!" << std::endl;
        return 1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t * lpcap_handle;
    pcap_t * rpcap_handle;

    lpcap_handle = pcap_open_offline(lpcap.c_str(), errbuf);
    if (!lpcap_handle) {
        std::cerr << "pcap_open_offline failed, err: " << errbuf << std::endl;
        return 1;
    }
    auto lpcapGuard = MakeGuard([lpcap_handle]() {
        pcap_close(lpcap_handle);
    });

    rpcap_handle = pcap_open_offline(rpcap.c_str(), errbuf);
    if (!rpcap_handle) {
        std::cerr << "pcap_open_offline failed, err: " << errbuf << std::endl;
        return 1;
    }
    auto rpcapGuard = MakeGuard([rpcap_handle]() {
        pcap_close(rpcap_handle);
    });

    struct pcap_pkthdr *l_pkt_header;
    struct pcap_pkthdr *r_pkt_header;
    const u_char *l_pkt_data, *r_pkt_data;
    int lret, rret;
    int nPktNum = 0;

    while(true) {
        lret = pcap_next_ex(lpcap_handle, &l_pkt_header, &l_pkt_data);
        if (lret == -1) {
            std::cerr << "pcap_next_ex failed! error: " << pcap_geterr(lpcap_handle) << " Pkt Num: " << nPktNum << std::endl;
            return 1;
        }
        rret = pcap_next_ex(rpcap_handle, &r_pkt_header, &r_pkt_data);
        if (rret == -1) {
            std::cerr << "pcap_next_ex failed! error: " << pcap_geterr(lpcap_handle) << " Pkt Num: " << nPktNum << std::endl;
            return 1;
        }
        if (lret == rret) {
            if (lret == 1) {
                // compare two packets
                if(l_pkt_header->caplen != r_pkt_header->caplen) {
                    std::cerr << "Compare result 1 for pkt header caplen, Pkt num: " << nPktNum << std::endl;
                    return 1;
                }
                if(std::memcmp(l_pkt_data, r_pkt_data, l_pkt_header->caplen)!=0)  {
                    std::cerr << "Compare result 1 for pkt data, Pkt num: " << nPktNum << std::endl;
                    return 1;
                }
            } else if (lret==-2){
                // no more packet
                std::cout << "Compare result 0, Pkt num: " << nPktNum << std::endl;
                return 0;
            } else {
                std::cerr << "Result code not defined!" << std::endl;
                return 1;
            }
        } else {
            std::cerr << "Compare result 1 for result not equal, Pkt num: " << nPktNum << std::endl;
            return 1;
        }
        nPktNum++;
    }
}
