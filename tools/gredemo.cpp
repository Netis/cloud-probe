#include <arpa/inet.h>
#include <iostream>
#include <fstream>
#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>

typedef struct PktHdr {
    uint32_t tv_sec;  // epoc seconds
    uint32_t tv_usec; // and microseconds
    uint32_t caplen;  // actual capture length
    uint32_t len; 	  // wire packet length
} pkthdr_t, *pkthdr_ptr_t;

typedef struct GreHdr {
    uint16_t flags;
    uint16_t protocol;
    uint32_t keybit;
} gre_hdr;

int main(int argc, const char* argv[]) {
    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
        ("help", "demo help message")
        ("pcap", boost::program_options::value<std::string>(), "pcap file")
        ("remote", boost::program_options::value<std::string>(), "gre remote ip")
        ("keybit", boost::program_options::value<uint32_t>(), "gre keybit");

    boost::program_options::variables_map vm;
    boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc), vm);
    boost::program_options::notify(vm);

    if (vm.count("help")) {
        std::cout << desc << std::endl;
        return 0;
    }

    if (!vm.count("pcap") || !vm.count("remote") || !vm.count("keybit")) {
        std::cout << desc << std::endl;
        return 1;
    }

    std::string pcap_file = vm["pcap"].as<std::string>();
    std::string remote_ip = vm["remote"].as<std::string>();
    uint32_t keybit = vm["keybit"].as<uint32_t>();

    boost::filesystem::path p = pcap_file;
    if (!boost::filesystem::exists(p)) {
        std::cout << "pcap file not exist! file path: " << pcap_file << std::endl;
        return 1;
    }
    if (!boost::filesystem::is_regular_file(p)) {
        std::cout << "pcap file is not regular file! file path: " << pcap_file << std::endl;
        return 1;
    }

    // open pcap file
    std::fstream fs;
    fs.open(pcap_file, std::ios_base::in | std::ios_base::binary);
    if (!fs.is_open()) {
        std::cout << "open pcap file failed! file path: " << pcap_file << std::endl;
        return 1;
    }
    // read pcap header
    bool isBigEndian;
    unsigned char pcap_header[24];
    try {
        fs.read((char*) pcap_header, sizeof(pcap_header));
        if ((fs.rdstate() & std::ifstream::failbit) != 0) {
            std::cout << "read pcap file header wrong! error:" << std::to_string(fs.rdstate()) << std::endl;
            return 1;
        }
    } catch (std::fstream::failure e) {
        std::cout << "Exception read file, " << e.what() << std::endl;
        return 1;
    }

    if (pcap_header[0]==0xA1 && pcap_header[1]==0xB2
        && pcap_header[2]==0xC3 && pcap_header[3]==0xD4) {
        isBigEndian = true;
    }
    else if (pcap_header[3]==0xA1 && pcap_header[2]==0xB2
             && pcap_header[1]==0xC3 && pcap_header[0]==0xD4) {
        isBigEndian = false;
    }
    else {
        std::cout << "pcap file header wrong! file path: " << pcap_file << std::endl;
        return 1;
    }

    // gre socket
    struct sockaddr_in remote_addr;
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_addr.s_addr = inet_addr(remote_ip.c_str());

    int sockfd;
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_GRE))==-1) {
        std::cout << "create socket fd failed!" << std::endl;
        return 1;
    }

    gre_hdr greHdr;
    greHdr.flags = htons(0x2000);
    greHdr.protocol = htons(0x6558);
    greHdr.keybit = htonl(keybit);

    char grebuffer[65535 + sizeof(gre_hdr)];
    std::memcpy((void*)grebuffer, (void*)&greHdr, sizeof(gre_hdr));
    char* pPktBuff = grebuffer + sizeof(gre_hdr);

    // read pcap header
    pkthdr_t pktHdr;
    char pkt_header[16];
    while(1) {
        try {
            fs.read(pkt_header, sizeof(pkt_header));
            if ((fs.rdstate() & std::ifstream::failbit) != 0) {
                if ( (fs.rdstate() & std::ifstream::eofbit) != 0 ) {
                    std::cout << "reach the end of pcap file!" << std::endl;
                    return 0;
                }
                std::cout << "read pcap header wrong! error:" << std::to_string(fs.rdstate()) << std::endl;
                return -1;
            }
        } catch (std::fstream::failure e) {
            std::cout << "Exception read file, " << e.what() << std::endl;
            return 1;
        }
        if (isBigEndian) {
            pktHdr.tv_sec = ntohl(*((uint32_t*)pkt_header));
            pktHdr.tv_usec = ntohl(*((uint32_t*)(pkt_header+4)));
            pktHdr.caplen = ntohl(*((uint32_t*)(pkt_header+8)));
            pktHdr.len = ntohl(*((uint32_t*)(pkt_header+12)));
        } else {
            pktHdr.tv_sec = *((uint32_t*)pkt_header);
            pktHdr.tv_usec = *((uint32_t*)(pkt_header+4));
            pktHdr.caplen = *((uint32_t*)(pkt_header+8));
            pktHdr.len = *((uint32_t*)(pkt_header+12));
        }

        // read pcap
        if (pktHdr.len > 65535) {
            std::cout << "pcap header wrong, len great than 65535! " << pktHdr.len << std::endl;
            return 1;
        }
        try {
            fs.read(pPktBuff, pktHdr.len);
        } catch (std::fstream::failure e) {
            std::cout << "Exception read file, " << e.what() << std::endl;
            return 1;
        }

        // gre send pkt
        sendto(sockfd, grebuffer, pktHdr.len+sizeof(gre_hdr), 0, (struct sockaddr *)&remote_addr, sizeof(struct sockaddr));
    }
}
