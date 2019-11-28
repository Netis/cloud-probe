#include "gtest/gtest.h"
#include "../src/syshelp.h"
#include "../src/pcaphandler.h"
#include "../src/socketgre.h"
#include "../src/pcapexportplugin.h"

namespace {
    TEST(SysHelpTest, test) {
        EXPECT_EQ(0, set_high_setpriority());
        EXPECT_EQ(0, set_cpu_affinity(0));
    }

    class PcapExportTest : public PcapExportBase {
        int initExport() {
            return 0;
        }

        int exportPacket(const struct pcap_pkthdr* header, const uint8_t* pkt_data) {
            return 0;
        }

        int closeExport() {
            return 0;
        }
    };

    TEST(PcapHandlerTest, test) {
        PcapOfflineHandler handler;
        pcap_init_t param;
        handler.addExport(std::make_shared<PcapExportTest>());
        EXPECT_EQ(0, handler.openPcap("sample.pcap", param, "", false));
        EXPECT_EQ(0, handler.startPcapLoop(10));
    }

    TEST(PcapExportGre, test) {
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        PcapExportGre greExport(remoteips, 2, "", IP_PMTUDISC_DONT);
        EXPECT_EQ(0, greExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, greExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, greExport.closeExport());
    }

    TEST(erpsan_type3, test) {
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        std::string proto_config = R"(
            [
                {
                    "ext_file_path": "libproto_erspan_type3.so",
                    "ext_params": {
                        "use_default_header": false,
                        "enable_vlan": true,
                        "vlan": 1024,
                        "enable_sequence": true,
                        "sequence_begin": 10000,
                        "enable_timestamp": true
                    }
                }
            ]
        )";
        PcapExportPlugin erspanExport(remoteips, proto_config, "", IP_PMTUDISC_DONT);
        EXPECT_EQ(0, erspanExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, erspanExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, erspanExport.closeExport());
    }

    TEST(erpsan_type2, test) {
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        std::string proto_config = R"(
            [
                {
                    "ext_file_path": "libproto_erspan_type2.so",
                    "ext_params": {
                        "use_default_header": false,
                        "enable_vlan": true,
                        "vlan": 1027,
                        "enable_sequence": true,
                        "sequence_begin": 10000
                    }
                }
            ]
        )";
        PcapExportPlugin erspanExport(remoteips, proto_config, "", IP_PMTUDISC_DONT);
        EXPECT_EQ(0, erspanExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, erspanExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, erspanExport.closeExport());
    }

    TEST(erpsan_type1, test) {
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        std::string proto_config = R"(
            [
                {
                    "ext_file_path": "libproto_erspan_type1.so",
                    "ext_params": {
                    }
                }
            ]
        )";
        PcapExportPlugin erspanExport(remoteips, proto_config, "", IP_PMTUDISC_DONT);
        EXPECT_EQ(0, erspanExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, erspanExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, erspanExport.closeExport());
    }
}