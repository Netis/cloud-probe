#include "gtest/gtest.h"
#include "../src/syshelp.h"
#include "../src/pcaphandler.h"
#include "../src/socketgre.h"
#include "../src/pcapexport_extension.h"

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

    TEST(proto_erpsan_type3, test) {
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        std::string proto_config = R"(
            {
                "ext_file_path": "libproto_erspan_type3.so",
                "ext_params": {
                    "remoteips": [
                        "10.1.1.37"
                    ],
                    "pmtudisc_option": "dont",
                    "use_default_header": false,
                    "enable_vlan": true,
                    "vlan": 1024,
                    "enable_sequence": true,
                    "sequence_begin": 10000,
                    "enable_timestamp": true
                }
            }
        )";
        PcapExportExtension erspanExport(PcapExportExtension::EXT_TYPE_PORT_MIRROR, proto_config);
        EXPECT_EQ(0, erspanExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, erspanExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, erspanExport.closeExport());
    }

    TEST(proto_erpsan_type2, test) {
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        std::string proto_config = R"(
            {
                "ext_file_path": "libproto_erspan_type2.so",
                "ext_params": {
                    "remoteips": [
                        "10.1.1.37"
                    ],
                    "pmtudisc_option": "dont",                   
                    "use_default_header": false,
                    "enable_vlan": true,
                    "vlan": 1027,
                    "enable_sequence": true,
                    "sequence_begin": 10000
                }
            }
        )";
        PcapExportExtension erspanExport(PcapExportExtension::EXT_TYPE_PORT_MIRROR, proto_config);
        EXPECT_EQ(0, erspanExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, erspanExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, erspanExport.closeExport());
    }

    TEST(proto_erpsan_type1, test) {
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        std::string proto_config = R"(
            {
                "ext_file_path": "libproto_erspan_type1.so",
                "ext_params": {
                    "remoteips": [
                        "10.1.1.37"
                    ],
                    "pmtudisc_option": "dont"
                }
            }
        )";
        PcapExportExtension erspanExport(PcapExportExtension::EXT_TYPE_PORT_MIRROR, proto_config);
        EXPECT_EQ(0, erspanExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, erspanExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, erspanExport.closeExport());
    }

    TEST(proto_gre, test) {
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        std::string proto_config = R"(
            {
                "ext_file_path": "libproto_gre.so",
                "ext_params": {
                    "remoteips": [
                        "10.1.1.37"
                    ],
                    "pmtudisc_option": "dont",                    
                    "use_default_header": false,
                    "enable_key": true,
                    "key": 3,
                    "enable_sequence": true,
                    "sequence_begin": 10000
                }
            }
        )";
        PcapExportExtension greExport(PcapExportExtension::EXT_TYPE_PORT_MIRROR, proto_config);
        EXPECT_EQ(0, greExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, greExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, greExport.closeExport());
    }

    TEST(proto_vxlan, test) {
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        std::string proto_config = R"(
            {
                "ext_file_path": "libproto_vxlan.so",
                "ext_params": {
                    "remoteips": [
                        "10.1.1.37"
                    ],
                    "pmtudisc_option": "dont",                    
                    "use_default_header": false,
                    "vni": 3310
                }
            }
        )";
        PcapExportExtension vxlanExport(PcapExportExtension::EXT_TYPE_PORT_MIRROR, proto_config);
        EXPECT_EQ(0, vxlanExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, vxlanExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, vxlanExport.closeExport());
    }

    TEST(monitor_netflow, test) {
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        std::string monitor_config = R"(
            {
                "ext_file_path": "libmonitor_netflow.so",
                "ext_params": {
                    "collectors_ipport": [
                        {
                            "ip": "10.1.1.37",
                            "port": 2055
                        },
                        {
                            "ip": "10.1.1.38",
                            "port": 2055
                        }
                    ],
                    "interface": "eth0",
                    "netflow_version": 5
                }
            }
        )";
        PcapExportExtension netflowExport(PcapExportExtension::EXT_TYPE_TRAFFIC_MONITOR, monitor_config);
        EXPECT_EQ(0, netflowExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, netflowExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, netflowExport.closeExport());
    }
}