#include "gtest/gtest.h"
#include "../src/syshelp.h"
#include "../src/pcaphandler.h"
#include "../src/socketgre.h"
#include "../src/agent_status.h"
#include "../src/agent_control_plane.h"

namespace {
    TEST(SysHelpTest, test) {
        EXPECT_EQ(0, set_high_setpriority());
        EXPECT_EQ(0, set_cpu_affinity(0));
    }

    class PcapExportTest : public PcapExportBase {
        int initExport() {
            return 0;
        }

        int exportPacket(const struct pcap_pkthdr* header, const uint8_t* pkt_data, int direct) {
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
        EXPECT_EQ(0, greExport.exportPacket(&header, pkt_data.data(), PKTD_NONCHECK));
        EXPECT_EQ(0, greExport.closeExport());
    }

    TEST(AgentStatusQuery, test) {
        // AgentStatus::get_instance()->update_status(1586508861, header->caplen, 
        //                      _gre_count, _gre_drop_count, _pcap_handle);
        AgentStatus* inst = AgentStatus::get_instance();
        inst->reset_agent_status();
        inst->update_capture_status(1586508861, 200, 1, 0, nullptr);
        inst->update_capture_status(1586508862, 200, 1, 0, nullptr);
        inst->update_capture_status(1586508863, 100, 1, 0, nullptr);
        EXPECT_EQ(1586508861, static_cast<uint32_t>(inst->first_packet_time()));
        EXPECT_EQ(1586508863, static_cast<uint32_t>(inst->last_packet_time()));
        EXPECT_EQ(500, static_cast<uint32_t>(inst->total_cap_bytes()));
    }

    TEST(AgentControlPlane, test) {

        AgentControlPlane zmq_server(5556);
        EXPECT_EQ(0, zmq_server.init_msg_server());
        sleep(1);
        zmq_server.close_msg_server();
    }

}