#include "gtest/gtest.h"
#include "../src/syshelp.h"
#include "../src/pcaphandler.h"
#include "../src/socketgre.h"

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
        PcapExportGre greExport("127.0.1.1", 2);
        EXPECT_EQ(0, greExport.initExport());
        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, greExport.exportPacket(&header, pkt_data.data()));
        EXPECT_EQ(0, greExport.closeExport());
    }

}