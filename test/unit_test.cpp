
#define private public
#define protected public

#include <boost/program_options.hpp>

#include "gtest/gtest.h"
#include "../src/syshelp.h"
#include "../src/pcaphandler.h"
#include "../src/socketgre.h"
#include "../src/socketvxlan.h"
#include "../src/socketzmq.h"
#include "../src/agent_status.h"
#include "../src/agent_control_plane.h"
#include "../src/logfilecontext.h"

namespace {
    TEST(SysHelpTest, test) {
        EXPECT_EQ(-1, set_high_setpriority());
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
    TEST(PcapExport, test) {
        uint8_t buff[10]={1,2,2,3,4,4,5,3,3,2};
        EXPECT_EQ(31834,rte_raw_cksum((void*)buff, 4));

        timeval tv;
        tv.tv_usec =1;
        tv.tv_sec = 1;
        EXPECT_EQ(1000001, tv2us(&tv));
    }

    TEST(PcapExportGre, test) {
        LogFileContext ctx(false, "");
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        PcapExportGre greExport1(remoteips, 2, "eth0", IP_PMTUDISC_DONT, 100, ctx);
        PcapExportGre greExport2(remoteips, 2, "", IP_PMTUDISC_DONT, 0, ctx);
        EXPECT_EQ(0, greExport1.initExport());
        EXPECT_EQ(exporttype::gre,greExport1.getExportType());

        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, greExport1.exportPacket(&header, pkt_data.data(), 0));
        EXPECT_EQ(0, greExport1.closeExport());
    }

    TEST(PcapExportVxlan, test) {
        LogFileContext ctx(false, "");
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        PcapExportVxlan vxlanExport1(remoteips, 2, "eth0", IP_PMTUDISC_DONT, 4789,100,1, ctx);
        PcapExportVxlan vxlanExport2(remoteips, 12, "eth0", IP_PMTUDISC_DONT, 4789,100,2, ctx);
        EXPECT_EQ(0, vxlanExport1.initExport());
        
        EXPECT_EQ(exporttype::vxlan,vxlanExport1.getExportType());

        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, vxlanExport1.exportPacket(&header, pkt_data.data(), 1));
        EXPECT_EQ(0, vxlanExport1.closeExport());

        EXPECT_EQ(-1, vxlanExport2.exportPacket(&header, pkt_data.data(), 0));
        EXPECT_EQ(0, vxlanExport2.closeExport());
        PcapExportVxlan vxlanExport3(remoteips, 12, "eth0", IP_PMTUDISC_DONT, 4789,100,2, ctx);
        EXPECT_EQ(0, vxlanExport3.initExport());
        EXPECT_EQ(0, vxlanExport3.exportPacket(&header, pkt_data.data(), 0));
        EXPECT_EQ(0, vxlanExport3.closeExport());
    }

    TEST(PcapExportZMQ, test) {
        LogFileContext ctx(false, "");
        std::vector<std::string> remoteips;
        remoteips.push_back("127.0.1.1");
        PcapExportZMQ zmqExport(remoteips, 5566, 2, 12, "eth0", 10,100, ctx);
        
        EXPECT_EQ(0, zmqExport.initExport());
        EXPECT_EQ(exporttype::zmq,zmqExport.getExportType());

        pcap_pkthdr header;
        header.caplen = 32;
        header.len = 32;
        std::vector<uint8_t> pkt_data(32);
        EXPECT_EQ(0, zmqExport.exportPacket(&header, pkt_data.data(), 0));
        EXPECT_EQ(0,zmqExport.getForwardCnt());
        EXPECT_EQ(0,zmqExport.getForwardByte());
        EXPECT_EQ(0, zmqExport.closeExport());
    }

    TEST(AgentStatusQuery, test) {
        // AgentStatus::get_instance()->update_status(1586508861, header->caplen, 
        //                      _gre_count, _gre_drop_count, _pcap_handle);
        AgentStatus* inst = AgentStatus::get_instance();
        inst->reset_agent_status();
        inst->update_capture_status(1586508861, 200, 200, 1, 0, nullptr);
        inst->update_capture_status(1586508862, 200, 200, 1, 0, nullptr);
        inst->update_capture_status(1586508863, 100, 100, 1, 0, nullptr);
        EXPECT_EQ(1586508861, static_cast<uint32_t>(inst->first_packet_time()));
        EXPECT_EQ(1586508863, static_cast<uint32_t>(inst->last_packet_time()));
        EXPECT_EQ(100, static_cast<uint32_t>(inst->total_cap_bytes()));
    }

    TEST(AgentControlPlane, test) {
        LogFileContext ctx(false, "");
        AgentControlPlane zmq_server(ctx, 5556);
        sleep(1);
        msg_t req_msg;
        memset (&req_msg,0,sizeof(msg_t));
        EXPECT_EQ(-1, zmq_server.msg_req_check(&req_msg));
        req_msg.msglength = sizeof(req_msg);
        EXPECT_EQ(-1, zmq_server.msg_req_check(&req_msg));
        req_msg.magic = MSG_MAGIC_NUMBER;
        req_msg.action = MSG_ACTION_REQ_MAX;
        EXPECT_EQ(-1, zmq_server.msg_req_check(&req_msg));
        req_msg.action = MSG_ACTION_REQ_INVALID;
        EXPECT_EQ(0, zmq_server.msg_req_check(&req_msg));
        
        char tmp[sizeof(msg_t) + sizeof(msg_status_t)];
        msg_t *rep = (msg_t*)tmp;
        EXPECT_EQ(0, zmq_server.msg_rsp_process(&req_msg,rep));
    }

    TEST(GreSendStatisLog, test) {
        LogFileContext ctx(false, "");
        GreSendStatisLog statisLog(ctx, true);
        EXPECT_NO_THROW(statisLog.initSendLog("test"));
        EXPECT_NO_THROW(statisLog.logSendStatis(1,2,2,1,1));
        GreSendStatisLog statisLog1(ctx, false);
        EXPECT_NO_THROW(statisLog1.initSendLog("test"));
        EXPECT_NO_THROW(statisLog1.logSendStatis(123,2,2,1,1));
    }

    TEST(PcapHandler, test) {
      EXPECT_EQ(4290838664,makeMplsHdr(1,12));
      std::vector<std::string> ips;
      LogFileContext ctx(false, "");
      
      pcap_init_t pcapParam;
      pcapParam.snaplen = 2048;
      pcapParam.timeout = 3000;
      pcapParam.promisc = 0;
      pcapParam.buffer_size = 256*1024 * 1024;
      HandleParam param("/root/tmp/",16, 128,"eth0", "", pcapParam,  
                "", "host 10.1.1.1 and host nic.eth0", "", ctx);
      PcapHandler handler(param);
      EXPECT_EQ(128,handler.getPacketLen(256));
     
      EXPECT_EQ(0, handler.openPcap());
      EXPECT_EQ(0, handler.setMacAddr("eth0",""));
      EXPECT_NO_THROW(handler.setDirIPPorts("host 10.1.1.1 and host nic.eth0"));
      in_addr s;
      EXPECT_EQ(-1,handler.checkPktDirection(&s,&s,0,0));
    }

    TEST(LogFileContext,test) {
        LogFileContext ctx;
        ctx.setLogFileEnable(true);
        EXPECT_EQ(true,ctx.logFileEnable_);
        ctx.setLogFileHandlerId("abc");
        EXPECT_EQ("abc",ctx.handlerId_);
        std::string str= ctx.getTimeString();
        EXPECT_EQ(21,str.length());
    }

}
