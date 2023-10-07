
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
#include "../src/daemonManager.h"
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

    TEST(DaemonManager, test) {
        std::vector<std::string> commands;
        commands.push_back("--help");

        EXPECT_LT(0,exec(commands));
        // EXPECT_EQ(false,checkProcessRunning());
        EXPECT_EQ(0, (unsigned)checkProcessRunning());

        std::string cmd("agentdaemon -m https://172.16.206.21:8085/api/v1/daemons -l vir66 --platformId tencent -c keystore.p12 --password netis123 --deployEnv HOST --namespace HOST --podname PODNAME");
        std::vector<std::string> splits;
        boost::split(splits, cmd, boost::is_any_of(" "));
        std::vector<char *> args;
        for (size_t i = 0; i < splits.size(); i++) {
            args.push_back((char *) splits[i].data());
        }
        args.push_back(nullptr);
        char hostname[HOST_NAME_MAX + 1];
        ::gethostname(hostname, sizeof(hostname));
        boost::program_options::options_description desc("Allowed options");
        desc.add_options()
            ("port,p", boost::program_options::value<uint16_t>()->default_value(9022)->value_name("PORT"),
             "service port; PORT defaults 9022")
            ("host,s", boost::program_options::value<std::string>()->default_value("127.0.0.1")->value_name("HOST"),
             "service host")
            ("certificate,c", boost::program_options::value<std::string>()->default_value("")->value_name("CERT"),
             "server certificate path")
            ("query,q", boost::program_options::value<std::string>()->default_value("20000,20100")->value_name("AGENT_QUERY_PORT_RANGE"),
             "set agent status query request zmq port range.")
            ("key,k", boost::program_options::value<std::string>()->default_value("")->value_name("KEY"),
             "server key path")
            ("manager,m", boost::program_options::value<std::string>()->default_value("")->value_name("MANAGER"),
             "manager url")
            ("mode,d", boost::program_options::value<std::string>()->default_value("pull")->value_name("MODE"),
             "sync mode; pull|push, defaults pull")
            ("labels,l", boost::program_options::value<std::string>()->default_value("")->value_name("LABELS"),
             "service labels, split by ','")
            ("name,n", boost::program_options::value<std::string>()->default_value(hostname)->value_name("NAME"),
             "daemon name")
            ("platformId", boost::program_options::value<std::string>()->value_name("PLATFORMID"),
             "platform Id")
            ("password", boost::program_options::value<std::string>()->default_value("")->value_name("PASSWORD"),
             "password of ssl certificate")
	    ("podname", boost::program_options::value<std::string>()->value_name("PODNAME"),
             "podname of PA, used in sidecard mode")
             ("deployEnv", boost::program_options::value<std::string>()->value_name("DEPLOYENV"),
             "deployed env, its value can only be \"HOST\" or \"INSTANCE\"")

             ("namespace", boost::program_options::value<std::string>()->value_name("NAMESPACE"),
             "namespace of PA, usedin sidecard mode");

        boost::program_options::options_description all;
        all.add(desc);
        boost::program_options::variables_map vm;
        
        boost::program_options::parsed_options parsed = boost::program_options::command_line_parser(
                    (int) (args.size() - 1), &*args.begin())
                    .options(all).run();
        boost::program_options::store(parsed, vm);
        boost::program_options::notify(vm);

        timer_tasks_t* tasks = timer_tasks_new();
        LogFileContext ctx(false, "");
        DaemonManager daemonMgr(vm, tasks, ctx);
        std::shared_ptr<io::swagger::server::model::PacketAgentData> data = std::make_shared<io::swagger::server::model::PacketAgentData>();
        data->setInterfaceNames("ens33");
        data->setServiceTag(12);
        data->setBpf("host 10.1.1.12");
        data->setPacketChannelType("GRE");
        uint16_t port = 1268;
        uint64_t buffSize=256;
        std::string cmdStr=daemonMgr.createParams(data, port, buffSize);
        EXPECT_EQ(" --expression host 10.1.1.12 --control 1268 -b 256",cmdStr);
        std::unordered_set<std::string> intfaces = daemonMgr.readInterfaces(ctx);
        auto iter = intfaces.find("eth0");
        EXPECT_EQ(true, iter!=intfaces.end());
        daemonMgr.zmqPortAvlPop();
        EXPECT_EQ(0, daemonMgr.zmqPortAvlPop());
        EXPECT_NO_THROW(daemonMgr.zmqPortAvlPush(20000));
        EXPECT_NO_THROW(daemonMgr.updateAgents());
    }

    TEST(Timer,test) {
        timer_tasks_t* tasks = timer_tasks_new();
        EXPECT_NE(nullptr, tasks);
      	
        uint64_t tid = timer_tasks_push(tasks, (task_cb_t)printf, (void*)"test", 1);
        EXPECT_EQ(0, tid);
        timer_tasks_cancel(tasks,tid);
        timer_tasks_stop(tasks);
        timer_tasks_term(tasks);
    }

    TEST(Report, test) {
        io::swagger::server::model::Report report;

        report.setPid(111);
        EXPECT_EQ(true, report.pidIsSet());


        std::shared_ptr<io::swagger::server::model::PacketAgentMetrics> metrics(new io::swagger::server::model::PacketAgentMetrics());
        struct timeval val;
        val.tv_sec = 1;
        val.tv_usec = 2;
        metrics->setSamplingTime(val);
        metrics->setSamplingTimestamp(23456);
        metrics->setSamplingMicroTimestamp(12345);
        EXPECT_EQ(true,metrics->samplingTimeIsSet());
        metrics->setCpuLoad(0.22);
        EXPECT_EQ(0.22,metrics->getCpuLoad());
        EXPECT_EQ(true,metrics->cpuLoadIsSet());

        metrics->setCpuLoadRate(0.22);
        EXPECT_EQ(0.22,metrics->getCpuLoadRate());
        EXPECT_EQ(true,metrics->cpuLoadRateIsSet());

        metrics->setMemUse(22);
        EXPECT_EQ(22,metrics->getMemUse());
        EXPECT_EQ(true,metrics->memUseIsSet());

        metrics->setMemUseRate(0.22);
        EXPECT_EQ(0.22,metrics->getMemUseRate());
        EXPECT_EQ(true,metrics->memUseRateIsSet());

        metrics->setCapBytes(2200);
        EXPECT_EQ(2200,metrics->getCapBytes());
        EXPECT_EQ(true,metrics->capBytesIsSet());

        metrics->setCapPackets(2200);
        EXPECT_EQ(2200,metrics->getCapPackets());
        EXPECT_EQ(true,metrics->capPacketsIsSet());

        metrics->setCapDrop(2200);
        EXPECT_EQ(2200,metrics->getCapDrop());
        EXPECT_EQ(true,metrics->capDropIsSet());

        metrics->setFwdBytes(2200);
        EXPECT_EQ(2200,metrics->getFwdBytes());
        EXPECT_EQ(true,metrics->fwdBytesIsSet());

        metrics->setFwdPackets(2200);
        EXPECT_EQ(2200,metrics->getFwdPackets());
        EXPECT_EQ(true,metrics->fwdPacketsIsSet());

        report.setPacketAgentMetrics(metrics);
        report.getPacketAgentMetrics();
        EXPECT_EQ(true,report.packetAgentMetricsIsSet());

        report.addPacketAgentLogs("DEBUG", "It is just for test");
        EXPECT_EQ(true,report.packetAgentLogsIsSet());

        nlohmann::json jsonStr = report.toJson();

        report.fromJson(jsonStr);

        metrics->unsetSamplingTime();
        metrics->unsetCpuLoad();
        metrics->unsetCpuLoadRate();
        metrics->unsetMemUse();
        metrics->unsetMemUseRate();
        metrics->unsetCapBytes();
        metrics->unsetCapPackets();
        metrics->unsetCapDrop();
        metrics->unsetFwdBytes();
        metrics->unsetFwdPackets();

        report.unsetPacketAgentMetrics();
        report.unsetPacketAgentLogs();
        report.unsetPid();
    }

    TEST(Agent, test) {
       io::swagger::server::model::Agent agent;
       agent.setCpuLimit(0.22);
       EXPECT_EQ(0.22, agent.getCpuLimit());
       EXPECT_EQ(true,agent.cpuLimitIsSet());
       
       agent.setMemLimit(220);
       EXPECT_EQ(220, agent.getMemLimit());
       EXPECT_EQ(true,agent.memLimitIsSet());

       agent.setId(220);
       EXPECT_EQ(220, agent.getId());
       EXPECT_EQ(true,agent.idIsSet());

       agent.setPid(220);
       EXPECT_EQ(220, agent.m_Pid);
       EXPECT_EQ(true,agent.pidIsSet());

       agent.setName("test");
       EXPECT_EQ("test", agent.getName());
       EXPECT_EQ(true,agent.nameIsSet());
       agent.setStatus("active");
       EXPECT_EQ("active", agent.getStatus());
       EXPECT_EQ(true,agent.statusIsSet());
       
       struct timeval val;
       agent.setStartTime(val);
       EXPECT_NO_THROW(agent.getStartTime());
       EXPECT_EQ(true,agent.startTimeIsSet());

       agent.setStartTimestamp(12345);

       agent.setStartMicroTimestamp(12345);

       EXPECT_EQ(0, (unsigned)agent.packetAgentStrategiesIsSet());

       agent.setVersion(1);
       EXPECT_EQ(1, agent.m_Version);
       EXPECT_EQ(true,agent.versionIsSet());

       nlohmann::json valj = agent.toJson();
       agent.fromJson(valj);
       agent.unsetCpuLimit();
       agent.unsetMemLimit();
       agent.unsetId();
       agent.unsetPid();
       agent.unsetName();
       agent.unsetStatus();
       agent.unsetStartTime();   
       agent.unsetPacketAgentStrategies();
       agent.unsetVersion();
    }

    TEST(PacketAgentData, test) {
       std::shared_ptr<io::swagger::server::model::PacketAgentData> strategy(new io::swagger::server::model::PacketAgentData());

       strategy->setInterfaceNames("eth0");
       std::vector<std::string> strs =strategy->getInterfaceNames();
       EXPECT_EQ("eth0", strs[0]);
       EXPECT_EQ(true,strategy->interfaceNamesIsSet());

       strategy->setInstanceNames("test");
       std::vector<std::string> strs2 =strategy->getInstanceNames();
       EXPECT_EQ("test", strs2[0]);
       EXPECT_EQ(true,strategy->instanceNamesIsSet());

       strategy->setContainerIds("1j2e41opjlksjef");
       strs =strategy->getContainerIds();
       EXPECT_EQ("1j2e41opjlksjef", strs[0]);
       EXPECT_EQ(true,strategy->containerIdsIsSet());

       strategy->setBpf("test");
       EXPECT_EQ("test", strategy->getBpf());
       EXPECT_EQ(true,strategy->containerIdsIsSet());

       strategy->setSliceLen(256);
       EXPECT_EQ(256, strategy->getSliceLen());
       EXPECT_EQ(true,strategy->sliceLenIsSet());

       strategy->setPacketChannelType("gre");
       EXPECT_EQ("gre", strategy->getPacketChannelType());
       EXPECT_EQ(true,strategy->packetChannelTypeIsSet());

       strategy->setPacketChannelKey(12);
       EXPECT_EQ(12, strategy->getPacketChannelKey());
       EXPECT_EQ(true,strategy->packetChannelKeyIsSet());
       
       strategy->setAddress("10.1.2.123");
       EXPECT_EQ("10.1.2.123", strategy->getAddress());
       EXPECT_EQ(true,strategy->addressIsSet());

       strategy->setPort(100);
       EXPECT_EQ(100, strategy->getPort());
       EXPECT_EQ(true,strategy->portIsSet());
       
       strategy->setDumpInterval(10);
       EXPECT_EQ(10, strategy->getDumpInterval());
       EXPECT_EQ(true,strategy->dumpIntervalIsSet());

       strategy->setServiceTag(10);
       EXPECT_EQ(10, strategy->getServiceTag());
       EXPECT_EQ(true,strategy->serviceTagIsSet());

       strategy->setHasServiceTag(true);
       EXPECT_EQ(true, strategy->getHasServiceTag());
       EXPECT_EQ(true,strategy->hasServiceTagIsSet());

       strategy->setReqPattern("host 10.1.2.123");
       EXPECT_EQ("host 10.1.2.123", strategy->getReqPattern());
       EXPECT_EQ(true,strategy->reqPatternIsSet());

       strategy->setStartup("-t 0");
       EXPECT_EQ("-t 0", strategy->getStartup());
       EXPECT_EQ(true,strategy->startupIsSet());

       strategy->setDumpDir("/root/tmp");
       EXPECT_EQ("/root/tmp", strategy->getDumpDir());
       EXPECT_EQ(true,strategy->dumpDirIsSet());

       strategy->setBuffLimit(100);
       EXPECT_EQ(100, strategy->getBuffLimit());
       EXPECT_EQ(true,strategy->buffLimitIsSet());

       strategy->setForwardRateLimit(100);
       EXPECT_EQ(100, strategy->getForwardRateLimit());
       EXPECT_EQ(true,strategy->forwardRateLimitIsSet());

       strategy->setApiVersion("0.1");
       EXPECT_EQ("0.1", strategy->getApiVersion());
       EXPECT_EQ(true,strategy->apiVersionIsSet());

       strategy->setObservationDomainId(1);
       std::vector<uint32_t> vals=strategy->getObservationDomainIds();
       EXPECT_EQ(1, vals[0]);
       EXPECT_EQ(true,strategy->observationDomainIdsIsSet());

       strategy->setExtensionFlag(1);
       EXPECT_EQ(1, strategy->getExtensionFlag());
       EXPECT_EQ(true,strategy->extensionFlagIsSet());

       strategy->setObservationPointId(1);
       std::vector<uint8_t> values=strategy->getObservationPointIds();
       EXPECT_EQ(1, values[0]);
       EXPECT_EQ(true,strategy->observationPointIdsIsSet());

       nlohmann::json valj = strategy->toJson();
       strategy->fromJson(valj);
       
       strategy->unsetInterfaceNames();
       strategy->unsetInstanceNames();
       strategy->unsetContainerIds();
       strategy->unsetServiceTag();
       strategy->unsetHasServiceTag();
       strategy->unsetBpf();
       strategy->unsetSliceLen();
       strategy->unsetPacketChannelType();
       strategy->unsetAddress();
       strategy->unsetPort();
       strategy->unsetDumpDir();
       strategy->unsetDumpInterval();
       strategy->unsetBuffLimit();
       strategy->unsetForwardRateLimit();
       strategy->unsetApiVersion();
       strategy->unsetObservationDomainIds();
       strategy->unsetExtensionFlag();
       strategy->unsetObservationPointIds();
       strategy->unsetReqPattern();
       strategy->unsetStartup();

    }

    TEST(Daemon, test) {
        io::swagger::server::model::Daemon daemon;
        daemon.setId(1);
        EXPECT_EQ(1,daemon.getId());
        EXPECT_EQ(true,daemon.idIsSet());

        daemon.setName("test");
        EXPECT_EQ("test",daemon.getName());
        EXPECT_EQ(true,daemon.nameIsSet());

        daemon.setDeployEnv("test");
        EXPECT_EQ("test",daemon.getDeployEnv());
        EXPECT_EQ(true,daemon.deployEnvIsSet());

        daemon.setNamespace("test");
        EXPECT_EQ("test",daemon.getNamespace());
        EXPECT_EQ(true,daemon.namespaceIsSet());

        daemon.setPodName("test");
        EXPECT_EQ("test",daemon.getPodName());
        EXPECT_EQ(true,daemon.podNameIsSet());

        daemon.setPlatformId("test");
        EXPECT_EQ("test",daemon.getPodName());
        EXPECT_EQ(true,daemon.podNameIsSet());

        daemon.setClientVersion("0.1");
        EXPECT_EQ("0.1",daemon.getClientVersion());
        EXPECT_EQ(true,daemon.clientVersionIsSet()); 

        daemon.setNodeName("test");
        EXPECT_EQ("test",daemon.getNodeName());
        EXPECT_EQ(true,daemon.nodeNameIsSet());

        daemon.setUuid("abcd");
        EXPECT_EQ("abcd",daemon.getUuid());
        EXPECT_EQ(true,daemon.uuidIsSet());

        daemon.setService("abcd");
        EXPECT_EQ("abcd",daemon.getService());
        EXPECT_EQ(true,daemon.serviceIsSet());

        daemon.setRegisterRequestIpAddress("10.1.1.1");
        EXPECT_EQ("10.1.1.1",daemon.getRegisterRequestIpAddress());
        EXPECT_EQ(true,daemon.registerRequestIpAddressIsSet());

        daemon.setApiVersion("0.1");
        EXPECT_EQ("0.1",daemon.getApiVersion());
        EXPECT_EQ(true,daemon.apiVersionIsSet()); 

        daemon.setStatus("active");
        EXPECT_EQ("active",daemon.getStatus());
        EXPECT_EQ(true,daemon.statusIsSet()); 

        struct timeval val;
        daemon.setStartTime(val);
        EXPECT_NO_THROW(daemon.getStartTime());
        EXPECT_EQ(true,daemon.startTimeIsSet());

        daemon.setStartTimestamp(1234);
        daemon.setStartMicroTimestamp(1234);

        std::shared_ptr<io::swagger::server::model::Label> label(new io::swagger::server::model::Label);
        label->setValue("test");
        EXPECT_EQ("test",label->getValue());
        EXPECT_EQ(true,label->valueIsSet()); 

        std::vector<std::shared_ptr<io::swagger::server::model::NetworkInterface>> interfs;
        EXPECT_NO_THROW(interfs = daemon.getNetworkInterfaces());

        nlohmann::json jVal=daemon.toJson();
        daemon.fromJson(jVal);

        label->unsetValue();

        daemon.unsetId();
        daemon.unsetName();
        daemon.unsetNamespace();
        daemon.unsetDeployEnv();
        daemon.unsetPodName();
        daemon.unsetPlatformId();
        daemon.unsetClientVersion();
        daemon.unsetNodeName();
        daemon.unsetUuid();
        daemon.unsetRegisterRequestIpAddress();
        daemon.unsetService();
        daemon.unsetApiVersion();
        daemon.unsetStatus();
        daemon.unsetStartTime();
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
