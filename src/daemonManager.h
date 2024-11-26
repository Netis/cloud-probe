//
// Created by root on 12/30/20.
//

#ifndef PKTMINERG_DAEMONMANAGER_H
#define PKTMINERG_DAEMONMANAGER_H

#include <unordered_set>
#include <mutex>
#include <fstream>
#include <chrono>
#include <thread>

#include <unistd.h>
#include <signal.h>
#include <sys/wait.h>
#include <curl/curl.h>
#include <unistd.h>
#include <cerrno> 
#include "zmq.hpp"

#include <boost/algorithm/string.hpp>
#include <boost/date_time.hpp>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/format.hpp>
#include <boost/program_options/variables_map.hpp>
#include <boost/date_time/posix_time/posix_time.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/filesystem.hpp>

#include "glog/logging.h"
#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/SimpleLayout.hh"
#include "log4cpp/PropertyConfigurator.hh"
#include "restful/model/Daemon.h"
#include "restful/model/Report.h"
#include "restful/model/Agent.h"
#include "restful/model/Error.h"
#include "restful/model/PacketAgentData.h"
#include "restful/model/PacketChannelMetrics.h"

#include "agent_control_itf.h"
#include "timer_tasks.h"
#include "logfilecontext.h"


#define API_VERSION "v1"
#define SUPPORT_API_VERSIONS "v1"

enum class DaemonSynMode
{
    DEFAULT,
    PUSH,
    PULL
};

typedef struct {  
    uint32_t resourcePointDirection:2;
    uint32_t observationPointId:5; 
    uint32_t extensionFlag:1;
    uint32_t observationDomainId:24;
} Vni2;

pid_t exec(std::vector<std::string> & commands);
bool checkProcessRunning ( );
void getActiveInstanceNames(std::set<std::string> & names);

class DaemonManager
{
public:
    DaemonManager(const boost::program_options::variables_map& vm, timer_tasks_t* tasks, LogFileContext& ctx);

    ~DaemonManager();
    
private:
    static void scanNetworkInterface(void* user);

    void scanNetworkInterfaceImpl();

    static void getDaemon(void* user);

    void getDaemonImpl();

    static std::unordered_set<std::string> readInterfaces(LogFileContext& ctx);

    int daemonReg();

    static int getCurlRespError(const std::string& body, int& code, std::string& message);

    static size_t curlWriteFunction(char *ptr, size_t size, size_t nmemb, void *userdata);

    bool updateAgentStatusSync();

    int updateChannelStatusSync();

    int updateChannelCpuLoadSync();

    int updateChannleMemUse();

    void updateAgents();

    bool delAgent();

    void clearAgent();

    void sendPostToMgr (std::stringstream &msg);

    int startPA(io::swagger::server::model::Agent& body, std::stringstream &result);

    void initZmqPortAvl();

    uint16_t zmqPortAvlPop();

    void zmqPortAvlPush(uint16_t port);

    void startPullMode(bool startGetDaemon);

    std::string getChannelArg(std::shared_ptr<io::swagger::server::model::PacketAgentData> data, unsigned int id);

    std::string createParams(std::shared_ptr<io::swagger::server::model::PacketAgentData>, uint16_t port, uint64_t buffSize);

    void killRunningPktg();

    void clearCgroupfolder(pid_t pid);

private:
    const boost::program_options::variables_map& vm_;
    std::unordered_set<std::string> interfaces_;
    timer_tasks_t* tasks_;
    uint32_t getDaemonPeroidUs_;
    uint32_t scanNetworkInterfacePeroidUs_;
    uint64_t getDaemonTid_;
    io::swagger::server::model::Daemon daemon_;
    io::swagger::server::model::Report report_;
    io::swagger::server::model::Agent agent_;
    uint64_t capBuff_ = 0;
    pid_t agentPid_ = 0;
    uint16_t zmqPort_;
    const uint32_t ZMQ_TIMEOUT_ = 1000; // millisecond unit
    const long CURL_TIMEOUT_ = 5l; //second unit
    std::recursive_mutex mtx_;
    int32_t lastAgentId_ = -1;
    std::pair<uint16_t, uint16_t> zmqPortRange_;
    std::vector<std::pair<uint16_t, bool>> zmqPortAvl_;
    std::vector<std::map<std::string, bool>> instanceStatus_;
    bool instanceCheck_ = false;
    std::string paUUID_ = "";
    std::string output_buffer;
    LogFileContext ctx_;
};
#endif //PKTMINERG_DAEMONMANAGER_H
