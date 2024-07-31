//
// Created by root on 12/30/20.
//
#include <fstream>
#include "daemonManager.h"
#include "dep.h"

pid_t exec(std::vector<std::string> & commands) {
    pid_t pid = fork();
    if (pid == -1) {
        return -1;
    }
    if (pid > 0) {
        return pid;
    }

    std::vector<char*> vstr;
    for(auto& m : commands)
        vstr.push_back((char*)m.data());
    vstr.push_back(NULL);

    ::execvp("pktminerg", &*vstr.begin());
    //::execl("/bin/sh", "sh", "-c", command, NULL);
    //::execlp("pktminerg", "pktminerg", command, NULL);
    exit(0);
}

bool checkProcessRunning ( ) {
    FILE* fp;
    char buffer[2] = {0};
    pid_t ppid = getpid();
    const auto cmd = boost::str(
            boost::format("ps -ef|grep pktminerg|grep %1%|grep -v grep |wc -l") %ppid);
    fp=popen(cmd.c_str(),"r");
    fgets(buffer,sizeof(buffer),fp);
    pclose(fp);

    if (buffer [0] != '0') {
        return true;
    }
    return false;
}

void DaemonManager::killRunningPktg() {
    FILE * fp;
    char buffer[10]={0};
    pid_t ppid = getpid();
    const auto cmd = boost::str(
    boost::format("ps -ef|grep pktminerg|grep %1%|grep -v grep |awk '{print $2}'") %ppid);
    fp=popen(cmd.c_str(),"r");
        while (fgets(buffer,sizeof(buffer),fp)) {
            pid_t pid = atoi(buffer);
            auto strInfo = boost::str(boost::format("kill running pid=%1%")% pid);
                ctx_.log(strInfo, log4cpp::Priority::INFO);
                LOG(INFO) << strInfo;
            std::cout<<"kill running pktg pid="<<pid<<" agentPid="<<agentPid_<<std::endl; 
            if (kill(pid, SIGTERM) == -1) {
                auto strErr = boost::str(boost::format("kill pid=%1% failed, error=%2%")
                                     % pid % errno);
                ctx_.log(strErr, log4cpp::Priority::ERROR);
                LOG(ERROR) << strErr;
                report_.addPacketAgentLogs("ERROR", strErr);
            }
            if (waitpid(pid, NULL, 0) == -1) {
                auto strErr = boost::str(boost::format("wait pid=%1% failed, error=%2%")
                                 % pid % errno);
                ctx_.log(strErr, log4cpp::Priority::ERROR);
                LOG(ERROR) << strErr;
                    report_.addPacketAgentLogs("ERROR", strErr);
            }
            clearCgroupfolder(pid);
            clearCgroupfolder(agentPid_);
            agentPid_ = 0;
        }
}

void getActiveInstanceNames(std::set<std::string> & names) {
    FILE *fp;
    char buffer[256];
    fp=popen("sh get_name_of_instance.sh","r");
    while(!feof(fp)){
        fgets(buffer,sizeof(buffer),fp);
        std::string str(buffer, strlen(buffer)-1);
        names.insert(str);
    }
    pclose(fp);
    return;
}

void DaemonManager::clearCgroupfolder(pid_t pid) {
    std::string path1("/cgroup/");
    std::string path2("/sys/fs/cgroup/");
    
    std::vector<std::string> pathToRemove;

    pathToRemove.push_back(path1+"cpu/pid-"+std::to_string(pid));
    pathToRemove.push_back(path2+"cpu/pid-"+std::to_string(pid));
    pathToRemove.push_back(path1+"memory/pid-"+std::to_string(pid));
    pathToRemove.push_back(path2+"memory/pid-"+std::to_string(pid));
    
    for(auto pStr:pathToRemove) {
        boost::filesystem::path p(pStr);
        if (boost::filesystem::exists(p)) {
            if (rmdir(pStr.c_str()) == -1) {
                output_buffer = boost::str(boost::format("Fail to remove path:%1%,%2% ")%pStr%strerror(errno));
                ctx_.log(output_buffer, log4cpp::Priority::ERROR);
                LOG(ERROR) << output_buffer;
            } else {
                output_buffer = boost::str(boost::format("Successfully remove path:%1%")%pStr);
                ctx_.log(output_buffer, log4cpp::Priority::INFO);
                LOG(INFO) << output_buffer;

            }
        }
    }
    return;
}  

void DaemonManager::getDaemonImpl() {
    std::lock_guard<std::recursive_mutex> lock{mtx_};
    std::shared_ptr<CURL> curl(::curl_easy_init(), [](CURL *curl) {
        ::curl_easy_cleanup(curl);
    });

    if (curl == nullptr) {
        ctx_.log("curl init failed", log4cpp::Priority::ERROR);
        LOG(ERROR) << "curl init failed";
        return;
    }
    std::string url;
    CURLcode res;
    long statusCode;
    std::string body;
    std::stringstream jsonStream;
    if (checkProcessRunning()) {
        updateAgents();
    }
    else {
        clearAgent();
    }

    jsonStream << daemon_.toJson();
    
    const auto json = jsonStream.str();

    if (report_.packetAgentLogsIsSet()) {
        report_.unsetPacketAgentLogs();
    }
    int32_t version = 0;
    if (agent_.versionIsSet()) {
        version = agent_.getVersion();
    }
    
    url = boost::str(boost::format("%1%/%2%/sync/strategy?version=%3%") % vm_["manager"].as<std::string>() %daemon_.getId() %version);
    
    ::curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    ::curl_easy_setopt(curl.get(), CURLOPT_CUSTOMREQUEST, "GET");
    ::curl_easy_setopt(curl.get(), CURLOPT_FOLLOWLOCATION, 1L);
    ::curl_easy_setopt(curl.get(), CURLOPT_DEFAULT_PROTOCOL, "https");
    struct curl_slist *headers = NULL;
    ::curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, headers);

    if (!vm_["certificate"].as<std::string>().empty()) {
        ::curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, false);
        ::curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, false);

        ::curl_easy_setopt(curl.get(), CURLOPT_SSLCERTTYPE, "P12");
        ::curl_easy_setopt(curl.get(), CURLOPT_SSLKEYPASSWD, vm_["password"].as<std::string>().c_str());
        ::curl_easy_setopt(curl.get(), CURLOPT_SSLCERT, vm_["certificate"].as<std::string>().c_str());
    }

    std::shared_ptr<CURL> list(curl_slist_append(nullptr, "Content-Type: application/json"), [](curl_slist* slist) { ::curl_slist_free_all(slist); });
    ::curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, list.get());
    ::curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, CURL_TIMEOUT_);
    //::curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, json.c_str());
    body.resize(40960);
    body.resize(0);
    ::curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &body);
    ::curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, curlWriteFunction);

    if((res = curl_easy_perform(curl.get())) != CURLE_OK)
    {
        output_buffer = boost::str(boost::format("curl_easy_perform(POST %1%) failed: %2%")
            % url % curl_easy_strerror(res));
        ctx_.log(output_buffer, log4cpp::Priority::ERROR);
        LOG(ERROR) << output_buffer;
        return;
    }
  
    ::curl_easy_getinfo(curl.get(), CURLINFO_RESPONSE_CODE, &statusCode);
    
    if (statusCode == 200) {
        nlohmann::json js = nlohmann::json::parse(body);
        agent_.fromJson(js);
        std::string str = boost::str(boost::format("curl_easy_perform(GET %1%) ok: sc=%2%")
                                % url % statusCode);

        ctx_.log(str, log4cpp::Priority::INFO);
        LOG(INFO) << str;

        report_.addPacketAgentLogs("INFO", str);

        std::stringstream result;

        if (agentPid_ != 0) {
            delAgent();
        }
        int numOfStrategies = agent_.getPacketAgentStrategies().size();
        instanceStatus_.clear();
        instanceStatus_.resize(numOfStrategies);

        startPA(agent_, result);

        if(agent_.SyncIntervalIsSet() && agent_.getSyncInterval() > 0) {
            int periodUs = agent_.getSyncInterval() * TICK_US_SEC;
            timer_tasks_cancel(tasks_, getDaemonTid_);
            getDaemonTid_ = timer_tasks_push(tasks_, getDaemon, this, periodUs);
        }
    } else if(statusCode == 304) {
        std::string str = boost::str(boost::format("curl_easy_perform(GET %1%) ok: sc=%2%")
                                 % url % statusCode);
        ctx_.log(str, log4cpp::Priority::INFO);
        LOG(INFO) << str;

        report_.addPacketAgentLogs("INFO", str);


        if ((agentPid_!= 0 && !checkProcessRunning ()) || instanceCheck_) {

            if (agentPid_!= 0 && !checkProcessRunning ())  {
                std::string str = boost::str(boost::format("Pktminerg is not running, restart it."));
                ctx_.log(str, log4cpp::Priority::ERROR);
                LOG(ERROR) << str;
                report_.addPacketAgentLogs("ERROR", str);
                clearCgroupfolder(agentPid_);
                zmqPortAvlPush(zmqPort_);
            }

            std::stringstream result;           
            startPA(agent_, result);
        }
        if (agentPid_ != 0)
            report_.setPid(agentPid_);

        if (agentPid_ != 0 && agent_.startTimeIsSet() && report_.getPacketAgentMetrics()) {
            report_.getPacketAgentMetrics()->setStartTime(agent_.getStartTime());
        }
        std::stringstream jsonS;
        jsonS << report_.toJson();
        const auto json = jsonS.str();

        if (report_.packetAgentLogsIsSet()) {
            report_.unsetPacketAgentLogs();
        }

        std::shared_ptr<CURL> curlR(::curl_easy_init(), [](CURL *curl) {
            ::curl_easy_cleanup(curl);
        });

        if (curlR == nullptr) {
            ctx_.log("curl init failed", log4cpp::Priority::ERROR);
            LOG(ERROR) << "curl init failed";
            return;
        }

        url = boost::str(boost::format("%1%/%2%/sync/metrics") % vm_["manager"].as<std::string>()%daemon_.getId());

        ::curl_easy_setopt(curlR.get(), CURLOPT_URL, url.c_str());
        if (!vm_["certificate"].as<std::string>().empty()) {
            ::curl_easy_setopt(curlR.get(), CURLOPT_SSL_VERIFYPEER, false);
            ::curl_easy_setopt(curlR.get(), CURLOPT_SSL_VERIFYHOST, false);

            ::curl_easy_setopt(curlR.get(), CURLOPT_SSLCERTTYPE, "P12");
            ::curl_easy_setopt(curlR.get(), CURLOPT_SSLKEYPASSWD, vm_["password"].as<std::string>().c_str());
            ::curl_easy_setopt(curlR.get(), CURLOPT_SSLCERT, vm_["certificate"].as<std::string>().c_str());
        }
        std::shared_ptr<CURL> list(curl_slist_append(nullptr, "Content-Type: application/json"), [](curl_slist* slist) { ::curl_slist_free_all(slist); });
        ::curl_easy_setopt(curlR.get(), CURLOPT_HTTPHEADER, list.get());
        ::curl_easy_setopt(curlR.get(), CURLOPT_TIMEOUT, CURL_TIMEOUT_);
        ::curl_easy_setopt(curlR.get(), CURLOPT_POSTFIELDS, json.c_str());

        body.resize(40960);
        body.resize(0);
        ::curl_easy_setopt(curlR.get(), CURLOPT_WRITEDATA, &body);
        ::curl_easy_setopt(curlR.get(), CURLOPT_WRITEFUNCTION, curlWriteFunction);
        curl_easy_perform(curlR.get());

    }else { //404 or default
        std::string str = boost::str(boost::format("curl_easy_perform(POST %1%) failed: sc=%2% body=%3%, do re-reg!")
            % url % statusCode % body);
        ctx_.log(str, log4cpp::Priority::ERROR);
        LOG(ERROR) << str;

        report_.addPacketAgentLogs("ERROR", str);
        if (agentPid_ != 0) {
            if (kill(agentPid_, SIGTERM) == -1) {
                auto strErr = boost::str(boost::format("kill pid=%1% failed, error=%2%")
                                 % agentPid_ % errno);
                ctx_.log(strErr, log4cpp::Priority::ERROR);
                LOG(ERROR) << strErr;
                report_.addPacketAgentLogs("ERROR", strErr);
            }
            if (waitpid(agentPid_, NULL, 0) == -1) {
                auto strErr = boost::str(boost::format("wait pid=%1% failed, error=%2%")
                                 % agentPid_ % errno);
                ctx_.log(strErr, log4cpp::Priority::ERROR);
                LOG(ERROR) << strErr;
                report_.addPacketAgentLogs("ERROR", strErr);
            }
            agentPid_ = 0;
        }
        timer_tasks_cancel(tasks_, getDaemonTid_);
        char *nodeName = getenv("HOSTNAME");
        if(nodeName != nullptr) {
            daemon_.setNodeName(nodeName);
        }
        
        struct timeval tv;
        gettimeofday(&tv,NULL);
        daemon_.setStartTime(tv);
        
        interfaces_.clear();
    }
    return;
}

void DaemonManager::sendPostToMgr (std::stringstream& msg) {
    std::shared_ptr<CURL> curl(::curl_easy_init(), [](CURL* curl) {
            ::curl_easy_cleanup(curl);
        });

        if (curl == nullptr) {
            ctx_.log("curl init failed", log4cpp::Priority::ERROR);
            LOG(ERROR) << "curl init failed";
            return;
        }
        ::curl_easy_setopt(curl.get(), CURLOPT_URL, (vm_["manager"].as<std::string>()+'/'+ std::to_string(daemon_.getId())+"/report").c_str());
        if (!vm_["certificate"].as<std::string>().empty()) {
            ::curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, false);
            ::curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, false);

            ::curl_easy_setopt(curl.get(), CURLOPT_SSLCERTTYPE, "P12");
            ::curl_easy_setopt(curl.get(), CURLOPT_SSLKEYPASSWD, vm_["password"].as<std::string>().c_str());
            ::curl_easy_setopt(curl.get(), CURLOPT_SSLCERT, vm_["certificate"].as<std::string>().c_str());
        }
        ctx_.log(msg.str(), log4cpp::Priority::INFO);
        LOG(INFO) << msg.str() << std::endl;

        std::shared_ptr<struct curl_slist> list (::curl_slist_append(nullptr, "accept: application/json"),[](curl_slist* slist) {
            ::curl_slist_free_all(slist);
        });

        list.reset(curl_slist_append(list.get(), "Content-Type: application/json"));
        ::curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, list.get());
        ::curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, ("{\"code\":" + std::to_string(daemon_.getId())+"\"message\":\""+msg.str()+"\"}").c_str());
        if (const auto rc = ::curl_easy_perform(curl.get()) != CURLE_OK) {
            output_buffer = boost::str(boost::format("curl perform failed, return code=%1%") % rc);
            ctx_.log(output_buffer, log4cpp::Priority::INFO);
            LOG(ERROR) << output_buffer;
        }
    return;
}

std::string DaemonManager::getChannelArg(std::shared_ptr<io::swagger::server::model::PacketAgentData> data, unsigned int id) {
    std::string channel_args;

        if(data->getPacketChannelType() == "GRE") {
            uint32_t serviceTag;
            if (data->getHasServiceTag()) {
                serviceTag = data->getServiceTag();
            } else {
                serviceTag = 0xffffffff;
            }
            channel_args = boost::str(boost::format(" -k %1%")
                                      %serviceTag);
        }
        else if(data->getPacketChannelType() == "ZMQ") {
            uint32_t serviceTag;
            if (data->getHasServiceTag()) {
                serviceTag = data->getServiceTag();
            } else {
                serviceTag = 0xffffffff;
            }
            channel_args = boost::str(boost::format(" -k %1% -z %2%")
                                      %serviceTag
                                      %data->getPort());

        } else if(data->getPacketChannelType() == "VXLAN") {
            uint32_t serviceTag;
            if(!data->apiVersionIsSet() || data->getApiVersion() == "v1") {
                if (data->getHasServiceTag()) {
                serviceTag = data->getServiceTag();
                /*if (daemon_.registerRequestIpAddressIsSet()) {
                    std::string addr = daemon_.getRegisterRequestIpAddress();
                    std::vector<std::string> vecSegTag;
	                boost::split(vecSegTag,addr,boost::is_any_of("."));
                    if (vecSegTag.size() == 4) {
                        serviceTag += stol(vecSegTag[2]+vecSegTag[3]);
                    }
                }*/
                } else {
                    serviceTag = 0xffffff;
                }
                channel_args = boost::str(boost::format(" --vni1 %1% -x %2%")
                                      %serviceTag
                                      %data->getPort());
            } else {                
                Vni2 tag;
                tag.observationDomainId = data->observationDomainIdsIsSet()&&data->getObservationDomainIds().size()>id?data->getObservationDomainIds()[id]:1;
                tag.extensionFlag = data->extensionFlagIsSet()?data->getExtensionFlag():0; 
                tag.observationPointId = data->observationPointIdsIsSet()&&data->getObservationPointIds().size()>id?data->getObservationPointIds()[id]:1;
                tag.resourcePointDirection = 0;
                memcpy(&serviceTag, &tag, sizeof(serviceTag));
                channel_args = boost::str(boost::format(" --vni2 %1% -x %2%")
                                      %serviceTag
                                      %data->getPort());
            }
        } else if(data->getPacketChannelType() == "FILE") {
            if (data->dumpDirIsSet()) {
                channel_args = std::string(" --dump ") + data->getDumpDir() + std::string(" --interval ") + std::to_string(data->getDumpInterval());
                uint32_t serviceTag;
                if (data->getHasServiceTag()) {
                    serviceTag = data->getServiceTag();
                } else {
                    serviceTag = 0xffffffff;
                }
                channel_args += boost::str(boost::format(" -k %1%")
                                           %serviceTag);
            }

        }
        return channel_args;
}

std::string DaemonManager::createParams(std::shared_ptr<io::swagger::server::model::PacketAgentData> data, uint16_t port, uint64_t buffSize) {
    std::string dir = "";
    if (data->reqPatternTypeIsSet()) {
        if(data->getReqPatternType() == "AUTO") {
            dir = "auto";
        } else if (data->getReqPatternType() == "CUSTOM") {
            if (data->reqPatternIsSet()) {
                dir = data->getReqPattern();
                std::replace(dir.begin(),dir.end(),' ', '_');
            }
        }
    }
    
    return boost::str(boost::format("%1%%2% --control %3%%4%%5%%6%%7%%8%")
                        % (data->addressIsSet()
                           ? std::string(" -r ") + data->getAddress() : std::string())
                        % (data->getBpf().empty()
                           ? std::string() : std::string(" --expression ") + data->getBpf())
                        % (port)
                        % (boost::format(" -b %1%") % buffSize)
                        % (data->sliceLenIsSet()
                           ? std::string(" --slice ") + std::to_string(data->getSliceLen()) : std::string())
                        % (data->startupIsSet() ? boost::str(
                                boost::format(" %1%") % data->getStartup()) : std::string())
                        % (data->forwardRateLimitIsSet()
                           ? std::string(" --mbps ") + std::to_string(data->getForwardRateLimit()) : std::string())
                        % (dir != ""
                           ? std::string(" --dir ") + dir : std::string()));
}

int DaemonManager::startPA(io::swagger::server::model::Agent& body, std::stringstream &result) {
    uint16_t port;
    if (!body.packetAgentStrategiesIsSet()) {
        return -1;
    }
    std::vector<std::string> commandStr;
    std::string str;
    commandStr.push_back("pktminerg");
    str += "pktminerg";
    auto datas = body.getPacketAgentStrategies();
    if (datas.size() == 0) {
        return -1;
    }
    std::set<std::string> names;
    try{
        getActiveInstanceNames(names);
    }
    catch (...) {
        std::string str = boost::str(boost::format("Can't get active instance."));
        ctx_.log(str, log4cpp::Priority::INFO);
        LOG(INFO) << str;
    }
    uint64_t buffSize;
    if(body.getMemLimit() == 0) {
        buffSize = 256;
    } else {
        uint32_t stratigies = 0;
        for (auto &data:datas){
            if (data->containerIdsIsSet()) {
                stratigies += data->getContainerIds().size();
            } else if (data->interfaceNamesIsSet()) {
                stratigies += data->getInterfaceNames().size();
            } else if (data->instanceNamesIsSet()) {
                
                instanceCheck_ = true;
                for (auto & i: data->getInstanceNames()) {
                    if(std::find(names.begin(), names.end(), i) != names.end()) {
                        stratigies += 1;
                    }
                }           
            }
        }
        if (stratigies == 0 || stratigies > body.getMemLimit()) {

            return -1;
        }
        buffSize = body.getMemLimit()/stratigies;
    }
    
    if(!(port = zmqPortAvlPop())) {
            io::swagger::server::model::Error error;
            error.setCode(0);
            error.setMessage("no avl agent zmq rep port");
            result << error.toJson();
            return -1;
    }
    int noOfData = 0;
    //get buffer size
    for (auto &data: datas){
        auto &instanceStatus = instanceStatus_[noOfData++];
        if (data->getPacketChannelType() != "GRE" &&
            data->getPacketChannelType() != "ZMQ" &&
            data->getPacketChannelType() != "VXLAN" &&
            data->getPacketChannelType() != "FILE") {
            io::swagger::server::model::Error error;
            error.setCode(0);
            error.setMessage(boost::str(boost::format(
                    "packetChannelType=%1% must be GRE or ZMQ or VXLAN or FILE") % data->getPacketChannelType()));
            std::stringstream result;
            result << error.toJson();
            continue;
        }
              
        replace(str.begin(),str.end(),'/',' ');
        
        std::string cmdParams = createParams(data,port,buffSize);

        if (data->containerIdsIsSet()) {
            int id = 0;
            for (auto & i: data->getContainerIds()) {
                const auto command = boost::str(
                        boost::format("%1%%2%%3%")
                        %(std::string("-c ") + i)
                        %getChannelArg(data, id)
                        %cmdParams);

                commandStr.push_back(command);
                str += " " + command;
                id ++;
            }
        } else if (data->interfaceNamesIsSet()) {
            int id = 0;
            for (auto & i: data->getInterfaceNames()) {
                const auto command = boost::str(
                        boost::format("%1%%2%%3%")
                        %(std::string("-i ") + i)
                        %getChannelArg(data, id)
                        %cmdParams);
                commandStr.push_back(command);
                str += " " + command;
                id++;
            }

        } else if (data->instanceNamesIsSet()) {
            
            bool needRestart = false;
			if (checkProcessRunning()) {
            	for (auto & item: instanceStatus) {
                    if ((std::find(names.begin(), names.end(), item.first) == names.end() && item.second) ||
                        (std::find(names.begin(), names.end(), item.first) != names.end() && !item.second))
                    needRestart = true;
                    break;
            	}
            	if (!needRestart && instanceStatus.size() != 0) {
                	continue;
            	}
            }
            instanceStatus.clear();
            killRunningPktg();
            int id = 0;
            for (auto & i: data->getInstanceNames()) {
                if(std::find(names.begin(), names.end(), i) == names.end()) {
                    instanceStatus.insert(std::pair<std::string, bool>(i,false));
                    continue;
                }

                instanceStatus.insert(std::pair<std::string, bool>(i,true));

                const auto command = boost::str(
                        boost::format("%1%%2%%3%")
                        %(std::string("-m ") + i)
                        % getChannelArg(data, id)
                        %cmdParams);

                commandStr.push_back(command);
                str += " " + command;
                id++;
            }

        } else {
            std::string str = boost::str(boost::format("No instance or interface or container in the strategy."));
            ctx_.log(str, log4cpp::Priority::INFO);
            LOG(INFO) << str;
        }

    }

  	if (commandStr.size() < 2) {
        zmqPortAvlPush(port);
       return -1;
    }
  	if (checkProcessRunning()) {
        killRunningPktg();
  	}
    ctx_.log(str, log4cpp::Priority::INFO);
    LOG(INFO) << str;
    report_.addPacketAgentLogs("INFO", str);
    auto pid = exec(commandStr);

    int cnt = 0;
    while (!checkProcessRunning() && cnt++ < 2) {
        std::string str = boost::str(boost::format("Fail to start pktminerg and restart it."));
        ctx_.log(str, log4cpp::Priority::ERROR);
        LOG(ERROR) << str;

        report_.addPacketAgentLogs("ERROR", str);
        pid = exec(commandStr);
    }

    str = boost::str(boost::format("Pktminerg is running and pid = %1%.") % pid);
    ctx_.log(str, log4cpp::Priority::INFO);
    LOG(INFO) << str;

    report_.addPacketAgentLogs("INFO", str);

    report_.setPid(pid);
    int16_t memLimit = (body.getMemLimit() == 0)?0:body.getMemLimit() - 290;
    const auto limit = boost::str(
            boost::format("limit_cpu_mem_pid.sh %1% %2% %3%M") % pid %
            (static_cast<uint32_t>(body.getCpuLimit() * 1000)) %
                    memLimit);
    ctx_.log(limit, log4cpp::Priority::INFO);
    LOG(INFO) << limit;
    report_.addPacketAgentLogs("INFO", limit);
    ::system(limit.c_str());
    body.setName(boost::str(boost::format("%1%") % body.getId()));
    const auto waitResult = waitpid(pid, NULL, WNOHANG);
    body.setStatus(waitResult == -1 ? "error" : waitResult == pid ? "inactive" : "active");
    struct timeval tv;
    gettimeofday(&tv,NULL);
    body.setStartTime(tv);
    if (zmqPort_ != port)
        zmqPortAvlPush(zmqPort_);        
    agentPid_ = pid;
    zmqPort_ = port;
    return 0;
}

bool DaemonManager::updateAgentStatusSync() {
    
    // get Agent->PacketAgentData->PacketAgentMetrics, lazy init
    std::shared_ptr<io::swagger::server::model::PacketAgentMetrics> packet_channel_metric_ptr = report_.getPacketAgentMetrics();
    if (!packet_channel_metric_ptr) {
        packet_channel_metric_ptr = std::make_shared<io::swagger::server::model::PacketAgentMetrics>();
        report_.setPacketAgentMetrics(packet_channel_metric_ptr);
    }
    // update PacketAgentMetrics
    struct timeval tv;

    gettimeofday(&tv,NULL);
    packet_channel_metric_ptr->setSamplingTime(tv);

    const auto waitResult = waitpid(agentPid_, NULL, WNOHANG);
    agent_.setStatus(
            (waitResult == -1 || waitResult == agentPid_) ? "inactive" : "active");
    return (waitResult != agentPid_) && (waitResult != -1);
}

int DaemonManager::updateChannelStatusSync() {
    
    msg_t req,* rep;
    char tmp[sizeof(msg_t) + sizeof(msg_status_t)];
    req.magic = MSG_MAGIC_NUMBER;
    req.msglength = sizeof(msg_t);
    req.action = MSG_ACTION_REQ_QUERY_STATUS;
    req.query_id = 0;
    zmq::context_t zmq_context;
    zmq::socket_t zmq_socket(zmq_context, ZMQ_REQ);
    zmq_socket.setsockopt(ZMQ_LINGER, 0);
    // zmq_socket.set(zmq::sockopt::linger, 0);
    // zmq_socket.connect(zmq_endpoint_.c_str());
    zmq_socket.connect(boost::str(boost::format("tcp://127.0.0.1:%1%") % zmqPort_));

    zmq_pollitem_t pollitem;
    pollitem.socket = static_cast<void*>(zmq_socket);
    pollitem.events = ZMQ_POLLIN;

    zmq::message_t msg_send(&req, sizeof(msg_t), NULL);
    zmq::send_result_t send_num = zmq_socket.send(msg_send, zmq::send_flags::none);
    if (!send_num || (send_num.value() == 0)) {
        ctx_.log("agent status request send failed.", log4cpp::Priority::ERROR);
        std::cerr << "agent status request send failed." << std::endl;
        return -1;
    }


    int ret = zmq::poll(&pollitem, 1, ZMQ_TIMEOUT_);
    if ((ret > 0) && (pollitem.revents == ZMQ_POLLIN)) {

        zmq::message_t msg_recv;
        zmq::recv_result_t recv_ret = {};

        // check
        recv_ret = zmq_socket.recv(msg_recv, zmq::recv_flags::none);
        if (!recv_ret) {
            ctx_.log("agent status response recv failed.", log4cpp::Priority::ERROR);
            std::cerr << "agent status response recv failed." << std::endl;
            return -1;
        }

        size_t zmq_recv_size = msg_recv.size();
        if (zmq_recv_size != sizeof(msg_t) + sizeof(msg_status_t)) {
            ctx_.log("agent status response recv length is invalid.", log4cpp::Priority::ERROR);
            std::cerr << "agent status response recv length is invalid." << std::endl;
            return -1;
        }
        memcpy(tmp, msg_recv.data(), zmq_recv_size);
        rep = (msg_t*)tmp;
        if (rep->magic != MSG_MAGIC_NUMBER) {
            ctx_.log("agent status response recv magic error.", log4cpp::Priority::ERROR);
            std::cerr << "agent status response recv magic error." << std::endl;
            return -1;
        }
        if (rep->action != MSG_ACTION_REQ_QUERY_STATUS) {
            ctx_.log("agent status response recv action error.", log4cpp::Priority::ERROR);
            std::cerr << "agent status response recv action error." << std::endl;
            return -1;
        }
        if (rep->msglength != sizeof(msg_t) + sizeof(msg_status_t)) {
            ctx_.log("agent status response recv msglength error.", log4cpp::Priority::ERROR);
            std::cerr << "agent status response recv msglength error." << std::endl;
            return -1;
        }

        msg_status_t* p_status = (msg_status_t*)((char*)rep + sizeof(msg_t));

        // get Agent->PacketAgentData->PacketAgentMetrics, lazy init
        std::shared_ptr<io::swagger::server::model::PacketAgentMetrics> packet_channel_metric_ptr = report_.getPacketAgentMetrics();
        if (!packet_channel_metric_ptr) {
            packet_channel_metric_ptr = std::make_shared<io::swagger::server::model::PacketAgentMetrics>();
            report_.setPacketAgentMetrics(packet_channel_metric_ptr);
        }
        
        packet_channel_metric_ptr->setCapBytes(p_status->total_cap_bytes);
        packet_channel_metric_ptr->setCapPackets(p_status->total_cap_packets);
        packet_channel_metric_ptr->setCapDrop(p_status->total_cap_drop_count);
        packet_channel_metric_ptr->setFwdBytes(p_status->total_fwd_bytes);
        packet_channel_metric_ptr->setFwdPackets(p_status->total_fwd_count);

    } else {
        ctx_.log("agent status query failed.", log4cpp::Priority::ERROR);
        std::cerr << "agent status query failed." << std::endl;
        return -1;
    }
    return 0;
}

// get user/nice/system/idle/irq/softirq twice from /proc/stat's first line in jiffy
// get utime/stime/cutime/cstime twice from /proc/[pid]/stat in jiffy
// total_time_delta =
//     (user_new + nice_new + system_new + idle_new) -
//     (user_old + nice_old + system_old + idle_old)
// proc_time_delta =
//     (utime_new + stime_new + cutime_new + cstime_new) -
//     (utime_old + stime_old + cutime_old + cstime_old)
// cpuLoad = proc_time_delta
// cpuLoadRate = proc_time_delta / total_time_delta
int DaemonManager::updateChannelCpuLoadSync() {
    
    pid_t pid = agentPid_;

    std::string proc_stat_str;
    std::string proc_pid_stat_str;
    std::vector<std::string> proc_stat_params;
    std::vector<std::string> proc_pid_stat_params;


    std::string proc_stat_path = "/proc/stat";
    std::string proc_pid_stat_path = "/proc/" + std::to_string(pid) + "/stat";


    const uint16_t PROC_STAT_USER_INDEX = 1;
    const uint16_t PROC_STAT_NICE_INDEX = 2;
    const uint16_t PROC_STAT_SYSTEM_INDEX = 3;
    const uint16_t PROC_STAT_IDLE_INDEX = 4;
    const uint16_t PROC_STAT_IRQ_INDEX = 6;
    const uint16_t PROC_STAT_SOFTIRQ_INDEX = 7;

    const uint16_t PROC_PID_STAT_UTIME_INDEX = 13;
    const uint16_t PROC_PID_STAT_STIME_INDEX = 14;
    const uint16_t PROC_PID_STAT_CUTIME_INDEX = 15;
    const uint16_t PROC_PID_STAT_CSTIME_INDEX = 16;


    uint16_t sample_index = 0;
    const uint16_t SAMPLE_COUNT = 2;
    uint64_t total_time[SAMPLE_COUNT];
    uint64_t proc_time[SAMPLE_COUNT];

    uint16_t retry_count = 0;
    const uint16_t RETRY_COUNT_MAX = 3;

    while (true) {
        std::ifstream proc_stat(proc_stat_path.c_str());
        std::ifstream proc_pid_stat(proc_pid_stat_path.c_str());

        if (proc_stat.is_open() && proc_pid_stat.is_open()) {
            std::getline(proc_stat, proc_stat_str);
            boost::split(proc_stat_params, proc_stat_str, boost::is_any_of("\t\n "),
                         boost::token_compress_on);

            std::getline(proc_pid_stat, proc_pid_stat_str);
            boost::split(proc_pid_stat_params, proc_pid_stat_str, boost::is_any_of("\t\n "),
                         boost::token_compress_on);

            // check if split out needed value
            if (proc_stat_params.size() <= PROC_STAT_NICE_INDEX ||
                    proc_pid_stat_params.size() <= PROC_PID_STAT_CSTIME_INDEX) {
                ctx_.log("parse cpu info failed when updating agent cpu load.", log4cpp::Priority::ERROR);
                std::cerr << "parse cpu info failed when updating agent cpu load." << std::endl;
                retry_count++;
                if (retry_count > RETRY_COUNT_MAX) {
                    return -1;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }

            total_time[sample_index] =
                    std::stoull(proc_stat_params[PROC_STAT_USER_INDEX]) +
                    std::stoull(proc_stat_params[PROC_STAT_NICE_INDEX]) +
                    std::stoull(proc_stat_params[PROC_STAT_SYSTEM_INDEX]) +
                    std::stoull(proc_stat_params[PROC_STAT_IDLE_INDEX]) +
                    std::stoull(proc_stat_params[PROC_STAT_IRQ_INDEX]) +
                    std::stoull(proc_stat_params[PROC_STAT_SOFTIRQ_INDEX]);


            proc_time[sample_index] =
                    std::stoull(proc_pid_stat_params[PROC_PID_STAT_UTIME_INDEX]) +
                    std::stoull(proc_pid_stat_params[PROC_PID_STAT_STIME_INDEX]) +
                    std::stoull(proc_pid_stat_params[PROC_PID_STAT_CUTIME_INDEX]) +
                    std::stoull(proc_pid_stat_params[PROC_PID_STAT_CSTIME_INDEX]);


            //std::cout <<std::to_string(pid) <<": " <<total_time[sample_index] << " " << proc_time[sample_index] << std::endl;

        } else {
            if (!proc_stat.is_open()) {
                ctx_.log("/proc/stat open failed when updating agent cpu load.", log4cpp::Priority::ERROR);
                std::cerr << "/proc/stat open failed when updating agent cpu load." << std::endl;
            }
            if (!proc_pid_stat.is_open()) {
                output_buffer = std::string("/proc/") + std::to_string(pid) + "/stat open failed when updating agent cpu load.";
                ctx_.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << output_buffer << std::endl;
            }
            retry_count++;
            if (retry_count > RETRY_COUNT_MAX) {
                return -1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        sample_index++;
        if (sample_index >= SAMPLE_COUNT) {
            break;
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }

    // get Agent->PacketAgentData->PacketAgentMetrics, lazy init
    std::shared_ptr<io::swagger::server::model::PacketAgentMetrics> packet_channel_metric_ptr = report_.getPacketAgentMetrics();
    if (!packet_channel_metric_ptr) {
        packet_channel_metric_ptr = std::make_shared<io::swagger::server::model::PacketAgentMetrics>();
        report_.setPacketAgentMetrics(packet_channel_metric_ptr);
    }

    double proc_time_delta = static_cast<double>(proc_time[SAMPLE_COUNT - 1] - proc_time[0]);
    packet_channel_metric_ptr->setCpuLoad(proc_time_delta/100);

    int64_t total_time_delta = total_time[SAMPLE_COUNT - 1] - total_time[0];
    if (total_time_delta > 0) {
        double cpu_load_rate =
                proc_time_delta;
        cpu_load_rate /= ::sysconf(_SC_NPROCESSORS_CONF);
        packet_channel_metric_ptr->setCpuLoadRate(cpu_load_rate/100);
    } else {
        packet_channel_metric_ptr->setCpuLoadRate(0.0);
    }


    return 0;
}

// get MemTotal from /proc/meminfo in KB
// get VmRSS from /proc/[pid]/status in KB
// memUse = VmRSS * 1024
// memUseRate = VmRSS / MemTotal
int DaemonManager::updateChannleMemUse() {

    pid_t pid = agentPid_;

    std::string proc_meminfo_str;
    std::string proc_pid_status_str;
    std::vector<std::string> proc_meminfo_params;
    std::vector<std::string> proc_pid_status_params;

    std::string proc_meminfo_path = "/proc/meminfo";
    std::string proc_pid_status_path = "/proc/" + std::to_string(pid) + "/status";

    const uint16_t PROC_MEMINFO_INDEX = 1;

    uint16_t retry_count = 0;
    const uint16_t RETRY_COUNT_MAX = 3;

    uint64_t total_ram_mem_kb = 0;
    // uint64_t total_swap_mem_kb = 0;
    // uint64_t proc_vmsize_kb = 0;
    uint64_t proc_vmrss_kb = 0;

    bool vm_get = false;
    bool total_ram_mem_get = false;
    // bool total_swap_mem_get = false;

    while (true) {
        std::ifstream proc_meminfo(proc_meminfo_path.c_str());
        std::ifstream proc_pid_status(proc_pid_status_path.c_str());

        if (proc_meminfo.is_open() && proc_pid_status.is_open()) {
            // scan and get MemTotal and SwapTotal from /proc/meminfo line by line
            while (proc_meminfo.good()) {
                std::getline(proc_meminfo, proc_meminfo_str);

                if (std::string::npos != proc_meminfo_str.find("MemTotal:")) {
                    boost::split(proc_meminfo_params, proc_meminfo_str, boost::is_any_of("\t\n "),
                                 boost::token_compress_on);
                    total_ram_mem_kb = std::stoull(proc_meminfo_params[PROC_MEMINFO_INDEX]);
                    proc_meminfo_params.clear();
                    total_ram_mem_get = true;
                    break;
                }
            }

            // scan and get VmRSS from /proc/[pid]/status line by line
            while (proc_pid_status.good()) {
                std::getline(proc_pid_status, proc_pid_status_str);

                if (std::string::npos != proc_pid_status_str.find("VmRSS:")) {
                    boost::split(proc_pid_status_params, proc_pid_status_str, boost::is_any_of("\t\n "),
                                 boost::token_compress_on);
                    proc_vmrss_kb = std::stoull(proc_pid_status_params[PROC_MEMINFO_INDEX]);
                    proc_pid_status_params.clear();
                    vm_get = true;
                    break;
                }
            }


            // all 2 params must get valid value at the same time.
            if (!total_ram_mem_get || !vm_get) {
                if (!total_ram_mem_get) {
                    ctx_.log("retrieve total_ram_mem_kb failed when updating agent mem use.", log4cpp::Priority::ERROR);
                    std::cerr << "retrieve total_ram_mem_kb failed when updating agent mem use."
                              << std::endl;
                }

                if (!vm_get) {
                    ctx_.log("retrieve proc_vmrss_kb failed when updating agent mem use.", log4cpp::Priority::ERROR);
                    std::cerr << "retrieve proc_vmrss_kb failed when updating agent mem use."
                              << std::endl;
                }
                retry_count++;
                if (retry_count >= RETRY_COUNT_MAX) {
                    return -1;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
        } else {
            if (!proc_meminfo.is_open()) {
                ctx_.log("/proc/meminfo open failed when updating agent mem use.", log4cpp::Priority::ERROR);
                std::cerr << "/proc/meminfo open failed when updating agent mem use." << std::endl;
            }
            if (!proc_pid_status.is_open()) {
                output_buffer = std::string("/proc/") + std::to_string(pid) + "/status open failed when updating agent mem use.";
                ctx_.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << output_buffer << std::endl;
            }
            retry_count++;
            if (retry_count >= RETRY_COUNT_MAX) {
                return -1;
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
            continue;
        }
        break;
    }

    // get Agent->PacketAgentData->PacketAgentMetrics, lazy init
    std::shared_ptr<io::swagger::server::model::PacketAgentMetrics> packet_channel_metric_ptr = report_.getPacketAgentMetrics();
    if (!packet_channel_metric_ptr) {
        packet_channel_metric_ptr = std::make_shared<io::swagger::server::model::PacketAgentMetrics>();
        report_.setPacketAgentMetrics(packet_channel_metric_ptr);
    }

    packet_channel_metric_ptr->setMemUse(static_cast<int64_t>(proc_vmrss_kb * 1024));

    if (total_ram_mem_kb) {
        double mem_load_rate =
                static_cast<double>(proc_vmrss_kb) / static_cast<double>(total_ram_mem_kb);
        packet_channel_metric_ptr->setMemUseRate(mem_load_rate);
    } else {
        packet_channel_metric_ptr->setMemUseRate(0.0);
    }



    /*
    std::cout << "update_agent_mem_stat" << std::endl;
    std::cout << total_ram_mem_kb << std::endl;
    std::cout << total_swap_mem_kb << std::endl;
    std::cout << proc_vmsize_kb << std::endl;
    std::cout << mem_load_rate << std::endl;
    */
   return 0;
}

bool DaemonManager::delAgent() {
    if (kill(agentPid_, SIGTERM) == -1) {
        auto strErr = boost::str(boost::format("kill pid=%1% failed, error=%2%")
                                 % agentPid_ % errno);
        ctx_.log(strErr, log4cpp::Priority::ERROR);
        LOG(ERROR) << strErr;
        report_.addPacketAgentLogs("ERROR", strErr);
    }
    if (waitpid(agentPid_, NULL, 0) == -1) {
        auto strErr = boost::str(boost::format("wait pid=%1% failed, error=%2%")
                                 % agentPid_ % errno);
        ctx_.log(strErr, log4cpp::Priority::ERROR);
        LOG(ERROR) << strErr;
        report_.addPacketAgentLogs("ERROR", strErr);
    }
    clearCgroupfolder(agentPid_);
    agentPid_ = 0;
    zmqPortAvlPush(zmqPort_);
    return true;
}


DaemonManager::DaemonManager(const boost::program_options::variables_map &vm, timer_tasks_t* tasks, LogFileContext& ctx)
        :vm_(vm),tasks_(tasks), ctx_(ctx)
{
    daemon_.setLogFileContext(ctx);
    daemon_.setName(vm_["name"].as<std::string>());
    const auto uuid = boost::uuids::random_generator()();
    daemon_.setUuid(to_string(uuid));
    const auto service = boost::str(boost::format("http%1%://%2%:%3%")
                                    % (vm["certificate"].as<std::string>().empty() ? std::string{} : "s")
                                    % vm["host"].as<std::string>() % vm["port"].as<uint16_t>());

    daemon_.setService(service);
    daemon_.setApiVersion(API_VERSION);

    char *nodeName = getenv("HOSTNAME");
	if(nodeName != nullptr) {
        daemon_.setNodeName(nodeName);
    }
    
    //set podname (and name space) for sidecard mode
    if(vm_.count("podname")) {
        char* podName = getenv(vm_["podname"].as<std::string>().c_str());
        if (podName==nullptr || strlen(podName)==0) {
            output_buffer = std::string("can't get the value of ") + vm_["podname"].as<std::string>();
            ctx_.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << output_buffer << std::endl;
            timer_tasks_stop(tasks_);
            return;
        }
        daemon_.setPodName(podName);
        if(vm_.count("namespace")) {
            char* nameSpace = getenv(vm_["namespace"].as<std::string>().c_str());
            if (nameSpace == nullptr || strlen(nameSpace)==0) {
                output_buffer = std::string("can't get the value of ") + vm_["namespace"].as<std::string>();
                ctx_.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << output_buffer << std::endl;
                timer_tasks_stop(tasks_);
                return;
            }
            daemon_.setNamespace(nameSpace);  
        }
    }

    if(vm_.count("deployEnv")) {
        if((vm_["deployEnv"].as<std::string>() == "HOST") || (vm_["deployEnv"].as<std::string>() == "INSTANCE")) {
            daemon_.setDeployEnv(vm_["deployEnv"].as<std::string>().c_str());
        } else {
            output_buffer = std::string("The value of deployEnv can only be \"HOST\" or \"INSTANCE\", while input value is ") 
                            + vm_["deployEnv"].as<std::string>();
            ctx_.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << output_buffer << std::endl;
            timer_tasks_stop(tasks_);
            return; 
        }
    }
    
	daemon_.setClientVersion("0.8.0");
    std::vector<std::string> strs;
    split(strs, SUPPORT_API_VERSIONS, boost::algorithm::is_any_of(","));
    for (const auto& str:strs) {
        daemon_.getSupportApiVersions().push_back(str);
    }

    daemon_.setStatus("active");
    struct timeval tv;
    gettimeofday(&tv,NULL);
    daemon_.setStartTime(tv);
    daemon_.setSyncMode("pull");

    strs.resize(0);

    daemon_.setPlatformId (vm_["platformId"].as<std::string>());
    strs.resize(0);
    std::string query = vm_["query"].as<std::string>();
    split(strs, query, boost::algorithm::is_any_of(","));
    zmqPortRange_ = std::make_pair((uint16_t)atoi(strs[0].c_str()), (uint16_t)atoi(strs[1].c_str()));
    initZmqPortAvl();

    scanNetworkInterfacePeroidUs_ = TICK_US_SEC * 60;
    getDaemonPeroidUs_ = TICK_US_SEC * 15;
    timer_tasks_push(tasks_, scanNetworkInterface, this, scanNetworkInterfacePeroidUs_);
    getDaemonTid_ = TID_INVALID;

    std::ifstream fin;
    fin.open("/usr/local/bin/uuid",std::ios::in);
    if(fin.is_open()) {
        char buf[256]={0};
        fin.read(buf,256);
        if(strlen(buf) > 0) {
            paUUID_=buf;
            daemon_.setPaUUID(paUUID_);
        }
        output_buffer = std::string("read uuid=") + paUUID_;
        ctx_.log(output_buffer, log4cpp::Priority::INFO);
        std::cout << output_buffer << std::endl;    
        fin.close();
    }
}

DaemonManager::~DaemonManager() {

    killRunningPktg();
}

void DaemonManager::scanNetworkInterface(void *user) {
    try {
        ((DaemonManager *) user)->scanNetworkInterfaceImpl();

    }catch (const std::exception& ex)
    {
        std::string output_buffer = boost::str(boost::format("scanNetworkInterface failed: %1%") % ex.what());
        ((DaemonManager *) user)->ctx_.log(output_buffer, log4cpp::Priority::ERROR);
        LOG(ERROR) << output_buffer;
    }
}

void DaemonManager::scanNetworkInterfaceImpl() {
    //impl here
    std::unordered_set<std::string> interfaces;

    interfaces = readInterfaces(ctx_);

    std::lock_guard<std::recursive_mutex> lock{mtx_};
    if(interfaces != interfaces_)
    {
        ctx_.log("scanNetworkInterface changed ", log4cpp::Priority::INFO);
        LOG(INFO) << "scanNetworkInterface changed ";
        daemon_.updateNics();
        if(vm_.count("includingNICs"))  {
            std::vector<std::string> nics;
            boost::split(nics, vm_["includingNICs"].as<std::string>(), boost::is_any_of(","));
            if (0 == daemon_.filterNics(nics)) {
                ctx_.log("No nics left after filtering, please check the config of \"includingNICs\"", log4cpp::Priority::ERROR);
                std::cerr << "No nics left after filtering, please check the config of \"includingNICs\"" << std::endl;
                timer_tasks_stop(tasks_);
                return;
            }

        }
        
        if(!daemonReg())
            interfaces_ = interfaces;
    }
}

void DaemonManager::getDaemon(void *user) {
    //try {
        ((DaemonManager*)user)->getDaemonImpl();
    //}catch (const std::exception& ex)
    //{
      //  LOG(ERROR) << boost::str(boost::format("getDaemon failed: %1%") % ex.what());
    //}
}

std::unordered_set<std::string> DaemonManager::readInterfaces(LogFileContext& ctx) {
    std::unordered_set<std::string> interfaces;
    struct ifaddrs* ifaddr;
    if (::getifaddrs(&ifaddr) == -1) {
        ctx.log("getifaddrs failed", log4cpp::Priority::ERROR);
        LOG(ERROR) << "getifaddrs failed";
        return interfaces;
    }

    for (auto ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        interfaces.insert(ifa->ifa_name);
    }
    ::freeifaddrs(ifaddr);
    return interfaces;
}

int DaemonManager::daemonReg() {
    std::shared_ptr<CURL> curl(::curl_easy_init(), [](CURL* curl) {
        ::curl_easy_cleanup(curl);
    });

    if (curl == nullptr) {
        ctx_.log("curl init failed", log4cpp::Priority::ERROR);
        LOG(ERROR) << "curl init failed";
        return -1;
    }

    std::stringstream jsonStream;
    std::string url;
    CURLcode res;
    long statusCode;
    std::string body;
    std::vector<std::string> strs;

    daemon_.getLabels().clear();
    std::string labels = vm_["labels"].as<std::string>();
    split(strs, labels, boost::algorithm::is_any_of(","));
    for (const auto& str:strs) {
        std::shared_ptr<io::swagger::server::model::Label> newItem(new io::swagger::server::model::Label());
        newItem->setValue(str);
        daemon_.getLabels().push_back(newItem);
    }

    url = vm_["manager"].as<std::string>();
    ::curl_easy_setopt(curl.get(), CURLOPT_URL, url.c_str());
    jsonStream << daemon_.toJson();
    const auto json = jsonStream.str();
    
    ::curl_easy_setopt(curl.get(), CURLOPT_POSTFIELDS, json.c_str());
    if (!vm_["certificate"].as<std::string>().empty()) {
        ::curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYPEER, false);
        ::curl_easy_setopt(curl.get(), CURLOPT_SSL_VERIFYHOST, false);

        ::curl_easy_setopt(curl.get(), CURLOPT_SSLCERTTYPE, "P12");
        ::curl_easy_setopt(curl.get(), CURLOPT_SSLKEYPASSWD, vm_["password"].as<std::string>().c_str());
        ::curl_easy_setopt(curl.get(), CURLOPT_SSLCERT, vm_["certificate"].as<std::string>().c_str());
    }
    //LOG(INFO) << json.c_str() << std::endl;

    std::shared_ptr<CURL> list(curl_slist_append(nullptr, "Content-Type: application/json"), [](curl_slist* slist) {
        ::curl_slist_free_all(slist);
    });
    ::curl_easy_setopt(curl.get(), CURLOPT_HTTPHEADER, list.get());
    ::curl_easy_setopt(curl.get(), CURLOPT_TIMEOUT, CURL_TIMEOUT_);
    body.resize(40960);
    body.resize(0);
    ::curl_easy_setopt(curl.get(), CURLOPT_WRITEDATA, &body);
    ::curl_easy_setopt(curl.get(), CURLOPT_WRITEFUNCTION, curlWriteFunction);

    if ((res = ::curl_easy_perform(curl.get())) != CURLE_OK) {
        output_buffer = boost::str(boost::format("curl_easy_perform(POST %1%) failed: %2%")
                        % url % curl_easy_strerror(res));
        ctx_.log(output_buffer, log4cpp::Priority::ERROR);
        LOG(ERROR) << output_buffer;
        return -1;
    }
    ::curl_easy_getinfo (curl.get(), CURLINFO_RESPONSE_CODE, &statusCode);

    if(statusCode != 200) {
        std::string message;
        //getCurlRespError(body, code, message);
        output_buffer = boost::str(boost::format("curl_easy_perform(POST %1%) failed: sc=%2% body=%3%")
                                 % url % statusCode % body);
        ctx_.log(output_buffer, log4cpp::Priority::ERROR);
        LOG(ERROR) << output_buffer;
        return -1;
    }
    else
    {
        output_buffer = boost::str(boost::format("curl_easy_perform(POST %1%) ok: sc=%2%")
                                 % url % statusCode);
        ctx_.log(output_buffer, log4cpp::Priority::INFO);
        LOG(INFO) << output_buffer;

        nlohmann::json js = nlohmann::json::parse(body);
        
        daemon_.fromJson(js);
        if(paUUID_.length() == 0 && daemon_.paUUIDIsSet()) {
            paUUID_ = daemon_.getPaUUID();
            std::ofstream fout;
            fout.open("/usr/local/bin/uuid",std::ios::out);
            fout.write(paUUID_.c_str(),paUUID_.length());
            output_buffer = std::string("get uuid and write=") + paUUID_;
            ctx_.log(output_buffer, log4cpp::Priority::INFO);
            std::cout << output_buffer << std::endl;
            fout.close();
        }
        startPullMode(true);
       
        return 0;
    }
    return 0;
}
void DaemonManager::startPullMode(bool startGetDaemon)//Daemon -> PAM
{    
    if (startGetDaemon) {
        int periodUs = getDaemonPeroidUs_;
        if(agent_.SyncIntervalIsSet() && agent_.getSyncInterval() > 0)
            periodUs = agent_.getSyncInterval() * TICK_US_SEC;
        getDaemonTid_ = timer_tasks_push(tasks_, getDaemon, this, periodUs);
    }
}
int DaemonManager::getCurlRespError(const std::string &body, int &code, std::string &message) {

    nlohmann::json js = nlohmann::json::parse(body);
    if(js.find("code") != js.end())
        code = js.at("code");
    else
        return -1;
    if(js.find("message") != js.end())
        message = js.at("message");
    else
        return -1;
    return 0;
}

size_t DaemonManager::curlWriteFunction(char *ptr, size_t size, size_t nmemb, void *userdata) {
    std::string* body = (std::string*)userdata;
    size_t relSize = size * nmemb;
    size_t preSize = body->size();

    body->resize(preSize + relSize);
    memcpy(&*body->begin() + preSize, ptr, relSize);
    return relSize;
}

void DaemonManager::updateAgents() {
    
    updateAgentStatusSync();
    updateChannelCpuLoadSync();
    updateChannleMemUse();
    updateChannelStatusSync();
}

void DaemonManager::clearAgent() {
    report_.unsetPacketAgentMetrics();
    report_.unsetPid();
}

void DaemonManager::initZmqPortAvl() {
    for(uint16_t port = zmqPortRange_.first; port <= zmqPortRange_.second; ++port)
    {
        zmqPortAvl_.push_back(std::make_pair(port, true));
    }
}

uint16_t DaemonManager::zmqPortAvlPop() {
    for(auto& m : zmqPortAvl_)
    {
        if(m.second)
        {
            m.second = false;
            return m.first;
        }
    }
    return 0;
}

void DaemonManager::zmqPortAvlPush(uint16_t port) {
    for(auto& m : zmqPortAvl_)
        if(m.first == port)
        {
            m.second = true;
            return;
        }
}
