/**
* Netis Agent REST APIs
* Netis Agent 管理平台由 **Agent**, **Daemon**, **Manager** 三个组件组成。   * Agent: 部署在用户环境中采集数据，当前支持 Packet Agent 采集网络数据   * Daemon: 部署在用户环境中通过 REST APIs 管理 Agent   * Manager: 部署在监控环境中通过 REST APIs 管理 Daemon 和 Agent 
*
* OpenAPI spec version: 0.1.0
* 
*
* NOTE: This class is auto generated by the swagger code generator program.
* https://github.com/swagger-api/swagger-codegen.git
* Do not edit the class manually.
*/


#include "Agent.h"

namespace io {
    namespace swagger {
        namespace server {
            namespace model {

                Agent::Agent() {
                    m_Id = 0;
                    m_IdIsSet = false;
                    m_Name = "";
                    m_NameIsSet = false;
                    m_StatusIsSet = false;
                    m_StartTimestamp = 0;
                    m_StartMicroTimestamp = 0;
                    m_StartTimeIsSet = false;
                    m_StrategyIsSet = false;
                    m_CpuLimit = 0.0;
                    m_CpuLimitIsSet = false;
                    m_MemLimit = 0;
                    m_MemLimitIsSet = false;
                    m_Version = 0;
                    m_VersionIsSet = false;
                    m_SyncInterval = 0;
                    m_SyncIntervalIsSet = false;
                }

                Agent::~Agent() {
                }

                void Agent::validate() {
                    // TODO: implement validation
                }

                nlohmann::json Agent::toJson() const {
                    nlohmann::json val = nlohmann::json::object();

                    if (m_IdIsSet) {
                        val["id"] = m_Id;
                    }
                    if (m_PidIsSet) {
                        val["pid"] = m_Pid;
                    }
                    if (m_NameIsSet) {
                        val["name"] = ModelBase::toJson(m_Name);
                    }
                    if (m_StatusIsSet) {
                        val["status"] = ModelBase::toJson(m_Status);
                    }
                    if (m_StartTimeIsSet) {
                        val["startTimestamp"] = m_StartTimestamp;
                        val["startMicroTimestamp"] = m_StartMicroTimestamp;
                    }
                    {
                        nlohmann::json jsonArray;
                        for (auto& item : m_Strategy) {
                            jsonArray.push_back(ModelBase::toJson(item));
                        }

                        if (jsonArray.size() > 0) {
                            val["packetAgentStrategies"] = jsonArray;
                        }
                    }

                    if(m_CpuLimitIsSet)
                    {
                        val["cpuLimit"] = m_CpuLimit;
                    }
                    if(m_MemLimitIsSet)
                    {
                        val["memLimit"] = m_MemLimit;
                    }
                    if(m_Version)
                    {
                        val["version"] = m_Version;
                    }


                    if (m_SyncIntervalIsSet) {
                        val["syncInterval"] = ModelBase::toJson(m_SyncInterval);
                    }

                    return val;
                }

                void Agent::fromJson(nlohmann::json& val) {

                    MB_FSET(id, Id)
                    MB_FSET(pid, Pid)
                    MB_FSET(name, Name)
                    MB_FSET(status, Status)
                    MB_FSET(startTimestamp, StartTimestamp)
                    MB_FSET(startMicroTimestamp, StartMicroTimestamp)
                   {
                        m_Strategy.clear();
                        nlohmann::json jsonArray;
                        MB_FCHECK(strategy){
                            for (auto& item : val["strategy"]) {

                                if (!item.is_null()){
                                    std::shared_ptr<PacketAgentData> newItem(new PacketAgentData());
                                    newItem->fromJson(item);
                                    m_Strategy.push_back(newItem);
                                   
                                }

                            }
                             m_StrategyIsSet = true;
                        }
                    }
                    MB_FSET(cpuLimit, CpuLimit)
                    MB_FSET(memLimit, MemLimit)
                    MB_FSET(version, Version)
                    MB_FSET(syncInterval, SyncInterval)
                }


                double Agent::getCpuLimit() const {
                    return m_CpuLimit;
                }

                void Agent::setCpuLimit(double value) {
                    m_CpuLimit = value;
                    m_CpuLimitIsSet = true;
                }

                bool Agent::cpuLimitIsSet() const {
                    return m_CpuLimitIsSet;
                }

                void Agent::unsetCpuLimit() {
                    m_CpuLimitIsSet = false;
                }

                int64_t Agent::getMemLimit() const {
                    return m_MemLimit;
                }

                void Agent::setMemLimit(int64_t value) {
                    m_MemLimit = value;
                    m_MemLimitIsSet = true;
                }

                bool Agent::memLimitIsSet() const {
                    return m_MemLimitIsSet;
                }

                void Agent::unsetMemLimit() {
                    m_MemLimitIsSet = false;
                }
                int32_t Agent::getId() const {
                    return m_Id;
                }

                void Agent::setId(int32_t value) {
                    m_Id = value;
                    m_IdIsSet = true;
                }

                bool Agent::idIsSet() const {
                    return m_IdIsSet;
                }

                void Agent::unsetId() {
                    m_IdIsSet = false;
                }

                void Agent::setPid(int32_t value) {
                    m_Pid = value;
                    m_PidIsSet = true;
                }

                bool Agent::pidIsSet() const {
                    return m_PidIsSet;
                }

                void Agent::unsetPid() {
                    m_PidIsSet = false;
                }

                std::string Agent::getName() const {
                    return m_Name;
                }

                void Agent::setName(std::string value) {
                    m_Name = value;
                    m_NameIsSet = true;
                }

                bool Agent::nameIsSet() const {
                    return m_NameIsSet;
                }

                void Agent::unsetName() {
                    m_NameIsSet = false;
                }

                std::string Agent::getStatus() const {
                    return m_Status;
                }

                void Agent::setStatus(std::string value) {
                    m_Status = value;
                    m_StatusIsSet = true;
                }

                bool Agent::statusIsSet() const {
                    return m_StatusIsSet;
                }

                void Agent::unsetStatus() {
                    m_StatusIsSet = false;
                }

                long Agent::getStartTime() const {
                    return m_StartTimestamp;
                }

                void Agent::setStartTime(struct timeval val) {
                    m_StartTimestamp = val.tv_sec;
                    m_StartMicroTimestamp = val.tv_usec;
                    m_StartTimeIsSet = true;
                }

                void Agent::setStartTimestamp(long val) {
                    m_StartTimestamp = val;
                    m_StartTimeIsSet = true;
                }

                void Agent::setStartMicroTimestamp(long val) {
                    m_StartMicroTimestamp = val;
                    m_StartTimeIsSet = true;
                }

                bool Agent::startTimeIsSet() const {
                    return m_StartTimeIsSet;
                }

                void Agent::unsetStartTime() {
                    m_StartTimeIsSet = false;
                }

                std::vector<std::shared_ptr<PacketAgentData>> Agent::getPacketAgentStrategies() const {
                    return m_Strategy;
                }

                bool Agent::packetAgentStrategiesIsSet() const {
                    return m_StrategyIsSet;
                }

                void Agent::unsetPacketAgentStrategies() {
                    m_StrategyIsSet = false;
                }
                int32_t Agent::getVersion() const {
                    return m_Version;
                }

                void Agent::setVersion(int32_t value) {
                    m_Version = value;
                    m_VersionIsSet = true;
                }

                bool Agent::versionIsSet() const {
                    return m_VersionIsSet;
                }

                void Agent::unsetVersion() {
                    m_VersionIsSet = false;
                }

            }
        }
    }
}

