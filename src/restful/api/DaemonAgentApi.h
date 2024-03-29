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

#ifndef DaemonAgentApi_H_
#define DaemonAgentApi_H_


#include <pistache/endpoint.h>
#include <pistache/http.h>
#include <pistache/router.h>
#include <pistache/http_headers.h>

#include "Agent.h"
#include "Error.h"
#include "Daemon.h"

namespace io {
    namespace swagger {
        namespace server {
            namespace api {

                using namespace io::swagger::server::model;

                class DaemonAgentApi {
                public:
                    DaemonAgentApi(Pistache::Address addr);

                    virtual ~DaemonAgentApi() {};

                    void init(size_t thr);

                    void start();

                    void shutdown();

                    const std::string base_ = "/api/v1";
                private:
                    void setupRoutes();

                    void del_agent_by_id_handler(const Pistache::Rest::Request& request,
                                                 Pistache::Http::ResponseWriter response);

                    void list_agents_handler(const Pistache::Rest::Request& request,
                                             Pistache::Http::ResponseWriter response);

                    void query_agent_by_id_handler(const Pistache::Rest::Request& request,
                                                   Pistache::Http::ResponseWriter response);

                    void start_agent_handler(const Pistache::Rest::Request& request,
                                             Pistache::Http::ResponseWriter response);

                    void update_agent_by_id_handler(const Pistache::Rest::Request& request,
                                                    Pistache::Http::ResponseWriter response);

                    void get_status_handler(const Pistache::Rest::Request &request,
                                                Pistache::Http::ResponseWriter response);

                    void daemon_agent_api_default_handler(const Pistache::Rest::Request& request,
                                                          Pistache::Http::ResponseWriter response);

                    std::shared_ptr<Pistache::Http::Endpoint> httpEndpoint;
                    Pistache::Rest::Router router;


                    /// <summary>
                    /// delAgentById
                    /// </summary>
                    /// <remarks>
                    /// 根据 ID 删除 Agent
                    /// </remarks>
                    /// <param name="agentId">Agent ID</param>
                    virtual void del_agent_by_id(Pistache::Http::ResponseWriter& response) = 0;

                    /// <summary>
                    /// listAgents
                    /// </summary>
                    /// <remarks>
                    /// 列出 Daemon 上所有 Agent
                    /// </remarks>
                    virtual void list_agents(Pistache::Http::ResponseWriter& response) = 0;

                    /// <summary>
                    /// queryAgentById
                    /// </summary>
                    /// <remarks>
                    /// 根据 ID 查询 Agent 信息
                    /// </remarks>
                    /// <param name="agentId">Agent ID</param>
                    virtual void
                    query_agent_by_id(Pistache::Http::ResponseWriter& response) = 0;

                    /// <summary>
                    /// startAgent
                    /// </summary>
                    /// <remarks>
                    /// 启动一个 Agent
                    /// </remarks>
                    /// <param name="body"> (optional)</param>
                    virtual void start_agent(const Agent& body, Pistache::Http::ResponseWriter& response) = 0;

                    /// <summary>
                    /// updateAgentById
                    /// </summary>
                    /// <remarks>
                    /// 根据 ID 更新 Agent 信息
                    /// </remarks>
                    /// <param name="agentId">Agent ID</param>
                    /// <param name="body"> (optional)</param>
                    virtual void update_agent_by_id(const std::string& action,const Agent& body,
                                                    Pistache::Http::ResponseWriter& response) = 0;

                    /// <summary>
                    /// getStatus
                    /// </summary>
                    /// <remarks>
                    /// 查询 Daemon 状态
                    /// </remarks>
                    virtual void get_status(Pistache::Http::ResponseWriter &response) = 0;

                };

            }
        }
    }
}

#endif /* DaemonAgentApi_H_ */

