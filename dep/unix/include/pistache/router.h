/* router.h
   Mathieu Stefani, 05 janvier 2016

   Simple HTTP Rest Router
*/

#pragma once

#include <memory>
#include <regex>
#include <string>
#include <tuple>
#include <unordered_map>
#include <vector>

#include <pistache/flags.h>
#include <pistache/http.h>
#include <pistache/http_defs.h>

#include "pistache/string_view.h"
#include "glog/logging.h"

namespace Pistache {
    namespace Rest {

        class Description;

        namespace details {
            template<typename T>
            struct LexicalCast {
                static T cast(const std::string& value) {
                    std::istringstream iss(value);
                    T out;
                    if (!(iss >> out)) {
                        throw std::runtime_error("Bad lexical cast");
                    }
                    return out;
                }
            };

            template<>
            struct LexicalCast<std::string> {
                static std::string cast(const std::string& value) { return value; }
            };
        } // namespace details

        class TypedParam {
        public:
            TypedParam(std::string name, std::string value)
                    : name_(std::move(name)), value_(std::move(value)) {}

            template<typename T>
            T as() const {
                return details::LexicalCast<T>::cast(value_);
            }

            const std::string& name() const { return name_; }

        private:
            const std::string name_;
            const std::string value_;
        };

        class Request;

        struct Route {
            enum class Result {
                Ok, Failure
            };

            enum class Status {
                Match, NotFound, NotAllowed
            };

            typedef std::function<Result(const Request, Http::ResponseWriter)> Handler;

            explicit Route(Route::Handler handler) : handler_(std::move(handler)) {}

            template<typename... Args>
            void invokeHandler(Args&& ... args) const {
                handler_(std::forward<Args>(args)...);
            }

            Handler handler_;
        };

        namespace Private {
            class RouterHandler;
        }

/**
 * A request URI is made of various path segments.
 * Since all routes handled by a router are naturally
 * represented as a tree, this class provides support for it.
 * It is possible to perform tree-based routing search instead
 * of linear one.
 * This class holds all data for a given path segment, meaning
 * that it holds the associated route handler (if any) and all
 * next child routes (by means of fixed routes, parametric,
 * optional parametric and splats).
 * Each child is in turn a SegmentTreeNode.
 */
        class SegmentTreeNode {
        private:
            enum class SegmentType {
                Fixed, Param, Optional, Splat
            };

            /**
             * string_view are very efficient when working with the
             * substring function (massively used for routing) but are
             * non-owning. To let the content survive after it is firstly
             * created, their content is stored in this reference pointer
             * that is in charge of managing their lifecycle (create on add,
             * reset on remove).
             */
            std::shared_ptr<char> resource_ref_;

            std::unordered_map<std::string_view, std::shared_ptr<SegmentTreeNode>> fixed_;
            std::unordered_map<std::string_view, std::shared_ptr<SegmentTreeNode>> param_;
            std::unordered_map<std::string_view, std::shared_ptr<SegmentTreeNode>>
                    optional_;
            std::shared_ptr<SegmentTreeNode> splat_;
            std::shared_ptr<Route> route_;

            /**
             * Common web servers (nginx, httpd, IIS) collapse multiple
             * forward slashes to a single one. This regex is used to
             * obtain the same result.
             */
            static std::regex multiple_slash;

            static SegmentType getSegmentType(const std::string_view& fragment);

            /**
             * Fetches the route associated to a given path.
             * \param[in] path Requested resource path. Must have no leading slash
             * and no multiple slashes:
             * eg:
             * - auth/login is valid
             * - /auth/login is invalid
             * - auth//login is invalid
             * \param[in,out] params Contains all the parameters parsed so far.
             * \param[in,out] splats Contains all the splats parsed so far.
             * \returns Tuple containing the route, the list of all parsed parameters
             * and the list of all parsed splats.
             * \throws std::runtime_error An empty path was given
             */
            std::tuple<std::shared_ptr<Route>, std::vector<TypedParam>,
                    std::vector<TypedParam>>
            findRoute(const std::string_view& path, std::vector<TypedParam>& params,
                      std::vector<TypedParam>& splats) const;

        public:
            SegmentTreeNode();

            explicit SegmentTreeNode(const std::shared_ptr<char>& resourceReference);

            /**
             * Sanitizes a resource URL by removing any duplicate slash, leading
             * slash and trailing slash.
             * @param path URL to sanitize.
             * @return Sanitized URL.
             */
            static std::string sanitizeResource(const std::string& path);

            /**
             * Associates a route handler to a given path.
             * \param[in] path Requested resource path. Must have no leading and trailing
             * slashes and no multiple slashes:
             * eg:
             * - auth/login is valid
             * - /auth/login is invalid
             * - auth/login/ is invalid
             * - auth//login is invalid
             * \param[in] handler Handler to associate to path.
             * \param[in] resource_reference \see SegmentTreeNode::resource_ref_
             * \throws std::runtime_error An empty path was given
             */
            void addRoute(const std::string_view& path, const Route::Handler& handler,
                          const std::shared_ptr<char>& resource_reference);

            /**
             * Removes the route handler associated to a given path.
             * \param[in] path Requested resource path. Must have no leading slash
             * and no multiple slashes:
             * eg:
             * - auth/login is valid
             * - /auth/login is invalid
             * - auth//login is invalid
             * \throws std::runtime_error An empty path was given
             */
            bool removeRoute(const std::string_view& path);

            /**
             * Finds the correct route for the given path.
             * \param[in] path Requested resource path. Must have no leading slash
             * and no multiple slashes:
             * eg:
             * - auth/login is valid
             * - /auth/login is invalid
             * - auth//login is invalid
             * \throws std::runtime_error An empty path was given
             * \return Found route with its resolved parameters and splats (if no route
             * is found, first element of the tuple is a null pointer).
             */
            std::tuple<std::shared_ptr<Route>, std::vector<TypedParam>,
                    std::vector<TypedParam>>
            findRoute(const std::string_view& path) const;
        };

        class Router {
        public:
            static Router fromDescription(const Rest::Description& desc);

            std::shared_ptr<Private::RouterHandler> handler() const;

            static std::shared_ptr<Private::RouterHandler>
            handler(std::shared_ptr<Rest::Router> router);

            void initFromDescription(const Rest::Description& desc);

            void get(const std::string& resource, Route::Handler handler);

            void post(const std::string& resource, Route::Handler handler);

            void put(const std::string& resource, Route::Handler handler);

            void patch(const std::string& resource, Route::Handler handler);

            void del(const std::string& resource, Route::Handler handler);

            void options(const std::string& resource, Route::Handler handler);

            void addRoute(Http::Method method, const std::string& resource,
                          Route::Handler handler);

            void removeRoute(Http::Method method, const std::string& resource);

            void head(const std::string& resource, Route::Handler handler);

            void addCustomHandler(Route::Handler handler);

            void addNotFoundHandler(Route::Handler handler);

            inline bool hasNotFoundHandler() { return notFoundHandler != nullptr; }

            void invokeNotFoundHandler(const Http::Request& req,
                                       Http::ResponseWriter resp) const;

            Route::Status route(const Http::Request& request,
                                Http::ResponseWriter response);

            Router() : routes(), customHandlers(), notFoundHandler() {}

        private:
            std::unordered_map<Http::Method, SegmentTreeNode> routes;

            std::vector<Route::Handler> customHandlers;

            Route::Handler notFoundHandler;
        };

        namespace Private {

            class RouterHandler : public Http::Handler {
            public:

            HTTP_PROTOTYPE(RouterHandler)

                /**
                 * Used for immutable router. Useful if all the routes are
                 * defined at compile time (and for backward compatibility)
                 * \param[in] router Immutable router.
                 */
                explicit RouterHandler(const Rest::Router& router);

                /**
                 * Used for mutable router. Useful if it is required to
                 * add/remove routes at runtime.
                 * \param[in] router Pointer to a (mutable) router.
                 */
                explicit RouterHandler(std::shared_ptr<Rest::Router> router);

                void onRequest(const Http::Request& req,
                               Http::ResponseWriter response) override;

            private:
                std::shared_ptr<Rest::Router> router;
            };
        } // namespace Private

        class Request : public Http::Request {
        public:
            friend class Router;

            bool hasParam(const std::string& name) const;

            TypedParam param(const std::string& name) const;

            TypedParam splatAt(size_t index) const;

            std::vector<TypedParam> splat() const;

        private:
            explicit Request(const Http::Request& request,
                             std::vector<TypedParam>&& params,
                             std::vector<TypedParam>&& splats);

            std::vector<TypedParam> params_;
            std::vector<TypedParam> splats_;
        };

        namespace Routes {

            void Get(Router& router, const std::string& resource, Route::Handler handler);

            void Post(Router& router, const std::string& resource, Route::Handler handler);

            void Put(Router& router, const std::string& resource, Route::Handler handler);

            void Patch(Router& router, const std::string& resource, Route::Handler handler);

            void Delete(Router& router, const std::string& resource,
                        Route::Handler handler);

            void Options(Router& router, const std::string& resource,
                         Route::Handler handler);

            void Remove(Router& router, Http::Method method, const std::string& resource);

            void Head(Router& router, const std::string& resource, Route::Handler handler);

            void NotFound(Router& router, Route::Handler handler);

            namespace details {
                template<class... Args>
                struct TypeList {
                    template<size_t N>
                    struct At {
                        static_assert(N < sizeof...(Args), "Invalid index");
                        typedef typename std::tuple_element<N, std::tuple<Args...>>::type Type;
                    };
                };

                template<typename... Args>
                void static_checks() {
                    static_assert(sizeof...(Args) == 2, "Function should take 2 parameters");
//            typedef details::TypeList<Args...> Arguments;
// Disabled now as it
// 1/ does not compile
// 2/ might not be relevant
#if 0
                    static_assert(std::is_same<Arguments::At<0>::Type, const Rest::Request&>::value, "First argument should be a const Rest::Request&");
                    static_assert(std::is_same<typename Arguments::At<0>::Type, Http::Response>::value, "Second argument should be a Http::Response");
#endif
                }
            } // namespace details

            template<typename Result, typename Cls, typename... Args, typename Obj>
            Route::Handler bind(Result (Cls::*func)(Args...), Obj obj) {
                details::static_checks<Args...>();

                return [=](const Rest::Request& request, Http::ResponseWriter response) {

                    LOG(INFO) << "request address=" << request.address().host() << ":" << request.address().port()
                              << " method=" << request.method() << " resource=" << request.resource() << " body="
                              << request.body();
                    (obj->*func)(request, std::move(response));
                    return Route::Result::Ok;
                };
            }

            template<typename Result, typename Cls, typename... Args, typename Obj>
            Route::Handler bind(Result (Cls::*func)(Args...), std::shared_ptr<Obj> objPtr) {
                details::static_checks<Args...>();

                return [=](const Rest::Request& request, Http::ResponseWriter response) {
                    (objPtr.get()->*func)(request, std::move(response));

                    return Route::Result::Ok;
                };
            }

            template<typename Result, typename... Args>
            Route::Handler bind(Result (* func)(Args...)) {
                details::static_checks<Args...>();

                return [=](const Rest::Request& request, Http::ResponseWriter response) {
                    func(request, std::move(response));

                    return Route::Result::Ok;
                };
            }

        } // namespace Routes
    } // namespace Rest
} // namespace Pistache
