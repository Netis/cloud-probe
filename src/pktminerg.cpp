#include <iostream>
#include <csignal>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include "pcaphandler.h"
#include "socketgre.h"
#include "socketvxlan.h"
#include "socketzmq.h"
#include "versioninfo.h"
#include "syshelp.h"
#ifndef WIN32
    #include "agent_control_plane.h"

#endif

std::vector<std::shared_ptr<PcapHandler>> handlers;
bool isLoop = true;

static void getAllRemoteIP(std::vector<std::string > & remoteIps, int argc, char* argv[]) {
    for (int i = 1; i < argc; i++) {
        std::string argStr {argv[i]};
        std::vector<std::string> args;
        boost::algorithm::split(args, argStr, boost::algorithm::is_any_of(" "));
        for (uint8_t i = 0; i < args.size()-1; i++) {
            if ((args[i] == "-r" || args[i] == "remoteip")) {
                std::vector<std::string> ips;
                boost::algorithm::split(ips, args[i+1], boost::algorithm::is_any_of(","));
                remoteIps.insert(remoteIps.end(), ips.cbegin(), ips.cend());
                continue;
            }
        }
    }
    return;
}

int main(int argc, char* argv[]) {
    boost::program_options::options_description generic("Generic options");
    generic.add_options()
            ("version,v", "show version.")
            ("help,h", "show help.");

    boost::program_options::options_description desc("Allowed options");
    desc.add_options()
            ("interface,i", boost::program_options::value<std::string>()->value_name("NIC"),
             "interface to capture packets")
            ("bind_device,B", boost::program_options::value<std::string>()->value_name("BIND"),
             "send GRE packets from this binded device.(Not available on Windows)")
            ("pmtudisc_option,M", boost::program_options::value<std::string>()->value_name("MTU"),
             " Select Path MTU Discovery strategy.  pmtudisc_option may be either do (prohibit fragmentation, even local one), want (do PMTU discovery, fragment locally when packet size is large), or dont (do not set DF flag)")
            ("pcapfile,f", boost::program_options::value<std::string>()->value_name("PATH"),
             "specify pcap file for offline mode, mostly for test")
            ("remoteip,r", boost::program_options::value<std::string>()->value_name("IPs"),
             "set gre remote IPs, seperate by ',' Example: -r 8.8.4.4,8.8.8.8")
            ("zmq_port,z", boost::program_options::value<int>()->default_value(0)->value_name("ZMQ_PORT"),
             "set remote zeromq server port to receive packets reliably; ZMQ_PORT default value 0 means disable.")
            ("zmq_hwm,m", boost::program_options::value<int>()->default_value(4096)->value_name("ZMQ_HWM"),
             "set zeromq queue high watermark; ZMQ_HWM default value 100.")
            ("keybit,k", boost::program_options::value<int>()->default_value(1)->value_name("KEYBIT"),
             "set gre key bit; BIT defaults 1")
            ("vni,n", boost::program_options::value<int>()->value_name("VNI"),
             "set gre key bit; BIT defaults 1")
            ("snaplen,s", boost::program_options::value<int>()->default_value(2048)->value_name("LENGTH"),
             "set snoop packet snaplen; LENGTH defaults 2048 and units byte")
            ("timeout,t", boost::program_options::value<int>()->default_value(3)->value_name("TIME"),
             "set snoop packet timeout; TIME defaults 3 and units second")
            ("buffsize,b", boost::program_options::value<int>()->default_value(256)->value_name("SIZE"),
             "set snoop buffer size; SIZE defaults 256 and units MB")
            ("count,c", boost::program_options::value<int>()->default_value(0)->value_name("COUNT"),
             "exit after receiving count packets; COUNT defaults; count<=0 means unlimited")
            ("priority,p", "set high priority mode")
            ("cpu", boost::program_options::value<int>()->value_name("ID"), "set cpu affinity ID")
            ("expression", boost::program_options::value<std::vector<std::string>>()->value_name("FILTER"),
             R"(filter packets with FILTER; FILTER as same as tcpdump BPF expression syntax)")

            ("dump", boost::program_options::value<std::string>()->default_value("./")->value_name("DUMP"),
             "specify pcap dump file dump dir")
            ("slice", boost::program_options::value<int>()->default_value(0)->value_name("SLICE"),
             "specify the length of the received packets that will be transferred or dumped.")
            ("interval", boost::program_options::value<int>()->default_value(-1)->value_name("INTERVAL"),
             "specify the interval for dump file creation")
            ("mbps", boost::program_options::value<double>()->default_value(0)->value_name("mbps"),
             "specify a floating point value for the Mbps rate that pktmg should send packets at.")
            ("dir", boost::program_options::value<std::string>()->value_name("DIR"),
             "specify the direction determination expression")
            ("nofilter",
             "force no filter; In online mode, only use when GRE interface "
                 "is set via CLI, AND you confirm that the snoop interface is "
                 "different from the gre interface.");

    boost::program_options::positional_options_description position;
    position.add("expression", -1);

    boost::program_options::options_description all;
    all.add(generic).add(desc);

    // help
    if (argc == 1 || strcmp(argv[1], "--help") == 0) {
        std::cout << all << std::endl;
        return 0;
    }

    // version
    if (strcmp(argv[1], "--version") == 0) {
        showVersion();
        return 0;
    }

    //got all remote IPs
    std::vector<std::string> allRemoteIPs;
    getAllRemoteIP(allRemoteIPs, argc, argv);

    for (uint8_t i = 1; i < argc; i++) {
        std::string str{argv[i]};

        std::vector<std::string> splits;
        boost::split(splits, str, boost::is_any_of(" "));
        std::vector<char *> args;
        std::string first{"pktminerg"};
        args.push_back((char *) first.data());

        for (size_t i = 0; i < splits.size(); i++) {
            args.push_back((char *) splits[i].data());
            if ((splits[i] == "-i" || splits[i] == "--interface") && i < splits.size() - 1) {
                ++i;
                args.push_back((char *) splits[i].data());
                while (i + 1 < splits.size() && splits[i + 1][0] != '-') {
                    i++;
                    args.push_back((char *) "-i");
                    args.push_back((char *) splits[i].data());
                }
            }
        }
        args.push_back(nullptr);

        boost::program_options::variables_map vm;
        try {
            boost::program_options::parsed_options parsed = boost::program_options::command_line_parser(
                    (int) (args.size() - 1), &*args.begin())
                    .options(all).positional(position).run();
            boost::program_options::store(parsed, vm);
            boost::program_options::notify(vm);
        } catch (boost::program_options::error &e) {
            std::cerr << StatisLogContext::getTimeString() << "Parse command line failed, error is " << e.what() << "."
                      << std::endl;
            return 1;
        }

        // check options
        if (vm.count("interface") + vm.count("pcapfile") != 1) {
            std::cerr << StatisLogContext::getTimeString()
                      << "Please choice only one snoop mode, from interface use -i or from pcap file use -f ."
                      << std::endl;
            return 1;
        }

        std::string bind_device = "";
        if (vm.count("bind_device")) {
            bind_device = vm["bind_device"].as<std::string>();
        }

        int pmtudisc = -1;
        int update_status = 0;
#ifdef WIN32
        //TODO: support pmtudisc_option on WIN32
#else
        if (vm.count("pmtudisc_option")) {
            const auto pmtudisc_option = vm["pmtudisc_option"].as<std::string>();
            if (pmtudisc_option == "do") {
                pmtudisc = IP_PMTUDISC_DO;
            } else if (pmtudisc_option == "dont") {
                pmtudisc = IP_PMTUDISC_DONT;
            } else if (pmtudisc_option == "want") {
                pmtudisc = IP_PMTUDISC_WANT;
            } else {
                std::cerr << StatisLogContext::getTimeString()
                          << "Wrong value for -M: do, dont, want are valid ones." << std::endl;
                return 1;
            }
        }
        std::shared_ptr<AgentControlPlane> agent_control_plane;
        if (vm.count("control")) {
            const auto daemon_zmq_port = vm["control"].as<int>();
            agent_control_plane = std::make_shared<AgentControlPlane>(daemon_zmq_port);
            agent_control_plane->init_msg_server();
            update_status = 1;
        }
#endif // WIN32


        if (!vm.count("remoteip") && !vm.count("dump")) {
            std::cerr << StatisLogContext::getTimeString()
                      << "Please set gre remote ip with --remoteip (or -r)  or get dump directory with --Dump."
                      << std::endl;
            return 1;
        }

        std::vector<std::string> remoteips;
        if (vm.count("remoteip")) {
            std::string remoteip = vm["remoteip"].as<std::string>();
            boost::algorithm::split(remoteips, remoteip, boost::algorithm::is_any_of(","));
        }

        int zmq_port = vm["zmq_port"].as<int>();
        int zmq_hwm = vm["zmq_hwm"].as<int>();

        int keybit = vm["keybit"].as<int>();

        std::string filter = "";
        if (vm.count("expression")) {
            auto expressions = vm["expression"].as<std::vector<std::string >>();
            for (size_t i = 0; i < expressions.size(); i++) {
                filter = filter + expressions[i] + " ";
                if (expressions[i] == "host" && i + 1 < expressions.size()) {
                    if (i > 0 && expressions[i - 1] == "not") {
                        continue;
                    }
                    if (expressions[i + 1].find("nic.") == 0) {
                        std::vector<std::string> ips;
                        if (!replaceWithIfIp(expressions[i + 1], ips)) {
                            std::cerr << "Please input right interface name." << std::endl;
                            return 1;
                        }
                    }
                }
            }
        }

        // no filter option
        bool nofilter = false;
        if (vm.count("nofilter")) {
            nofilter = true;
            if (vm.count("interface")) {
                if (bind_device == "") {
                    std::cerr << StatisLogContext::getTimeString() << "Can't enable --nofilter option "
                              << "because GRE bind devices(-B) is not set, GRE packet might be sent via packet captured interface(-i)"
                              << std::endl;
                    return 1;
                } else if (bind_device == vm["interface"].as<std::string>()) {
                    std::cerr << StatisLogContext::getTimeString() << "Can't enable --nofilter option "
                              << "because packet captured interface(-i) is equal to GRE bind devices(-B)"
                              << std::endl;
                    return 1;
                } else {
                    // valid
                }
            }
        }

        if (nofilter) {
            filter = "";
        } else {
            for (size_t i = 0; i < allRemoteIPs.size(); ++i) {
                if (filter.length() > 0) {
                    filter = filter + " and not host " + allRemoteIPs[i];
                } else {
                    filter = "not host " + allRemoteIPs[i];
                }
            }
        }

        // dump option
        // dump option
        bool dumpfile = false;
        if (vm["interval"].as<int>() >= 0) {
            dumpfile = true;
        }

        // snoop mode
        pcap_init_t param;
        param.buffer_size = vm["buffsize"].as<int>() * 1024 * 1024;
        param.snaplen = vm["snaplen"].as<int>();
        param.promisc = 0;
        param.timeout = vm["timeout"].as<int>() * 1000;
        param.need_update_status = update_status;
        int nCount = vm["count"].as<int>();
        if (nCount < 0) {
            nCount = 0;
        }

        // priority option
        if (vm.count("priority")) {
            set_high_setpriority();
        }

        // cpu option
        if (vm.count("cpu")) {
            int cpuid = vm["cpu"].as<int>();
            if (set_cpu_affinity(cpuid) == 0) {
                std::cout << StatisLogContext::getTimeString() << "Call set_cpu_affinity(" << cpuid << ") success."
                          << std::endl;
            } else {
                std::cerr << StatisLogContext::getTimeString() << "Call set_cpu_affinity(" << cpuid << ") failed."
                          << std::endl;
                return 1;
            }
        }

        std::shared_ptr<PcapHandler> handler;

        if (vm.count("pcapfile")) {
            // offline
            std::string path = vm["pcapfile"].as<std::string>();
            handler = std::make_shared<PcapOfflineHandler>(vm["dump"].as<std::string>(), vm["interval"].as<int>());
            if (handler->openPcap(path, param, "", dumpfile) != 0) {
                std::cerr << StatisLogContext::getTimeString() << "Call PcapOfflineHandler openPcap failed."
                          << std::endl;
                return 1;
            }
        } else if (vm.count("interface")) {
            // online
            std::string dev = vm["interface"].as<std::string>();
            handler = std::make_shared<PcapLiveHandler>(vm["dump"].as<std::string>(), vm["interval"].as<int>());
            if (vm.count("dir")) {
                handler->setDirIPPorts(vm["dir"].as<std::string>());
            }
            if (handler->openPcap(dev, param, filter, dumpfile) != 0) {
                std::cerr << StatisLogContext::getTimeString() << "Call PcapLiveHandler openPcap failed." << std::endl;
                return 1;
            }

        } else {
            std::cerr << StatisLogContext::getTimeString()
                      << "Please choice snoop mode: from interface use -i or from pcap file use -f." << std::endl;
            return 1;
        }
        std::shared_ptr<PcapExportBase> exportPtr = nullptr;
        if (zmq_port != 0) {
            exportPtr = std::make_shared<PcapExportZMQ>(remoteips, zmq_port, zmq_hwm, keybit, bind_device, param.buffer_size,vm["mbps"].as<double>());
            int err = exportPtr->initExport();
            if (err != 0) {
                std::cerr << StatisLogContext::getTimeString()
                          << "zmqExport initExport failed." << std::endl;
                return err;
            }
        }
        else if(vm.count("vni")){
            int vni = vm["vni"].as<int>();
            exportPtr = std::make_shared<PcapExportVxlan>(remoteips, vni, bind_device, pmtudisc, vm["mbps"].as<double>());
            int err = exportPtr->initExport();
            if (err != 0) {
                std::cerr << StatisLogContext::getTimeString() << "vxlanExport initExport failed." << std::endl;
                return err;
            }
        }
        else{
            // export gre
            exportPtr = std::make_shared<PcapExportGre>(remoteips, keybit, bind_device, pmtudisc, vm["mbps"].as<double>());
            int err = exportPtr->initExport();
            if (err != 0) {
                std::cerr << StatisLogContext::getTimeString() << "greExport initExport failed." << std::endl;
                return err;
            }
        }
        if (vm.count("slice")) {
            handler->setSliceLength(vm["slice"].as<int>());
        }
        handler->addExport(exportPtr);
        handlers.push_back(handler);
    }

    // signal
    std::signal(SIGINT, [](int) {
        isLoop = false;
    });
    std::signal(SIGTERM, [](int) {
        isLoop = false;
    });
    // begin pcap snoop

    std::cout << StatisLogContext::getTimeString() << "Start pcap snoop." << std::endl;
    while (isLoop && !handlers.empty()) {
        for (auto iter = handlers.begin(); iter != handlers.end() && isLoop;) {
            if ((*iter)->handlePacket()) {
                ++iter;
            } else {
                (*iter)->closeExports();
                iter = handlers.erase(iter);
            }
        }

    }

    // end
    for (auto handler: handlers) {
        handler->closeExports();
    }
    return 0;
}
