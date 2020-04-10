#include <iostream>
#include <csignal>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include "pcaphandler.h"
#include "socketgre.h"
#include "versioninfo.h"
#include "syshelp.h"
#ifndef WIN32
    #include "agent_control_plane.h"
#endif

std::shared_ptr<PcapHandler> handler = nullptr;

int main(int argc, const char* argv[]) {
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
            ("keybit,k", boost::program_options::value<int>()->default_value(1)->value_name("BIT"),
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
            ("dump", "specify dump file, mostly for integrated test")
            ("control", boost::program_options::value<int>()->value_name("CONTROL_PORT"),
             "set zmq listen port for agent daemon control. Control server won't be up if this option is not set")
            ("nofilter",
             "force no filter; In online mode, only use when GRE interface "
                 "is set via CLI, AND you confirm that the snoop interface is "
                 "different from the gre interface.");

    boost::program_options::positional_options_description position;
    position.add("expression", -1);

    boost::program_options::options_description all;
    all.add(generic).add(desc);

    boost::program_options::variables_map vm;
    try {
        boost::program_options::parsed_options parsed = boost::program_options::command_line_parser(argc, argv)
                .options(all).positional(position).run();
        boost::program_options::store(parsed, vm);
        boost::program_options::notify(vm);
    } catch (boost::program_options::error& e) {
        std::cerr << StatisLogContext::getTimeString() << "Parse command line failed, error is " << e.what() << "."
                  << std::endl;
        return 1;
    }

    // help
    if (vm.count("help")) {
        std::cout << all << std::endl;
        return 0;
    }

    // version
    if (vm.count("version")) {
        showVersion();
        return 0;
    }

    // check options
    if (vm.count("interface") && vm.count("pcapfile")) {
        std::cerr << StatisLogContext::getTimeString()
                  << "Please choice only one snoop mode, from interface use -i or from pcap file use -f." << std::endl;
        return 1;
    }

    std::string bind_device = "";
    if (vm.count("bind_device")) {
        bind_device = vm["bind_device"].as<std::string>();
    }

    int pmtudisc = -1;
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
    }
#endif // WIN32


    if (!vm.count("remoteip")) {
        std::cerr << StatisLogContext::getTimeString() << "Please set gre remote ip with --remoteip or -r."
                  << std::endl;
        return 1;
    }

    std::string remoteip = vm["remoteip"].as<std::string>();
    std::vector<std::string> remoteips;
    boost::algorithm::split(remoteips, remoteip, boost::algorithm::is_any_of(","));

    int keybit = vm["keybit"].as<int>();

    std::string filter = "";
    if (vm.count("expression")) {
        auto expressions = vm["expression"].as<std::vector<std::string>>();
        std::for_each(expressions.begin(), expressions.end(),
                      [&filter](const std::string& express) { filter = filter + express + " "; });
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
        for (size_t i = 0; i < remoteips.size(); ++i) {
            if (filter.length() > 0) {
                filter = filter + " and not host " + remoteips[i];
            } else {
                filter = "not host " + remoteips[i];
            }
        }
    }

    // dump option
    bool dumpfile = false;
    if (vm.count("dump")) {
        dumpfile = true;
    }

    // snoop mode
    pcap_init_t param;
    param.buffer_size = vm["buffsize"].as<int>() * 1024 * 1024;
    param.snaplen = vm["snaplen"].as<int>();
    param.promisc = 0;
    param.timeout = vm["timeout"].as<int>() * 1000;
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

    if (vm.count("pcapfile")) {
        // offline
        std::string path = vm["pcapfile"].as<std::string>();
        handler = std::make_shared<PcapOfflineHandler>();
        if (handler->openPcap(path, param, "", dumpfile) != 0) {
            std::cerr << StatisLogContext::getTimeString() << "Call PcapOfflineHandler openPcap failed." << std::endl;
            return 1;
        }
    } else if (vm.count("interface")) {
        // online
        std::string dev = vm["interface"].as<std::string>();
        handler = std::make_shared<PcapLiveHandler>();
        if (handler->openPcap(dev, param, filter, dumpfile) != 0) {
            std::cerr << StatisLogContext::getTimeString() << "Call PcapLiveHandler openPcap failed." << std::endl;
            return 1;
        }

    } else {
        std::cerr << StatisLogContext::getTimeString()
                  << "Please choice snoop mode: from interface use -i or from pcap file use -f." << std::endl;
        return 1;
    }

    // signal
    std::signal(SIGINT, [](int) {
        if (handler != nullptr) {
            handler->stopPcapLoop();
        }
    });
    std::signal(SIGTERM, [](int) {
        if (handler != nullptr) {
            handler->stopPcapLoop();
        }
    });

    // export gre
    std::shared_ptr<PcapExportBase> greExport = std::make_shared<PcapExportGre>(remoteips, keybit, bind_device, pmtudisc);
    int err = greExport->initExport();
    if (err != 0) {
        std::cerr << StatisLogContext::getTimeString()
                  << "greExport initExport failed." << std::endl;
        return err;
    }
    handler->addExport(greExport);

    // begin pcap snoop

    std::cout << StatisLogContext::getTimeString() << "Start pcap snoop." << std::endl;
    handler->startPcapLoop(nCount);
    std::cout << StatisLogContext::getTimeString() << "End pcap snoop." << std::endl;

    // end
    greExport->closeExport(); 
    return 0;
}
