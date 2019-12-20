#include <iostream>
#include <csignal>
#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>

#include "pcaphandler.h"
#include "socketgre.h"
#include "pcapexport_extension.h"
#include "versioninfo.h"
#include "syshelp.h"

std::shared_ptr<PcapHandler> handler = nullptr;

int get_port_mirror_config_param(std::string& proto_config, std::vector<std::string>& extension_remoteips,
    std::string& extension_bind_device, int& extension_pmtudisc);
int get_traffic_monitor_config_param(std::string& monitor_config, std::vector<std::string>& collectorips);

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
             "set gre remote IPs(ipv4/ipv6), seperate by ',' Example: -r 8.8.4.4,fe80::250::11")
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
            ("nofilter",
                 "force no filter; In online mode, only use when GRE interface "
                 "is set via CLI, AND you confirm that the snoop interface is "
                 "different from the gre interface.")
            ("proto-config", boost::program_options::value<std::string>()->value_name("PROTO-CONFIG"),
                 "(Experimental feature. For linux platform only.) "
                 "The port mirror extension's configuration in "
                 "JSON string format. If not set, packet-agent will use default "
                 "tunnel protocol (GRE with key) to export packet. "
                 "If set, -r, -B, -M is ignore.")
            ("monitor-config", boost::program_options::value<std::string>()->value_name("MONITOR-CONFIG"),
                 "(Experimental feature. For linux platform only.) "
                 "The traffic monitor extension's configuration in "
                 "JSON string format. If not set, network monitor is disabled. "
                 "Now only support NetFlow V1/5/7 protocol.");

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


    // exporter params:
    std::string bind_device = "";
    int pmtudisc = -1;
    std::vector<std::string> remoteips;
    std::vector<std::string> collectorips;

#ifdef WIN32  
    // TODO: support proto-config and pmtudisc_option
    if (!vm.count("remoteip")) {
        std::cerr << StatisLogContext::getTimeString() << "Please set gre remote ip with --remoteip or -r."
                  << std::endl;
        return 1;
    }
    std::string remoteip = vm["remoteip"].as<std::string>();        
    boost::algorithm::split(remoteips, remoteip, boost::algorithm::is_any_of(","));

    if (vm.count("bind_device")) {
        bind_device = vm["bind_device"].as<std::string>();
    }
#else
    if (vm.count("proto-config")) {
        std::string proto_config_json_str = vm["proto-config"].as<std::string>();
        get_port_mirror_config_param(proto_config_json_str, remoteips, bind_device, pmtudisc);
        if (remoteips.size() == 0) {
            std::cerr << StatisLogContext::getTimeString() << "Please set port mirror extension remote ip in json. "
                      << std::endl;
            return 1;
        }

    } else {
        if (!vm.count("remoteip")) {
            std::cerr << StatisLogContext::getTimeString() << "Please set gre remote ip with --remoteip or -r."
                      << std::endl;
            return 1;
        }
        std::string remoteip = vm["remoteip"].as<std::string>();        
        boost::algorithm::split(remoteips, remoteip, boost::algorithm::is_any_of(","));

        if (vm.count("bind_device")) {
            bind_device = vm["bind_device"].as<std::string>();
        }

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
    }
    if (vm.count("monitor-config")) {
        std::string monitor_config = vm["monitor-config"].as<std::string>();
        get_traffic_monitor_config_param(monitor_config, collectorips);
    }
#endif // WIN32

    int keybit = vm["keybit"].as<int>();



    // pcap params:
    // filter option
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
        
        for (size_t i = 0; i < collectorips.size(); ++i) {
            if (filter.length() > 0) {
                filter = filter + " and not host " + collectorips[i];
            } else {
                filter = "not host " + collectorips[i];
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



    // system params:
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



    // init handler
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

    // init signal
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

    // init exporter
    std::shared_ptr<PcapExportBase> exporter;
#ifdef WIN32
    if (vm.count("proto-config")) {
        std::cerr << StatisLogContext::getTimeString()
                  << "Not support --proto-config on Windows platform. Run as classic mode(Gre with key)" << std::endl;
    }
    if (vm.count("monitor-config")) {
        std::cerr << StatisLogContext::getTimeString()
                  << "Not support --monitor-config on Windows platform. " << std::endl;
    }
    exporter = std::make_shared<PcapExportGre>(remoteips, keybit, bind_device, pmtudisc);
    int err = exporter->initExport();
    if (err != 0) {
        std::cerr << StatisLogContext::getTimeString()
        << "greExport initExport failed." << std::endl;
        return err;
    }
    handler->addExport(exporter);
#else
    if (vm.count("proto-config")) {
        // export gre/erspan type1/2/3/vxlan...
        std::string proto_config_json_str = vm["proto-config"].as<std::string>();
        exporter = std::make_shared<PcapExportExtension>(PcapExportExtension::EXT_TYPE_PORT_MIRROR, proto_config_json_str);
        int err = exporter->initExport();
        if (err != 0) {
            std::cerr << StatisLogContext::getTimeString()
            << "PcapExportExtension proto-config initExport failed." << std::endl;
            return err;
        }
        handler->addExport(exporter);
    } else {
        // export gre
        exporter = std::make_shared<PcapExportGre>(remoteips, keybit, bind_device, pmtudisc);
        int err = exporter->initExport();
        if (err != 0) {
            std::cerr << StatisLogContext::getTimeString()
            << "greExport initExport failed." << std::endl;
            return err;
        }
        handler->addExport(exporter);
    }

    if (vm.count("monitor-config")) {
        std::string monitor_config_json_str = vm["monitor-config"].as<std::string>();
        exporter = std::make_shared<PcapExportExtension>(PcapExportExtension::EXT_TYPE_TRAFFIC_MONITOR, monitor_config_json_str);
        int err = exporter->initExport();
        if (err != 0) {
            std::cerr << StatisLogContext::getTimeString()
            << "PcapExportExtension monitor-config initExport failed." << std::endl;
            return err;
        }
        handler->addExport(exporter);
    }
#endif

    // begin pcap snoop
    std::cout << StatisLogContext::getTimeString() << "Start pcap snoop." << std::endl;
    handler->startPcapLoop(nCount);
    std::cout << StatisLogContext::getTimeString() << "End pcap snoop." << std::endl;

    // end
    exporter->closeExport();
    return 0;
}




int get_port_mirror_config_param(std::string& proto_config, std::vector<std::string>& extension_remoteips,
            std::string& extension_bind_device, int& extension_pmtudisc) {
    std::stringstream ss(proto_config);
    boost::property_tree::ptree proto_config_tree;

    extension_remoteips.clear();
    extension_bind_device = "";
    extension_pmtudisc = -1;

    try {
        boost::property_tree::read_json(ss, proto_config_tree);
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << "pktminerg: " << "Parse proto_config json string failed!" << std::endl;
        return -1;
    }

    if (proto_config_tree.get_child_optional("ext_params")) {
        boost::property_tree::ptree& config_items = proto_config_tree.get_child("ext_params");

        // ext_params.remoteips[]
        if (config_items.get_child_optional("remoteips")) {
            boost::property_tree::ptree& remote_ip_tree = config_items.get_child("remoteips");

            for (auto it = remote_ip_tree.begin(); it != remote_ip_tree.end(); it++) {
                extension_remoteips.push_back(it->second.get_value<std::string>());
            }
        }

        // ext_params.bind_device
        if (config_items.get_child_optional("bind_device")) {
            extension_bind_device = config_items.get<std::string>("bind_device");
        }

        // ext_params.pmtudisc
        if (config_items.get_child_optional("pmtudisc_option")) {
            std::string pmtudisc_option = config_items.get<std::string>("pmtudisc_option");
            if (pmtudisc_option == "do") {
                extension_pmtudisc = IP_PMTUDISC_DO;
            } else if (pmtudisc_option == "dont") {
                extension_pmtudisc = IP_PMTUDISC_DONT;
            } else if (pmtudisc_option == "want") {
                extension_pmtudisc = IP_PMTUDISC_WANT;
            } else {
                std::cerr << "pktminerg: " << "pmtudisc_option config invalid. Reset to -1." << std::endl;
                extension_pmtudisc = -1;
            }
        }
    }
    return 0;
}

int get_traffic_monitor_config_param(std::string& monitor_config, std::vector<std::string>& collectorips) {
    std::stringstream ss(monitor_config);
    boost::property_tree::ptree monitor_config_tree;

    collectorips.clear();

    try {
        boost::property_tree::read_json(ss, monitor_config_tree);
    } catch (boost::property_tree::ptree_error & e) {
        std::cerr << "pktminerg: " << "Parse monitor_config json string failed!" << std::endl;
        return -1;
    }

    // ext_params
    if (monitor_config_tree.get_child_optional("ext_params")) {
        boost::property_tree::ptree& config_items = monitor_config_tree.get_child("ext_params");

        // ext_params.collectors_ipport[]
        if (config_items.get_child_optional("collectors_ipport")) {
            boost::property_tree::ptree& collectors_ipport = config_items.get_child("collectors_ipport");
            for (auto it = collectors_ipport.begin(); it != collectors_ipport.end(); it++) {
                // ext_params.collectors_ipport[].ip
                if (it->second.get_child_optional("ip")) {
                    collectorips.push_back(it->second.get<std::string>("ip"));
                }
            }
        }
    }
    return 0;
}
