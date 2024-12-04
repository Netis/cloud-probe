#include <iostream>
#include <csignal>
#include <locale>
#include <cstring>
#include <stdio.h>
#include <cctype>

#include <boost/program_options.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/filesystem.hpp>

#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/RollingFileAppender.hh"
#include "log4cpp/DailyRollingFileAppender.hh"
#include "log4cpp/SimpleLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/PropertyConfigurator.hh"
#include "log4cpp/Configurator.hh"


#include "pcaphandler.h"
#include "socketgre.h"
#include "socketzmq.h"
#include "socketvxlan.h"
#include "versioninfo.h"
#include "syshelp.h"
#include "agent_control_plane.h"
#include "logfilecontext.h"


#define  LOG_FILE_DEFAULT_SIZE_IN_BYTES     (1024 * 1024 * 1024)  //1GB
#define  LOG_FILE_DEFAULT_BACKUP_COUNT      (10)
#define  LOG_FILE_DEFAULT_LEVEL             (log4cpp::Priority::INFO)
#define  LOG_FILE_DEFAULT_NAME              ("pktminerg.log")

#ifdef _WIN32

//#pragma comment( linker, "/subsystem:\"windows\" /entry:\"mainCRTStartup\"" )
#endif

std::vector<std::shared_ptr<PcapHandler>> handlers;
bool isLoop = true;

// static void getAllRemoteIP(std::vector<std::string > & remoteIps, int argc, char* argv[]) {
//     for (int i = 1; i < argc; i++) {
//         std::string argStr {argv[i]};
//         std::vector<std::string> args;
//         boost::algorithm::split(args, argStr, boost::algorithm::is_any_of(" "));
//         for (uint8_t i = 0; i < args.size()-1; i++) {
//             if ((args[i] == "-r" || args[i] == "remoteip")) {
//                 std::vector<std::string> ips;
//                 boost::algorithm::split(ips, args[i+1], boost::algorithm::is_any_of(","));
//                 remoteIps.insert(remoteIps.end(), ips.cbegin(), ips.cend());
//                 continue;
//             }
//         }
//     }
//     return;
// }

static void getAllRemoteIPViaGroupOptions(std::vector<std::string>& remoteIps, const std::vector<std::string>& group_options) {
    for (uint32_t i = 0; i < group_options.size(); i++) {
        std::string argStr = group_options[i];
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

static std::string getProccssIdWithContainer(const std::string &containerId, LogFileContext& ctx) {
	char buffer[80] = {0};
#ifndef _WIN32
    FILE *fp;
    std::string id = containerId;
    std::size_t pos = containerId.find("://");
    if (pos != std::string::npos && pos+3 < containerId.length()) {
        id = containerId.substr(pos+3);
    }

    std::string output_buffer = std::string("Get Id:") + id +std::string(" from CPM.");
    ctx.log(output_buffer, log4cpp::Priority::INFO);
    std::cout << StatisLogContext::getTimeString() << output_buffer << std::endl;
    //get pid with docker
    auto cmd = std::string("docker inspect ") + id + std::string("|grep -i \"pid\"");
    fp=popen(cmd.c_str(),"r");
    if (!fgets(buffer,sizeof(buffer),fp)) {
        pclose(fp);
        cmd = std::string("crictl inspect ") + id + std::string("|grep -i \"pid\""); 
        fp=popen(cmd.c_str(),"r");
        fgets(buffer,sizeof(buffer),fp);
    }
    std::cout<<StatisLogContext::getTimeString()<<"Get Pid with docker/crictl:"<<buffer<<std::endl;
    pclose(fp);
    if (strlen(buffer) != 0) {
        std::string pidStr = buffer;
        int leftIndex = pidStr.find(":");
        int rightIndex = pidStr.find(",");
        pidStr = pidStr.substr(leftIndex+1, rightIndex-leftIndex-1);
        if (pidStr[0]==' ') {
            pidStr = pidStr.substr(1,pidStr.length()-1);
        }
        std::cout<<StatisLogContext::getTimeString()<<"Get PidNum with docker/crictl:"<<pidStr<<std::endl;
        return pidStr;
    } else {     
        auto cmd = boost::str(
        boost::format("sh get_pid_with_container.sh %1%") % id);
	    fp=popen(cmd.c_str(),"r");
	    fgets(buffer,sizeof(buffer),fp);
        pclose(fp);
    }   

    if (strlen(buffer) == 0) {
        std::string output_buffer = std::string("Can't get pid for the containerId:") + id;
        ctx.log(output_buffer, log4cpp::Priority::ERROR);
        std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
        return std::string();
    }
#endif	
    return std::string(buffer, strlen(buffer) - 1);
}

// static uint64_t handle_file_size_param(std::string file_size) {
//     uint64_t log_max_file_size = 1024 * 1024 * 1024;
//     size_t len = file_size.size();
//     uint64_t factor = 1;
//     std::string digit;
//     // boost::regex expression("^[1-9]+[0-9]*[kKmMgG]?$");
//     // boost::cmatch what;
//     // if (boost::regex_match(i->Name(), what, expression)) {
//     if (len) {        
//         if (::isalpha(file_size[len - 1])) {
//             switch (file_size[len - 1]) {
//                 case 'k':
//                 case 'K':
//                     factor = 1024;
//                     break;
//                 case 'm':
//                 case 'M':
//                     factor = 1024 * 1024;
//                     break;
//                 case 'g':
//                 case 'G':
//                     factor = 1024 * 1024 * 1024;
//                     break;
//                 default:
//                     factor = 1;
//                     break;
//             }
//             digit = file_size.substr(0, len - 1);
//         } else {
//             digit = file_size;
//             factor = 1;
//         }

//         try {
//             log_max_file_size = std::stoul(digit) * factor;
//         } catch (...) {
//             std::cerr << "Invalid log file size parameter. use default value." << std::endl;
//             return 1024 * 1024 * 1024;
//         }
//     } else {
//         log_max_file_size = 1024 * 1024 * 1024;
//     }
//     return log_max_file_size;
// }

static bool init_log4cpp(bool logfile_daily, uint64_t logfile_size, uint32_t logfile_backup_count, 
                log4cpp::Priority::Value logfile_level, std::string logfile_name ) {

    if (logfile_backup_count == 0) {
        std::cerr << "logfile_backup_count is configure as 0, reset to 1" << std::endl;
        logfile_backup_count = 1;
    }

    log4cpp::Category& root = log4cpp::Category::getRoot();
    root.setPriority(logfile_level);

    log4cpp::Appender *appender = nullptr;
    if (logfile_daily) {
        appender = new log4cpp::DailyRollingFileAppender("daily_rolling", logfile_name, logfile_backup_count);
    } else if (logfile_size) {
        appender = new log4cpp::RollingFileAppender("rolling", logfile_name, logfile_size, logfile_backup_count);
    } else {
        std::cerr << "logfile_size and logfile_daily is all 0, treat logfile_size = 1G and logfile_daily = false" << std::endl;
        logfile_size = 1024 * 1024 * 1024;
        logfile_daily = false;
        appender = new log4cpp::RollingFileAppender("rolling", logfile_name, logfile_size, logfile_backup_count);
    }
    log4cpp::PatternLayout *patternLayout = new log4cpp::PatternLayout();
    patternLayout->setConversionPattern("%m %n");
    appender->setLayout(patternLayout);
    root.addAppender(appender);

    // dump
    std::cout << "logfile_daily : " << (logfile_daily ? "true" : "false")
            << ", logfile_size : " << logfile_size
            << ", logfile_backup_count : " << logfile_backup_count
            << ", logfile_level : " << logfile_level
            << ", logfile_name : " << logfile_name << std::endl;
    return true;
}


static int classify_all_options(int argc, char* argv[], std::vector<std::string>& global_options, std::vector<std::string>& group_options) {
    global_options.clear();
    group_options.clear();
    for (int i = 1; i < argc; i++) { // skip program title
        std::string option = argv[i];
        if (std::strcmp(argv[i], "--version") == 0 || std::strcmp(argv[i], "-v") == 0
                || std::strcmp(argv[i], "--help") == 0 || std::strcmp(argv[i], "-h") == 0
                || std::strcmp(argv[i], "--logfile-enable") == 0 || std::strcmp(argv[i], "--logfile-daily") == 0
                || std::strcmp(argv[i], "--logfile-config-local-encoding") == 0 ) {
            global_options.push_back(argv[i]);
        } else if (std::strcmp(argv[i], "--logfile-size") == 0
                || std::strcmp(argv[i], "--logfile-backup-count") == 0 || std::strcmp(argv[i], "--logfile-level") == 0
                || std::strcmp(argv[i], "--logfile-name") == 0 || std::strcmp(argv[i], "--logfile-config-file") == 0) {
            global_options.push_back(argv[i]);
            global_options.push_back(argv[++i]);
        } else if (option.find("--logfile-size=") == 0 
                || option.find("--logfile-backup-count=") == 0 || option.find("--logfile-level=") == 0
                || option.find("--logfile-name=") == 0 || option.find("--logfile-config-file=") == 0) {
            global_options.push_back(option);
        } else {
            group_options.push_back(argv[i]);
        }
    }
    return 0;
}

static std::string get_log_output_path(std::string config_file_path) {
    std::string result = "";

    std::ifstream in(config_file_path.c_str());
    std::string fullLine, command;
    std::string leftSide, rightSide;
    char line[256];
    std::string::size_type length;
    bool partiallyRead(false);	// fix for bug#137, for strings longer than 256 chars

    while (in) {
        if (in.getline(line, 256) || !in.bad()) {
            // either string is read fully or only partially (logical but not read/write error)
            if (partiallyRead)
                fullLine.append(line);
            else
                fullLine = line;
            partiallyRead = (in.fail() && !in.bad());
            if (partiallyRead && !in.eof()) {
                in.clear(in.rdstate() & ~std::ios::failbit);
                continue; // to get full line
            }
        } else {
            break;
        }
        /* if the line contains a # then it is a comment
            if we find it anywhere other than the beginning, then we assume 
            there is a command on that line, and it we don't find it at all
            we assume there is a command on the line (we test for valid 
            command later) if neither is true, we continue with the next line
        */
        length = fullLine.find('#');
        if (length == std::string::npos) {
            command = fullLine;
        } else if (length > 0) {
            command = fullLine.substr(0, length);
        } else {
            continue;
        }

        // check the command and handle it
        length = command.find('=');
        if (length != std::string::npos) {
            leftSide = command.substr(0, length);
            rightSide = command.substr(length + 1, command.size() - length);
            boost::algorithm::trim(leftSide);
            boost::algorithm::trim(rightSide);
        } else {
            continue;
        }
        if (leftSide.find(".fileName") != std::string::npos) {
            result = rightSide;
            in.close();
            return result;
        }
    }
    return result;
}

int main(int argc, char* argv[]) {
    boost::program_options::options_description generic("Generic options");
    std::shared_ptr<AgentControlPlane> agent_control_plane;
    
    std::ofstream test("..\\log.txt", std::ios::app|std::ios::out);
    generic.add_options()
            ("version,v", "show version.")
            ("help,h", "show help.")
// #ifdef _WIN32
//             ("logfile-config-local-encoding", "treat log config file as local encoding. If not specified, treat config file as utf-8 encoding. Windows only.")
// #endif
            ;
            // ("logfile-enable", "enable log file output.")
            // ("logfile-size", boost::program_options::value<std::string>()->default_value("1G")->value_name("LOGFILESIZE"),
            //  "specify the log file max size in bytes,[[x]k | [x]K | [x]m | [x]M | [x]g | [x]G | [x]], 0 to not use. default value 1G")
            // ("logfile-daily", "splitter log file daily, logfile-size must be set to 0")
            // ("logfile-backup-count", boost::program_options::value<uint16_t>()->default_value(10)->value_name("LOGFILEBACKUPCOUNT"),
            //  "specify the log file max backup count, default value 10")
            // ("logfile-level", boost::program_options::value<std::string>()->default_value("DEBUG")->value_name("LOGFILELEVEL"),
            //  "specify the log file output priority level, [DEBUG | INFO | WARN | ERROR], default value DEBUG")
            // ("logfile-name", boost::program_options::value<std::string>()->default_value(std::string("pktminerg.log"))->value_name("LOGFILENAME"),
            //  "specify the log file dir and name, absolute/relative path and file name. use current directory if relative specified")
            // ("logfile-config-file", boost::program_options::value<std::string>()->default_value(std::string(""))->value_name("LOGFILECONFIGFILE"),
            //  "specify the log config file, if not specific, use command line param");

    boost::program_options::options_description desc("\
            Multi-interface is supported and the format should be \" \" \" \" ...\n\
            the rules for each interface are set within \"  \", for example, pktminerg \"-i eth0 -r 10.1.1.1.\" \"-i eth1 -r 10.1.1.2\"\n\n\
Allowed options for each interface:");
    desc.add_options()
            ("interface,i", boost::program_options::value<std::vector<std::string>>()->value_name("NIC"),
             "interface to capture packets")
            ("container,c", boost::program_options::value<std::string>()->value_name("CONTAINER"),
             "container to capture packets")
            ("interface_csets,S",
             boost::program_options::value<std::string>()->default_value("gb2312")->value_name("NIC_CSETS"),
             "characters sets of interface, avl: gb2312 utf8")
            ("bind_device,B", boost::program_options::value<std::string>()->value_name("BIND"),
             "send GRE packets from this binded device.(Not available on Windows)")
            ("pmtudisc_option,M", boost::program_options::value<std::string>()->value_name("MTU"),
             " Select Path MTU Discovery strategy.  pmtudisc_option may be either do (prohibit fragmentation, even local one), want (do PMTU discovery, fragment locally when packet size is large), or dont (do not set DF flag)")
            ("remoteip,r", boost::program_options::value<std::string>()->value_name("IPs"),
             "set gre remote IPs, seperate by ',' Example: -r 8.8.4.4,8.8.8.8")
            ("zmq_port,z", boost::program_options::value<int>()->default_value(0)->value_name("ZMQ_PORT"),
             "set remote zeromq server port to receive packets reliably; ZMQ_PORT default value 0 means disable.")
            ("zmq_hwm", boost::program_options::value<int>()->default_value(100)->value_name("ZMQ_HWM"),
             "set zeromq queue high watermark; ZMQ_HWM default value 100.")
            ("keybit,k", boost::program_options::value<uint32_t>()->default_value(0xffffffff)->value_name("BIT"),
             "set gre key bit; BIT defaults 1")
            ("vni1,n", boost::program_options::value<uint32_t>()->value_name("VNI1"),
             "set udp vxlan vni of version 1;")
              ("vni2", boost::program_options::value<uint32_t>()->value_name("VNI2"),
             "set udp vxlan vni of version 2;")
            ("vxlan_port,x", boost::program_options::value<int>()->default_value(4789)->value_name("VXLAN_PORT"),
             "set udp vxlan port;")
            ("snaplen,s", boost::program_options::value<int>()->default_value(2048)->value_name("LENGTH"),
             "set snoop packet snaplen; LENGTH defaults 2048 and units byte")
            ("timeout,t", boost::program_options::value<int>()->default_value(3000)->value_name("TIME"),
             "set snoop packet timeout; TIME defaults 3000 and units ms")
            ("buffsize,b", boost::program_options::value<int>()->default_value(256)->value_name("SIZE"),
             "set snoop buffer size; SIZE defaults 256 and units MB")
            ("priority,p", "set high priority mode")
            ("cpu", boost::program_options::value<int>()->value_name("ID"), "set cpu affinity ID")
            ("expression", boost::program_options::value<std::vector<std::string>>()->value_name("FILTER"),
             R"(filter packets with FILTER; FILTER as same as tcpdump BPF expression syntax)")
            ("dump", boost::program_options::value<std::string>()->default_value("./")->value_name("DUMP"),
             "specify pcap dump file dump dir")
            ("interval", boost::program_options::value<int>()->default_value(-1)->value_name("INTERVAL"),
             "specify the interval for dump file creation")
            ("control", boost::program_options::value<uint16_t>()->default_value(15566)->value_name("CONTROL_ZMQ_PORT"),
             "set zmq listen port for agent daemon control. Control server won't be up if this option is not set")
            ("slice", boost::program_options::value<int>()->default_value(0)->value_name("SLICE"),
             "specify the length of the received packets that will be transferred or dumped.")
            ("nofilter",
             "force no filter; In online mode, only use when GRE interface "
             "is set via CLI, AND you confirm that the snoop interface is "
             "different from the gre interface.")
            ("mbps", boost::program_options::value<double>()->default_value(0)->value_name("mbps"),
             "specify a floating point value for the Mbps rate that pktmg should send packets at.")
            ("dir", boost::program_options::value<std::string>()->value_name("DIR"),
             "specify the direction determination expression")
             ("capTime", boost::program_options::value<int>()->value_name("CAPTIME"),"set capture time in tranferred packets for VxLan")          
#ifdef _WIN32
             ("macRefreshInterval", boost::program_options::value<int>()->value_name("MACREFRESHINTERVAL"),
             "specify the interval to refresh mac list of VM and PA")
#endif
            ("kvm,m", boost::program_options::value<std::string>()->value_name("KVM"),
             "specify the name of virtual machine in KVM env");

    boost::program_options::positional_options_description position;
    position.add("expression", -1);

    boost::program_options::options_description all;

    all.add(generic).add(desc);

    // separate global options and group options
    std::vector<std::string> global_options;
    std::vector<std::string> group_options;
    classify_all_options(argc, argv, global_options, group_options);

    // = process global options =
    std::vector<char *> general_args;
    std::string general_first{"pktminerg"};
    general_args.push_back((char *) general_first.data());
    for (size_t i = 0; i < global_options.size(); i++) {
        general_args.push_back((char *)global_options[i].data());
    }
    general_args.push_back(nullptr);
    boost::program_options::variables_map vm_general;
    try {       
        boost::program_options::store(
            boost::program_options::parse_command_line(
                (int)(general_args.size() - 1), 
                &*general_args.begin(), 
                generic), 
            vm_general);
        boost::program_options::notify(vm_general);
    } catch (boost::program_options::error &e) {
        std::cerr << StatisLogContext::getTimeString() << "Parse command line failed, error is " << e.what() << "." << std::endl;
        return 1;
    }

    // help
    if (vm_general.count("help")) {
        std::cout << all << std::endl;
        return 0;
    }

    // version
    if (vm_general.count("version")) {
        showVersion();
        return 0;
    }    

    // // log file params
    // bool logfile_enable = false;    
    // uint64_t logfile_size = 1024 * 1024 * 1024;  // 1G
    // bool logfile_daily = false;
    // uint32_t logfile_backup_count = 10;    
    // log4cpp::Priority::Value logfile_level = log4cpp::Priority::INFO;
    // std::string logfile_name = "pktminerg.log";
    // std::string logfile_config_file = "";


    // if (vm_general.count("logfile-enable")) {
    //     logfile_enable = true;
    // }

    // if (vm_general.count("logfile-size")) {
    //     logfile_size = handle_file_size_param(vm_general["logfile-size"].as<std::string>());
    // }

    // if (vm_general.count("logfile-daily")) {
    //     logfile_daily = true;
    // }

    // if (vm_general.count("logfile-backup-count")) {
    //     logfile_backup_count = vm_general["logfile-backup-count"].as<uint16_t>();
    // }

    // if (vm_general.count("logfile-level")) {
    //     std::string logLevel = vm_general["logfile-level"].as<std::string>();
    //     if (logLevel == "DEBUG") {
    //         logfile_level = log4cpp::Priority::DEBUG;
    //     } else if (logLevel == "INFO") {
    //         logfile_level = log4cpp::Priority::INFO;
    //     } else if (logLevel == "WARN") {
    //         logfile_level = log4cpp::Priority::WARN;
    //     } else if (logLevel == "ERROR") {
    //         logfile_level = log4cpp::Priority::ERROR;
    //     } else {
    //         logfile_level = log4cpp::Priority::DEBUG;
    //     }
    // }

    // if (vm_general.count("logfile-name")) {
    //     if (vm_general["logfile-name"].as<std::string>().size()) {
    //         logfile_name = vm_general["logfile-name"].as<std::string>();
    //     }
    //     boost::trim(logfile_name);
    // }

    // if (vm_general.count("logfile-config-file")) {
    //     if (vm_general["logfile-config-file"].as<std::string>().size()) {
    //         logfile_config_file = vm_general["logfile-config-file"].as<std::string>();
    //     }
    //     boost::trim(logfile_config_file);
    // }
    
    // if (logfile_enable) {        
    //     if (logfile_config_file.size()) {
    //         /*
    //             // rolling by log file size default content
    //             log4cpp.rootCategory=DEBUG, rootAppender

    //             log4cpp.appender.rootAppender=RollingFileAppender
    //             log4cpp.appender.rootAppender.fileName=pktminerg.log
    //             log4cpp.appender.rootAppender.maxFileSize=100
    //             log4cpp.appender.rootAppender.maxBackupIndex=10
    //             log4cpp.appender.rootAppender.layout=PatternLayout
    //             log4cpp.appender.rootAppender.layout.ConversionPattern=%m %n

    //             // rolling by 1 day default content
    //             log4cpp.rootCategory=DEBUG, rootAppender

    //             log4cpp.appender.rootAppender=DailyRollingFileAppender
    //             log4cpp.appender.rootAppender.fileName=pktminerg.log
    //             log4cpp.appender.rootAppender.maxDaysToKeep=10
    //             log4cpp.appender.rootAppender.layout=PatternLayout
    //             log4cpp.appender.rootAppender.layout.ConversionPattern=%m %n
    //         */
    //         log4cpp::PropertyConfigurator::configure(logfile_config_file);
    //     } else {
    //         if (logfile_backup_count == 0) {
    //             std::cerr << "logfile_backup_count is configure as 0, reset to 1" << std::endl;
    //             logfile_backup_count = 1;
    //         }

    //         log4cpp::Category& root = log4cpp::Category::getRoot();
    //         root.setPriority(logfile_level);

    //         log4cpp::Appender *appender = nullptr;
    //         if (logfile_daily) {
    //             appender = new log4cpp::DailyRollingFileAppender("daily_rolling", logfile_name, logfile_backup_count);
    //         } else if (logfile_size) {
    //             appender = new log4cpp::RollingFileAppender("rolling", logfile_name, logfile_size, logfile_backup_count);
    //         } else {
    //             std::cerr << "logfile_size and logfile_daily is all 0, treat logfile_size = 1G and logfile_daily = false" << std::endl;
    //             logfile_size = 1024 * 1024 * 1024;
    //             logfile_daily = false;
    //             appender = new log4cpp::RollingFileAppender("rolling", logfile_name, logfile_size, logfile_backup_count);
    //         }
    //         log4cpp::PatternLayout *patternLayout = new log4cpp::PatternLayout();
    //         patternLayout->setConversionPattern("%m %n");
    //         appender->setLayout(patternLayout);
    //         root.addAppender(appender);
    //     }
    // }
    char buf[4096] = {0};
    memset(buf, 0, 4096);
#ifdef _WIN32
    // if (vm_general.count("logfile-config-local-encoding") == 0) {
    //     ::setlocale(LC_ALL, "zh_CN.UTF-8");
    //     // std::cout << "logfile-config-local-encoding=0" << ::setlocale(LC_ALL, ".UTF-8") << std::endl;
    // } else {
    //     std::cout << "logfile-config-local-encoding" << ::setlocale(LC_ALL, "") << std::endl;
    // }
    ::GetModuleFileNameA(NULL, buf, 4096);
#else
    ::readlink("/proc/self/exe", buf, 4096);
#endif
    std::cout << buf << " startup." << std::endl;

    bool logfile_config_file_exists = false;
    boost::filesystem::path binary_path{buf};
    boost::filesystem::path config_file_path = binary_path.parent_path();
    if (boost::filesystem::is_directory(config_file_path)) {
        config_file_path /= "pktminerg.properties";
        try {
            std::string output_path = get_log_output_path(config_file_path.string());
            if (output_path.size()) {
                boost::filesystem::path wrapper{output_path};
                if (wrapper.parent_path().string().size() && !boost::filesystem::exists(wrapper.parent_path())) {
                    boost::filesystem::create_directories(wrapper.parent_path());
                }
            }
        } catch (...) {
            std::cerr << "Error occurs when try creating log output dir " << std::endl;
        }

        logfile_config_file_exists = boost::filesystem::exists(config_file_path);
        if (logfile_config_file_exists) {
            try {
                log4cpp::PropertyConfigurator::configure(config_file_path.string());
            } catch (log4cpp::ConfigureFailure e) {
                std::cerr << "Load config file failed, ConfigureFailure reason : " << e.what() 
                                << ".\n Use default value." << std::endl;
                init_log4cpp(false, LOG_FILE_DEFAULT_SIZE_IN_BYTES, LOG_FILE_DEFAULT_BACKUP_COUNT, 
                                    LOG_FILE_DEFAULT_LEVEL, LOG_FILE_DEFAULT_NAME);
            } catch (std::exception e) {
                std::cerr << "Load config file failed, reason : " << e.what() 
                                << ".\n Use default value." << std::endl;
                init_log4cpp(false, LOG_FILE_DEFAULT_SIZE_IN_BYTES, LOG_FILE_DEFAULT_BACKUP_COUNT, 
                                    LOG_FILE_DEFAULT_LEVEL, LOG_FILE_DEFAULT_NAME);
            } catch (...) {
                std::cerr << "Load config file failed." << ".\n Use default value." << std::endl;
                init_log4cpp(false, LOG_FILE_DEFAULT_SIZE_IN_BYTES, LOG_FILE_DEFAULT_BACKUP_COUNT, 
                                    LOG_FILE_DEFAULT_LEVEL, LOG_FILE_DEFAULT_NAME);
            }            
        }
    }


    
    // if (argc == 1 || strcmp(argv[1], "--help") == 0) {        
    //     std::cout << all << std::endl;
    //     return 0;
    // }

    // // version
    // if (strcmp(argv[1], "--version") == 0) {
    //     showVersion();
    //     return 0;
    // }


    // = process group options =
    uint32_t handler_idx = 0;
    LogFileContext g_ctx(logfile_config_file_exists, "");
    std::string output_buffer;

    //got all remote IPs
    std::vector<std::string> allRemoteIPs;
    getAllRemoteIPViaGroupOptions(allRemoteIPs, group_options);
    
    for (uint32_t i = 0; i < group_options.size(); i++) {
        handler_idx ++;
        char handler_id[20] = {0};
        std::snprintf(handler_id, sizeof(handler_id) - 1, "[-%02u-]", handler_idx);
        LogFileContext ctx(logfile_config_file_exists, std::string(handler_id));

        std::string str = group_options[i];

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
                    args.push_back((char*)"-i");
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
            output_buffer = std::string("Parse command line failed, error is ") + e.what() + ".";
            ctx.log(output_buffer, log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
            return 1;
        }

        // check options
        if ((vm.count("interface") || vm.count("container")) + vm.count("pcapfile") + vm.count("kvm")!= 1) {
            ctx.log("Please choice only one snoop mode, from interface use -i or from pcap file use -f or from container use -c or from KVM use -m.", 
                    log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() 
                    << "Please choice only one snoop mode, from interface use -i or from pcap file use -f or from container use -c or from KVM use -m." 
                    << std::endl;
            return 1;
        }

        std::string bind_device = "";
        if (vm.count("bind_device")) {
            bind_device = vm["bind_device"].as<std::string>();
        }

        int pmtudisc = -1;
        int update_status = 0;

        if (vm.count("pmtudisc_option")) {
            const auto pmtudisc_option = vm["pmtudisc_option"].as<std::string>();
            if (pmtudisc_option == "do") {
                pmtudisc = IP_PMTUDISC_DO;
            } else if (pmtudisc_option == "dont") {
                pmtudisc = IP_PMTUDISC_DONT;
            }
#ifndef _WIN32
                else if (pmtudisc_option == "want") {
                    pmtudisc = IP_PMTUDISC_WANT;
                }
#endif
            else {
                ctx.log("Wrong value for -M: do, dont, want are valid ones.", log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << "Wrong value for -M: do, dont, want are valid ones." << std::endl;
                return 1;
            }
        }

        uint16_t daemon_zmq_port = vm["control"].as<uint16_t>();
        if (daemon_zmq_port) {
            if (agent_control_plane == nullptr) {
                try {
                    agent_control_plane = std::make_shared<AgentControlPlane>(ctx, daemon_zmq_port);
                } catch (zmq::error_t& e) {
                    output_buffer = std::string("Can not bind daemon zmq port:") + std::to_string(daemon_zmq_port) + "," +e.what();
                    ctx.log(output_buffer, log4cpp::Priority::ERROR);
                    std::cerr << output_buffer << std::endl;
                    return 1;
                }      
            }
            update_status = 1;
        }

        if (!vm.count("remoteip") && !vm.count("dump")) {
            ctx.log("Please set gre remote ip with --remoteip(or -r) or get dump directory with --Dump.", 
                    log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() 
                    << "Please set gre remote ip with --remoteip(or -r) or get dump directory with --Dump." 
                    << std::endl;
            return 1;
        }
        std::vector<std::string> remoteips;
        if (vm.count("remoteip")) {
            std::string remoteip = vm["remoteip"].as<std::string>();
            boost::algorithm::split(remoteips, remoteip, boost::algorithm::is_any_of(","));
        }

        exporttype type;
        std::string val;

        int zmq_port = vm["zmq_port"].as<int>();
        int zmq_hwm = vm["zmq_hwm"].as<int>();
        uint32_t keybit;
        uint32_t vni;
        uint8_t vni_version;
        int vxlan_port;
        int capTime = 0;
        
        if (zmq_port > 0) {
            type = exporttype::zmq;
            keybit = vm["keybit"].as<uint32_t>();
        } else if (vm.count("vni1")) {
            vni = vm["vni1"].as<uint32_t>();
            type = exporttype::vxlan;
            vxlan_port = vm["vxlan_port"].as<int>();
            vni_version = 1;
        } else if (vm.count("vni2")) {
            vni = vm["vni2"].as<uint32_t>();
            type = exporttype::vxlan;
            vxlan_port = vm["vxlan_port"].as<int>();
            vni_version = 2;
        } else {
            type = exporttype::gre;
            keybit = vm["keybit"].as<uint32_t>();
        }

        if(vm.count("capTime")) {
            capTime = vm["capTime"].as<int>();
        }
        std::string intface = "";
        if (vm.count("interface")) {
            auto strs = vm["interface"].as<std::vector<std::string>>();
            for (uint16_t i = 0; i < strs.size(); i++) {
                intface = intface + strs[i];
                if (i < strs.size() - 1) {
                    intface = intface + " ";
                }
            }
        }
        std::string processId = "";
        if (vm.count("container")) {
            if (intface == "") {
                intface = "eth0";
            }
            processId = getProccssIdWithContainer(vm["container"].as<std::string>(), g_ctx);
            if (processId.length() == 0) {
                continue;
            }
        }
        std::string machineName = "";
#ifndef _WIN32
        if (vm.count("kvm")) {
            machineName = vm["kvm"].as<std::string>();  
            FILE *fp;
	        char buffer[80] = {0};
                   
            const auto cmd = boost::str(
                boost::format("sh get_if_with_name.sh %1%") % machineName);
	        fp=popen(cmd.c_str(),"r");
	        fgets(buffer,sizeof(buffer),fp);
            pclose(fp);
            if (strlen(buffer) == 0) {
                ctx.log("Please input the right name of virtual machine in KVM.", log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() 
                        << "Please input the right name of virtual machine in KVM." << std::endl;
                return 1;
            }	
            intface = std::string(buffer, strlen(buffer) - 1);
            if (intface == "-") {
                ctx.log("The virtual machine is shutdown.", log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << "The virtual machine is shutdown." << std::endl;
                return 1; 
            }
        }
#endif
        std::string filter = "";

        if (vm.count("expression")) {
            auto expressions = vm["expression"].as<std::vector<std::string>>();
#ifndef _WIN32
            int fd = -1;
            if (processId != "") {
                std::string path = "/proc/" + processId + "/ns/net";
                fd = open(path.c_str(), O_RDONLY); /* Get file descriptor for namespace */

                if (fd == -1) {
                    output_buffer = std::string("Can not open the namespace:") + path;
                    ctx.log(output_buffer, log4cpp::Priority::ERROR);
                    std::cerr << output_buffer <<std::endl;
                    continue;
                }
                if (setns(fd, 0) == -1) {
                    output_buffer = std::string("Can not set the namespace:") + path;
                    ctx.log(output_buffer, log4cpp::Priority::ERROR);
                    std::cerr << output_buffer << std::endl;
                    continue;
                }
            }
#endif
            for (size_t i = 0; i < expressions.size(); i++) {
                filter = filter + expressions[i] + " ";
                if (expressions[i] == "host" && i + 1 < expressions.size()) {
                    if (i > 0 && expressions[i - 1] == "not") {
                        continue;
                    }
                    if (expressions[i + 1].find("nic.") == 0) {
                        std::vector<std::string> ips;
                        if (!replaceWithIfIp(expressions[i + 1],ips, ctx)) {
                            output_buffer = "Please input right interface name.";
                            ctx.log(output_buffer, log4cpp::Priority::ERROR);
                            std::cerr << output_buffer << std::endl;
                            return 1;
                        }
                    } 
                }
            }
#ifndef _WIN32
            if (processId != "") {
                close(fd);
            }
#endif
        }

        // no filter option
        bool nofilter = false;
        if (vm.count("nofilter")) {
            nofilter = true;
            if (vm.count("interface")) {
                if (bind_device == "") {
                    output_buffer = std::string("Can't enable --nofilter option ") +
                        "because GRE bind devices(-B) is not set, GRE packet might be sent via packet captured interface(-i)";
                    ctx.log(output_buffer, log4cpp::Priority::ERROR);
                    std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
                    return 1;
                } else if (bind_device == intface) {
                    output_buffer = std::string("Can't enable --nofilter option ") +
                        "because packet captured interface(-i) is equal to GRE bind devices(-B)";
                    ctx.log(output_buffer, log4cpp::Priority::ERROR);
                    std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
                    return 1;
                } else {
                    // valid
                }
            }
        }

        if (!nofilter) {
            for (size_t i = 0; i < allRemoteIPs.size(); ++i) {
                if (filter.length() > 0) {
                    filter = filter + " and not host " + allRemoteIPs[i];
                } else {
                    filter = "not host " + allRemoteIPs[i];
                }
            }
        }

        // snoop mode
        pcap_init_t pcapParam;
        pcapParam.buffer_size = vm["buffsize"].as<int>() * 1024 * 1024;
        pcapParam.snaplen = vm["snaplen"].as<int>();
        pcapParam.promisc = 0;
        pcapParam.timeout = vm["timeout"].as<int>();
        pcapParam.need_update_status = update_status;
        
        // priority option
        if (vm.count("priority")) {
            set_high_setpriority();
        }

        // cpu option
        if (vm.count("cpu")) {
            int cpuid = vm["cpu"].as<int>();
            if (set_cpu_affinity(cpuid) == 0) {
                output_buffer = std::string("Call set_cpu_affinity(") + std::to_string(cpuid) + ") success.";
                ctx.log(output_buffer, log4cpp::Priority::INFO);
                std::cout << StatisLogContext::getTimeString() << output_buffer << std::endl;
            } else {
                output_buffer = std::string("Call set_cpu_affinity(") + std::to_string(cpuid) + ") failed.";
                ctx.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
                return 1;
            }
        }

        std::shared_ptr<PcapHandler> handler;
        std::string dev = intface;
        if (vm.count("interface") || vm.count("container") || vm.count("kvm")) {
            boost::trim(dev);
            
#ifdef _WIN32
            std::string cset = vm["interface_csets"].as<std::string>();

            if (cset != "gb2312" && cset != "utf8") {
                output_buffer = std::string("unsupported characters sets(") + cset + 
                        ") of interface";
                ctx.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
                return 1;
            }
            
#endif
            std::string dirStr =  vm.count("dir")?vm["dir"].as<std::string>():"";
            HandleParam param(vm["dump"].as<std::string>(), vm["interval"].as<int>(), vm["slice"].as<int>(),
                                                        dev, processId, pcapParam, filter, dirStr, machineName, ctx);

            handler = std::make_shared<PcapHandler>(param);
        } else {
            ctx.log("Please choice snoop mode: from interface use -i or from pcap file use -c or from kvm use -m.", 
                    log4cpp::Priority::ERROR);
            std::cerr << StatisLogContext::getTimeString() 
                    << "Please choice snoop mode: from interface use -i or from pcap file use -c or from kvm use -m." 
                    << std::endl;
            continue;
        }
        
        std::shared_ptr<PcapExportBase> exportPtr = nullptr;
        switch (type) {
            case exporttype::zmq:
                exportPtr = std::make_shared<PcapExportZMQ>(remoteips, zmq_port, zmq_hwm, keybit, bind_device,
                                                            pcapParam.buffer_size, vm["mbps"].as<double>(), ctx);
                break;

            case exporttype::gre:
                exportPtr = std::make_shared<PcapExportGre>(remoteips, keybit, bind_device, pmtudisc, vm["mbps"].as<double>(), ctx);
                break;

            case exporttype::vxlan:
                exportPtr = std::make_shared<PcapExportVxlan>(remoteips, vni, bind_device, pmtudisc, vxlan_port, 
                                    vm["mbps"].as<double>(), vni_version, ctx, capTime);
                break;

            default:
                output_buffer = std::string("unkown export type:") + std::to_string((int) type);
                ctx.log(output_buffer, log4cpp::Priority::ERROR);
                std::cerr << StatisLogContext::getTimeString() << output_buffer << std::endl;
                continue;
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
    // begin pcap snoopopenPcap
    bool allHandlersDown = false;
    g_ctx.log("Start pcap snoop.", log4cpp::Priority::INFO);
    std::cout << StatisLogContext::getTimeString() << "Start pcap snoop." << std::endl;
    while (isLoop && !handlers.empty()) {
        if(allHandlersDown) {
#ifdef _WIN32
            usleep(100);
#else
            usleep(100000);
#endif
        }
        allHandlersDown = true;
        auto now = std::chrono::steady_clock::now();
    
        auto milliseconds = std::chrono::time_point_cast<std::chrono::milliseconds>(now);
        auto epoch = milliseconds.time_since_epoch();
        long long currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(epoch).count();
        
        for (auto iter = handlers.begin(); iter != handlers.end() && isLoop;++iter) {
            if((*iter)->getHandlerCheckTime() > 0 && currentTime-(*iter)->getHandlerCheckTime() < 100) {
                continue;
            }
            if((*iter)->getHandlerCheckTime() != 0) {
                if((*iter)->openPcap() == -1) {
                    (*iter)->clearHandler();
                    (*iter)->setHandlerCheckTime(currentTime);
                    continue;
                }
                if ((*iter)->initExport() == -1) {
                    (*iter)->getLogFileContext().log("initExport failed.", log4cpp::Priority::ERROR);
                    std::cerr << StatisLogContext::getTimeString() << "initExport failed." << std::endl;
                    (*iter)->clearHandler();
                    (*iter)->setHandlerCheckTime(currentTime);
                    continue;
                }
                (*iter)->setHandlerCheckTime(0);
            }
                       
            if ((*iter)->handlePacket() == 0) {    
                allHandlersDown = false;
            } else {
                (*iter)->clearHandler();
                (*iter)->setHandlerCheckTime(currentTime);
            }
        }
    }
    g_ctx.log("End pcap snoop.", log4cpp::Priority::INFO);
    std::cout << StatisLogContext::getTimeString() << "End pcap snoop." << std::endl;

    // end
    for (auto handler: handlers) {
        handler->clearHandler();
    }
    test.close();
    // google::ShutdownGoogleLogging();
    return 0;
}
