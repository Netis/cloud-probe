#include <csignal>
#include <cctype>

#include <boost/program_options.hpp>
#include <boost/filesystem.hpp>
#include "glog/logging.h"

#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/RollingFileAppender.hh"
#include "log4cpp/DailyRollingFileAppender.hh"
#include "log4cpp/SimpleLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/PropertyConfigurator.hh"
#include "log4cpp/Configurator.hh"

#include "version.h"
#include "daemonManager.h"
#include "logfilecontext.h"


#define  LOG_FILE_DEFAULT_SIZE_IN_BYTES     (1024 * 1024 * 1024)  //1GB
#define  LOG_FILE_DEFAULT_BACKUP_COUNT      (10)
#define  LOG_FILE_DEFAULT_LEVEL             (log4cpp::Priority::INFO)
#define  LOG_FILE_DEFAULT_NAME              ("agentdaemon.log")


void showVersion() {
    std::cout << "~ probedaemon version " << std::string(PKTMINERG_VERSION) << " (rev: " <<
              std::string(PKTMINERG_GIT_COMMIT_HASH) << " build: " << std::string(PKTMINERG_BUILD_TIME) << ")"
              << std::endl;
}

timer_tasks_t* __tasks;


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

int main(int argc, const char* argv[]) {


    google::InitGoogleLogging(argv[0]);
    google::SetStderrLogging(google::GLOG_INFO);
    boost::program_options::options_description generic("Generic options");
    generic.add_options()
            ("version,v", "show version.")
            ("help,h", "show help.")
            ("config", boost::program_options::value<std::string>(), "Config file");
            // ("logfile-enable", "enable log file output.")
            // ("logfile-size", boost::program_options::value<std::string>()->default_value("1G")->value_name("LOGFILESIZE"),
            //  "specify the log file max size in bytes,[[x]k | [x]K | [x]m | [x]M | [x]g | [x]G | [x]], 0 to not use. default value 1G")
            // ("logfile-daily", "splitter log file daily, logfile-size must be set to 0")
            // ("logfile-backup-count", boost::program_options::value<uint16_t>()->default_value(10)->value_name("LOGFILEBACKUPCOUNT"),
            //  "specify the log file max backup count, default value 10")
            // ("logfile-level", boost::program_options::value<std::string>()->default_value("DEBUG")->value_name("LOGFILELEVEL"),
            //  "specify the log file output priority level, [DEBUG | INFO | WARN | ERROR], default value DEBUG")
            // ("logfile-name", boost::program_options::value<std::string>()->default_value(std::string("agentdaemon.log"))->value_name("LOGFILENAME"),
            //  "specify the log file dir and name, absolute/relative path and file name. use current directory if relative specified")
            // ("logfile-config-file", boost::program_options::value<std::string>()->default_value(std::string(""))->value_name("LOGFILECONFIGFILE"),
            //  "specify the log config file, if not specific, use command line param");

    boost::program_options::options_description desc("Allowed options");
    char hostname[HOST_NAME_MAX + 1];
    ::gethostname(hostname, sizeof(hostname));
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
            ("includingNICs", boost::program_options::value<std::string>()->value_name("INCLUDINGNICS"),
             "specify the nics which will be included in the register message to CPM")
            ("namespace", boost::program_options::value<std::string>()->value_name("NAMESPACE"),
             "namespace of PA, usedin sidecard mode");

    boost::program_options::options_description all;
    all.add(generic).add(desc);

    boost::program_options::variables_map vm;
    try {
        boost::program_options::parsed_options parsed = boost::program_options::command_line_parser(argc, argv)
                .options(all).run();
        boost::program_options::store(parsed, vm);
        boost::program_options::notify(vm);

        if (vm.count("config")) {
            std::ifstream configStream{vm["config"].as<std::string>().c_str()};
            if (configStream) {
                boost::program_options::store(boost::program_options::parse_config_file(configStream, desc), vm);
            }

        }

    } catch (boost::program_options::error& e) {
        std::cerr << "Parse command line failed, error is " << e.what() << "." << std::endl;
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

    // // log file params
    // bool logfile_enable = false;    
    // uint64_t logfile_size = 1024 * 1024 * 1024;  // 1G
    // bool logfile_daily = false;
    // uint32_t logfile_backup_count = 10;    
    // log4cpp::Priority::Value logfile_level = log4cpp::Priority::DEBUG;
    // std::string logfile_name = "agentdaemon.log";
    // std::string logfile_config_file = "";

    // if (vm.count("logfile-enable")) {
    //     logfile_enable = true;
    // }

    // if (vm.count("logfile-size")) {
    //     logfile_size = handle_file_size_param(vm["logfile-size"].as<std::string>());
    // }

    // if (vm.count("logfile-daily")) {
    //     logfile_daily = true;
    // }

    // if (vm.count("logfile-backup-count")) {
    //     logfile_backup_count = vm["logfile-backup-count"].as<uint16_t>();
    // }

    // if (vm.count("logfile-level")) {
    //     std::string logLevel = vm["logfile-level"].as<std::string>();
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

    // if (vm.count("logfile-name")) {
    //     if (vm["logfile-name"].as<std::string>().size()) {
    //         logfile_name = vm["logfile-name"].as<std::string>();
    //     }
    //     boost::trim(logfile_name);
    // }

    // if (vm.count("logfile-config-file")) {
    //     if (vm["logfile-config-file"].as<std::string>().size()) {
    //         logfile_config_file = vm["logfile-config-file"].as<std::string>();
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
    //             log4cpp.appender.rootAppender.maxFileSize=1048576000
    //             log4cpp.appender.rootAppender.maxBackupIndex=10
    //             log4cpp.appender.rootAppender.layout=PatternLayout
    //             log4cpp.appender.rootAppender.layout.ConversionPattern="%m %n" 

    //             // rolling by 1 day default content
    //             log4cpp.rootCategory=DEBUG, rootAppender

    //             log4cpp.appender.rootAppender=DailyRollingFileAppender
    //             log4cpp.appender.rootAppender.fileName=pktminerg.log
    //             log4cpp.appender.rootAppender.maxDaysToKeep=10
    //             log4cpp.appender.rootAppender.layout=PatternLayout
    //             log4cpp.appender.rootAppender.layout.ConversionPattern="%m %n" 
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
    ::GetModuleFileNameA(NULL, buf, 4096);
#else
    ::readlink("/proc/self/exe", buf, 4096);
#endif
    std::cout << buf << " startup." << std::endl;
    
    bool logfile_config_file_exists = false;
    boost::filesystem::path binary_path{buf};
    boost::filesystem::path config_file_path = binary_path.parent_path();
    if (boost::filesystem::is_directory(config_file_path)) {
        config_file_path /= "probedaemon.properties";
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



    LogFileContext ctx(logfile_config_file_exists, "");

    if (!vm.count("platformId")) {
        ctx.log("PlatformId is mandatory.", log4cpp::Priority::ERROR);
        std::cerr << "PlatformId is mandatory." << std::endl;
        return 1;
    }
    
    if(!(__tasks = timer_tasks_new()))
    {
        ctx.log("timer tasks init failed", log4cpp::Priority::ERROR);
        std::cerr << "timer tasks init failed" << std::endl;
        return 1;
    }
    // signal
    std::signal(SIGINT, [](int) {
        timer_tasks_stop(__tasks);
    });
    std::signal(SIGTERM, [](int) {
        timer_tasks_stop(__tasks);
    });
    
    {
        DaemonManager dm(vm, __tasks, ctx);
        timer_tasks_run(__tasks);
    }
    timer_tasks_term(__tasks);
    google::ShutdownGoogleLogging();
    return 0;
}


