#ifndef PKTMINERG_LOGFILECONTEXT_H
#define PKTMINERG_LOGFILECONTEXT_H

#include <string>
#include <unordered_map>

#include "log4cpp/Priority.hh"

typedef void(*log_file_func)(std::string output_buffer, int priority);

class LogFileContext {
public:
    LogFileContext();
    LogFileContext(bool logFileEnable, std::string handlerId);
    ~LogFileContext();
    void setLogFileEnable(bool logFileEnable);
    void setLogFileHandlerId(std::string handlerId);
    void log(std::string output_buffer, int priority);

    static std::string getTimeString();

private:
    bool logFileEnable_;
    std::string handlerId_;
    std::unordered_map<int, std::string> logLevels_ = {
        {log4cpp::Priority::DEBUG, std::string("[DEBUG]")},
        {log4cpp::Priority::INFO, std::string("[INFO] ")},
        {log4cpp::Priority::WARN, std::string("[WARN] ")},
        {log4cpp::Priority::ERROR, std::string("[ERROR]")}
    };
};



#endif //PKTMINERG_LOGFILECONTEXT_H
