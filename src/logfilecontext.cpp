#include <ctime>

#include "log4cpp/Category.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/RollingFileAppender.hh"
#include "log4cpp/SimpleLayout.hh"
#include "log4cpp/PatternLayout.hh"
#include "log4cpp/PropertyConfigurator.hh"


#include "logfilecontext.h"

// void LogFileContext::logFileFuncEmpty(std::string output_buffer, int priority) {
//     (void)output_buffer;
//     (void)priority;
//     return;
// }

// void LogFileContext::logFileFunc(std::string output_buffer, int priority) {
//     log4cpp::Category& root = log4cpp::Category::getRoot();
//     root << priority << output_buffer;
// }

LogFileContext::LogFileContext() {
    logFileEnable_ = false;
    handlerId_ = "";
}

LogFileContext::LogFileContext(bool logFileEnable, std::string handlerId):
    logFileEnable_(logFileEnable),
    handlerId_(handlerId) {
}


LogFileContext::~LogFileContext() {

}

void LogFileContext::setLogFileEnable(bool logFileEnable) {
    logFileEnable_ = logFileEnable;
}

void LogFileContext::setLogFileHandlerId(std::string handlerId) {
    handlerId_ = handlerId;
}


void LogFileContext::log(std::string message, int priority){
    if (logFileEnable_) {
        std::string logPriorityLevel("[INFO] ");
        if (logLevels_.find(priority) != logLevels_.end()) {
            logPriorityLevel = logLevels_[priority];
        }
        log4cpp::Category& root = log4cpp::Category::getRoot();
        root << priority << getTimeString() << logLevels_[priority] << handlerId_ << " " << message;
    }
}


std::string LogFileContext::getTimeString() {
    char time_buffer[20] = {0};
    const auto now = time(NULL);
    const auto* ts = localtime(&now);
    strftime(time_buffer, 20, "%Y-%m-%d %H:%M:%S", ts);
    return std::string("[") + time_buffer + std::string("]");
}

