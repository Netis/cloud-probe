// testNTEventLog.cpp : Derived from testPattern.cpp.
//

#include "log4cpp/Portability.hh"

#ifdef WIN32
#include <windows.h>
#endif
#ifdef LOG4CPP_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <stdlib.h>

#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/NTEventLogAppender.hh"
#include "log4cpp/Priority.hh"

int main(int argc, char* argv[])
{
    log4cpp::Appender* appender = 
        new log4cpp::NTEventLogAppender("default", "testNTEventLog");

    log4cpp::Category& sub1 = 
        log4cpp::Category::getInstance(std::string("sub1"));
    sub1.addAppender(appender);
    sub1.setPriority(log4cpp::Priority::DEBUG);
    
    sub1.emerg("sub1 emerg");
    sub1.fatal("sub1 fatal");
    sub1.alert("sub1 alert");
    sub1.crit("sub1 crit");
    sub1.error("sub1 error");
    sub1.warn("sub1 warn");
    sub1.notice("sub1 notice");
    sub1.info("sub1 info");
    sub1.debug("sub1 debug");
    sub1.log(log4cpp::Priority::NOTSET, "sub1 notset");
    sub1.log(log4cpp::Priority::ERROR, "sub1 error");

    log4cpp::Category::shutdown();

    return 0;
}

