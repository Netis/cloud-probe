#include <stdio.h>
#include <iostream>
#include "log4cpp/FixedContextCategory.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/OstreamAppender.hh"
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/NDC.hh"

int main(int argc, char** argv) {    
    log4cpp::Appender* appender = 
        new log4cpp::OstreamAppender("default", &std::cout);

    log4cpp::Layout* layout = new log4cpp::BasicLayout();
    appender->setLayout(layout);

    log4cpp::Category& root = log4cpp::Category::getRoot();
    root.addAppender(appender);
       root.setPriority(log4cpp::Priority::ERROR);
    
    log4cpp::FixedContextCategory sub1(std::string("sub1"), std::string("context1"));

    log4cpp::FixedContextCategory sub1_2(std::string("sub1"), std::string("context1_2"));

    log4cpp::FixedContextCategory sub2(std::string("sub1.sub2"), std::string("context2"));

    std::cout << " root priority = " << root.getPriority() << std::endl;
    std::cout << " sub1 priority = " << sub1.getPriority() << std::endl;
    std::cout << " sub2 priority = " << sub2.getPriority() << std::endl;
    
    root.error("root error");
    root.warn("root warn");
    sub1.error("sub1 error");
    sub1.warn("sub1 warn");
    sub1_2.error("sub1 error");
    sub1_2.warn("sub1 warn");
    sub2.error("sub2 error");
    sub2.warn("sub2 warn");
    
    log4cpp::Category::getInstance(std::string("sub1")).
               setPriority(log4cpp::Priority::INFO);

    std::cout << " root priority = " << root.getPriority() << std::endl;
    std::cout << " sub1 priority = " << sub1.getPriority() << std::endl;
    std::cout << " sub2 priority = " << sub2.getPriority() << std::endl;
   
    std::cout << "priority info" << std::endl;
    root.error("root error");
    root.warn("root warn");
    sub1.error("sub1 error");
    sub1.warn("sub1 warn");
    sub2.error("sub2 error");
    sub2.warn("sub2 warn");
    sub2.error("%s %s %d", "test", "vform", 123);
    sub2.warnStream() << "streamed warn";

    sub2 << log4cpp::Priority::WARN << "warn2.." << "..warn3..value=" << 0 
         << log4cpp::eol << "..warn4";

    log4cpp::Category::shutdown();

    return 0;
}
