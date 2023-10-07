#include <stdio.h>
#include <iostream>
#include <log4cpp/Category.hh>
#include <log4cpp/Appender.hh>
#include <log4cpp/OstreamAppender.hh>
#include <log4cpp/Layout.hh>
#include <log4cpp/BasicLayout.hh>
#include <log4cpp/Priority.hh>
#include <log4cpp/NDC.hh>


void testLogva(log4cpp::Category& category,
               log4cpp::Priority::Value priority, 
               const char* stringFormat,
               ...)
{
    va_list va;
    va_start(va, stringFormat);
    category.logva(priority, stringFormat, va);
    va_end(va);
} /* end testLogva */

void testGetAppender(log4cpp::Category& category,
                     log4cpp::Appender* appender,
                     log4cpp::Appender* appender2,
                     log4cpp::Appender& appender3)
{
    // test getAppender() - should return one of the three appenders
    log4cpp::Appender *tmpAppender = category.getAppender();
    if ((tmpAppender == appender) ||
        (tmpAppender == appender2) ||
        (tmpAppender == &appender3))
    {
        std::cout << "tmpAppender == appender or appender2 or appender3" << std::endl;
    }
    else
    {
        std::cout << "tmpAppender != appender or appender2 or appender3" << std::endl;
    } /* end if-else */

    // test getAppender(const std::string& name) const
    tmpAppender = category.getAppender("appender2");
    if (tmpAppender == appender2)
    {
        std::cout << "tmpAppender == appender2" << std::endl;
    }
    else
    {
        std::cout << "tmpAppender != appender2" << std::endl;
    } /* end if-else */

    tmpAppender = category.getAppender("appender3");
    if (tmpAppender == &appender3)
    {
        std::cout << "tmpAppender == appender3" << std::endl;
    }
    else
    {
        std::cout << "tmpAppender != appender3" << std::endl;
    } /* end if-else */

} /* end testGetAppender() */

void testMultiAppenders()
{
    log4cpp::Appender* appender = 
        new log4cpp::OstreamAppender("appender", &std::cout);
    
    log4cpp::Appender* appender2 = 
        new log4cpp::OstreamAppender("appender2", &std::cout);

    log4cpp::OstreamAppender appender3("appender3", &std::cout);

    log4cpp::Layout* layout = new log4cpp::BasicLayout();
    log4cpp::Layout* layout2 = new log4cpp::BasicLayout();
    log4cpp::Layout* layout3 = new log4cpp::BasicLayout();

    appender->setLayout(layout);
    appender2->setLayout(layout2);
    appender3.setLayout(layout3);

    // add three appenders to root category
    log4cpp::Category& root = log4cpp::Category::getRoot();
    root.setPriority(log4cpp::Priority::ERROR);

    // clear root's initial appender
    root.removeAllAppenders();

    root.addAppender(appender);
    root.addAppender(appender2);
    root.addAppender(appender3);

    // dump a message - should see three on the screen
    std::cout << "You should see three lines of \"root error #1\"" << std::endl;
    root.error("root error #1");
    std::cout << "Did you?" << std::endl;

    // get getAppender() changes on category with appenders
    std::cout << "You should see messages that tmpAppender == other appenders" << std::endl;
    testGetAppender(root, appender, appender2, appender3);
    std::cout << "Did you?" << std::endl;

    // add appender by reference to sub1 category
    log4cpp::Category& sub1 = 
        log4cpp::Category::getInstance(std::string("sub1"));
    sub1.addAppender(appender3);

    // clear all appenders
    root.removeAllAppenders();
    sub1.removeAllAppenders();

    // dump a message - should not see it on the screen
    std::cout << "You should not see any lines of  \"root error #2\"" << std::endl;
    root.error("root error #2");
    std::cout << "Did you?" << std::endl;

    // get getAppender() changes on category with no appenders
    std::cout << "You should see messages that tmpAppender != other appenders" << std::endl;
    testGetAppender(root, appender, appender2, appender3);
    std::cout << "Did you?" << std::endl;


    // add three appenders to root category
    appender = new log4cpp::OstreamAppender("appender", &std::cout);
    appender2 = new log4cpp::OstreamAppender("appender2", &std::cout);
    root.addAppender(appender);
    root.addAppender(appender2);
    root.addAppender(appender3);

    // test removing valid and invalid
    root.removeAppender(appender);
    root.removeAppender(appender2);
    root.removeAppender(&appender3);

} /* end testMultiAppenders() */


int main(int argc, char** argv) {    

    testMultiAppenders();

    log4cpp::Appender* appender = 
        new log4cpp::OstreamAppender("default", &std::cout);

    log4cpp::Appender* appender2 = 
        new log4cpp::OstreamAppender("default2", &std::cout);

    log4cpp::Layout* layout = new log4cpp::BasicLayout();
    log4cpp::Layout* layout2 = new log4cpp::BasicLayout();
    
    appender->setLayout(layout);
    appender2->setLayout(layout2);

    log4cpp::Category& root = log4cpp::Category::getRoot();
    root.addAppender(appender);
    root.setPriority(log4cpp::Priority::ERROR);
    
    log4cpp::Category& sub1 = 
        log4cpp::Category::getInstance(std::string("sub1"));
	sub1.addAppender(appender2);
	sub1.setAdditivity(false);

    log4cpp::Category& sub2 = 
        log4cpp::Category::getInstance(std::string("sub1.sub2"));

    std::cout << " root priority = " << root.getPriority() << std::endl;
    std::cout << " sub1 priority = " << sub1.getPriority() << std::endl;
    std::cout << " sub2 priority = " << sub2.getPriority() << std::endl;
    
    root.error("root error");
    root.warn("root warn");
    sub1.error("sub1 error");
    sub1.warn("sub1 warn");
    sub2.error("sub2 error");
    sub2.warn("sub2 warn");
    
    testLogva(root, log4cpp::Priority::EMERG, "This contains %d %s", 2, "variable arguments");
    testLogva(root, log4cpp::Priority::ALERT, "This contains %d %s", 2, "variable arguments");
    testLogva(root, log4cpp::Priority::CRIT, "This contains %d %s", 2, "variable arguments");
    testLogva(root, log4cpp::Priority::ERROR, "This contains %d %s", 2, "variable arguments");
    testLogva(root, log4cpp::Priority::WARN, "This contains %d %s", 2, "variable arguments");
    testLogva(root, log4cpp::Priority::INFO, "This contains %d %s", 2, "variable arguments");
    testLogva(root, log4cpp::Priority::NOTICE, "This contains %d %s", 2, "variable arguments");
    testLogva(root, log4cpp::Priority::DEBUG, "This contains %d %s", 2, "variable arguments");

    char lengthy1[] = "Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. Test for variable-arguments lists overflow. ";
    testLogva(root, log4cpp::Priority::ERROR, "This contains really lengthy strings which should be logged well (%d bytes): %s", sizeof(lengthy1), lengthy1);

    sub1.setPriority(log4cpp::Priority::INFO);
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
