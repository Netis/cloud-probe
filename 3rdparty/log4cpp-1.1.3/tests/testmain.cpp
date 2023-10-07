#include <stdio.h>
#include "log4cpp/Portability.hh"
#ifdef LOG4CPP_HAVE_UNISTD_H
#include <unistd.h>
#endif
#include <iostream>
#include "log4cpp/Category.hh"
#include "log4cpp/Appender.hh"
#include "log4cpp/FileAppender.hh"
#include "log4cpp/OstreamAppender.hh"
#ifdef LOG4CPP_HAVE_SYSLOG
#include "log4cpp/SyslogAppender.hh"
#endif
#include "log4cpp/Layout.hh"
#include "log4cpp/BasicLayout.hh"
#include "log4cpp/Priority.hh"
#include "log4cpp/NDC.hh"

int main(int argc, char** argv) {
	log4cpp::Appender* appender;
#ifdef LOG4CPP_HAVE_SYSLOG
	log4cpp::SyslogAppender* syslogAppender;

	syslogAppender = new log4cpp::SyslogAppender("syslog", "log4cpp");
#else
	log4cpp::Appender* syslogAppender;

	syslogAppender = new log4cpp::OstreamAppender("syslogdummy", &std::cout);
#endif

	if (argc < 2) {
		appender = new log4cpp::OstreamAppender("default", &std::cout);
	} else {
		appender = new log4cpp::FileAppender("default", argv[1]);
	}

	syslogAppender->setLayout(new log4cpp::BasicLayout());
	appender->setLayout(new log4cpp::BasicLayout());

	log4cpp::Category& root = log4cpp::Category::getRoot();
	root.addAppender(syslogAppender);
	root.setPriority(log4cpp::Priority::ERROR);

	log4cpp::Category& sub1 = log4cpp::Category::getInstance(std::string("sub1"));
	sub1.addAppender(appender);

	log4cpp::Category& sub2 = log4cpp::Category::getInstance(std::string("sub1.sub2"));

	log4cpp::NDC::push(std::string("ndc1"));

	std::cout << " root prio = " << root.getPriority() << std::endl;
	std::cout << " sub1 prio = " << sub1.getPriority() << std::endl;
	std::cout << " sub2 prio = " << sub2.getPriority() << std::endl;

	root.error("root error");
	root.warn("root warn");
	sub1.error("sub1 error");
	sub1.warn("sub1 warn");
	sub2.error("sub2 error");
	sub2.warn("sub2 warn");

	sub1.setPriority(log4cpp::Priority::INFO);
	std::cout << " root prio = " << root.getPriority() << std::endl;
	std::cout << " sub1 prio = " << sub1.getPriority() << std::endl;
	std::cout << " sub2 prio = " << sub2.getPriority() << std::endl;

	std::cout << "priority info" << std::endl;
	root.error("root error");
	root.warn("root warn");
	sub1.error("sub1 error");
	sub1.warn("sub1 warn");
	sub2.error("sub2 error");
	sub2.warn("sub2 warn");

	sub2.warnStream() << "streamed warn";

	sub2 << log4cpp::Priority::WARN << "warn2" << " warn3" 
             << log4cpp::eol << " warn4";

	{
		for(int i = 0; i < 10000; i++) {
			char ndc2[20];
			sprintf(ndc2, "i=%d", i);
			log4cpp::NDC::push(ndc2);
			sub1.info("%s%d", "i = ", i);
			if ((i % 10) == 0) {
				sub1.log(log4cpp::Priority::NOTICE, "reopen log");
				if (log4cpp::Appender::reopenAll()) {
					sub1.info("log reopened");
				} else {
					sub1.warn("could not reopen log");
				}
			}
#ifndef WIN32
			sleep(1);
#endif
			log4cpp::NDC::pop();
		}
	}

	return 0;
}
