// testConfig.cpp : Derived from testPattern.cpp.
//

#include <log4cpp/Portability.hh>

#ifdef WIN32
#include <windows.h>
#endif
#ifdef LOG4CPP_HAVE_UNISTD_H
#include <unistd.h>
#endif

#include <iostream>

#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <log4cpp/HierarchyMaintainer.hh>

#include <stdlib.h>
#include <crtdbg.h>

void testPropConfigRead() {
    std::string initFileName;
#if defined(WIN32)
        initFileName = "./log4cpp.nt.property";
#else
        initFileName = "./log4cpp.property";
#endif
    log4cpp::PropertyConfigurator::configure(initFileName);

    log4cpp::Category& root = log4cpp::Category::getRoot();

    log4cpp::Category& sub1 = 
        log4cpp::Category::getInstance(std::string("sub1"));

    log4cpp::Category& sub2 = 
        log4cpp::Category::getInstance(std::string("sub1.sub2"));

    root.error("root error");
    root.warn("root warn");
    sub1.error("sub1 error");
    sub1.warn("sub1 warn");
    // the following 2 should only be in A1, not A2
    sub1.info("sub1 info");
    sub1.debug("sub1 debug");

    // do a few so that the log rolls over
    sub2.warn("sub2 warn 1");
    sub2.warn("sub2 warn 2");
    sub2.warn("sub2 warn 3");
    sub2.warn("sub2 warn 4");
    sub2.warn("sub2 warn 5");
    sub2.warn("sub2 warn 6");
    sub2.warn("sub2 warn 7");

#if defined(WIN32)
    log4cpp::Category& nt = 
        log4cpp::Category::getInstance(std::string("subNT"));
    nt.error("subNT error");
    nt.warn("subNT warn");
    nt.debug("subNT debug");
#endif

    log4cpp::Category::shutdownForced(); 
//    log4cpp::Category::shutdown(); 
}

int main(int argc, char* argv[])
{
// _CRTDBG_MAP_ALLOC is for detecting memory leaks on Windows
#ifdef _CRTDBG_MAP_ALLOC
	_CrtSetDbgFlag ( _CRTDBG_ALLOC_MEM_DF | _CRTDBG_LEAK_CHECK_DF );
#endif

    try {
		// test single properties read
		testPropConfigRead();

		// test few more instantiations and shutdowns by shutdownForced()
		for (int i=0; i < 2; ++i) {
			testPropConfigRead();
		}
    } catch(log4cpp::ConfigureFailure& f) {
        std::cout << "Configure Problem " << f.what() << std::endl;
        return -1; 
    }

#ifdef _CRTDBG_MAP_ALLOC
	//_CrtDumpMemoryLeaks(); // would give detected leaks, since statically allocated objects were not freed yet
#endif
	return 0;
}
