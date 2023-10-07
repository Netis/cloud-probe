#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <iostream>

#include <log4cpp/Category.hh>
#include <log4cpp/OstreamAppender.hh>
#include <log4cpp/FileAppender.hh>
#include <log4cpp/BasicLayout.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/TimeStamp.hh>

#include "Clock.hh"


// -----------------------------------------------------------------------------
int main(int argc, char* argv[])
{
    int    count  = argc > 1 ? std::atoi(argv[1]) : 100;
    size_t size   = argc > 2 ? std::atoi(argv[2]) : 128;    

    std::cout << "  count: " << count << std::endl
	      << "   size: " << size  << " bytes" << std::endl
	      << std::endl;

    log4cpp::Category&	root	 = log4cpp::Category::getRoot();
    root.setPriority(log4cpp::Priority::ERROR);    

    log4cpp::OstreamAppender ostreamAppender("cerr", &std::cerr);
    log4cpp::FileAppender fileAppender("stderr", fileno(stderr));
    ostreamAppender.setLayout(new log4cpp::BasicLayout());
    fileAppender.setLayout(new log4cpp::BasicLayout());

    root.removeAllAppenders();
    root.addAppender(ostreamAppender);

    log4cpp::Category& log = log4cpp::Category::getInstance("someCategory");

    Clock  clock;
    char*  buffer = new char[size + 1];
    
    std::memset(buffer, 'X', size + 1);
    buffer[size] = '\0';

    std::cout << "BasicLayout:" << std::endl;
    {	
	clock.start();
	for (int i = 0; i < count; i++) log.error("%s", buffer);    
	clock.stop();
	std::cout << "  charbuf printf  ostream:  " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }
    
    {	
        const char* buffer2 = buffer;
	clock.start();
	for (int i = 0; i < count; i++) log.error(std::string(buffer2));    
	clock.stop();
	std::cout << "  charbuf string  ostream:  " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }

    {
	std::string str(size, 'X');

	clock.start();
	for (int i = 0; i < count; i++) 
            log << log4cpp::Priority::ERROR << str;
	clock.stop();
	std::cout << "  string  stream  ostream:  " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }

    {
	clock.start();
	for (int i = 0; i < count; i++) 
            log << log4cpp::Priority::ERROR << buffer;
	clock.stop();
	std::cout << "  charbuf stream  ostream:  " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }
    
    {
	std::string str(size, 'X');

	clock.start();
        log4cpp::CategoryStream s(log << log4cpp::Priority::ERROR);
	for (int i = 0; i < count; i++) 
            s << str << log4cpp::eol;
	clock.stop();
	std::cout << "  string  stream2 ostream:  " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }

    {
	clock.start();
        log4cpp::CategoryStream s(log << log4cpp::Priority::ERROR);
	for (int i = 0; i < count; i++) 
            s << buffer << log4cpp::eol;
	clock.stop();
	std::cout << "  charbuf stream2 ostream:  " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }
    
    {
	std::string str(size, 'X');
	
	clock.start();
	for (int i = 0; i < count; i++) log.error(str);
	clock.stop();
	std::cout << "  direct  string  ostream:  " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }

    {
	std::string str(size, 'X');
        root.removeAllAppenders();
        root.addAppender(fileAppender);

	clock.start();
	for (int i = 0; i < count; i++) log.error(str);
	clock.stop();
	std::cout << "  direct  string  file:     " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }

    std::cout << "PatternLayout:" << std::endl;
    {
        log4cpp::PatternLayout* patternLayout = new log4cpp::PatternLayout();
        patternLayout->setConversionPattern("%R %p %c %x: %m\n");
        ostreamAppender.setLayout(patternLayout);
    }
    {
        log4cpp::PatternLayout* patternLayout = new log4cpp::PatternLayout();
        patternLayout->setConversionPattern("%R %p %c %x: %m\n");
        fileAppender.setLayout(patternLayout);
    }

    root.removeAllAppenders();
    root.addAppender(ostreamAppender);

    {	
	clock.start();
	for (int i = 0; i < count; i++) log.error("%s", buffer);    
	clock.stop();
	std::cout << "  charbuf printf ostream:  " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }
    
    {
	std::string str(size, 'X');
	
	clock.start();
	for (int i = 0; i < count; i++) log.error(str);
	clock.stop();
	std::cout << "  direct  string ostream:  " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }

    {
	std::string str(size, 'X');
        root.removeAllAppenders();
        root.addAppender(fileAppender);

	clock.start();
	for (int i = 0; i < count; i++) log.error(str);
	clock.stop();
	std::cout << "  string  file:     " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }

    {
	clock.start();
	for (int i = 0; i < count; i++) fprintf(stderr, "%d ERROR someCategory : %s\n", log4cpp::TimeStamp().getSeconds(), buffer);
	clock.stop();
	std::cout << std::endl << "  fprintf:        " << ((float)clock.elapsed()) / count << " us" << std::endl;
    }

    delete[] buffer;
    log4cpp::Category::shutdown();

    return 0;
}
