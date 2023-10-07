#include <log4cpp/Category.hh>
#include <log4cpp/PropertyConfigurator.hh>
#include <log4cpp/DailyRollingFileAppender.hh>
#include <log4cpp/PatternLayout.hh>
#include <log4cpp/OstreamAppender.hh>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <iostream>
#include <ctime>
#include <sys/stat.h>
#include <fcntl.h>
#include <memory>
#include <cstring>

#ifdef LOG4CPP_HAVE_IO_H
#    include <io.h>
#endif
#ifdef LOG4CPP_HAVE_UNISTD_H
#    include <unistd.h>
#endif

#ifndef WIN32    // only available on Win32
#include <dirent.h>
#else
#include <direct.h>  
#endif

#ifdef WIN32
#pragma comment(lib, "Ws2_32.lib")
#endif

using namespace log4cpp;
using namespace std;
static const char* const test_message = "message";
static const char* const daily_file_prefix = "dailyrolling_file.log";
static const char* const nestedDir = "nesteddir";
#ifndef WIN32 
#define PATHDELIMITER "/" 
#else 
#define PATHDELIMITER "\\"
#endif
const char* const nesteddirname = "nesteddir"PATHDELIMITER;


class DailyRollingTest {
	DailyRollingFileAppender* dailyApp, *nestedDirDailyApp;
public:
	bool remove_impl(const char* filename)
	{
	   int res = remove(filename);

	   if (res != 0 && errno != ENOENT)
		  cout << "Can't remove file '" << filename << "'.\n";

	   return res == 0 || (res != 0 && errno == ENOENT);
	}

	bool remove_files()
	{
//	   if (!remove_impl(daily_file_prefix))
//		  return false;

	   return true;
	}

	bool setup()
	{
	   if (!remove_files())
		  return false;

	   Category& root = Category::getRoot();
	   dailyApp = new DailyRollingFileAppender("daily-rolling-appender", daily_file_prefix, 1);
	   nestedDirDailyApp = new DailyRollingFileAppender("nesteddir-daily-rolling-appender", std::string(nesteddirname).append(daily_file_prefix), 1);
	   root.addAppender(dailyApp);
	   root.addAppender(nestedDirDailyApp);
	   root.setPriority(Priority::DEBUG);

	   return true;
	}

	void make_log_files()
	{
	   Category::getRoot().debugStream() << test_message << 1;
	   Category::getRoot().debugStream() << test_message << 2;
	   Category::getRoot().debugStream() << test_message << 3;
	   Category::getRoot().debugStream() << "The message before rolling over attempt";
	   dailyApp->rollOver();
	   nestedDirDailyApp->rollOver();
	   Category::getRoot().debugStream() << "The message after rolling over attempt";
	   Category::getRoot().debugStream() << test_message << 4;
	   Category::getRoot().debugStream() << test_message << 5;
	}

	bool exists(const char* filename)
	{
	   FILE* f = fopen(filename, "r");
	   if (f == NULL)
	   {
		  cout << "File '" << filename << "' doesn't exists.\n";
		  return false;
	   }

	   fclose(f);

	   return true;
	}

	bool check_log_files()
	{
	   bool result = exists(daily_file_prefix);

	   Category::shutdown();
	   return result && remove_files();
	}
};

int testOnlyDailyRollingFileAppender() {
	DailyRollingTest dailyTest;
	   if (!dailyTest.setup())
	   {
	      cout << "Setup has failed. Check for permissions on files " << daily_file_prefix << "*'.\n";
	      return -1;
	   }

	   dailyTest.make_log_files();

	   if (dailyTest.check_log_files())
	      return 0;
	   else
	      return -1;
}

int testConfigDailyRollingFileAppender()
{
		/* looking for the init file in $srcdir is a requirement of
		   automake's distcheck target.
		*/
		const char* srcdir = getenv("srcdir");
		std::string initFileName;
	   try {
#if defined(WIN32)
        initFileName = "./testConfig.log4cpp.dailyroll.nt.properties";
#else
        initFileName = "./testConfig.log4cpp.dailyroll.properties";
#endif
			if (srcdir != NULL) {
	            initFileName = std::string(srcdir) + PATHDELIMITER + initFileName;
	        }

	        log4cpp::PropertyConfigurator::configure(initFileName);
	    } catch(log4cpp::ConfigureFailure& f) {
	        std::cout << "Configure Problem " << f.what() << "($srcdir=" << ((srcdir != NULL)?srcdir:"NULL") << ")" << std::endl;
	        return -1;
	    }

	    log4cpp::Category& root = log4cpp::Category::getRoot();

	    log4cpp::Category& sub1 =
	        log4cpp::Category::getInstance(std::string("sub1"));

	    root.error("root error");
	    root.warn("root warn");
	    sub1.error("sub1 error");
	    sub1.warn("sub1 warn");

	    log4cpp::Category::shutdown();
	    return 0;
}

//  Note: this test changes system time. Run it only manually
namespace OnlyManualTesting {

	const char* absolutePathCategoryName = "absolutePathCategory";
	const int maxDaysToKeep = 3;

#if defined(WIN32)
    const char *logFilename = "C:\\Temp\\log4cpp\\dailyrolling_abs_path_file.log";
    const char *logPathname = "C:\\Temp\\log4cpp";
#else
    const char *logFilename = "/var/log/log4cpp/dailyrolling_abs_path_file.log";
    const char *logPathname = "/var/log/log4cpp";
#endif

    void setupManualEntryLog() {
#if defined(WIN32)
		if (access(logPathname, 0) != 0) {
			mkdir(logPathname);
		}
#else
		if (access(logPathname, F_OK) != 0) {
			mkdir(logPathname, 644);
		}
#endif

		log4cpp::PatternLayout *ostreamLayout = new log4cpp::PatternLayout();
		ostreamLayout->setConversionPattern("%d: %p %c %x: %m %n");
		log4cpp::Appender *ostreamAppender = new log4cpp::OstreamAppender("ostreamAppender", &std::cout);
		ostreamAppender->setLayout(ostreamLayout);

		log4cpp::PatternLayout *fileLayout = new log4cpp::PatternLayout();
		fileLayout->setConversionPattern("%d: %p %c %x: %m %n");
		log4cpp::Appender *fileAppender = new log4cpp::DailyRollingFileAppender("fileAppender", logFilename, maxDaysToKeep);
		fileAppender->setLayout(fileLayout);

		log4cpp::Category& absolutePathCategory =
				log4cpp::Category::getInstance(std::string(absolutePathCategoryName));
		absolutePathCategory.setAdditivity(false);

		absolutePathCategory.addAppender(ostreamAppender);
		absolutePathCategory.addAppender(fileAppender);
		absolutePathCategory.setPriority(log4cpp::Priority::DEBUG);
	}

    int checkThatNoMoreThanNLogFilesPresent(const std::string _fileName, int n);

	int jumpToFuture(int seconds) {
		
#if defined(WIN32)
		SYSTEMTIME now;
		GetSystemTime(&now);
		now.wDay += seconds / (24*60*60);
		now.wSecond += 1;
		if (SetSystemTime(&now) == 0) {
			std::cerr << "Can not change system time. Probably not today... Try running as admin? Err: " << GetLastError() << std::endl;
			return -1;
		}
#else
		time_t  now;
		if (time(&now) == -1)
			return -1;

		now += seconds;

		if (stime(&now) == -1) {
			std::cerr << "Can not set date. Need admin privileges?" << std::endl;
			return -1;
		}
#endif
		return 0;
	}

	int makeManualEntryLog()
	{
		const int totalLinesCount = 14, linesPerDay=3, jumpPeriod=24*60*60 + 1;
		int i = 0, future = 0;

		log4cpp::Category& absolutePathCategory =
				log4cpp::Category::getInstance(std::string(absolutePathCategoryName));

		// 1. update system time (eg: use 'date' command on Linux) manually when test program is running here (at least 4 times)
        absolutePathCategory.debugStream() << "debug line " << i;
		while (++i <= totalLinesCount) {
			if (i % linesPerDay == 0) {
				if (jumpToFuture(jumpPeriod) == -1)
					return -1;
				future += jumpPeriod;
			}
            absolutePathCategory.debugStream() << "debug line " << i;
		}

		if (jumpToFuture(0-future) == -1)
			return -1;

        // 2. check the number of files in /var/log/log4cpp ( <= maxDaysToKeep) (+1 to allow consequent runs of test)
        if (checkThatNoMoreThanNLogFilesPresent(std::string(logFilename), maxDaysToKeep + 1) == -1)
            return -1;

		return 0;
	}

//  Note: this test changes system time. Run it only manually
    int checkThatNoMoreThanNLogFilesPresent(const std::string _fileName, int n) {
        // iterate over files around log file and count files with same prefix
        const std::string::size_type last_delimiter = _fileName.rfind(PATHDELIMITER);
        const std::string dirname((last_delimiter == std::string::npos)? "." : _fileName.substr(0, last_delimiter));
        const std::string filname((last_delimiter == std::string::npos)? _fileName : _fileName.substr(last_delimiter+1, _fileName.size()-last_delimiter-1));
        int logFilesCount(0);
#ifndef WIN32    // only available on Win32
        struct dirent **entries;
        int nentries = scandir(dirname.c_str(), &entries, 0, alphasort);
        if (nentries < 0)
            return -1;
        for (int i = 0; i < nentries; i++) {
            if (strstr(entries[i]->d_name, filname.c_str())) {
                ++logFilesCount;
            }
            free(entries[i]);
        }
        free(entries);
#else
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WIN32_FIND_DATA ffd;
	const std::string pattern = _fileName + "*";

    hFind = FindFirstFile(pattern.c_str(), &ffd);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            if (!(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                ++logFilesCount;
            }
        } while (FindNextFile(hFind, &ffd) != 0);
		FindClose(hFind);
		hFind = INVALID_HANDLE_VALUE;
	}
#endif
        if (logFilesCount > n) {
            std::cerr << "Too many log files in the dir " << dirname << ": " << logFilesCount << std::endl;
        } else {
            std::cout << "Daily log files in the dir " << dirname << ": " << logFilesCount << std::endl;
        }

        return (logFilesCount <= n) ? 0 : -1;
    }

	int testDailyRollingFileAppenderChangeDateManualOnly() {
		setupManualEntryLog();
		return makeManualEntryLog();
	}
}

int main()
{
	int res = testOnlyDailyRollingFileAppender();
	if (!res)
		res = testConfigDailyRollingFileAppender();

//  Note: this test changes system time. Run it only manually
//	if (!res)
//		res = OnlyManualTesting::testDailyRollingFileAppenderChangeDateManualOnly();

	return res;
}
