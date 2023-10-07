/*
 * DailyRollingFileAppender.cpp
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#include "PortabilityImpl.hh"
#ifdef LOG4CPP_HAVE_IO_H
#    include <io.h>
#endif
#ifdef LOG4CPP_HAVE_UNISTD_H
#    include <unistd.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <log4cpp/DailyRollingFileAppender.hh>
#include <log4cpp/Category.hh>
#include <log4cpp/FactoryParams.hh>
#include <memory>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <iostream>

#ifdef LOG4CPP_HAVE_SSTREAM
#include <sstream>
#include <iomanip>
#endif

#ifndef WIN32    // only available on Win32
#include <dirent.h>
#endif

namespace log4cpp {

	unsigned int DailyRollingFileAppender::maxDaysToKeepDefault = 30;

    DailyRollingFileAppender::DailyRollingFileAppender(const std::string& name,
                                             const std::string& fileName, 
                                             unsigned int maxDaysToKeep,
                                             bool append,
                                             mode_t mode) :
        FileAppender(name, fileName, append, mode),
        _maxDaysToKeep(maxDaysToKeep != 0 ? maxDaysToKeep : maxDaysToKeepDefault) {
		struct stat statBuf;
		int res;
		time_t t;

		// obtain last modification time
		res = ::stat(fileName.c_str(), &statBuf);
		if (res < 0) {
			t = time(NULL);
		} else {
			t = statBuf.st_mtime;
		}
#ifndef WIN32    // only available on Win32
		localtime_r(&t, &_logsTime);
#else
		localtime_s(&_logsTime, &t);
#endif
	}

	void DailyRollingFileAppender::setMaxDaysToKeep(unsigned int maxDaysToKeep) {
		_maxDaysToKeep = maxDaysToKeep;
	}

	unsigned int DailyRollingFileAppender::getMaxDaysToKeep() const {
		return _maxDaysToKeep;
	}

	void DailyRollingFileAppender::rollOver()
	{
		std::ostringstream filename_s;
		int res_close = ::close(_fd);
		if (res_close != 0) {
			std::cerr << "Error closing file " << _fileName << std::endl;
		}
		filename_s << _fileName << "." << _logsTime.tm_year + 1900 << "-"
						<< std::setfill('0') << std::setw(2) << _logsTime.tm_mon + 1 << "-"
						<< std::setw(2) << _logsTime.tm_mday << std::ends;
		const std::string lastFn = filename_s.str();
		int res_rename = ::rename(_fileName.c_str(), lastFn.c_str());
		if (res_rename != 0) {
			std::cerr << "Error renaming file " << _fileName << " to " << lastFn << std::endl;
		}

		_fd = ::open(_fileName.c_str(), _flags, _mode);
		if (_fd == -1) {
			std::cerr << "Error opening file " << _fileName << std::endl;
		}

		const time_t oldest = time(NULL) - _maxDaysToKeep * 60 * 60 * 24;

#ifndef WIN32 
#define PATHDELIMITER "/" 
#else 
#define PATHDELIMITER "\\"
#endif
		// iterate over files around log file and delete older with same prefix
		const std::string::size_type last_delimiter = _fileName.rfind(PATHDELIMITER);
		const std::string dirname((last_delimiter == std::string::npos)? "." : _fileName.substr(0, last_delimiter));
		const std::string filname((last_delimiter == std::string::npos)? _fileName : _fileName.substr(last_delimiter+1, _fileName.size()-last_delimiter-1));
#ifndef WIN32    // only available on Win32
		struct dirent **entries;
		int nentries = scandir(dirname.c_str(), &entries, 0, alphasort);
		if (nentries < 0)
			return;
		for (int i = 0; i < nentries; i++) {
			struct stat statBuf;
			const std::string fullfilename = dirname + PATHDELIMITER + entries[i]->d_name;
			int res = ::stat(fullfilename.c_str(), &statBuf);
			if ((res == -1) || (!S_ISREG(statBuf.st_mode))) {
				free(entries[i]);
				continue;
			}
			if (statBuf.st_mtime < oldest && strstr(entries[i]->d_name, filname.c_str())) {
				std::cout << " Deleting " << fullfilename.c_str() << std::endl;
				::unlink(fullfilename.c_str());
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
			struct stat statBuf;
			const std::string fullfilename = dirname + PATHDELIMITER + ffd.cFileName;
			int res = ::stat(fullfilename.c_str(), &statBuf);
            if (res != -1 && statBuf.st_mtime < oldest && !(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                std::cout << "Deleting " << fullfilename << "\n";
				::unlink(fullfilename.c_str());
            }
        } while (FindNextFile(hFind, &ffd) != 0);

        if (GetLastError() != ERROR_NO_MORE_FILES) {
			// [XXX] some kind of error happened
        }
		FindClose(hFind);
		hFind = INVALID_HANDLE_VALUE;
	}
#endif
	}

	void DailyRollingFileAppender::_append(const log4cpp::LoggingEvent &event)
	{
		struct tm now;
		time_t t = time(NULL);

#ifndef WIN32    // only available on Win32
		bool timeok = localtime_r(&t, &now) != NULL;
#else
		bool timeok = localtime_s(&now, &t) == 0;
#endif
		if (timeok) {
			if ((now.tm_mday != _logsTime.tm_mday) ||
				(now.tm_mon != _logsTime.tm_mon) ||
				(now.tm_year != _logsTime.tm_year)) {
				rollOver();
				_logsTime = now;
			}
		}
		log4cpp::FileAppender::_append(event);
	}

   std::auto_ptr<Appender> create_daily_roll_file_appender(const FactoryParams& params)
   {
      std::string name, filename;
      bool append = true;
      mode_t mode = 664;
      unsigned int max_days_keep = 0;
      params.get_for("daily roll file appender").required("name", name)("filename", filename)("max_days_keep", max_days_keep)
                                          .optional("append", append)("mode", mode);

      return std::auto_ptr<Appender>(new DailyRollingFileAppender(name, filename, max_days_keep, append, mode));
   }
}
