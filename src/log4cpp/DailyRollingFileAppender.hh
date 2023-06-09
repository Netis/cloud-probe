/*
 * DailyRollingFileAppender.hh
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#ifndef _LOG4CPP_DAILYROLLINGFILEAPPENDER_HH
#define _LOG4CPP_DAILYROLLINGFILEAPPENDER_HH

#include <log4cpp/Portability.hh>
#include <log4cpp/FileAppender.hh>
#include <string>
#include <stdarg.h>

namespace log4cpp {

    /**
       DailyRollingFileAppender is a FileAppender that rolls over the logfile once
       the next day starts.
       @since 1.1.2
    **/
    class LOG4CPP_EXPORT DailyRollingFileAppender : public FileAppender {
        public:
        DailyRollingFileAppender(const std::string& name,
                            const std::string& fileName,
                            unsigned int maxDaysToKeep = maxDaysToKeepDefault,
                            bool append = true,
                            mode_t mode = 00644);

        virtual void setMaxDaysToKeep(unsigned int maxDaysToKeep);
        virtual unsigned int getMaxDaysToKeep() const;

        virtual void rollOver();

        static unsigned int maxDaysToKeepDefault;
        protected:
        virtual void _append(const LoggingEvent& event);

        unsigned int _maxDaysToKeep;
        // last log's file creation time (or last modification if appender just created)
        struct tm _logsTime;
    };
}

#endif // _LOG4CPP_DAILYROLLINGFILEAPPENDER_HH
