/*
 * Copyright 2002, Log4cpp Project. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#include <log4cpp/threading/Threading.hh>
#include <cstdlib>

#if defined(LOG4CPP_HAVE_THREADING) && defined(LOG4CPP_USE_PTHREADS)

namespace log4cpp {
    namespace threading {

        std::string getThreadId() {
            char buffer[4*sizeof(long)];
            int bufsize = sizeof(buffer)/sizeof(buffer[0]);
            int n = ::snprintf(buffer, bufsize, "%lu", pthread_self());	// thread id unsigned
            if (n >= bufsize) {
            	// escape to heap allocation
				char *buff_alloc;
				int size = ::asprintf(&buff_alloc, "%lu", pthread_self());	// thread id unsigned
				if (size < 0) {
					throw std::bad_alloc();
				}
				std::string res(buff_alloc);
				free(buff_alloc);
				return res;
            }
            return std::string(buffer);
        }

    }
}

#endif // LOG4CPP_HAVE_THREADING && LOG4CPP_USE_PTHREADS
