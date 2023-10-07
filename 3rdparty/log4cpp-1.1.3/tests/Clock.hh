/* $Id$
 * 
 * See the COPYING file for the terms of usage and distribution.
 */

#ifndef __CLOCK_H
#define __CLOCK_H

#include <log4cpp/Portability.hh>

#ifdef LOG4CPP_HAVE_STDINT_H
#include <stdint.h>
#endif // LOG4CPP_HAVE_STDINT_H

#ifdef __osf__
    typedef long usec_t;    /* number of microseconds since 1970/01/01 */
#   define INT64_CONSTANT(val)  (val##L)
#else
    typedef int64_t usec_t;
#   define INT64_CONSTANT(val)  (val##LL)
#endif

class Clock
{
public:
    static bool		UsingCPU;
    static usec_t 	time(void);

    			Clock(void);
    			~Clock(void);

    bool		active(void) const { return _active; }
    usec_t		elapsed(void) const;
    usec_t		start(void);
    usec_t		reset(void) { return start(); }
    usec_t		stop(void);

private:
    usec_t		_start;    
    usec_t		_elapsed;
    bool		_active;
};

#endif
