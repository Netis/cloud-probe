/*
 * Copyright 2002, Log4cpp Project. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#ifndef _LOG4CPP_LOCALTIME_HH
#define _LOG4CPP_LOCALTIME_HH

#include <time.h>

namespace log4cpp
{
   void localtime(const ::time_t* time, ::tm* t);
}

#endif
