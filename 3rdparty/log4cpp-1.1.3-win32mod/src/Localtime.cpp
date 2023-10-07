/*
 * Copyright 2002, Log4cpp Project. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#include <log4cpp/Portability.hh>
#include "Localtime.hh"
#include <time.h>
#include <memory.h>

namespace log4cpp         
{

#if defined(_MSC_VER) && defined(LOG4CPP_HAVE_LOCALTIME_R)
   void localtime(const ::time_t* time, ::tm* t)
   {
      localtime_s(t, time);  
   }
#endif

#if !defined(_MSC_VER) && defined(LOG4CPP_HAVE_LOCALTIME_R)
   void localtime(const ::time_t* time, ::tm* t)
   {
      localtime_r(time, t);
   }
#endif

#if !defined(LOG4CPP_HAVE_LOCALTIME_R)
   void localtime(const ::time_t* time, ::tm* t)
   {
      ::tm* tmp = ::localtime(time);
      memcpy(t, tmp, sizeof(::tm));
   }
#endif

}
