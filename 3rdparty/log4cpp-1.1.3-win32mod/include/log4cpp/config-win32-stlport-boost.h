/*
 * Copyright 2002, LifeLine Networks BV (www.lifeline.nl). All rights reserved.
 * Copyright 2002, Bastiaan Bakker. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#ifndef _INCLUDE_LOG4CPP_CONFIG_WIN32_H
#define _INCLUDE_LOG4CPP_CONFIG_WIN32_H 1
 
/* manually edited from include/log4cpp/config.h */

/* Define if you have the syslog function.  */
/* #undef LOG4CPP_HAVE_SYSLOG */

/* Define if you have the `ftime' function. */
#ifndef LOG4CPP_HAVE_FTIME 
#define LOG4CPP_HAVE_FTIME  1 
#endif

/* Define if you have the `gettimeofday' function. */
/* #undef LOG4CPP_HAVE_GETTIMEOFDAY */ 

/* define if the compiler has int64_t */
#ifndef LOG4CPP_HAVE_INT64_T 
#define LOG4CPP_HAVE_INT64_T

#include <boost/cstdint.hpp>
using boost::int64_t;

#endif

/* define if the compiler has in_addr_t */
#ifndef LOG4CPP_HAVE_IN_ADDR_T 
#define LOG4CPP_HAVE_IN_ADDR_T

#ifndef u_long 
typedef unsigned long u_long;
#endif

/* u_long is the type of in_addr.s_addr */
typedef u_long in_addr_t;

/* u_short is the type of sockaddr_in.sin_port */
// typedef u_short		in_port_t;

#endif

/* Define if you have the <io.h> header file.  */
#ifndef LOG4CPP_HAVE_IO_H
#define LOG4CPP_HAVE_IO_H 1
#endif

/* Define if you have the <unistd.h> header file.  */
/* #undef LOG4CPP_HAVE_UNISTD_H */

/* Define if you have the idsa library (-lidsa).  */
/* #undef LOG4CPP_HAVE_LIBIDSA */

/* Define if you have the `strcasecmp' function. */
/* #undef LOG4CPP_HAVE_STRCASECMP */

/* Name of package */
#ifndef LOG4CPP_PACKAGE
#define LOG4CPP_PACKAGE  "log4cpp"
#endif

/* Version number of package */
#ifndef LOG4CPP_VERSION
#define LOG4CPP_VERSION  "1.0"
#endif

/* define if the compiler implements namespaces */
#ifndef LOG4CPP_HAVE_NAMESPACES
#define LOG4CPP_HAVE_NAMESPACES 1
#endif

/* define if the compiler has stringstream */
#ifndef LOG4CPP_HAVE_SSTREAM
#define LOG4CPP_HAVE_SSTREAM 1
#endif

#if defined(_MSC_VER)
#    if _MSC_VER < 1300
#       define LOG4CPP_HAS_WCHAR_T 0
#    else
#       define LOG4CPP_HAS_WCHAR_T 1
#    endif
#else
#   define LOG4CPP_HAS_WCHAR_T 1
#endif

/* define if the C library has snprintf */
#ifndef LOG4CPP_HAVE_SNPRINTF
#define LOG4CPP_HAVE_SNPRINTF 1
#endif

#if defined(_MSC_VER) && _MSC_VER >= 1300
#define LOG4CPP_HAVE_LOCALTIME_R 1
#endif

/* define to get around problems with ERROR in windows.h */
#ifndef LOG4CPP_FIX_ERROR_COLLISION
#define LOG4CPP_FIX_ERROR_COLLISION 1
#endif

/* define WIN32 for Borland */
#ifndef WIN32
#define WIN32
#endif

/* use threads */
#ifndef LOG4CPP_HAVE_THREADING
#define LOG4CPP_HAVE_THREADING
#endif

/* use boost threads */
#ifndef LOG4CPP_USE_BOOSTTHREADS
#define LOG4CPP_USE_BOOSTTHREADS
#endif

/* supply DLL main */
#ifndef LOG4CPP_SUPPLY_DLLMAIN
#define LOG4CPP_SUPPLY_DLLMAIN
#endif

/* MSVCs <cstdlib> and <cstring> headers are broken in the sense that they
   put functions in the global namespace instead of std::
   The #defines below enable a workaround for MSVC 6 and lower. If MSVC 7
   is still broken please adjust the _MSC_VER version check and report it.
   See also bug report #628211.
*/
#if defined(_MSC_VER) && _MSC_VER < 1300

#ifndef LOG4CPP_CSTDLIB_NOT_IN_STD
#define LOG4CPP_CSTDLIB_NOT_IN_STD
#endif

#ifndef LOG4CPP_CSTRING_NOT_IN_STD
#define LOG4CPP_CSTRING_NOT_IN_STD
#endif

#ifndef LOG4CPP_CTIME_NOT_IN_STD
#define LOG4CPP_CTIME_NOT_IN_STD
#endif

#ifndef LOG4CPP_CMATH_NOT_IN_STD
#define LOG4CPP_CMATH_NOT_IN_STD
#endif

#endif

/* define mode_t. Move to Portability.hh if more platforms need it */
typedef int mode_t;

/* _INCLUDE_LOG4CPP_CONFIG_WIN32_H */
#endif
