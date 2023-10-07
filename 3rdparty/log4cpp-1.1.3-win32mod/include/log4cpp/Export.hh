/*
 * Copyright 2002, LifeLine Networks BV (www.lifeline.nl). All rights reserved.
 * Copyright 2002, Bastiaan Bakker. All rights reserved.
 *
 * See the COPYING file for the terms of usage and distribution.
 */

#ifndef _LOG4CPP_EXPORT_HH
#define _LOG4CPP_EXPORT_HH

#ifdef LOG4CPP_HAS_DLL
#	ifdef LOG4CPP_BUILD_DLL
#		if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__MINGW32__)
#			define LOG4CPP_EXPORT __declspec(dllexport)
#               else
#			define LOG4CPP_EXPORT
#               endif 
#	else
#		if defined(_MSC_VER) || defined(__BORLANDC__) || defined(__MINGW32__)
#			define LOG4CPP_EXPORT __declspec(dllimport)
#               else
#			define LOG4CPP_EXPORT
#               endif 
#	endif
#else
#	define LOG4CPP_EXPORT 
#endif

#endif // _LOG4CPP_EXPORT_HH

