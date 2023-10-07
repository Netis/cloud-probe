dnl @synopsis PETI_PEDANTIC_GCC
dnl
dnl For development purposes, it is desirable to have autoconf
dnl automatically enable warnings when compiling C or C++ sources. In
dnl case the underlying compiler is a gcc, the appropriate flags are
dnl "-Wall -pedantic". This macro will add them to $CFLAGS and
dnl $CXXFLAGS if $CC is found to be a gcc.
dnl
dnl @author Peter Simons <simons@computer.org>
dnl original version: peti_pedantic_gcc.m4,v 1.4 2000/12/31 10:18:09 simons
dnl @version $Id$

AC_DEFUN([PETI_PEDANTIC_GCC],
    [
    if test "$GCC" = yes; then
 	if test "$host" = x86-pc-nto-qnx; then
 	    CFLAGS="$CXXFLAGS -Wno-unused -O0"
 	    CXXFLAGS="$CXXFLAGS -Wno-unused -DLOG4CPP_MISSING_INT64_OSTREAM_OP -O0"
        else
            case `$CXX --version` in
                *2.97*) CFLAGS="$CFLAGS -Wall -Wno-unused -pedantic -D_ISOC99_SOURCE"
                        CXXFLAGS="$CXXFLAGS -Wall -Wno-unused -pedantic -D_ISOC99_SOURCE" 
                        ;;
                *2.96*) CFLAGS="$CFLAGS -Wall -Wno-unused"
                        CXXFLAGS="$CXXFLAGS -Wall -Wno-unused" 
                        ;;
	        *)      CFLAGS="$CFLAGS -Wall -Wno-unused -pedantic"
                        CXXFLAGS="$CXXFLAGS -Wall -Wno-unused -pedantic"
                        ;;
            esac
        fi
    fi
    ])
