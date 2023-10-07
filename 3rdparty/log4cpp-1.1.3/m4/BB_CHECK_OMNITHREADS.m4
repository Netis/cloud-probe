dnl@synposis BB_CHECK_OMNITHREADS.m4
dnl
AC_DEFUN([BB_CHECK_OMNITHREADS],[
AC_REQUIRE([AC_PROG_CC])dnl
AC_REQUIRE([AC_PROG_CXX])dnl
AC_REQUIRE([AC_PROG_CPP])dnl
AC_REQUIRE([AC_PROG_CXXCPP])dnl


AC_ARG_WITH(omnithreads, [  --with-omnithreads      include omnithreads support], [OMNIDIR=${with_omnithreads}], [OMNIDIR=no])

if test "x$OMNIDIR" = "xyes"; then
    OMNIDIR=/usr
fi

if test "x$OMNIDIR" = "x"; then
    OMNIDIR=no
fi

if test "x$OMNIDIR" != "xno"; then
    case $host_cpu in
        sparc*)
            OMNIDEFINES=-D__sparc__
            ;;
        i386)
            OMNIDEFINES=-D__x86__
            ;;
        i486)
            OMNIDEFINES=-D__x86__
            ;;
        i586)
            OMNIDEFINES=-D__x86__
            ;;
        i686)
            OMNIDEFINES=-D__x86__
            ;;
        *)
            AC_MSG_ERROR([unknown CPU: $host_cpu])
            ;;
    esac

    case $host_os in
        solaris*)
            OMNIDEFINES="$OMNIDEFINES -D__sunos__ -D__OSVERSION__=5"
            ;;
        linux*)
            OMNIDEFINES="$OMNIDEFINES -D__linux__ -D__OSVERSION__=2"
            ;;
        *)
            AC_MSG_ERROR([unknown OS: $host_os])
            ;;
    esac

    CPPFLAGS="$CPPFLAGS -D_PTHREADS -D_REENTRANT -D_THREAD_SAFE"
    CFLAGS="$CFLAGS $OMNIDEFINES -I$OMNIDIR/include"
    CXXFLAGS="$CXXCFLAGS $OMNIDEFINES -I$OMNIDIR/include"
    dnl AC_CHECK_HEADERS([omnithread.h])

    AC_LANG_PUSH(C++)

    LIBS="$LIBS -L$OMNIDIR/lib -lomnithread"
    AC_CACHE_CHECK([for omnithreads library],
    bb_cv_check_omnithreads,
    AC_TRY_LINK(
        #include <omnithread.h>
        ,omni_mutex my_mutex,
        bb_cv_check_omnithreads=yes,bb_cv_check_omnithreads=no)
    )
    if test "x$bb_cv_check_omnithreads" = "xno"; then
        AC_MSG_ERROR([omnithreads not found])
    fi

    AC_DEFINE(HAVE_THREADING,,[define if threading is enabled])
    AC_DEFINE(USE_OMNITHREADS,,[define if omnithread library is available])

    AC_LANG_POP(C++)
fi
])
