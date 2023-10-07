# Configure paths for LOG4CPP
# Owen Taylor     97-11-3

dnl AM_PATH_LOG4CPP([MINIMUM-VERSION, [ACTION-IF-FOUND [, ACTION-IF-NOT-FOUND]]])
dnl Test for LOG4CPP, and define LOG4CPP_CFLAGS and LOG4CPP_LIBS
dnl
AC_DEFUN([AM_PATH_LOG4CPP],
[dnl 
dnl Get the cflags and libraries from the log4cpp-config script
dnl
AC_ARG_WITH(log4cpp-prefix,[  --with-log4cpp-prefix=PFX   Prefix where LOG4CPP is installed (optional)],
            log4cpp_config_prefix="$withval", log4cpp_config_prefix="")
AC_ARG_WITH(log4cpp-exec-prefix,[  --with-log4cpp-exec-prefix=PFX Exec prefix where LOG4CPP is installed (optional)],
            log4cpp_config_exec_prefix="$withval", log4cpp_config_exec_prefix="")
AC_ARG_ENABLE(log4cpptest, [  --disable-log4cpptest       Do not try to compile and run a test LOG4CPP program],
		    , enable_log4cpptest=yes)

  if test x$log4cpp_config_exec_prefix != x ; then
     log4cpp_config_args="$log4cpp_config_args --exec-prefix=$log4cpp_config_exec_prefix"
     if test x${LOG4CPP_CONFIG+set} != xset ; then
        LOG4CPP_CONFIG=$log4cpp_config_exec_prefix/bin/log4cpp-config
     fi
  fi
  if test x$log4cpp_config_prefix != x ; then
     log4cpp_config_args="$log4cpp_config_args --prefix=$log4cpp_config_prefix"
     if test x${LOG4CPP_CONFIG+set} != xset ; then
        LOG4CPP_CONFIG=$log4cpp_config_prefix/bin/log4cpp-config
     fi
  fi

  AC_PATH_PROG(LOG4CPP_CONFIG, log4cpp-config, no)
  min_log4cpp_version=ifelse([$1], ,0.99.7,$1)
  AC_MSG_CHECKING(for LOG4CPP - version >= $min_log4cpp_version)
  no_log4cpp=""
  if test "$LOG4CPP_CONFIG" = "no" ; then
    no_log4cpp=yes
  else
    LOG4CPP_CFLAGS=`$LOG4CPP_CONFIG $log4cpp_config_args --cflags`
    LOG4CPP_LIBS=`$LOG4CPP_CONFIG $log4cpp_config_args --libs`
    log4cpp_config_major_version=`$LOG4CPP_CONFIG $log4cpp_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\1/'`
    log4cpp_config_minor_version=`$LOG4CPP_CONFIG $log4cpp_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\2/'`
    log4cpp_config_micro_version=`$LOG4CPP_CONFIG $log4cpp_config_args --version | \
           sed 's/\([[0-9]]*\).\([[0-9]]*\).\([[0-9]]*\)/\3/'`
    if test "x$enable_log4cpptest" = "xyes" ; then
      ac_save_CFLAGS="$CFLAGS"
      ac_save_CXXFLAGS="$CXXFLAGS"
      ac_save_LIBS="$LIBS"
      CFLAGS="$CFLAGS $LOG4CPP_CFLAGS"
      CXXFLAGS="$CXXFLAGS $LOG4CPP_CFLAGS"
      LIBS="$LOG4CPP_LIBS $LIBS"
dnl
dnl Now check if the installed LOG4CPP is sufficiently new. (Also sanity
dnl checks the results of log4cpp-config to some extent
dnl
      rm -f conf.log4cpptest
      AC_TRY_RUN([
#include <log4cpp/Category.hh>
#include <stdio.h>
#include <stdlib.h>

int 
main ()
{
  int log4cpp_major, log4cpp_minor, log4cpp_micro;
  int major, minor, micro;
  char *tmp_version;
  char *tmp_log4cpp_version;

  system ("touch conf.log4cpptest");

  /* HP/UX 9 (%@#!) writes to sscanf strings */
  tmp_version = strdup("$min_log4cpp_version");
  if (sscanf(tmp_version, "%d.%d.%d", &major, &minor, &micro) != 3) {
     printf("%s, bad version string\n", "$min_log4cpp_version");
     exit(1);
   }

   /* HP/UX 9 (%@#!) writes to sscanf strings */
   tmp_log4cpp_version = strdup(LOG4CPP_VERSION);
   if (sscanf(tmp_log4cpp_version, "%d.%d.%d", &log4cpp_major, &log4cpp_minor, &log4cpp_micro) != 3) {
     printf("%s, bad log4cpp version string\n", LOG4CPP_VERSION);
     exit(1);
   }

   if ((log4cpp_major > major) ||
      ((log4cpp_major == major) && (log4cpp_minor > minor)) ||
      ((log4cpp_major == major) && (log4cpp_minor == minor) && (log4cpp_micro >= micro)))
   {
        return 0;
   }
   else
   {
        printf("\n*** An old version of LOG4CPP (%d.%d.%d) was found.\n",
               log4cpp_major, log4cpp_minor, log4cpp_micro);
        printf("*** You need a version of LOG4CPP newer than %d.%d.%d. The latest version of\n",
	       major, minor, micro);
        printf("***\n");
        printf("*** If you have already installed a sufficiently new version, this error\n");
        printf("*** probably means that the wrong copy of the log4cpp-config shell script is\n");
        printf("*** being found. The easiest way to fix this is to remove the old version\n");
        printf("*** of LOG4CPP, but you can also set the LOG4CPP_CONFIG environment to point to the\n");
        printf("*** correct copy of log4cpp-config. (In this case, you will have to\n");
        printf("*** modify your LD_LIBRARY_PATH enviroment variable, or edit /etc/ld.so.conf\n");
        printf("*** so that the correct libraries are found at run-time))\n");
   }

   log4cpp::Category& log = log4cpp::Category::getRoot();
   return 1;
}
],, no_log4cpp=yes,[echo $ac_n "cross compiling; assumed OK... $ac_c"])
       CFLAGS="$ac_save_CFLAGS"
       CXXFLAGS="$ac_save_CXXFLAGS"
       LIBS="$ac_save_LIBS"
     fi
  fi
  if test "x$no_log4cpp" = x ; then
     AC_MSG_RESULT(yes)
     ifelse([$2], , :, [$2])     
  else
     AC_MSG_RESULT(no)
if test "$LOG4CPP_CONFIG" = "no" ; then
echo "*** The log4cpp-config script installed by LOG4CPP could not be found"
       echo "*** If LOG4CPP was installed in PREFIX, make sure PREFIX/bin is in"
       echo "*** your path, or set the LOG4CPP_CONFIG environment variable to the"
       echo "*** full path to log4cpp-config."
     else
       if test -f conf.log4cpptest ; then
        :
       else
          echo "*** Could not run LOG4CPP test program, checking why..."
          CFLAGS="$CFLAGS $LOG4CPP_CFLAGS"
          CXXFLAGS="$CXXFLAGS $LOG4CPP_CFLAGS"
          LIBS="$LIBS $LOG4CPP_LIBS"
          AC_TRY_LINK([
#include <log4cpp/Category.hh>
],      [ log4cpp::Category::getRoot(); return 0; ],
        [ echo "*** The test program compiled, but did not run. This usually means"
          echo "*** that the run-time linker is not finding LOG4CPP or finding the wrong"
          echo "*** version of LOG4CPP. If it is not finding LOG4CPP, you'll need to set your"
          echo "*** LD_LIBRARY_PATH environment variable, or edit /etc/ld.so.conf to point"
          echo "*** to the installed location  Also, make sure you have run ldconfig if that"
          echo "*** is required on your system"
	  echo "***"
          echo "*** If you have an old version installed, it is best to remove it, although"
          echo "*** you may also be able to get things to work by modifying LD_LIBRARY_PATH"
          echo "***" ],
        [ echo "*** The test program failed to compile or link. See the file config.log for the"
          echo "*** exact error that occured. This usually means LOG4CPP was incorrectly installed"
          echo "*** or that you have moved LOG4CPP since it was installed. In the latter case, you"
          echo "*** may want to edit the log4cpp-config script: $LOG4CPP_CONFIG" ])
          CFLAGS="$ac_save_CFLAGS"
          CXXFLAGS="$ac_save_CXXFLAGS"
          LIBS="$ac_save_LIBS"
       fi
     fi
     LOG4CPP_CFLAGS=""
     LOG4CPP_LIBS=""
     ifelse([$3], , :, [$3])
  fi
  AC_SUBST(LOG4CPP_CFLAGS)
  AC_SUBST(LOG4CPP_LIBS)
  rm -f conf.log4cpptest
])
