AC_DEFUN([BB_ENABLE_REMOTE_SYSLOG],
[
AC_ARG_ENABLE(remote-syslog, [  --disable-remote-syslog disables remote syslog appender], [], [ enable_remote_syslog=yes])

# for RemoteSyslogAppender
if test "x$enable_remote_syslog" = xyes; then
    AC_CHECK_LIB(socket,socket, LIBS="-lsocket $LIBS",,)
    AC_CHECK_LIB(nsl,gethostbyname, LIBS="-lnsl $LIBS",,)
else
    AC_DEFINE(DISABLE_REMOTE_SYSLOG,1,[define if RemoteSyslogAppender is disabled])
fi

AM_CONDITIONAL([DISABLE_REMOTE_SYSLOG], [test "x$enable_remote_syslog" != xyes])
])
