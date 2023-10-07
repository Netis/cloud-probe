AC_DEFUN([BB_ENABLE_SMTP],
[
AC_ARG_ENABLE(smtp, [  --disable-smtp          disables SMTP appender], [], [ enable_smtp=yes])

# for SmtpAppender
if test "x$enable_smtp" != xyes; then
    AC_DEFINE(DISABLE_SMTP,1,[define if SmtpAppender is disabled])
fi

AM_CONDITIONAL([DISABLE_SMTP], [test "x$enable_smtp" != xyes])
])
