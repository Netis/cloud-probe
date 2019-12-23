set -x
aclocal
autoheader
automake --add-missing --copy -i
autoconf
#./configure $* 
