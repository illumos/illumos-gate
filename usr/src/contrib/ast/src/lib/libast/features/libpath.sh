########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1985-2011 AT&T Intellectual Property          #
#                      and is licensed under the                       #
#                 Eclipse Public License, Version 1.0                  #
#                    by AT&T Intellectual Property                     #
#                                                                      #
#                A copy of the License is available at                 #
#          http://www.eclipse.org/org/documents/epl-v10.html           #
#         (with md5 checksum b35adb5213ca9657e911e9befb180842)         #
#                                                                      #
#              Information and Software Systems Research               #
#                            AT&T Research                             #
#                           Florham Park NJ                            #
#                                                                      #
#                 Glenn Fowler <gsf@research.att.com>                  #
#                  David Korn <dgk@research.att.com>                   #
#                   Phong Vo <kpv@research.att.com>                    #
#                                                                      #
########################################################################
ok=0
for i in \
	-x /lib/ld.so /lib/ld-*.so /usr/lib/ld.so /lib/rld \
	-f /usr/shlib/libc.so /shlib/libc.so /usr/lib/libc.so \
	-r /usr/shlib/libc.so /shlib/libc.so
do	case $i in
	-*)	op=$i; continue ;;
	esac
	if	test $op $i
	then	ok=1
		break
	fi
	set x $i.[0-9]*
	if	test $op $2
	then	ok=1
		break
	fi
done
if	test "0" != "$ok"
then	libpath=lib:LD_LIBRARY_PATH
	case `package` in
	sgi.*)	if	test -d /lib32
		then	libpath="lib32:LD_LIBRARYN32_PATH:sgi.mips3|sgi.*-n32,$libpath"
		fi
		if	test -d /lib64
		then	libpath="lib64:LD_LIBRARY64_PATH:sgi.mips[4-9]|sgi.*-64,$libpath"
		fi
		;;
	sol*.*) if	test -d /lib/32
		then	libpath="lib/32:LD_LIBRARY_PATH_32,$libpath"
		fi
		if	test -d /lib/64
		then	libpath="lib/64:LD_LIBRARY_PATH_64:sol.*64*,$libpath"
		fi
		;;
	esac
elif	test -x /lib/dld.sl
then	libpath=lib:SHLIB_PATH
elif	test -x /usr/lib/dyld
then	libpath=lib:DYLD_LIBRARY_PATH
else	case `package` in
	ibm.*|mvs.*)
		libpath=lib:LIBPATH
		;;
	*)	libpath=
		;;
	esac
fi
case $libpath in
'')	libpath=bin ;;
esac
echo "#define CONF_LIBPATH	\"$libpath\""
