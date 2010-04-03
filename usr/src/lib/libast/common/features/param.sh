########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1985-2010 AT&T Intellectual Property          #
#                      and is licensed under the                       #
#                  Common Public License, Version 1.0                  #
#                    by AT&T Intellectual Property                     #
#                                                                      #
#                A copy of the License is available at                 #
#            http://www.opensource.org/licenses/cpl1.0.txt             #
#         (with md5 checksum 059e8cd6165cb4c31e351f2b69388fd9)         #
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
: generate "<sys/param.h> + <sys/types.h> + <sys/stat.h>" include sequence
case $# in
0)	;;
*)	eval $1
	shift
	;;
esac
for i in "#include <sys/param.h>" "#include <sys/param.h>
#ifndef S_IFDIR
#include <sys/stat.h>
#endif" "#include <sys/param.h>
#ifndef S_IFDIR
#include <sys/types.h>
#include <sys/stat.h>
#endif" "#ifndef S_IFDIR
#include <sys/types.h>
#include <sys/stat.h>
#endif"
do	echo "$i
struct stat V_stat_V;
F_stat_F() { V_stat_V.st_mode = 0; }" > $tmp.c
	if	$cc -c $tmp.c >/dev/null
	then	echo "$i"
		break
	fi
done
