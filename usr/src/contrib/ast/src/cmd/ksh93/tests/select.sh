########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2011 AT&T Intellectual Property          #
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
#                  David Korn <dgk@research.att.com>                   #
#                                                                      #
########################################################################
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	let Errors+=1
}
alias err_exit='err_exit $LINENO'

Command=${0##*/}
integer Errors=0

tmp=$(mktemp -dt) || { err_exit mktemp -dt failed; exit 1; }
trap "cd /; rm -rf $tmp" EXIT

PS3='ABC '

cat > $tmp/1 <<\!
1) foo
2) bar
3) bam
!

select i in foo bar bam
do	case $i in
	foo)	break;;
	*)	err_exit "select 1 not working"
		break;;
	esac
done 2> /dev/null <<!
1
!

unset i
select i in foo bar bam
do	case $i in
	foo)	err_exit "select foo not working" 2>&3
		break;;
	*)	if	[[ $REPLY != foo ]]
		then	err_exit "select REPLY not correct" 2>&3
		fi
		( set -u; : $i ) || err_exit "select: i not set to null" 2>&3
		break;;
	esac
done  3>&2 2> $tmp/2 <<!
foo
!

exit $((Errors<125?Errors:125))
