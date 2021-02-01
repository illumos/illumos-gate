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

bar=foo2
bam=foo[3]
for i in foo1 foo2 foo3 foo4 foo5 foo6
do	foo=0
	case $i in
	foo1)	foo=1;;
	$bar)	foo=2;;
	$bam)	foo=3;;
	foo[4])	foo=4;;
	${bar%?}5)
		foo=5;;
	"${bar%?}6")
		foo=6;;
	esac
	if	[[ $i != foo$foo ]]
	then	err_exit "$i not matching correct pattern"
	fi
done
f="[ksh92]"
case $f in
\[*\])  ;;
*)      err_exit "$f does not match \[*\]";;
esac

if	[[ $($SHELL -c '
		x=$(case abc {
			abc)	{ print yes;};;
			*)	 print no;;
			}
		)
		print -r -- "$x"' 2> /dev/null) != yes ]]
then err_exit 'case abc {...} not working'
fi
[[ $($SHELL -c 'case a in
a)      print -n a > /dev/null ;&
b)      print b;;
esac') != b ]] && err_exit 'bug in ;& at end of script'
[[ $(VMDEBUG=1 $SHELL -c '
	tmp=foo
	for i in a b
	do	case $i in
		a)	:  tmp=$tmp tmp.h=$tmp.h;;
		b)	( tmp=bar )
			for j in a
			do	print -r -- $tmp.h
			done
			;;
		esac
	done
') == foo.h ]] || err_exit "optimizer bug"

x=$($SHELL -ec 'case a in a) echo 1; false; echo 2 ;& b) echo 3;; esac')
[[ $x == 1 ]] || err_exit 'set -e ignored on case fail through'

exit $((Errors<125?Errors:125))
