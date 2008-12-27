########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2008 AT&T Intellectual Property          #
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
#                  David Korn <dgk@research.att.com>                   #
#                                                                      #
########################################################################
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors++ ))
}
alias err_exit='err_exit $LINENO'

Command=${0##*/}
integer Errors=0

mkdir /tmp/ksh$$ || err_exit "mkdir /tmp/ksh$$ failed"
trap 'cd /; rm -rf /tmp/ksh$$' EXIT
cd /tmp/ksh$$ || err_exit "cd /tmp/ksh$$ failed"

[[ $( trap 'print -n got_child' SIGCHLD
	sleep 2 &
	for	((i=0; i < 4; i++))
	do 	sleep .9
		print -n $i
	done) == 01got_child23 ]] || err_exit 'SIGCHLD not working'

# begin standalone SIGINT test generation

cat > tst <<'!'
# shell trap tests
#
#    tst  control script that calls tst-1, must be run by ksh
#  tst-1  calls tst-2
#  tst-2  calls tst-3
#  tst-3  defaults or handles and discards/propagates SIGINT
#
# initial -v option lists script entry and SIGINT delivery
#
# three test options
#
#     d call next script directly, otherwise via $SHELL -c
#     t trap, echo, and kill self on SIGINT, otherwise x or SIGINT default if no x
#     x trap, echo on SIGINT, and exit 0, otherwise SIGINT default
#
# Usage: tst [-v] [-options] shell-to-test ...

# "trap + sig" is an unadvertized extension for this test
# if run from nmake SIGINT is set to SIG_IGN
# this call sets it back to SIG_DFL
# semantics w.r.t. function scope must be worked out before
# making it public
trap + INT

set -o monitor

function gen
{
	typeset o t x d
	for x in - x
	do	case $x in
		[$1])	for t in - t
			do	case $t in
				[$1])	for d in - d
					do	case $d in
						[$1])	o="$o $x$t$d"
						esac
					done
				esac
			done
		esac
	done
	echo '' $o
}

case $1 in
-v)	v=v; shift ;;
-*v*)	v=v ;;
*)	v= ;;
esac
case $1 in
*' '*)	o=$1; shift ;;
-*)	o=$(gen $1); shift ;;
*)	o=$(gen -txd) ;;
esac
case $# in
0)	set ksh bash ksh88 pdksh ash zsh ;;
esac
for f in $o
do	case $# in
	1)	;;
	*)	echo ;;
	esac
	for sh
	do	if	$sh -c 'exit 0' > /dev/null 2>&1
		then	case $# in
			1)	printf '%3s ' "$f" ;;
			*)	printf '%16s %3s ' "$sh" "$f" ;;
			esac
			$sh tst-1 $v$f $sh > tst.out &
			wait
			echo $(cat tst.out)
		fi
	done
done
case $# in
1)	;;
*)	echo ;;
esac
!
cat > tst-1 <<'!'
exec 2>/dev/null
case $1 in
*v*)	echo 1-main ;;
esac
{
	sleep 2
	case $1 in
	*v*)	echo "SIGINT" ;;
	esac
	kill -s INT 0
} &
case $1 in
*t*)	trap '
		echo 1-intr
		trap - INT
		# omitting the self kill exposes shells that deliver
		# the SIGINT trap but exit 0 for -xt
		# kill -s INT $$
	' INT
	;;
esac
case $1 in
*d*)	tst-2 $1 $2; status=$? ;;
*)	$2 -c "tst-2 $1 $2"; status=$? ;;
esac
printf '1-%04d\n' $status
sleep 2
!
cat > tst-2 <<'!'
case $1 in
*x*)	trap '
		echo 2-intr
		exit
	' INT
	;;
*t*)	trap '
		echo 2-intr
		trap - INT
		kill -s INT $$
	' INT
	;;
esac
case $1 in
*v*)	echo 2-main ;;
esac
case $1 in
*d*)	tst-3 $1 $2; status=$? ;;
*)	$2 -c "tst-3 $1 $2"; status=$? ;;
esac
printf '2-%04d\n' $status
!
cat > tst-3 <<'!'
case $1 in
*x*)	trap '
		sleep 2
		echo 3-intr
		exit 0
	' INT
	;;
*)	trap '
		sleep 2
		echo 3-intr
		trap - INT
		kill -s INT $$
	' INT
	;;
esac
case $1 in
*v*)	echo 3-main ;;
esac
sleep 5
printf '3-%04d\n' $?
!
chmod +x tst tst-?

# end standalone test generation

export PATH=$PATH:
typeset -A expected
expected[---]="3-intr"
expected[--d]="3-intr"
expected[-t-]="3-intr 2-intr 1-intr 1-0258"
expected[-td]="3-intr 2-intr 1-intr 1-0258"
expected[x--]="3-intr 2-intr 1-0000"
expected[x-d]="3-intr 2-intr 1-0000"
expected[xt-]="3-intr 2-intr 1-intr 1-0000"
expected[xtd]="3-intr 2-intr 1-intr 1-0000"

tst $SHELL > tst.got

while	read ops out
do	[[ $out == ${expected[$ops]} ]] || err_exit "interrupt $ops test failed -- expected '${expected[$ops]}', got '$out'"
done < tst.got

float s=$SECONDS
[[ $($SHELL -c 'trap "print SIGUSR1 ; exit 0" USR1; (trap "" USR1 ; exec kill -USR1 $$ & sleep 5); print done') == SIGUSR1 ]] || err_exit 'subshell ignoring signal does not send signal to parent' 
(( (SECONDS-s) < 4 )) && err_exit 'parent does not wait for child to complete before handling signal'
((s = SECONDS))
[[ $($SHELL -c 'trap "print SIGUSR1 ; exit 0" USR1; (trap "exit" USR1 ; exec kill -USR1 $$ & sleep 5); print done') == SIGUSR1 ]] || err_exit 'subshell catching signal does not send signal to parent' 
(( SECONDS-s < 4 )) && err_exit 'parent completes early'
exit $((Errors))
