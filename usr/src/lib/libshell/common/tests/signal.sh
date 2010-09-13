########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2010 AT&T Intellectual Property          #
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

tmp=$(mktemp -dt) || { err_exit mktemp -dt failed; exit 1; }
trap "cd /; rm -rf $tmp" EXIT

cd $tmp || err_exit "cd $tmp failed"

(
	set --pipefail
	{
		$SHELL 2> out2 <<- \EOF
			g=false
			trap 'print -u2 PIPED; $g && exit 0;g=true' PIPE
			while :
			do 	print hello
			done
		EOF
	} | head > /dev/null
	(( $? == 0)) ||   err_exit "SIGPIPE with wrong error code $?"
	[[ $(<out2) == $'PIPED\nPIPED' ]] || err_exit 'SIGPIPE output on standard error is not correct'
) &
cop=$!
{ sleep 4; kill $cop; } 2>/dev/null &
spy=$!
if	wait $cop 2>/dev/null
then	kill $spy 2>/dev/null
else	err_exit "pipe with --pipefail PIPE trap hangs"
fi
wait
rm -f out2

[[ $( trap 'print -n got_child' SIGCHLD
	sleep 2 &
	for	((i=0; i < 4; i++))
	do 	sleep .75
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
#     x trap, echo on SIGINT, and tst-3 exit 0, tst-2 exit, otherwise SIGINT default
#     z trap, echo on SIGINT, and tst-3 exit 0, tst-2 exit 0, otherwise SIGINT default
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
	for x in - x z
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
*z*)	trap '
		echo 2-intr
		exit 0
	' INT
	;;
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
*[xz]*)	trap '
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
expected[x--]="3-intr 2-intr"
expected[x-d]="3-intr 2-intr"
expected[xt-]="3-intr 2-intr 1-intr 1-0258"
expected[xtd]="3-intr 2-intr 1-intr 1-0258"
expected[z--]="3-intr 2-intr 1-0000"
expected[z-d]="3-intr 2-intr 1-0000"
expected[zt-]="3-intr 2-intr 1-intr 1-0000"
expected[ztd]="3-intr 2-intr 1-intr 1-0000"

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

unset n s t
for s in $(kill -l)
do	if	! n=$(kill -l $s 2>/dev/null)
	then	err_exit "'kill -l $s' failed"
		continue
	fi
	if	! t=$(kill -l $n 2>/dev/null)
	then	err_exit "'kill -l $n' failed"
		continue
	fi
	if	[[ $s == ?(SIG)$t ]]
	then	continue
	fi
	if	! m=$(kill -l $t 2>/dev/null)
	then	err_exit "'kill -l $t' failed"
		continue
	fi
	if	[[ $m == $n ]]
	then	continue
	fi
	err_exit "'kill -l $s' => $n, 'kill -l $n' => $t, kill -l $t => $m -- expected $n"
done
yes=$(whence -p yes)
[[ $yes ]] && for exp in TERM VTALRM PIPE
do { $SHELL <<- EOF
		foo() { return 0; }
		trap foo EXIT
		{ sleep 2; kill -$exp \$\$; sleep 3; kill -0 \$\$ && kill -KILL \$\$; } &
		$yes | while read yes; do
		        (/bin/date; sleep .1)
		done > /dev/null
	EOF
    } 2>> /dev/null
    got=$(kill -l $?)
    [[ $exp == $got ]] || err_exit "kill -$exp \$\$ failed, required termination by signal '$got'"
done

SECONDS=0
$SHELL 2> /dev/null -c 'sleep 2 && kill $$ & trap "print done;exit 3" EXIT; (sleep 5);print finished' > $tmp/sig
(( $?==3)) || err_exit "wrong exit status expecting 3 got $?"
x=$(<$tmp/sig)
[[ $x == done ]] || err_exit "wrong result - execting done got $x"
(( SECONDS > 3.5 )) && err_exit "took $SECONDS seconds, expecting around 2"

SECONDS=0
{ $SHELL 2> /dev/null -c 'sleep 2 && kill $$ & trap "print done;exit" EXIT; (sleep 5);print finished' > $tmp/sig ;} 2> /dev/null
[[ $(kill -l $?) == TERM ]] || err_exit "wrong exit status expecting TERM got $(kill -l $?)"
x=$(<$tmp/sig)
[[ $x == done ]] || err_exit "wrong result - execting done got $x"
(( SECONDS > 3.5 )) && err_exit "took $SECONDS seconds, expecting around 2"

SECONDS=0
x=$($SHELL 2> /dev/null -c 'sleep 2 && kill $$ & trap "print done;exit 3" EXIT; (sleep 5);print finished')
(( $?==3)) || err_exit "wrong exit status expecting 3 got $?"
[[ $x == done ]] || err_exit "wrong result - execting done got $x"
(( SECONDS < 4 )) && err_exit "took $SECONDS seconds, expecting around 5"

trap '' SIGBUS
[[ $($SHELL -c 'trap date SIGBUS;trap -p SIGBUS') ]] && err_exit 'SIGBUS should not have a trap'
trap -- - SIGBUS

exit $((Errors))
