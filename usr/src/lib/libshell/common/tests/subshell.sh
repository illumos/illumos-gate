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
	print -u$Error_fd -n "\t"
	print -u$Error_fd -r ${Command}[$1]: "${@:2}"
	(( Errors+=1 ))
}
alias err_exit='err_exit $LINENO'
Command=${0##*/}
integer Errors=0 Error_fd=2

z=()
z.foo=( [one]=hello [two]=(x=3 y=4) [three]=hi)
z.bar[0]=hello
z.bar[2]=world
z.bar[1]=(x=4 y=5)
val='(
	typeset -a bar=(
		[0]=hello
		[2]=world
		[1]=(
			x=4
			y=5
		)
	)
	typeset -A foo=(
		[one]=hello
		[three]=hi
		[two]=(
			x=3
			y=4
		)
	)
)'
[[ $z == "$val" ]] || err_exit 'compound variable with mixed arrays not working'
z.bar[1]=yesyes
[[ ${z.bar[1]} == yesyes ]] || err_exit 'reassign of index array compound variable fails'
z.bar[1]=(x=12 y=5)
[[ ${z.bar[1]} == $'(\n\tx=12\n\ty=5\n)' ]] || err_exit 'reassign array simple to compound variable fails'
eval val="$z"
(
	z.foo[three]=good
	[[ ${z.foo[three]} == good ]] || err_exit 'associative array assignment in subshell not working'
)
[[ $z == "$val" ]] || err_exit 'compound variable changes after associative array assignment'
eval val="$z"
(
false
	z.foo[two]=ok
	[[ ${z.foo[two]} == ok ]] || err_exit 'associative array assignment to compound variable in subshell not working'
	z.bar[1]=yes
	[[ ${z.bar[1]} == yes ]] || err_exit 'index array assignment to compound variable in subshell not working'
)
[[ $z == "$val" ]] || err_exit 'compound variable changes after associative array assignment'
	
x=(
	foo=( qqq=abc rrr=def)
	bar=( zzz=no rst=fed)
)
eval val="$x"
(
	unset x.foo
	[[ ${x.foo.qqq} ]] && err_exit 'x.foo.qqq should be unset'
	x.foo=good
	[[ ${x.foo} == good ]] || err_exit 'x.foo should be good'
)
[[ $x == "$val" ]] || err_exit 'compound variable changes after unset leaves'
unset l
(
	l=( a=1 b="BE" )
)
[[ ${l+foo} != foo ]] || err_exit 'l should be unset'

Error_fd=9
eval "exec $Error_fd>&2 2>/dev/null"

TEST_notfound=notfound
while	whence $TEST_notfound >/dev/null 2>&1
do	TEST_notfound=notfound-$RANDOM
done

tmp=/tmp/kshsubsh$$
trap "rm -f $tmp" EXIT
integer BS=1024 nb=64 ss=60 bs no
for bs in $BS 1
do	$SHELL -c '
		{
			sleep '$ss'
			kill -KILL $$
		} &
		set -- $(printf %.'$(($BS*$nb))'c x | dd bs='$bs')
		print ${#1}
		kill $!
	' > $tmp 2>/dev/null
	no=$(<$tmp)
	(( no == (BS * nb) )) || err_exit "shell hangs on command substitution output size >= $BS*$nb with write size $bs -- expected $((BS*nb)), got ${no:-0}"
done
# this time with redirection on the trailing command
for bs in $BS 1
do	$SHELL -c '
		{
			sleep 2
			sleep '$ss'
			kill -KILL $$
		} &
		set -- $(printf %.'$(($BS*$nb))'c x | dd bs='$bs' 2>/dev/null)
		print ${#1}
		kill $!
	' > $tmp 2>/dev/null
	no=$(<$tmp)
	(( no == (BS * nb) )) || err_exit "shell hangs on command substitution output size >= $BS*$nb with write size $bs and trailing redirection -- expected $((BS*nb)), got ${no:-0}"
done

# exercise command substitutuion trailing newline logic w.r.t. pipe vs. tmp file io

set -- \
	'post-line print'								\
	'$TEST_unset; ($TEST_fork; print 1); print'					\
	1										\
	'pre-line print'								\
	'$TEST_unset; ($TEST_fork; print); print 1'					\
	$'\n1'										\
	'multiple pre-line print'							\
	'$TEST_unset; ($TEST_fork; print); print; ($TEST_fork; print 1); print'		\
	$'\n\n1'									\
	'multiple post-line print'							\
	'$TEST_unset; ($TEST_fork; print 1); print; ($TEST_fork; print); print'		\
	1										\
	'intermediate print'								\
	'$TEST_unset; ($TEST_fork; print 1); print; ($TEST_fork; print 2); print'	\
	$'1\n\n2'									\
	'simple variable'								\
	'$TEST_unset; ($TEST_fork; l=2; print "$l"); print $l'				\
	2										\
	'compound variable'								\
	'$TEST_unset; ($TEST_fork; l=(a=2 b="BE"); print "$l"); print $l'		\
	$'(\n\ta=2\n\tb=BE\n)'								\

export TEST_fork TEST_unset

while	(( $# >= 3 ))
do	txt=$1
	cmd=$2
	exp=$3
	shift 3
	for TEST_unset in '' 'unset var'
	do	for TEST_fork in '' 'ulimit -c 0'
		do	for TEST_shell in "eval" "$SHELL -c"
			do	if	! got=$($TEST_shell "$cmd")
				then	err_exit "${TEST_shell/*-c/\$SHELL -c} ${TEST_unset:+unset }${TEST_fork:+fork }$txt print failed"
				elif	[[ "$got" != "$exp" ]]
				then	EXP=$(printf %q "$exp")
					GOT=$(printf %q "$got")
					err_exit "${TEST_shell/*-c/\$SHELL -c} ${TEST_unset:+unset }${TEST_fork:+fork }$txt command substitution failed -- expected $EXP, got $GOT"
				fi
			done
		done
	done
done

r=$( ($SHELL -c '
	{
		sleep 32
		kill -KILL $$
	} &
	for v in $(set | sed "s/=.*//")
	do	command unset $v
	done
	typeset -Z5 I
	for ((I = 0; I < 1024; I++))
	do	eval A$I=1234567890
	done
	a=$(set 2>&1)
	print ok
	kill -KILL $!
') 2>/dev/null)
[[ $r == ok ]] || err_exit "large subshell command substitution hangs"

for TEST_command in '' $TEST_notfound
do	for TEST_exec in '' 'exec'
	do	for TEST_fork in '' 'ulimit -c 0;'
		do	for TEST_redirect in '' '>/dev/null'
			do	for TEST_substitute in '' ': $'
				do

	TEST_test="$TEST_substitute($TEST_fork $TEST_exec $TEST_command $TEST_redirect)"
	[[ $TEST_test == '('*([[:space:]])')' ]] && continue
	r=$($SHELL -c '
		{
			sleep 2
			kill -KILL $$
		} &
		'"$TEST_test"'
		kill $!
		print ok
		')
	[[ $r == ok ]] || err_exit "shell hangs on $TEST_test"

				done
			done
		done
	done
done

exit $Errors
