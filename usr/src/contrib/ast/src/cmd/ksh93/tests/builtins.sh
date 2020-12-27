########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2012 AT&T Intellectual Property          #
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

# test shell builtin commands
builtin getconf
: ${foo=bar} || err_exit ": failed"
[[ $foo == bar ]] || err_exit ": side effects failed"
set -- - foobar
[[ $# == 2 && $1 == - && $2 == foobar ]] || err_exit "set -- - foobar failed"
set -- -x foobar
[[ $# == 2 && $1 == -x && $2 == foobar ]] || err_exit "set -- -x foobar failed"
getopts :x: foo || err_exit "getopts :x: returns false"
[[ $foo == x && $OPTARG == foobar ]] || err_exit "getopts :x: failed"
OPTIND=1
getopts :r:s var -r
if	[[ $var != : || $OPTARG != r ]]
then	err_exit "'getopts :r:s var -r' not working"
fi
OPTIND=1
getopts :d#u OPT -d 16177
if	[[ $OPT != d || $OPTARG != 16177 ]]
then	err_exit "'getopts :d#u OPT=d OPTARG=16177' failed -- OPT=$OPT OPTARG=$OPTARG"
fi
OPTIND=1
while getopts 'ab' option -a -b
do	[[ $OPTIND == $((OPTIND)) ]] || err_exit "OPTIND optimization bug"
done

USAGE=$'[-][S:server?Operate on the specified \asubservice\a:]:[subservice:=pmserver]
    {
        [p:pmserver]
        [r:repserver]
        [11:notifyd]
    }'
set pmser p rep r notifyd -11
while	(( $# > 1 ))
do	OPTIND=1
	getopts "$USAGE" OPT -S $1
	[[ $OPT == S && $OPTARG == $2 ]] || err_exit "OPT=$OPT OPTARG=$OPTARG -- expected OPT=S OPTARG=$2"
	shift 2
done

false ${foo=bar} &&  err_exit "false failed"
read <<!
hello world
!
[[ $REPLY == 'hello world' ]] || err_exit "read builtin failed"
print x:y | IFS=: read a b
if	[[ $a != x ]]
then	err_exit "IFS=: read ... not working"
fi
read <<!
hello \
world
!
[[ $REPLY == 'hello world' ]] || err_exit "read continuation failed"
read -d x <<!
hello worldxfoobar
!
[[ $REPLY == 'hello world' ]] || err_exit "read builtin failed"
read <<\!
hello \
	world \

!
[[ $REPLY == 'hello 	world' ]] || err_exit "read continuation2 failed"
print "one\ntwo" | { read line
	print $line | /bin/cat > /dev/null
	read line
}
read <<\!
\
a\
\
\
b
!
if	[[ $REPLY != ab ]]
then	err_exit "read multiple continuation failed"
fi
if	[[ $line != two ]]
then	err_exit "read from pipeline failed"
fi
line=two
read line < /dev/null
if	[[ $line != "" ]]
then	err_exit "read from /dev/null failed"
fi
if	[[ $(print -R -) != - ]]
then	err_exit "print -R not working correctly"
fi
if	[[ $(print -- -) != - ]]
then	err_exit "print -- not working correctly"
fi
print -f "hello%nbar\n" size > /dev/null
if	((	size != 5 ))
then	err_exit "%n format of printf not working"
fi
print -n -u2 2>&1-
[[ -w /dev/fd/1 ]] || err_exit "2<&1- with built-ins has side effects"
x=$0
if	[[ $(eval 'print $0') != $x ]]
then	err_exit '$0 not correct for eval'
fi
$SHELL -c 'read x <<< hello' 2> /dev/null || err_exit 'syntax <<< not recognized'
($SHELL -c 'read x[1] <<< hello') 2> /dev/null || err_exit 'read x[1] not working'
unset x
readonly x
set -- $(readonly)
if      [[ " $@ " != *" x "* ]]
then    err_exit 'unset readonly variables are not displayed'
fi
if	[[ $(	for i in foo bar
		do	print $i
			continue 10
		done
	    ) != $'foo\nbar' ]]
then	err_exit 'continue breaks out of loop'
fi
(continue bad 2>/dev/null && err_exit 'continue bad should return an error')
(break bad 2>/dev/null && err_exit 'break bad should return an error')
(continue 0 2>/dev/null && err_exit 'continue 0 should return an error')
(break 0 2>/dev/null && err_exit 'break 0 should return an error')
breakfun() { break;}
continuefun() { continue;}
for fun in break continue
do	if	[[ $(	for i in foo
			do	${fun}fun
				print $i
			done
		) != foo ]]
	then	err_exit "$fun call in ${fun}fun breaks out of for loop"
	fi
done
if	[[ $(print -f "%b" "\a\n\v\b\r\f\E\03\\oo") != $'\a\n\v\b\r\f\E\03\\oo' ]]
then	err_exit 'print -f "%b" not working'
fi
if	[[ $(print -f "%P" "[^x].*b\$") != '*[!x]*b' ]]
then	err_exit 'print -f "%P" not working'
fi
if	[[ $(print -f "%(pattern)q" "[^x].*b\$") != '*[!x]*b' ]]
then	err_exit 'print -f "%(pattern)q" not working'
fi
if	[[ $(abc: for i in foo bar;do print $i;break abc;done) != foo ]]
then	err_exit 'break labels not working'
fi
if	[[ $(command -v if)	!= if ]]
then	err_exit	'command -v not working'
fi
read -r var <<\!

!
if	[[ $var != "" ]]
then	err_exit "read -r of blank line not working"
fi
mkdir -p $tmp/a/b/c 2>/dev/null || err_exit  "mkdir -p failed"
$SHELL -c "cd $tmp/a/b; cd c" 2>/dev/null || err_exit "initial script relative cd fails"

trap 'print TERM' TERM
exp=$'trap -- \'print TERM\' TERM\ntrap -- \'cd /; rm -rf '$tmp$'\' EXIT'
got=$(trap)
[[ $got == $exp ]] || err_exit "\$(trap) failed -- expected \"$exp\", got \"$got\""
exp='print TERM'
got=$(trap -p TERM)
[[ $got == $exp ]] || err_exit "\$(trap -p TERM) failed -- expected \"$exp\", got \"$got\""

[[ $($SHELL -c 'trap "print ok" SIGTERM; kill -s SIGTERM $$' 2> /dev/null) == ok ]] || err_exit 'SIGTERM not recognized'
[[ $($SHELL -c 'trap "print ok" sigterm; kill -s sigterm $$' 2> /dev/null) == ok ]] || err_exit 'SIGTERM not recognized'
[[ $($SHELL -c '( trap "" TERM);kill $$;print bad' == bad) ]] 2> /dev/null && err_exit 'trap ignored in subshell causes it to be ignored by parent'
${SHELL} -c 'kill -1 -$$' 2> /dev/null
[[ $(kill -l $?) == HUP ]] || err_exit 'kill -1 -pid not working'
${SHELL} -c 'kill -1 -$$' 2> /dev/null
[[ $(kill -l $?) == HUP ]] || err_exit 'kill -n1 -pid not working'
${SHELL} -c 'kill -s HUP -$$' 2> /dev/null
[[ $(kill -l $?) == HUP ]] || err_exit 'kill -HUP -pid not working'
n=123
typeset -A base
base[o]=8#
base[x]=16#
base[X]=16#
for i in d i o u x X
do	if	(( $(( ${base[$i]}$(printf "%$i" $n) )) != n  ))
	then	err_exit "printf %$i not working"
	fi
done
if	[[ $( trap 'print done' EXIT) != done ]]
then	err_exit 'trap on EXIT not working'
fi
if	[[ $( trap 'print done' EXIT; trap - EXIT) == done ]]
then	err_exit 'trap on EXIT not being cleared'
fi
if	[[ $(LC_MESSAGES=C type test) != 'test is a shell builtin' ]]
then	err_exit 'whence -v test not a builtin'
fi
builtin -d test
if	[[ $(type test) == *builtin* ]]
then	err_exit 'whence -v test after builtin -d incorrect'
fi
typeset -Z3 percent=$(printf '%o\n' "'%'")
forrmat=\\${percent}s
if      [[ $(printf "$forrmat") != %s ]]
then    err_exit "printf $forrmat not working"
fi
if	(( $(printf 'x\0y' | wc -c) != 3 ))
then	err_exit 'printf \0 not working'
fi
if	[[ $(printf "%bx%s\n" 'f\to\cbar') != $'f\to' ]]
then	err_exit 'printf %bx%s\n  not working'
fi
alpha=abcdefghijklmnop
if	[[ $(printf "%10.*s\n" 5 $alpha) != '     abcde' ]]
then	err_exit 'printf %10.%s\n  not working'
fi
float x2=.0000625
if	[[ $(printf "%10.5E\n" x2) != 6.25000E-05 ]]
then	err_exit 'printf "%10.5E" not normalizing correctly'
fi
x2=.000000001
if	[[ $(printf "%g\n" x2 2>/dev/null) != 1e-09 ]]
then	err_exit 'printf "%g" not working correctly'
fi
#FIXME#($SHELL read -s foobar <<\!
#FIXME#testing
#FIXME#!
#FIXME#) 2> /dev/null || err_exit ksh read -s var fails
if	[[ $(printf +3 2>/dev/null) !=   +3 ]]
then	err_exit 'printf is not processing formats beginning with + correctly'
fi
if	printf "%d %d\n" 123bad 78 >/dev/null 2>/dev/null
then	err_exit "printf not exiting non-zero with conversion errors"
fi
if	[[ $(trap --version 2> /dev/null;print done) != done ]]
then	err_exit 'trap builtin terminating after --version'
fi
if	[[ $(set --version 2> /dev/null;print done) != done ]]
then	err_exit 'set builtin terminating after --veresion'
fi
unset -f foobar
function foobar
{
	print 'hello world'
}
OPTIND=1
if	[[ $(getopts  $'[+?X\ffoobar\fX]' v --man 2>&1) != *'Xhello world'X* ]]
then	err_exit '\f...\f not working in getopts usage strings'
fi
if	[[ $(printf '%H\n' $'<>"& \'\tabc') != '&lt;&gt;&quot;&amp;&nbsp;&apos;&#9;abc' ]]
then	err_exit 'printf %H not working'
fi
if	[[ $(printf '%(html)q\n' $'<>"& \'\tabc') != '&lt;&gt;&quot;&amp;&nbsp;&apos;&#9;abc' ]]
then	err_exit 'printf %(html)q not working'
fi
if	[[ $( printf 'foo://ab_c%(url)q\n' $'<>"& \'\tabc') != 'foo://ab_c%3C%3E%22%26%20%27%09abc' ]]
then	err_exit 'printf %(url)q not working'
fi
if	[[ $(printf '%R %R %R %R\n' 'a.b' '*.c' '^'  '!(*.*)') != '^a\.b$ \.c$ ^\^$ ^(.*\..*)!$' ]]
then	err_exit 'printf %T not working'
fi
if	[[ $(printf '%(ere)q %(ere)q %(ere)q %(ere)q\n' 'a.b' '*.c' '^'  '!(*.*)') != '^a\.b$ \.c$ ^\^$ ^(.*\..*)!$' ]]
then	err_exit 'printf %(ere)q not working'
fi
if	[[ $(printf '%..:c\n' abc) != a:b:c ]]
then	err_exit "printf '%..:c' not working"
fi
if	[[ $(printf '%..*c\n' : abc) != a:b:c ]]
then	err_exit "printf '%..*c' not working"
fi
if	[[ $(printf '%..:s\n' abc def ) != abc:def ]]
then	err_exit "printf '%..:s' not working"
fi
if	[[ $(printf '%..*s\n' : abc def) != abc:def ]]
then	err_exit "printf '%..*s' not working"
fi
[[ $(printf '%q\n') == '' ]] || err_exit 'printf "%q" with missing arguments'
# we won't get hit by the one second boundary twice, right?
[[ $(printf '%T\n' now) == "$(date)" ]] ||
[[ $(printf '%T\n' now) == "$(date)" ]] ||
err_exit 'printf "%T" now'
behead()
{
	read line
	left=$(cat)
}
print $'line1\nline2' | behead
if	[[ $left != line2 ]]
then	err_exit "read reading ahead on a pipe"
fi
read -n1 y <<!
abc
!
exp=a
if      [[ $y != $exp ]]
then    err_exit "read -n1 failed -- expected '$exp', got '$y'"
fi
print -n $'{ read -r line;print $line;}\nhello' > $tmp/script
chmod 755 $tmp/script
if	[[ $($SHELL < $tmp/script) != hello ]]
then	err_exit 'read of incomplete line not working correctly'
fi
set -f
set -- *
if      [[ $1 != '*' ]]
then    err_exit 'set -f not working'
fi
unset pid1 pid2
false &
pid1=$!
pid2=$(
	wait $pid1
	(( $? == 127 )) || err_exit "job known to subshell"
	print $!
)
wait $pid1
(( $? == 1 )) || err_exit "wait not saving exit value"
wait $pid2
(( $? == 127 )) || err_exit "subshell job known to parent"
env=
v=$(getconf LIBPATH)
for v in ${v//,/ }
do	v=${v#*:}
	v=${v%%:*}
	eval [[ \$$v ]] && env="$env $v=\"\$$v\""
done
if	[[ $(foo=bar; eval foo=\$foo $env exec -c \$SHELL -c \'print \$foo\') != bar ]]
then	err_exit '"name=value exec -c ..." not working'
fi
$SHELL -c 'OPTIND=-1000000; getopts a opt -a' 2> /dev/null
[[ $? == 1 ]] || err_exit 'getopts with negative OPTIND not working'
getopts 'n#num' opt  -n 3
[[ $OPTARG == 3 ]] || err_exit 'getopts with numerical arguments failed'
if	[[ $($SHELL -c $'printf \'%2$s %1$s\n\' world hello') != 'hello world' ]]
then	err_exit 'printf %2$s %1$s not working'
fi
val=$(( 'C' ))
set -- \
	"'C"	$val	0	\
	"'C'"	$val	0	\
	'"C'	$val	0	\
	'"C"'	$val	0	\
	"'CX"	$val	1	\
	"'CX'"	$val	1	\
	"'C'X"	$val	1	\
	'"CX'	$val	1	\
	'"CX"'	$val	1	\
	'"C"X'	$val	1
while (( $# >= 3 ))
do	arg=$1 val=$2 code=$3
	shift 3
	for fmt in '%d' '%g'
	do	out=$(printf "$fmt" "$arg" 2>/dev/null)
		err=$(printf "$fmt" "$arg" 2>&1 >/dev/null)
		printf "$fmt" "$arg" >/dev/null 2>&1
		ret=$?
		[[ $out == $val ]] || err_exit "printf $fmt $arg failed -- expected '$val', got '$out'"
		if	(( $code ))
		then	[[ $err ]] || err_exit "printf $fmt $arg failed, error message expected"
		else	[[ $err ]] && err_exit "$err: printf $fmt $arg failed, error message not expected -- got '$err'"
		fi
		(( $ret == $code )) || err_exit "printf $fmt $arg failed -- expected exit code $code, got $ret"
	done
done
((n=0))
((n++)); ARGC[$n]=1 ARGV[$n]=""
((n++)); ARGC[$n]=2 ARGV[$n]="-a"
((n++)); ARGC[$n]=4 ARGV[$n]="-a -v 2"
((n++)); ARGC[$n]=4 ARGV[$n]="-a -v 2 x"
((n++)); ARGC[$n]=4 ARGV[$n]="-a -v 2 x y"
for ((i=1; i<=n; i++))
do	set -- ${ARGV[$i]}
	OPTIND=0
	while	getopts -a tst "av:" OPT
	do	:
	done
	if	[[ $OPTIND != ${ARGC[$i]} ]]
	then	err_exit "\$OPTIND after getopts loop incorrect -- expected ${ARGC[$i]}, got $OPTIND"
	fi
done
options=ab:c
optarg=foo
set -- -a -b $optarg -c bar
while	getopts $options opt
do	case $opt in
	a|c)	[[ $OPTARG ]] && err_exit "getopts $options \$OPTARG for flag $opt failed, expected \"\", got \"$OPTARG\"" ;;
	b)	[[ $OPTARG == $optarg ]] || err_exit "getopts $options \$OPTARG failed -- \"$optarg\" expected, got \"$OPTARG\"" ;;
	*)	err_exit "getopts $options failed -- got flag $opt" ;;
	esac
done

[[ $($SHELL 2> /dev/null -c 'readonly foo; getopts a: foo -a blah; echo foo') == foo ]] || err_exit 'getopts with readonly variable causes script to abort'

unset a
{ read -N3 a; read -N1 b;}  <<!
abcdefg
!
exp=abc
[[ $a == $exp ]] || err_exit "read -N3 here-document failed -- expected '$exp', got '$a'"
exp=d
[[ $b == $exp ]] || err_exit "read -N1 here-document failed -- expected '$exp', got '$b'"
read -n3 a <<!
abcdefg
!
exp=abc
[[ $a == $exp ]] || err_exit "read -n3 here-document failed -- expected '$exp', got '$a'"
#(print -n a;sleep 1; print -n bcde) | { read -N3 a; read -N1 b;}
#[[ $a == $exp ]] || err_exit "read -N3 from pipe failed -- expected '$exp', got '$a'"
#exp=d
#[[ $b == $exp ]] || err_exit "read -N1 from pipe failed -- expected '$exp', got '$b'"
#(print -n a;sleep 1; print -n bcde) | read -n3 a
#exp=a
#[[ $a == $exp ]] || err_exit "read -n3 from pipe failed -- expected '$exp', got '$a'"
#rm -f $tmp/fifo
#if	mkfifo $tmp/fifo 2> /dev/null
#then	(print -n a; sleep 1;print -n bcde)  > $tmp/fifo &
#	{
#	read -u5 -n3 -t2 a || err_exit 'read -n3 from fifo timedout'
#	read -u5 -n1 -t2 b || err_exit 'read -n1 from fifo timedout'
#	} 5< $tmp/fifo
#	exp=a
#	[[ $a == $exp ]] || err_exit "read -n3 from fifo failed -- expected '$exp', got '$a'"
#	rm -f $tmp/fifo
#	mkfifo $tmp/fifo 2> /dev/null
#	(print -n a; sleep 1;print -n bcde) > $tmp/fifo &
#	{
#	read -u5 -N3 -t2 a || err_exit 'read -N3 from fifo timed out'
#	read -u5 -N1 -t2 b || err_exit 'read -N1 from fifo timedout'
#	} 5< $tmp/fifo
#	exp=abc
#	[[ $a == $exp ]] || err_exit "read -N3 from fifo failed -- expected '$exp', got '$a'"
#	exp=d
#	[[ $b == $exp ]] || err_exit "read -N1 from fifo failed -- expected '$exp', got '$b'"
#fi
#rm -f $tmp/fifo

function longline
{
	integer i
	for((i=0; i < $1; i++))
	do	print argument$i
	done
}
# test command -x option
integer sum=0 n=10000
if	! ${SHELL:-ksh} -c 'print $#' count $(longline $n) > /dev/null  2>&1
then	for i in $(command command -x ${SHELL:-ksh} -c 'print $#;[[ $1 != argument0 ]]' count $(longline $n) 2> /dev/null)
	do	((sum += $i))
	done
	(( sum == n )) || err_exit "command -x processed only $sum arguments"
	command -p command -x ${SHELL:-ksh} -c 'print $#;[[ $1 == argument0 ]]' count $(longline $n) > /dev/null  2>&1
	[[ $? != 1 ]] && err_exit 'incorrect exit status for command -x'
fi
# test command -x option with extra arguments
integer sum=0 n=10000
if      ! ${SHELL:-ksh} -c 'print $#' count $(longline $n) > /dev/null  2>&1
then    for i in $(command command -x ${SHELL:-ksh} -c 'print $#;[[ $1 != argument0 ]]' count $(longline $n) one two three) #2> /dev/null)
	do      ((sum += $i))
	done
	(( sum  > n )) || err_exit "command -x processed only $sum arguments"
	(( (sum-n)%3==0 )) || err_exit "command -x processed only $sum arguments"
	(( sum == n+3)) && err_exit "command -x processed only $sum arguments"
	command -p command -x ${SHELL:-ksh} -c 'print $#;[[ $1 == argument0 ]]' count $(longline $n) > /dev/null  2>&1
	[[ $? != 1 ]] && err_exit 'incorrect exit status for command -x'
fi
# test for debug trap
[[ $(typeset -i i=0
	trap 'print $i' DEBUG
	while (( i <2))
	do	(( i++))
	done) == $'0\n0\n1\n1\n2' ]]  || err_exit  "DEBUG trap not working"
getconf UNIVERSE - ucb
[[ $($SHELL -c 'echo -3') == -3 ]] || err_exit "echo -3 not working in ucb universe"
typeset -F3 start_x=SECONDS total_t delay=0.02
typeset reps=50 leeway=5
sleep $(( 2 * leeway * reps * delay )) |
for (( i=0 ; i < reps ; i++ ))
do	read -N1 -t $delay
done
(( total_t = SECONDS - start_x ))
if	(( total_t > leeway * reps * delay ))
then	err_exit "read -t in pipe taking $total_t secs - $(( reps * delay )) minimum - too long"
elif	(( total_t < reps * delay ))
then	err_exit "read -t in pipe taking $total_t secs - $(( reps * delay )) minimum - too fast"
fi
$SHELL -c 'sleep $(printf "%a" .95)' 2> /dev/null || err_exit "sleep doesn't except %a format constants"
$SHELL -c 'test \( ! -e \)' 2> /dev/null ; [[ $? == 1 ]] || err_exit 'test \( ! -e \) not working'
[[ $(ulimit) == "$(ulimit -fS)" ]] || err_exit 'ulimit is not the same as ulimit -fS'
tmpfile=$tmp/file.2
print $'\nprint -r -- "${.sh.file} ${LINENO} ${.sh.lineno}"' > $tmpfile
[[ $( . "$tmpfile") == "$tmpfile 2 1" ]] || err_exit 'dot command not working'
print -r -- "'xxx" > $tmpfile
[[ $($SHELL -c ". $tmpfile"$'\n print ok' 2> /dev/null) == ok ]] || err_exit 'syntax error in dot command affects next command'

float sec=$SECONDS del=4
exec 3>&2 2>/dev/null
$SHELL -c "( sleep 1; kill -ALRM \$\$ ) & sleep $del" 2> /dev/null
exitval=$?
(( sec = SECONDS - sec ))
exec 2>&3-
(( exitval )) && err_exit "sleep doesn't exit 0 with ALRM interupt"
(( sec > (del - 1) )) || err_exit "ALRM signal causes sleep to terminate prematurely -- expected 3 sec, got $sec"
typeset -r z=3
y=5
for i in 123 z  %x a.b.c
do	( unset $i)  2>/dev/null && err_exit "unset $i should fail"
done
a=()
for i in y y  y[8] t[abc] y.d a.b  a
do	unset $i ||  print -u2  "err_exit unset $i should not fail"
done
[[ $($SHELL -c 'y=3; unset 123 y;print $?$y') == 1 ]] 2> /dev/null ||  err_exit 'y is not getting unset with unset 123 y'
[[ $($SHELL -c 'trap foo TERM; (trap;(trap) )') == 'trap -- foo TERM' ]] || err_exit 'traps not getting reset when subshell is last process'

n=$(printf "%b" 'a\0b\0c' | wc -c)
(( n == 5 )) || err_exit '\0 not working with %b format with printf'

t=$(ulimit -t)
[[ $($SHELL -c 'ulimit -v 15000 2>/dev/null; ulimit -t') == "$t" ]] || err_exit 'ulimit -v changes ulimit -t'

$SHELL 2> /dev/null -c 'cd ""' && err_exit 'cd "" not producing an error'
[[ $($SHELL 2> /dev/null -c 'cd "";print hi') != hi ]] && err_exit 'cd "" should not terminate script'

bincat=$(whence -p cat)
builtin cat
out=$tmp/seq.out
seq 11 >$out
cmp -s <(print -- "$($bincat<( $bincat $out ) )") <(print -- "$(cat <( cat $out ) )") || err_exit "builtin cat differs from $bincat"

[[ $($SHELL -c '{ printf %R "["; print ok;}' 2> /dev/null) == ok ]] || err_exit $'\'printf %R "["\' causes shell to abort'

v=$( $SHELL -c $'
	trap \'print "usr1"\' USR1
	trap exit USR2
	sleep 1 && {
		kill -USR1 $$ && sleep 1
		kill -0 $$ 2>/dev/null && kill -USR2 $$
	} &
	sleep 2 | read
	echo done
' ) 2> /dev/null
[[ $v == $'usr1\ndone' ]] ||  err_exit 'read not terminating when receiving USR1 signal'

mkdir $tmp/tmpdir1
cd $tmp/tmpdir1
pwd=$PWD
cd ../tmpdir1
[[ $PWD == "$pwd" ]] || err_exit 'cd ../tmpdir1 causes directory to change'
cd "$pwd"
mv $tmp/tmpdir1 $tmp/tmpdir2
cd ..  2> /dev/null || err_exit 'cannot change directory to .. after current directory has been renamed'
[[ $PWD == "$tmp" ]] || err_exit 'after "cd $tmp/tmpdir1; cd .." directory is not $tmp'

cd "$tmp"
mkdir $tmp/tmpdir2/foo
pwd=$PWD
cd $tmp/tmpdir2/foo
mv $tmp/tmpdir2 $tmp/tmpdir1
cd ../.. 2> /dev/null || err_exit 'cannot change directory to ../.. after current directory has been renamed'
[[ $PWD == "$tmp" ]] || err_exit 'after "cd $tmp/tmpdir2; cd ../.." directory is not $tmp'
cd "$tmp"
rm -rf tmpdir1

cd /etc
cd ..
[[ $(pwd) == / ]] || err_exit 'cd /etc;cd ..;pwd is not /'
cd /etc
cd ../..
[[ $(pwd) == / ]] || err_exit 'cd /etc;cd ../..;pwd is not /'
cd /etc
cd .././..
[[ $(pwd) == / ]] || err_exit 'cd /etc;cd .././..;pwd is not /'
cd /usr/bin
cd ../..
[[ $(pwd) == / ]] || err_exit 'cd /usr/bin;cd ../..;pwd is not /'
cd /usr/bin
cd ..
[[ $(pwd) == /usr ]] || err_exit 'cd /usr/bin;cd ..;pwd is not /usr'
cd "$tmp"
if	mkdir $tmp/t1
then	(
		cd $tmp/t1
		> real_t1
		(
			cd ..
			mv t1 t2
			mkdir t1
		)
		[[ -f real_t1 ]] || err_exit 'real_t1 not found after parent directory renamed in subshell'
	)
fi
cd "$tmp"

$SHELL +E -i <<- \! && err_exit 'interactive shell should not exit 0 after false'
	false
	exit
!

if	kill -L > /dev/null 2>&1
then	[[ $(kill -l HUP) == "$(kill -L HUP)" ]] || err_exit 'kill -l and kill -L are not the same when given a signal name'
	[[ $(kill -l 9) == "$(kill -L 9)" ]] || err_exit 'kill -l and kill -L are not the same when given a signal number'
	[[ $(kill -L) == *'9) KILL'* ]] || err_exit 'kill -L output does not contain 9) KILL'
fi

unset ENV
v=$($SHELL 2> /dev/null +o rc -ic $'getopts a:bc: opt --man\nprint $?')
[[ $v == 2* ]] || err_exit 'getopts --man does not exit 2 for interactive shells'

read baz <<< 'foo\\\\bar'
[[ $baz == 'foo\\bar' ]] || err_exit 'read of foo\\\\bar not getting foo\\bar'

: ~root
[[ $(builtin) == *.sh.tilde* ]] &&  err_exit 'builtin contains .sh.tilde'

exit $((Errors<125?Errors:125))
