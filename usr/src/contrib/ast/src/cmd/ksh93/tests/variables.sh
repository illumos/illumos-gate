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

[[ ${.sh.version} == "$KSH_VERSION" ]] || err_exit '.sh.version != KSH_VERSION'
unset ss
[[ ${@ss} ]] && err_exit '${@ss} should be empty string when ss is unset'
[[ ${!ss} == ss ]] ||  err_exit '${!ss} should be ss when ss is unset'
[[ ${#ss} == 0 ]] ||  err_exit '${#ss} should be 0 when ss is unset'
# RANDOM
if	(( RANDOM==RANDOM || $RANDOM==$RANDOM ))
then	err_exit RANDOM variable not working
fi
# SECONDS
sleep 3
if	(( SECONDS < 2 ))
then	err_exit SECONDS variable not working
fi
# _
set abc def
if	[[ $_ != def ]]
then	err_exit _ variable not working
fi
# ERRNO
#set abc def
#rm -f foobar#
#ERRNO=
#2> /dev/null < foobar#
#if	(( ERRNO == 0 ))
#then	err_exit ERRNO variable not working
#fi
# PWD
if	[[ !  $PWD -ef . ]]
then	err_exit PWD variable failed, not equivalent to .
fi
# PPID
exp=$$
got=${ $SHELL -c 'print $PPID'; }
if	[[ ${ $SHELL -c 'print $PPID'; } != $$ ]]
then	err_exit "PPID variable failed -- expected '$exp', got '$got'"
fi
# OLDPWD
old=$PWD
cd /
if	[[ $OLDPWD != $old ]]
then	err_exit "OLDPWD variable failed -- expected '$old', got '$OLDPWD'"
fi
cd $old || err_exit cd failed
# REPLY
read <<-!
	foobar
	!
if	[[ $REPLY != foobar ]]
then	err_exit REPLY variable not working
fi
integer save=$LINENO
# LINENO
LINENO=10
#
#  These lines intentionally left blank
#
if	(( LINENO != 13))
then	err_exit LINENO variable not working
fi
LINENO=save+10
IFS=:
x=a::b::c
if	[[ $x != a::b::c ]]
then	err_exit "word splitting on constants"
fi
set -- $x
if	[[ $# != 5 ]]
then	err_exit ":: doesn't separate null arguments "
fi
set x
if	x$1=0 2> /dev/null
then	err_exit "x\$1=value treated as an assignment"
fi
# check for attributes across subshells
typeset -i x=3
y=1/0
if	( x=y ) 2> /dev/null
then	err_exit "attributes not passed to subshells"
fi
unset x
function x.set
{
	nameref foo=${.sh.name}.save
	foo=${.sh.value}
	.sh.value=$0
}
x=bar
if	[[ $x != x.set ]]
then	err_exit 'x.set does not override assignment'
fi
x.get()
{
	nameref foo=${.sh.name}.save
	.sh.value=$foo
}

if	[[ $x != bar ]]
then	err_exit 'x.get does not work correctly'
fi
typeset +n foo
unset foo
foo=bar
(
	unset foo
	set +u
	if	[[ $foo != '' ]]
	then	err_exit '$foo not null after unset in subsehll'
	fi
)
if	[[ $foo != bar ]]
then	err_exit 'unset foo in subshell produces side effect '
fi
unset foo
if	[[ $( { : ${foo?hi there} ; } 2>&1) != *'hi there' ]]
then	err_exit '${foo?hi there} with foo unset does not print hi there on 2'
fi
x=$0
set foobar
if	[[ ${@:0} != "$x foobar" ]]
then	err_exit '${@:0} not expanding correctly'
fi
set --
if	[[ ${*:0:1} != "$0" ]]
then	err_exit '${@:0} not expanding correctly'
fi
ACCESS=0
function COUNT.set
{
        (( ACCESS++ ))
}
COUNT=0
(( COUNT++ ))
if	(( COUNT != 1 || ACCESS!=2 ))
then	err_exit " set discipline failure COUNT=$COUNT ACCESS=$ACCESS"
fi
LANG=C > /dev/null 2>&1
if	[[ $LANG != C ]]
then	err_exit "C locale not working"
fi
unset RANDOM
unset -n foo
foo=junk
function foo.get
{
	.sh.value=stuff
	unset -f foo.get
}
if	[[ $foo != stuff ]]
then	err_exit "foo.get discipline not working"
fi
if	[[ $foo != junk ]]
then	err_exit "foo.get discipline not working after unset"
fi
# special variables
set -- 1 2 3 4 5 6 7 8 9 10
sleep 1000 &
if	[[ $(print -r -- ${#10}) != 2 ]]
then	err_exit '${#10}, where ${10}=10 not working'
fi
for i in @ '*' ! '#' - '?' '$'
do	false
	eval foo='$'$i bar='$'{$i}
	if	[[ ${foo} != "${bar}" ]]
	then	err_exit "\$$i not equal to \${$i}"
	fi
	command eval bar='$'{$i%?} 2> /dev/null || err_exit "\${$i%?} gives syntax error"
	if	[[ $i != [@*] && ${foo%?} != "$bar"  ]]
	then	err_exit "\${$i%?} not correct"
	fi
	command eval bar='$'{$i#?} 2> /dev/null || err_exit "\${$i#?} gives syntax error"
	if	[[ $i != [@*] && ${foo#?} != "$bar"  ]]
	then	err_exit "\${$i#?} not correct"
	fi
	command eval foo='$'{$i} bar='$'{#$i} || err_exit "\${#$i} gives synta
x error"
	if	[[ $i != @([@*]) && ${#foo} != "$bar" ]]
	then	err_exit "\${#$i} not correct"
	fi
done
kill $!
unset x
CDPATH=/
x=$(cd ${tmp#/})
if	[[ $x != $tmp ]]
then	err_exit 'CDPATH does not display new directory'
fi
CDPATH=/:
x=$(cd ${tmp%/*}; cd ${tmp##*/})
if	[[ $x ]]
then	err_exit 'CDPATH displays new directory when not used'
fi
x=$(cd ${tmp#/})
if	[[ $x != $tmp ]]
then	err_exit "CDPATH ${tmp#/} does not display new directory"
fi
TMOUT=100
(TMOUT=20)
if	(( TMOUT !=100 ))
then	err_exit 'setting TMOUT in subshell affects parent'
fi
unset y
function setdisc # var
{
        eval function $1.get'
        {
                .sh.value=good
        }
        '
}
y=bad
setdisc y
if	[[ $y != good ]]
then	err_exit 'setdisc function not working'
fi
integer x=$LINENO
: $'\
'
if	(( LINENO != x+3  ))
then	err_exit '\<newline> gets linenumber count wrong'
fi
set --
set -- "${@-}"
if	(( $# !=1 ))
then	err_exit	'"${@-}" not expanding to null string'
fi
for i in : % + / 3b '**' '***' '@@' '{' '[' '}' !!  '*a' '$foo'
do      (eval : \${"$i"} 2> /dev/null) && err_exit "\${$i} not an syntax error"
done
unset IFS
( IFS='  ' ; read -r a b c <<-!
	x  y z
	!
	if	[[ $b ]]
	then	err_exit 'IFS="  " not causing adjacent space to be null string'
	fi
)
read -r a b c <<-!
x  y z
!
if	[[ $b != y ]]
then	err_exit 'IFS not restored after subshell'
fi

# The next part generates 3428 IFS set/read tests.

unset IFS x
function split
{
	i=$1 s=$2 r=$3
	IFS=': '
	set -- $i
	IFS=' '
	g="[$#]"
	while	:
	do	case $# in
		0)	break ;;
		esac
		g="$g($1)"
		shift
	done
	case "$g" in
	"$s")	;;
	*)	err_exit "IFS=': '; set -- '$i'; expected '$s' got '$g'" ;;
	esac
	print "$i" | IFS=": " read arg rem; g="($arg)($rem)"
	case "$g" in
	"$r")	;;
	*)	err_exit "IFS=': '; read '$i'; expected '$r' got '$g'" ;;
	esac
}
for str in 	\
	'-'	\
	'a'	\
	'- -'	\
	'- a'	\
	'a -'	\
	'a b'	\
	'- - -'	\
	'- - a'	\
	'- a -'	\
	'- a b'	\
	'a - -'	\
	'a - b'	\
	'a b -'	\
	'a b c'
do
	IFS=' '
	set x $str
	shift
	case $# in
	0)	continue ;;
	esac
	f1=$1
	case $f1 in
	'-')	f1='' ;;
	esac
	shift
	case $# in
	0)	for d0 in '' ' '
		do
			for d1 in '' ' ' ':' ' :' ': ' ' : '
			do
				case $f1$d1 in
				'')	split "$d0$f1$d1" "[0]" "()()" ;;
				' ')	;;
				*)	split "$d0$f1$d1" "[1]($f1)" "($f1)()" ;;
				esac
			done
		done
		continue
		;;
	esac
	f2=$1
	case $f2 in
	'-')	f2='' ;;
	esac
	shift
	case $# in
	0)	for d0 in '' ' '
		do
			for d1 in ' ' ':' ' :' ': ' ' : '
			do
				case ' ' in
				$f1$d1|$d1$f2)	continue ;;
				esac
				for d2 in '' ' ' ':' ' :' ': ' ' : '
				do
					case $f2$d2 in
					'')	split "$d0$f1$d1$f2$d2" "[1]($f1)" "($f1)()" ;;
					' ')	;;
					*)	split "$d0$f1$d1$f2$d2" "[2]($f1)($f2)" "($f1)($f2)" ;;
					esac
				done
			done
		done
		continue
		;;
	esac
	f3=$1
	case $f3 in
	'-')	f3='' ;;
	esac
	shift
	case $# in
	0)	for d0 in '' ' '
		do
			for d1 in ':' ' :' ': ' ' : '
			do
				case ' ' in
				$f1$d1|$d1$f2)	continue ;;
				esac
				for d2 in ' ' ':' ' :' ': ' ' : '
				do
					case $f2$d2 in
					' ')	continue ;;
					esac
					case ' ' in
					$f2$d2|$d2$f3)	continue ;;
					esac
					for d3 in '' ' ' ':' ' :' ': ' ' : '
					do
						case $f3$d3 in
						'')	split "$d0$f1$d1$f2$d2$f3$d3" "[2]($f1)($f2)" "($f1)($f2)" ;;
						' ')	;;
						*)	x=$f2$d2$f3$d3
							x=${x#' '}
							x=${x%' '}
							split "$d0$f1$d1$f2$d2$f3$d3" "[3]($f1)($f2)($f3)" "($f1)($x)"
							;;
						esac
					done
				done
			done
		done
		continue
		;;
	esac
done
unset IFS

if	[[ $( (print ${12345:?}) 2>&1) != *12345* ]]
then	err_exit 'incorrect error message with ${12345?}'
fi
unset foobar
if	[[ $( (print ${foobar:?}) 2>&1) != *foobar* ]]
then	err_exit 'incorrect error message with ${foobar?}'
fi
unset bar
if	[[ $( (print ${bar:?bam}) 2>&1) != *bar*bam* ]]
then	err_exit 'incorrect error message with ${foobar?}'
fi
{ $SHELL -c '
function foo
{
	typeset SECONDS=0
	sleep 1.5
	print $SECONDS

}
x=$(foo)
(( x >1 && x < 2 ))
'
} 2> /dev/null   || err_exit 'SECONDS not working in function'
cat > $tmp/script <<-\!
	posixfun()
	{
		unset x
	 	nameref x=$1
	 	print  -r -- "$x"
	}
	function fun
	{
	 	nameref x=$1
	 	print  -r -- "$x"
	}
	if	[[ $1 ]]
	then	file=${.sh.file}
	else	print -r -- "${.sh.file}"
	fi
!
chmod +x $tmp/script
. $tmp/script  1
[[ $file == $tmp/script ]] || err_exit ".sh.file not working for dot scripts"
[[ $($SHELL $tmp/script) == $tmp/script ]] || err_exit ".sh.file not working for scripts"
[[ $(posixfun .sh.file) == $tmp/script ]] || err_exit ".sh.file not working for posix functions"
[[ $(fun .sh.file) == $tmp/script ]] || err_exit ".sh.file not working for functions"
[[ $(posixfun .sh.fun) == posixfun ]] || err_exit ".sh.fun not working for posix functions"
[[ $(fun .sh.fun) == fun ]] || err_exit ".sh.fun not working for functions"
[[ $(posixfun .sh.subshell) == 1 ]] || err_exit ".sh.subshell not working for posix functions"
[[ $(fun .sh.subshell) == 1 ]] || err_exit ".sh.subshell not working for functions"
(
    [[ $(posixfun .sh.subshell) == 2 ]]  || err_exit ".sh.subshell not working for posix functions in subshells"
    [[ $(fun .sh.subshell) == 2 ]]  || err_exit ".sh.subshell not working for functions in subshells"
    (( .sh.subshell == 1 )) || err_exit ".sh.subshell not working in a subshell"
)
TIMEFORMAT='this is a test'
[[ $({ { time :;} 2>&1;}) == "$TIMEFORMAT" ]] || err_exit 'TIMEFORMAT not working'
: ${.sh.version}
[[ $(alias integer) == *.sh.* ]] && err_exit '.sh. prefixed to alias name'
: ${.sh.version}
[[ $(whence rm) == *.sh.* ]] && err_exit '.sh. prefixed to tracked alias name'
: ${.sh.version}
[[ $(cd /bin;env | grep PWD=) == *.sh.* ]] && err_exit '.sh. prefixed to PWD'
# unset discipline bug fix
dave=dave
function dave.unset
{
    unset dave
}
unset dave
[[ $(typeset +f) == *dave.* ]] && err_exit 'unset discipline not removed'

x=$(
	dave=dave
	function dave.unset
	{
		print dave.unset
	}
)
[[ $x == dave.unset ]] || err_exit 'unset discipline not called with subset completion'

print 'print ${VAR}' > $tmp/script
unset VAR
VAR=new $tmp/script > $tmp/out
got=$(<$tmp/out)
[[ $got == new ]] || err_exit "previously unset environment variable not passed to script, expected 'new', got '$got'"
[[ ! $VAR ]] || err_exit "previously unset environment variable set after script, expected '', got '$VAR'"
unset VAR
VAR=old
VAR=new $tmp/script > $tmp/out
got=$(<$tmp/out)
[[ $got == new ]] || err_exit "environment variable covering local variable not passed to script, expected 'new', got '$got'"
[[ $VAR == old ]] || err_exit "previously set local variable changed after script, expected 'old', got '$VAR'"
unset VAR
export VAR=old
VAR=new $tmp/script > $tmp/out
got=$(<$tmp/out)
[[ $got == new ]] || err_exit "environment variable covering environment variable not passed to script, expected 'new', got '$got'"
[[ $VAR == old ]] || err_exit "previously set environment variable changed after script, expected 'old', got '$VAR'"

(
	unset dave
	function  dave.append
	{
		.sh.value+=$dave
		dave=
	}
	dave=foo; dave+=bar
	[[ $dave == barfoo ]] || exit 2
) 2> /dev/null
case $? in
0)	 ;;
1)	 err_exit 'append discipline not implemented';;
*)	 err_exit 'append discipline not working';;
esac
.sh.foobar=hello
{
	function .sh.foobar.get
	{
		.sh.value=world
	}
} 2> /dev/null || err_exit "cannot add get discipline to .sh.foobar"
[[ ${.sh.foobar} == world ]]  || err_exit 'get discipline for .sh.foobar not working'
x='a|b'
IFS='|'
set -- $x
[[ $2 == b ]] || err_exit '$2 should be b after set'
exec 3>&2 2> /dev/null
set -x
( IFS= ) 2> /dev/null
set +x
exec 2>&3-
set -- $x
[[ $2 == b ]] || err_exit '$2 should be b after subshell'
: & pid=$!
( : & )
[[ $pid == $! ]] || err_exit '$! value not preserved across subshells'
unset foo
typeset -A foo
function foo.set
{
	case ${.sh.subscript} in
	bar)	if	((.sh.value > 1 ))
	        then	.sh.value=5
			foo[barrier_hit]=yes
		fi
		;;
	barrier_hit)
		if	[[ ${.sh.value} == yes ]]
		then	foo[barrier_not_hit]=no
		else	foo[barrier_not_hit]=yes
		fi
		;;
	esac
}
foo[barrier_hit]=no
foo[bar]=1
(( foo[bar] == 1 )) || err_exit 'foo[bar] should be 1'
[[ ${foo[barrier_hit]} == no ]] || err_exit 'foo[barrier_hit] should be no'
[[ ${foo[barrier_not_hit]} == yes ]] || err_exit 'foo[barrier_not_hit] should be yes'
foo[barrier_hit]=no
foo[bar]=2
(( foo[bar] == 5 )) || err_exit 'foo[bar] should be 5'
[[ ${foo[barrier_hit]} == yes ]] || err_exit 'foo[barrier_hit] should be yes'
[[ ${foo[barrier_not_hit]} == no ]] || err_exit 'foo[barrier_not_hit] should be no'
unset x
typeset -i x
function x.set
{
	typeset sub=${.sh.subscript}
	(( sub > 0 )) && (( x[sub-1]= x[sub-1] + .sh.value ))
}
x[0]=0 x[1]=1 x[2]=2 x[3]=3
[[ ${x[@]} == '12 8 5 3' ]] || err_exit 'set discipline for indexed array not working correctly'
float seconds
((SECONDS=3*4))
seconds=SECONDS
(( seconds < 12 || seconds > 12.1 )) &&  err_exit "SECONDS is $seconds and should be close to 12"
unset a
function a.set
{
	print -r -- "${.sh.name}=${.sh.value}"
}
[[ $(a=1) == a=1 ]] || err_exit 'set discipline not working in subshell assignment'
[[ $(a=1 :) == a=1 ]] || err_exit 'set discipline not working in subshell command'

[[ ${.sh.subshell} == 0 ]] || err_exit '${.sh.subshell} should be 0'
(
	[[ ${.sh.subshell} == 1 ]] || err_exit '${.sh.subshell} should be 1'
	(
		[[ ${.sh.subshell} == 2 ]] || err_exit '${.sh.subshell} should be 2'
	)
)

set -- {1..32768}
(( $# == 32768 )) || err_exit "\$# failed -- expected 32768, got $#"
set --

unset r v x
path=$PATH
x=foo
for v in EDITOR VISUAL OPTIND CDPATH FPATH PATH ENV LINENO RANDOM SECONDS _
do	nameref r=$v
	unset $v
	if	( $SHELL -c "unset $v; : \$$v" ) 2>/dev/null
	then	[[ $r ]] && err_exit "unset $v failed -- expected '', got '$r'"
		r=$x
		[[ $r == $x ]] || err_exit "$v=$x failed -- expected '$x', got '$r'"
	else	err_exit "unset $v; : \$$v failed"
	fi
done

x=x
for v in LC_ALL LC_CTYPE LC_MESSAGES LC_COLLATE LC_NUMERIC
do	nameref r=$v
	unset $v
	[[ $r ]] && err_exit "unset $v failed -- expected '', got '$r'"
	d=$($SHELL -c "$v=$x" 2>&1)
	[[ $d ]] || err_exit "$v=$x failed -- expected locale diagnostic"
	{ g=$( r=$x; print -- $r ); } 2>/dev/null
	[[ $g == '' ]] || err_exit "$v=$x failed -- expected '', got '$g'"
	{ g=$( r=C; r=$x; print -- $r ); } 2>/dev/null
	[[ $g == 'C' ]] || err_exit "$v=C; $v=$x failed -- expected 'C', got '$g'"
done
PATH=$path

cd $tmp

print print -n zzz > zzz
chmod +x zzz
exp='aaazzz'
got=$($SHELL -c 'unset SHLVL; print -n aaa; ./zzz' 2>&1) >/dev/null 2>&1
[[ $got == "$exp" ]] || err_exit "unset SHLVL causes script failure -- expected '$exp', got '$got'"

mkdir glean
for cmd in date ok
do	exp="$cmd ok"
	rm -f $cmd
	print print $exp > glean/$cmd
	chmod +x glean/$cmd
	got=$(CDPATH=:.. $SHELL -c "PATH=:/bin:/usr/bin; date > /dev/null; cd glean && ./$cmd" 2>&1)
	[[ $got == "$exp" ]] || err_exit "cd with CDPATH after PATH change failed -- expected '$exp', got '$got'"
done

v=LC_CTYPE
unset $v
[[ -v $v ]] && err_exit "unset $v; [[ -v $v ]] failed"
eval $v=C
[[ -v $v ]] || err_exit "$v=C; [[ -v $v ]] failed"

cmd='set --nounset; unset foo; : ${!foo*}'
$SHELL -c "$cmd" 2>/dev/null || err_exit "'$cmd' exit status $?, expected 0"

SHLVL=1
level=$($SHELL -c $'$SHELL -c \'print -r "$SHLVL"\'')
[[ $level  == 3 ]]  || err_exit "SHLVL should be 3 not $level"

[[ $($SHELL -c '{ x=1; : ${x.};print ok;}' 2> /dev/null) == ok ]] || err_exit '${x.} where x is a simple variable causes shell to abort'

$SHELL -c 'unset .sh' 2> /dev/null
[[ $? == 1 ]] || err_exit 'unset .sh should return 1'

exit $((Errors<125?Errors:125))
