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

unset HISTFILE

function fun
{
	while  command exec 3>&1
	do	break
	done 2>   /dev/null
	print -u3 good
}
print 'read -r a; print -r -u$1 -- "$a"' > $tmp/mycat
chmod 755 $tmp/mycat
for ((i=3; i < 10; i++))
do
	eval "a=\$(print foo | $tmp/mycat" $i $i'>&1 > /dev/null |cat)' 2> /dev/null
	[[ $a == foo ]] || err_exit "bad file descriptor $i in comsub script"
done
exec 3> /dev/null
[[ $(fun) == good ]] || err_exit 'file 3 closed before subshell completes'
exec 3>&-
cd $tmp || { err_exit "cd $tmp failed"; exit ; }
print foo > file1
print bar >> file1
if	[[ $(<file1) != $'foo\nbar' ]]
then	err_exit 'append (>>) not working'
fi
set -o noclobber
exec 3<> file1
read -u3 line
exp=foo
if	[[ $line != $exp ]]
then	err_exit "read on <> fd failed -- expected '$exp', got '$line'"
fi
if	( 4> file1 ) 2> /dev/null
then	err_exit 'noclobber not causing exclusive open'
fi
set +o noclobber

FDFS=(
	( dir=/proc/self/fd	semantics='open'	)
	( dir=/proc/$$/fd	semantics='open'	)
	( dir=/dev/fd		semantics='open|dup'	)
	( dir=/dev/fd		semantics='dup'	)
)
for ((fdfs=0; fdfs<${#FDFS[@]}-1; fdfs++))
do	[[ -e ${FDFS[fdfs].dir} ]] && { command : > ${FDFS[fdfs].dir}/1; } 2>/dev/null >&2 && break
done

exec 3<> file1
if	command exec 4< ${FDFS[fdfs].dir}/3
then	read -u3 got
	read -u4 got
	exp='foo|bar'
	case $got in
	foo)	semantics='open' ;;
	bar)	semantics='dup' ;;
	*)	semantics='failed' ;;
	esac
	[[ $semantics == @(${FDFS[fdfs].semantics}) ]] || err_exit "'4< ${FDFS[fdfs].dir}/3' $semantics semantics instead of ${FDFS[fdfs].semantics} -- expected '$exp', got '$got'"
fi

# 2004-11-25 ancient /dev/fd/N redirection bug fix
got=$(
	{
		print -n 1
		print -n 2 > ${FDFS[fdfs].dir}/2
		print -n 3
		print -n 4 > ${FDFS[fdfs].dir}/2
	}  2>&1
)
exp='1234|4'
case $got in
1234)	semantics='dup' ;;
4)	semantics='open' ;;
*)	semantics='failed' ;;
esac
[[ $semantics == @(${FDFS[fdfs].semantics}) ]] || err_exit "${FDFS[fdfs].dir}/N $semantics semantics instead of ${FDFS[fdfs].semantics} -- expected '$exp', got '$got'"

cat > close0 <<\!
exec 0<&-
echo $(./close1)
!
print "echo abc" > close1
chmod +x close0 close1
x=$(./close0)
if	[[ $x != "abc" ]]
then	err_exit "picked up file descriptor zero for opening script file"
fi
cat > close0 <<\!
	for ((i=0; i < 1100; i++))
	do	exec 4< /dev/null
		read -u4
	done
	exit 0
!
./close0 2> /dev/null || err_exit "multiple exec 4< /dev/null can fail"
$SHELL -c '
	trap "rm -f in out" EXIT
	for ((i = 0; i < 1000; i++))
	do	print -r -- "This is a test"
	done > in
	> out
	exec 1<> out
	builtin cat
	print -r -- "$(<in)"
	cmp -s in out'  2> /dev/null
[[ $? == 0 ]] || err_exit 'builtin cat truncates files'
cat >| script <<-\!
print hello
( exec 3<&- 4<&-)
exec 3<&- 4<&-
print world
!
chmod +x script
[[ $( $SHELL ./script) == $'hello\nworld' ]] || err_exit 'closing 3 & 4 causes script to fail'
cd ~- || err_exit "cd back failed"
( exec  > '' ) 2> /dev/null  && err_exit '> "" does not fail'
unset x
( exec > ${x} ) 2> /dev/null && err_exit '> $x, where x null does not fail'
exec <<!
foo
bar
!
( exec 0< /dev/null)
read line
if	[[ $line != foo ]]
then	err_exit 'file descriptor not restored after exec in subshell'
fi
exec 3>&- 4>&-
[[ $( {
	read -r line; print -r -- "$line"
	(
	        read -r line; print -r -- "$line"
	) & wait
	while	read -r line
        do	print -r -- "$line"
	done
 } << !
line 1
line 2
line 3
!) == $'line 1\nline 2\nline 3' ]] || err_exit 'read error with subshells'
# 2004-05-11 bug fix
cat > $tmp/1 <<- ++EOF++
	script=$tmp/2
	trap "rm -f \$script" EXIT
	exec 9> \$script
	for ((i=3; i<9; i++))
	do	eval "while read -u\$i; do : ; done \$i</dev/null"
		print -u9 "exec \$i< /dev/null"
	done
	for ((i=0; i < 60; i++))
	do	print -u9 -f "%.80c\n"  ' '
	done
	print -u9 'print ok'
	exec 9<&-
	chmod +x \$script
	\$script
++EOF++
chmod +x $tmp/1
[[ $($SHELL  $tmp/1) == ok ]]  || err_exit "parent i/o causes child script to fail"
# 2004-12-20 redirection loss bug fix
cat > $tmp/1 <<- \++EOF++
	function a
	{
		trap 'print ok' EXIT
		: > /dev/null
	}
	a
++EOF++
chmod +x $tmp/1
[[ $($tmp/1) == ok ]] || err_exit "trap on EXIT loses last command redirection"
print > /dev/null {n}> $tmp/1
[[ ! -s $tmp/1 ]] && newio=1
if	[[ $newio && $(print hello | while read -u$n; do print $REPLY; done {n}<&0) != hello ]]
then	err_exit "{n}<&0 not working with for loop"
fi
[[ $({ read -r; read -u3 3<&0; print -- "$REPLY" ;} <<!
hello
world
!) == world ]] || err_exit 'I/O not synchronized with <&'
x="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNSPQRSTUVWXYZ1234567890"
for ((i=0; i < 62; i++))
do	printf "%.39c\n"  ${x:i:1}
done >  $tmp/seek
if	command exec 3<> $tmp/seek
then	(( $(3<#) == 0 )) || err_exit "not at position 0"
	(( $(3<# ((EOF))) == 40*62 )) || err_exit "not at end-of-file"
	command exec 3<# ((40*8)) || err_exit "absolute seek fails"
	read -u3
	[[ $REPLY == +(i) ]] || err_exit "expected iiii..., got $REPLY"
	[[ $(3<#) == $(3<# ((CUR)) ) ]] || err_exit '$(3<#)!=$(3<#((CUR)))'
	command exec 3<# ((CUR+80))
	read -u3
	[[ $REPLY == {39}(l) ]] || err_exit "expected lll..., got $REPLY"
	command exec 3<# ((EOF-80))
	read -u3
	[[ $REPLY == +(9) ]] || err_exit "expected 999..., got $REPLY"
	command exec 3># ((80))
	print -u3 -f "%.39c\n"  @
	command exec 3># ((80))
	read -u3
	[[ $REPLY == +(@) ]] || err_exit "expected @@@..., got $REPLY"
	read -u3
	[[ $REPLY == +(d) ]] || err_exit "expected ddd..., got $REPLY"
	command exec 3># ((EOF))
	print -u3 -f "%.39c\n"  ^
	(( $(3<# ((CUR-0))) == 40*63 )) || err_exit "not at extended end-of-file"
	command exec 3<# ((40*62))
	read -u3
	[[ $REPLY == +(^) ]] || err_exit "expected ddd..., got $REPLY"
	command exec 3<# ((0))
	command exec 3<# *jjjj*
	read -u3
	[[  $REPLY == {39}(j) ]] || err_exit "<# pattern failed"
	[[ $(command exec 3<## *llll*) == {39}(k) ]] || err_exit "<## pattern not saving standard output"
	read -u3
	[[  $REPLY == {39}(l) ]] || err_exit "<## pattern failed to position"
	command exec 3<# *abc*
	read -u3 && err_exit "not found pattern not positioning at eof"
	cat $tmp/seek | read -r <# *WWW*
	[[ $REPLY == *WWWWW* ]] || err_exit '<# not working for pipes'
	{ < $tmp/seek <# ((2358336120)) ;} 2> /dev/null || err_exit 'long seek not working'
else	err_exit "$tmp/seek: cannot open for reading"
fi
command exec 3<&- || 'cannot close 3'
for ((i=0; i < 62; i++))
do	printf "%.39c\n"  ${x:i:1}
done >  $tmp/seek
if	command exec {n}<> $tmp/seek
then	{ command exec {n}<#((EOF)) ;} 2> /dev/null || err_exit '{n}<# not working'
	if	$SHELL -c '{n}</dev/null' 2> /dev/null
	then	(( $({n}<#) ==  40*62))  || err_exit '$({n}<#) not working'
	else	err_exit 'not able to parse {n}</dev/null'
	fi
fi
$SHELL -ic '
{
    print -u2  || exit 2
    print -u3  || exit 3
    print -u4  || exit 4
    print -u5  || exit 5
    print -u6  || exit 6
    print -u7  || exit 7
    print -u8  || exit 8
    print -u9  || exit 9
}  3> /dev/null 4> /dev/null 5> /dev/null 6> /dev/null 7> /dev/null 8> /dev/null 9> /dev/null' > /dev/null 2>&1
exitval=$?
(( exitval ))  && err_exit  "print to unit $exitval failed"
$SHELL -c "{ > $tmp/1 ; date;} >&- 2> /dev/null" > $tmp/2
[[ -s $tmp/1 || -s $tmp/2 ]] && err_exit 'commands with standard output closed produce output'
$SHELL -c "$SHELL -c ': 3>&1' 1>&- 2>/dev/null" && err_exit 'closed standard output not passed to subshell'
[[ $(cat  <<- \EOF | $SHELL
	do_it_all()
	{
	 	dd 2>/dev/null  # not a ksh93 buildin
	 	return $?
	}
	do_it_all ; exit $?
	hello world
EOF) == 'hello world' ]] || err_exit 'invalid readahead on stdin'
$SHELL -c 'exec 3>; /dev/null'  2> /dev/null && err_exit '>; with exec should be an error'
$SHELL -c ': 3>; /dev/null'  2> /dev/null || err_exit '>; not working with at all'
print hello > $tmp/1
if	! $SHELL -c "false >; $tmp/1"  2> /dev/null
then	let 1;[[ $(<$tmp/1) == hello ]] || err_exit '>; not preserving file on failure'
fi
if	! $SHELL -c "sed -e 's/hello/hello world/' $tmp/1" >; $tmp/1  2> /dev/null
then	[[ $(<$tmp/1) == 'hello world' ]] || err_exit '>; not updating file on success'
fi

$SHELL -c 'exec 3<>; /dev/null'  2> /dev/null && err_exit '<>; with exec should be an error'
$SHELL -c ': 3<>; /dev/null'  2> /dev/null || err_exit '<>; not working with at all'
print $'hello\nworld' > $tmp/1
if      ! $SHELL -c "false <>; $tmp/1"  2> /dev/null
then    [[ $(<$tmp/1) == $'hello\nworld' ]] || err_exit '<>; not preserving file on failure'
fi
if	! $SHELL -c "head -1 $tmp/1" <>; $tmp/1  2> /dev/null
then	[[ $(<$tmp/1) == hello ]] || err_exit '<>; not truncating file on success of head'
fi
print $'hello\nworld' > $tmp/1
if	! $SHELL -c head  < $tmp/1 <#((6)) <>; $tmp/1  2> /dev/null
then	[[ $(<$tmp/1) == world ]] || err_exit '<>; not truncating file on success of behead'
fi

unset y
read -n1 y <<!
abc
!
if      [[ $y != a ]]
then    err_exit  'read -n1 not working'
fi
unset a
{ read -N3 a; read -N1 b;}  <<!
abcdefg
!
[[ $a == abc ]] || err_exit 'read -N3 here-document not working'
[[ $b == d ]] || err_exit 'read -N1 here-document not working'
read -n3 a <<!
abcdefg
!
[[ $a == abc ]] || err_exit 'read -n3 here-document not working'
(print -n a; sleep 1; print -n bcde) | { read -N3 a; read -N1 b;}
[[ $a == abc ]] || err_exit 'read -N3 from pipe not working'
[[ $b == d ]] || err_exit 'read -N1 from pipe not working'
(print -n a; sleep 1; print -n bcde) |read -n3 a
[[ $a == a ]] || err_exit 'read -n3 from pipe not working'
if	mkfifo $tmp/fifo 2> /dev/null
then	(print -n a; sleep 2; print -n bcde) > $tmp/fifo &
	{
	read -u5 -n3 -t3 a || err_exit 'read -n3 from fifo timed out'
	read -u5 -n1 -t3 b || err_exit 'read -n1 from fifo timed out'
	} 5< $tmp/fifo
	exp=a
	got=$a
	[[ $got == "$exp" ]] || err_exit "read -n3 from fifo failed -- expected '$exp', got '$got'"
	exp=b
	got=$b
	[[ $got == "$exp" ]] || err_exit "read -n1 from fifo failed -- expected '$exp', got '$got'"
	rm -f $tmp/fifo
	wait
	mkfifo $tmp/fifo 2> /dev/null
	(print -n a; sleep 2; print -n bcde) > $tmp/fifo &
	{
	read -u5 -N3 -t3 a || err_exit 'read -N3 from fifo timed out'
	read -u5 -N1 -t3 b || err_exit 'read -N1 from fifo timed out'
	} 5< $tmp/fifo
	exp=abc
	got=$a
	[[ $got == "$exp" ]] || err_exit "read -N3 from fifo failed -- expected '$exp', got '$got'"
	exp=d
	got=$b
	[[ $got == "$exp" ]] || err_exit "read -N1 from fifo failed -- expected '$exp', got '$got'"
	wait
fi
(
	print -n 'prompt1: '
	sleep .1
	print line2
	sleep .1
	print -n 'prompt2: '
	sleep .1
) | {
	read -t2 -n 1000 line1
	read -t2 -n 1000 line2
	read -t2 -n 1000 line3
	read -t2 -n 1000 line4
}
[[ $? == 0 ]]		 	&& err_exit 'should have timed out'
[[ $line1 == 'prompt1: ' ]] 	|| err_exit "line1 should be 'prompt1: '"
[[ $line2 == line2 ]]		|| err_exit "line2 should be line2"
[[ $line3 == 'prompt2: ' ]]	|| err_exit "line3 should be 'prompt2: '"
[[ ! $line4 ]]			|| err_exit "line4 should be empty"

if	$SHELL -c "export LC_ALL=C.UTF-8; c=$'\342\202\254'; [[ \${#c} == 1 ]]" 2>/dev/null
then	lc_utf8=C.UTF-8
else	lc_utf8=''
fi

typeset -a e o=(-n2 -N2)
integer i
set -- \
	'a'	'bcd'	'a bcd'	'ab cd' \
	'ab'	'cd'	'ab cd'	'ab cd' \
	'abc'	'd'	'ab cd'	'ab cd' \
	'abcd'	''	'ab cd'	'ab cd'
while	(( $# >= 3 ))
do	a=$1
	b=$2
	e[0]=$3
	e[1]=$4
	shift 4
	for ((i = 0; i < 2; i++))
	do	for lc_all in C $lc_utf8
		do	g=$(LC_ALL=$lc_all $SHELL -c "{ print -n '$a'; sleep 0.2; print -n '$b'; sleep 0.2; } | { read ${o[i]} a; print -n \$a; read a; print -n \ \$a; }")
			[[ $g == "${e[i]}" ]] || err_exit "LC_ALL=$lc_all read ${o[i]} from pipe '$a $b' failed -- expected '${e[i]}', got '$g'"
		done
	done
done

if	[[ $lc_utf8 ]]
then	export LC_ALL=$lc_utf8
	typeset -a c=( '' 'A' $'\303\274' $'\342\202\254' )
	integer i w
	typeset o
	if	(( ${#c[2]} == 1 && ${#c[3]} == 1 ))
	then	for i in 1 2 3
		do	for o in n N
			do	for w in 1 2 3
				do	print -nr "${c[w]}" | read -${o}${i} g
					if	[[ $o == N ]] && (( i > 1 ))
					then	e=''
					else	e=${c[w]}
					fi
					[[ $g == "$e" ]] || err_exit "read -${o}${i} failed for '${c[w]}' -- expected '$e', got '$g'"
				done
			done
		done
	fi
fi

exec 3<&2
file=$tmp/file
redirect 5>$file 2>&5
print -u5 -f 'This is a test\n'
print -u2 OK
exec 2<&3
exp=$'This is a test\nOK'
got=$(< $file)
[[ $got == $exp ]] || err_exit "output garbled when stderr is duped -- expected $(printf %q "$exp"), got $(printf %q "$got")"
print 'hello world' > $file
1<>; $file  1># ((5))
(( $(wc -c < $file) == 5 )) || err_exit "$file was not truncate to 5 bytes"

$SHELL -c "PS4=':2:'
	exec 1> $tmp/21.out 2> $tmp/22.out
	set -x
	printf ':1:A:'
	print \$(:)
	print :1:Z:" 1> $tmp/11.out 2> $tmp/12.out
[[ -s $tmp/11.out ]] && err_exit "standard output leaked past redirection"
[[ -s $tmp/12.out ]] && err_exit "standard error leaked past redirection"
exp=$':1:A:\n:1:Z:'
got=$(<$tmp/21.out)
[[ $exp == "$got" ]] || err_exit "standard output garbled -- expected $(printf %q "$exp"), got $(printf %q "$got")"
exp=$':2:printf :1:A:\n:2::\n:2:print\n:2:print :1:Z:'
got=$(<$tmp/22.out)
[[ $exp == "$got" ]] || err_exit "standard error garbled -- expected $(printf %q "$exp"), got $(printf %q "$got")"

tmp=$tmp $SHELL 2> /dev/null -c 'exec 3<&1 ; exec 1<&- ; exec > $tmp/outfile;print foobar' || err_exit 'exec 1<&- causes failure'
[[ $(<$tmp/outfile) == foobar ]] || err_exit 'outfile does not contain foobar'

print hello there world > $tmp/foobar
sed  -e 's/there //' $tmp/foobar  >; $tmp/foobar
[[ $(<$tmp/foobar) == 'hello world' ]] || err_exit '>; redirection not working on simple command'
print hello there world > $tmp/foobar
{ sed  -e 's/there //' $tmp/foobar;print done;} >; $tmp/foobar 
[[ $(<$tmp/foobar) == $'hello world\ndone' ]] || err_exit '>; redirection not working for compound command'
print hello there world > $tmp/foobar
$SHELL -c "sed  -e 's/there //' $tmp/foobar  >; $tmp/foobar"
[[ $(<$tmp/foobar) == 'hello world' ]] || err_exit '>; redirection not working with -c on a simple command'

rm -f "$tmp/junk"
for	(( i=1; i < 50; i++ ))
do      out=$(/bin/ls "$tmp/junk" 2>/dev/null)
	if	(( $? == 0 ))
	then    err_exit 'wrong error code with redirection'
		break
	fi
done

rm -f $tmp/file1 $tmp/file2
print foo > $tmp/file3
ln -s $tmp/file3 $tmp/file2
ln -s $tmp/file2 $tmp/file1
print bar >; $tmp/file1
[[ $(<$tmp/file3) == bar ]] || err_exit '>; not following symlinks'

for i in 1
do	:
done	{n}< /dev/null
[[ -r /dev/fd/$n ]] &&  err_exit "file descriptor n=$n left open after {n}<"

n=$( exec {n}< /dev/null; print -r -- $n)
[[ -r /dev/fd/$n ]] && err_exit "file descriptor n=$n left open after subshell"

exit $((Errors<125?Errors:125))
