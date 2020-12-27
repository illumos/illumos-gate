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
# test the behavior of co-processes
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

if	[[ -d /cygdrive ]]
then	err_exit cygwin detected - coprocess tests disabled - enable at the risk of wedging your system
	exit $((Errors))
fi

bintrue=$(whence -p true)

function ping # id
{
	integer x=0
	while ((x++ < 5))
	do	read -r
		print -r "$1 $REPLY"
	done
}

bincat=$(whence -p cat)
builtin cat

for cat in cat $bincat
do

	$cat |&
	print -p "hello"
	read -p line
	[[ $line == hello ]] || err_exit "$cat coprocessing fails"
	exec 5>&p 6<&p
	print -u5 'hello again' || err_exit "write on $cat coprocess u5 fails"
	read -u6 line
	[[ $line == 'hello again' ]] || err_exit "$cat coprocess after moving fds fails"
	exec 5<&- 6<&-
	wait $!
	
	ping three |&
	exec 3>&p
	ping four |&
	exec 4>&p
	ping pipe |&
	
	integer count
	for i in three four pipe four pipe four three pipe pipe three pipe
	do	case $i in
		three)	to=-u3;;
		four)	to=-u4;;
		pipe)	to=-p;;
		esac
		(( count++ ))
		print $to $i $count
	done
	
	while	((count > 0))
	do	(( count-- ))
		read -p
		set -- $REPLY
		if	[[ $1 != $2 ]]
		then	err_exit "$cat coprocess $1 does not match $2"
		fi
		case $1 in
		three)	;;
		four)	;;
		pipe)	;;
		*)	err_exit "$cat coprocess unknown message +|$REPLY|+" ;;
		esac
	done
	kill $(jobs -p) 2>/dev/null
	
	file=$tmp/regress
	$cat > $file  <<-!
	$cat |&
	!
	chmod +x $file
	sleep 10 |&
	$file 2> /dev/null || err_exit "parent $cat coprocess prevents script coprocess"
	exec 5<&p 6>&p
	exec 5<&- 6>&-
	kill $(jobs -p) 2>/dev/null
	
	${SHELL-ksh} |&
	cop=$!
	exp=Done
	print -p $'print hello | '$cat$'\nprint '$exp
	read -t 5 -p
	read -t 5 -p
	got=$REPLY
	if	[[ $got != $exp ]]
	then	err_exit "${SHELL-ksh} $cat coprocess io failed -- got '$got', expected '$exp'"
	fi
	exec 5<&p 6>&p
	exec 5<&- 6>&-
	{ sleep 4; kill $cop; } 2>/dev/null &
	spy=$!
	if	wait $cop 2>/dev/null
	then	kill $spy 2>/dev/null
	else	err_exit "$cat coprocess hung after 'exec 5<&p 6>&p; exec 5<&- 6>&-'"
	fi
	wait
	
	{
	echo line1 | grep 'line2'
	echo line2 | grep 'line1'
	} |&
	SECONDS=0 count=0
	while	read -p -t 10 line
	do	((count++))
	done
	if	(( SECONDS > 8 ))
	then	err_exit "$cat coprocess read -p hanging (SECONDS=$SECONDS count=$count)"
	fi
	wait $!
	
	( sleep 3 |& sleep 1 && kill $!; sleep 1; sleep 3 |& sleep 1 && kill $! ) ||
		err_exit "$cat coprocess cleanup not working correctly"
	{ : |& } 2>/dev/null ||
		err_exit "subshell $cat coprocess lingers in parent"
	wait $!
	
	unset N r e
	integer N=5
	e=12345
	(
		integer i
		for ((i = 1; i <= N; i++))
		do	print $i |&
			read -p r
			print -n $r
			wait $!
		done
		print
	) 2>/dev/null | read -t 10 r
	[[ $r == $e ]] || err_exit "$cat coprocess timing bug -- expected $e, got '$r'"
	
	r=
	(
		integer i
		for ((i = 1; i <= N; i++))
		do	print $i |&
			sleep 0.01
			r=$r$($cat <&p)
			wait $!
		done
		print $r
	) 2>/dev/null | read -t 10 r
	[[ $r == $e ]] || err_exit "$cat coprocess command substitution bug -- expected $e, got '$r'"
	
	(
		$cat |&
		sleep 0.01
		exec 6>&p
		print -u6 ok
		exec 6>&-
		sleep 2
		kill $! 2> /dev/null
	) && err_exit "$cat coprocess with subshell would hang"
	for sig in IOT ABRT
	do	if	( trap - $sig ) 2> /dev/null
		then	if	[[ $( { sig=$sig $SHELL  2> /dev/null <<- ++EOF++
					$cat |&
					pid=\$!
					trap "print TRAP" \$sig
					(
						sleep 2
						kill -\$sig \$\$
						sleep 2
						kill -\$sig \$\$
						kill \$pid
						sleep 2
						kill \$\$
					) &
					while	read -p || ((\$? > 256))
					do	:
					done
				++EOF++
				} ) != $'TRAP\nTRAP' ]] 2> /dev/null
			then	err_exit "traps when reading from $cat coprocess not working"
			fi
			break
		fi
	done
	
	trap 'sleep_pid=; kill $pid; err_exit "$cat coprocess 1 hung"' TERM
	{ sleep 5; kill $$; } &
	sleep_pid=$!
	$cat |&
	pid=$!
	exec 5<&p 6>&p
	exp=hi
	print -u6 $exp; read -u5
	[[ $REPLY == "$exp" ]] || err_exit "REPLY from $cat coprocess failed -- expected '$exp', got '$REPLY'"
	exec 6>&-
	wait $pid
	trap - TERM
	[[ $sleep_pid ]] && kill $sleep_pid
	
	trap 'sleep_pid=; kill $pid; err_exit "$cat coprocess 2 hung"' TERM
	{ sleep 5; kill $$; } &
	sleep_pid=$!
	$cat |&
	pid=$!
	print foo >&p 2> /dev/null || err_exit "first write of foo to $cat coprocess failed"
	print foo >&p 2> /dev/null || err_exit "second write of foo to coprocess failed"
	kill $pid
	wait $pid 2> /dev/null
	trap - TERM
	[[ $sleep_pid ]] && kill $sleep_pid
	
	trap 'sleep_pid=; kill $pid; err_exit "$cat coprocess 3 hung"' TERM
	{ sleep 5; kill $$; } &
	sleep_pid=$!
	$cat |&
	pid=$!
	print -p foo
	print -p bar
	read <&p || err_exit "first read from $cat coprocess failed"
	[[ $REPLY == foo ]] || err_exit "first REPLY from $cat coprocess is $REPLY not foo"
	read <&p || err_exit "second read from $cat coprocess failed"
	[[ $REPLY == bar ]] || err_exit "second REPLY from $cat coprocess is $REPLY not bar"
	kill $pid
	wait $pid 2> /dev/null
	trap - TERM
	[[ $sleep_pid ]] && kill $sleep_pid

done

exp=ksh
got=$(print -r $'#00315
COATTRIBUTES=\'label=make \'
# @(#)$Id: libcoshell (AT&T Research) 2008-04-28 $
_COSHELL_msgfd=5
{ { (eval \'function fun { trap \":\" 0; return 1; }; trap \"exit 0\" 0; fun; exit 1\') && PATH= print -u$_COSHELL_msgfd ksh; } || { times && echo bsh >&$_COSHELL_msgfd; } || { echo osh >&$_COSHELL_msgfd; }; } >/dev/null 2>&1' | $SHELL 5>&1)
[[ $got == $exp ]] || err_exit "coshell(3) identification sequence failed -- expected '$exp', got '$got'"

function cop
{
	read
	print ok
}

exp=ok

cop |&
pid=$!
if	print -p yo 2>/dev/null
then	read -p got
else	got='no coprocess'
fi
[[ $got == $exp ]] || err_exit "main coprocess main query failed -- expected $exp, got '$got'"
kill $pid 2>/dev/null
wait

cop |&
pid=$!
(
if	print -p yo 2>/dev/null
then	read -p got
else	got='no coprocess'
fi
[[ $got == $exp ]] || err_exit "main coprocess subshell query failed -- expected $exp, got '$got'"
)
kill $pid 2>/dev/null
wait

exp='no coprocess'

(
cop |&
print $! > $tmp/pid
)
pid=$(<$tmp/pid)
if	print -p yo 2>/dev/null
then	read -p got
else	got=$exp
fi
[[ $got == $exp ]] || err_exit "subshell coprocess main query failed -- expected $exp, got '$got'"
kill $pid 2>/dev/null
wait

(
cop |&
print $! > $tmp/pid
)
pid=$(<$tmp/pid)
(
if	print -p yo 2>/dev/null
then	read -p got
else	got=$exp
fi
[[ $got == $exp ]] || err_exit "subshell coprocess subshell query failed -- expected $exp, got '$got'"
kill $pid 2>/dev/null
wait
)

function mypipe
{
	read; read
	print -r -- "$REPLY"
}

mypipe |&
print -p "hello"
z="$( $bintrue $($bintrue) )"
{ print -p "world";} 2> /dev/null
read -p
[[ $REPLY == world ]] ||  err_exit "expected 'world' got '$REPLY'"
kill $pid 2>/dev/null
wait


function cop
{
        read
        print ok
}
exp=ok
cop |&
pid=$!
(
if      print -p yo 2>/dev/null
then    read -p got
else    got='no coprocess'
fi
[[ $got == $exp ]] || err_exit "main coprocess subshell query failed -- expected $exp, got '$got'"
)
kill $pid 2>/dev/null
wait

tee=$(whence -p tee)
ls -l |&
pid=$!
$tee -a /dev/null <&p > /dev/null
wait $pid
x=$?
[[ $x == 0 ]] || err_exit "coprocess exitval should be 0, not $x"

exit $((Errors<125?Errors:125))
