########################################################################
#                                                                      #
#               This software is part of the ast package               #
#           Copyright (c) 1982-2007 AT&T Knowledge Ventures            #
#                      and is licensed under the                       #
#                  Common Public License, Version 1.0                  #
#                      by AT&T Knowledge Ventures                      #
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

if	[[ -d /cygdrive ]]
then	err_exit cygwin detected - coprocess tests disabled - enable at the risk of wedging your system
	exit $((Errors))
fi

function ping # id
{
	integer x=0
	while ((x < 5))
	do	read -r
		print -r "$1 $REPLY"
	done
}

cat |&
print -p "hello"
read -p line
[[ $line == hello ]] || err_exit 'coprocessing fails' 
exec 5>&p 6<&p
print -u5 'hello again' || err_exit 'write on u5 fails'
read -u6 line
[[ $line == 'hello again' ]] || err_exit 'coprocess after moving fds fails' 
exec 5<&- 6<&-

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
	count=count+1
	print  $to $i $count
done

while	((count > 0))
do	count=count-1
	read -p
#	print -r - "$REPLY"
	set -- $REPLY
	if	[[ $1 != $2 ]]
	then	err_exit "$1 does not match 2"
	fi
	case $1 in
	three);;
	four) ;;
	pipe) ;;
	*)	err_exit "unknown message +|$REPLY|+"
	esac
done

file=/tmp/regress$$
trap "rm -f $file" EXIT
cat > $file  <<\!
/bin/cat |&
!
chmod +x $file
$file 2> /dev/null  || err_exit "parent coprocess prevents script coprocess"
exec 5<&p 6>&p
exec 5<&- 6>&-
${SHELL-ksh} |&
print -p  $'print hello | cat\nprint Done'
read -t 5 -p
read -t 5 -p
if	[[ $REPLY != Done ]]
then	err_exit	"${SHELL-ksh} coprocess not working"
fi
exec 5<&p 6>&p
exec 5<&- 6>&-
count=0
{
echo line1 | grep 'line2'
echo line2 | grep 'line1'
} |&
SECONDS=0
while
   read -p -t 10 line
do
   ((count = count + 1))
   echo "Line $count: $line"
done
if	(( SECONDS > 8 ))
then	err_exit 'read -p hanging'
fi
( sleep 3 |& sleep 1 && kill $!; sleep 1; sleep 3 |& sleep 1 && kill $! ) || 
	err_exit "coprocess cleanup not working correctly"
unset line
(
	integer n=0
	while read  line
	do	echo $line  |&
		if	cat  <&p 
		then	((n++))
			wait $!
		fi
	done > /dev/null 2>&1 <<-  !
		line1
		line2
		line3
		line4
		line5
		line6
		line7
	!
	(( n==7 ))  && print ok
)  | read -t 10 line
if	[[ $line != ok ]]
then	err_exit 'coprocess timing bug'
fi
(
	/bin/cat |&
	exec 6>&p
	print -u6 ok
	exec 6>&-
	sleep 1
	kill $! 2> /dev/null 
) && err_exit 'coprocess with subshell would hang'
for sig in IOT ABRT
do	if	( trap - $sig ) 2> /dev/null
	then	if	[[ $(	
				cat |&
				pid=$!
				trap "print TRAP" $sig
				(
					sleep 2
					kill -$sig $$
					sleep 2
					kill -$sig $$
					kill $pid
				) 2> /dev/null &
				read -p
			) != $'TRAP\nTRAP' ]]
		then	err_exit 'traps when reading from coprocess not working'
		fi
		break
	fi
done

trap 'sleep_pid=; kill $pid; err_exit "coprocess 1 hung"' TERM
{ sleep 5; kill $$; } &
sleep_pid=$!
builtin cat
cat |&
pid=$!
exec 5<&p 6>&p
print -u6 hi; read -u5
[[ $REPLY == hi ]] || err_exit 'REPLY is $REPLY not hi'
exec 6>&-
wait $pid
trap - TERM
[[ $sleep_pid ]] && kill $sleep_pid

trap 'sleep_pid=; kill $pid; err_exit "coprocess 2 hung"' TERM
{ sleep 5; kill $$; } &
sleep_pid=$!
cat |& 
pid=$!
print foo >&p 2> /dev/null || err_exit 'first write of foo to coprocess failed'
print foo >&p 2> /dev/null || err_exit 'second write of foo to coprocess failed'
kill $pid
wait $pid 2> /dev/null
trap - TERM
[[ $sleep_pid ]] && kill $sleep_pid

trap 'sleep_pid=; kill $pid; err_exit "coprocess 3 hung"' TERM
{ sleep 5; kill $$; } &
sleep_pid=$!
cat |& 
pid=$!
print -p foo
print -p bar
read <&p || err_exit 'first read from coprocess failed'
[[ $REPLY == foo ]] || err_exit "first REPLY is $REPLY not foo"
read <&p || err_exit 'second read from coprocess failed'
[[ $REPLY == bar ]] || err_exit "second REPLY is $REPLY not bar"
kill $pid
wait $pid 2> /dev/null
trap - TERM
[[ $sleep_pid ]] && kill $sleep_pid

exit $((Errors))
