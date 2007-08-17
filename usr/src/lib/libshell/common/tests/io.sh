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
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	let Errors+=1
}
alias err_exit='err_exit $LINENO'

Command=${0##*/}
integer Errors=0
# cut here
function fun
{
	while  command exec 3>&1 
	do	break  
	done 2>   /dev/null
	print -u3 good
}
print 'read -r a;print -r -u$1 -- "$a"' >  /tmp/mycat$$
chmod 755 /tmp/mycat$$
for ((i=3; i < 10; i++))
do
	eval "a=\$(print foo | /tmp/mycat$$" $i $i'>&1 > /dev/null |cat)' 2> /dev/null
	[[ $a == foo ]] || err_exit "bad file descriptor $i in comsub script"
done
rm -f /tmp/mycat$$
exec 3> /dev/null
[[ $(fun) == good ]] || err_exit 'file 3 closed before subshell completes'
exec 3>&-
mkdir /tmp/ksh$$ || err_exit "mkdir /tmp/ksh$$ failed"
trap 'rm -rf /tmp/ksh$$' EXIT
cd /tmp/ksh$$ || err_exit "cd /tmp/ksh$$ failed"
print foo > file1
print bar >> file1
if	[[ $(<file1) != $'foo\nbar' ]]
then	err_exit 'append (>>) not working'
fi
set -o noclobber
exec 3<> file1
read -u3 line
if	[[ $line != foo ]]
then	err_exit '<> not working right with read'
fi
if	( 4> file1 ) 2> /dev/null
then	err_exit 'noclobber not causing exclusive open'
fi
set +o noclobber
if	command exec 4< /dev/fd/3
then	read -u4 line
	if	[[ $line != bar ]]
	then	'4< /dev/fd/3 not working correctly'
	fi
fi
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
	trap "rm -f in$$ out$$" EXIT
	for ((i = 0; i < 1000; i++))
	do	print -r -- "This is a test"
	done > in$$
	> out$$
	exec 1<> out$$
	builtin cat
	print -r -- "$(cat in$$)"
	cmp -s in$$ out$$'  2> /dev/null
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
exec 3>&- 4>&-; cd /; rm -r /tmp/ksh$$ || err_exit "rm -r /tmp/ksh$$ failed"
[[ $( {
	read -r line;print -r -- "$line"
	(
	        read -r line;print -r -- "$line"
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
cat > /tmp/io$$.1 <<- \++EOF++  
	script=/tmp/io$$.2
	trap 'rm -f $script' EXIT
	exec 9> $script
	for ((i=3; i<9; i++))
	do	eval "while read -u$i; do : ;done $i</dev/null"
		print -u9 "exec $i< /dev/null" 
	done
	for ((i=0; i < 60; i++))
	do	print -u9 -f "%.80c\n"  ' '
	done
	print -u9 'print ok'
	exec 9<&-
	chmod +x $script
	$script
++EOF++
chmod +x /tmp/io$$.1
[[ $($SHELL  /tmp/io$$.1) == ok ]]  || err_exit "parent i/o causes child script to fail"
rm -rf /tmp/io$$.[12]
# 2004-11-25 ancient /dev/fd/NN redirection bug fix
x=$(
	{
		print -n 1
		print -n 2 > /dev/fd/2
		print -n 3
		print -n 4 > /dev/fd/2
	}  2>&1
)
[[ $x == "1234" ]] || err_exit "/dev/fd/NN redirection fails to dup"
# 2004-12-20 redirction loss bug fix
cat > /tmp/io$$.1 <<- \++EOF++  
	function a
	{
		trap 'print ok' EXIT
		: > /dev/null
	}
	a
++EOF++
chmod +x /tmp/io$$.1
[[ $(/tmp/io$$.1) == ok ]] || err_exit "trap on EXIT loses last command redirection"
print > /dev/null {n}> /tmp/io$$.1 
[[ ! -s /tmp/io$$.1 ]] && newio=1
rm -rf /tmp/io$$.1
if	[[ $newio && $(print hello | while read -u$n; do print $REPLY; done {n}<&0) != hello ]] 
then	err_exit "{n}<&0 not working with for loop"
fi
[[ $({ read -r;read -u3 3<&0; print -- "$REPLY" ;} <<!
hello
world
!) == world ]] || err_exit 'I/O not synchronized with <&'
trap 'rm -f /tmp/seek$$; exit $((Errors+1))' EXIT
x="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNSPQRSTUVWXYZ1234567890"
for ((i=0; i < 62; i++))
do	printf "%.39c\n"  ${x:i:1}
done >  /tmp/seek$$
if	command exec 3<> /tmp/seek$$
then	(( $(3<#) == 0 )) || err_exit "not at position 0"
	(( $(3<# ((EOF))) == 40*62 )) || err_exit "not at end-of-file"
	command exec 3<# ((40*8)) || err_exit "absolute seek fails"	
	read -u3
	[[ $REPLY == +(i) ]] || err_exit "expecting iiii..."
	[[ $(3<#) == $(3<# ((CUR)) ) ]] || err_exit '$(3<#)!=$(3<#((CUR)))'
	command exec 3<# ((CUR+80))
	read -u3
	[[ $REPLY == {39}(l) ]] || err_exit "expecting lll..."
	command exec 3<# ((EOF-80))
	read -u3
	[[ $REPLY == +(9) ]] || err_exit "expecting 999...; got $REPLY"
	command exec 3># ((80))
	print -u3 -f "%.39c\n"  @
	command exec 3># ((80))
	read -u3
	[[ $REPLY == +(@) ]] || err_exit "expecting @@@..."
	read -u3
	[[ $REPLY == +(d) ]] || err_exit "expecting ddd..."
	command exec 3># ((EOF))
	print -u3 -f "%.39c\n"  ^
	(( $(3<# ((CUR-0))) == 40*63 )) || err_exit "not at extended end-of-file"
	command exec 3<# ((40*62)) 
	read -u3
	[[ $REPLY == +(^) ]] || err_exit "expecting ddd..."
	command exec 3<# ((0))
	command exec 3<# *jjjj*
	read -u3
	[[  $REPLY == {39}(j) ]] || err_exit "<# pattern failed"
	[[ $(command exec 3<## *llll*) = {39}(k) ]] || err_exit "<## pattern not saving standard output"
	read -u3
	[[  $REPLY == {39}(l) ]] || err_exit "<## pattern failed to position"
	command exec 3<# *abc*
	read -u3 && err_exit "not found pattern not positioning at eof"
	cat /tmp/seek$$ | read -r <# *WWW*
	[[ $REPLY == *WWWWW* ]] || err_exit '<# not working for pipes'
else	err_exit "/tmp/seek$$: cannot open for reading"
fi
trap "" EXIT
rm -f  /tmp/seek$$
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
trap 'rm -rf /tmp/io.sh$$*' EXIT
$SHELL -c "{ > /tmp/io.sh$$.1 ; date;} >&- 2> /dev/null" > /tmp/io.sh$$.2
[[ -s /tmp/io.sh$$.1 || -s /tmp/io.sh$$.2 ]] && err_exit 'commands with standard output closed produce output'
$SHELL -c "$SHELL -c ': 3>&1' 1>&- 2>/dev/null" && err_exit 'closed standard output not passed to subshell'
exit $((Errors))
