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
	let Errors+=1
}
alias err_exit='err_exit $LINENO'

# test basic file operations like redirection, pipes, file expansion
Command=${0##*/}
integer Errors=0
set -- \
	go+r	0000	\
	go-r	0044	\
	ug=r	0330	\
	go+w	0000	\
	go-w	0022	\
	ug=w	0550	\
	go+x	0000	\
	go-x	0011	\
	ug=x	0660	\
	go-rx	0055	\
	uo-wx	0303	\
	ug-rw	0660	\
	o=	0007
while	(( $# >= 2 ))
do	umask 0
	umask $1
	g=$(umask)
	[[ $g == $2 ]] || err_exit "umask 0; umask $1 failed -- expected $2, got $g"
	shift 2
done
umask u=rwx,go=rx || err_exit "umask u=rws,go=rx failed"
if	[[ $(umask -S) != u=rwx,g=rx,o=rx ]]
then	err_exit 'umask -S incorrect'
fi
mkdir  /tmp/ksh$$ || err_exit "mkdir /tmp/ksh$$ failed" 
trap "cd /; rm -rf /tmp/ksh$$" EXIT
pwd=$PWD
[[ $SHELL != /* ]] && SHELL=$pwd/$SHELL
cd /tmp/ksh$$ || err_exit "cd /tmp/ksh$$ failed"
um=$(umask -S)
( umask 0777; > foobar )
rm -f foobar
> foobar
[[ -r foobar ]] || err_exit 'umask not being restored after subshell'
umask "$um"
rm -f foobar
# optimizer bug test
> foobar
for i in 1 2
do      print foobar*
        rm -f foobar
done > out$$
if      [[ "$(<out$$)"  != "foobar"$'\n'"foobar*" ]]
then    print -u2 "optimizer bug with file expansion"
fi
rm -f out$$ foobar
mkdir dir
if	[[ $(print */) != dir/ ]]
then	err_exit 'file expansion with trailing / not working'
fi
if	[[ $(print *) != dir ]]
then	err_exit 'file expansion with single file not working'
fi
print hi > .foo
if	[[ $(print *) != dir ]]
then	err_exit 'file expansion leading . not working'
fi
date > dat1 || err_exit "date > dat1 failed"
test -r dat1 || err_exit "dat1 is not readable"
x=dat1
cat <$x > dat2 || err_exit "cat < $x > dat2 failed"
cat dat1 dat2 | cat  | cat | cat > dat3 || err_exit "cat pipe failed"
cat > dat4 <<!
$(date)
!
cat dat1 dat2 | cat  | cat | cat > dat5 &
wait $!
set -- dat*
if	(( $# != 5 ))
then	err_exit "dat* matches only $# files"
fi
if	(command > foo\\abc) 2> /dev/null 
then	set -- foo*
	if	[[ $1 != 'foo\abc' ]]
	then	err_exit 'foo* does not match foo\abc'
	fi
fi
if ( : > TT* && : > TTfoo ) 2>/dev/null
then	set -- TT*
	if	(( $# < 2 ))
	then	err_exit 'TT* not expanding when file TT* exists'
	fi
fi
cd ~- || err_exit "cd back failed"
cat > /tmp/ksh$$/script <<- !
	#! $SHELL
	print -r -- \$0
!
chmod 755 /tmp/ksh$$/script
if	[[ $(/tmp/ksh$$/script) != "/tmp/ksh$$/script" ]]
then	err_exit '$0 not correct for #! script'
fi
rm -r /tmp/ksh$$ || err_exit "rm -r /tmp/ksh$$ failed"
bar=foo
eval foo=\$bar
if	[[ $foo != foo ]]
then	err_exit 'eval foo=\$bar not working'
fi
bar='foo=foo\ bar'
eval $bar
if	[[ $foo != 'foo bar' ]]
then	err_exit 'eval foo=\$bar, with bar="foo\ bar" not working'
fi
cd /tmp
cd ../../tmp || err_exit "cd ../../tmp failed"
if	[[ $PWD != /tmp ]]
then	err_exit 'cd ../../tmp is not /tmp'
fi
( sleep 2; cat <<!
foobar
!
) | cat > /tmp/foobar$$ &
wait $!
foobar=$( < /tmp/foobar$$) 
if	[[ $foobar != foobar ]]
then	err_exit "$foobar is not foobar"
fi
{
	print foo
	/bin/echo bar
	print bam
} > /tmp/foobar$$
if	[[ $( < /tmp/foobar$$) != $'foo\nbar\nbam' ]]
then	err_exit "Output file pointer not shared correctly."
fi
cat > /tmp/foobar$$ <<\!
	print foo
	/bin/echo bar
	print bam
!
chmod +x /tmp/foobar$$
if	[[ $(/tmp/foobar$$) != $'foo\nbar\nbam' ]]
then	err_exit "Script not working."
fi
if	[[ $(/tmp/foobar$$ | /bin/cat) != $'foo\nbar\nbam' ]]
then	err_exit "Script | cat not working."
fi
if	[[ $( /tmp/foobar$$) != $'foo\nbar\nbam' ]]
then	err_exit "Output file pointer not shared correctly."
fi
rm -f /tmp/foobar$$
x=$( (print foo) ; (print bar) )
if	[[ $x != $'foo\nbar' ]]
then	err_exit " ( (print foo);(print bar ) failed"
fi
x=$( (/bin/echo foo) ; (print bar) )
if	[[ $x != $'foo\nbar' ]]
then	err_exit " ( (/bin/echo);(print bar ) failed"
fi
x=$( (/bin/echo foo) ; (/bin/echo bar) )
if	[[ $x != $'foo\nbar' ]]
then	err_exit " ( (/bin/echo);(/bin/echo bar ) failed"
fi
cat > /tmp/ksh$$ <<\!
if	[[ -p /dev/fd/0 ]]
then	builtin cat
	cat - > /dev/null
	[[ -p /dev/fd/0 ]] && print ok
else	print no
fi
!
chmod +x /tmp/ksh$$
case $( (print) | /tmp/ksh$$;:) in
ok)	;;
no)	err_exit "[[ -p /dev/fd/0 ]] fails for standard input pipe" ;;
*)	err_exit "builtin replaces standard input pipe" ;;
esac
print 'print $0' > /tmp/ksh$$
print ". /tmp/ksh$$" > /tmp/ksh$$x
chmod +x /tmp/ksh$$x
if	[[ $(/tmp/ksh$$x) != /tmp/ksh$$x ]]
then	err_exit '$0 not correct for . script'
fi
rm -r /tmp/ksh$$ /tmp/ksh$$x
mkdir  /tmp/ksh$$ || err_exit "mkdir /tmp/ksh$$ failed" 
cd /tmp/ksh$$ || err_exit "cd /tmp/ksh$$ failed"
print ./b > ./a; print ./c > b; print ./d > c; print ./e > d; print "echo \"hello there\"" > e 
chmod 755 a b c d e
x=$(./a)
if	[[ $x != "hello there" ]]
then	err_exit "nested scripts failed" 
fi
x=$( (./a) | cat)
if	[[ $x != "hello there" ]]
then	err_exit "scripts in subshells fail" 
fi
cd ~- || err_exit "cd back failed"
rm -r /tmp/ksh$$ || err_exit "rm -r /tmp/ksh$$ failed"
x=$( (/bin/echo foo) 2> /dev/null )
if	[[ $x != foo ]]
then	err_exit "subshell in command substitution fails"
fi
exec 1>&-
x=$(print hello)
if	[[ $x != hello ]]
then	err_exit "command subsitution with stdout closed failed"
fi
cd $pwd
x=$(cat <<\! | $SHELL
/bin/echo | /bin/cat
/bin/echo hello
!
)
if	[[ $x != $'\n'hello ]]
then	err_exit "$SHELL not working when standard input is a pipe"
fi
x=$( (/bin/echo hello) 2> /dev/null )
if	[[ $x != hello ]]
then	err_exit "subshell in command substitution with 1 closed fails"
fi
cat > /tmp/ksh$$ <<- \!
read line 2> /dev/null
print done
!
if	[[ $($SHELL /tmp/ksh$$ <&-) != done ]]
then	err_exit "executing script with 0 closed fails"
fi
trap '' INT
cat > /tmp/ksh$$ <<- \!
trap 'print bad' INT
kill -s INT $$
print good
!
chmod +x /tmp/ksh$$
if	[[ $($SHELL  /tmp/ksh$$) != good ]]
then	err_exit "traps ignored by parent not ignored"
fi
trap - INT
cat > /tmp/ksh$$ <<- \!
read line
/bin/cat
!
if	[[ $($SHELL /tmp/ksh$$ <<!
one
two
!
)	!= two ]]
then	err_exit "standard input not positioned correctly"
fi
word=$(print $'foo\nbar' | { read line; /bin/cat;})
if	[[ $word != bar ]]
then	err_exit "pipe to { read line; /bin/cat;} not working"
fi
word=$(print $'foo\nbar' | ( read line; /bin/cat) )
if	[[ $word != bar ]]
then	err_exit "pipe to ( read line; /bin/cat) not working"
fi
if	[[ $(print x{a,b}y) != 'xay xby' ]]
then	err_exit 'brace expansion not working'
fi
if	[[ $(for i in foo bar
	  do ( tgz=$(print $i)
	  print $tgz)
	  done) != $'foo\nbar' ]]
then	err_exit 'for loop subshell optimizer bug'
fi
unset a1
optbug()
{
	set -A a1  foo bar bam
	integer i
	for ((i=0; i < 3; i++))
	do
		(( ${#a1[@]} < 2 )) && return 0
		set -- "${a1[@]}"
		shift
		set -A a1 -- "$@"
	done
	return 1
}
optbug ||  err_exit 'array size optimzation bug'
wait # not running --pipefail which would interfere with subsequent tests
: $(jobs -p) # required to clear jobs for next jobs -p (interactive side effect)
sleep 20 &
pids=$!
if	[[ $(jobs -p) != $! ]]
then	err_exit 'jobs -p not reporting a background job' 
fi
sleep 20 &
pids="$pids $!"
foo()
{
	set -- $(jobs -p)
	(( $# == 2 )) || err_exit "$# jobs not reported -- 2 expected"
}
foo
kill $pids

[[ $( (trap 'print alarm' ALRM; sleep 4) & sleep 2; kill -ALRM $!; sleep 2; wait) == alarm ]] || err_exit 'ALRM signal not working'
[[ $($SHELL -c 'trap "" HUP; $SHELL -c "(sleep 2;kill -HUP $$)& sleep 4;print done"') != done ]] && err_exit 'ignored traps not being ignored'
[[ $($SHELL -c 'o=foobar; for x in foo bar; do (o=save);print $o;done' 2> /dev/null ) == $'foobar\nfoobar' ]] || err_exit 'for loop optimization subshell bug'
command exec 3<> /dev/null
if	cat /dev/fd/3 >/dev/null 2>&1
then	[[ $($SHELL -c 'cat <(print foo)' 2> /dev/null) == foo ]] || err_exit 'process substitution not working'
	[[ $($SHELL -c 'print $(cat <(print foo) )' 2> /dev/null) == foo ]] || err_exit 'process substitution in subshell not working'
	[[ $($SHELL -c  $'tee >(grep \'1$\' > /tmp/ksh'$$'x) > /dev/null <<-  \!!!
	line0
	line1
	line2
	!!!
	wait
	cat /tmp/ksh'$$x 2> /dev/null)  == line1 ]] || err_exit '>() process substitution fails'
	> /tmp/ksh$$x
	[[ $($SHELL -c  $'
	for i in 1
	do	tee >(grep \'1$\' > /tmp/ksh'$$'x) > /dev/null  <<-  \!!!
		line0
		line1
		line2
		!!!
	done
	wait
	cat /tmp/ksh'$$x 2>> /dev/null) == line1 ]] || err_exit '>() process substitution fails in for loop'
	[[ $({ $SHELL -c 'cat <(for i in x y z; do print $i; done)';} 2> /dev/null) == $'x\ny\nz' ]] ||
		err_exit 'process substitution of compound commands not working'
fi
[[ $($SHELL -r 'command -p :' 2>&1) == *restricted* ]]  || err_exit 'command -p not restricted'
print cat >  /tmp/ksh$$x
chmod +x /tmp/ksh$$x
[[ $($SHELL -c "print foo | /tmp/ksh$$x ;:" 2> /dev/null ) == foo ]] || err_exit 'piping into script fails'
[[ $($SHELL -c 'X=1;print -r -- ${X:=$(expr "a(0)" : '"'a*(\([^)]\))')}'" 2> /dev/null) == 1 ]] || err_exit 'x=1;${x:=$(..."...")} failure'
[[ $($SHELL -c 'print -r -- ${X:=$(expr "a(0)" : '"'a*(\([^)]\))')}'" 2> /dev/null) == 0 ]] || err_exit '${x:=$(..."...")} failure'
exec 3<&-
if	[[ -d /dev/fd  && -w /dev/fd/3 ]]
then	[[ $(cat <(print hello) ) == hello ]] || err_exit "process substitution not working outside for or while loop"
	$SHELL -c '[[ $(for i in 1;do cat <(print hello);done ) == hello ]]' 2> /dev/null|| err_exit "process substitution not working in for or while loop"
fi
exec 3> /dev/null
print 'print foo "$@"' > /tmp/ksh$$x
[[ $( print "(/tmp/ksh$$x bar)" | $SHELL 2>/dev/null) == 'foo bar' ]] || err_exit 'script pipe to shell fails'
print "#! $SHELL" > /tmp/ksh$$x
print 'print  -- $0' >> /tmp/ksh$$x
chmod +x /tmp/ksh$$x
[[ $(/tmp/ksh$$x) == /tmp/ksh$$x ]] || err_exit  "\$0 is $0 instead of /tmp/ksh$$x"
cat > /tmp/ksh$$x <<- \EOF
	myfilter() { x=$(print ok | cat); print  -r -- $SECONDS;}
	set -o pipefail
	sleep 3 | myfilter
EOF
(( $($SHELL /tmp/ksh$$x) > 2.0 )) && err_exit 'command substitution causes pipefail option to hang'
rm -f /tmp/ksh$$x
exec 3<&-
( typeset -r foo=bar) 2> /dev/null || err_exit 'readonly variables set in a subshell cannot unset'
$SHELL -c 'x=${ print hello;}; [[ $x == hello ]]' 2> /dev/null || err_exit '${ command;} not supported'
$SHELL 2> /dev/null <<- \EOF || err_exit 'multiline ${...} command substitution not supported'
	x=${
		print hello
	}
	[[ $x == hello ]]
EOF
$SHELL 2> /dev/null <<- \EOF || err_exit '${...} command substitution with side effects not supported '
	y=bye
	x=${
		y=hello
		print hello
	}
	[[ $y == $x ]]
EOF
$SHELL   2> /dev/null <<- \EOF || err_exit 'nested ${...} command substitution not supported'
	x=${
		print ${ print hello;} $(print world)
	}
	[[ $x == 'hello world' ]]
EOF
$SHELL   2> /dev/null <<- \EOF || err_exit 'terminating } is not a reserved word with ${ command }'
	x=${	{ print -n } ; print -n hello ; }  ; print ' world' }
	[[ $x == '}hello world' ]]
EOF
$SHELL   2> /dev/null <<- \EOF || err_exit '${ command;}xxx not working'
	f()
	{
		print foo
	}
	[[ ${ f;}bar == foobar ]]
EOF

unset foo
function foo
{
	print bar
}
[[ ${foo} == bar ]] || err_exit '${foo} is not command substitution when foo unset' 
[[ ! ${foo[@]} ]] || err_exit '${foo[@]} is not empty when foo is unset' 
[[ ! ${foo[3]} ]] || err_exit '${foo[3]} is not empty when foo is unset' 
[[ $(print  "[${ print foo }]") == '[foo]' ]] || err_exit '${...} not working when } is followed by ]'
[[ $(print  "${ print "[${ print foo }]" }") == '[foo]' ]] || err_exit 'nested ${...} not working when } is followed by ]'
unset foo
foo=$(false) > /dev/null && err_exit 'failed command substitution with redirection not returning false'
expected=foreback
got=$(print -n fore;(sleep 2;print back)&)
[[ $got == $expected ]] || err_exit "command substitution background process output error -- got '$got', expected '$expected'"

for false in false $(whence -p false)
do	x=$($false) && err_exit "x=\$($false) should fail"
	$($false) && err_exit "\$($false) should fail"
	$($false) > /dev/null && err_exit "\$($false) > /dev/null should fail"
done
[[ $(env 'x-a=y'  $SHELL -c 'env | grep x-a') == *x-a=y* ]] || err_exit 'invalid environment variables not preserved'
exit $((Errors))
