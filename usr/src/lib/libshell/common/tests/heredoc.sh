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
	let Errors+=1
}
alias err_exit='err_exit $LINENO'

Command=${0##*/}
integer Errors=0

tmp=$(mktemp -dt) || { err_exit mktemp -dt failed; exit 1; }
trap "cd /; rm -rf $tmp" EXIT

f=$tmp/here1
g=$tmp/here2
cat > $f <<!
hello world
!
if	[[ $(<$f) != 'hello world' ]]
then	err_exit "'hello world' here doc not working"
fi
cat > $g <<\!
hello world
!
cmp $f $g 2> /dev/null || err_exit "'hello world' quoted here doc not working"
cat > $g <<- !
	hello world
!
cmp $f $g 2> /dev/null || err_exit "'hello world' tabbed here doc not working"
cat > $g <<- \!
	hello world
!
cmp $f $g 2> /dev/null || err_exit "'hello world' quoted tabbed here doc not working"
x=hello
cat > $g <<!
$x world
!
cmp $f $g 2> /dev/null || err_exit "'$x world' here doc not working"
cat > $g <<!
$(print hello) world
!
cmp $f $g 2> /dev/null || err_exit "'$(print hello) world' here doc not working"
cat > $f <<\!!
!@#$%%^^&*()_+~"::~;'`<>?/.,{}[]
!!
if	[[ $(<$f) != '!@#$%%^^&*()_+~"::~;'\''`<>?/.,{}[]' ]]
then	err_exit "'hello world' here doc not working"
fi
cat > $g <<!!
!@#\$%%^^&*()_+~"::~;'\`<>?/.,{}[]
!!
cmp $f $g 2> /dev/null || err_exit "unquoted here doc not working"
exec 3<<!
	foo
!
if	[[ $(<&3) != '	foo' ]]
then	err_exit "leading tabs stripped with <<!"
fi
$SHELL -c "
eval `echo 'cat <<x'` "|| err_exit "eval `echo 'cat <<x'` core dumps"
cat > /dev/null <<EOF # comments should not cause core dumps
abc
EOF
cat >$g << :
:
:
cmp /dev/null $g 2> /dev/null || err_exit "empty here doc not working"
x=$(print $( cat <<HUP
hello
HUP
)
)
if	[[ $x != hello ]]
then	err_exit "here doc inside command sub not working"
fi
y=$(cat <<!
${x:+${x}}
!
)
if	[[ $y != "${x:+${x}}" ]]
then	err_exit '${x:+${x}} not working in here document'
fi
$SHELL -c '
x=0
while (( x < 100 ))
do	((x = x+1))
	cat << EOF
EOF
done
' 2> /dev/null  || err_exit '100 empty here docs fails'
{
	print 'builtin -d cat
	cat <<- EOF'
	for ((i=0; i < 100; i++))
	do print XXXXXXXXXXXXXXXXXXXX
	done
	print ' XXX$(date)XXXX
	EOF'
} > $f
chmod +x "$f"
$SHELL "$f" > /dev/null  || err_exit "large here-doc with command substitution fails"
x=$(/bin/cat <<!
$0
!
)
[[ "$x" == "$0" ]] || err_exit '$0 not correct inside here documents'
$SHELL -c 'x=$(
cat << EOF
EOF)' 2> /dev/null || err_exit 'here-doc cannot be terminated by )'
if	[[ $( IFS=:;cat <<-!
			$IFS$(print hi)$IFS
		!) != :hi: ]]
then	err_exit '$IFS unset by command substitution in here docs'
fi
if	x=$($SHELL -c 'cat <<< "hello world"' 2> /dev/null)
then	[[ $x == 'hello world' ]] || err_exit '<<< documents not working'
	x=$($SHELL -c 'v="hello  world";cat <<< $v' 2> /dev/null)
	[[ $x == 'hello  world' ]] || err_exit '<<< documents with $x not working'
	x=$($SHELL -c 'v="hello  world";cat <<< "$v"' 2> /dev/null)
	[[ $x == 'hello  world' ]] || err_exit '<<< documents with $x not working'
else	err_exit '<<< syntax not supported'
fi
if	[[ $(cat << EOF #testing
#abc
abc
EOF) != $'#abc\nabc' ]]
then	err_exit 'comments not preserved in here-documents'
fi
cat  > "$f" <<- '!!!!'
	builtin cat
	: << EOF
	$PWD
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	EOF
	command exec 3>&- 4>&- 5>&- 6>&- 7>&- 8>&- 9>&-
	x=abc
	cat << EOF
	$x
	EOF
!!!!
chmod 755 "$f"
if	[[ $($SHELL  "$f") != abc ]]
then	err_exit	'here document descritor was closed'
fi
cat  > "$f" <<- '!!!!'
	exec 0<&-
	foobar()
	{
		/bin/cat <<- !
		foobar
		!
	}
	: << EOF
	$PWD
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
	EOF
	print -r -- "$(foobar)"
!!!!
if	[[ $($SHELL  "$f") != foobar ]]
then	err_exit	'here document with stdin closed failed'
fi
printf $'cat   <<# \\!!!\n\thello\n\t\tworld\n!!!' > $f
[[ $($SHELL "$f") == $'hello\n\tworld' ]] || err_exit "<<# not working for quoted here documents"
printf $'w=world;cat   <<# !!!\n\thello\n\t\t$w\n!!!' > $f
[[ $($SHELL "$f") == $'hello\n\tworld' ]] || err_exit "<<# not working for non-quoted here documents"
[[ $( $SHELL  <<- \++++
	S=( typeset a )
	function S.a.get
	{
	     .sh.value=$__a
	}
	__a=1234
	cat <<-EOF
	${S.a}
	EOF
++++
) == 1234 ]]  2> /dev/null || err_exit 'here document with get discipline failed'
[[ $($SHELL -c 'g(){ print ok;}; cat <<- EOF
	${ g;}
	EOF
	' 2> /dev/null) == ok ]] || err_exit '${ command;} not working in heredoc'
script=$f
{
for ((i=0; i < 406; i++))
do	print ': 23456789012345678'
done
print : 123456789123
cat <<- \EOF
eval "$(
	{ cat                                 ; } <<MARKER
	  print  hello
	MARKER
)"
EOF
} > $script
chmod +x $script
[[ $($SHELL $script) == hello ]] 2> /dev/null || err_exit 'heredoc embeded in command substitution fails at buffer boundary'

got=$( cat << EOF
\
abc
EOF)
[[ $got == abc ]] || err_exit 'line continuation at start of buffer not working'

exit $((Errors))
