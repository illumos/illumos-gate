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

cd $tmp || exit
type /xxxxxx > out1 2> out2
[[ -s out1 ]] && err_exit 'type should not write on stdout for not found case'
[[ -s out2 ]] || err_exit 'type should write on stderr for not found case'
mkdir dir1 dir2
cat  > dir1/foobar << '+++'
foobar() { print foobar1;}
function dir1 { print dir1;}
+++
cat  > dir2/foobar << '+++'
foobar() { print foobar2;}
function dir2 { print dir2;}
+++
chmod +x dir[12]/foobar
p=$PATH
FPATH=$PWD/dir1
PATH=$FPATH:$p
[[ $( foobar) == foobar1 ]] || err_exit 'foobar should output foobar1'
FPATH=$PWD/dir2
PATH=$FPATH:$p
[[ $(foobar) == foobar2 ]] || err_exit 'foobar should output foobar2'
FPATH=$PWD/dir1
PATH=$FPATH:$p
[[ $(foobar) == foobar1 ]] || err_exit 'foobar should output foobar1 again'
FPATH=$PWD/dir2
PATH=$FPATH:$p
[[ ${ foobar;} == foobar2 ]] || err_exit 'foobar should output foobar2 with ${}'
[[ ${ dir2;} == dir2 ]] || err_exit 'should be dir2'
[[ ${ dir1;} == dir1 ]] 2> /dev/null &&  err_exit 'should not be be dir1'
FPATH=$PWD/dir1
PATH=$FPATH:$p
[[ ${ foobar;} == foobar1 ]] || err_exit 'foobar should output foobar1 with ${}'
[[ ${ dir1;} == dir1 ]] || err_exit 'should be dir1'
[[ ${ dir2;} == dir2 ]] 2> /dev/null &&  err_exit 'should not be be dir2'
FPATH=$PWD/dir2
PATH=$FPATH:$p
[[ ${ foobar;} == foobar2 ]] || err_exit 'foobar should output foobar2 with ${} again'
PATH=$p
(PATH="/bin")
[[ $($SHELL -c 'print -r -- "$PATH"') == "$PATH" ]] || err_exit 'export PATH lost in subshell'
cat > bug1 <<- EOF
	print print ok > $tmp/ok
	/bin/chmod 755 $tmp/ok
	function a
	{
	        typeset -x PATH=$tmp
	        ok
	}
	path=\$PATH
	unset PATH
	a
	PATH=\$path
}
EOF
[[ $($SHELL ./bug1 2>/dev/null) == ok ]]  || err_exit "PATH in function not working"
cat > bug1 <<- \EOF
	function lock_unlock
	{
	typeset PATH=/usr/bin
	typeset -x PATH=''
	}

	PATH=/usr/bin
	: $(PATH=/usr/bin getconf PATH)
	typeset -ft lock_unlock
	lock_unlock
EOF
($SHELL ./bug1)  2> /dev/null || err_exit "path_delete bug"
mkdir tdir
if	$SHELL tdir > /dev/null 2>&1
then	err_exit 'not an error to run ksh on a directory'
fi

print 'print hi' > ls
if	[[ $($SHELL ls 2> /dev/null) != hi ]]
then	err_exit "$SHELL name not executing version in current directory"
fi
if	[[ $(ls -d . 2>/dev/null) == . && $(PATH=/bin:/usr/bin:$PATH ls -d . 2>/dev/null) != . ]]
then	err_exit 'PATH export in command substitution not working'
fi
pwd=$PWD
# get rid of leading and trailing : and trailing :.
PATH=${PATH%.}
PATH=${PATH%:}
PATH=${PATH#.}
PATH=${PATH#:}
path=$PATH
var=$(whence date)
dir=$(basename "$var")
for i in 1 2 3 4 5 6 7 8 9 0
do	if	! whence notfound$i 2> /dev/null
	then	cmd=notfound$i
		break
	fi
done
print 'print hello' > date
chmod +x date
print 'print notfound' >  $cmd
chmod +x "$cmd"
> foo
chmod 755 foo
for PATH in $path :$path $path: .:$path $path: $path:. $PWD::$path $PWD:.:$path $path:$PWD $path:.:$PWD
do
#	print path=$PATH $(whence date)
#	print path=$PATH $(whence "$cmd")
		date
		"$cmd"
done > /dev/null 2>&1
builtin -d date 2> /dev/null
if	[[ $(PATH=:/usr/bin; date) != 'hello' ]]
then	err_exit "leading : in path not working"
fi
(
	PATH=$PWD:
	builtin chmod
	print 'print cannot execute' > noexec
	chmod 644 noexec
	if	[[ ! -x noexec ]]
	then	noexec > /dev/null 2>&1
	else	exit 126
	fi
)
status=$?
[[ $status == 126 ]] || err_exit "exit status of non-executable is $status -- 126 expected"
builtin -d rm 2> /dev/null
chmod=$(whence chmod)
rm=$(whence rm)
d=$(dirname "$rm")

chmod=$(whence chmod)

for cmd in date foo
do	exp="$cmd found"
	print print $exp > $cmd
	$chmod +x $cmd
	got=$($SHELL -c "unset FPATH; PATH=/dev/null; $cmd" 2>&1)
	[[ $got == $exp ]] && err_exit "$cmd as last command should not find ./$cmd with PATH=/dev/null"
	got=$($SHELL -c "unset FPATH; PATH=/dev/null; $cmd" 2>&1)
	[[ $got == $exp ]] && err_exit "$cmd should not find ./$cmd with PATH=/dev/null"
	exp=$PWD/./$cmd
	got=$(unset FPATH; PATH=/dev/null; whence ./$cmd)
	[[ $got == $exp ]] || err_exit "whence $cmd should find ./$cmd with PATH=/dev/null"
	exp=$PWD/$cmd
	got=$(unset FPATH; PATH=/dev/null; whence $PWD/$cmd)
	[[ $got == $exp ]] || err_exit "whence \$PWD/$cmd should find ./$cmd with PATH=/dev/null"
done

exp=''
got=$($SHELL -c "unset FPATH; PATH=/dev/null; whence ./notfound" 2>&1)
[[ $got == $exp ]] || err_exit "whence ./$cmd failed -- expected '$exp', got '$got'"
got=$($SHELL -c "unset FPATH; PATH=/dev/null; whence $PWD/notfound" 2>&1)
[[ $got == $exp ]] || err_exit "whence \$PWD/$cmd failed -- expected '$exp', got '$got'"

unset FPATH
PATH=/dev/null
for cmd in date foo
do	exp="$cmd found"
	print print $exp > $cmd
	$chmod +x $cmd
	got=$($cmd 2>&1)
	[[ $got == $exp ]] && err_exit "$cmd as last command should not find ./$cmd with PATH=/dev/null"
	got=$($cmd 2>&1; :)
	[[ $got == $exp ]] && err_exit "$cmd should not find ./$cmd with PATH=/dev/null"
	exp=$PWD/./$cmd
	got=$(whence ./$cmd)
	[[ $got == $exp ]] || err_exit "whence ./$cmd should find ./$cmd with PATH=/dev/null"
	exp=$PWD/$cmd
	got=$(whence $PWD/$cmd)
	[[ $got == $exp ]] || err_exit "whence \$PWD/$cmd should find ./$cmd with PATH=/dev/null"
done
exp=''
got=$(whence ./notfound)
[[ $got == $exp ]] || err_exit "whence ./$cmd failed -- expected '$exp', got '$got'"
got=$(whence $PWD/notfound)
[[ $got == $exp ]] || err_exit "whence \$PWD/$cmd failed -- expected '$exp', got '$got'"

PATH=$d:
cp "$rm" kshrm
if	[[ $(whence kshrm) != $PWD/kshrm  ]]
then	err_exit 'trailing : in pathname not working'
fi
cp "$rm" rm
PATH=:$d
if	[[ $(whence rm) != $PWD/rm ]]
then	err_exit 'leading : in pathname not working'
fi
PATH=$d: whence rm > /dev/null
if	[[ $(whence rm) != $PWD/rm ]]
then	err_exit 'pathname not restored after scoping'
fi
mkdir bin
print 'print ok' > bin/tst
chmod +x bin/tst
if	[[ $(PATH=$PWD/bin tst 2>/dev/null) != ok ]]
then	err_exit '(PATH=$PWD/bin foo) does not find $PWD/bin/foo'
fi
cd /
if	whence ls > /dev/null
then	PATH=
	if	[[ $(whence rm) ]]
	then	err_exit 'setting PATH to Null not working'
	fi
	unset PATH
	if	[[ $(whence rm) != /*rm ]]
	then	err_exit 'unsetting path  not working'
	fi
fi
PATH=/dev:$tmp
x=$(whence rm)
typeset foo=$(PATH=/xyz:/abc :)
y=$(whence rm)
[[ $x != "$y" ]] && err_exit 'PATH not restored after command substitution'
whence getconf > /dev/null  &&  err_exit 'getconf should not be found'
builtin /bin/getconf
PATH=/bin
PATH=$(getconf PATH)
x=$(whence ls)
PATH=.:$PWD:${x%/ls}
[[ $(whence ls) == "$x" ]] || err_exit 'PATH search bug when .:$PWD in path'
PATH=$PWD:.:${x%/ls}
[[ $(whence ls) == "$x" ]] || err_exit 'PATH search bug when :$PWD:. in path'
cd   "${x%/ls}"
[[ $(whence ls) == /* ]] || err_exit 'whence not generating absolute pathname'
status=$($SHELL -c $'trap \'print $?\' EXIT;/xxx/a/b/c/d/e 2> /dev/null')
[[ $status == 127 ]] || err_exit "not found command exit status $status -- expected 127"
status=$($SHELL -c $'trap \'print $?\' EXIT;/dev/null 2> /dev/null')
[[ $status == 126 ]] || err_exit "non executable command exit status $status -- expected 126"
status=$($SHELL -c $'trap \'print $?\' ERR;/xxx/a/b/c/d/e 2> /dev/null')
[[ $status == 127 ]] || err_exit "not found command with ERR trap exit status $status -- expected 127"
status=$($SHELL -c $'trap \'print $?\' ERR;/dev/null 2> /dev/null')
[[ $status == 126 ]] || err_exit "non executable command ERR trap exit status $status -- expected 126"

# universe via PATH

builtin getconf
getconf UNIVERSE - att # override sticky default 'UNIVERSE = foo'

[[ $(PATH=/usr/ucb/bin:/usr/bin echo -n ucb) == 'ucb' ]] || err_exit "ucb universe echo ignores -n option"
[[ $(PATH=/usr/xpg/bin:/usr/bin echo -n att) == '-n att' ]] || err_exit "att universe echo does not ignore -n option"

PATH=$path

scr=$tmp/script
exp=126

: > $scr
chmod a=x $scr
{ got=$($scr; print $?); } 2>/dev/null
[[ "$got" == "$exp" ]] || err_exit "unreadable empty script should fail -- expected $exp, got $got"
{ got=$(command $scr; print $?); } 2>/dev/null
[[ "$got" == "$exp" ]] || err_exit "command of unreadable empty script should fail -- expected $exp, got $got"
[[ "$(:; $scr; print $?)" == "$exp" ]] 2>/dev/null || err_exit "unreadable empty script in [[ ... ]] should fail -- expected $exp"
[[ "$(:; command $scr; print $?)" == "$exp" ]] 2>/dev/null || err_exit "command unreadable empty script in [[ ... ]] should fail -- expected $exp"
got=$($SHELL -c "$scr; print \$?" 2>/dev/null)
[[ "$got" == "$exp" ]] || err_exit "\$SHELL -c of unreadable empty script should fail -- expected $exp, got" $got
got=$($SHELL -c "command $scr; print \$?" 2>/dev/null)
[[ "$got" == "$exp" ]] || err_exit "\$SHELL -c of command of unreadable empty script should fail -- expected $exp, got" $got

rm -f $scr
print : > $scr
chmod a=x $scr
{ got=$($scr; print $?); } 2>/dev/null
[[ "$got" == "$exp" ]] || err_exit "unreadable non-empty script should fail -- expected $exp, got $got"
{ got=$(command $scr; print $?); } 2>/dev/null
[[ "$got" == "$exp" ]] || err_exit "command of unreadable non-empty script should fail -- expected $exp, got $got"
[[ "$(:; $scr; print $?)" == "$exp" ]] 2>/dev/null || err_exit "unreadable non-empty script in [[ ... ]] should fail -- expected $exp"
[[ "$(:; command $scr; print $?)" == "$exp" ]] 2>/dev/null || err_exit "command unreadable non-empty script in [[ ... ]] should fail -- expected $exp"
got=$($SHELL -c "$scr; print \$?" 2>/dev/null)
[[ "$got" == "$exp" ]] || err_exit "\$SHELL -c of unreadable non-empty script should fail -- expected $exp, got" $got
got=$($SHELL -c "command $scr; print \$?" 2>/dev/null)
[[ "$got" == "$exp" ]] || err_exit "\$SHELL -c of command of unreadable non-empty script should fail -- expected $exp, got" $got

# whence -a bug fix
cd "$tmp"
ifs=$IFS
IFS=$'\n'
PATH=$PATH:
> ls
chmod +x ls
ok=
for i in $(whence -a ls)
do	if	[[ $i == *"$PWD/ls" ]]
	then	ok=1
		break;
	fi
done
[[ $ok ]] || err_exit 'whence -a not finding all executables'
rm -f ls
PATH=${PATH%:}

#whence -p bug fix
function foo
{
	:
}
[[ $(whence -p foo) == foo ]] && err_exit 'whence -p foo should not find function foo'

# whence -q bug fix
$SHELL -c 'whence -q cat' & pid=$!
sleep 3
kill $! 2> /dev/null && err_exit 'whence -q appears to be hung'

FPATH=$PWD
print  'function foobar { :;}' > foobar
autoload foobar;
exec {m}< /dev/null
for ((i=0; i < 25; i++))
do	( foobar )
done
exec {m}<& -
exec {n}< /dev/null
(( n > m )) && err_exit 'autoload function in subshell leaves file open'

# whence -a bug fix
rmdir=rmdir
if	mkdir "$rmdir"
then	rm=${ whence rm;}
	cp "$rm" "$rmdir"
	{ PATH=:${rm%/rm} $SHELL -c "cd \"$rmdir\";whence -a rm";} > /dev/null 2>&1
	exitval=$?
	(( exitval==0 )) || err_exit "whence -a has exitval $exitval"
fi

[[ ! -d bin ]] && mkdir bin
[[ ! -d fun ]] && mkdir fun
print 'FPATH=../fun' > bin/.paths
cat <<- \EOF > fun/myfun
	function myfun
	{
		print myfun
	}
EOF
x=$(FPATH= PATH=$PWD/bin $SHELL -c  ': $(whence less);myfun') 2> /dev/null
[[ $x == myfun ]] || err_exit 'function myfun not found'

cp $(whence -p echo) user_to_group_relationship.hdr.query
FPATH=/foobar:
PATH=$FPATH:$PATH:.
[[ $(user_to_group_relationship.hdr.query foobar) == foobar ]] 2> /dev/null || err_exit 'Cannot execute command with . in name when PATH and FPATH end in :.'

mkdir -p $tmp/new/bin
mkdir $tmp/new/fun
print FPATH=../fun > $tmp/new/bin/.paths
print FPATH=../xxfun > $tmp/bin/.paths
cp "$(whence -p echo)" $tmp/new/bin
PATH=$tmp/bin:$tmp/new/bin:$PATH
x=$(whence -p echo 2> /dev/null)
[[ $x == "$tmp/new/bin/echo" ]] ||  err_exit 'nonexistant FPATH directory in .paths file causes path search to fail'

$SHELL 2> /dev/null <<- \EOF || err_exit 'path search problem with non-existant directories in PATH'
	PATH=/usr/nogood1/bin:/usr/nogood2/bin:/bin:/usr/bin
	tail /dev/null && tail /dev/null
EOF

( PATH=/bin:usr/bin
cat << END >/dev/null 2>&1
${.sh.version}
END
) || err_exit '${.sh.xxx} variables causes cat not be found'

exit $((Errors<125?Errors:125))

