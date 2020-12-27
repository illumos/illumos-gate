########################################################################
#                                                                      #
#               This software is part of the ast package               #
#          Copyright (c) 1982-2011 AT&T Intellectual Property          #
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
# test the behavior of return and exit with functions

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

foo=NOVAL bar=NOVAL
file=$tmp/test
function foo
{
	typeset foo=NOEXIT
	trap "foo=EXIT;rm -f $file" EXIT
	> $file
	if	(( $1 == 0 ))
	then	return $2
	elif	(( $1 == 1 ))
	then	exit $2
	else	bar "$@"
	fi
}

function bar
{
	typeset bar=NOEXIT
	trap 'bar=EXIT' EXIT
	if	(( $1 == 2 ))
	then	return $2
	elif	(( $1 == 3 ))
	then	exit $2
	fi
}

function funcheck
{
	[[ $foo == EXIT ]] || err_exit "foo "$@" : exit trap not set"
	if	[[ -f $file ]]
	then	rm -r $file
		err_exit "foo $@: doesn't remove $file"
	fi
	foo=NOVAL bar=NOVAL
}

(exit 0) || err_exit "exit 0 is not zero"
(return 0) || err_exit "return 0 is not zero"
(exit) || err_exit "default exit value is not zero"
(return) || err_exit "default return value is not zero"
(exit 35)
ret=$?
if	(( $ret != 35 ))
then	err_exit "exit 35 is $ret not 35"
fi
(return 35)
ret=$?
if	(( $ret != 35 ))
then	err_exit "return 35 is $ret not 35"
fi

foo 0 0 || err_exit "foo 0 0: incorrect return"
funcheck 0 0
foo 0 3
ret=$?
if	(( $ret != 3 ))
then	err_exit "foo 0 3: return is $ret not 3"
fi
funcheck 0 3
foo 2 0 || err_exit "foo 2 0: incorrect return"
[[ $bar == EXIT ]] || err_exit "foo 2 0: bar exit trap not set"
funcheck 2 0
foo 2 3
ret=$?
if	(( $ret != 3 ))
then	err_exit "foo 2 3: return is $ret not 3"
fi
[[ $bar == EXIT ]] || err_exit "foo 2 3: bar exit trap not set"
funcheck 2 3
(foo 3 3)
ret=$?
if	(( $ret != 3 ))
then	err_exit "foo 3 3: return is $ret not 3"
fi
foo=EXIT
funcheck 3 3
cat > $file <<!
return 3
exit 4
!
( . $file )
ret=$?
if	(( $ret != 3 ))
then	err_exit "return in dot script is $ret should be 3"
fi
chmod 755 $file
(  $file )
ret=$?
if	(( $ret != 3 ))
then	err_exit "return in script is $ret should be 3"
fi
cat > $file <<!
: line 1
# next line should fail and cause an exit
: > /
exit 4
!
( . $file ; exit 5 ) 2> /dev/null
ret=$?
if	(( $ret != 1 ))
then	err_exit "error in dot script is $ret should be 1"
fi
(  $file; exit 5 ) 2> /dev/null
ret=$?
if	(( $ret != 5 ))
then	err_exit "error in script is $ret should be 5"
fi
cat > $file <<\!
print -r -- "$0"
!
x=$( . $file)
if	[[ $x != $0 ]]
then	err_exit "\$0 in a dot script is $x. Should be $0"
fi
x=$($SHELL -i --norc 2> /dev/null <<\!
typeset -i x=1/0
print hello
!
)
if	[[ $x != hello ]]
then	err_exit "interactive shell terminates with error in bltin"
fi
x=$( set -e
	false
	print bad
	)
if	[[ $x != '' ]]
then	err_exit "set -e doesn't terminate script on error"
fi
x=$( set -e
	trap 'exit 0' EXIT
	false
	print bad
	)
if	(( $? != 0 ))
then	err_exit "exit 0 in trap should doesn't set exit value to 0"
fi
$SHELL <<\!
trap 'exit 8' EXIT
exit 1
!
if	(( $? != 8 ))
then	err_exit "exit 8 in trap should set exit value to 8"
fi

exit $((Errors<125?Errors:125))
