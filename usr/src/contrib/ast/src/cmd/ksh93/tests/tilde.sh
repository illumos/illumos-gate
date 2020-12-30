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
	print -u2 -r $Command: "$@"
	let Errors+=1
}
alias err_exit='err_exit $LINENO'

Command=${0##*/}
integer Errors=0

tmp=$(mktemp -dt) || { err_exit mktemp -dt failed; exit 1; }
trap "cd /; rm -rf $tmp" EXIT

if	$SHELL -c '[[ ~root == /* ]]'
then	x=$(print -r -- ~root)
	[[ $x == ~root ]] || err_exit '~user expanded in subshell prevent ~user from working'
fi

function home # id
{
	typeset IFS=: pwd=/etc/passwd
	set -o noglob
	if	[[ -f $pwd ]] && grep -c "^$1:" $pwd > /dev/null
	then	set -- $(grep "^$1:" $pwd)
		print -r -- "$6"
	else	print .
	fi
}

OLDPWD=/bin
if	[[ ~ != $HOME ]]
then	err_exit '~' not $HOME
fi
x=~
if	[[ $x != $HOME ]]
then	err_exit x=~ not $HOME
fi
x=x:~
if	[[ $x != x:$HOME ]]
then	err_exit x=x:~ not x:$HOME
fi
if	[[ ~+ != $PWD ]]
then	err_exit '~' not $PWD
fi
x=~+
if	[[ $x != $PWD ]]
then	err_exit x=~+ not $PWD
fi
if	[[ ~- != $OLDPWD ]]
then	err_exit '~' not $PWD
fi
x=~-
if	[[ $x != $OLDPWD ]]
then	err_exit x=~- not $OLDPWD
fi
for u in root Administrator
do	h=$(home $u)
	if	[[ $h != . ]]
	then	[[ ~$u -ef $h ]] || err_exit "~$u not $h"
		x=~$u
		[[ $x -ef $h ]] || x="~$u not $h"
		break
	fi
done
x=~g.r.emlin
if	[[ $x != '~g.r.emlin' ]]
then	err_exit "x=~g.r.emlin failed -- expected '~g.r.emlin', got '$x'"
fi
x=~:~
if	[[ $x != "$HOME:$HOME" ]]
then	err_exit "x=~:~ failed, expected '$HOME:$HOME', got '$x'"
fi
HOME=/
[[ ~ == / ]] || err_exit '~ should be /'
[[ ~/foo == /foo ]] || err_exit '~/foo should be /foo when ~==/'
print $'print ~+\n[[ $1 ]] && $0' > $tmp/tilde
chmod +x $tmp/tilde
nl=$'\n'
[[ $($tmp/tilde foo) == "$PWD$nl$PWD" ]] 2> /dev/null  || err_exit 'tilde fails inside a script run by name'

exit $((Errors<125?Errors:125))
