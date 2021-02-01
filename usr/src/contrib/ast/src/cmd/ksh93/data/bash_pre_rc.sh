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
#
# bash compatibility startup script
#
# Author:
# Karsten Fleischer
# Omnium Software Engineering
# An der Luisenburg 7
# D-51379 Leverkusen
# Germany
#
# <K.Fleischer@omnium.de>
#

alias declare=typeset

nameref FUNCNAME=.sh.fun
integer SHLVL
export SHLVL
SHLVL+=1

if	[[ ! $EUID ]]
then	EUID=$(id -u)
	readonly EUID
fi

if	[[ ! $UID ]]
then	UID=$(id -u)
	readonly UID
fi

readonly SHELLOPTS
if ! shopt -qo restricted; then
	IFS=:
	for i in $SHELLOPTS
	do
		[[ -n "$i" ]] && set -o $i
	done
	unset IFS
fi
function SHELLOPTS.get
{
	.sh.value=$(shopt -so)
	.sh.value=${.sh.value//+([[:space:]])on*([[:space:]])/:}
	.sh.value=${.sh.value%:}
}

set -A GROUPS $(id -G)
function GROUPS.set
{
	return 1
}
function GROUPS.unset
{
	unset -f GROUPS.set
	unset -f GROUPS.unset
}

typeset -A DIRSTACK
function DIRSTACK.get
{
	set -A .sh.value $(dirs)
}
function DIRSTACK.set
{
	integer index
	index=_push_max-.sh.subscript
	(( index == _push_max || index < _push_top )) && return
	_push_stack[index]=${.sh.value}
}
function DIRSTACK.unset
{
	unset -f DIRSTACK.get
	unset -f DIRSTACK.set
	unset -f DIRSTACK.unset
}

function PS1.set 
{
	typeset prefix remaining=${.sh.value} var= n= k=
	while	[[ $remaining ]]
	do	prefix=${remaining%%'\'*}
		remaining=${remaining#$prefix}
		var+="$prefix"
		case ${remaining:1:1} in
		t)	var+="\$(printf '%(%H:%M:%S)T')";;
		d)	var+="\$(printf '%(%a %b:%e)T')";;
		n)	var+=$'\n';;
		s)	var+=ksh;;
		w)	var+="\$(pwd)";;
		W)	var+="\$(basename \"\$(pwd)\")";;
		u)	var+=$USER;;
		h)	var+=$(hostname -s);;
		'#')	var+=!;;
		!)	var+=!;;
		@)	var+="\$(printf '%(%I:%M%p)T')";;
		'$')	if	(( $(id -u) == 0 ))
			then	var+='#'
			else	var+='$'
			fi;;
		'\')	var+='\\';;
		'['|']')	;;
		[0-7])	case ${remaining:1:3} in
			[0-7][0-7][0-7])
				k=4;;
			[0-7][0-7])
				k=3;;
			*)	k=2;;
			esac
			eval n="\$'"${remaining:0:k}"'"
			var+=$n
			remaining=${remaining:k}
			continue
			;;
		"")	;;
		*)	var+='\'${remaining:0:2};;
		esac
		remaining=${remaining:2}
	done
	.sh.value=$var
}
function logout
{
	if shopt -q login_shell; then
		exit
	else
		print ${BASH##*/}: $0: not login shell: use 'exit' >&2
		return 1
	fi
}
PS1="bash$ "

function source
{
	if ! shopt -qpo posix; then
		unset	OPATH
		typeset OPATH=$PATH
		typeset PATH=$PATH
		if shopt -q sourcepath; then
			PATH=$OPATH:.
		else
			PATH=.
		fi
	fi
	. "$@"
}
unalias .
alias .=source

alias enable=builtin

function help
{
	typeset b cmd usage try_cmd man
	function has_help_option
	{
		[[ $1 == @(''|/*|:|echo|false|true|login|test|'[') ]] && return 1
		return 0
	}
	typeset -A short_use=(
		[echo]='Usage: echo [ options ] [arg]...'
		[:]='Usage: : ...'
		[true]='Usage: true ...'
		[false]='Usage: false ...'
		[login]='Usage: login [-p] [name]'
		['[']='Usage: [ EXPRESSION ] | [ OPTION'
		[test]='Usage: test EXPRESSION | test'
	)
	b=$(builtin)
	if	(( $# == 0))
	then	print 'The following is the current list of built-in commands:'
		print -r $'Type help *name* for more information about name\n'
		for cmd in $b
		do	if	has_help_option $cmd
			then	usage=$($cmd --short 2>&1)
				print -r -- "${usage:7}"
			else	print -r -- ${short_use[$cmd]:7}
			fi
		done
		return
	fi
	b=${b/'['/}
	man=--man
	[[ $1 == -s ]] && man=--short && shift
	for try_cmd
	do	if	has_help_option $try_cmd
		then	if	[[ $try_cmd == @(${b//$'\n'/'|'}) ]]
			then	$try_cmd $man
			else	man $try_cmd
			fi
		elif	[[ $man == '--short' ]]
		then	print -r -- ${short_use[$try_cmd]}
		else	man $try_cmd
		fi
	done
}

function cd
{

	local msg
	local args
	local i
	local a
	local ret

	if ! shopt -q cdable_vars; then
		command cd "$@"
	else
		msg=$(command cd "$@" 2>&1)
		ret=$?
		if [[ $ret != 0 ]]; then
			for i
			do
				case $i in
				-*)	args="$args $i" ;;
				*/*)	args="$args $i" ;;
				*)	eval a="$"$i
					if [[ -n $a ]]; then args="$args $a"
					else args="$args $i"
					fi
					;;
				esac
			done

			command cd $args
		else
			print -- $msg
			return $ret
		fi
	fi
}

typeset BASH=$0
! shopt -qo posix && HISTFILE=~/.bash_history
HOSTNAME=$(hostname)
nameref BASH_SUBSHELL=.sh.subshell
