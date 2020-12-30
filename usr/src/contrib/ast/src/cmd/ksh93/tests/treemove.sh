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
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# This test checks whether "typeset -m" correctly moves local variables
# into a global variable tree.
#
# This was reported as CR #XXXXXXXX ("XXXX"):
# -- snip --
#XXXX
# -- snip --
#

function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors+=1 ))
}

alias err_exit='err_exit $LINENO'

integer Errors=0

## test start
typeset -C tree1 tree2

# add node to tree which uses "typeset -m" to move a local variable
# into tree1.subtree["a_node"]
function f1
{
	nameref tr=$1
	typeset -A tr.subtree
	typeset -C node
	node.one="hello"
	node.two="world"
	# move local note into the array
false
	typeset -m tr.subtree["a_node"]=node
	return 0
}

# Alternative version which uses "nameref" instead of "typeset -m"
function f2
{
	nameref tr=$1
	typeset -A tr.subtree
	nameref node=tr.subtree["a_node"]
	node.one="hello"
	node.two="world"
	return 0
}

f1 tree1
f2 tree2

[[ "${tree1.subtree["a_node"].one}" == "hello" ]] || err_exit "expected tree1.subtree[\"a_node\"].one == 'hello', got ${tree1.subtree["a_node"].one}"
[[ "${tree1.subtree["a_node"].two}" == "world" ]] || err_exit "expected tree1.subtree[\"a_node\"].two == 'world', got ${tree1.subtree["a_node"].two}"
[[ "${tree1}" == "${tree2}" ]] || err_exit "tree1 and tree2 differ:$'\n'"

unset c
compound c
typeset -C -a c.ar
c.ar[4]=( a4=1 )
typeset -m "c.ar[5]=c.ar[4]"
exp=$'(\n\ttypeset -C -a ar=(\n\t\t[5]=(\n\t\t\ta4=1\n\t\t)\n\t)\n)'
[[ $(print -v c) == "$exp" ]] || err_exit 'typeset -m "c.ar[5]=c.ar[4]" not working'

typeset -T x_t=( hello=world )
function m
{
	compound c
	compound -a c.x
	x_t c.x[4][5][8].field
	x_t x
	typeset -m c.x[4][6][9].field=x
	exp=$'(\n\ttypeset -C -a x=(\n\t\t[4]=(\n\t\t\t[5]=(\n\t\t\t\t[8]=(\n\t\t\t\t\tx_t field=(\n\t\t\t\t\t\thello=world\n\t\t\t\t\t)\n\t\t\t\t)\n\t\t\t)\n\t\t\t[6]=(\n\t\t\t\t[9]=(\n\t\t\t\t\tx_t field=(\n\t\t\t\t\t\thello=world\n\t\t\t\t\t)\n\t\t\t\t)\n\t\t\t)\n\t\t)\n\t)\n)'
	[[ $(print -v c) == "$exp" ]] || err_exit "typeset -m c.x[4][6][9].field=x where x is a type is not working"
}
m

function moveme
{
	nameref src=$2 dest=$1
	typeset -m dest=src
}
function main
{
	compound a=( aa=1 )
	compound -a ar
	moveme ar[4] a 2> /dev/null || err_exit 'function moveme fails'
	exp=$'(\n\t[4]=(\n\t\taa=1\n\t)\n)'
	[[ $(print -v ar) == "$exp" ]] || err_exit 'typeset -m dest=src where dest and src are name references fails'
}
main


{
$SHELL <<- \EOF
	function main
	{
		compound c=(
			compound -a board
		)
		for ((i=0 ; i < 2 ; i++ )) ; do
			compound el=(typeset id='pawn')
			typeset -m "c.board[1][i]=el"
		done
		exp=$'(\n\ttypeset -C -a board=(\n\t\t[1]=(\n\t\t\t(\n\t\t\t\tid=pawn\n\t\t\t)\n\t\t\t(\n\t\t\t\tid=pawn\n\t\t\t)\n\t\t)\n\t)\n)'
		[[ $(print -v c) == "$exp" ]] || exit 1
	}
	main
EOF
} 2> /dev/null
if	((exitval=$?))
then	if	[[ $(kill -l $exitval) == SEGV ]]
	then	err_exit 'typeset -m "c.board[1][i]=el" core dumps'
	else	err_exit 'typeset -m "c.board[1][i]=el" gives wrong value'
	fi
fi
exit $((Errors<125?Errors:125))
