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

# tests done
exit $((Errors))
