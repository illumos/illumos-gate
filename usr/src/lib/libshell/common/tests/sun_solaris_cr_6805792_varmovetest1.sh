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
# Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This test checks whether "typeset -m" correctly moves local variables
# into a global variable tree.
#
# This was reported as CR #6805792 ("XXXX"):
# -------- snip --------
# The following attempt to move a local node into an associative array
# fails like this:
# -- snip --
# typeset -C tree
# function f1
# {
#        nameref tr=$1
# 
#        typeset -A tr.subtree
# 
#        typeset -C node
# 
#        node.one="hello"
#        node.two="world"
# 
#        # move local note into the array
#        typeset -m tr.subtree["a_node"]=node
# 
#        return 0
# }
# f1 tree
# printf "%B\n" tree
# print "ok"
# exit 0
# -- snip --
# The output looks like this:
# -- snip --
# $ ksh93
# varmovetest1.sh
# (
# (
# )
# ok
# -- snip --
# ... but AFAIK it should print:
# -- snip --
# (
#        typeset -A subtree=(
#                [a_node]=(
#                        one=hello
#                        two=world
#                )
#        )
# )
# ok
# -- snip --
# -------- snip --------
#

# test setup
function err_exit
{
	print -u2 -n "\t"
	print -u2 -r ${Command}[$1]: "${@:2}"
	(( Errors < 127 && Errors++ ))
}
alias err_exit='err_exit $LINENO'

set -o nounset
Command=${0##*/}
integer Errors=0


## test start
compound tree1 tree2

# add node to tree which uses "typeset -m" to move a local variable
# into tree1.subtree["a_node"]
function f1
{
	nameref tr=$1
	
	typeset -A tr.subtree
	
	compound node
	
	node.one="dummy1"
	node.two="dummy2"
	
	# We use the nameref's here since ast-ksh,2008-12-12 crashes
	# when this function returns because "nodeone" and "nodetwo"
	# still reference "node" which was renamed.
	# (note that "f1" must be first function and the first being
	# called, otherwise the crash will not occur)
	nameref nodeone=node.one
	nameref nodetwo=node.two
	nodeone="hello"
	nodetwo="world"
	
	# move local note into the array
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

[[ "${tree1.subtree["a_node"].one}" == "hello" ]] || err_exit "Expected tree1.subtree[\"a_node\"].one == 'hello', got ${tree1.subtree["a_node"].one}"
[[ "${tree1.subtree["a_node"].two}" == "world" ]] || err_exit "Expected tree1.subtree[\"a_node\"].two == 'world', got ${tree1.subtree["a_node"].two}"
[[ "${tree1}" == "${tree2}" ]] || err_exit "tree1 and tree2 differ:"$'\n'"$(diff -u <( printf '%B\n' tree1 ) <( printf '%B\n' tree2 ) )"


# tests done
exit $((Errors))
