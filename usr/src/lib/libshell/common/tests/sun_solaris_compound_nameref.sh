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
# Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
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

#
# name reference test #001
# Note we run this test in a seperate shell to make sure the memory
# corruption originally reported can be reproduced (which precisely
# depends on ordering in the testcase)
(
cat <<EOF
	function err_exit
	{
		print -u2 -n "\t"
		print -u2 -r \${Command}[\$1]: "\${@:2}"
		(( Errors++ ))
	}
	alias err_exit='err_exit \$LINENO'

	function function2
	{
		nameref v=\$1

		v.x=19
		v.y=20
	}

	function function1
	{
		typeset compound_var=()

		function2 compound_var

		printf "x=%d, y=%d\n" compound_var.x compound_var.y 
	}

	x="\$(function1)"

	[[ "\$x" == 'x=19, y=20' ]] || err_exit "expected 'x=19, y=20', got '\${x}'"

EOF
) | ${SHELL}
(( Errors+=$? ))


#
# name reference test #002
# Originally derived from the xmldocumenttree1.sh demo which failed
# with ast-ksh.2009-04-15 since the nodepath+nodesnum nameref calls
# were removing the compound variable members nodes+nodesnum (caused
# by a scoping bug)
#
(
cat <<EOF
	compound xdoc
	compound -A xdoc.nodes
	integer xdoc.nodesnum=0

	function test1
	{
        	nameref doc=xdoc
        	nameref nodepath="doc.nodes"
        	nameref nodesnum="doc.nodesnum"
        	print -v doc
	}

	test1
EOF
) | out=$( ${SHELL} ) || err_exit "shell returned exit code $?"

(( ${ wc -l <<<"${out}" ; } == 4 )) || err_exit "Expected four lines of output, got ${out}"
(set -o errexit ; read -C tmp <<<"${out}" ; [[ "$(typeset +p tmp.nodes)" == *-A* ]]) || err_exit "missing variable tmp.nodes"
(set -o errexit ; read -C tmp <<<"${out}" ; [[ -v tmp.nodesnum                   ]]) || err_exit "missing variable tmp.nodesnum"


#
# name reference test #003a
# ast-ksh.2009-06-30 failed with the following compound variable/nameref test
#
(
cat <<EOF
	compound -A addrsp

	nameref sp=addrsp
        
	sp[14]=( size=1 )
        
	if [[ -v sp[19] ]] ; then
        	print "should not happen"
	else
        	print "Ok"
	fi
EOF
) | out=$( ${SHELL} ) || err_exit "shell returned exit code $?"
[[ "${out}" == "Ok" ]] || err_exit "Expected 'Ok', got ${out}"


#
# name reference test #003b
# (same as test #003a but uses a function)
# ast-ksh.2009-06-30 failed with the following compound variable/nameref test
#
(
cat <<EOF
	compound -A addrsp
	
	function t1
	{
		nameref sp=\$1
        
		sp[14]=( size=1 )
        
		if [[ -v sp[19] ]] ; then
        		print "should not happen"
		else
        		print "Ok"
		fi
	}

	t1 addrsp
EOF
) | out=$( ${SHELL} ) || err_exit "shell returned exit code $?"
[[ "${out}" == "Ok" ]] || err_exit "Expected 'Ok', got ${out}"


#
# name reference test #004a
# (same as #003a but uses an indexed array instead of an associative one)
# ast-ksh.2009-06-30 failed with the following compound variable/nameref test
#
(
cat <<EOF
	compound -a addrsp

	nameref sp=addrsp
        
	sp[14]=( size=1 )
        
	if [[ -v sp[19] ]] ; then
        	print "should not happen"
	else
        	print "Ok"
	fi
EOF
) | out=$( ${SHELL} ) || err_exit "shell returned exit code $?"
[[ "${out}" == "Ok" ]] || err_exit "Expected 'Ok', got ${out}"


#
# name reference test #004b
# (same as test #004a but uses a function)
# ast-ksh.2009-06-30 failed with the following compound variable/nameref test
#
(
cat <<EOF
	compound -a addrsp
	
	function t1
	{
		nameref sp=\$1
        
		sp[14]=( size=1 )
        
		if [[ -v sp[19] ]] ; then
        		print "should not happen"
		else
        		print "Ok"
		fi
	}

	t1 addrsp
EOF
) | out=$( ${SHELL} ) || err_exit "shell returned exit code $?"
[[ "${out}" == "Ok" ]] || err_exit "Expected 'Ok', got ${out}"


# tests done
exit $((Errors))
