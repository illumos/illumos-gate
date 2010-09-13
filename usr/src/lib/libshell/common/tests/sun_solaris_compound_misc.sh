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
# Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
#

#
# This test module contains misc compound tests which do not have
# their own module yet.
#
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

# global utility functions
compound bracketstat=(
	integer bopen=0
	integer bclose=0
)

function count_brackets
{
	typeset x="$1"
	typeset c

	integer i
	(( bracketstat.bopen=0 , bracketstat.bclose=0 ))

	for (( i=0 ; i < ${#x} ; i++ )) ; do
	        c="${x:i:1}"
		[[ "$c" == "(" ]] && (( bracketstat.bopen++ ))
		[[ "$c" == ")" ]] && (( bracketstat.bclose++ ))
	done
	
	(( bracketstat.bopen != bracketstat.bclose )) && return 1
	
	return 0
}


typeset ocwd
typeset tmpdir

# create temporary test directory
ocwd="$PWD"
tmpdir="$(mktemp -t -d "test_sun_solaris_compound_misc.XXXXXXXX")" || err_exit "Cannot create temporary directory"

cd "${tmpdir}" || { err_exit "cd ${tmpdir} failed." ; exit $((Errors)) ; }

# ksh93 <= ast-ksh.2010-03-09 prints garbage for compound x=( compound -a nodes=( [4]=( ) ) );typeset -p x
function test_compound_indexed_array_init_1
{
	compound vx=( compound -a nodes=( [4]=( ) )  )
	compound vy
	compound -a vy.nodes=( [4]=( ) )
	compound vz
	compound -a vz.nodes
	vz.nodes[4]=( )

	cx="$(typeset -p vx)" ; cx="${cx//vx/tt}"
	cy="$(typeset -p vy)" ; cy="${cy//vy/tt}"
	cz="$(typeset -p vz)" ; cz="${cz//vz/tt}"
	[[ "$cx" == "$cy" ]] || err_exit "'$cx' != '$cy'"
	[[ "$cx" == "$cz" ]] || err_exit "'$cx' != '$cz'"
	[[ "$cy" == "$cz" ]] || err_exit "'$cy' != '$cz'"

	count_brackets "$cx" || err_exit "Brackets not balanced for '$cx'"
	count_brackets "$cy" || err_exit "Brackets not balanced for '$cy'"
	count_brackets "$cz" || err_exit "Brackets not balanced for '$cz'"
	count_brackets "$(print -v vx)" || err_exit "Brackets not balanced for '$(print -v vx)'"
	count_brackets "$(print -v vy)" || err_exit "Brackets not balanced for '$(print -v vy)'"
	count_brackets "$(print -v vz)" || err_exit "Brackets not balanced for '$(print -v vz)'"
	count_brackets "$(print -C vx)" || err_exit "Brackets not balanced for '$(print -C vx)'"
	count_brackets "$(print -C vy)" || err_exit "Brackets not balanced for '$(print -C vy)'"
	count_brackets "$(print -C vz)" || err_exit "Brackets not balanced for '$(print -C vz)'"

	cx="$(typeset +p vx.nodes)" ;    [[ "$cx" == *-C* && "$cx" == *-a* ]] || err_exit "'$cx' lacks -C/-a attribute"
	cy="$(typeset +p vy.nodes)" ;    [[ "$cy" == *-C* && "$cy" == *-a* ]] || err_exit "'$cy' lacks -C/-a attribute"
	cz="$(typeset +p vz.nodes)" ;    [[ "$cz" == *-C* && "$cz" == *-a* ]] || err_exit "'$cz' lacks -C/-a attribute"
	cx="$(typeset +p vx.nodes[4])" ; [[ "$cx" == *-C*                  ]] || err_exit "'$cx' lacks -C attribute"
	cy="$(typeset +p vy.nodes[4])" ; [[ "$cy" == *-C*                  ]] || err_exit "'$cy' lacks -C attribute"
	cz="$(typeset +p vz.nodes[4])" ; [[ "$cz" == *-C*                  ]] || err_exit "'$cz' lacks -C attribute"

	return 0
}

# ksh93 <= ast-ksh.2010-03-09 prints garbage for compound x=( compound -a nodes=( [4]=( ) ) );typeset -p x
# this test is the same as test_compound_indexed_array_init_1 but "-a" was replaced with "-A"
function test_compound_associative_array_init_1
{
	compound vx=( compound -A nodes=( [4]=( ) )  )
	compound vy
	compound -A vy.nodes=( [4]=( ) )
	compound vz
	compound -A vz.nodes
	vz.nodes[4]=( )

	cx="$(typeset -p vx)" ; cx="${cx//vx/tt}"
	cy="$(typeset -p vy)" ; cy="${cy//vy/tt}"
	cz="$(typeset -p vz)" ; cz="${cz//vz/tt}"
	[[ "$cx" == "$cy" ]] || err_exit "'$cx' != '$cy'"
	[[ "$cx" == "$cz" ]] || err_exit "'$cx' != '$cz'"
	[[ "$cy" == "$cz" ]] || err_exit "'$cy' != '$cz'"

	count_brackets "$cx" || err_exit "Brackets not balanced for '$cx'"
	count_brackets "$cy" || err_exit "Brackets not balanced for '$cy'"
	count_brackets "$cz" || err_exit "Brackets not balanced for '$cz'"
	count_brackets "$(print -v vx)" || err_exit "Brackets not balanced for '$(print -v vx)'"
	count_brackets "$(print -v vy)" || err_exit "Brackets not balanced for '$(print -v vy)'"
	count_brackets "$(print -v vz)" || err_exit "Brackets not balanced for '$(print -v vz)'"
	count_brackets "$(print -C vx)" || err_exit "Brackets not balanced for '$(print -C vx)'"
	count_brackets "$(print -C vy)" || err_exit "Brackets not balanced for '$(print -C vy)'"
	count_brackets "$(print -C vz)" || err_exit "Brackets not balanced for '$(print -C vz)'"

	cx="$(typeset +p vx.nodes)" ;    [[ "$cx" == *-C* && "$cx" == *-A* ]] || err_exit "'$cx' lacks -C/-A attribute"
	cy="$(typeset +p vy.nodes)" ;    [[ "$cy" == *-C* && "$cy" == *-A* ]] || err_exit "'$cy' lacks -C/-A attribute"
	cz="$(typeset +p vz.nodes)" ;    [[ "$cz" == *-C* && "$cz" == *-A* ]] || err_exit "'$cz' lacks -C/-A attribute"
	cx="$(typeset +p vx.nodes[4])" ; [[ "$cx" == *-C*                  ]] || err_exit "'$cx' lacks -C attribute"
	cy="$(typeset +p vy.nodes[4])" ; [[ "$cy" == *-C*                  ]] || err_exit "'$cy' lacks -C attribute"
	cz="$(typeset +p vz.nodes[4])" ; [[ "$cz" == *-C*                  ]] || err_exit "'$cz' lacks -C attribute"

	return 0
}

# run tests
test_compound_indexed_array_init_1
test_compound_associative_array_init_1

cd "${ocwd}"
rmdir "${tmpdir}" || err_exit "Cannot remove temporary directory ${tmpdir}".

# tests done
exit $((Errors))
