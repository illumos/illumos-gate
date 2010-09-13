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
# This test checks whether arithmetric math correctly supports
# negative zero values
#
# This was reported as CR #6805795 ("[ku1] ksh93 does not differ between -0 and +0"):
# ------------ snip ------------
#  Original bug report was:
# ------ snip ------
# Is there a reason why ksh93 does not display the negative sign for the
# value zero ? For example if I have use the C99 function "copysign"
# (copies absolute value of operant a and sign of operant b) I get this
# for { a=5, b=-0 }:
# -- snip --
# $ ksh93 -c 'float x; (( x=copysign(5, -0) )) ; printf "%f\n"
# x'
# -5.000000
# -- snip --
# Now if I swap operands a and b I get this result:
# -- snip --
# $ ksh93 -c 'float x; (( x=copysign(0, -5) )) ; printf "%f\n" x'
# 0.000000
# -- snip --
# AFAIK this result should be "-0.000000" ... or not ?
# BTW: Parsing of "-0" doesn't seem to work either, e.g.
# -- snip --
# $ ksh93 -c 'float x a=-1 b=-0; (( x=copysign(a, b) )) ; printf "%f\n"
# x'
# 1.000000
# -- snip --
# ... while AFAIK it should be "-1.000000" since the 2nd operand of
# "copysign" defines the sign of the result.
# ------ snip ------
# ------------ snip ------------
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

typeset str

# test 1: test "copysign()" using constant values
str=$(
	set -o errexit

	print -- $(( copysign(0, -5) ))
	) || err_exit "test failed."
[[ "${str}" == "-0" ]] || err_exit "Expected copysign(0, -5) == -0, got ${str}"


# test 2: Same as test 1 but using variables for the values
str=$(
	set -o errexit

	float a
	float b
	float c
	
	a=0.
	b=-5.
	
	(( c=copysign(a, b) ))

	print -- "$c"
	) || err_exit "test failed."
[[ "${str}" == "-0" ]] || err_exit "Expected c == -0, got ${str}"


# test 3: test "signbit()"
str=$(
	set -o errexit
	
	float a
	
	a=-0.
	
	print -- $(( signbit(a) ))
	) || err_exit "test failed."
[[ "${str}" == "1" ]] || err_exit "Expected signbit(a, b) == 1, got ${str}"


# test 4: test "signbit()"
str=$(
	set -o errexit
	
	float a
	float c
	
	a=-0.
	
	(( c=signbit(a) ))

	print -- "$c"
	) || err_exit "test failed."
[[ "${str}" == "1" ]] || err_exit "Expected c == 1, got ${str}"


# test 5: test whether "typeset -X" (C99 "hexfloat") correctly recognizes
# negative zero assigned from a "float"
str=$(
	set -o errexit
	
	float a      # float
	typeset -X c # hexfloat
	
	a=-0.
	
	# copy value from "float" to "hexfloat"
	(( c=a ))
	
	print -- "$c"
	) || err_exit "test failed."
[[ "${str}" == -0x* ]] || err_exit "Expected c == -0x*, got ${str}"


# test 6: Reverse of test 5: Test whether "float" correctly recognizes
# a C99 "hexfloat" value
str=$(
	set -o errexit
	
	typeset -X a # hexfloat
	float c      # float
	
	a=-0x0.0000000000000000000000000000p+00
	
	# copy value from "hexfloat" to "float"
	(( c=a ))
	
	print -- "$c"
	) || err_exit "test failed."
[[ "${str}" == "-0" ]] || err_exit "Expected c == -0, got ${str}"


# tests done
exit $((Errors))
