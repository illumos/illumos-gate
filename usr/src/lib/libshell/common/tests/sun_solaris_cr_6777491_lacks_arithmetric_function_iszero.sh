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
# This test checks whether the arithmetric function "iszero" is available.
#
# This was reported as CR #6777491 ("*ksh93* lacks arithmetric function
# iszero()"):
# ------------ snip ------------
# ksh93 lacks arithmetric function "iszero()" which limits the ability
# to classify floating-point values or even correctly match against
# zero (since IEEE754-1985/2008 floating-point math differs between
# positive and negaive zero values).
# Frequency
#    Always
# Regression
#    No
# Steps to Reproduce
#    $ ksh93 -c '(( iszero(0) )) && print "0 is a zero"'
# Expected Result
#    Output to stdout:
# -- snip --
# 0 is a zero
# -- snip --
# Actual Result
#    ksh93 exists with:
# -- snip --
# ksh93: iszero(0) : unknown function
# -- snip --
# Error Message(s)
#    ksh93: iszero(0) : unknown function
# Test Case
#    ksh93 -c '(( iszero(0) )) && print "0 is a zero"'
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
integer i

typeset -a tests=(
	'(( iszero(0)   )) && print "OK"'
	'(( iszero(0.)  )) && print "OK"'
	'(( iszero(-0)  )) && print "OK"'
	'(( iszero(-0.) )) && print "OK"'
	'float n=0.  ; (( iszero(n) )) && print "OK"'
	'float n=+0. ; (( iszero(n) )) && print "OK"'
	'float n=-0. ; (( iszero(n) )) && print "OK"'
	'float n=1.  ; (( iszero(n) )) || print "OK"'
	'float n=1.  ; (( iszero(n-1.) )) && print "OK"'
	'float n=-1. ; (( iszero(n+1.) )) && print "OK"'
)

for (( i=0 ; i < ${#tests[@]} ; i++ )) ; do
	str="$( $SHELL -o errexit -c "${tests[i]}" 2>&1 )" || err_exit "test $i: returned non-zero exit code $?"
	[[ "${str}" == "OK" ]] || err_exit "test $i: expected 'OK', got '${str}'"
done

# tests done
exit $((Errors))
