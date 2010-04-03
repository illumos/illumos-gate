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
# This test checks whether arithmetric math correctly
# converts a IEEE 754-2008 floating-point value to the C99 hexfloat format
# and back _without_ using digits.
#
# This was reported as CR #6855875 ("typeset -X x ; print $x # does not
# print sufficient digits to restore value"):
# ------------ snip ------------
# $ typeset -X varname # was added to ksh93 to get a reliable way
# (using the C99 "hexfloat" format (see printf(3c)'s "%a" format)) to
# serialise a IEEE754-2008 floating-point value to a string and later feed
# it back into a application _without_ loosing any precision (normal
# base10 floating-point values (e.g. used by $ typeset -E/-F-G #) cause
# rounding errors since IEEE754-2008 |long double| uses base2).
# However $ typeset -l -X x ; ... ; print $x # currently does not print
# sufficient number of digits to restore the full |long double| value as
# expected, instead some digits are missing, resulting in an unwanted
# rounding.
# Example:
# -- snip --
# $ ksh93 -c 'typeset -l -X y y_ascii; (( y=sin(90) )) ; y_ascii=$y ; (( y
# == y_ascii )) || print "no match,\n\t$(printf "%a\n" y)\n!=\n\t$(printf
# "%a\n" y_ascii)"'
# no match,
#         0x1.c9b9ee41cb8665c7890a136ace6bp-01
# !=
#         0x1.c9b9ee41cc000000000000000000p-01
# -- snip --
# Frequency
#    Always
# Regression
#    No
# Steps to Reproduce
#    [See description]
# Expected Result
#    [See description]
# Actual Result
#    [See description]
# Error Message(s)
#    -
# Test Case
#    typeset -l -X y y_ascii
# (( y=sin(90) ))
# y_ascii=$y # convert y to string and store it in "y_ascii"
# if (( y == y_ascii )) ; then
#     print "no match,\n\t$(printf "%a\n" y)\n!=\n\t$(printf "%a\n"
# y_ascii)"
# fi
# Workaround
#    1. Manually increase the number of digits via typeset
# -X<numdigits>
#     OR
# 2. Use $ printf "%a" varname #
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


# declare variables
typeset		str
integer		i
float		x
float -a	test_values

typeset -l -X	y # hexfloat
typeset -l -E	y_restored1
typeset -l -F	y_restored2
typeset -l -X	y_restored3


# create array of test values
for (( x=-181. ; x < 361. ; x+=.1 )) ; do
	test_values+=( x )
done
test_values+=( 0 -0 +0 ) # (nan -nan inf -inf) are excluded since nan!=nan is always "true"


# run the tests
for (( i=0 ; i < ${#test_values[@]} ; i++ )) ; do
	(( y=sin(test_values[i]) ))

	# convert floating-point value to string (using the hexfloat format) and store it in "str"
	str="${y}"

	# convert it back (via string assignment)
	y_restored1="${str}"
	y_restored2="${str}"
	y_restored3="${str}"
	(( y == y_restored1 )) || err_exit "no match,"$'\n\t'"$(printf "%a\n" y)"$'\n'"!="$'\n\t'"$(printf "%a\n" y_restored1)"
	(( y == y_restored2 )) || err_exit "no match,"$'\n\t'"$(printf "%a\n" y)"$'\n'"!="$'\n\t'"$(printf "%a\n" y_restored2)"
	(( y == y_restored3 )) || err_exit "no match,"$'\n\t'"$(printf "%a\n" y)"$'\n'"!="$'\n\t'"$(printf "%a\n" y_restored3)"

	# convert it back (using arithmetric expression)
	(( y_restored1=str ))
	(( y_restored2=str ))
	(( y_restored3=str ))
	(( y == y_restored1 )) || err_exit "no match,"$'\n\t'"$(printf "%a\n" y)"$'\n'"!="$'\n\t'"$(printf "%a\n" y_restored1)"
	(( y == y_restored2 )) || err_exit "no match,"$'\n\t'"$(printf "%a\n" y)"$'\n'"!="$'\n\t'"$(printf "%a\n" y_restored2)"
	(( y == y_restored3 )) || err_exit "no match,"$'\n\t'"$(printf "%a\n" y)"$'\n'"!="$'\n\t'"$(printf "%a\n" y_restored3)"

	# we exit if we get more than 8 errors (126 would be the maximum)
	(( Errors > 8 )) && exit $((Errors))
done


# tests done
exit $((Errors))
