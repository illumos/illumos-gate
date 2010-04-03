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
# This test checks whether ksh93 does not execute builtin command
# "foo" when referencing variable "foo" when the variable is not
# set (this applies to all builtin commands not bound to a
# specific PATH element, e.g. "test", "sleep", "print" etc.).
#
# This was reported as CR #6848486 ('"echo ${test}" with test
# undefined crashes the shell')
# ------------ snip ------------
# This is an odd one:
#
# $ ksh93 --version
#   version         sh (AT&T Research) 93t 2008-11-04
# $ ksh93
# jl138328@gir:~$ echo $test
#
# jl138328@gir:~$ echo ${test}                                                    
# Segmentation Fault (core dumped)
# ------------ snip ------------
#
# The bug originates from the ksh93 "type system" which allows
# an application to define it's own types in ksh93. In such cases
# the output of function "mytype.len" is used when type "mytype"
# has no member variable "len" (note it requires the use of
# ${foo} since the use of $foo does not allow "foo" to contain
# a dot in the variable name).
# The implementation in ast-ksh.2009-11-04 however does this
# for _all_ types of variables and not only for those which
# are a member of an application-defined type, therefore
# causing this bug.
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


# Test 1: Test whether the shell crashes when looking for an empty
# "shell" variable.
# (note: return code 78 was just picked randomly)
$SHELL -c 'unset test ; print ${test} ; exit 78' >/dev/null 2>&1
(( $? == 78 )) || err_exit "expected return code is 78, got $?"


# Test 2: Test whether the shell can reach a point (which prints
# "#mark") after the use of ${test} in the script.
out=$($SHELL -o errexit -c 'unset test ; print ${test} ; print "#mark"' 2>&1 ) || err_exit "Shell returned error code $?, expected 0."
[[ "$out" == $'\n#mark' ]] || err_exit "Expected output \$'\n#mark', got '${out}'"


# Test 3: Check whether the use of ${sleep} returns nothing
# (ast-ksh.2008-11-04 will return the usage string of the sleep
# builtin)
out=$($SHELL -o errexit -c 'print ${sleep} ; print "#mark"' 2>&1 ) || err_exit "Shell returned error code $?, expected 0."
[[ "$out" == $'\n#mark' ]] || err_exit "Expected output \$'\n#mark', got '${out}'"


# tests done
exit $((Errors))
