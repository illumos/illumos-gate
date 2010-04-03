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
# Test whether CR #6754020 ("ksh93 does weird '[' expansion") has
# been fixed.
#
# Quote from CR #6754020: 
# ---- snip ----
# The problem is that subprocess uses /bin/sh as the shell when it
# spins off the process. As Brad demonstrated:
# /bin/sh -c 'echo F[[O]'
# F[[O][
# 
# In short, this bug only appears when run through the test suite,
# or by people  running /bin/sh who don't understand how their shell
# treats special characters.
# -- snip --
# 
# In this case ksh93 has a bug which causes "F[[O]" to be expanded
# in a wrong way.
# ---- snip ----


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


typeset s

# test using "echo"
s="$(${SHELL} -c 'echo F[[O]')"
[[ "$s" == 'F[[O]' ]] || err_exit "Expected 'F[[O]', got $s"

s="$(${SHELL} -c 'echo F[[[O]]')"
[[ "$s" == 'F[[[O]]' ]] || err_exit "Expected 'F[[[O]]', got $s"


# test using "print"
s="$(${SHELL} -c 'print F[[O]')"
[[ "$s" == 'F[[O]' ]] || err_exit "Expected 'F[[O]', got $s"

s="$(${SHELL} -c 'print F[[[O]]')"
[[ "$s" == 'F[[[O]]' ]] || err_exit "Expected 'F[[[O]]', got $s"

 
# tests done
exit $((Errors))
