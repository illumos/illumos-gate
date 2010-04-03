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
# This test checks whether arithmetric operator '<character>
# is working
#
# This was reported as CR #6805794 ('[ku1] printf returns "invalid character constant" for $ printf "%d\n" "'<euro>"'):
# ------------ snip ------------
# There seems be a bug in how ast-ksh.2008-11-04's "printf" builtin
# handles multibyte characters. For example if I try this in the
# en_US.UTF-8 locale ("<euro>" needs to be replace with the EURO symbol):
# -- snip --
# $ printf "%d\n" "'<euro>"
# -ksh93: printf: warning: ': invalid character constant
# 226
# -- snip --
# AFAIK the correct behaviour was to return the numeric value of the
# <euro> symbol in this case (hexadecimal "20ac", decimal 8364), e.g.
# -- snip --
# $ printf "%d\n"
# "'<euro>"
# 8364
# -- snip --
# Frequency
#    Always
# Regression
#    No
# Steps to Reproduce
#    Enter this in an interractive shell:
# $ printf "%d\n" "'<euro>"
# Expected Result
#    -- snip --
# $ printf "%d\n"
# "'<euro>"
# 8364
# -- snip --
# Actual Result
#    -- snip --
# $ printf "%d\n" "'<euro>"
# -ksh93: printf: warning: ': invalid character constant
# 226
# -- snip --
# Error Message(s)
#    printf: warning: ': invalid character constant
# Test Case
#    printf "%d\n" "'<euro>"
# Workaround
#    None.
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
typeset str

# test whether the locale uses an UTF-8 (-like) encoding and override it on demand
[[ "$(printf "\u[20ac]")" == $'\342\202\254' ]] || LC_ALL=en_US.UTF-8
if [[ "$(printf "\u[20ac]")" != $'\342\202\254' ]] ; then
	err_exit "Local overrride failed."
	exit $((Errors))
fi

# run test
str=$(print $'printf "%d\\\\n" "\'\342\202\254"' | source /dev/stdin)
[[ "${str}" == "8364" ]] || err_exit "expected 8364, got ${str}"


# tests done
exit $((Errors))
