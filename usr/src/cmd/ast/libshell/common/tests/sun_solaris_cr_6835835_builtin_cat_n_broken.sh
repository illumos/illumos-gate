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
# This test checks whether ksh93's builtin "cat" command properly
# supports the "-n" option.
#
# This was reported as CR #6835835 ('ksh93 "cat" builtin does not handle "-n" correctly'):
# ------------ snip ------------
# [Originally reported in
# http://mail.opensolaris.org/pipermail/ksh93-integration-discuss/2009-February/007050.html
# by Casper Dik]
# -- snip --
# I just noticed this in ksh93:
#  ksh93 -c 'yes "" | head -5|cat -n'
#     1
#     2
#     3
#     4
# (I used this for older shells when I want to a list of all integers from 1
# to a particular number)
# -- snip --
# Frequency
#   Always
# Regression
#   No
# Steps to Reproduce
#   Execute $ ksh93 -c 'yes "" | head -5|cat -n' #
# Expected Result
#     1
#     2
#     3
#     4
#     5
# Actual Result
#
#
#     1
#     2
#
#     3
#
#     4
# Error Message(s)
#   None.
# Test Case
#   See description.
# Workaround
#   Disable ksh93's builtin "cat" command either via using an absolute path
#   to the "cat" command (POSIX-style workaround) or using ksh93's
#   "builtin" command to remove "cat" from the list of builtin
#   commands (e.g. $ builtin -d /bin/cat /usr/bin/cat #).
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

#
# test 1: Compare output of various "cat -n" combinations
#
integer i
typeset expected_output
typeset out

expected_output=$( ${SHELL} -c 'for ((i=1 ; i <= 12 ; i++ )) ; do printf "%6d\t\n" i ; done' )

compound -a testcases=(
	# note: we have to add an extra /usr/bin/cat at the end of the pipe to make
	# sure the "cat" builtin uses the correct buffering mode to trigger
	# the error and a "true" to make sure the "cat" command isn't the last command
	# of the shell
	( name="test1a" cmd='integer i ; builtin cat ; for ((i=1 ; i <= 12 ; i++ )) ; do print ; done | cat -n          | /usr/bin/cat ; true' )
	# same as "test1a" but uses external "cat" command
	( name="test1b" cmd='integer i ;               for ((i=1 ; i <= 12 ; i++ )) ; do print ; done | /usr/bin/cat -n | /usr/bin/cat ; true' )

	# same as "test1a" but without the last /usr/bin/cat in the pipe
	( name="test1c" cmd='integer i ; builtin cat ; for ((i=1 ; i <= 12 ; i++ )) ; do print ; done | cat -n ; true' )
	# same as "test1b" but without the last /usr/bin/cat in the pipe
	( name="test1d" cmd='integer i ;               for ((i=1 ; i <= 12 ; i++ )) ; do print ; done | /usr/bin/cat -n ; true' )
)

for testid in "${!testcases[@]}" ; do
	nameref tc=testcases[${testid}]

	out="$( ${SHELL} -o errexit -c "${tc.cmd}" )" || err_exit "${tc.name}: Shell failed"
	[[ "${expected_output}" == "${out}" ]] || err_exit "${tc.name}: Builtin output does not match expected output"

	out="$( ${SHELL} +o errexit -c "${tc.cmd}" )" || err_exit "${tc.name}: Shell failed"
	[[ "${expected_output}" == "${out}" ]] || err_exit "${tc.name}: Builtin output does not match expected output"
done


#
# test 2: Casper Dik's original testcase
# from http://mail.opensolaris.org/pipermail/ksh93-integration-discuss/2009-February/007050.html
#

cmp -s \
	<( ${SHELL} -c 'yes "" | head -5 | cat -n' ) \
	<( for ((i=1 ; i <= 5 ; i++ )) ; do printf "%6d\t\n" i ; done ) \
	|| err_exit 'yes "" | head -5 | cat -n does not match expected output.'


# tests done
exit $((Errors))
