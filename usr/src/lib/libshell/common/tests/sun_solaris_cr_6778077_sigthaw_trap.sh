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
# This test checks whether ksh93 supports traps for the SIGTHAW
# signal.
#
# This was reported as CR #6778077 ("*ksh93* does not understand "THAW"
# as a signal for use with trap"):
# -- snip --
# While ksh93 understand THAW in the list of signals for kill it does
# not understand it for "trap'
# 
# : pod5.eu TS 6 $; kill -l | egrep '(THAW|FREEZE)'
# FREEZE
# THAW
# : pod5.eu TS 7 $; trap "echo THAW" THAW
# ksh93: trap: THAW: bad trap
# : pod5.eu TS 8 $;
# 
# Using the signal number (35) works around this.
# -- snip --
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


## test one: Check whether the shell supports SIGTHAW as trap
${SHELL} -o errexit -c 'trap "true" SIGTHAW ; true' || err_exit "SIGTHAW not supported."
${SHELL} -o errexit -c 'trap "true" THAW ; true'    || err_exit "THAW not supported."
${SHELL} -o errexit -c 'trap "true" 35 ; true'      || err_exit "signal 35 not supported."


## test two: Check whether the shell supports SIGFREEZE as trap
## (we check this since it is SIGTHAW's counterpart)
${SHELL} -o errexit -c 'trap "true" SIGFREEZE ; true' || err_exit "SIGFREEZE not supported."
${SHELL} -o errexit -c 'trap "true" FREEZE ; true'    || err_exit "FREEZE not supported."
${SHELL} -o errexit -c 'trap "true" 34 ; true'        || err_exit "signal 34 not supported."


## test three: Check all other signals listed by "kill -l"
kill -l | while read i ; do
	str="$( ${SHELL} -c "trap true $i ; print 'ok'" 2>&1 )" || err_exit "shell returned code $? for trap $i"
	[[ "${str}" == "ok" ]] || err_exit "expected 'ok', got $str"
done


# tests done
exit $((Errors))
