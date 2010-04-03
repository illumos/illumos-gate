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
# This test checks whether a background process called in a subshell can
# cause it to wait for the child process instead of exiting.
#
# This was reported as CR #6881017 ("Subshell doesn't exit, holds pipe
# open preventing callers from exiting"):
# ------------ snip ------------
# The following scenario hangs with snv_122, 100% reproducible:
# 
# Create a script hangit:
# -----
# #!/bin/ksh
# ( sleep 100000 </dev/null >/dev/null 2>&1 & )
# exit 0
# -----
# 
# Run the following command:
# hangit | tee -a /tmp/log
# 
# The hang can be eliminated either by removing the "exit 0" line (?!?), or by
# redirecting the subshell output to /dev/null.
# 
# This is pretty nasty. I've whittled it down to this simple case but am seeing
# it in a much more subtle and complex environment where there are several
# intermediate calling scripts which have exited and eventually the parent pipes
# the output and hangs on the open pipe. It was hard to track down.
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

float tstart tstop tdiff

# run test with 10 second timeout
(( tstart=SECONDS ))
$SHELL -c '( sleep 10 </dev/null >/dev/null 2>&1 & ) ; exit 0' | cat >/dev/null
(( tstop=SECONDS ))

# we remove two seconds below to make sure we don't run into issues
# with smaller xntpd adjustments
(( tdiff=tstop-tstart ))
(( tdiff < (10.-2.) )) || err_exit "test run needed ${tdiff} seconds to complete (instead of < 8.)"

# tests done
exit $((Errors))
