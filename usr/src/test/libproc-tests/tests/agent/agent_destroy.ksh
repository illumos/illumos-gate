#!/usr/bin/ksh
#
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2026 Oxide Computer Company
#

#
# This runs the agent_destroy tests against targets of each data model.
#

unalias -a
set -o pipefail

at_arg0=$(basename $0)
at_dir=$(dirname $0)
at_prog32="$at_dir/agent_destroy.32"
at_prog64="$at_dir/agent_destroy.64"
at_targ32="$at_dir/agent_target.32"
at_targ64="$at_dir/agent_target.64"
at_exit=0

printf "Running 32-bit controller against 32-bit target\n"
if ! $at_prog32 $at_targ32; then
	at_exit=1
fi

printf "\nRunning 64-bit controller against 32-bit target\n"
if ! $at_prog64 $at_targ32; then
	at_exit=1
fi

printf "\nRunning 64-bit controller against 64-bit target\n"
if ! $at_prog64 $at_targ64; then
	at_exit=1
fi

if (( at_exit == 0 )); then
	printf "All variants passed successfully\n"
fi

exit $at_exit
