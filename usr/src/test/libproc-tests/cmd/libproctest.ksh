#!/usr/bin/ksh

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
# Copyright 2024 Oxide Computer Company
#

#
# Run the libproc test suite
#

#
# Standardize the environment and add debugging features.
#
export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default
unalias -a
set -o pipefail

proc_arg0=$(basename $0)
proc_rundir="$(dirname $0)/../runfiles"
proc_file="default.run"
proc_runfile="$proc_rundir/$proc_file"
proc_runner="/opt/test-runner/bin/run"

function fatal
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$proc_arg0: $msg" >&2
        exit 1
}


[[ -f "$proc_runfile" ]] || fatal "could not find runfile $proc_runfile"
$proc_runner -c "$proc_runfile"
