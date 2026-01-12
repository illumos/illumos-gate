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
# Copyright 2026 Oxide Computer Company
#

#
# Run the various I2C tests
#

#
# Standardize the environment and add debugging features.
#
export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default
unalias -a
set -o pipefail

un_arg0=$(basename $0)
un_rundir="$(dirname $0)/../runfiles"
un_file="default.run"
un_runfile="$un_rundir/$un_file"
un_runner="/opt/test-runner/bin/run"

function fatal
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$un_arg0: $msg" >&2
        exit 1
}

[[ -f "$un_runfile" ]] || fatal "could not find runfile $un_runfile"
$un_runner -c "$un_runfile"
