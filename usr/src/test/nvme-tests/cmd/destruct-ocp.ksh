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
# Run tests that can wreak havoc on a device with OCP features (e.g.
# error injection, changing the PLP Health window, etc.)
#

#
# Environment sanitization.
#
export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default
unalias -a
set -o pipefail

de_arg0=$(basename $0)
de_rundir="$(dirname $0)/../runfiles"
de_file="destruct-ocp.run"
de_runfile="$de_rundir/$de_file"
de_runner="/opt/test-runner/bin/run"
de_nvmeadm="/usr/sbin/nvmeadm"

function fatal
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$de_arg0: $msg" >&2
        exit 1
}


if (( $# == 0 )); then
	fatal "missing required device name"
fi

if ! $de_nvmeadm list "$1" > /dev/null; then
	fatal "failed to find device $1"
fi

export NVME_TEST_DEVICE=$1
$de_runner -c "$de_runfile"
