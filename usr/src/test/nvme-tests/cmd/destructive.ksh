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
# Copyright 2025 Oxide Computer Company
#
#

#
# Run destructive user tests after verification that the device is
# usable.
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
de_root="$(dirname $0)/.."
de_rundir="$de_root/runfiles"
de_file="destruct.run"
de_runfile="$de_rundir/$de_file"
de_runner="/opt/test-runner/bin/run"
de_check="$de_root/tests/libnvme/check-destruct.64"


if (( $# == 0 )); then
	fatal "missing required device name"
fi

export NVME_TEST_DEVICE=$1
if ! $de_check; then
	exit 1
fi

$de_runner -c "$de_runfile"
