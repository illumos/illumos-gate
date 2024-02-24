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
# Validate that the NVMe device in question is usable for these tests.
# What we care about is that namespace one is present.
#
export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default
unalias -a
set -o pipefail

nd_arg0=$(basename $0)
nd_rundir="$(dirname $0)/../runfiles"
nd_file="non-destruct.run"
nd_runfile="$nd_rundir/$nd_file"
nd_runner="/opt/test-runner/bin/run"
nd_nvmeadm="/usr/sbin/nvmeadm"
nd_device=

function fatal
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "$nd_arg0: $msg" >&2
        exit 1

}

#
# Check that the supplied device is an NVMe device that the system knows
# about and that it has basic features that we can use.
#
function check_device
{
	typeset nn

	if ! $nd_nvmeadm list "$nd_device" >/dev/null; then
		fatal "failed to find device $nd_device"
	fi

	if ! $nd_nvmeadm list "$nd_device/1" >/dev/null; then
		fatal "failed to find namespace 1 on $nd_device"
	fi
}

#
# Export the basic environment variables that the test programs expect
# to identify what to operate on.
#
function setup_env
{
	export NVME_TEST_DEVICE=$nd_device
}

function run_tests
{
	$nd_runner -c "$nd_runfile"
}

if (( $# == 0 )); then
	fatal "missing required device name"
fi

nd_device="$1"

check_device
setup_env
run_tests
