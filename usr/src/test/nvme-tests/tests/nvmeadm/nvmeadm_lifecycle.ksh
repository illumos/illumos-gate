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
# Perform a basic lifecycle tests with the nvmeadm command that shows we can
# go from a non-existent namespace through to something attached to blkdev and
# back down again. Also validate that the various blkdev attach and detach
# commands properly handle the no-op cases.
#
# This command starts from the device-reset empty profile.
#

#
# Set up the environment with a standard locale and debugging tools to help us
# catch failures.
#
export LC_ALL=C.UTF-8
export LD_PRELOAD=libumem.so
export UMEM_DEBUG=default
unalias -a
set -o pipefail

nt_prog=/usr/sbin/nvmeadm
nt_arg0=$(basename $0)
nt_exit=0
nt_fail=0
nt_dev="$NVME_TEST_DEVICE"
nt_ns="$NVME_TEST_DEVICE/1"

function warn
{
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="failed"
	echo "TEST FAILED: $msg" >&2
	nt_exit=1
	((nt_fail++))
}

function fatal
{
        typeset msg="$*"
        [[ -z "$msg" ]] && msg="failed"
        echo "TEST FAILED: $msg" >&2
        exit 1
}

function check_state
{
	typeset targ="$1"
	typeset state=

	state=$($nt_prog list -p -o ns-state $nt_ns)
	if (( $? != 0 )); then
		warn "failed to get $nt_ns state"
		return
	fi

	if [[ "$targ" != "$state" ]]; then
		warn "found $nt_ns in wrong state, expected $targ, but found " \
		    "$state"
	else
		printf "TEST PASSED: %s is correctly in state %s\n" "$nt_ns" \
		    "$state"
	fi
}

function check_detach
{
	typeset state="$1"

	if ! $nt_prog detach $nt_ns >/dev/null; then
		warn "blkdev detach failed with $state ns"
	else
		printf "TEST PASSED: blkdev detach worked with %s ns\n" "$state"
	fi
}

function nvmeadm_fail
{
	if "$nt_prog" $@ 2>/dev/null 1>/dev/null; then
		warn "should have failed with args $@, but passed"
		return;
	fi

	printf "TEST PASSED: program failed: %s\n" "$*"
}

#
# While we have no namespaces attached, detach should work. We should then be
# able to create a namespace.
#
check_state "unallocated"
check_detach "unallocated"
nvmeadm_fail delete-namespace $nt_ns
nvmeadm_fail attach-namespace $nt_ns
nvmeadm_fail detach-namespace $nt_ns
nvmeadm_fail attach $nt_ns

if ! $nt_prog create-namespace -b 4096 $nt_dev 10g > /dev/null; then
	fatal "failed to create namespace"
else
	printf "TEST PASSED: Successfully created namespace\n"
fi

check_state "allocated"
check_detach "allocated"
nvmeadm_fail detach-namespace $nt_ns
nvmeadm_fail attach $nt_ns

if ! $nt_prog attach-namespace $nt_ns > /dev/null; then
	fatal "failed to attach controller to $nt_ns"
else
	printf "TEST PASSED: successfully attached controller to %s\n" "$nt_ns"
fi

check_state "active-usable"
check_detach "active-usable"
nvmeadm_fail delete-namespace $nt_ns
nvmeadm_fail attach-namespace $nt_ns

if ! $nt_prog attach $nt_ns; then
	fatal "failed to attach blkdev to $nt_ns"
else
	printf "TEST PASSED: successfully attached blkdev to %s\n" "$nt_ns"
fi

check_state "blkdev"
nvmeadm_fail delete-namespace $nt_ns
nvmeadm_fail attach-namespace $nt_ns
nvmeadm_fail detach-namespace $nt_ns

#
# nvmeadm attach should work while blkdev is attached.
#
if ! $nt_prog attach $nt_ns; then
	warn "blkdev attach no-op didn't work"
else
	printf "TEST PASSED: blkdev attach was a no-op\n"
fi

check_state "blkdev"
check_detach "blkdev"
check_state "active-usable"

if ! $nt_prog detach-namespace $nt_ns > /dev/null; then
	fatal "failed to detach controller to $nt_ns"
else
	printf "TEST PASSED: successfully detached controller from %s\n" \
	    "$nt_ns"
fi

check_state "allocated"
check_detach "allocated"

if ! $nt_prog delete-namespace $nt_ns > /dev/null; then
	fatal "failed to delete namespace $nt_ns"
else
	printf "TEST PASSED: successfully deleted namespace %s\n" "$nt_ns"
fi

check_state "unallocated"
check_detach "unallocated"

#
# Proceed to test general commands that require a controller or namespace fail
# as we expect as well as other missing arguments.
#
nvmeadm_fail create-namespace
nvmeadm_fail create-namespace $nt_dev 10g
nvmeadm_fail create-namespace -b 4096 -f 2 $nt_dev 10g
nvmeadm_fail create-namespace -b 100 $nt_dev 10g
nvmeadm_fail create-namespace -b 100 $nt_ns 10g
nvmeadm_fail create-namespace -f 3 $nt_ns 10g
nvmeadm_fail create-namespace -f 512 $nt_dev 10g
nvmeadm_fail create-namespace -b 4096 $nt_dev 10gg
nvmeadm_fail create-namespace -b 4096 $nt_dev 10L
nvmeadm_fail create-namespace -b 4096 $nt_dev 10.0B
nvmeadm_fail create-namespace -b 4096 -c nothing $nt_dev 10g
nvmeadm_fail create-namespace -b 4096 -n 32 $nt_dev 10g
nvmeadm_fail create-namespace -b 4096 -n triforce $nt_dev 10g
nvmeadm_fail create-namespace -b 4096 -t commands $nt_dev 10g
nvmeadm_fail delete-namespace
nvmeadm_fail delete-namespace $nt_dev
nvmeadm_fail delete-namespace $nt_ns 12345
nvmeadm_fail attach-namespace
nvmeadm_fail attach-namespace $nt_dev
nvmeadm_fail attach-namespace $nt_ns 12345
nvmeadm_fail detach-namesapce
nvmeadm_fail detach-namesapce $nt_dev
nvmeadm_fail detach-namesapce $nt_ns 12345
nvmeadm_fail format
nvmeadm_fail format $nt_ns 7777
nvmeadm_fail format $nt_ns foobar
nvmeadm_fail format $nt_ns 0 oops
nvmeadm_fail secure-erase
nvmeadm_fail secure-erase $nt_ns foo

if (( nt_exit == 0 )); then
	printf "All tests passed successfully!\n"
else
	printf "%u tests failed!\n" "$nt_fail"
fi

exit $nt_exit
