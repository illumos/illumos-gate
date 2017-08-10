#!/bin/ksh -p
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
# DESCRIPTION:
#	Writes that zinject makes fail must not trip the allocation
#	throttle's assertions on DEBUG kernels when the failing device is
#	a top-level vdev, and the pool must recover once the injection is
#	cleared.
#
# STRATEGY:
#	1. Turn on the allocation throttle, and create a failmode=wait pool
#	   on one file vdev, so that the leaf vdev is also the top-level
#	   vdev that writes are allocated on.
#	2. Make writes and probes to the vdev fail, dirty some data and
#	   start a txg sync: the writes fail and the pool suspends.
#	3. Clear the injection and run "zpool clear".  The txg sync must
#	   complete and the data must be intact.
#

. $STF_SUITE/include/libtest.shlib

verify_runnable "global"

VDEV=$TEST_BASE_DIR/werr-vdev
SRC=$TEST_BASE_DIR/werr-src
FS=$TESTPOOL/$TESTFS
typeset clear_pid="" sync_pid=""
typeset throttle=""

function cleanup
{
	typeset pid stuck=""

	zinject -c all >/dev/null 2>&1
	if pool_is_suspended; then
		zpool clear $TESTPOOL >/dev/null 2>&1 &
		pid=$!
		if ! wait_for 60 is_done $pid; then
			log_note "zpool clear in cleanup hung"
			stuck=1
		fi
	fi
	for pid in $clear_pid $sync_pid; do
		kill $pid 2>/dev/null
		if ! wait_for 60 is_done $pid; then
			log_note "process $pid did not exit"
			stuck=1
		fi
	done
	if [[ -n $stuck ]] || pool_is_suspended; then
		log_note "not destroying $TESTPOOL"
	else
		poolexists $TESTPOOL && destroy_pool $TESTPOOL
		rm -f $VDEV
	fi
	rm -f $SRC
	[[ -n $throttle ]] && set_tunable32 zio_dva_throttle_enabled $throttle
}

function pool_is_suspended
{
	zpool status $TESTPOOL 2>/dev/null | grep -q -E "ZFS-8000-(HC|JQ)"
}

function is_done # pid
{
	! kill -0 $1 2>/dev/null
}

#
# log_fail prints its message only after the cleanup, which hangs if the txg
# sync is stuck, so log the reason first.
#
function fail
{
	log_note "$*"
	log_fail "$*"
}

function wait_for # seconds command ...
{
	typeset -i tries=$1
	shift
	while ((tries-- > 0)); do
		"$@" && return 0
		sleep 1
	done
	return 1
}

log_assert "Write errors injected on a top-level vdev do not trip the" \
    "allocation throttle"
log_onexit cleanup

# The pool samples the tunable when it is created.
throttle=$(get_tunable zio_dva_throttle_enabled)
log_must set_tunable32 zio_dva_throttle_enabled 1

log_must mkfile $MINVDEVSIZE $VDEV
log_must zpool create -f -o failmode=wait $TESTPOOL $VDEV
log_must zfs create -o compression=off $FS
log_must dd if=/dev/urandom of=$SRC bs=128k count=8
log_must zpool sync $TESTPOOL

#
# Fail every write to the vdev, and its probes, so that the failed writes
# suspend the pool rather than being retried forever.
#
log_must zinject -d $VDEV -e io -T write $TESTPOOL
log_must zinject -d $VDEV -L pad2 $TESTPOOL
log_must cp $SRC /$FS/file
zpool sync $TESTPOOL &
sync_pid=$!
wait_for 60 pool_is_suspended || fail "pool did not suspend"

log_must zinject -c all
zpool clear $TESTPOOL &
clear_pid=$!
wait_for 60 is_done $clear_pid || fail "zpool clear hung"
wait $clear_pid || fail "zpool clear failed"
clear_pid=""
wait_for 60 is_done $sync_pid || fail "txg sync hung"
wait $sync_pid || fail "txg sync failed"
sync_pid=""
pool_is_suspended && fail "pool still suspended"

log_must zpool export $TESTPOOL
log_must zpool import -d $TEST_BASE_DIR $TESTPOOL
log_must cmp $SRC /$FS/file

log_pass "Write errors injected on a top-level vdev do not trip the" \
    "allocation throttle"
