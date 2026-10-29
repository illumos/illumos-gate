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
	if is_pool_suspended $TESTPOOL; then
		zpool clear $TESTPOOL >/dev/null 2>&1 &
		pid=$!
		if ! wait_for 60 is_process_exited $pid; then
			log_note "zpool clear in cleanup hung"
			stuck=1
		fi
	fi
	for pid in $clear_pid $sync_pid; do
		kill $pid 2>/dev/null
		if ! wait_for 60 is_process_exited $pid; then
			log_note "process $pid did not exit"
			stuck=1
		fi
	done
	if [[ -n $stuck ]] || is_pool_suspended $TESTPOOL; then
		log_note "not destroying $TESTPOOL"
	else
		poolexists $TESTPOOL && destroy_pool $TESTPOOL
		rm -f $VDEV
	fi
	rm -f $SRC
	[[ -n $throttle ]] && set_tunable32 zio_dva_throttle_enabled $throttle
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
wait_for 60 is_pool_suspended $TESTPOOL || log_fail "pool did not suspend"

log_must zinject -c all
zpool clear $TESTPOOL &
clear_pid=$!
wait_for 60 is_process_exited $clear_pid || log_fail "zpool clear hung"
wait $clear_pid || log_fail "zpool clear failed"
clear_pid=""
wait_for 60 is_process_exited $sync_pid || log_fail "txg sync hung"
wait $sync_pid || log_fail "txg sync failed"
sync_pid=""
is_pool_suspended $TESTPOOL && log_fail "pool still suspended"

log_must zpool export $TESTPOOL
log_must zpool import -d $TEST_BASE_DIR $TESTPOOL
log_must cmp $SRC /$FS/file

log_pass "Write errors injected on a top-level vdev do not trip the" \
    "allocation throttle"
