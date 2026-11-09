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

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#	Detaching the original device of an in-use hot spare completes
#	while the pool is at its dirty data limit.  The detach writes a
#	history record for the spare it removes; that must not wait for
#	a txg sync while it holds the config lock, which the sync needs.
#
# STRATEGY:
#	1. Create a pool with one device and a hot spare, and replace the
#	   device with the spare
#	2. Lower zfs_dirty_data_max, turn off the write throttle's delays,
#	   slow down I/O with zinject and keep the pool at its dirty data
#	   limit with a writer
#	3. Detach the original device; it must finish within the timeout
#	4. Check that the spare is now a normal device of the pool and
#	   that the history has the "detach" and the spare's "vdev remove"
#	   records
#

verify_runnable "global"

log_assert "Detaching a spared device at the dirty data limit completes"

typeset -i TIMEOUT=60
typeset -i dpid=0
typeset -i wpid=0
typeset -i tpid=0
typeset DEVDIR=$TEST_BASE_DIR/zpool_detach_spare_throttle
typeset ORIG=$DEVDIR/orig
typeset SPARE=$DEVDIR/spare
typeset DTOUT=$DEVDIR/dtrace.out
typeset DIRTY_MAX=$(get_tunable zfs_dirty_data_max)
typeset DELAY_SCALE=$(get_tunable zfs_delay_scale)

function cleanup
{
	((tpid > 0)) && kill $tpid 2>/dev/null
	if ((wpid > 0)); then
		kill $wpid 2>/dev/null
		wait $wpid 2>/dev/null
	fi
	if ((dpid > 0)) && kill -0 $dpid 2>/dev/null; then
		#
		# The pool is deadlocked and nothing here can undo that:
		# zinject and zpool destroy would hang too.
		#
		log_note "zpool detach is still running; reboot to recover"
		set_tunable64 zfs_dirty_data_max $DIRTY_MAX
		set_tunable64 zfs_delay_scale $DELAY_SCALE
		return
	fi
	zinject -c all
	set_tunable64 zfs_dirty_data_max $DIRTY_MAX
	set_tunable64 zfs_delay_scale $DELAY_SCALE
	poolexists $TESTPOOL1 && destroy_pool $TESTPOOL1
	rm -rf $DEVDIR
}

log_onexit cleanup

log_must mkdir -p $DEVDIR
#
# The devices must be large enough that the writer is held back by the
# dirty data limit, not by space reservations.
#
log_must truncate -s $((MINVDEVSIZE * 4)) $ORIG $SPARE
log_must zpool create -f -O compression=off $TESTPOOL1 $ORIG spare $SPARE
log_must zpool replace $TESTPOOL1 $ORIG $SPARE
log_must zpool wait -t resilver $TESTPOOL1
log_must check_hotspare_state $TESTPOOL1 $SPARE "INUSE"

#
# Without the write throttle's delays, the writer fills the pool to its
# dirty data limit and then waits for a txg sync to make room, so the
# pool stays at the limit.
#
log_must set_tunable64 zfs_dirty_data_max $((16 * 1024 * 1024))
log_must set_tunable64 zfs_delay_scale 0
for dev in $ORIG $SPARE; do
	log_must zinject -d $dev -D 20:1 $TESTPOOL1
done

function dtrace_ready
{
	grep -q "^ready" $DTOUT 2>/dev/null
}

function over_max
{
	grep -q "^over max" $DTOUT 2>/dev/null
}

#
# Note when a writer has to wait because the pool is at its dirty data limit.
#
dtrace -q -o $DTOUT -n '
    BEGIN { printf("ready\n"); }
    fbt::dmu_tx_wait:entry
    /!seen && args[0]->tx_wait_dirty &&
     args[0]->tx_pool->dp_dirty_total >= `zfs_dirty_data_max/
    { seen = 1; printf("over max\n"); }' &
tpid=$!
wait_for 60 dtrace_ready || log_fail "dtrace did not start"

typeset mntpnt=$(get_prop mountpoint $TESTPOOL1)
(
	trap 'kill $ddpid 2>/dev/null; exit' TERM
	while true; do
		dd if=/dev/zero of=$mntpnt/file bs=1024k count=64 \
		    conv=notrunc 2>/dev/null &
		ddpid=$!
		wait $ddpid
	done
) &
wpid=$!
wait_for 60 over_max || log_fail "pool never reached its dirty data limit"
kill $tpid
tpid=0

zpool detach $TESTPOOL1 $ORIG &
dpid=$!

typeset -i waited=0
while kill -0 $dpid 2>/dev/null; do
	((waited++ >= TIMEOUT)) && \
	    log_fail "zpool detach still running after ${TIMEOUT}s"
	sleep 1
done
wait $dpid
typeset -i rc=$?
dpid=0
log_note "zpool detach returned $rc after about ${waited}s"
log_must [ $rc -eq 0 ]

kill $wpid
wait $wpid 2>/dev/null
wpid=0
log_must zinject -c all

if zpool status $TESTPOOL1 | grep -q $ORIG; then
	log_fail "$ORIG is still in $TESTPOOL1"
fi
log_must [ -z "$(get_device_state $TESTPOOL1 $SPARE spares)" ]
log_must eval "zpool history -i $TESTPOOL1 | grep 'detach' | grep -q $ORIG"
log_must eval "zpool history -i $TESTPOOL1 | grep 'vdev remove' | \
    grep -q $SPARE"

log_pass "Detaching a spared device at the dirty data limit completes"
