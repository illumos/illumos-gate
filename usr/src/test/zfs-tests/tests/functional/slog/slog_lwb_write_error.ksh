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

. $STF_SUITE/tests/functional/slog/slog.kshlib

#
# DESCRIPTION:
#	A synchronous write must not return before its data is on stable
#	storage. When the write of the log block holding its record fails,
#	the ZIL must fall back to waiting for the txg to sync, so the
#	pool's on-disk uberblock must have advanced by the time the write
#	returns.
#
# STRATEGY:
#	1. Raise zfs_txg_timeout so that txgs sync only on demand.
#	2. Create a pool with a log device and a sync=always file system.
#	3. Do one synchronous write to create the ZIL, then sync the pool.
#	4. Inject write errors on the log device.
#	5. Do synchronous writes, and verify that each one advanced the
#	   on-disk uberblock txg before returning.
#

verify_runnable "global"

TXG_TIMEOUT_LONG=3600

function cleanup
{
	zinject -c all >/dev/null 2>&1
	set_tunable32 zfs_txg_timeout $ORIG_TXG_TIMEOUT
	poolexists $TESTPOOL && destroy_pool $TESTPOOL
}

#
# Print the txg of the pool's newest uberblock on disk.
#
function ondisk_txg #pool
{
	zdb -u $1 | awk '$1 == "txg" { print $3; exit }'
}

ORIG_TXG_TIMEOUT=$(get_tunable zfs_txg_timeout)
log_onexit cleanup
log_must setup

log_must set_tunable32 zfs_txg_timeout $TXG_TIMEOUT_LONG
log_must zpool create $TESTPOOL $VDEV log $SDEV
log_must zfs create -o sync=always $TESTPOOL/$TESTFS
mntpnt=$(get_prop mountpoint $TESTPOOL/$TESTFS)

log_must dd if=/dev/urandom of=$mntpnt/file bs=8k count=1
sync_pool $TESTPOOL

log_must zinject -d $SDEV -e io -T write $TESTPOOL

for i in 1 2 3; do
	before=$(ondisk_txg $TESTPOOL)
	[[ -n "$before" ]] || log_fail "could not read the on-disk txg"
	log_must dd if=/dev/urandom of=$mntpnt/file bs=8k count=1 \
	    oseek=$i conv=notrunc
	after=$(ondisk_txg $TESTPOOL)
	log_note "sync write $i: on-disk txg $before -> $after"
	if [[ -z "$after" ]] || (( after <= before )); then
		log_fail "sync write $i returned before its txg synced" \
		    "after a log block write error"
	fi
done

log_must zinject -c all

errs=$(zpool status -p $TESTPOOL | awk -v dev=$SDEV '$1 == dev { print $4 }')
log_note "write errors on $SDEV: $errs"
[[ -n "$errs" ]] && (( errs > 0 )) || \
    log_fail "no write errors were injected on $SDEV"

log_pass "Sync writes wait for the txg to sync after a log block write error."
