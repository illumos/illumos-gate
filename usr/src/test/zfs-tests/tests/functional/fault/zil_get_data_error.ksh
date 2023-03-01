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
#	fsync must not return success for a write whose ZIL record could not
#	be built because zl_get_data() failed with an unexpected error (here
#	ECKSUM from reading the file data back) before the txg holding the
#	write has synced.
#
# STRATEGY:
#	1. Create a file system with primarycache=metadata, so a file block
#	   is evicted from memory as soon as spa_sync has written it, and
#	   logbias=throughput, so writes are logged as WR_INDIRECT records.
#	   Create its ZIL with an fsync, so that zil_create() (which waits
#	   for a txg sync) does not run later.
#	2. Overwrite a block of a file without syncing it.
#	3. Inject checksum errors on reads of the file's data, and a delay
#	   on every I/O to the disk.  The delay makes the rest of spa_sync
#	   (metadata, labels, uberblock, flushes) take many times longer
#	   than the write of the file block itself.
#	4. Start a txg sync, and wait until the file block has been written
#	   and evicted while the txg is still syncing.
#	5. fsync the file.  Building the ZIL record reads the evicted block
#	   back, which fails with ECKSUM, so the record cannot be logged.
#	   fsync must not return before the txg holding the write has synced.
#	6. Clear the injection and verify the file data.
#
#	The immediate (WR_NEED_COPY) case is not tested: zfs_get_data()
#	asserts that dmu_read() returns only 0 or ENOENT, so it panics a
#	DEBUG kernel before zil_lwb_commit() sees the error.
#

. $STF_SUITE/include/libtest.shlib

verify_runnable "global"

DISK=${DISKS%% *}
FILE=/$TESTPOOL/$TESTFS/file
RECSIZE=131072
DELAY_MS=1000
typeset sync_pid=""

function cleanup
{
	zinject -c all >/dev/null 2>&1
	if [[ -n $sync_pid ]]; then
		wait $sync_pid
	fi
	destroy_pool $TESTPOOL
}

#
# Print the txg being synced and the last synced txg of a pool.
#
function pool_txgs # pool
{
	typeset spa=$(echo "::spa" | mdb -k | \
	    nawk -v pool=$1 '$NF == pool {print $1}')

	echo "$spa::print -d spa_t spa_syncing_txg spa_ubsync.ub_txg" | \
	    mdb -k | nawk '{sub(/^0t/, "", $NF); print $NF}' | xargs
}

function write_file # file offset length char [fsync]
{
	python -c "import os; \
	    fd = os.open('$1', os.O_WRONLY | os.O_CREAT, 0o644); \
	    assert os.pwrite(fd, b'$4' * $3, $2) == $3; \
	    '$5' == 'fsync' and os.fsync(fd); \
	    os.close(fd)"
}

function fsync_file # file
{
	python -c "import os; os.fsync(os.open('$1', os.O_RDONLY))"
}

function check_file # file
{
	python -c "import sys; \
	    sys.exit(open('$1', 'rb').read() != b'B' * $RECSIZE)"
}

log_assert "fsync waits for the txg when zl_get_data() fails unexpectedly"
log_onexit cleanup

log_must zpool create -f $TESTPOOL $DISK
log_must zfs create -o logbias=throughput -o primarycache=metadata \
    -o recordsize=$RECSIZE $TESTPOOL/$TESTFS
log_must write_file /$TESTPOOL/$TESTFS/zil 0 512 x fsync
log_must write_file $FILE 0 $RECSIZE A
sync_pool $TESTPOOL

log_must write_file $FILE 0 $RECSIZE B
log_must zinject -t data -e checksum -f 100 $FILE
log_must zinject -d $DISK -D $DELAY_MS:100 $TESTPOOL
zpool sync $TESTPOOL &
sync_pid=$!
sleep $((DELAY_MS * 4 / 1000))

set -- $(pool_txgs $TESTPOOL)
typeset -i txg=$1 synced=$2
log_note "syncing txg $txg, last synced txg $synced"
((txg > synced)) || log_fail "no txg sync in progress"

log_must fsync_file $FILE
set -- $(pool_txgs $TESTPOOL)
synced=$2
log_note "last synced txg after fsync: $synced"
((synced >= txg)) || log_fail "fsync returned before txg $txg synced"

log_must zinject -c all
wait $sync_pid
sync_pid=""
log_must check_file $FILE

log_pass "fsync waits for the txg when zl_get_data() fails unexpectedly"
