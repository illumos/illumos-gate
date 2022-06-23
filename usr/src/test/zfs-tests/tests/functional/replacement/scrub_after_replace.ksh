#!/usr/bin/ksh -p
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
# A scrub that is set up right after a "zpool replace" in a RAID-Z pool,
# before the resilver that the replace scheduled has begun, must write the
# data to the new device.  The scrub runs instead of the resilver, and when
# it completes the old device is detached, so the new device must hold its
# column of every block.
#
# STRATEGY:
# 1. Create a raidz1 pool of three file vdevs and write some data
# 2. Delay the I/O of the vdevs, and start the sync of a txg
# 3. While that txg syncs, start a scrub and then replace the third vdev.
#    The replace is applied before the txg of the scrub's setup syncs, and
#    the resilver is scheduled for a later txg, so the scrub's setup cancels
#    the resilver.
# 4. Wait for the scrub and the replace to finish, and check that a scrub
#    (not a resilver) ran and that the old vdev was detached
# 5. Offline the first vdev, so that the new vdev's column is needed
# 6. Verify that the data reads back correctly
# 7. Scrub the pool and verify that there are no data errors
#

verify_runnable "global"

typeset VDEV_DIR=$TEST_BASE_DIR/scrub_after_replace.vdevs
typeset MNTPNT=$TEST_BASE_DIR/scrub_after_replace
typeset VDEV1=$VDEV_DIR/vdev1
typeset VDEV2=$VDEV_DIR/vdev2
typeset VDEV3=$VDEV_DIR/vdev3
typeset VDEV4=$VDEV_DIR/vdev4
typeset FILE=$MNTPNT/file

function cleanup
{
	zinject -c all >/dev/null 2>&1
	log_must set_tunable32 zfs_scan_suspend_progress 0
	poolexists $TESTPOOL2 && destroy_pool $TESTPOOL2
	rm -rf $VDEV_DIR $MNTPNT
}

log_assert "A scrub right after a RAID-Z replace writes the new device"
log_onexit cleanup

# 1. Create a raidz1 pool of three file vdevs and write some data
log_must mkdir -p $VDEV_DIR
log_must truncate -s $MINVDEVSIZE $VDEV1 $VDEV2 $VDEV3 $VDEV4
log_must zpool create -O mountpoint=$MNTPNT -O compression=off $TESTPOOL2 \
    raidz1 $VDEV1 $VDEV2 $VDEV3
log_must dd if=/dev/urandom of=$FILE bs=1024k count=64
typeset cksum_before=$(cksum < $FILE)
log_must zpool sync $TESTPOOL2

#
# 2. Delay the I/O of the vdevs, and start the sync of a txg.  Keep the
# scrub from issuing I/O until the replace is done, so that it doesn't
# slow down the txgs that the replace waits for.
#
log_must set_tunable32 zfs_scan_suspend_progress 1
for vdev in $VDEV1 $VDEV2 $VDEV3; do
	log_must zinject -d $vdev -D 100:1 $TESTPOOL2
done
log_must dd if=/dev/urandom of=$MNTPNT/file2 bs=1024k count=1
zpool sync $TESTPOOL2 &
typeset sync_pid=$!
sleep 0.5

#
# 3. While that txg syncs, start a scrub and then replace the third vdev.
# The scrub's setup is assigned to a txg that can't sync until the replace
# has been applied, and the replace schedules its resilver a few txgs later.
#
zpool scrub $TESTPOOL2 &
typeset scrub_pid=$!
sleep 0.5
log_must zpool replace $TESTPOOL2 $VDEV3 $VDEV4
wait $scrub_pid || log_fail "zpool scrub $TESTPOOL2 failed"
wait $sync_pid || log_fail "zpool sync $TESTPOOL2 failed"
log_must zinject -c all
log_must set_tunable32 zfs_scan_suspend_progress 0

#
# 4. Wait for the scrub and the replace to finish, and check that a scrub
# (not a resilver) ran and that the old vdev was detached.
#
log_must zpool wait -t scrub,resilver,replace $TESTPOOL2
typeset scan=$(zpool status $TESTPOOL2 | grep "scan:")
log_note "$scan"
echo "$scan" | grep -q "scrub repaired" || \
    log_fail "A scrub didn't run after the replace: $scan"
vdevs_in_pool $TESTPOOL2 $VDEV3 && \
    log_fail "$VDEV3 is still in $TESTPOOL2 after the replace"
log_must vdevs_in_pool $TESTPOOL2 $VDEV4

#
# 5. Offline the first vdev, so that the new vdev's column is needed.
# Export and import the pool first, so that the data is read from disk.
#
log_must zpool export $TESTPOOL2
log_must zpool import -d $VDEV_DIR $TESTPOOL2
log_must zpool offline $TESTPOOL2 $VDEV1

# 6. Verify that the data reads back correctly
typeset cksum_after=$(cksum < $FILE)
if [[ "$cksum_after" != "$cksum_before" ]]; then
	zpool status -v $TESTPOOL2
	log_fail "$FILE changed: '$cksum_before' became '$cksum_after'"
fi

# 7. Scrub the pool and verify that there are no data errors
log_must zpool scrub -w $TESTPOOL2
if ! zpool status -v $TESTPOOL2 | grep -q "errors: No known data errors"; then
	zpool status -v $TESTPOOL2
	log_fail "$TESTPOOL2 has data errors"
fi

log_pass "A scrub right after a RAID-Z replace writes the new device"
