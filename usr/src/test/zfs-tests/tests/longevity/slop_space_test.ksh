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
# Copyright (c) 2017 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/pool_checkpoint/pool_checkpoint.kshlib

#
# DESCRIPTION:
#	Ensure that all levels of reserved slop space are
#	followed by ZFS.
#
# STRATEGY:
#	1. Create testpool with two filesystems
#	2. On the first filesystem create a big file that holds
#	   a large portion of the pool's space. Then overwrite it
#	   in such a way that if we free it after taking a
#	   checkpoint it will append a lot of small entries to
#	   the checkpoint's space map
#	3. Checkpoint the pool
#	4. On the second filesystem, create a file and keep writing
#	   to it until we hit the first level of reserved space
#	   (128M)
#	5. Then start adding properties to second filesystem until
#	   we hit the second level of reserved space (64M)
#	6. Destroy the first filesystem and wait until the async
#	   destroys of this operation hit the last level of
#	   reserved space (32M)
#	7. Attempt to destroy the second filesystem (should fail)
#	8. Discard the checkpoint
#

DISK="$(echo $DISKS | cut -d' ' -f1)"
DISKFS=$TESTPOOL/disks

NESTEDPOOL=nestedpool

FILEDISKSIZE=4g
FILEDISKLOCATION=/$DISKFS
FILEDISK=$FILEDISKLOCATION/dsk1

FS0=$NESTEDPOOL/fs0
FS1=$NESTEDPOOL/fs1

FS0FILE=/$FS0/file
FS1FILE=/$FS1/file

CKPOINTEDFILEBLOCKS=3200
NUMOVERWRITTENBLOCKS=$(($CKPOINTEDFILEBLOCKS * 1024 * 1024 / 512 / 2))

verify_runnable "global"

function test_cleanup
{
	log_must mdb_ctf_set_int zfs_async_block_max_blocks 0xffffffffffffffff
	poolexists $NESTEDPOOL && destroy_pool $NESTEDPOOL
	log_must zpool destroy $TESTPOOL
}

function wait_until_extra_reserved
{
	#
	# Loop until we get from gigabytes to megabytes
	#
	size_range=$(zpool list | awk '{print $1,$4}' | \
	    grep $NESTEDPOOL | awk '{print $2}' | grep G)
	while [ "" != "$size_range" ]; do
		sleep 5
		size_range=$(zpool list | awk '{print $1,$4}' | \
		    grep $NESTEDPOOL | awk '{print $2}' | grep G)
	done


	#
	# Loop until we hit the 32M limit
	#
	free=$(zpool list | awk '{print $1,$4}' | \
	    grep $NESTEDPOOL | awk '{print $2}' | cut -d"M" -f1 | \
	    cut -d"." -f1)
	while (( $free > 32 )); do
		sleep 5
		free=$(zpool list | awk '{print $1,$4}' | \
		    grep $NESTEDPOOL | awk '{print $2}' | cut -d"M" -f1 | \
		    cut -d"." -f1)
	done

	#
	# Even though we may have hit the 32M limit we
	# still need to wait to ensure that we are at
	# the stable state where async destroys are suspended.
	#
	sleep 300
}

log_must zpool create $TESTPOOL $DISK
log_onexit test_cleanup

log_must zfs create $DISKFS

log_must mkfile -n $FILEDISKSIZE $FILEDISK
log_must zpool create $NESTEDPOOL $FILEDISK
log_must zfs create -o recordsize=512 $FS0
log_must zfs create -o recordsize=512 $FS1


#
# Create a ~3.2G file and ensure it is
# synced to disk
#
log_must dd if=/dev/zero of=$FS0FILE bs=1M count=$CKPOINTEDFILEBLOCKS
log_must sync

# for debugging purposes
log_must zpool list $NESTEDPOOL

#
# Overwrite every second block of the file.
# The idea is to make long space map regions
# where we have subsequent entries that cycle
# between marked as ALLOCATED and FREE. This
# way we attempt to keep the space maps long
# and fragmented.
#
# So later, when there is a checkpoint and we
# destroy the filesystem, all of these entries
# should be copied over to the checkpoint's
# space map increasing capacity beyond the
# extra reserved slop space.
#
log_must dd if=/dev/zero of=$FS0FILE bs=512 ostride=2 \
    count=$NUMOVERWRITTENBLOCKS conv=notrunc

# for debugging purposes
log_must zpool list $NESTEDPOOL

log_must zpool checkpoint $NESTEDPOOL

#
# Keep writing to the pool until we get to
# the first slop space limit.
#
log_mustnot dd if=/dev/zero of=$FS1FILE bs=512

# for debugging purposes
log_must zpool list $NESTEDPOOL

#
# Keep adding properties to our second
# filesystem until we hit we hit the
# second slop space limit.
#
for i in {1..100}
do
	#
	# We use this nested loop logic to fit more
	# properties in one zfs command and reducing
	# the overhead caused by the number of times
	# we wait for a txg to sync (e.g. equal to the
	# number of times we execute zfs(1m))
	#
	PROPERTIES=""
	for j in {1..100}
	do
		PROPVAL=$(dd if=/dev/urandom bs=6000 count=1 | base64 -w 0)
		PROP="user:prop-$i-$j=$PROPVAL"
		PROPERTIES="$PROPERTIES $PROP"
	done
	zfs set $PROPERTIES  $FS1 || break
	log_note "- setting properties: iteration $i out of 100 -"
done

for k in {1..100}
do
	#
	# In case we broke out of the loop above because we
	# couldn't fit 100 props in the space left, make sure
	# to fill up the space that's left by setting one property
	# at a time
	#
	PROPVAL=$(dd if=/dev/urandom bs=6000 count=1 | base64 -w 0)
	PROP="user:prop-extra-$k=$PROPVAL"
	zfs set $PROP $FS1 || break
done

# for debugging purposes
log_must zpool list $NESTEDPOOL

#
# By the time we are done with the loop above
# we should be getting ENOSPC for trying to add
# new properties. As a sanity check though, try
# again (this time with log_mustnot).
#
log_mustnot zfs set user:proptest="should fail!" $FS0
log_mustnot zfs set user:proptest="should fail!" $FS1

# for debugging purposes
log_must zpool list $NESTEDPOOL

#
# We are about to destroy the first filesystem,
# but we want to do so in a way that generates
# as many entries as possible in the vdev's
# checkpoint space map. Thus, we reduce the
# amount of checkpointed blocks that we "free"
# every txg.
#
log_must mdb_ctf_set_int zfs_async_block_max_blocks 0t10000

log_must zfs destroy $FS0

#
# Keep looping until we hit that point where
# we are at the last slop space limit (32.0M)
# and async destroys are suspended.
#
wait_until_extra_reserved

# for debugging purposes
log_must zpool list $NESTEDPOOL

#
# At this point we shouldn't be allowed to
# destroy anything.
#
log_mustnot zfs destroy $FS1

#
# The only operations that should be allowed
# is discarding the checkpoint.
#
log_must zpool checkpoint -d $NESTEDPOOL

wait_discard_finish $NESTEDPOOL

#
# Now that we have space again, we should be
# able to destroy that filesystem.
#
log_must zfs destroy $FS1

log_pass "All levels of slop space work as expected."
