#!/bin/ksh -p
#
# CDDL HEADER START
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
# CDDL HEADER END
#

#
# Copyright (c) 2019 by Tim Chase. All rights reserved.
# Copyright (c) 2019 Lawrence Livermore National Security, LLC.
# Copyright 2019 Joyent, Inc.
# Copyright 2026 Oxide Computer Company
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/cli_root/zpool_initialize/zpool_initialize.kshlib
. $STF_SUITE/tests/functional/cli_root/zpool_trim/zpool_trim.kshlib

#
# DESCRIPTION:
# After trimming, the disk is actually trimmed.
#
# STRATEGY:
# 1. Create a one-disk pool using a sparse file, on a pool of its own.
# 2. Initialize the pool and verify the file vdev is no longer sparse.
# 3. Trim the pool and verify the file vdev is again sparse.
#

function cleanup
{
	if poolexists $TESTPOOL; then
		destroy_pool $TESTPOOL
	fi

	if poolexists $TESTPOOL1; then
		destroy_pool $TESTPOOL1
	fi

	log_must set_tunable32 zfs_trim_extent_bytes_min $trim_extent_bytes_min
}
log_onexit cleanup

#
# Keep the file vdev on a pool of our own, on a dataset with zle compression,
# so that its size on disk does not depend on where $TESTDIR is or on how that
# pool compresses. zle stores the pattern zpool initialize writes at full size,
# since the pattern has no zero bytes. Like any setting other than off, it
# also stores the zero-filled blocks a partial TRIM leaves as holes.
#
DISK1=${DISKS%% *}
LARGESIZE=$((MINVDEVSIZE * 4))
LARGEFILE="/$TESTPOOL1/largefile"

# Reduce trim size to allow for tighter tolerance below when checking.
typeset trim_extent_bytes_min=$(get_tunable zfs_trim_extent_bytes_min)
log_must set_tunable32 zfs_trim_extent_bytes_min 4096

log_must zpool create -f -O compression=zle $TESTPOOL1 $DISK1
log_must truncate -s $LARGESIZE "$LARGEFILE"
log_must zpool create $TESTPOOL "$LARGEFILE"

original_size=$(file_alloc_bytes "$LARGEFILE")

log_must zpool initialize -w $TESTPOOL

new_size=$(file_alloc_bytes "$LARGEFILE")
log_must test $new_size -gt $((8 * 1024 * 1024))

log_must zpool trim $TESTPOOL
wait_trim_complete $TESTPOOL $LARGEFILE

new_size=$(file_alloc_bytes "$LARGEFILE")
log_must within_tolerance $new_size $original_size $((128 * 1024 * 1024))

log_pass "Trimmed appropriate amount of disk space"
