#! /bin/ksh -p
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
# Copyright (c) 2020, George Amanakis. All rights reserved.
# Copyright 2026 Oxide Computer Company
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/removal/removal.kshlib

#
# DESCRIPTION:
#	Resilvering results in no CKSUM errors in pools with indirect vdevs.
#
# STRATEGY:
#	1. Create a pool with two top-vdevs
#	2. Write a file
#	3. Remove one of the top-vdevs, with 64K removal segments so that
#	   each 128K block that was on it is split
#	4. Reattach it to make a mirror
#

TMPDIR=${TMPDIR:-$TEST_BASE_DIR}

DISK1="$TMPDIR/dsk1"
DISK2="$TMPDIR/dsk2"
DISKS="$DISK1 $DISK2"

log_must truncate -s 1g $DISK1
log_must truncate -s 1g $DISK2

function cleanup
{
	log_must set_tunable32 zfs_remove_max_segment $ORIG_REMOVE_MAX_SEGMENT
	default_cleanup_noexit
	log_must rm -f $DISKS
}

ORIG_REMOVE_MAX_SEGMENT=$(get_tunable zfs_remove_max_segment)

log_must zpool create -O compression=off $TESTPOOL $DISK1 $DISK2
log_onexit cleanup

log_must dd if=/dev/urandom of=/$TESTPOOL/file bs=1024k count=64
log_must zpool sync $TESTPOOL

log_must set_tunable32 zfs_remove_max_segment 65536
log_must zpool remove -w $TESTPOOL $DISK2
log_must set_tunable32 zfs_remove_max_segment $ORIG_REMOVE_MAX_SEGMENT
log_must zpool attach -w $TESTPOOL $DISK1 $DISK2

verify_pool $TESTPOOL

# verify_pool only looks at the errors of the root vdev.
typeset errors=$(zpool status -p $TESTPOOL | awk '
    !NF { isvdev = 0 }
    isvdev { errors += $5 }
    /CKSUM$/ { isvdev = 1 }
    END { print errors + 0 }')
if ((errors != 0)); then
	log_must zpool status -v $TESTPOOL
	log_fail "Unexpected CKSUM errors found on $TESTPOOL ($errors)"
fi

log_pass "Resilvering results in no CKSUM errors with indirect vdevs"
