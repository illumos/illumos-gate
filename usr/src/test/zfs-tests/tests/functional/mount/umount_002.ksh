#! /usr/bin/ksh -p
#
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
# Copyright 2016 Nexenta Systems, Inc. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
# zfs umount should not fail because flushing of DNLC
# uses async implementation of zfs_inactive
#
# STRATEGY:
# 1. Call zfs unmount/mount to be sure DNLC is empty
# 2. Create a lot of files
# 3. Call zfs unmount command
# 4. Make sure the file systems were unmounted
# 5. Mount them back
#

for fs in 1 2 3; do
	log_must mounted $TESTDIR.$fs
	log_must zfs umount $TESTPOOL/$TESTFS.$fs
	log_must unmounted $TESTDIR.$fs
	log_must zfs mount $TESTPOOL/$TESTFS.$fs
	log_must mounted $TESTDIR.$fs

	for fn in $(seq 1 8096); do
		log_must dd if=/dev/urandom of=$TESTDIR.$fs/file$fn bs=1024 \
		    count=1
	done

	log_must zfs umount $TESTPOOL/$TESTFS.$fs
	log_must unmounted $TESTDIR.$fs
	log_must zfs mount $TESTPOOL/$TESTFS.$fs
	log_must mounted $TESTDIR.$fs
	log_must rm -f $TESTDIR.$fs/file*
done

log_pass "All file systems are unmounted"
