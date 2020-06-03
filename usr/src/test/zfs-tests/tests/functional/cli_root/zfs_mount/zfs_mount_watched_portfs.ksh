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
# Copyright 2020 Joyent, Inc.
#

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
# 'zfs mount' should not get EBUSY due to portfs watching a directory
#
# STRATEGY:
# 1. Create a directory
# 2. Start watching the directory with port_associate
# 3. Create a filesystem
# 4. Mount the filesystem at the directory created in step 1
# 5. Destroy the filesystem
# 6. Remove the directory
# 7. Verify the watcher saw the directory removal
#

verify_runnable "both"

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
		log_must zfs destroy -f $TESTPOOL/$TESTFS1
	log_must rm -rf "$TESTDIR/mntpt" "$TESTDIR/watch_dir.log"
}

log_onexit cleanup

log_assert "'zfs mount' should not get EBUSY due to portfs watching a directory"

# 1. Create a directory.
log_must mkdir -p "$TESTDIR/mntpt"

# 2. Start watching the directory with port_associate
watch_dir portfs $TESTDIR/mntpt > $TESTDIR/watch_dir.log &

# 3. Create a filesystem
log_must zfs create $TESTPOOL/$TESTFS1

# 4. Mount the file system at the directory created in step 1
log_must zfs set mountpoint=$TESTDIR/mntpt $TESTPOOL/$TESTFS1

# 5. Destroy the filesystem
log_must zfs destroy $TESTPOOL/$TESTFS1

# 6. Remove the directory.  The corresponding portfs event will cause the
# watcher to exit.
log_must rmdir $TESTDIR/mntpt

# 7. Verify the watcher saw the directory removal. This ensures that the watcher
# was watching the directory we are interested in.
wait
log_must grep -q DELETE.$TESTDIR/mntpt $TESTDIR/watch_dir.log

log_pass "'zfs mount' should not get EBUSY due to portfs watching a directory"
