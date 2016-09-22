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
# Copyright (c) 2015 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
# While remapping all the files in a filesystem, ZFS should be able to
# concurrently perform ZPL operations (remove files, truncate files, etc).
#
# STRATEGY:
# 1. Create a ZFS filesystem
# 2. Create many files.
# 3. Continually remap the filesystem while performing ZPL operations.
# 4. After the specified time duration, the system should not be panic.
#

verify_runnable "both"

NUMFILES=10000
NUMTHREADS=16
TIMEOUT=500

log_assert "ZFS can handle ZPL operations during a remap."

default_setup_noexit "$DISKS"
log_onexit default_cleanup_noexit

seq -f "$TESTDIR/file%g" $NUMFILES | xargs touch || \
    log_fail "Unable to create test files."

function remove_random_file
{
	typeset target=$TESTDIR/file$((RANDOM % NUMFILES))
	if rm $target 2>/dev/null; then
		touch $target || log_note "Failure to re-create $target."
	fi
}

log_must touch $TESTDIR/continue
for thread in $(seq $NUMTHREADS); do
	(while [[ -f $TESTDIR/continue ]]; do
		remove_random_file
	done) &
done

#
# Remove the first disk to ensure there is something to remap.
#
log_must zpool remove $TESTPOOL ${DISKS/ */}

start=$(current_epoch)
while (($(current_epoch) < start + TIMEOUT)); do
	zfs remap $TESTPOOL/$TESTFS || \
	    log_fail "Failure to remap $TESTPOOL/$TESTFS"
done

log_pass "ZFS handles race as expected."
