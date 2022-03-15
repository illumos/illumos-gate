#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2013, 2016 by Delphix. All rights reserved.
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/utils_test/utils_test.kshlib

#
# DESCRIPTION:
# Ensure that the labelit(8) utility fails on a ZFS file system.
#
# STRATEGY:
# 1. Populate a ZFS file system with some files.
# 2. Run labelit(8) against the device.
# 3. Ensure it fails.
#

verify_runnable "global"

function cleanup
{
	ismounted $TESTPOOL/$TESTFS
	(( $? != 0 )) && \
		log_must zfs mount $TESTPOOL/$TESTFS

	rm -rf $TESTDIR/*
}

log_onexit cleanup

log_assert "Ensure that the labelit(8) utility fails on a ZFS file system."

populate_dir $NUM_FILES

log_must zfs unmount $TESTDIR

log_mustnot labelit /dev/rdsk/${DISK}s0 mfiles ${DISK}s0

log_pass "labelit(8) returned an error as expected."
