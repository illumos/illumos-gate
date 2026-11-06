#!/usr/bin/ksh -p
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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2013, 2016 by Delphix. All rights reserved.
# Copyright 2026 Oxide Computer Company
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/migration/migration.cfg

verify_runnable "global"

verify_disk_count "$DISKS" 1

create_pool $TESTPOOL "$ZFS_DISK"

rm -rf $TESTDIR  || log_unresolved Could not remove $TESTDIR
mkdir -p $TESTDIR || log_unresolved Could not create $TESTDIR

log_must zfs create $TESTPOOL/$TESTFS
log_must zfs set mountpoint=$TESTDIR $TESTPOOL/$TESTFS

rm -rf $NONZFS_TESTDIR  || log_unresolved Could not remove $NONZFS_TESTDIR
mkdir -p $NONZFS_TESTDIR || log_unresolved Could not create $NONZFS_TESTDIR

#
# Put the UFS file system on a lofi device, which always has 512-byte
# sectors, since UFS does not support disks with larger sectors.  First
# detach any lofi device left by an aborted run.
#
lofiadm $NONZFS_FILE > /dev/null 2>&1 && log_must lofiadm -d $NONZFS_FILE
log_must mkfile -n $FS_SIZE $NONZFS_FILE
lofidev=$(lofiadm -a $NONZFS_FILE) || log_fail "lofiadm -a $NONZFS_FILE failed"
log_must new_fs ${lofidev/lofi/rlofi}
log_must mount $lofidev $NONZFS_TESTDIR

log_pass
