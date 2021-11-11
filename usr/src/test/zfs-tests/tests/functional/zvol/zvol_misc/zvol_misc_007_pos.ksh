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
. $STF_SUITE/tests/functional/zvol/zvol_common.shlib

#
# DESCRIPTION:
# Verify name collision occurs when an attempt to destroy ZFS filesystem
# and create ZFS volume with the same name cannot cause system panic
#
# STRATEGY:
# 1. Create ZFS filesystems
# 2. Create nested ZFS volume
# 3. Read and displays information about the ZFS volume
# 4. Recursive destroy ZFS filesystems
# 5. Create ZFS volume with the same name as ZFS filesystem
# 6. Read and displays information about the ZFS volume
# 7. Verify the system continued work
#

verify_runnable "global"
log_assert "zfs can handle race volume create operation."
log_onexit cleanup

log_must $ZFS create $TESTPOOL/$TESTFS
log_must $ZFS create -V 1M $TESTPOOL/$TESTFS/$TESTVOL
log_must $STAT /dev/zvol/rdsk/$TESTPOOL/$TESTFS/$TESTVOL
log_must $ZFS destroy -r $TESTPOOL/$TESTFS
log_must $ZFS create -V 1M $TESTPOOL/$TESTFS
log_must $STAT /dev/zvol/rdsk/$TESTPOOL/$TESTFS

log_pass "zfs handle race volume create operation."
