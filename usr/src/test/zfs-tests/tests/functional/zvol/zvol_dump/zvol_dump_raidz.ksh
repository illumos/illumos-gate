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

#
# DESCRIPTION:
# Attempt to access a dump device on a RAID-Z pool.
#
# STRATEGY:
# 1. Create a RAID-Z pool.
# 2. Create a zvol on that pool called "dump".
# 3. Configure it with "dumpadm".
# 4. Attempt to issue reads and writes to it.
#

# Save the current dump device so we can restore it after the test.
orig_dump_device=$(dumpadm | awk '/Dump device/ { print $3 }')

function cleanup
{
	log_must dumpadm -u -d $orig_dump_device
	log_must zpool destroy -f $TESTPOOL
}

log_onexit cleanup

DISK1="$(echo $DISKS | cut -d' ' -f1)"
DISK2="$(echo $DISKS | cut -d' ' -f2)"
DISK3="$(echo $DISKS | cut -d' ' -f3)"

log_must zpool create -f $TESTPOOL raidz $DISK1 $DISK2 $DISK3
log_must zfs create -V 8G $TESTPOOL/dump

log_must dumpadm -u -d /dev/zvol/dsk/$TESTPOOL/dump

log_must dd if=/dev/zvol/dsk/$TESTPOOL/dump of=/dev/null bs=1M count=1
log_must dd if=/dev/urandom of=/dev/zvol/dsk/$TESTPOOL/dump bs=1M count=1

log_pass "Reads and writes to the dump device on a RAID-Z pool were successful"
