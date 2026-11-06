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
# Copyright (c) 2014, 2017 by Delphix. All rights reserved.
# Copyright 2026 Oxide Computer Company
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/removal/removal.kshlib

TMPDIR=${TMPDIR:-$TEST_BASE_DIR}
log_must mkfile 1g $TMPDIR/dsk1
log_must mkfile 1g $TMPDIR/dsk2

function cleanup
{
	default_cleanup_noexit
	log_must rm -f $TMPDIR/dsk1 $TMPDIR/dsk2
}

default_setup_noexit "$DISKS"
log_onexit cleanup

#
# During a removal, only vdevs with the pool's ashift can be added.  A file
# vdev gets ashift 9, so give it the largest ashift of the pool's disks, which
# have 4K sectors on some systems.
#
ashift=$(zdb -C $TESTPOOL | \
    awk '$1 == "ashift:" && $2 > a {a = $2} END {print a}')
[[ -n $ashift ]] || log_fail "could not get the ashift of $TESTPOOL"

function callback
{
	log_mustnot zpool attach -f $TESTPOOL $TMPDIR/dsk1 $TMPDIR/dsk2
	log_mustnot zpool add -f $TESTPOOL \
	    raidz $TMPDIR/dsk1 $TMPDIR/dsk2
	log_must zpool add -f -o ashift=$ashift $TESTPOOL $TMPDIR/dsk1
	return 0
}

test_removal_with_operation callback

log_pass "Removal can only add normal disks."
