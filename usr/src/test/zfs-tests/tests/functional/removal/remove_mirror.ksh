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
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/removal/removal.kshlib

TMPDIR=${TMPDIR:-/tmp}
log_must mkfile $(($MINVDEVSIZE * 2)) $TMPDIR/dsk1
log_must mkfile $(($MINVDEVSIZE * 2)) $TMPDIR/dsk2
log_must mkfile $(($MINVDEVSIZE * 2)) $TMPDIR/dsk3
DISKS="$TMPDIR/dsk1 mirror $TMPDIR/dsk2 $TMPDIR/dsk3"

function cleanup
{
	default_cleanup_noexit
	log_must rm -f $DISKS
}

log_must default_setup_noexit "$DISKS"
log_onexit cleanup

# Attempt to remove the non mirrored disk.
log_must zpool remove $TESTPOOL $TMPDIR/dsk1

# Attempt to remove one of the disks in the mirror.
log_mustnot zpool remove $TESTPOOL $TMPDIR/dsk2

# Add back the first disk.
log_must zpool add $TESTPOOL $TMPDIR/dsk1

# Now attempt to remove the mirror.
log_must zpool remove $TESTPOOL mirror-1

log_pass "Removal will succeed for top level vdev(s)."
