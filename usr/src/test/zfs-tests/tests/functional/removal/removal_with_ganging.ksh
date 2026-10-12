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

function cleanup
{
	log_must set_tunable64 metaslab_force_ganging $orig_force_ganging
	default_cleanup_noexit
}

typeset orig_force_ganging=$(get_tunable metaslab_force_ganging)
log_onexit cleanup
default_setup_noexit "$DISKS"
log_must set_tunable64 metaslab_force_ganging $((2**14))

FILE_CONTENTS="Leeloo Dallas mul-ti-pass."

echo $FILE_CONTENTS  >$TESTDIR/$TESTFILE0
log_must [ "x$(cat $TESTDIR/$TESTFILE0)" = "x$FILE_CONTENTS" ]
log_must file_write -o create -f $TESTDIR/$TESTFILE1 -b $((2**20)) -c $((2**7))

log_must zpool remove $TESTPOOL $REMOVEDISK
log_must wait_for_removal $TESTPOOL
log_mustnot vdevs_in_pool $TESTPOOL $REMOVEDISK

log_must dd if=/$TESTDIR/$TESTFILE0 of=/dev/null
log_must [ "x$(cat $TESTDIR/$TESTFILE0)" = "x$FILE_CONTENTS" ]

log_pass "Removed device not in use after removal."
