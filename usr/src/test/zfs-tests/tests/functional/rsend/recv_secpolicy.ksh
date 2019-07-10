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
# Copyright 2019 Joyent, Inc.
#

. $STF_SUITE/tests/functional/rsend/rsend.kshlib

#
# DESCRIPTION:
# Verify that the parent dataset is passed to the kernel's zfs_secpolicy_recv
# function during a zfs receive.
#
# STRATEGY:
# 1. Create a hierarchy of datasets.
# 2. Take a snapshot of the final child dataset and send it to a file.
# 3. Use DTrace to run the zfs recv command and simultaneously monitor the
#    zc_name member of the zfs_cmd_t structure that is validated in
#    zfs_secpolicy_recv.
# 4. Verify that the zc_name member is the parent dataset, as expected.
#

verify_runnable "both"

function cleanup
{
	destroy_dataset $TESTPOOL/testfs2 "-r"
	destroy_dataset $TESTPOOL/testfs1 "-r"
	[[ -f $sendfile ]] && log_must rm $sendfile
}
log_onexit cleanup

log_assert "Verify zfs_secpolicy_recv is passed the proper trimmed name"

typeset sendfile=$TESTDIR/sendfile

log_must zfs create $TESTPOOL/testfs1
log_must zfs create $TESTPOOL/testfs1/data
log_must zfs create $TESTPOOL/testfs1/data/foo

log_must zfs create $TESTPOOL/testfs2
log_must zfs create $TESTPOOL/testfs2/data

log_must mkfile 4k /$TESTPOOL/testfs1/data/foo/testfile0

log_must zfs snap $TESTPOOL/testfs1/data/foo@1

log_must eval "zfs send $TESTPOOL/testfs1/data/foo@1 > $sendfile"

zc_name=$(/usr/sbin/dtrace -q -n \
   'fbt::zfs_secpolicy_recv:entry {printf("%s", stringof(args[0]->zc_name));}' \
    -c "zfs receive $TESTPOOL/testfs2/data/foo" < $sendfile)

[[ "$zc_name" == "$TESTPOOL/testfs2/data" ]] || \
    log_fail "zc_name mismatch: $zc_name != $TESTPOOL/testfs2/data"

log_pass "zfs_secpolicy_recv is passed the proper trimmed name"
