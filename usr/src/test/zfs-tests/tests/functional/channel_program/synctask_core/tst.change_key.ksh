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
. $STF_SUITE/tests/functional/cli_root/zfs_load-key/zfs_load-key_common.kshlib
. $STF_SUITE/tests/functional/channel_program/channel_common.kshlib

#
# DESCRIPTION:
#	Try to change an encrypted dataset key via a ZFS channel program

verify_runnable "both"

function cleanup
{
	datasetexists $TESTPOOL/$TESTFS1 && \
		log_must zfs destroy -f $TESTPOOL/$TESTFS1
}
log_onexit cleanup

log_assert "zfs.sync.change_key should change key material"

log_must eval "echo $HEXKEY | zfs create -o encryption=on" \
        "-o keyformat=hex -o keylocation=prompt $TESTPOOL/$TESTFS1"

log_must $ZCP_ROOT/synctask_core/change_key.exe $TESTPOOL/$TESTFS1 $HEXKEY1

# Key shouldn't appear in zpool history when using change_key.exe
log_mustnot eval "zfs history -il $TESTPOOL | grep $HEXKEY1"

log_must zfs unmount $TESTPOOL/$TESTFS1
log_must zfs unload-key $TESTPOOL/$TESTFS1

log_mustnot eval "echo $HEXKEY | zfs load-key $TESTPOOL/$TESTFS1"
log_must key_unavailable $TESTPOOL/$TESTFS1

log_must eval "echo $HEXKEY1 | zfs load-key $TESTPOOL/$TESTFS1"

log_pass "zfs.sync.change_key should change key material"
