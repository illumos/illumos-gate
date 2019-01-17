#!/bin/ksh -p
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
# Copyright 2026 Oxide Computer Company
#

#
# DESCRIPTION:
#	A full-block write that extends a file is done by filling a loaned
#	ARC buffer and assigning it to the file's dbuf.  If the indirect
#	block above that dbuf cannot be read, the assignment fails with
#	EIO.  zfs_write() must return the error.  Before the fix it
#	ignored it: the write succeeded and the file grew, but the new
#	block was never written (it reads back as zeros), and the loaned
#	buffer was leaked.
#
# STRATEGY:
#	1. Write a file of 8 full blocks, so that it has an indirect
#	   block, and export and import the pool to empty the caches.
#	2. Inject read errors on the file's first level-1 block.
#	3. Append one full block.  The write must fail.
#	4. Clear the injection, and check that the file did not grow.
#

. $STF_SUITE/include/libtest.shlib

verify_runnable "global"

DISK=${DISKS%% *}
FS=$TESTPOOL/fs
FILE=/$FS/file
BLKSZ=$((128 * 1024))
NBLKS=8

function cleanup
{
	zinject -c all >/dev/null 2>&1
	destroy_pool $TESTPOOL
}

log_assert "A full-block write fails if its indirect block cannot be read"
log_onexit cleanup

log_must zpool create -f $TESTPOOL $DISK
log_must zfs create -o recordsize=$BLKSZ -o compression=off $FS
log_must dd if=/dev/urandom of=$FILE bs=$BLKSZ count=$NBLKS
sync_pool $TESTPOOL

typeset objset=$(get_prop objsetid $FS)
typeset obj=$(ls -i $FILE | nawk '{print $1}')
log_note "$FILE is object $obj in objset $objset"

log_must zpool export $TESTPOOL
log_must zpool import $TESTPOOL
log_must zinject -b $(printf "%x:%x:1:0" $objset $obj) $TESTPOOL

#
# Without the fix, this write succeeds although nothing was written.
#
log_mustnot dd if=/dev/urandom of=$FILE bs=$BLKSZ count=1 oseek=$NBLKS \
    conv=notrunc

log_must zinject -c all
typeset size=$(stat -c %s $FILE)
(( size == BLKSZ * NBLKS )) || \
    log_fail "$FILE has size $size after a failed write"

log_pass "A full-block write fails if its indirect block cannot be read"
