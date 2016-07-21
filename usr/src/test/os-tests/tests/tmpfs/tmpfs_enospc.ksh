#!/usr/bin/ksh
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
# Copyright 2016 Joyent, Inc.
#

#
# Verify that if we fill up a tmpfs that we can't then perform
# additional things to it that would result in the creation or use of
# kernel memory.
#

te_arg0=$(basename $0)
te_root=$(dirname $0)
te_bin=$te_root/tmpfs_full
te_mountpoint="/var/tmp/$0.$$"
te_mount=/usr/sbin/mount
te_umount=/usr/sbin/umount
te_testfile=1m
te_mounted=
te_exit=1

function fatal
{
	[[ -n "$te_mounted" ]] && $te_umount $te_mountpoint
	rmdir $te_mountpoint
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="test failed"
	echo "$te_arg0: test failed $msg" >&2
	exit 1
}

function setup
{
	typeset ofile=$te_mountpoint/$te_testfile

	mkdir -p $te_mountpoint || fatal \
	    "failed to make mountpoint $te_mountpoint"
	$te_mount -F tmpfs swap $te_mountpoint || fatal \
	    "failed to mount tmpfs, check user perms"
	te_mounted=1
	dd if=/dev/zero of=$ofile bs=1M count=1 2>/dev/null || fatal \
	    "failed to create a 1 MB file"
	$te_mount -F tmpfs -o remount,size=512k swap $te_mountpoint ||
	    fatal "failed to remount tmpfs"
}

function run_test
{
	$te_bin $te_mountpoint $te_testfile || fatal "$te_bin failed"
}

function cleanup
{
	te_mounted=
	$te_umount $te_mountpoint || fatal "failed to unmount $te_mountpoint"
	rmdir $te_mountpoint || fatal "failed to remove $te_mountpoint"
}

setup
run_test
cleanup

exit 0
