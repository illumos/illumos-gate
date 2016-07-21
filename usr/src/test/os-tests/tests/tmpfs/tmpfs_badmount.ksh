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
# Test various options to try and mount a tmpfs. Aside from the first to
# verify that we can mount tmpfs at all, these should all fail.
#

tb_arg0=$(basename $0)
tb_mountpoint="/var/tmp/$0.$$"
tb_mount=/usr/sbin/mount
tb_umount=/usr/sbin/umount

function fatal
{
	rmdir $tb_mountpoint
	typeset msg="$*"
	[[ -z "$msg" ]] && msg="test failed"
	echo "$tb_arg0: test failed $msg" >&2
	exit 1
}

function check_mount
{
	mkdir -p $tb_mountpoint || fatal \
	    "failed to make mountpoint $tb_mountpoint"
	$tb_mount -F tmpfs swap $tb_mountpoint || fatal \
	    "failed to mount tmpfs, check user perms"
	$tb_umount $tb_mountpoint || fatal \
	    "failed to unmount test point"
}

function test_one
{
	typeset opts=$1

	[[ -z "$opts" ]] && fatal "missing required opts"
	$tb_mount -F tmpfs -o $opts swap $tb_mountpoint 2>/dev/null
	if [[ $? -eq 0 ]]; then
		$tb_umount $tb_mountpoint
		fatal "successfully mounted with opts $opts, expected failure"
	fi
}

check_mount

#
# Test invalid percentages.
#
test_one "size=-5%"
test_one "size=200%"
test_one "size=55.55555%"
test_one "size=100.0%"
test_one "size=bad%"
test_one "size=30g%"
test_one "size=%"
test_one "size=%wat"

#
# Test invalid sizes. Only kmg are valid prefixes.
#
test_one "size=hello;world"
test_one "size=0xnope"
test_one "size=3.14g"
test_one "size=3;14"
test_one "size=thisisanormalsize"
test_one "size="
test_one "size=100mtry"

#
# Now, we need to try and trigger a bunch of overflow. We're going to do
# this assuming we're on a 64-bit kernel (which will always overflow a
# 32-bit kernel).
#
test_one "size=20000000000000000000"
test_one "size=1ggggggggggggggggggg"
test_one "size=1mmmmmmmmmmmmmmmmmmm"
test_one "size=1kkkkkkkkkkkkkkkkkkk"
test_one "size=1kkkkkkkkkkkkkkkkkkk"
test_one "size=18014398509481983k"
test_one "size=17592186044416m"
test_one "size=17179869185g"
test_one "size=17179869184g"

#
# Let's throw a couple bad modes around while we're here.
#
test_one "mode=17777"
test_one "mode=27777"
test_one "mode=37777"
test_one "mode=47777"
test_one "mode=57777"
test_one "mode=67777"
test_one "mode=77777"
test_one "mode=87777"
test_one "mode=97777"
test_one "mode=asdf"
test_one "mode=deadbeef"
test_one "mode=kefka"

rmdir $tb_mountpoint
