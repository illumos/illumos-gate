#!/bin/ksh -p
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#

#
# Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
#

#
# ID: misc_002
#
# DESCRIPTION:
#	Verify attribute cache invalidation after
#	some higher-level directory is renamed.
#
# STRATEGY:
#	1. run "mount -F smbfs //server/public /export/mnt"
#	2. mkdir a/b/c/d
#	3. mv a z
#	4. mkdir a
#	5. verify stat of a/b/c shows ENOENT
#	(All steps must be completed in less than a few seconds.)
#

. $STF_SUITE/include/libtest.ksh

tc_id="misc002"
tc_desc=" Verify attribute cache invalidation under renamed directory"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name)||return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the public share"
	return
else
	cti_report "PASS: smbmount can mount the public share"
fi

cmd="mkdir -p $TMNT/a/b/c"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
fi

cmd="mv $TMNT/a $TMNT/z"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
fi

cmd="mkdir $TMNT/a"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
fi

# a should exist, but should have nothing under it.
if [[ -d $TMNT/a/b/c ]] ; then
	cti_fail "FAIL: a/b/c/d still exists"
	return
fi

# z should exist, and z/b/c
if [[ ! -d $TMNT/z ]] ; then
	cti_fail "FAIL: dir 'z' missing"
	return
fi
if [[ ! -d $TMNT/z/b/c ]] ; then
	cti_fail "FAIL: dir 'z/b/c/d' missing"
	return
fi

cti_execute_cmd "rm -rf $TMNT/*"

smbmount_clean $TMNT
cti_pass "$tc_id: PASS"
