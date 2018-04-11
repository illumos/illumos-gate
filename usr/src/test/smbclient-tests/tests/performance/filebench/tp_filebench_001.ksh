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
# ID: filebench_001
#
# DESCRIPTION:
#        Verify filebench fileio testing on the smbfs
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. run fileio filebench can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="filebench_001"
tc_desc=" Verify filebench on the smbfs"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT
sleep 3

cmd="ls -l $filebenchdir/filebench"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_report "FAIL: There is no filebench package, please install it."
	cti_untested $tc_id
	return
fi

cmd="mount -F smbfs //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd

if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the share \"public\" "
	return
else
	cti_report "PASS: smbmount mount the share successfully"
fi


rm -rf $TMNT/*

#run fileio filebench
cti_execute_cmd $filebenchdir/filebench ${STF_SUITE}/config/fileio
if [[ $? != 0 ]]; then
	cti_fail "FAIL: filebench fileio failed"
	return
else
	cti_report "PASS: filebench fileio successfully"
fi

cti_execute_cmd rm -rf $TMNT/*
smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
