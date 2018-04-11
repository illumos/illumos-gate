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
# ID: error_001
#
# DESCRIPTION:
#        Verify link error on the smbfs
#
# STRATEGY:
#        1. run "mount -F smbfs //server/public $TMNT" on the smb
#        2. touch file and create link
#	 3. The "ln -s" can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="error001"
tc_desc=" Verify link error on the smbfs"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "smbmount  can't mount the public share"
	return
else
	cti_report "smbmount  can mount the public share"
fi

# cleanup
cti_execute_cmd "rm -rf $TMNT/*"

cti_execute_cmd "touch $TMNT/file"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: touch file failed on smbfs"
	return
else
	cti_report "PASS: touch file succeeded on smbfs"
fi

cti_execute_cmd "(cd $TMNT; ln file file_ln)"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: ln file file_ln succeeded on smbfs"
	return
else
	cti_report "PASS: ln file file_ln failed on smbfs"
fi

cti_execute_cmd "(cd $TMNT; ln -s file file_ln)"
if [[ $? == 0 ]]; then
	cti_fail "ln -s file file_ln succeeded on smbfs"
	return
else
	cti_report "ln -s file file_ln failed on smbfs"
fi
cti_execute_cmd "rm $TMNT/file"

cti_execute_cmd "mkdir $TMNT/dir"
if [[ $? != 0 ]]; then
	cti_fail "mkdir dir failed on smbfs"
	return
else
	cti_report "mkdir dir succeeded on smbfs"
fi

cti_execute_cmd "(cd $TMNT; ln -s dir dir_ln)"
if [[ $? == 0 ]]; then
	cti_fail "ln -s dir dir_ln succeeded on smbfs"
	return
else
	cti_report "ln -s dir dir_ln failed on smbfs"
fi

cti_execute_cmd "rmdir $TMNT/dir"

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
