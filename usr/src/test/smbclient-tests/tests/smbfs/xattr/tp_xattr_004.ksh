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
# ID:  xattr_004
#
# DESCRIPTION:
# Verify from local tmpfs with xattrs copied to mount point retain xattr info
# and from mount point with xattrs copied to local tmpfs retain xattr info
#
# STRATEGY:
#	1. Create files in local tmpfs with xattrs
#       2. Copy those files to mount point
#	3. Ensure the xattrs can be retain
#	4. Do the same in reverse.
#

. $STF_SUITE/include/libtest.ksh

tc_id=xattr_004
tc_desc="Verify from local tmpfs with xattrs copied to mount point retain xattr info\
	  and from mount point with xattrs copied to local tmpfs retain xattr info"
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
	cti_fail "FAIL: smbmount can't mount the public share unexpectedly"
	return
else
	cti_report "PASS: smbmount can mount the public share as expected"
fi

smbmount_getmntopts $TMNT |grep /xattr/ >/dev/null
if [[ $? != 0 ]]; then
	smbmount_clean $TMNT
	cti_unsupported "UNSUPPORTED (no xattr in this mount)"
	return
fi

# Create files in local tmpfs, and set some xattrs on them.

cti_execute_cmd "touch $TDIR/test_file1"
cti_execute_cmd "runat $TDIR/test_file1 cp /etc/passwd ."

# copy local tmpfs to mount point

cti_execute_cmd "cp -@ $TDIR/test_file1 $TMNT"

# ensure the xattr information has been copied correctly

cti_execute_cmd "runat $TMNT/test_file1 diff passwd /etc/passwd"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: file xattr not retain when it copy from local tmpfs to mount point"
	return
else
	cti_report "PASS: file xattr retain when it copy from local tmpfs to mount point"
fi
# copy mount point to local tmpfs

cti_execute_cmd "cp -@ $TMNT/test_file1 $TDIR/test_file2"
# ensure the xattr information has been copied correctly

cti_execute_cmd "runat $TDIR/test_file2 diff passwd /etc/passwd"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: file xattr not retain when it copy from mount point to local tmpfs"
	return
else
	cti_report "PASS: file xattr retain when it copy from mount point to local tmpfs"
fi

cti_execute_cmd "rm -rf $TDIR/*"

smbmount_clean $TMNT
cti_pass "$tc_id: PASS"
