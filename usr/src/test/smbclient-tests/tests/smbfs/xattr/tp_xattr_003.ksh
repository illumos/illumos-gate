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
# ID:  xattr_003
#
# DESCRIPTION:
# Verify from local tmpfs with xattrs moved to mount point preserve/omit xattrs
# and from mount point with xattrs moved to local tmpfs preserve/omit xattrs
#
# STRATEGY:
#	1. Create a file, and set an with an xattr
#       2. Move the file to mount point
#	3. Check that mv doesn't have any flags to preserve/omit xattrs -
#          they're always moved.
#	4. Do the same in reverse.
#

. $STF_SUITE/include/libtest.ksh

tc_id=xattr_003
tc_desc="Verify from local tmpfs with xattrs moved to mount point preserve/omit xattrs\
	and from mount point with xattrs moved to local tmpfs preserve/omit xattrs"

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

#create a file in local file system with a xattr and then mv it to mount point

cti_execute_cmd "touch $TDIR/test_file"
create_xattr $TDIR/test_file passwd /etc/passwd
cti_execute_cmd "mv $TDIR/test_file $TMNT/test_file"
if [[ $? != 0 ]]; then
	 cti_fail "FAIL: can't move the file with xattr from local to mount point unexpectedly
"
	 return
else
	 cti_report "PASS: can move the file with xattr from local to mount point as expected"
fi
cti_execute FAIL "runat $TMNT/test_file diff passwd /etc/passwd"
if [[ $? != 0 ]]; then
	 cti_fail "FAIL: after move the xattr has changed unexpectedly"
	 return
else
	 cti_report "PASS: after move the xattr has not changed as expected"
fi
cti_execute_cmd "rm -rf $TDIR/*"
cti_execute_cmd "rm -rf $TMNT/*"

#create a file in mount point with a xattr and then mv it to local file system

cti_execute_cmd "touch $TMNT/test_file"
create_xattr $TMNT/test_file passwd /etc/passwd
cti_execute_cmd "mv $TMNT/test_file $TDIR/test_file"
if [[ $? != 0 ]]; then
	 cti_fail "FAIL: can't move the file with xattr from mount point to local unexpectedly"
	 return
else
	 cti_report "PASS: can move the file with xattr from mount point to local as expected"
fi
cti_execute FAIL "runat $TDIR/test_file diff passwd /etc/passwd"
if [[ $? != 0 ]]; then
	 cti_fail "FAIL: after move the xattr has changed unexpectedly"
	 return
else
	 cti_report "PASS: after move the xattr has not changed as expected"
fi

smbmount_clean $TMNT
cti_pass "$tc_id: PASS"
