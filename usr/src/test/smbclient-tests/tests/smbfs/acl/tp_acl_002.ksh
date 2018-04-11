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
# ID: acl_002
#
# DESCRIPTION:
#	Copy ACLs to/from and smbfs mount with cpio
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. create a file, make sure it has an ACL
#       3. cpio -oP -O archive.cpio
#	4. remove the file
#	5. cpio -iP -I archive.cpio
#	6. verify extracted ACL matches original
#

. $STF_SUITE/include/libtest.ksh

tc_id="acl002"
tc_desc="Verify we can save/restore ACLs with cpio"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs -oacl //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	return
else
	cti_report "PASS: $cmd"
fi

# Require that the mount supports ACLs
smbmount_getmntopts $TMNT |grep /acl/ >/dev/null
if [[ $? != 0 ]]; then
	smbmount_clean $TMNT
	cti_unsupported "UNSUPPORTED (no ACLs in this mount)"
	return
fi

# create a file, make sure it has an ACL
cmd="cp /etc/passwd $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi
cmd="ls -V $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi
tail +2 cti_stdout > acl_save

#       3. cpio -oP -O archive.cpio
cmd="echo $tc_id | \
 ( cd $TMNT ; cpio -ocP -O $TDIR/$tc_id.cpio )"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi

#	4. remove the file
cti_execute_cmd "rm -f $TMNT/$tc_id"

#	5. cpio -iP -I archive.cpio
cmd="( cd $TMNT ; cpio -icP -I $TDIR/$tc_id.cpio )"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi

#	6. verify extracted ACL matches original
cmd="ls -V $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi
tail +2 cti_stdout > acl_test

cmd="diff acl_save acl_test"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi

cti_execute_cmd "rm $TDIR/$tc_id.cpio"
cti_execute_cmd "rm $TMNT/$tc_id"
smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
