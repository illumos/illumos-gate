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
# ID: acl_003
#
# DESCRIPTION:
#	Verify we can modify an ACL (add everyone ACE)
#
# STRATEGY:
#       1. run "mount -F smbfs ..."
#       2. create a file, make sure it has an ACL
#       3. chmod A+everyone@:rxaRcs::allow file
#	4. verify everyone line is there
#

. $STF_SUITE/include/libtest.ksh

tc_id="acl003"
tc_desc="Verify we can modify an ACL (add everyone ACE)"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

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

#       3. chmod A+everyone@:rxaRcs::allow file
cmd="chmod A+everyone@:rxaRcs::allow $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi

#	4. verify everyone line is there
cmd="ls -V $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi
tail +2 cti_stdout > acl_test

# The new ACL should be different, and should contain "everyone@"
cmd="diff acl_save acl_test"
cti_execute_cmd $cmd
if [[ $? == 0 ]]; then
	cti_fail "FAIL: ACL should have changed"
	smbmount_clean $TMNT
	return
fi

grep ' everyone@:' acl_test >/dev/null
if [[ $? != 0 ]]; then
	cti_fail "FAIL: did not find new ACE"
	smbmount_clean $TMNT
	return
fi

cti_execute_cmd "rm $TMNT/$tc_id"
smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
