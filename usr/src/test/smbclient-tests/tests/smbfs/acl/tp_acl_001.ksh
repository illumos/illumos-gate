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
# ID: acl_001
#
# DESCRIPTION:
#	Read ACLs in an smbfs mount using "ls"
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. try "ls -V" etc.
#

. $STF_SUITE/include/libtest.ksh

tc_id="acl001"
tc_desc="Verify we can view ACLs with ls"
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

# create a file
cmd="cp /etc/passwd $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi

# verify "ls -l" shows a plus sign
cmd="ls -l $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi
read mode junk < cti_stdout
case "$mode" in
*+)
	cti_report "PASS: have plus sign"
	;;
*)
	cti_fail "FAIL: no plus sign"
	smbmount_clean $TMNT
	return
esac

# verify "ls -V" shows an ACL
cmd="ls -V $TMNT/$tc_id"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: $cmd"
	smbmount_clean $TMNT
	return
fi
cnt=$(wc -l < cti_stdout)
if [[ "$cnt" -lt 2 ]] ; then
	cti_fail "FAIL: no ACEs found"
	smbmount_clean $TMNT
	return
fi

cti_execute_cmd "rm $TMNT/$tc_id"
smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
