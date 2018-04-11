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
# ID:  xattr_007
#
# DESCRIPTION:
# Verify mkdir and various mknods fail inside the xattr namespace
#
# STRATEGY:
#	1. Create a file and add an xattr to it (to ensure the namespace exists)
#       2. Verify that mkdir fails inside the xattr namespace
#	3. Verify that various mknods fails inside the xattr namespace
#

. $STF_SUITE/include/libtest.ksh

tc_id=xattr_007
tc_desc="Verify mkdir and various mknods fail inside the xattr namespace"
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

# Create files set some xattrs on them.

cti_execute_cmd "touch $TMNT/test_file"
create_xattr $TMNT/test_file passwd /etc/passwd

# Try to create directory in the xattr namespace

cti_execute_cmd "runat $TMNT/test_file mkdir foo"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: mkdir inside the xattr namespace succeeded unexpectedly"
	return
else
	cti_report "PASS: mkdir inside the xattr namespace failed as expected"
fi
# Try to create a range of different filetypes in the xattr namespace

cti_execute_cmd "runat $TMNT/test_file mknod block b 888 888"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: mknod block file succeeded unexpectedly inside the xattr namespace"
	return
else
	cti_report "PASS: mknod block file failed as expected inside the xattr namespace"
fi

cti_execute_cmd "runat $TMNT/test_file mknod char c"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: mknod char file succeeded unexpectedly inside the xattr namespace"
	return
else
	cti_report "PASS: mknod char file failed as expected inside the xattr namespace"
fi

cti_execute_cmd "runat $TMNT/test_file mknod fifo p"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: mknod fifo file succeeded unexpectedly inside the xattr namespace"
	return
else
	cti_report "PASS: mknod fifo file failed as expected inside the xattr namespace"
fi

smbmount_clean $TMNT
cti_pass "$tc_id: PASS"
