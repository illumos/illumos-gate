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
# ID:  xattr_002
#
# DESCRIPTION:
# Verify trying to read a non-existent xattr should fail.
#
# STRATEGY:
#	1. Create a file
#       2. Try to read a non-existent xattr, check that an error is returned.
#

. $STF_SUITE/include/libtest.ksh

tc_id=xattr_002
tc_desc="Verify trying to read a non-existent xattr should fail"
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

# create a file

cti_execute_cmd "touch $TMNT/test_file"

# should not find an xattr file
cti_execute_cmd "runat $TMNT/test_file cat not-here.txt"
if [[ $? == 0 ]]; then
	cti_fail "FAIL: A read of a non-existent xattr succeeded unexpectedly"
	return
else
	cti_report "PASS: A read of a non-existent xattr fail as expected"
fi

smbmount_clean $TMNT
cti_pass "$tc_id: PASS"
