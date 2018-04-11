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
# ID: mkdir_004
#
# DESCRIPTION:
#        Verify can muti dir operation on the smbfs
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. mkdir and rmdir can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="mkdir004"
tc_desc=" Verify can muti dir operation on the smbfs"
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
	cti_fail "FAIL: smbmount  can mount the public share"
	return
else
	cti_report "PASS: smbmount  can't mount the public share"
fi

cpath=$(pwd)
cti_execute_cmd "rm -rf $TMNT/*"

# create 40 testdir
i=1
while ((i<40)); do
	cti_execute_cmd "mkdir $TMNT/testdir$i"
	if [[ $? != 0 ]]; then
		cti_fail "FAIL: mkdir testdir$i faled"
		return
	fi
	((i=i+1))
done

cti_execute FAIL "ls -la $TMNT"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: ls -la failed"
	return
else
	cti_report "PASS: ls -la succeeded"
fi

# del the 40 testdir
i=1
while ((i<40)); do
	cti_execute_cmd "rmdir $TMNT/testdir$i"
	if [[ $? != 0 ]]; then
		cti_fail "FAIL: rmdir testdir$i failed"
		return
	fi
	((i=i+1))
done

# create 40 deep dir
cdir=$(pwd)
i=1
d=testdir_a1
while ((i<40)); do
	cti_execute_cmd "mkdir $TMNT/$d"
	if [[ $? != 0 ]]; then
		cti_fail "FAIL: mkdir testdir_a$i failed"
		return
	fi
	((i=i+1))
	d=$d/testdir_a$i
done

# find on dirs
cti_execute FAIL "find $TMNT"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: find . failed"
	return
else
	cti_report "PASS: find . succeeded"
fi

# clean up
cti_execute_cmd "rm -rf $TMNT/*"
smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
