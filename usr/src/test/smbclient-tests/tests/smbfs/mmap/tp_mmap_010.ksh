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

# Copyright 2018 Nexenta Systems, Inc.  All rights reserved.

#
# mmap test purpose
#
# __stc_assertion_start
#
# ID: mmap_010
#
# DESCRIPTION:
#        Verify file read/write is coherent with mmap.
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. open and mmap a test file
#       3. write something into test file, then check the result through mmap
#	4. memset some parts of mmaped addr, then check the result through
#	   file read
#	5. close test file
# KEYWORDS:
#
# TESTABILITY: explicit
#
# __stc_assertion_end
#

. $STF_SUITE/include/libtest.ksh

tc_id="mmap010"
tc_desc=" Verify file read/write is coherent with mmap"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

# Note: size should be prime (see cp_mmap)
size=1123k

server=$(server_name) || return

testdir=$TDIR
mnt_point=$TMNT

testdir_init $testdir
smbmount_clean $mnt_point
smbmount_init $mnt_point

test_file="tmp010"

cmd="mount -F smbfs //$TUSER:$TPASS@$server/public $mnt_point"
cti_execute -i '' FAIL $cmd
if (($?!=0)); then
	cti_fail "FAIL: $cmd"
	return
else
	cti_report "PASS: $cmd"
fi

# open, mmap a file in smbfs, then perform the 2 tests mentioned above
cti_execute FAIL "rw_mmap -n $size -f ${mnt_point}/${test_file}"
if (($?!=0)); then
	cti_fail "FAIL: $cmd"
	return
else
	cti_report "PASS: $cmd"
fi

# do the same thing in local file, for comparison
cti_execute FAIL "rw_mmap -n $size -f ${testdir}/${test_file}"
if (($?!=0)); then
	cti_fail "FAIL: $cmd"
	return
else
	cti_report "PASS: $cmd"
fi

# diff the local file & smbfs file

cti_execute_cmd "sum ${testdir}/${test_file}"
read sum1 cnt1 junk < cti_stdout
cti_report "local sum $sum1 $cnt1"

cti_execute_cmd "sum ${mnt_point}/${test_file}"
read sum2 cnt2 junk < cti_stdout
cti_report "smbfs sum $sum2 $cnt2"

if [[ $sum1 != $sum2 ]] ; then
        cti_fail "FAIL: the files are different"
        return
else
        cti_report "PASS: the files are the same"
fi

cti_execute_cmd "rm -rf $testdir/*"
cti_execute_cmd "rm -f ${mnt_point}/${test_file}"

smbmount_clean $mnt_point

cti_pass "${tc_id}: PASS"
