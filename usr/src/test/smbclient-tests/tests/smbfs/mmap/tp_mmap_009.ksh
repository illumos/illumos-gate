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
# ID: mmap_009
#
# DESCRIPTION:
#        Verify smbfs will help sync the dirty pages to the file and close it, including otW close, if the userland does not explicitly do it.
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. mkfile in smbfs
#	3. open, mmap the file, then write some data into the mapped addr
#	4. exit without close the file
#	5. verify the data successfully written back to smb server
# KEYWORDS:
#
# TESTABILITY: explicit
#
# __stc_assertion_end
#

. $STF_SUITE/include/libtest.ksh

tc_id="mmap009"
tc_desc=" Verify smbfs will sync the dirty pages to the file and close it,
 including otW close, if the userland does not explicitly do it."
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

server=$(server_name) || return

testdir=$TDIR
mnt_point=$TMNT

testdir_init $testdir
smbmount_clean $mnt_point
smbmount_init $mnt_point

test_file="tmp009"

cmd="mount -F smbfs //$TUSER:$TPASS@$server/public $mnt_point"
cti_execute -i '' FAIL $cmd
if (($?!=0)); then
	cti_fail "FAIL: $cmd"
	return
else
	cti_report "PASS: $cmd"
fi

# open, mmap a file in smbfs, then write something into it,
# exit without msync/munmap/close
cti_execute FAIL "no_close ${mnt_point}/${test_file}"
if (($?!=0)); then
	cti_fail "FAIL: $cmd"
	return
else
	cti_report "PASS: $cmd"
fi

# do the same thing in local file, for comparison
cti_execute FAIL "no_close ${testdir}/${test_file}"
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
