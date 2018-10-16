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
# ID: misc_001
#
# DESCRIPTION:
#        Verify can truncate files on the smbfs
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. truncate and rm can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="misc001"
tc_desc=" Verify can truncate files on the smbfs"
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
	cti_fail "FAIL: smbmount  can't mount the public share"
	return
else
	cti_report "PASS: smbmount  can mount the public share"
fi

# truncate file
cmd="file_trunc -f 4194304 -b 8192 -c 100 -s 0 -o 10 $TMNT/test_file"
cti_execute_cmd $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: truncate file failed"
	return
else
	cti_report "PASS: truncate file succeeded"
fi

cti_execute_cmd "rm $TMNT/test_file"
smbmount_clean $TMNT

cti_pass "${tc_id}: PASS"
