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
# ID: create_010
#
# DESCRIPTION:
#        Verify can create and copy 200M file on the smbfs
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. create, cp and rm can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="create010"
tc_desc="Verify can create files on the smbfs"
print_test_case $tc_id - $tc_desc

if [[ $STC_CIFS_CLIENT_DEBUG == 1 ]] || \
	[[ *:${STC_CIFS_CLIENT_DEBUG}:* == *:$tc_id:* ]]; then
    set -x
fi

if [[ -n "$STC_QUICK" ]] ; then
  cti_notinuse "${tc_id}: skipped (STC_QUICK)"
  return
fi

server=$(server_name) || return

testdir_init $TDIR
smbmount_clean $TMNT
smbmount_init $TMNT

cmd="mount -F smbfs //$TUSER:$TPASS@$server/public $TMNT"
cti_execute -i '' FAIL $cmd
if [[ $? != 0 ]]; then
	cti_fail "FAIL: smbmount can't mount the public share"
	return
else
	cti_report "PASS: smbmount can mount the public share"
fi

cti_execute_cmd "rm -rf $TMNT/*"
cti_execute_cmd "rm -rf $TDIR/*"

# create file
mkfile 20m $TDIR/file
cti_execute_cmd "cp $TDIR/file $TMNT/file &"
pid1=$!

sleep 3
tail -f $TMNT/file >/dev/null 2>&1 &
pid2=$!

wait $pid1
if [[ $? != 0 ]]; then
	cti_fail "FAIL: failed to copy the 20M file"
	return
else
	cti_report "PASS: copied the 20M file successfully"
fi

sleep 5

cti_execute_cmd "kill -9 $pid2"

sleep 5

cti_execute_cmd "rm $TDIR/file"

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
