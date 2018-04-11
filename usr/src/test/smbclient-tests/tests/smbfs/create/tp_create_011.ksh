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
# ID: create_011
#
# DESCRIPTION:
#        Verify can create tar file on the smbfs
#
# STRATEGY:
#       1. run "mount -F smbfs //server/public /export/mnt"
#       2. tar and rm can get the right message
#

. $STF_SUITE/include/libtest.ksh

tc_id="create011"
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

# reference dir for copy (ro)
refdir=/kernel/misc

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

cti_execute_cmd "tar cf $TDIR/kernel.tar $refdir"
cti_execute_cmd "tar cf $TMNT/kernel.tar $refdir"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the tar cf command is failed "
	return
else
	cti_report "PASS: the tar cf command is successful"
fi

cti_execute_cmd "cmp -s $TMNT/kernel.tar $TDIR/kernel.tar"
if [[ $? != 0 ]]; then
	cti_fail "FAIL: the two tar files are different"
	return
else
	cti_report "PASS: the two tar files are same"
fi

cti_execute_cmd "rm -rf  $TMNT/kernel.tar $TDIR/kernel.tar"

smbmount_clean $TMNT
cti_pass "${tc_id}: PASS"
