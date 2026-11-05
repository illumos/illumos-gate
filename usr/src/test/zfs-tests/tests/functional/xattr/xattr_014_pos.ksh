#!/bin/ksh -p
#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2026 Oxide Computer Company
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/xattr/xattr_common.kshlib

#
# DESCRIPTION:
# Removing a file frees its extended attribute directory and the
# attributes in it, without an unmount.
#
# STRATEGY:
#	1. Create a file in a new project and add xattrs to it
#	2. Verify that the project's object count includes them
#	3. Remove the file and sync the pool
#	4. Verify that the project uses no objects or space
#

typeset prj=4014
typeset file=$TESTDIR/myfile.$$

function cleanup {
	rm -f $file
}

log_assert "Removing a file frees its extended attributes"
log_onexit cleanup

log_must touch $file
log_must zfs project -s -p $prj $file
create_xattr $file a1 /etc/passwd
create_xattr $file a2 /etc/passwd
create_xattr $file a3 /etc/passwd
sync_pool $TESTPOOL

# the file, its xattr directory and the 3 attributes
typeset objs=$(get_prop projectobjused@$prj $TESTPOOL/$TESTFS)
[[ $objs == 5 ]] || log_fail "projectobjused is $objs before rm, expected 5"

log_must rm $file
sync_pool $TESTPOOL

objs=$(get_prop projectobjused@$prj $TESTPOOL/$TESTFS)
typeset used=$(get_prop projectused@$prj $TESTPOOL/$TESTFS)
[[ $objs == 0 && $used == 0 ]] || \
    log_fail "project still uses $objs objects and $used bytes after rm"

log_pass "Removing a file frees its extended attributes"
