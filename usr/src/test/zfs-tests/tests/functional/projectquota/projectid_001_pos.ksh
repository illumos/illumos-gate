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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2017 by Fan Yong. All rights reserved.
# Copyright 2019 Joyent, Inc.
#

. $STF_SUITE/tests/functional/projectquota/projectquota_common.kshlib

#
#
# DESCRIPTION:
#	Check project ID/flags can be set/inherited properly
#
#
# STRATEGY:
#	1. Create a regular file and a directroy.
#	2. Set project ID on both directroy and regular file.
#	3. New created subdir or regular file should inherit its parent's
#	   project ID if its parent has project inherit flag.
#	4. New created subdir should inherit its parent project's inherit flag.
#

function cleanup
{
	log_must rm -f $PRJFILE
	log_must rm -rf $PRJDIR
}

log_onexit cleanup

log_assert "Check project ID/flags can be set/inherited properly"

log_must touch $PRJFILE
log_must mkdir $PRJDIR

# log_must chattr -p $PRJID1 $PRJFILE
log_must zfs project -s -p $PRJID1 $PRJFILE
# log_must eval "lsattr -p $PRJFILE | grep $PRJID1 | grep -v '\-P[- ]* '"
log_must eval "zfs project $PRJFILE | grep $PRJID1"
# log_must chattr -p $PRJID1 $PRJDIR
log_must zfs project -s -p $PRJID1 $PRJDIR
# log_must eval "lsattr -pd $PRJDIR | grep $PRJID1 | grep -v '\-P[- ]* '"
log_must eval "zfs project $PRJDIR | grep $PRJID1"

# "-1" is invalid project ID, should be denied
# log_mustnot chattr -p -1 $PRJFILE
log_mustnot zfs project -s -p -1 $PRJFILE
# log_must eval "lsattr -p $PRJFILE | grep $PRJID1 | grep -v '\-P[- ]* '"
log_must eval "zfs project $PRJFILE | grep $PRJID1"

log_must mkdir $PRJDIR/dchild
# log_must eval "lsattr -pd $PRJDIR/dchild | grep $PRJID1 | grep '\-P[- ]* '"
log_must eval "zfs project -d $PRJDIR/dchild | grep $PRJID1"
log_must touch $PRJDIR/fchild
# log_must eval "lsattr -p $PRJDIR/fchild | grep $PRJID1"
log_must eval "zfs project $PRJDIR/fchild | grep $PRJID1"

log_must touch $PRJDIR/dchild/foo
# log_must eval "lsattr -p $PRJDIR/dchild/foo | grep $PRJID1"
log_must eval "zfs project $PRJDIR/dchild/foo | grep $PRJID1"

# do not support project ID/flag on block special file
log_must mknod $PRJDIR/dchild/b_foo b 124 124
# log_mustnot lsattr -p $PRJDIR/dchild/b_foo
# log_mustnot chattr -p 123 $PRJDIR/dchild/b_foo
log_mustnot zfs project -s -p 123 $PRJDIR/dchild/b_foo

# do not support project ID/flag on character special file
log_must mknod $PRJDIR/dchild/c_foo c 125 125
# log_mustnot lsattr -p $PRJDIR/dchild/c_foo
# log_mustnot chattr -p 123 $PRJDIR/dchild/c_foo
log_mustnot zfs project -s -p 123 $PRJDIR/dchild/c_foo

log_pass "Check project ID/flags can be set/inherited properly"
