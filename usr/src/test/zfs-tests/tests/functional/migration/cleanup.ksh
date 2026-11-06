#!/usr/bin/ksh -p
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
# Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

#
# Copyright (c) 2013, 2016 by Delphix. All rights reserved.
# Copyright 2026 Oxide Computer Company
#

. $STF_SUITE/include/libtest.shlib
. $STF_SUITE/tests/functional/migration/migration.cfg

verify_runnable "global"

ismounted $NONZFS_TESTDIR ufs
(( $? == 0 )) && log_must umount -f $NONZFS_TESTDIR
lofiadm $NONZFS_FILE > /dev/null 2>&1 && log_must lofiadm -d $NONZFS_FILE
rm -f $NONZFS_FILE

ismounted $TESTPOOL/$TESTFS
[[ $? == 0 ]] && log_must zfs umount -f $TESTDIR
destroy_pool $TESTPOOL
log_must rm -rf $TESTDIR

log_pass
