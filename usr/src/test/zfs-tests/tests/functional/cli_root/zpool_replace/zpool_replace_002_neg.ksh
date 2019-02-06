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
# Copyright 2019 Joyent, Inc.
#

. $STF_SUITE/include/libtest.shlib

#
# DESCRIPTION:
#
# zpool replace returns an error when spare device is faulted.
#
# STRATEGY:
# 1. Add hot spare to pool
# 2. Fault the hot spare device
# 3. Attempt to replace a device in a pool with the faulted spare
# 4. Verify the 'zpool replace' command fails
#

SPARE=${DISKS##* }
DISK=${DISKS%% *}

verify_runnable "global"
log_must zpool add $TESTPOOL spare $SPARE
log_assert "zpool replace returns an error when the hot spare is faulted"

log_must zinject -d $SPARE -A fault $TESTPOOL
log_mustnot zpool replace $TESTPOOL $DISK $SPARE

log_pass "zpool replace returns an error when the hot spare is faulted"
