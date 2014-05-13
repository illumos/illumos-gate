#!/bin/sh
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
# Copyright 2014 Joyent, Inc.  All rights reserved.
#

LD_LIBRARY_PATH=/usr/lib/brand/lx
LD_PRELOAD=/native/usr/lib/brand/lx/lx_thunk.so.1
LD_BIND_NOW=1
export LD_LIBRARY_PATH LD_PRELOAD LD_BIND_NOW
export SMF_FMRI="svc:/network/ip-interface-management:default"

exec /native/usr/lib/brand/lx/lx_native /native/lib/inet/ipmgmtd
