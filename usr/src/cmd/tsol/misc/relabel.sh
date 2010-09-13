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
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# This program is invoked to do the actual file transfer
# associated with an invocation of the setflabel(3TSOL) function.
#
# It executes in the global zone with the user's identity and 
# basic privileges plus the file_dac_search privilege.  This
# script should not not assume that stdio is available or that
# any particular environment variables are set.  In particular,
# the DISPLAY variable will not normally be pre-set.
#
# Authorization checks and zone limit privilege checks
# are done before calling this script. Auditing is done
# upon return.
#
##############################################################
#
# Calling sequence:
#
# $1 is the global zone real pathname of the source file
#
# $2 is the global zone real destination pathname
#
# Exit status:
#
# 0 on success
# 1 on error
#
##############################################################
#
# This script can be customized or replaced to perform
# additional processing such as tranquility checks, dirty
# word filtering, copying instead of moving, etc.
#
# By default it does a check to determine if the source file
# is in use by calling fuser(1). However, this check
# does not work for filesystems that were automounted in
# non-global zones.
#
# Perform a simple tranquility check
#
inuse=`/usr/sbin/fuser $1 2>&1 | /usr/bin/cut -d ":" -f2`
if [ $inuse ]; then
#
#	file is in use
#
	exit 1
else
#
# Perform an inter-zone move of the data
	/usr/bin/mv $1 $2
	exit $?
fi
