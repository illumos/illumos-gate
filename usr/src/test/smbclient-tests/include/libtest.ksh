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
# Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
#

#
# common includes for smbclint-tests
#

. ${STF_SUITE}/include/default_cfg.ksh

. ${STF_SUITE}/include/services_common.ksh
. ${STF_SUITE}/include/smbutil_common.ksh
. ${STF_SUITE}/include/utils_common.ksh
. ${STF_SUITE}/include/smbmount_common.ksh
. ${STF_SUITE}/include/xattr_common.ksh

. ${STF_TOOLS}/contrib/include/ctiutils.shlib
