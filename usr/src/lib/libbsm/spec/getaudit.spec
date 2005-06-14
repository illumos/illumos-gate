#
# Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License, Version 1.0 only
# (the "License").  You may not use this file except in compliance
# with the License.
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
#pragma ident	"%Z%%M%	%I%	%E% SMI"
#
# lib/libbsm/spec/getaudit.spec

function	getaudit
include		<sys/param.h>, <bsm/audit.h>
declaration	int getaudit(struct auditinfo *info)
version		SUNW_0.7
errno		EFAULT EPERM EOVERFLOW
exception	$return == -1
end		

function	setaudit
include		<sys/param.h>, <bsm/audit.h>
declaration	int setaudit(struct auditinfo *info)
version		SUNW_0.7
errno		EFAULT EPERM
exception	$return == -1
end		

function	getaudit_addr
include		<sys/param.h>, <bsm/audit.h>
declaration	int getaudit_addr(struct auditinfo_addr *info, int len)
version		SUNW_1.2
errno		EFAULT EPERM
exception	$return == -1
end		

function	setaudit_addr
include		<sys/param.h>, <bsm/audit.h>
declaration	int setaudit_addr(struct auditinfo_addr *info, int len)
version		SUNW_1.2
errno		EFAULT EPERM
exception	$return == -1
end		

