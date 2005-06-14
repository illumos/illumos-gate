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
# lib/libsec/spec/acl.spec

function	aclcheck
include		<sys/acl.h>
declaration	int aclcheck(aclent_t *aclbufp,  int nentries,  int *which)
version		SUNW_0.9
errno		EINVAL
exception	($return == GRP_ERROR	|| \
			$return == USER_ERROR	|| \
			$return == CLASS_ERROR	|| \
			$return == OTHER_ERROR	|| \
			$return == DUPLICATE_ERROR	|| \
			$return == ENTRY_ERROR	|| \
			$return == MISS_ERROR	|| \
			$return == MEM_ERROR)
end		

function	aclsort
include		<sys/acl.h>
declaration	int aclsort(int nentries, int calclass, aclent_t *aclbufp)
version		SUNW_0.9
exception	$return == -1
end		

function	acltomode
include		<sys/types.h>, <sys/acl.h>
declaration	int acltomode(aclent_t *aclbufp, int nentries, mode_t *modep)
version		SUNW_0.9
errno		EINVAL
exception	$return == -1
end		

function	aclfrommode
include		<sys/types.h>, <sys/acl.h>
declaration	int aclfrommode(aclent_t *aclbufp, int  nentries, mode_t *modep)
version		SUNW_0.9
errno		EINVAL
exception	$return == -1
end		

function	acltotext
include		<sys/acl.h>
declaration	char *acltotext(aclent_t *aclbufp, int aclcnt)
version		SUNW_0.9
exception	$return == 0
end		

function	aclfromtext
include		<sys/acl.h>
declaration	aclent_t *aclfromtext(char *acltextp, int *aclcnt)
version		SUNW_0.9
exception	$return == 0
end		

