#
# Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

function	acl_check
include		<sys/acl.h>
declaration	int acl_check(acl_t *aclp, int flag);
version		SUNW_1.2
errno		EINVAL
exception	 ($return == EACL_GRP_ERROR   || \
	$return == EACL_USER_ERROR   || \
	$return == EACL_OTHER_ERROR  || \
	$return == EACL_CLASS_ERROR  || \
	$return == EACL_DUPLICATE_ERROR      || \
	$return == EACL_MISS_ERROR  || \
	$return == EACL_MEM_ERROR   || \
	$return == EACL_ENTRY_ERROR)	|| \
	$return == EACL_INHERIT_ERROR || \
	$return == EACL_FLAGS_ERROR || \
	$return == EACL_PERM_MASK_ERROR || \
	$return == EACL_COUNT_ERROR 
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

function	acl_get
include		<sys/acl.h>
declaration	int acl_get(char *, int, acl_t **);
version		SUNW_1.2
end		

function	facl_get
include		<aclutils.h>
declaration	int facl_get(int, int, acl_t **);
version		SUNW_1.2
end		

function	acl_set
include		<sys/acl.h>
declaration	int acl_set(char *, acl_t  *);
version		SUNW_1.2
end		

function	facl_set
include		<sys/acl.h>
declaration	int facl_set(int, acl_t  *);
version		SUNW_1.2
end		

function	acl_strip
include		<sys/acl.h>
declaration	int acl_strip(char *, uid_t, gid_t, mode_t);
version		SUNW_1.2
end		

function	acl_trivial
include		<sys/acl.h>
declaration	int acl_trivial(char *file)
version		SUNW_1.2
end

function	acl_totext
include		<sys/acl.h>
declaration	char *acl_totext(acl_t *acl, int flags);
version		SUNW_1.2
exception	$return == 0
end

function	acl_fromtext
include		<sys/acl.h>
declaration	int acl_fromtext(char *textp, acl_t **);
version		SUNW_1.2
end

function	acl_free
include		<sys/acl.h>
declaration	void acl_free(acl_t *aclp);
version		SUNW_1.2
end

function	acl_addentries
include		<sys/acl.h>
declaration	int acl_addentries(acl_t *acl1, aclt_t *acl2, int slot);
version		SUNWprivate_1.1
end

function	acl_removeentries
include		<sys/acl.h>
declaration	int acl_removeentries(acl_t *acl1, aclt_t *acl2, int, int);
version		SUNWprivate_1.1
end

function	acl_printacl
include		<sys/acl.h>
declaration	void acl_printacl(acl_t *aclp, int cols, int compact);
version		SUNWprivate_1.1
end

function	acl_strerror
include		<sys/acl.h>
declaration	char *acl_strerror(int errnum);
version		SUNWprivate_1.1
end

function	acl_modifyentries
include		<sys/acl.h>
declaration	int acl_modifyentries(acl_t *acl1, acl_t *newentries,
    int where);
version		SUNWprivate_1.1
end

function	acl_alloc
include		<sys/acl.h>
declaration	int acl_alloc(enum acl_type);
version		SUNWprivate_1.1
end

function	acl_dup
include		<aclutils.h>
declaration	acl_t acl_dup(acl_t *);
version		SUNWprivate_1.1
end 

function	acl_cnt
include		<aclutils.h>
declaration	int acl_cnt(acl_t *);
version		SUNWprivate_1.1
end

function	acl_type
include		<aclutils.h>
declaration	int acl_type(acl_t *);
version		SUNWprivate_1.1
end

function	acl_flags
include		<aclutils.h>
declaration	int acl_flags(acl_t *);
version		SUNWprivate_1.1
end

function	acl_data
include		<aclutils.h>
declaration	void *acl_data(acl_t *);
version		SUNWprivate_1.1
end

function	acl_error
include		<aclutils.h>
declaration	void acl_error(const char *, ...)
version		SUNWprivate_1.1
end

function	acl_parse
include		<aclutils.h>
declaration	void acl_parse(char *textp, acl_t **);
version		SUNWprivate_1.1
end
