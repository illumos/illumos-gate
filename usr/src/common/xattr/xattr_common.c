/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/attr.h>
#if defined(_KERNEL)
#include <sys/systm.h>
#else
#include <strings.h>
#endif

/*
 * This table maps each system attribute to its option and its view.
 * All new system attrs must be added to this table.  To add a new view,
 * add another entry to xattr_dirents[] and update xattr_view_t in sys/attr.h.
 * Also, xattr_file_pathconf() and sys/unistd.h should be updated to add
 * return values for the new view.
 */

static xattr_entry_t xattrs[F_ATTR_ALL] = {
	{ A_ARCHIVE, O_ARCHIVE, XATTR_VIEW_READWRITE, DATA_TYPE_BOOLEAN_VALUE },
	{ A_HIDDEN, O_HIDDEN, XATTR_VIEW_READWRITE, DATA_TYPE_BOOLEAN_VALUE },
	{ A_READONLY, O_READONLY, XATTR_VIEW_READWRITE,
	    DATA_TYPE_BOOLEAN_VALUE },
	{ A_SYSTEM, O_SYSTEM, XATTR_VIEW_READWRITE, DATA_TYPE_BOOLEAN_VALUE },
	{ A_APPENDONLY, O_APPENDONLY, XATTR_VIEW_READWRITE,
	    DATA_TYPE_BOOLEAN_VALUE },
	{ A_NODUMP, O_NODUMP, XATTR_VIEW_READWRITE, DATA_TYPE_BOOLEAN_VALUE },
	{ A_IMMUTABLE, O_IMMUTABLE, XATTR_VIEW_READWRITE,
	    DATA_TYPE_BOOLEAN_VALUE },
	{ A_AV_MODIFIED, O_AV_MODIFIED, XATTR_VIEW_READWRITE,
	    DATA_TYPE_BOOLEAN_VALUE },
	{ A_OPAQUE, O_NONE, XATTR_VIEW_READONLY, DATA_TYPE_BOOLEAN_VALUE },
	{ A_AV_SCANSTAMP, O_NONE, XATTR_VIEW_READONLY, DATA_TYPE_UINT8_ARRAY },
	{ A_AV_QUARANTINED, O_AV_QUARANTINED, XATTR_VIEW_READWRITE,
	    DATA_TYPE_BOOLEAN_VALUE },
	{ A_NOUNLINK, O_NOUNLINK, XATTR_VIEW_READWRITE,
	    DATA_TYPE_BOOLEAN_VALUE },
	{ A_CRTIME, O_NONE, XATTR_VIEW_READWRITE, DATA_TYPE_UINT64_ARRAY },
	{ A_OWNERSID, O_NONE, XATTR_VIEW_READWRITE, DATA_TYPE_NVLIST },
	{ A_GROUPSID, O_NONE, XATTR_VIEW_READWRITE, DATA_TYPE_NVLIST },
	{ A_FSID, O_NONE, XATTR_VIEW_READONLY, DATA_TYPE_UINT64 },
	{ A_REPARSE_POINT, O_REPARSE_POINT, XATTR_VIEW_READONLY,
	    DATA_TYPE_BOOLEAN_VALUE },
	{ A_GEN, O_NONE, XATTR_VIEW_READONLY, DATA_TYPE_UINT64 },
	{ A_OFFLINE, O_OFFLINE, XATTR_VIEW_READWRITE, DATA_TYPE_BOOLEAN_VALUE },
	{ A_SPARSE, O_SPARSE, XATTR_VIEW_READWRITE, DATA_TYPE_BOOLEAN_VALUE },
};

const char *
attr_to_name(f_attr_t attr)
{
	if (attr >= F_ATTR_ALL || attr < 0)
		return (NULL);

	return (xattrs[attr].x_name);
}

const char *
attr_to_option(f_attr_t attr)
{
	if (attr >= F_ATTR_ALL || attr < 0)
		return (NULL);

	return (xattrs[attr].x_option);
}

f_attr_t
name_to_attr(const char *name)
{
	int i;

	for (i = 0; i < F_ATTR_ALL; i++) {
		if (strcmp(name, xattrs[i].x_name) == 0)
			return (i);
	}

	return (F_ATTR_INVAL);
}

f_attr_t
option_to_attr(const char *option)
{
	int i;

	for (i = 0; i < F_ATTR_ALL; i++) {
		if (strcmp(option, xattrs[i].x_option) == 0)
			return (i);
	}

	return (F_ATTR_INVAL);
}

xattr_view_t
attr_to_xattr_view(f_attr_t attr)
{
	if (attr >= F_ATTR_ALL || attr < 0)
		return (XATTR_VIEW_INVALID);

	return (xattrs[attr].x_xattr_view);
}

int
attr_count(void)
{
	return (F_ATTR_ALL);
}

data_type_t
attr_to_data_type(f_attr_t attr)
{
	if (attr >= F_ATTR_ALL || attr < 0)
		return (DATA_TYPE_UNKNOWN);

	return (xattrs[attr].x_data_type);
}
