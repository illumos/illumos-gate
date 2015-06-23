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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/debug.h>

#include <attr.h>
#include <libnvpair.h>

static uint64_t zero_times[2];

static int
getxva_parse_nvl(xvattr_t *xvap,
    xoptattr_t *xoap, nvlist_t *nvl);

/*
 * See similar code to parse the nvlist in:
 * uts/common/fs/xattr.c : xattr_file_write()
 */
int
fop__getxvattr(vnode_t *vp, xvattr_t *xvap)
{
	nvlist_t *nvl = NULL;
	xoptattr_t *xoap = NULL;
	int error;

	if ((xoap = xva_getxoptattr(xvap)) == NULL) {
		return (EINVAL);
	}

	error = fgetattr(vp->v_fd, XATTR_VIEW_READWRITE, &nvl);
	if (error == 0) {
		error = getxva_parse_nvl(xvap, xoap, nvl);
		nvlist_free(nvl);
		nvl = NULL;
	}

	/*
	 * Also get the readonly attrs, but don't fail.
	 */
	if (fgetattr(vp->v_fd, XATTR_VIEW_READONLY, &nvl) == 0) {
		(void) getxva_parse_nvl(xvap, xoap, nvl);
		nvlist_free(nvl);
	}

	return (error);
}

static int
getxva_parse_nvl(xvattr_t *xvap,
    xoptattr_t *xoap, nvlist_t *nvl)
{
	nvpair_t *pair = NULL;
	int error;

	while (pair = nvlist_next_nvpair(nvl, pair)) {
		data_type_t type;
		f_attr_t attr;
		boolean_t value = B_FALSE;
		uint64_t *times = zero_times;
		uint_t nelems = 2;

		/*
		 * Validate the name and type of each attribute.
		 * Log any unknown names and continue.  This will
		 * help if additional attributes are added later.
		 */
		type = nvpair_type(pair);
		attr = name_to_attr(nvpair_name(pair));
		if (attr == F_ATTR_INVAL)
			continue;

		/*
		 * Verify nvlist type matches required type and view is OK
		 */

		if (type != attr_to_data_type(attr) ||
		    (attr_to_xattr_view(attr) == XATTR_VIEW_READONLY))
			continue;

		/*
		 * For OWNERSID/GROUPSID, just skip.
		 */
		if ((attr == F_OWNERSID || attr == F_GROUPSID))
			continue;

		/*
		 * Retrieve data from nvpair
		 */
		switch (type) {
		case DATA_TYPE_BOOLEAN_VALUE:
			if (nvpair_value_boolean_value(pair, &value)) {
				error = EINVAL;
				goto out;
			}
			break;

		case DATA_TYPE_UINT64_ARRAY:
			if (nvpair_value_uint64_array(pair, &times, &nelems)) {
				error = EINVAL;
				goto out;
			}
			if (nelems < 2)
				continue;
			break;

		case DATA_TYPE_NVLIST:
			continue;

		case DATA_TYPE_UINT8_ARRAY:
			continue;

		default:
			error = EINVAL;
			goto out;
		}

		switch (attr) {
		/*
		 * If we have several similar optional attributes to
		 * process then we should do it all together here so that
		 * xoap and the requested bitmap can be set in one place.
		 */
		case F_READONLY:
			XVA_SET_RTN(xvap, XAT_READONLY);
			xoap->xoa_readonly = value;
			break;

		case F_HIDDEN:
			XVA_SET_RTN(xvap, XAT_HIDDEN);
			xoap->xoa_hidden = value;
			break;

		case F_SYSTEM:
			XVA_SET_RTN(xvap, XAT_SYSTEM);
			xoap->xoa_system = value;
			break;

		case F_ARCHIVE:
			XVA_SET_RTN(xvap, XAT_ARCHIVE);
			xoap->xoa_archive = value;
			break;

		case F_CRTIME:
			XVA_SET_RTN(xvap, XAT_CREATETIME);
			xoap->xoa_createtime.tv_sec = times[0];
			xoap->xoa_createtime.tv_nsec = times[1];
			break;

		case F_REPARSE:
			XVA_SET_RTN(xvap, XAT_REPARSE);
			xoap->xoa_reparse = value;
			break;

		case F_OFFLINE:
			XVA_SET_RTN(xvap, XAT_OFFLINE);
			xoap->xoa_offline = value;
			break;

		case F_SPARSE:
			XVA_SET_RTN(xvap, XAT_SPARSE);
			xoap->xoa_sparse = value;
			break;

		default:
			break;
		}
	}
	error = 0;

out:
	return (error);
}

/*
 * See similar code to build the nvlist in:
 * uts/common/fs/xattr.c : xattr_fill_nvlist()
 */
int
fop__setxvattr(vnode_t *vp, xvattr_t *xvap)
{
	uint64_t times[2];
	nvlist_t *nvl;
	int error;
	xoptattr_t *xoap;	/* Pointer to optional attributes */

	if ((xoap = xva_getxoptattr(xvap)) == NULL)
		return (EINVAL);

	if (nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP))
		return (ENOMEM);

	if (XVA_ISSET_REQ(xvap, XAT_READONLY)) {
		VERIFY(nvlist_add_boolean_value(nvl,
		    attr_to_name(F_READONLY),
		    xoap->xoa_readonly) == 0);
	}

	if (XVA_ISSET_REQ(xvap, XAT_HIDDEN)) {
		VERIFY(nvlist_add_boolean_value(nvl,
		    attr_to_name(F_HIDDEN),
		    xoap->xoa_hidden) == 0);
	}

	if (XVA_ISSET_REQ(xvap, XAT_SYSTEM)) {
		VERIFY(nvlist_add_boolean_value(nvl,
		    attr_to_name(F_SYSTEM),
		    xoap->xoa_system) == 0);
	}

	if (XVA_ISSET_REQ(xvap, XAT_ARCHIVE)) {
		VERIFY(nvlist_add_boolean_value(nvl,
		    attr_to_name(F_ARCHIVE),
		    xoap->xoa_archive) == 0);
	}

	if (XVA_ISSET_REQ(xvap, XAT_CREATETIME)) {
		times[0] = xoap->xoa_createtime.tv_sec;
		times[1] = xoap->xoa_createtime.tv_nsec;
		VERIFY(nvlist_add_uint64_array(nvl,
		    attr_to_name(F_CRTIME),
		    times, 2) == 0);
	}

	if (XVA_ISSET_REQ(xvap, XAT_REPARSE)) {
		VERIFY(nvlist_add_boolean_value(nvl,
		    attr_to_name(F_REPARSE),
		    xoap->xoa_reparse) == 0);
	}

	if (XVA_ISSET_REQ(xvap, XAT_OFFLINE)) {
		VERIFY(nvlist_add_boolean_value(nvl,
		    attr_to_name(F_OFFLINE),
		    xoap->xoa_offline) == 0);
	}

	if (XVA_ISSET_REQ(xvap, XAT_SPARSE)) {
		VERIFY(nvlist_add_boolean_value(nvl,
		    attr_to_name(F_SPARSE),
		    xoap->xoa_sparse) == 0);
	}

	error = fsetattr(vp->v_fd, XATTR_VIEW_READWRITE, nvl);

	nvlist_free(nvl);

	return (error);
}
