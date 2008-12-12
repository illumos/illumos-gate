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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Case management and saved state restoration
 */

#include <gmem_state.h>
#include <gmem_mem.h>
#include <gmem_page.h>
#include <gmem_dimm.h>
#include <gmem.h>

#include <string.h>
#include <fm/fmd_api.h>

/* Must be in sync with gmem_ptrsubtype_t */
static gmem_case_closer_f *const gmem_case_closers[] = {
	NULL,
	gmem_dimm_close,		/* GMEM_PTR_DIMM_CASE */
	gmem_page_close,		/* GMEM_PTR_PAGE_CASE */
};

fmd_case_t *
gmem_case_create(fmd_hdl_t *hdl, gmem_header_t *hdr,
    gmem_ptrsubtype_t ptrsubtype, const char **uuidp)
{
	gmem_case_ptr_t ptr;
	gmem_case_closer_t *cl;
	fmd_case_t *cp;

	cl = fmd_hdl_alloc(hdl, sizeof (gmem_case_closer_t), FMD_SLEEP);
	cl->cl_func = gmem_case_closers[ptrsubtype];
	cl->cl_arg = hdr;

	cp = fmd_case_open(hdl, cl);

	ptr.ptr_type = hdr->hdr_nodetype;
	ptr.ptr_subtype = ptrsubtype;
	(void) strcpy(ptr.ptr_name, hdr->hdr_bufname);

	*uuidp = fmd_case_uuid(hdl, cp);
	fmd_buf_write(hdl, cp, *uuidp, &ptr, sizeof (gmem_case_ptr_t));

	return (cp);
}

void
gmem_case_redirect(fmd_hdl_t *hdl, fmd_case_t *cp, gmem_ptrsubtype_t newsubtype)
{
	const char *uuid = fmd_case_uuid(hdl, cp);
	gmem_case_ptr_t ptr;

	fmd_buf_read(hdl, cp, uuid, &ptr, sizeof (gmem_case_ptr_t));
	fmd_hdl_debug(hdl, "redirecting case %s from %d to %d\n", uuid,
	    ptr.ptr_subtype, newsubtype);
	ptr.ptr_subtype = newsubtype;
	fmd_buf_write(hdl, cp, uuid, &ptr, sizeof (gmem_case_ptr_t));
}

void
gmem_case_fini(fmd_hdl_t *hdl, fmd_case_t *cp, int close)
{
	const char *uuid = fmd_case_uuid(hdl, cp);
	gmem_case_closer_t *cl = fmd_case_getspecific(hdl, cp);

	if (close) {
		fmd_hdl_debug(hdl, "closing case %s\n", uuid);

		if (fmd_serd_exists(hdl, uuid))
			fmd_serd_destroy(hdl, uuid);

		if (fmd_buf_size(hdl, cp, uuid) != 0)
			fmd_buf_destroy(hdl, cp, uuid);

		fmd_case_setspecific(hdl, cp, NULL);
		fmd_case_close(hdl, cp);
	}

	if (cl != NULL)
		fmd_hdl_free(hdl, cl, sizeof (gmem_case_closer_t));
}

/* Must be in sync with gmem_nodetype_t */
static gmem_case_restorer_f *const gmem_case_restorers[] = {
	NULL,
	gmem_dimm_restore,	/* CMD_NT_DIMM */
	gmem_page_restore,	/* CMD_NT_PAGE */
};

int
gmem_state_restore(fmd_hdl_t *hdl)
{
	fmd_case_t *cp = NULL;

	while ((cp = fmd_case_next(hdl, cp)) != NULL) {
		const char *uuid = fmd_case_uuid(hdl, cp);
		gmem_case_closer_t *cl;
		gmem_case_ptr_t ptr;
		void *thing;
		size_t sz;

		if ((sz = fmd_buf_size(hdl, cp, uuid)) == 0)
			continue;
		else if (sz != sizeof (gmem_case_ptr_t))
			return (gmem_set_errno(EINVAL));

		fmd_buf_read(hdl, cp, fmd_case_uuid(hdl, cp), &ptr,
		    sizeof (gmem_case_ptr_t));

		if (ptr.ptr_type == 0 || ptr.ptr_type >
		    sizeof (gmem_case_restorers) /
		    sizeof (gmem_case_restorer_f *))
			return (gmem_set_errno(EINVAL));

		if ((thing = gmem_case_restorers[ptr.ptr_type](hdl,
		    cp, &ptr)) == NULL) {
			fmd_hdl_debug(hdl, "Unable to restore case %s\n", uuid);
			continue;
		}

		cl = fmd_hdl_alloc(hdl, sizeof (gmem_case_closer_t), FMD_SLEEP);
		cl->cl_func = gmem_case_closers[ptr.ptr_subtype];
		cl->cl_arg = thing;
		fmd_case_setspecific(hdl, cp, cl);
	}

	gmem_dimm_validate(hdl);
	gmem_page_validate(hdl);

	return (0);
}

void
gmem_case_restore(fmd_hdl_t *hdl, gmem_case_t *cc, fmd_case_t *cp, char *serdnm)
{
	if (!fmd_serd_exists(hdl, serdnm)) {
		fmd_hdl_strfree(hdl, serdnm);
		serdnm = NULL;
	}

	cc->cc_cp = cp;
	cc->cc_serdnm = serdnm;
}
