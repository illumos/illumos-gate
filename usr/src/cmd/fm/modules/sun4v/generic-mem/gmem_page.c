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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * Support routines for managing per-page state.
 */

#include <gmem_page.h>
#include <gmem_mem.h>
#include <gmem_dimm.h>
#include <gmem.h>

#include <errno.h>
#include <strings.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>

static void
page_write(fmd_hdl_t *hdl, gmem_page_t *page)
{
	fmd_buf_write(hdl, NULL, page->page_bufname, page,
	    sizeof (gmem_page_pers_t));
}

static void
gmem_page_free(fmd_hdl_t *hdl, gmem_page_t *page, int destroy)
{
	gmem_case_t *cc = &page->page_case;

	if (cc->cc_cp != NULL)
		gmem_case_fini(hdl, cc->cc_cp, destroy);

	if (cc->cc_serdnm != NULL) {
		if (fmd_serd_exists(hdl, cc->cc_serdnm) && destroy)
			fmd_serd_destroy(hdl, cc->cc_serdnm);
		fmd_hdl_strfree(hdl, cc->cc_serdnm);
	}

	if (destroy)
		fmd_buf_destroy(hdl, NULL, page->page_bufname);

	gmem_fmri_fini(hdl, &page->page_asru, destroy);

	gmem_list_delete(&gmem.gm_pages, page);
	fmd_hdl_free(hdl, page, sizeof (gmem_page_t));
}

void
gmem_page_destroy(fmd_hdl_t *hdl, gmem_page_t *page)
{
	fmd_hdl_debug(hdl, "destroying the page\n");
	gmem_page_free(hdl, page, FMD_B_TRUE);
}

static gmem_page_t *
page_lookup_by_physaddr(uint64_t pa)
{
	gmem_page_t *page;

	for (page = gmem_list_next(&gmem.gm_pages); page != NULL;
	    page = gmem_list_next(page)) {
		if (page->page_physbase == pa)
			return (page);
	}

	return (NULL);
}

gmem_page_t *
gmem_page_create(fmd_hdl_t *hdl, nvlist_t *modasru, uint64_t pa,
    uint64_t offset)
{
	gmem_page_t *page;
	nvlist_t *asru, *hsp;

	pa = pa & gmem.gm_pagemask;

	fmd_hdl_debug(hdl, "page_lookup: creating new page for %llx\n",
	    (u_longlong_t)pa);
	GMEM_STAT_BUMP(page_creat);

	page = fmd_hdl_zalloc(hdl, sizeof (gmem_page_t), FMD_SLEEP);
	page->page_nodetype = GMEM_NT_PAGE;
	page->page_version = CMD_PAGE_VERSION;
	page->page_physbase = pa;
	page->page_offset = offset;

	gmem_bufname(page->page_bufname, sizeof (page->page_bufname),
	    "page_%llx", (u_longlong_t)pa);

	if (nvlist_dup(modasru, &asru, 0) != 0) {
		fmd_hdl_debug(hdl, "Page create nvlist dup failed");
		return (NULL);
	}

	if (nvlist_alloc(&hsp, NV_UNIQUE_NAME, 0) != 0) {
		fmd_hdl_debug(hdl, "Page create nvlist alloc failed");
		nvlist_free(asru);
		return (NULL);
	}

	if (nvlist_add_uint64(hsp, FM_FMRI_MEM_PHYSADDR,
	    page->page_physbase) != 0 ||
	    nvlist_add_uint64(hsp, FM_FMRI_HC_SPECIFIC_OFFSET,
	    page->page_offset) != 0 ||
	    nvlist_add_nvlist(asru, FM_FMRI_HC_SPECIFIC, hsp) != 0) {
		fmd_hdl_debug(hdl, "Page create failed to build page fmri");
		nvlist_free(asru);
		nvlist_free(hsp);
		return (NULL);
	}

	gmem_fmri_init(hdl, &page->page_asru, asru, "page_asru_%llx",
	    (u_longlong_t)pa);

	nvlist_free(asru);
	nvlist_free(hsp);

	gmem_list_append(&gmem.gm_pages, page);
	page_write(hdl, page);

	return (page);
}

gmem_page_t *
gmem_page_lookup(uint64_t pa)
{
	pa = pa & gmem.gm_pagemask;

	return (page_lookup_by_physaddr(pa));
}

static gmem_page_t *
page_wrapv0(fmd_hdl_t *hdl, gmem_page_pers_t *pers, size_t psz)
{
	gmem_page_t *page;

	if (psz != sizeof (gmem_page_pers_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 0 state (%u bytes).\n", sizeof (gmem_page_pers_t));
	}

	page = fmd_hdl_zalloc(hdl, sizeof (gmem_page_t), FMD_SLEEP);
	bcopy(pers, page, sizeof (gmem_page_pers_t));
	fmd_hdl_free(hdl, pers, psz);
	return (page);
}

void *
gmem_page_restore(fmd_hdl_t *hdl, fmd_case_t *cp, gmem_case_ptr_t *ptr)
{
	gmem_page_t *page;

	for (page = gmem_list_next(&gmem.gm_pages); page != NULL;
	    page = gmem_list_next(page)) {
		if (strcmp(page->page_bufname, ptr->ptr_name) == 0)
			break;
	}

	if (page == NULL) {
		size_t pagesz;

		fmd_hdl_debug(hdl, "restoring page from %s\n", ptr->ptr_name);

		if ((pagesz = fmd_buf_size(hdl, NULL, ptr->ptr_name)) == 0) {
			if (fmd_case_solved(hdl, cp) ||
			    fmd_case_closed(hdl, cp)) {
				fmd_hdl_debug(hdl, "page %s from case %s not "
				    "found. Case is already solved or closed\n",
				    ptr->ptr_name, fmd_case_uuid(hdl, cp));
				return (NULL);
			} else {
				fmd_hdl_abort(hdl, "page referenced by case %s "
				    "does not exist in saved state\n",
				    fmd_case_uuid(hdl, cp));
			}
		} else if (pagesz > CMD_PAGE_MAXSIZE ||
		    pagesz < CMD_PAGE_MINSIZE) {
			fmd_hdl_abort(hdl, "page buffer referenced by case %s "
			    "is out of bounds (is %u bytes, max %u, min %u)\n",
			    fmd_case_uuid(hdl, cp), pagesz,
			    CMD_PAGE_MAXSIZE, CMD_PAGE_MINSIZE);
		}

		if ((page = gmem_buf_read(hdl, NULL, ptr->ptr_name,
		    pagesz)) == NULL) {
			fmd_hdl_abort(hdl, "failed to read page buf %s",
			    ptr->ptr_name);
		}

		fmd_hdl_debug(hdl, "found %d in version field\n",
		    page->page_version);

		switch (page->page_version) {
		case CMD_PAGE_VERSION_0:
			page = page_wrapv0(hdl, (gmem_page_pers_t *)page,
			    pagesz);
			break;
		default:
			fmd_hdl_abort(hdl, "unknown version (found %d) "
			    "for page state referenced by case %s.\n",
			    page->page_version, fmd_case_uuid(hdl, cp));
			break;
		}

		gmem_fmri_restore(hdl, &page->page_asru);

		gmem_list_append(&gmem.gm_pages, page);
	}

	switch (ptr->ptr_subtype) {
	case GMEM_PTR_PAGE_CASE:
		gmem_case_restore(hdl, &page->page_case, cp,
		    gmem_page_serdnm_create(hdl, "page", page->page_physbase));
		break;
	default:
		fmd_hdl_abort(hdl, "invalid %s subtype %d\n",
		    ptr->ptr_name, ptr->ptr_subtype);
	}

	return (page);
}

/*ARGSUSED*/
int
gmem_page_unusable(fmd_hdl_t *hdl, gmem_page_t *page)
{
	nvlist_t *asru = NULL;
	char *sn;

	if (nvlist_lookup_string(page->page_asru_nvl,
	    FM_FMRI_HC_SERIAL_ID, &sn) != 0)
		return (1);

	/*
	 * get asru in mem scheme from topology
	 */
	asru = gmem_find_dimm_asru(hdl, sn);
	if (asru == NULL)
		return (1);

	(void) nvlist_add_string_array(asru, FM_FMRI_MEM_SERIAL_ID, &sn, 1);
	(void) nvlist_add_uint64(asru, FM_FMRI_MEM_PHYSADDR,
	    page->page_physbase);
	(void) nvlist_add_uint64(asru, FM_FMRI_MEM_OFFSET, page->page_offset);

	if (fmd_nvl_fmri_unusable(hdl, asru)) {
		nvlist_free(asru);
		return (1);
	}

	nvlist_free(asru);

	return (0);
}


/*ARGSUSED*/
void
gmem_page_validate(fmd_hdl_t *hdl)
{
	gmem_page_t *page, *next;

	for (page = gmem_list_next(&gmem.gm_pages); page != NULL; page = next) {
		next = gmem_list_next(page);

		if (gmem_page_unusable(hdl, page))
			gmem_page_destroy(hdl, page);
	}
}

void
gmem_page_dirty(fmd_hdl_t *hdl, gmem_page_t *page)
{
	if (fmd_buf_size(hdl, NULL, page->page_bufname) !=
	    sizeof (gmem_page_pers_t))
		fmd_buf_destroy(hdl, NULL, page->page_bufname);

	/* No need to rewrite the FMRIs in the page - they don't change */
	fmd_buf_write(hdl, NULL, page->page_bufname, &page->page_pers,
	    sizeof (gmem_page_pers_t));
}

void
gmem_page_fini(fmd_hdl_t *hdl)
{
	gmem_page_t *page;

	while ((page = gmem_list_next(&gmem.gm_pages)) != NULL)
		gmem_page_free(hdl, page, FMD_B_FALSE);
}


int
gmem_page_fault(fmd_hdl_t *hdl, nvlist_t *fru, nvlist_t *rsc,
    fmd_event_t *ep, uint64_t afar, uint64_t offset)
{
	gmem_page_t *page = NULL;
	const char *uuid;
	nvlist_t *flt, *hsp;

	page = gmem_page_lookup(afar);
	if (page != NULL) {
		if (page->page_flags & GMEM_F_FAULTING ||
		    gmem_page_unusable(hdl, page)) {
			nvlist_free(rsc);
			page->page_flags |= GMEM_F_FAULTING;
			return (0);
		}
	} else {
		page = gmem_page_create(hdl, fru, afar, offset);
	}

	page->page_flags |= GMEM_F_FAULTING;
	if (page->page_case.cc_cp == NULL)
		page->page_case.cc_cp = gmem_case_create(hdl,
		    &page->page_header, GMEM_PTR_PAGE_CASE, &uuid);

	if (nvlist_lookup_nvlist(page->page_asru_nvl, FM_FMRI_HC_SPECIFIC,
	    &hsp) == 0)
		(void) nvlist_add_nvlist(rsc, FM_FMRI_HC_SPECIFIC, hsp);

	flt = fmd_nvl_create_fault(hdl, GMEM_FAULT_PAGE, 100, NULL, fru, rsc);
	nvlist_free(rsc);

	if (nvlist_add_boolean_value(flt, FM_SUSPECT_MESSAGE, B_FALSE) != 0)
		fmd_hdl_abort(hdl, "failed to add no-message member to fault");

	fmd_case_add_ereport(hdl, page->page_case.cc_cp, ep);
	fmd_case_add_suspect(hdl, page->page_case.cc_cp, flt);
	fmd_case_solve(hdl, page->page_case.cc_cp);
	return (1);
}

void
gmem_page_close(fmd_hdl_t *hdl, void *arg)
{
	gmem_page_destroy(hdl, arg);
}
