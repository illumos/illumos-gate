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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support routines for managing per-page state.
 */

#include <cmd_page.h>
#include <cmd_mem.h>
#include <cmd.h>
#ifdef sun4u
#include <cmd_dp_page.h>
#endif

#include <errno.h>
#include <strings.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>

static void
page_write(fmd_hdl_t *hdl, cmd_page_t *page)
{
	fmd_buf_write(hdl, NULL, page->page_bufname, page,
	    sizeof (cmd_page_pers_t));
}

static void
cmd_page_free(fmd_hdl_t *hdl, cmd_page_t *page, int destroy)
{
	cmd_case_t *cc = &page->page_case;

	if (cc->cc_cp != NULL)
		cmd_case_fini(hdl, cc->cc_cp, destroy);

	if (cc->cc_serdnm != NULL) {
		if (fmd_serd_exists(hdl, cc->cc_serdnm) && destroy)
			fmd_serd_destroy(hdl, cc->cc_serdnm);
		fmd_hdl_strfree(hdl, cc->cc_serdnm);
	}

	if (destroy)
		fmd_buf_destroy(hdl, NULL, page->page_bufname);

	cmd_fmri_fini(hdl, &page->page_asru, destroy);

	cmd_list_delete(&cmd.cmd_pages, page);
	fmd_hdl_free(hdl, page, sizeof (cmd_page_t));
}

void
cmd_page_destroy(fmd_hdl_t *hdl, cmd_page_t *page)
{
	cmd_page_free(hdl, page, FMD_B_TRUE);
}

static cmd_page_t *
page_lookup_by_physaddr(uint64_t pa)
{
	cmd_page_t *page;

	for (page = cmd_list_next(&cmd.cmd_pages); page != NULL;
	    page = cmd_list_next(page)) {
		if (page->page_physbase == pa)
			return (page);
	}

	return (NULL);
}

cmd_page_t *
cmd_page_create(fmd_hdl_t *hdl, nvlist_t *modasru, uint64_t pa)
{
	cmd_page_t *page;
	nvlist_t *asru;

	pa = pa & cmd.cmd_pagemask;

	fmd_hdl_debug(hdl, "page_lookup: creating new page for %llx\n",
	    (u_longlong_t)pa);
	CMD_STAT_BUMP(page_creat);

	page = fmd_hdl_zalloc(hdl, sizeof (cmd_page_t), FMD_SLEEP);
	page->page_nodetype = CMD_NT_PAGE;
	page->page_version = CMD_PAGE_VERSION;
	page->page_physbase = pa;

	cmd_bufname(page->page_bufname, sizeof (page->page_bufname),
	    "page_%llx", (u_longlong_t)pa);

	if ((errno = nvlist_dup(modasru, &asru, 0)) != 0 ||
	    (errno = nvlist_add_uint64(asru, FM_FMRI_MEM_PHYSADDR,
	    page->page_physbase)) != 0 ||
	    (errno = fmd_nvl_fmri_expand(hdl, asru)) != 0)
		fmd_hdl_abort(hdl, "failed to build page fmri");

	cmd_fmri_init(hdl, &page->page_asru, asru, "page_asru_%llx",
	    (u_longlong_t)pa);

	nvlist_free(asru);

	cmd_list_append(&cmd.cmd_pages, page);
	page_write(hdl, page);

	return (page);
}

cmd_page_t *
cmd_page_lookup(uint64_t pa)
{
	pa = pa & cmd.cmd_pagemask;

	return (page_lookup_by_physaddr(pa));
}

static cmd_page_t *
page_v0tov1(fmd_hdl_t *hdl, cmd_page_0_t *old, size_t oldsz)
{
	cmd_page_t *new;

	if (oldsz != sizeof (cmd_page_0_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 0 state (%u bytes).\n", sizeof (cmd_page_0_t));
	}

	new = fmd_hdl_zalloc(hdl, sizeof (cmd_page_t), FMD_SLEEP);
	new->page_header = old->page0_header;
	new->page_version = CMD_PAGE_VERSION;
	new->page_asru = old->page0_asru;

	fmd_hdl_free(hdl, old, oldsz);
	return (new);
}

static cmd_page_t *
page_wrapv1(fmd_hdl_t *hdl, cmd_page_pers_t *pers, size_t psz)
{
	cmd_page_t *page;

	if (psz != sizeof (cmd_page_pers_t)) {
		fmd_hdl_abort(hdl, "size of state doesn't match size of "
		    "version 1 state (%u bytes).\n", sizeof (cmd_page_pers_t));
	}

	page = fmd_hdl_zalloc(hdl, sizeof (cmd_page_t), FMD_SLEEP);
	bcopy(pers, page, sizeof (cmd_page_pers_t));
	fmd_hdl_free(hdl, pers, psz);
	return (page);
}

void *
cmd_page_restore(fmd_hdl_t *hdl, fmd_case_t *cp, cmd_case_ptr_t *ptr)
{
	cmd_page_t *page;

	for (page = cmd_list_next(&cmd.cmd_pages); page != NULL;
	    page = cmd_list_next(page)) {
		if (strcmp(page->page_bufname, ptr->ptr_name) == 0)
			break;
	}

	if (page == NULL) {
		int migrated = 0;
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

		if ((page = cmd_buf_read(hdl, NULL, ptr->ptr_name,
		    pagesz)) == NULL) {
			fmd_hdl_abort(hdl, "failed to read page buf %s",
			    ptr->ptr_name);
		}

		fmd_hdl_debug(hdl, "found %d in version field\n",
		    page->page_version);

		if (CMD_PAGE_VERSIONED(page)) {
			switch (page->page_version) {
			case CMD_PAGE_VERSION_1:
				page = page_wrapv1(hdl, (cmd_page_pers_t *)page,
				    pagesz);
				break;
			default:
				fmd_hdl_abort(hdl, "unknown version (found %d) "
				    "for page state referenced by case %s.\n",
				    page->page_version, fmd_case_uuid(hdl, cp));
				break;
			}
		} else {
			page = page_v0tov1(hdl, (cmd_page_0_t *)page, pagesz);
			migrated = 1;
		}

		if (migrated) {
/*			CMD_STAT_BUMP(page_migrat);	*/
			cmd_page_dirty(hdl, page);
		}

		cmd_fmri_restore(hdl, &page->page_asru);

		cmd_list_append(&cmd.cmd_pages, page);
	}

	switch (ptr->ptr_subtype) {
	case BUG_PTR_PAGE_CASE:
		fmd_hdl_debug(hdl, "recovering from out of order page ptr\n");
		cmd_case_redirect(hdl, cp, CMD_PTR_PAGE_CASE);
		/*FALLTHROUGH*/
	case CMD_PTR_PAGE_CASE:
		cmd_case_restore(hdl, &page->page_case, cp,
		    cmd_page_serdnm_create(hdl, "page", page->page_physbase));
		break;

#ifdef sun4u
	case CMD_PTR_DP_PAGE_DEFER:
		page->page_case.cc_cp = cp;
		cmd_dp_page_restore(hdl, page);
		break;
#endif
	default:
		fmd_hdl_abort(hdl, "invalid %s subtype %d\n",
		    ptr->ptr_name, ptr->ptr_subtype);
	}

	return (page);
}


/*ARGSUSED*/
void
cmd_page_validate(fmd_hdl_t *hdl)
{
	cmd_page_t *page, *next;

	for (page = cmd_list_next(&cmd.cmd_pages); page != NULL; page = next) {
		next = cmd_list_next(page);

		if (fmd_nvl_fmri_unusable(hdl, page->page_asru_nvl)) {
#ifdef sun4u
			if (cmd_dp_page_isdeferred(hdl, page) &&
			    fmd_nvl_fmri_present(hdl, page->page_asru_nvl))
					continue;
#endif
			cmd_page_destroy(hdl, page);
		}
	}
}

void
cmd_page_dirty(fmd_hdl_t *hdl, cmd_page_t *page)
{
	if (fmd_buf_size(hdl, NULL, page->page_bufname) !=
	    sizeof (cmd_page_pers_t))
		fmd_buf_destroy(hdl, NULL, page->page_bufname);

	/* No need to rewrite the FMRIs in the page - they don't change */
	fmd_buf_write(hdl, NULL, page->page_bufname, &page->page_pers,
	    sizeof (cmd_page_pers_t));
}

void
cmd_page_fini(fmd_hdl_t *hdl)
{
	cmd_page_t *page;

	while ((page = cmd_list_next(&cmd.cmd_pages)) != NULL)
		cmd_page_free(hdl, page, FMD_B_FALSE);
}
