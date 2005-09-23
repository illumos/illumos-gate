/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support routines for managing per-page state.
 */

#include <cmd_page.h>
#include <cmd.h>

#include <errno.h>
#include <string.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>

static void
page_write(fmd_hdl_t *hdl, cmd_page_t *page)
{
	fmd_buf_write(hdl, NULL, page->page_bufname, page, sizeof (cmd_page_t));
}

static void
cmd_page_free(fmd_hdl_t *hdl, cmd_page_t *page, int destroy)
{
	if (page->page_case != NULL)
		cmd_case_fini(hdl, page->page_case, destroy);

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
	page->page_physbase = pa;

	cmd_bufname(page->page_bufname, sizeof (page->page_bufname),
	    "page_%llx", (u_longlong_t)pa);

	if ((errno = nvlist_dup(modasru, &asru, 0)) != 0 ||
	    (errno = nvlist_add_uint64(asru, FM_FMRI_MEM_PHYSADDR,
	    page->page_physbase)) != 0)
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
		fmd_hdl_debug(hdl, "restoring page from %s\n", ptr->ptr_name);

		if ((page = cmd_buf_read(hdl, NULL, ptr->ptr_name,
		    sizeof (cmd_page_t))) == NULL) {
			fmd_hdl_abort(hdl, "failed to read buf %s",
			    ptr->ptr_name);
		}

		cmd_fmri_restore(hdl, &page->page_asru);

		page->page_case = NULL;
		cmd_list_append(&cmd.cmd_pages, page);
	}

	switch (ptr->ptr_subtype) {
	case BUG_PTR_PAGE_CASE:
		fmd_hdl_debug(hdl, "recovering from out of order page ptr\n");
		cmd_case_redirect(hdl, cp, CMD_PTR_PAGE_CASE);
		/*FALLTHROUGH*/
	case CMD_PTR_PAGE_CASE:
		page->page_case = cp;
		break;
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

		if (fmd_nvl_fmri_unusable(hdl, page->page_asru_nvl))
			cmd_page_destroy(hdl, page);
	}
}

void
cmd_page_fini(fmd_hdl_t *hdl)
{
	cmd_page_t *page;

	while ((page = cmd_list_next(&cmd.cmd_pages)) != NULL)
		cmd_page_free(hdl, page, FMD_B_FALSE);
}
