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
 * Fault-handling routines for page retirement faults
 */

#include <cmd_page.h>
#include <cmd.h>
#include <cmd_mem.h>

#include <errno.h>
#include <string.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#ifdef sun4v
#include <cmd_hc_sun4v.h>
#include <cmd_dimm.h>
#endif

void
cmd_page_fault(fmd_hdl_t *hdl, nvlist_t *modasru, nvlist_t *modfru,
    fmd_event_t *ep, uint64_t afar)
{
	cmd_page_t *page = NULL;
	const char *uuid;
	nvlist_t *flt;
#ifdef sun4v
	nvlist_t *nvlfru;
#endif

	page = cmd_page_lookup(afar);
	if (page != NULL) {
		/*
		 * If the page has already been retired then *page
		 * would have been freed and recreated. Thus the
		 * flag would be 0x0 - check to see if the page
		 * is unusable (retired).
		 */
		if (page->page_flags & CMD_MEM_F_FAULTING ||
		    fmd_nvl_fmri_unusable(hdl, page->page_asru_nvl)) {
			/* Page already faulted, don't fault again. */
			page->page_flags |= CMD_MEM_F_FAULTING;
			return;
		}
	} else {
		page = cmd_page_create(hdl, modasru, afar);
	}

	page->page_flags |= CMD_MEM_F_FAULTING;
	if (page->page_case.cc_cp == NULL)
		page->page_case.cc_cp = cmd_case_create(hdl,
		    &page->page_header, CMD_PTR_PAGE_CASE, &uuid);

#ifdef sun4v
	nvlfru = cmd_mem2hc(hdl, modfru);
	flt = cmd_nvl_create_fault(hdl, "fault.memory.page", 100,
	    page->page_asru_nvl, nvlfru, NULL);
	flt = cmd_fault_add_location(hdl, flt, cmd_fmri_get_unum(modfru));
	nvlist_free(nvlfru);
#else /* sun4v */
	flt = cmd_nvl_create_fault(hdl, "fault.memory.page", 100,
	    page->page_asru_nvl, modfru, NULL);
#endif /* sun4v */

	if (nvlist_add_boolean_value(flt, FM_SUSPECT_MESSAGE, B_FALSE) != 0)
		fmd_hdl_abort(hdl, "failed to add no-message member to fault");

	fmd_case_add_ereport(hdl, page->page_case.cc_cp, ep);
	fmd_case_add_suspect(hdl, page->page_case.cc_cp, flt);
	fmd_case_solve(hdl, page->page_case.cc_cp);
}

void
cmd_page_close(fmd_hdl_t *hdl, void *arg)
{
	cmd_page_destroy(hdl, arg);
}
