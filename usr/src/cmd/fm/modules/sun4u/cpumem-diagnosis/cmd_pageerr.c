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
 * Fault-handling routines for page retirement faults
 */

#include <cmd_page.h>
#include <cmd.h>

#include <errno.h>
#include <string.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>

void
cmd_page_fault(fmd_hdl_t *hdl, nvlist_t *modasru, nvlist_t *modfru,
    fmd_event_t *ep, uint64_t afar)
{
	cmd_page_t *page = cmd_page_lookup(afar);
	const char *uuid;
	nvlist_t *flt;

	if (page == NULL)
		page = cmd_page_create(hdl, modasru, afar);

	if (page->page_case != NULL) {
		/*
		 * We've already faulted this page.  No need to kick it while
		 * it's down -- don't fault it again.
		 */
		return;
	}

	page->page_case = cmd_case_create(hdl, &page->page_header,
	    CMD_PTR_PAGE_CASE, &uuid);

	flt = fmd_nvl_create_fault(hdl, "fault.memory.page", 100,
	    page->page_asru_nvl, modfru, NULL);

	if (nvlist_add_boolean_value(flt, FM_SUSPECT_MESSAGE, B_FALSE) != 0)
		fmd_hdl_abort(hdl, "failed to add no-message member to fault");

	fmd_case_add_ereport(hdl, page->page_case, ep);
	fmd_case_add_suspect(hdl, page->page_case, flt);
	fmd_case_solve(hdl, page->page_case);
}

void
cmd_page_close(fmd_hdl_t *hdl, void *arg)
{
	cmd_page_destroy(hdl, arg);
}
