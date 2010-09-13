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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Support routines for managing potential page and bank faults that have
 * been deferred due to a datapath error.  Currently deferment only occurs
 * if a memory UE occurs while a datapath error is active.  When this happens
 * a page case is created with a special subtype of CMD_PTR_DP_PAGE_DEFER.  An
 * entry (a cmd_dp_defer_t) is added to a list of deferred pages.  The entry
 * links to the cmd_page_t in the cmd_pages list and also keeps track of what
 * memory controller ids are associated with the first AFAR and any more that
 * are seen while the page is deferred.  This information is used to determine
 * if the page should be faulted if the fault should be skipped because an
 * intervening datapath fault has occurred.  If a page is faulted when it is
 * replayed, the corresponding bank is faulted, too, since the original error
 * was a UE.  Note that no action is taken to undo any action taken by the
 * kernel when the UE was detected.  Currently the kernel will attempt to
 * immediately retire the page where a UE is detected and the retire may or
 * may not have completed by the time FMA receives an ereport.  The possibility
 * of a datapath fault resulting in memory UEs is very small, so the likelihood
 * of encountering this scenario is also very small.
 */

#include <cmd.h>
#include <cmd_dp.h>
#include <cmd_dp_page.h>
#include <cmd_bank.h>
#include <cmd_page.h>

#include <fm/fmd_api.h>
#include <sys/nvpair.h>

extern void cmd_bank_fault(fmd_hdl_t *, cmd_bank_t *);

static void
dp_page_defer_data_write(fmd_hdl_t *hdl, cmd_dp_defer_t *dpage)
{
	fmd_buf_write(hdl, dpage->dp_defer_page->page_case.cc_cp, "mcids",
	    &dpage->dp_defer_mcids, sizeof (dpage->dp_defer_mcids));
}

static void
dp_page_defer_data_restore(fmd_hdl_t *hdl, cmd_dp_defer_t *dpage)
{
	fmd_buf_read(hdl, dpage->dp_defer_page->page_case.cc_cp, "mcids",
	    &dpage->dp_defer_mcids, sizeof (dpage->dp_defer_mcids));
}

static void
dp_page_defer_add_data(fmd_hdl_t *hdl, cmd_dp_defer_t *dpage, uint64_t afar)
{
	int mcid;
	int i;

	if (cmd_dp_get_mcid(afar, &mcid) < 0)
		fmd_hdl_abort(hdl, "cmd_dp_get_mcid failed");

	for (i = 0; i < DP_MAX_MCS; i++) {
		if (dpage->dp_defer_mcids[i] == -1) {
			dpage->dp_defer_mcids[i] = mcid;
			break;
		}
		if (dpage->dp_defer_mcids[i] == mcid)
			break;
	}

	if (i == DP_MAX_MCS)
		fmd_hdl_abort(hdl, "too many mcids for deferred page");

	dp_page_defer_data_write(hdl, dpage);
}

static cmd_dp_defer_t *
dp_page_defer_create(fmd_hdl_t *hdl, cmd_page_t *page, uint64_t afar)
{
	cmd_dp_defer_t *dpage;
	int i;

	dpage = fmd_hdl_zalloc(hdl, sizeof (cmd_dp_defer_t), FMD_SLEEP);

	dpage->dp_defer_page = page;

	for (i = 0; i < DP_MAX_MCS; i++)
		dpage->dp_defer_mcids[i] = -1;

	dp_page_defer_add_data(hdl, dpage, afar);

	cmd_list_append(&cmd.cmd_deferred_pages, dpage);

	return (dpage);
}

static cmd_dp_defer_t *
dp_page_defer_lookup(cmd_page_t *page)
{
	cmd_dp_defer_t *dpage;

	for (dpage = cmd_list_next(&cmd.cmd_deferred_pages); dpage != NULL;
	    dpage = cmd_list_next(dpage)) {
		if (dpage->dp_defer_page == page)
			return (dpage);
	}

	return (NULL);
}

void
cmd_dp_page_defer(fmd_hdl_t *hdl, nvlist_t *modasru, fmd_event_t *ep,
    uint64_t afar)
{
	cmd_dp_defer_t *dpage;
	cmd_page_t *page = cmd_page_lookup(afar);
	const char *uuid;

	if (page == NULL) {
		page = cmd_page_create(hdl, modasru, afar);
		dpage = dp_page_defer_create(hdl, page, afar);
		page->page_case.cc_cp = cmd_case_create(hdl, &page->page_header,
		    CMD_PTR_DP_PAGE_DEFER, &uuid);
		fmd_case_setprincipal(hdl, page->page_case.cc_cp, ep);
	} else {
		dpage = dp_page_defer_lookup(page);
		if (dpage == NULL)
			fmd_hdl_abort(hdl, "deferred page with no defer data");
		fmd_case_add_ereport(hdl, page->page_case.cc_cp, ep);
	}

	dp_page_defer_add_data(hdl, dpage, afar);
}

int
cmd_dp_page_check(fmd_hdl_t *hdl, cmd_dp_defer_t *dpage)
{
	int i;

	for (i = 0; i < DP_MAX_MCS; i++) {
		if (dpage->dp_defer_mcids[i] == -1)
			break;
		/*
		 * If there's no datapath fault corresponding to
		 * an mcid, that means the page incurred an error
		 * not attributable to a datapath fault.
		 */
		if (cmd_dp_lookup_fault(hdl, dpage->dp_defer_mcids[i]) == 0)
			return (0);
	}

	return (1);
}

void
cmd_dp_page_replay(fmd_hdl_t *hdl)
{
	fmd_event_t *ep;
	cmd_page_t *page;
	cmd_bank_t *bank;
	cmd_dp_defer_t *dpage;
	nvlist_t *nvl;

	while ((dpage = cmd_list_next(&cmd.cmd_deferred_pages)) != NULL) {
		fmd_hdl_debug(hdl, "replaying deferred page, "
		    "pa=%llx\n", dpage->dp_defer_page->page_physbase);

		page = dpage->dp_defer_page;

		if (cmd_dp_page_check(hdl, dpage)) {
			fmd_hdl_debug(hdl, "deferred memory UE  overtaken by "
			    "dp fault");
			CMD_STAT_BUMP(dp_ignored_ue);
			fmd_case_close(hdl, page->page_case.cc_cp);
			cmd_list_delete(&cmd.cmd_deferred_pages, dpage);
			fmd_hdl_free(hdl, dpage, sizeof (cmd_dp_defer_t));
			cmd_page_destroy(hdl, page);
			continue;
		}

		nvl = page->page_asru_nvl;

		bank = cmd_bank_lookup(hdl, nvl);

		ep = fmd_case_getprincipal(hdl, page->page_case.cc_cp);
		fmd_case_add_ereport(hdl, bank->bank_case.cc_cp, ep);

		bank->bank_nretired++;
		bank->bank_retstat.fmds_value.ui64++;
		cmd_bank_dirty(hdl, bank);

		fmd_case_reset(hdl, page->page_case.cc_cp);
		cmd_case_fini(hdl, page->page_case.cc_cp, FMD_B_TRUE);

		page->page_case.cc_cp = NULL;
		cmd_page_fault(hdl, nvl, nvl, ep, page->page_physbase);
		cmd_bank_fault(hdl, bank);

		cmd_list_delete(&cmd.cmd_deferred_pages, dpage);
		fmd_hdl_free(hdl, dpage, sizeof (cmd_dp_defer_t));
	}

	fmd_hdl_debug(hdl, "cmd_page_defer_replay() complete\n");
}

void
cmd_dp_page_restore(fmd_hdl_t *hdl, cmd_page_t *page)
{
	cmd_dp_defer_t *dpage;

	dpage = fmd_hdl_zalloc(hdl, sizeof (cmd_dp_defer_t), FMD_SLEEP);

	dpage->dp_defer_page = page;

	dp_page_defer_data_restore(hdl, dpage);

	cmd_list_append(&cmd.cmd_deferred_pages, dpage);
}

void
cmd_dp_page_validate(fmd_hdl_t *hdl)
{
	cmd_dp_defer_t *dpage, *next;
	cmd_page_t *page;

	for (dpage = cmd_list_next(&cmd.cmd_deferred_pages); dpage != NULL;
	    dpage = next) {
		next = cmd_list_next(dpage);

		page = dpage->dp_defer_page;

		if (!fmd_nvl_fmri_present(hdl, page->page_asru_nvl)) {
			cmd_page_destroy(hdl, page);
			cmd_list_delete(&cmd.cmd_deferred_pages, dpage);
			fmd_hdl_free(hdl, dpage, sizeof (cmd_dp_defer_t));
		}
	}
}

/*ARGSUSED*/
int
cmd_dp_page_isdeferred(fmd_hdl_t *hdl, cmd_page_t *page)
{
	cmd_dp_defer_t *dpage, *next;

	for (dpage = cmd_list_next(&cmd.cmd_deferred_pages); dpage != NULL;
	    dpage = next) {
		next = cmd_list_next(dpage);

		if (dpage->dp_defer_page == page) {
			return (1);
		}
	}

	return (0);
}
