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

#include <gmem_state.h>
#include <gmem_mem.h>
#include <gmem_page.h>
#include <gmem_dimm.h>
#include <gmem.h>

#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <strings.h>
#include <fm/fmd_api.h>
#include <fm/libtopo.h>
#include <sys/fm/protocol.h>
#include <sys/async.h>
#include <sys/fm/ldom.h>

gmem_t gmem;

typedef struct gmem_subscriber {
	const char *subr_class;
	gmem_evdisp_t (*subr_func)(fmd_hdl_t *, fmd_event_t *, nvlist_t *,
	    const char *);
	gmem_evdisp_stat_t subr_stat;
} gmem_subscriber_t;

static gmem_subscriber_t gmem_subscribers[] = {
	{ "ereport.cpu.generic-sparc.mem-is",	gmem_ce },
	{ "ereport.cpu.generic-sparc.mem-unk",	gmem_ce },
	{ "ereport.cpu.generic-sparc.mem-cs",	gmem_ce },
	{ "ereport.cpu.generic-sparc.mem-ss",	gmem_ce },
	{ NULL, NULL }
};

static void
gmem_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	gmem_subscriber_t *sp;
	int disp;

	fmd_hdl_debug(hdl, "gmem_recv: begin: %s\n", strrchr(class, '.') + 1);

	for (sp = gmem_subscribers; sp->subr_class != NULL; sp++) {
		if (fmd_nvl_class_match(hdl, nvl, sp->subr_class)) {
			disp = sp->subr_func(hdl, ep, nvl, class);
			((fmd_stat_t *)&sp->subr_stat)[disp].fmds_value.ui64++;
			fmd_hdl_debug(hdl, "gmem_recv: done: %s (disp %d)\n",
			    strrchr(class, '.') + 1, disp);
			return;
		}
	}

	fmd_hdl_debug(hdl, "gmem_recv: dropping %s - unable to handle\n",
	    class);
}

static void
gmem_close(fmd_hdl_t *hdl, fmd_case_t *cp)
{
	gmem_case_closer_t *cl = fmd_case_getspecific(hdl, cp);
	const char *uuid = fmd_case_uuid(hdl, cp);

	/*
	 * Our active cases all have closers registered in case-specific data.
	 * Cases in the process of closing (for which we've freed all associated
	 * data, but which haven't had an fmd-initiated fmdo_close callback)
	 * have had their case-specific data nulled out.
	 */
	fmd_hdl_debug(hdl, "close case %s%s\n", uuid,
	    (cl == NULL ? " (no cl)" : ""));

	if (cl != NULL)
		cl->cl_func(hdl, cl->cl_arg);
}

static void
gmem_gc(fmd_hdl_t *hdl)
{
	gmem_mem_gc(hdl);
}

static gmem_stat_t gm_stats = {
	{ "bad_mem_resource", FMD_TYPE_UINT64,
	    "memory resource missing or malformed" },
	{ "bad_close", FMD_TYPE_UINT64, "case close for nonexistent case" },
	{ "old_erpt", FMD_TYPE_UINT64, "ereport out of date wrt hardware" },
	{ "dimm_creat", FMD_TYPE_UINT64, "created new mem module structure" },
	{ "page_creat", FMD_TYPE_UINT64, "created new page structure" },
	{ "ce_unknown", FMD_TYPE_UINT64, "unknown CEs" },
	{ "ce_interm", FMD_TYPE_UINT64, "intermittent CEs" },
	{ "ce_clearable_persis", FMD_TYPE_UINT64, "clearable persistent CEs" },
	{ "ce_sticky", FMD_TYPE_UINT64, "sticky CEs" },
};

static const fmd_prop_t fmd_props[] = {
	{ "ce_n", FMD_TYPE_UINT32, "3" },
	{ "ce_t", FMD_TYPE_TIME, "72h" },
	{ "filter_ratio", FMD_TYPE_UINT32, "0" },
	{ "max_retired_pages", FMD_TYPE_UINT32, "512" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_ops_t fmd_ops = {
	gmem_recv,	/* fmdo_recv */
	NULL,
	gmem_close,	/* fmdo_close */
	NULL,		/* fmdo_stats */
	gmem_gc		/* fmdo_gc */
};

static const fmd_hdl_info_t fmd_info = {
	"SPARC-Generic-Memory Diagnosis", GMEM_VERSION, &fmd_ops, fmd_props
};

static const struct gmem_evdisp_name {
	const char *evn_name;
	const char *evn_desc;
} gmem_evdisp_names[] = {
	{ "%s", "ok %s ereports" },			/* GMEM_EVD_OK */
	{ "bad_%s", "bad %s ereports" },		/* GMEM_EVD_BAD */
	{ "unused_%s", "unused %s ereports" },		/* GMEM_EVD_UNUSED */
	{ "redun_%s", "redundant %s ereports" },	/* GMEM_EVD_REDUN */
};

void
_fmd_fini(fmd_hdl_t *hdl)
{
	gmem_mem_fini(hdl);
	gmem_page_fini(hdl);
}

void
_fmd_init(fmd_hdl_t *hdl)
{
	gmem_subscriber_t *sp;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return; /* error in configuration file or fmd_info */

	for (sp = gmem_subscribers; sp->subr_class != NULL; sp++)
		fmd_hdl_subscribe(hdl, sp->subr_class);

	bzero(&gmem, sizeof (gmem_t));

	gmem.gm_stats = (gmem_stat_t *)fmd_stat_create(hdl, FMD_STAT_NOALLOC,
	    sizeof (gm_stats) / sizeof (fmd_stat_t),
	    (fmd_stat_t *)&gm_stats);

	for (sp = gmem_subscribers; sp->subr_class != NULL; sp++) {
		const char *type = strrchr(sp->subr_class, '.') + 1;
		int i;

		for (i = 0; i < sizeof (gmem_evdisp_names) /
		    sizeof (struct gmem_evdisp_name); i++) {
			fmd_stat_t *stat = ((fmd_stat_t *)&sp->subr_stat) + i;

			(void) snprintf(stat->fmds_name,
			    sizeof (stat->fmds_name),
			    gmem_evdisp_names[i].evn_name, type);

			stat->fmds_type = FMD_TYPE_UINT64;
			(void) snprintf(stat->fmds_desc,
			    sizeof (stat->fmds_desc),
			    gmem_evdisp_names[i].evn_desc, type);

			(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, 1, stat);
		}
	}

	gmem.gm_pagesize = sysconf(_SC_PAGESIZE);
	gmem.gm_pagemask = ~((uint64_t)gmem.gm_pagesize - 1);

	gmem.gm_max_retired_pages = fmd_prop_get_int32(hdl,
	    "max_retired_pages");

	gmem.gm_ce_n = fmd_prop_get_int32(hdl, "ce_n");
	gmem.gm_ce_t = fmd_prop_get_int64(hdl, "ce_t");
	gmem.gm_filter_ratio = fmd_prop_get_int32(hdl, "filter_ratio");

	if (gmem_state_restore(hdl) < 0) {
		_fmd_fini(hdl);
		fmd_hdl_abort(hdl, "failed to restore saved state\n");
	}
}
