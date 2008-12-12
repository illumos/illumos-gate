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
 * Support routines for managing state related to memory modules.
 */

#include <gmem_mem.h>
#include <gmem_dimm.h>
#include <gmem.h>

#include <assert.h>
#include <errno.h>
#include <strings.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/mem.h>
#include <sys/nvpair.h>

char *
gmem_mem_serdnm_create(fmd_hdl_t *hdl, const char *serdbase, const char *serial)
{
	const char *fmt = "%s_%s_serd";
	size_t sz = snprintf(NULL, 0, fmt, serdbase, serial) + 1;
	char *nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
	(void) snprintf(nm, sz, fmt, serdbase, serial);

	return (nm);
}

char *
gmem_page_serdnm_create(fmd_hdl_t *hdl, const char *serdbase,
    uint64_t phys_addr)
{
	const char *fmt = "%s_%llXserd";
	size_t sz = snprintf(NULL, 0, fmt, serdbase, phys_addr) + 1;
	char *nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
	(void) snprintf(nm, sz, fmt, serdbase, phys_addr);

	return (nm);
}

char *
gmem_mq_serdnm_create(fmd_hdl_t *hdl, const char *serdbase,
    uint64_t phys_addr, uint16_t cw, uint16_t pos)
{
	const char *fmt = "%s_%llX_%x_%x_serd";
	size_t sz = snprintf(NULL, 0, fmt, serdbase, phys_addr, cw, pos) + 1;
	char *nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
	(void) snprintf(nm, sz, fmt, serdbase, phys_addr, cw, pos);

	return (nm);
}

uint32_t
gmem_get_serd_filter_ratio(nvlist_t *nvl)
{
	uint32_t filter_ratio = 0;
	uint32_t erpt_ratio;

	if (gmem.gm_filter_ratio == 0) {
		if (nvlist_lookup_uint32(nvl,
		    GMEM_ERPT_PAYLOAD_FILTER_RATIO, &erpt_ratio) == 0)
			filter_ratio = erpt_ratio;
	} else
		filter_ratio = gmem.gm_filter_ratio;

	return (filter_ratio);
}

void
gmem_page_serd_create(fmd_hdl_t *hdl, gmem_page_t *page, nvlist_t *nvl)
{
	uint32_t erpt_serdn, serd_n;
	uint64_t erpt_serdt, serd_t;

	serd_n = gmem.gm_ce_n;
	serd_t = gmem.gm_ce_t;

	if (serd_n == DEFAULT_SERDN && serd_t == DEFAULT_SERDT) {
		if (nvlist_lookup_uint32(nvl, GMEM_ERPT_PAYLOAD_SERDN,
		    &erpt_serdn) == 0)
			serd_n = erpt_serdn;
		if (nvlist_lookup_uint64(nvl, GMEM_ERPT_PAYLOAD_SERDT,
		    &erpt_serdt) == 0)
			serd_t = erpt_serdt;
	}

	page->page_case.cc_serdnm = gmem_page_serdnm_create(hdl, "page",
	    page->page_physbase);

	fmd_serd_create(hdl, page->page_case.cc_serdnm, serd_n, serd_t);
}

int
gmem_serd_record(fmd_hdl_t *hdl, const char *serdbaser, uint32_t ratio,
    fmd_event_t *ep)
{
	int i, rc;
	if (ratio == 0)
		return (fmd_serd_record(hdl, serdbaser, ep));
	for (i = 0; i < ratio; i++) {
		rc = fmd_serd_record(hdl, serdbaser, ep);
		if (rc != FMD_B_FALSE)
			break;
	}
	return (rc);
}

void
gmem_mem_case_restore(fmd_hdl_t *hdl, gmem_case_t *cc, fmd_case_t *cp,
    const char *serdbase, const char *serial)
{
	gmem_case_restore(hdl, cc, cp, gmem_mem_serdnm_create(hdl, serdbase,
	    serial));
}

void
gmem_mem_retirestat_create(fmd_hdl_t *hdl, fmd_stat_t *st, const char *serial,
    uint64_t value, const char *prefix)
{

	(void) snprintf(st->fmds_name, sizeof (st->fmds_name), "%s%s",
	    prefix, serial);
	(void) snprintf(st->fmds_desc, sizeof (st->fmds_desc),
	    "retirements for %s%s", prefix, serial);
	st->fmds_type = FMD_TYPE_UINT64;
	st->fmds_value.ui64 = value;

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, 1, st);
}

void
gmem_mem_gc(fmd_hdl_t *hdl)
{
	gmem_dimm_gc(hdl);
}

void
gmem_mem_fini(fmd_hdl_t *hdl)
{
	gmem_dimm_fini(hdl);
}
