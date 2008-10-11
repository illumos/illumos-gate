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

#include <cmd_mem.h>
#include <cmd_dimm.h>
#include <cmd_bank.h>
#include <cmd.h>
#ifdef sun4u
#include <cmd_dp.h>
#endif
#ifdef sun4v
#include <cmd_branch.h>
#endif

#include <errno.h>
#include <strings.h>
#include <ctype.h>
#include <fcntl.h>
#include <unistd.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/mem.h>
#include <sys/nvpair.h>

const char *
cmd_fmri_get_unum(nvlist_t *fmri)
{
	const char *scheme, *unum;
	uint8_t vers;

	if (nvlist_lookup_pairs(fmri, 0,
	    FM_VERSION, DATA_TYPE_UINT8, &vers,
	    FM_FMRI_SCHEME, DATA_TYPE_STRING, &scheme,
	    FM_FMRI_MEM_UNUM, DATA_TYPE_STRING, &unum,
	    NULL) != 0 || vers > FM_MEM_SCHEME_VERSION ||
	    strcmp(scheme, FM_FMRI_SCHEME_MEM) != 0)
		return (NULL);

	return (unum);
}

char *
cmd_mem_serdnm_create(fmd_hdl_t *hdl, const char *serdbase, const char *unum)
{
	const char *fmt = "%s_%s_serd";
	size_t sz = snprintf(NULL, 0, fmt, serdbase, unum) + 1;
	char *nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
	(void) snprintf(nm, sz, fmt, serdbase, unum);

	return (nm);
}

char *
cmd_page_serdnm_create(fmd_hdl_t *hdl, const char *serdbase,
    uint64_t phys_addr)
{
	const char *fmt = "%s_%llXserd";
	size_t sz = snprintf(NULL, 0, fmt, serdbase, phys_addr) + 1;
	char *nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
	(void) snprintf(nm, sz, fmt, serdbase, phys_addr);

	return (nm);
}

char *
cmd_mq_serdnm_create(fmd_hdl_t *hdl, const char *serdbase,
    uint64_t phys_addr, uint16_t cw, uint16_t pos)
{
	const char *fmt = "%s_%llX_%x_%x_serd";
	size_t sz = snprintf(NULL, 0, fmt, serdbase, phys_addr, cw, pos) + 1;
	char *nm = fmd_hdl_alloc(hdl, sz, FMD_SLEEP);
	(void) snprintf(nm, sz, fmt, serdbase, phys_addr, cw, pos);

	return (nm);
}

void
cmd_mem_case_restore(fmd_hdl_t *hdl, cmd_case_t *cc, fmd_case_t *cp,
    const char *serdbase, const char *unum)
{
	cmd_case_restore(hdl, cc, cp, cmd_mem_serdnm_create(hdl, serdbase,
	    unum));
}

void
cmd_mem_retirestat_create(fmd_hdl_t *hdl, fmd_stat_t *st, const char *unum,
    uint64_t value, const char *prefix)
{
	char *c;

	/*
	 * Prior to Niagara-2, every bank had to have at least two dimms; it
	 * was therefore impossible for the retirestat of a bank to ever have
	 * the same name (strcmp() == 0) as that of a dimm.
	 *
	 * Niagara-2 and VF, in "single channel mode" , retrieve an entire
	 * cache line from a single dimm.  We therefore use a different
	 * prefix to name the bank retirestat vs. the dimm retirestat,
	 * or else the DE will abort trying to register a duplicate stat name
	 * with fmd.
	 */
	(void) snprintf(st->fmds_name, sizeof (st->fmds_name), "%s%s",
	    prefix, unum);
	(void) snprintf(st->fmds_desc, sizeof (st->fmds_desc),
	    "retirements for %s", unum);
	st->fmds_type = FMD_TYPE_UINT64;
	st->fmds_value.ui64 = value;

	/*
	 * Sanitize the name of the statistic -- standard unums won't get
	 * by fmd's validity checker.
	 */
	for (c = st->fmds_name; *c != '\0'; c++) {
		if (!isupper(*c) && !islower(*c) &&
		    !isdigit(*c) && *c != '-' && *c != '_' && *c != '.')
			*c = '_';
	}

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, 1, st);
}

int
cmd_mem_thresh_check(fmd_hdl_t *hdl, uint_t nret)
{
	ulong_t npages = cmd_mem_get_phys_pages(hdl);
	ulong_t wrnpgs;

	fmd_hdl_debug(hdl, "thresh_check: npages is %lu\n", npages);
	if (npages == 0) {
		return (0);
	}

	if (cmd.cmd_thresh_abs_sysmem != 0) {
		wrnpgs = cmd.cmd_thresh_abs_sysmem;
	} else {
		/* threshold is in thousandths of a percent */
		wrnpgs = npages * cmd.cmd_thresh_tpct_sysmem / 100000;
	}

	fmd_hdl_debug(hdl, "thresh_check: nret %u, wrn %lu\n", nret, wrnpgs);

	return (nret > wrnpgs);
}

nvlist_t *
cmd_mem_fmri_create(const char *unum, char **serids, size_t nserids)
{
	nvlist_t *fmri;

	if ((errno = nvlist_alloc(&fmri, NV_UNIQUE_NAME, 0)) != 0)
		return (NULL);

	if ((errno = nvlist_add_uint8(fmri, FM_VERSION,
	    FM_MEM_SCHEME_VERSION)) != 0 || (errno = nvlist_add_string(fmri,
	    FM_FMRI_SCHEME, FM_FMRI_SCHEME_MEM)) != 0 || (errno =
	    nvlist_add_string(fmri, FM_FMRI_MEM_UNUM, unum)) != 0) {
		nvlist_free(fmri);
		return (NULL);
	}

	if ((nserids > 0) && (serids != NULL)) {
		(void) nvlist_add_string_array(fmri, FM_FMRI_MEM_SERIAL_ID,
		    serids, nserids);
	}
	return (fmri);
}

nvlist_t *
cmd_mem_fmri_derive(fmd_hdl_t *hdl, uint64_t afar, uint64_t afsr, uint16_t synd)
{
	mem_name_t mn;
	nvlist_t *fmri;
	int fd;

	if ((fd = open("/dev/mem", O_RDONLY)) < 0)
		return (NULL);

	mn.m_addr = afar;
	mn.m_synd = synd;
	mn.m_type[0] = afsr;
	mn.m_type[1] = 0;
	mn.m_namelen = 100;

	for (;;) {
		mn.m_name = fmd_hdl_alloc(hdl, mn.m_namelen, FMD_SLEEP);

		if (ioctl(fd, MEM_NAME, &mn) == 0)
			break;

		fmd_hdl_free(hdl, mn.m_name, mn.m_namelen);

		if (errno != ENOSPC) {
			(void) close(fd);
			return (NULL);
		}

		mn.m_namelen *= 2;
	}

	(void) close(fd);

	fmri = cmd_mem_fmri_create(mn.m_name, NULL, 0);
	fmd_hdl_free(hdl, mn.m_name, mn.m_namelen);

	return (fmri);
}

void
cmd_iorxefrx_queue(fmd_hdl_t *hdl, cmd_iorxefrx_t *rf)
{

	fmd_hdl_debug(hdl, "queueing IOxE/RxE/FRx for matching\n");

	rf->rf_expid = fmd_timer_install(hdl, (void *)CMD_TIMERTYPE_MEM, NULL,
	    cmd.cmd_iorxefrx_window);
	cmd_list_append(&cmd.cmd_iorxefrx, rf);
}

void
cmd_iorxefrx_free(fmd_hdl_t *hdl, cmd_iorxefrx_t *rf)
{
	/* It's not persisted, so just remove it */
	cmd_list_delete(&cmd.cmd_iorxefrx, rf);
	fmd_hdl_free(hdl, rf, sizeof (cmd_iorxefrx_t));
}

void
cmd_mem_timeout(fmd_hdl_t *hdl, id_t id)
{
	cmd_iorxefrx_t *rf;

	for (rf = cmd_list_next(&cmd.cmd_iorxefrx); rf != NULL;
	    rf = cmd_list_next(rf)) {
		if (rf->rf_expid == id) {
			fmd_hdl_debug(hdl, "reclaiming iorxefrx tid %d\n", id);
			cmd_iorxefrx_free(hdl, rf);
			return;
		}
	}
}

void
cmd_mem_gc(fmd_hdl_t *hdl)
{
	cmd_dimm_gc(hdl);
	cmd_bank_gc(hdl);
#ifdef sun4v
	cmd_branch_gc(hdl);
#endif
}

void
cmd_mem_fini(fmd_hdl_t *hdl)
{
	cmd_iorxefrx_t *rf;

	cmd_dimm_fini(hdl);
	cmd_bank_fini(hdl);
#ifdef sun4v
	cmd_branch_fini(hdl);
#endif

	while ((rf = cmd_list_next(&cmd.cmd_iorxefrx)) != NULL)
		cmd_iorxefrx_free(hdl, rf);
}
