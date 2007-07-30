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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <cma.h>

#include <strings.h>
#include <errno.h>
#include <time.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/fm/ldom.h>

static fmd_hdl_t *init_hdl;
ldom_hdl_t *cma_lhp;

cma_t cma;

cma_stats_t cma_stats = {
	{ "cpu_flts", FMD_TYPE_UINT64, "cpu faults resolved" },
	{ "cpu_fails", FMD_TYPE_UINT64, "cpu faults unresolveable" },
	{ "cpu_blfails", FMD_TYPE_UINT64, "failed cpu blacklists" },
	{ "cpu_supp", FMD_TYPE_UINT64, "cpu offlines suppressed" },
	{ "cpu_blsupp", FMD_TYPE_UINT64, "cpu blacklists suppressed" },
	{ "page_flts", FMD_TYPE_UINT64, "page faults resolved" },
	{ "page_fails", FMD_TYPE_UINT64, "page faults unresolveable" },
	{ "page_supp", FMD_TYPE_UINT64, "page retires suppressed" },
	{ "page_nonent", FMD_TYPE_UINT64, "retires for non-existent fmris" },
	{ "page_retmax", FMD_TYPE_UINT64, "hit max retries for page retire" },
	{ "bad_flts", FMD_TYPE_UINT64, "invalid fault events received" },
	{ "nop_flts", FMD_TYPE_UINT64, "inapplicable fault events received" },
	{ "auto_flts", FMD_TYPE_UINT64, "auto-close faults received" }
};

typedef struct cma_subscriber {
	const char *subr_class;
	const char *subr_sname;
	uint_t subr_svers;
	int (*subr_func)(fmd_hdl_t *, nvlist_t *, nvlist_t *, const char *);
} cma_subscriber_t;

static const cma_subscriber_t cma_subrs[] = {
	{ "fault.memory.page", FM_FMRI_SCHEME_MEM, FM_MEM_SCHEME_VERSION,
	    cma_page_retire },
	{ "fault.memory.dimm", FM_FMRI_SCHEME_MEM, FM_MEM_SCHEME_VERSION,
	    NULL },
	{ "fault.memory.dimm_sb", FM_FMRI_SCHEME_MEM, FM_MEM_SCHEME_VERSION,
	    NULL },
	{ "fault.memory.dimm_ck", FM_FMRI_SCHEME_MEM, FM_MEM_SCHEME_VERSION,
	    NULL },
	{ "fault.memory.dimm_ue", FM_FMRI_SCHEME_MEM, FM_MEM_SCHEME_VERSION,
	    NULL },
	{ "fault.memory.bank", FM_FMRI_SCHEME_MEM, FM_MEM_SCHEME_VERSION,
	    NULL },
	{ "fault.memory.datapath", FM_FMRI_SCHEME_MEM, FM_MEM_SCHEME_VERSION,
	    NULL },
	{ "fault.memory.link-c", FM_FMRI_SCHEME_MEM, FM_MEM_SCHEME_VERSION,
	    NULL },
	{ "fault.memory.link-u", FM_FMRI_SCHEME_MEM, FM_MEM_SCHEME_VERSION,
	    NULL },
	{ "fault.memory.link-f", FM_FMRI_SCHEME_MEM, FM_MEM_SCHEME_VERSION,
	    NULL },

	/*
	 * The following ultraSPARC-T1/T2 faults do NOT retire a cpu thread,
	 * and therefore must be intercepted before
	 * the default "fault.cpu.*" dispatch to cma_cpu_retire.
	 */
	{ "fault.cpu.*.l2cachedata", FM_FMRI_SCHEME_CPU,
	    FM_CPU_SCHEME_VERSION, NULL },
	{ "fault.cpu.*.l2cachetag", FM_FMRI_SCHEME_CPU,
	    FM_CPU_SCHEME_VERSION, NULL },
	{ "fault.cpu.*.l2cachectl", FM_FMRI_SCHEME_CPU,
	    FM_CPU_SCHEME_VERSION, NULL },
	{ "fault.cpu.*.l2data-c", FM_FMRI_SCHEME_CPU,
	    FM_CPU_SCHEME_VERSION, NULL },
	{ "fault.cpu.*.l2data-u", FM_FMRI_SCHEME_CPU,
	    FM_CPU_SCHEME_VERSION, NULL },
	{ "fault.cpu.*.mau", FM_FMRI_SCHEME_CPU,
	    FM_CPU_SCHEME_VERSION, NULL },
	{ "fault.cpu.*.lfu-u", FM_FMRI_SCHEME_CPU,
	    FM_CPU_SCHEME_VERSION, NULL },
	{ "fault.cpu.*.lfu-f", FM_FMRI_SCHEME_CPU,
	    FM_CPU_SCHEME_VERSION, NULL },
	{ "fault.cpu.*.lfu-p", FM_FMRI_SCHEME_CPU,
	    FM_CPU_SCHEME_VERSION, NULL },
	{ "fault.cpu.*", FM_FMRI_SCHEME_CPU, FM_CPU_SCHEME_VERSION,
	    cma_cpu_retire },
	{ NULL, NULL, 0, NULL }
};

static const cma_subscriber_t *
nvl2subr(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t **asrup)
{
	const cma_subscriber_t *sp;
	nvlist_t *asru;
	char *scheme;
	uint8_t version;

	if (nvlist_lookup_nvlist(nvl, FM_FAULT_ASRU, &asru) != 0 ||
	    nvlist_lookup_string(asru, FM_FMRI_SCHEME, &scheme) != 0 ||
	    nvlist_lookup_uint8(asru, FM_VERSION, &version) != 0) {
		cma_stats.bad_flts.fmds_value.ui64++;
		return (NULL);
	}

	for (sp = cma_subrs; sp->subr_class != NULL; sp++) {
		if (fmd_nvl_class_match(hdl, nvl, sp->subr_class) &&
		    strcmp(scheme, sp->subr_sname) == 0 &&
		    version <= sp->subr_svers) {
			*asrup = asru;
			return (sp);
		}
	}

	cma_stats.nop_flts.fmds_value.ui64++;
	return (NULL);
}

static void
cma_recv_list(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	char *uuid = NULL;
	nvlist_t **nva;
	uint_t nvc = 0;
	uint_t keepopen;
	int err = 0;

	err |= nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid);
	err |= nvlist_lookup_nvlist_array(nvl, FM_SUSPECT_FAULT_LIST,
	    &nva, &nvc);
	if (err != 0) {
		cma_stats.bad_flts.fmds_value.ui64++;
		return;
	}

	keepopen = nvc;
	while (nvc-- != 0 && !fmd_case_uuclosed(hdl, uuid)) {
		nvlist_t *nvl = *nva++;
		const cma_subscriber_t *subr;
		nvlist_t *asru;

		if ((subr = nvl2subr(hdl, nvl, &asru)) == NULL)
			continue;

		/*
		 * A handler returns CMA_RA_SUCCESS to indicate that
		 * from this suspects  point-of-view the case may be
		 * closed, CMA_RA_FAILURE otherwise.
		 * A handler must not close the case itself.
		 */
		if (subr->subr_func != NULL) {
			err = subr->subr_func(hdl, nvl, asru, uuid);

			if (err == CMA_RA_SUCCESS)
				keepopen--;
		}
	}

	if (!keepopen)
		fmd_case_uuclose(hdl, uuid);
}

static void
cma_recv_one(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	const cma_subscriber_t *subr;
	nvlist_t *asru;

	if ((subr = nvl2subr(hdl, nvl, &asru)) == NULL)
		return;

	if (subr->subr_func != NULL)
		(void) subr->subr_func(hdl, nvl, asru, NULL);

}

/*ARGSUSED*/
static void
cma_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	fmd_hdl_debug(hdl, "received %s\n", class);

	if (strcmp(class, FM_LIST_SUSPECT_CLASS) == 0)
		cma_recv_list(hdl, nvl);
	else
		cma_recv_one(hdl, nvl);
}

/*ARGSUSED*/
static void
cma_timeout(fmd_hdl_t *hdl, id_t id, void *arg)
{
	if (id == cma.cma_page_timerid)
		cma_page_retry(hdl);
	else if (id == cma.cma_cpu_timerid)
		cma_cpu_retry(hdl);
}

static void *
cma_init_alloc(size_t size)
{
	return (fmd_hdl_alloc(init_hdl, size, FMD_SLEEP));
}

static void
cma_init_free(void *addr, size_t size)
{
	fmd_hdl_free(init_hdl, addr, size);
}

static const fmd_hdl_ops_t fmd_ops = {
	cma_recv,	/* fmdo_recv */
	cma_timeout,	/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
};

static const fmd_prop_t fmd_props[] = {
	{ "cpu_tries", FMD_TYPE_UINT32, "10" },
	{ "cpu_delay", FMD_TYPE_TIME, "1sec" },
	{ "cpu_ret_mindelay", FMD_TYPE_TIME, "5sec" },
	{ "cpu_ret_maxdelay", FMD_TYPE_TIME, "5min" },
	{ "cpu_offline_enable", FMD_TYPE_BOOL, "true" },
	{ "cpu_forced_offline", FMD_TYPE_BOOL, "true" },
	{ "cpu_blacklist_enable", FMD_TYPE_BOOL, "true" },
	{ "page_ret_mindelay", FMD_TYPE_TIME, "1sec" },
	{ "page_ret_maxdelay", FMD_TYPE_TIME, "5min" },
	{ "page_retire_enable", FMD_TYPE_BOOL, "true" },
	{ "page_retire_maxretries", FMD_TYPE_UINT32, "0" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"CPU/Memory Retire Agent", CMA_VERSION, &fmd_ops, fmd_props
};

void
_fmd_init(fmd_hdl_t *hdl)
{
	hrtime_t nsec;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return; /* invalid data in configuration file */

	fmd_hdl_subscribe(hdl, "fault.cpu.*");
	fmd_hdl_subscribe(hdl, "fault.memory.*");

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (cma_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&cma_stats);

	cma.cma_cpu_tries = fmd_prop_get_int32(hdl, "cpu_tries");

	nsec = fmd_prop_get_int64(hdl, "cpu_delay");
	cma.cma_cpu_delay.tv_sec = nsec / NANOSEC;
	cma.cma_cpu_delay.tv_nsec = nsec % NANOSEC;

	cma.cma_page_mindelay = fmd_prop_get_int64(hdl, "page_ret_mindelay");
	cma.cma_page_maxdelay = fmd_prop_get_int64(hdl, "page_ret_maxdelay");

	cma.cma_cpu_mindelay = fmd_prop_get_int64(hdl, "cpu_ret_mindelay");
	cma.cma_cpu_maxdelay = fmd_prop_get_int64(hdl, "cpu_ret_maxdelay");

	cma.cma_cpu_dooffline = fmd_prop_get_int32(hdl, "cpu_offline_enable");
	cma.cma_cpu_forcedoffline = fmd_prop_get_int32(hdl,
	    "cpu_forced_offline");
	cma.cma_cpu_doblacklist = fmd_prop_get_int32(hdl,
	    "cpu_blacklist_enable");
	cma.cma_page_doretire = fmd_prop_get_int32(hdl, "page_retire_enable");
	cma.cma_page_maxretries =
	    fmd_prop_get_int32(hdl, "page_retire_maxretries");

	if (cma.cma_page_maxdelay < cma.cma_page_mindelay)
		fmd_hdl_abort(hdl, "page retirement delays conflict\n");

	init_hdl = hdl;
	cma_lhp = ldom_init(cma_init_alloc, cma_init_free);
}

void
_fmd_fini(fmd_hdl_t *hdl)
{
	ldom_fini(cma_lhp);
	cma_page_fini(hdl);
	cma_cpu_fini(hdl);
}
