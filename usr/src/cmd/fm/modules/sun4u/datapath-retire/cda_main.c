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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Peter Tribble.
 */

#include <cda.h>

#include <strings.h>
#include <errno.h>
#include <time.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>

cda_t cda;

cda_stats_t cda_stats = {
	{ "dp_offs", FMD_TYPE_UINT64, "successful cpu offlines" },
	{ "dp_fails", FMD_TYPE_UINT64, "datapath faults unresolveable" },
	{ "cpu_supp", FMD_TYPE_UINT64, "cpu offlines suppressed" },
	{ "bad_flts", FMD_TYPE_UINT64, "invalid fault events received" },
	{ "nop_flts", FMD_TYPE_UINT64, "inapplicable fault events received" },
};

typedef struct cda_subscriber {
	const char *subr_class;
	const char *subr_sname;
	uint_t subr_svers;
	void (*subr_func)(fmd_hdl_t *, nvlist_t *, nvlist_t *, const char *);
} cda_subscriber_t;

static const cda_subscriber_t cda_subrs[] = {
	{ "fault.asic.*.dp", FM_FMRI_SCHEME_HC, FM_HC_SCHEME_VERSION,
	    cda_dp_retire },
	{ NULL, NULL, 0, NULL }
};

static const cda_subscriber_t *
cda_get_subr(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t **asrup)
{
	const cda_subscriber_t *sp;
	nvlist_t *asru;
	char *scheme;
	uint8_t version;

	if (nvlist_lookup_nvlist(nvl, FM_FAULT_ASRU, &asru) != 0 ||
	    nvlist_lookup_string(asru, FM_FMRI_SCHEME, &scheme) != 0 ||
	    nvlist_lookup_uint8(asru, FM_VERSION, &version) != 0) {
		cda_stats.bad_flts.fmds_value.ui64++;
		return (NULL);
	}

	for (sp = cda_subrs; sp->subr_class != NULL; sp++) {
		if (fmd_nvl_class_match(hdl, nvl, sp->subr_class) &&
		    strcmp(scheme, sp->subr_sname) == 0 &&
		    version <= sp->subr_svers) {
			*asrup = asru;
			return (sp);
		}
	}

	cda_stats.nop_flts.fmds_value.ui64++;
	return (NULL);
}

static void
cda_recv_list(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	char *uuid = NULL;
	nvlist_t **nva;
	uint_t nvc;
	int err = 0;

	err |= nvlist_lookup_string(nvl, FM_SUSPECT_UUID, &uuid);
	err |= nvlist_lookup_nvlist_array(nvl, FM_SUSPECT_FAULT_LIST,
	    &nva, &nvc);
	if (err != 0) {
		cda_stats.bad_flts.fmds_value.ui64++;
		return;
	}

	while (nvc-- != 0) {
		nvlist_t *nvl = *nva++;
		const cda_subscriber_t *subr;
		nvlist_t *asru;

		if (fmd_case_uuclosed(hdl, uuid))
			break;

		if ((subr = cda_get_subr(hdl, nvl, &asru)) == NULL)
			continue;

		if (subr->subr_func != NULL)
			subr->subr_func(hdl, nvl, asru, uuid);
	}
}

static void
cda_recv_one(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	const cda_subscriber_t *subr;
	nvlist_t *asru;

	if ((subr = cda_get_subr(hdl, nvl, &asru)) == NULL)
		return;

	if (subr->subr_func != NULL)
		subr->subr_func(hdl, nvl, asru, NULL);
}

/*ARGSUSED*/
static void
cda_recv(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class)
{
	fmd_hdl_debug(hdl, "received %s\n", class);

	if (strcmp(class, FM_LIST_SUSPECT_CLASS) == 0)
		cda_recv_list(hdl, nvl);
	else
		cda_recv_one(hdl, nvl);
}

static const fmd_hdl_ops_t fmd_ops = {
	cda_recv,	/* fmdo_recv */
	NULL,		/* fmdo_timeout */
	NULL,		/* fmdo_close */
	NULL,		/* fmdo_stats */
	NULL,		/* fmdo_gc */
};

static const fmd_prop_t fmd_props[] = {
	{ "cpu_tries", FMD_TYPE_UINT32, "10" },
	{ "cpu_delay", FMD_TYPE_TIME, "1sec" },
	{ "cpu_offline_enable", FMD_TYPE_BOOL, "true" },
	{ "cpu_forced_offline", FMD_TYPE_BOOL, "true" },
	{ NULL, 0, NULL }
};

static const fmd_hdl_info_t fmd_info = {
	"Datapath Retire Agent", CDA_VERSION, &fmd_ops, fmd_props
};

static int
cda_platform_check_support(fmd_hdl_t *hdl)
{
	char buf[SYS_NMLN];

	if (sysinfo(SI_PLATFORM, buf, sizeof (buf)) == -1) {
		fmd_hdl_debug(hdl, "sysinfo failed");
		return (0);
	}

	if (strcmp(buf, "SUNW,Sun-Fire") == 0 ||
	    strcmp(buf, "SUNW,Netra-T12") == 0)
		return (1);
	else
		return (0);
}

void
_fmd_init(fmd_hdl_t *hdl)
{
	hrtime_t nsec;

	if (fmd_hdl_register(hdl, FMD_API_VERSION, &fmd_info) != 0)
		return; /* invalid data in configuration file */

	if (cda_platform_check_support(hdl) == 0) {
		fmd_hdl_debug(hdl, "platform not supported");
		fmd_hdl_unregister(hdl);
		return;
	}

	fmd_hdl_subscribe(hdl, "fault.asic.*.dp");

	(void) fmd_stat_create(hdl, FMD_STAT_NOALLOC, sizeof (cda_stats) /
	    sizeof (fmd_stat_t), (fmd_stat_t *)&cda_stats);

	cda.cda_cpu_tries = fmd_prop_get_int32(hdl, "cpu_tries");

	nsec = fmd_prop_get_int64(hdl, "cpu_delay");
	cda.cda_cpu_delay.tv_sec = nsec / NANOSEC;
	cda.cda_cpu_delay.tv_nsec = nsec % NANOSEC;

	cda.cda_cpu_dooffline = fmd_prop_get_int32(hdl,
	    "cpu_offline_enable");
	cda.cda_cpu_forcedoffline = fmd_prop_get_int32(hdl,
	    "cpu_forced_offline");
}

/*ARGSUSED*/
void
_fmd_fini(fmd_hdl_t *hdl)
{
}
