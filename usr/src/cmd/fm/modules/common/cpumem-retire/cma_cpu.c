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
 *
 * Copyright 2019 Joyent, Inc.
 */

#include <cma.h>

#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <fm/fmd_api.h>
#include <fm/fmd_agent.h>
#include <sys/fm/protocol.h>
#include <sys/bl.h>
#include <sys/processor.h>

static int cpu_statechange(fmd_hdl_t *, nvlist_t *, nvlist_t *, const char *,
    uint32_t, boolean_t);

#ifndef opl
/*
 * Perform retire/unretire by invoking the topo methods registered in the
 * hc-scheme resource.
 *
 * If the fault is found to be diagnosed under the old topology, the resource
 * will not exist in the current topology, then we fall back to legacy retire
 * (using the "cpu" scheme ASRU).
 */

static boolean_t
old_topo_fault(nvlist_t *nvl)
{
	nvlist_t *rsrc;
#ifdef i386
	nvlist_t **hcl;
	uint_t nhcl = 0;
	char *name;
#endif

	if (nvlist_lookup_nvlist(nvl, FM_FAULT_RESOURCE, &rsrc) != 0)
		return (B_TRUE);
#ifdef i386
	/*
	 * x86 has moved from "motherboard/chip/cpu" topo to
	 * "motherboard/chip/core/strand"
	 */
	if (nvlist_lookup_nvlist_array(rsrc, FM_FMRI_HC_LIST, &hcl, &nhcl)
	    == 0 && nhcl == 3 &&
	    nvlist_lookup_string(hcl[0], FM_FMRI_HC_NAME, &name) == 0 &&
	    strcmp(name, "motherboard") == 0 &&
	    nvlist_lookup_string(hcl[1], FM_FMRI_HC_NAME, &name) == 0 &&
	    strcmp(name, "chip") == 0 &&
	    nvlist_lookup_string(hcl[2], FM_FMRI_HC_NAME, &name) == 0 &&
	    strcmp(name, "cpu") == 0)
		return (B_TRUE);
#endif

	return (B_FALSE);
}

/* ARGSUSED */
int
cma_cpu_hc_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru,
    const char *uuid, boolean_t repair)
{
	int i, err;
	int rc = CMA_RA_SUCCESS;
	nvlist_t *rsrc;

	/*
	 * For the cached faults which were diagnosed under the old
	 * topology,  we fall back to retire by using cpu-scheme ASRUs.
	 * Under xVM Dom0, since logic cpuid in "cpu" scheme ASRU makes no
	 * sense, the fault should be ignored.
	 */
	if (old_topo_fault(nvl)) {
#ifdef i386
		if (! cma_is_native)
			return (CMA_RA_FAILURE);
#endif
		return (cma_cpu_cpu_retire(hdl, nvl, asru, uuid, repair));
	}

	/*
	 * Lookup the resource and call its topo methods to do retire/unretire
	 */
	if ((! repair && ! cma.cma_cpu_dooffline) ||
	    (repair && ! cma.cma_cpu_doonline)) {
		fmd_hdl_debug(hdl, "suppressed %s of CPU\n",
		    repair ? "unretire" : "retire");
		cma_stats.cpu_supp.fmds_value.ui64++;
	} else {
		err = FMD_AGENT_RETIRE_FAIL;
		if (nvlist_lookup_nvlist(nvl, FM_FAULT_RESOURCE, &rsrc) == 0) {
			if (repair) {
				err = fmd_nvl_fmri_unretire(hdl, rsrc);
			} else {
				for (i = 0; i < cma.cma_cpu_tries; i++) {
					err = fmd_nvl_fmri_retire(hdl, rsrc);
					if (err == FMD_AGENT_RETIRE_DONE)
						break;
					(void) nanosleep(&cma.cma_cpu_delay,
					    NULL);
				}
			}
		}
		if (err == FMD_AGENT_RETIRE_DONE) {
			if (repair)
				cma_stats.cpu_repairs.fmds_value.ui64++;
			else
				cma_stats.cpu_flts.fmds_value.ui64++;
		} else {
			rc = CMA_RA_FAILURE;
			cma_stats.bad_flts.fmds_value.ui64++;
#ifdef sun4v
			/* libldom requests are processed asynchronously */
			cma_cpu_start_retry(hdl, nvl, uuid, repair);
#endif
		}
	}

	if ((! repair && ! cma.cma_cpu_doblacklist) ||
	    (repair && ! cma.cma_cpu_dounblacklist)) {
		fmd_hdl_debug(hdl, "suppressed %s of CPU\n",
		    repair ? "unblacklist" : "blacklist");
		cma_stats.cpu_blsupp.fmds_value.ui64++;
	} else {
		if (cma_cpu_blacklist(hdl, nvl, asru, repair) < 0)
			cma_stats.cpu_blfails.fmds_value.ui64++;
	}

	return (rc);
}

#else /* opl */

/* ARGSUSED 4 */
int
cma_cpu_hc_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru,
    const char *uuid, boolean_t repair)
{
	uint_t cpuid;
	uint_t i, nprs;
	nvlist_t **hc_prs = NULL, *hc_spec_nvl;

	/* OPL has ASRU in "hc" scheme */
	if (nvlist_lookup_nvlist(asru, FM_FMRI_HC_SPECIFIC,
	    &hc_spec_nvl) != 0) {
		cma_stats.bad_flts.fmds_value.ui64++;
		fmd_hdl_debug(hdl,
		    "cma_cpu_hc_retire lookup hc_spec_nvl failed\n");
		return (CMA_RA_FAILURE);
	}

	if (nvlist_lookup_nvlist_array(hc_spec_nvl, FM_FMRI_HC_CPUIDS,
	    &hc_prs, &nprs) != 0) {
		cma_stats.bad_flts.fmds_value.ui64++;
		fmd_hdl_debug(hdl,
		    "cma_cpu_hc_retire lookup cpuid array failed\n");
		return (CMA_RA_FAILURE);
	}

	for (i = 0; i < nprs; i++) {
		if (nvlist_lookup_uint32(hc_prs[i],
		    FM_FMRI_CPU_ID, &cpuid) != 0) {
			cma_stats.bad_flts.fmds_value.ui64++;
			return (CMA_RA_FAILURE);
		}

		if (cpu_statechange(hdl, nvl, hc_prs[i], uuid, cpuid, repair)
		    != CMA_RA_SUCCESS) {
			cma_stats.bad_flts.fmds_value.ui64++;
			return (CMA_RA_FAILURE);
		}
	}

	return (CMA_RA_SUCCESS);
}
#endif /* opl */

/*
 * The rest of this file uses ASRUs to do retire, this is now not the
 * preferable way, but it's still needed for some circumstances when
 * retire via topo methods can't work, ie.
 *
 * 1) There are legacy platforms which don't have full topology.
 * 2) The resources in the FMD cached faults may not be set or exist in the
 *    up-to-dated topology.
 */

/* ARGSUSED */
static int
cpu_online(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru, const char *uuid,
    uint32_t cpuid)
{
	int err = CMA_RA_SUCCESS;

	if (cma.cma_cpu_doonline) {
		err = cma_cpu_statechange(hdl, asru, uuid, P_ONLINE,
		    B_TRUE);
	} else {
		fmd_hdl_debug(hdl, "suppressed online of CPU %u\n",
		    cpuid);
		cma_stats.cpu_supp.fmds_value.ui64++;
	}

	/* OPL performs the blacklist in the service processor */
#ifndef opl
	if (cma.cma_cpu_dounblacklist) {
		if (cma_cpu_blacklist(hdl, nvl, asru, B_TRUE) < 0)
			cma_stats.cpu_blfails.fmds_value.ui64++;
	} else {
		fmd_hdl_debug(hdl, "suppressed unblacklist of CPU %u\n", cpuid);
		cma_stats.cpu_blsupp.fmds_value.ui64++;
	}
#endif /* opl */

	return (err);
}

/* ARGSUSED */
static int
cpu_offline(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru, const char *uuid,
    uint32_t cpuid)
{
	int err = CMA_RA_FAILURE;

	if (cma.cma_cpu_dooffline) {
		int cpustate = P_FAULTED;

		if (cma.cma_cpu_forcedoffline)
			cpustate |= P_FORCED;
		err = cma_cpu_statechange(hdl, asru, uuid, cpustate,
		    B_FALSE);
	} else {
		fmd_hdl_debug(hdl, "suppressed offline of CPU %u\n",
		    cpuid);
		cma_stats.cpu_supp.fmds_value.ui64++;
	}

	/* OPL performs the blacklist in the service processor */
#ifndef opl
	if (cma.cma_cpu_doblacklist) {
		if (cma_cpu_blacklist(hdl, nvl, asru, B_FALSE) < 0)
			cma_stats.cpu_blfails.fmds_value.ui64++;
	} else {
		fmd_hdl_debug(hdl, "suppressed blacklist of CPU %u\n",
		    cpuid);
		cma_stats.cpu_blsupp.fmds_value.ui64++;
	}
#endif /* opl */

	return (err);
}

static int
cpu_statechange(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru, const char *uuid,
    uint32_t cpuid, boolean_t repair)
{
	if (repair)
		return (cpu_online(hdl, nvl, asru, uuid, cpuid));
	else
		return (cpu_offline(hdl, nvl, asru, uuid, cpuid));
}

const char *
p_online_state_fmt(int state)
{
	state &= ~P_FORCED;
	switch (state) {
	case P_OFFLINE:
		return (PS_OFFLINE);
	case P_ONLINE:
		return (PS_ONLINE);
	case P_FAULTED:
		return (PS_FAULTED);
	case P_POWEROFF:
		return (PS_POWEROFF);
	case P_NOINTR:
		return (PS_NOINTR);
	case P_SPARE:
		return (PS_SPARE);
	case P_DISABLED:
		return (PS_DISABLED);
	default:
		return ("unknown");
	}
}

int
cma_cpu_cpu_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru,
    const char *uuid, boolean_t repair)
{
	uint_t cpuid;

	if (nvlist_lookup_uint32(asru, FM_FMRI_CPU_ID, &cpuid) != 0) {
		fmd_hdl_debug(hdl, "cpu fault missing '%s'\n", FM_FMRI_CPU_ID);
		cma_stats.bad_flts.fmds_value.ui64++;
		return (CMA_RA_FAILURE);
	}

	return (cpu_statechange(hdl, nvl, asru, uuid, cpuid, repair));
}
