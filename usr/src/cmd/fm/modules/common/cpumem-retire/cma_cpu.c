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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <cma.h>

#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/bl.h>
#include <sys/processor.h>

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
	default:
		return ("unknown");
	}
}

int
cma_cpu_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru, const char *uuid,
    boolean_t repair)
{
	uint_t cpuid;

	/*
	 * This added expansion is needed to cover the situation where a
	 * cpu fault from the resource cache is replayed at fmd restart,
	 * and the cpu resource has been remapped or replaced.  The stored
	 * FMRI is expanded, but may have stale data.
	 */
	if (fmd_nvl_fmri_expand(hdl, asru) < 0) {
		fmd_hdl_debug(hdl, "failed to expand cpu asru\n");
		cma_stats.bad_flts.fmds_value.ui64++;
		return (CMA_RA_FAILURE);
	}

	if (nvlist_lookup_uint32(asru, FM_FMRI_CPU_ID, &cpuid) != 0) {
		fmd_hdl_debug(hdl, "cpu fault missing '%s'\n", FM_FMRI_CPU_ID);
		cma_stats.bad_flts.fmds_value.ui64++;
		return (CMA_RA_FAILURE);
	}

	return (cpu_statechange(hdl, nvl, asru, uuid, cpuid, repair));
}

#ifdef opl
/* ARGSUSED 4 */
int
cma_cpu_hc_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru,
    const char *uuid, boolean_t repair)
{
	uint_t cpuid;
	uint_t i, nprs;
	nvlist_t **hc_prs = NULL, *hc_spec_nvl;

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
