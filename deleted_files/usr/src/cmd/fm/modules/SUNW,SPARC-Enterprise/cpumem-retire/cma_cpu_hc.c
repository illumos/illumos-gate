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

#include <cma.h>
#include <opl_cma.h>
#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/processor.h>

int
cma_cpu_hc_offline(fmd_hdl_t *hdl, uint32_t cpuid)
{
	int err = CMA_RA_FAILURE;

	fmd_hdl_debug(hdl, "cma_cpu_hc_offline offline of CPU %u\n", cpuid);
	if (cma.cma_cpu_dooffline) {
		int cpustate = P_FAULTED;

		if (cma.cma_cpu_forcedoffline)
			cpustate |= P_FORCED;

		err = cpu_offline(hdl, cpuid, cpustate);
	} else {
		fmd_hdl_debug(hdl, "suppressed offline of CPU %u\n", cpuid);
		cma_stats.cpu_supp.fmds_value.ui64++;
	}

	if (cma.cma_cpu_doblacklist) {
		fmd_hdl_debug(hdl, "suppressed blacklist of CPU %u\n", cpuid);
		cma_stats.cpu_blsupp.fmds_value.ui64++;
	}

	return (err);
}

int
/* ARGSUSED 3 */
cma_cpu_hc_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru,
    const char *uuid)
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

		if (cma_cpu_hc_offline(hdl, cpuid) != CMA_RA_SUCCESS) {
			cma_stats.bad_flts.fmds_value.ui64++;
			return (CMA_RA_FAILURE);
		}
	}

	return (CMA_RA_SUCCESS);
}
