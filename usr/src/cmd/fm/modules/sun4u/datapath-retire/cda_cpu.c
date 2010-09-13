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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <cda.h>

#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/processor.h>

static void
cda_cpu_offline(fmd_hdl_t *hdl, uint_t cpuid, int cpustate)
{
	int i;

	for (i = 0; i < cda.cda_cpu_tries;
	    i++, (void) nanosleep(&cda.cda_cpu_delay, NULL)) {
		if (p_online(cpuid, cpustate) != -1) {
			fmd_hdl_debug(hdl, "offlined cpu %u\n", cpuid);
			cda_stats.dp_offs.fmds_value.ui64++;
			return;
		}
	}

	fmd_hdl_debug(hdl, "failed to offline %u: %s\n", cpuid,
	    strerror(errno));
	cda_stats.dp_fails.fmds_value.ui64++;
}

/*ARGSUSED*/
void
cda_dp_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru, const char *uuid)
{
	int ii;
	uint_t cpuid;
	uint_t hc_nprs;
	nvlist_t **hc_prs;
	char *id;

	/* Get the hc-list of elements in FMRI, and the size of the list */
	if (nvlist_lookup_nvlist_array(asru, FM_FMRI_HC_LIST, &hc_prs,
	    &hc_nprs) != 0) {
		fmd_hdl_debug(hdl, "failed to get '%s' from dp fault\n",
			FM_FMRI_HC_LIST);
		return;
	}

	/* walk hc-list and offline each CPU present */
	for (ii = 0; ii < hc_nprs; ii++) {
		int cpustate = P_FAULTED;

		if (nvlist_lookup_string(hc_prs[ii], FM_FMRI_HC_ID, &id) != 0) {
			fmd_hdl_debug(hdl, "dp fault missing '%s'\n",
			FM_FMRI_HC_ID);
			cda_stats.bad_flts.fmds_value.ui64++;
			return;
		}

		cpuid = atoi(id);
		if (!cda.cda_cpu_dooffline) {
			fmd_hdl_debug(hdl, "dp suppressed offline of "
				"CPU %u\n", cpuid);
			cda_stats.dp_supp.fmds_value.ui64++;
			continue;
		}

		if (cda.cda_cpu_forcedoffline)
			cpustate |= P_FORCED;

		cda_cpu_offline(hdl, cpuid, cpustate);
	}
}
