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

#include <sys/fm/ldom.h>
#include <sys/fm/protocol.h>

#include <assert.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/processor.h>

extern ldom_hdl_t *cma_lhp;

/*ARGSUSED*/
int
cpu_blacklist_cmd(fmd_hdl_t *hdl, nvlist_t *fmri)
{
	return (ldom_fmri_blacklist(cma_lhp, fmri));
}

/*ARGSUSED*/
int
cpu_cmd(fmd_hdl_t *hdl, nvlist_t *fmri, int cmd)
{
	int rc = 0;

	if (cmd & P_STATUS) {
		rc = ldom_fmri_status(cma_lhp, fmri);
	} else if (cmd & P_FAULTED) {
		rc = ldom_fmri_retire(cma_lhp, fmri);
	} else {
		errno = EINVAL;
		return (-1);
	}

	if (rc != P_OFFLINE && rc != P_ONLINE && rc != P_FAULTED) {
		errno = rc;
		return (-1);
	}

	return (rc);
}


int
cpu_offline(fmd_hdl_t *hdl, nvlist_t *asru, const char *uuid, int cpustate)
{
	int i;
	uint_t cpuid;
	cma_cpu_t *cpu;

	if (nvlist_lookup_uint32(asru, FM_FMRI_CPU_ID, &cpuid) != 0) {
		fmd_hdl_debug(hdl, "missing '%s'\n", FM_FMRI_CPU_ID);
		cma_stats.bad_flts.fmds_value.ui64++;
		return (CMA_RA_FAILURE);
	}

	/*
	 * cpu offlining using ldom_fmri_retire() may be asynchronous, so we
	 * have to set the timer and check the cpu status later.
	 */
	for (i = 0; i < cma.cma_cpu_tries;
	    i++, (void) nanosleep(&cma.cma_cpu_delay, NULL)) {
		if (cpu_cmd(hdl, asru, cpustate) != -1) {
			cma_stats.cpu_flts.fmds_value.ui64++;
			break;
		}
	}

	if (i >= cma.cma_cpu_tries) {
		cma_stats.cpu_fails.fmds_value.ui64++;
	}

	/*
	 * check to see if the cpu has been offline.
	 */
	fmd_hdl_debug(hdl, "cpu is not offline yet - sleeping\n");

	/*
	 * Create a cpu node and add to the head of the cpu list
	 */
	cpu = fmd_hdl_zalloc(hdl, sizeof (cma_cpu_t), FMD_SLEEP);
	(void) nvlist_dup(asru, &cpu->cpu_fmri, 0);
	if (uuid != NULL)
		cpu->cpu_uuid = fmd_hdl_strdup(hdl, uuid, FMD_SLEEP);

	cpu->cpuid = cpuid;
	cpu->cpu_next = cma.cma_cpus;
	cma.cma_cpus = cpu;

	if (cma.cma_cpu_timerid != 0)
		fmd_timer_remove(hdl, cma.cma_cpu_timerid);

	cma.cma_cpu_curdelay = cma.cma_cpu_mindelay;

	cma.cma_cpu_timerid =
	    fmd_timer_install(hdl, NULL, NULL, cma.cma_cpu_curdelay);

	return (CMA_RA_FAILURE);
}
