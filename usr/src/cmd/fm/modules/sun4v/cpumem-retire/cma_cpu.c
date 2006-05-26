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

#include <fcntl.h>
#include <unistd.h>
#include <strings.h>
#include <errno.h>
#include <time.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/processor.h>

static int
cpu_blacklist(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru)
{
	nvlist_t *fmri;
	int rc, err;

	/*
	 * Some platforms have special unums for the E$ DIMMs.  If we're dealing
	 * with a platform that has these unums, one will have been added to the
	 * fault as the resource.  We'll use that for the blacklisting.  If we
	 * can't find a resource, we'll fall back to the ASRU.
	 */
	if (nvlist_lookup_nvlist(nvl, FM_FAULT_RESOURCE, &fmri) != 0)
		fmri = asru;

	rc = cpu_blacklist_cmd(hdl, fmri);
	err = errno;

	if (rc < 0 && err != ENOTSUP) {
		errno = err;
		return (-1);
	}

	return (0);
}

static void
cma_cpu_free(fmd_hdl_t *hdl, cma_cpu_t *cpu)
{
	if (cpu->cpu_fmri != NULL)
		nvlist_free(cpu->cpu_fmri);
	if (cpu->cpu_uuid != NULL)
		fmd_hdl_strfree(hdl, cpu->cpu_uuid);
	fmd_hdl_free(hdl, cpu, sizeof (cma_cpu_t));
}

int
/* ARGSUSED 3 */
cma_cpu_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru, const char *uuid)
{
	uint_t cpuid;
	int err = CMA_RA_FAILURE;

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

	if (cma.cma_cpu_dooffline) {
		int cpustate = P_FAULTED;

		if (cma.cma_cpu_forcedoffline)
			cpustate |= P_FORCED;

		err = cpu_offline(hdl, asru, uuid, cpustate);
	} else {
		fmd_hdl_debug(hdl, "suppressed offline of CPU %u\n", cpuid);
		cma_stats.cpu_supp.fmds_value.ui64++;
	}

	if (cma.cma_cpu_doblacklist) {
		if (cpu_blacklist(hdl, nvl, asru) < 0)
			cma_stats.cpu_blfails.fmds_value.ui64++;
	} else {
		fmd_hdl_debug(hdl, "suppressed blacklist of CPU %u\n", cpuid);
		cma_stats.cpu_blsupp.fmds_value.ui64++;
	}

	return (err);
}

static int
cpu_retry(fmd_hdl_t *hdl, cma_cpu_t *cpu)
{
	int rc = 0;

	fmd_hdl_debug(hdl, "cpu_retry()\n");

	if (cpu->cpu_fmri == NULL) {
		return (1);
	}

	if (!fmd_nvl_fmri_present(hdl, cpu->cpu_fmri)) {
		fmd_hdl_debug(hdl, "cpu %u is not present", cpu->cpuid);
		return (1);
	}

	rc = cpu_cmd(hdl, cpu->cpu_fmri, P_STATUS);
	if (rc == P_FAULTED || rc == P_OFFLINE) {
		fmd_hdl_debug(hdl, "cpu %u is offlined on retry %u\n",
		    cpu->cpuid, cpu->cpu_nretries);
		cma_stats.cpu_flts.fmds_value.ui64++;

		if (cpu->cpu_uuid != NULL)
			fmd_case_uuclose(hdl, cpu->cpu_uuid);
		return (1); /* success */
	}

	if (rc == -1) {
		fmd_hdl_debug(hdl, "failed to retry cpu %u\n", cpu->cpuid);
		cma_stats.page_fails.fmds_value.ui64++;
		return (1); /* give up */
	}

	return (0);
}

void
cma_cpu_retry(fmd_hdl_t *hdl)
{
	cma_cpu_t **cpup;

	fmd_hdl_debug(hdl, "cma_cpu_retry: timer fired\n");

	cma.cma_cpu_timerid = 0;

	cpup = &cma.cma_cpus;
	while (*cpup != NULL) {
		cma_cpu_t *cpu = *cpup;

		if (cpu_retry(hdl, cpu)) {
			/*
			 * Successful retry or we're giving up - remove from
			 * the list
			 */
			*cpup = cpu->cpu_next;

			cma_cpu_free(hdl, cpu);
		} else {
			cpu->cpu_nretries++;
			cpup = &cpu->cpu_next;
		}
	}

	if (cma.cma_cpus == NULL)
		return; /* no more cpus */

	/*
	 * We still have cpus to check.  Back the delay
	 * off, and schedule a retry.
	 */
	cma.cma_cpu_curdelay = MIN(cma.cma_cpu_curdelay * 2,
	    cma.cma_cpu_maxdelay);

	fmd_hdl_debug(hdl, "scheduled cpu offline retry for %llu secs\n",
	    (u_longlong_t)(cma.cma_cpu_curdelay / NANOSEC));

	cma.cma_cpu_timerid =
	    fmd_timer_install(hdl, NULL, NULL, cma.cma_cpu_curdelay);
}

void
cma_cpu_fini(fmd_hdl_t *hdl)
{
	cma_cpu_t *cpu;

	while ((cpu = cma.cma_cpus) != NULL) {
		cma.cma_cpus = cpu->cpu_next;
		cma_cpu_free(hdl, cpu);
	}
}
