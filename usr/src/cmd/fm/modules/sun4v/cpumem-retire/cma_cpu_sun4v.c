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

#include <cma.h>

#include <sys/fm/ldom.h>
#include <sys/fm/protocol.h>
#include <fm/fmd_fmri.h>
#include <fm/libtopo.h>

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
cpu_blacklist_cmd(fmd_hdl_t *hdl, nvlist_t *fmri, boolean_t repair)
{
	if (repair)
		return (ldom_fmri_unblacklist(cma_lhp, fmri));
	else
		return (ldom_fmri_blacklist(cma_lhp, fmri));
}

int
cma_cpu_blacklist(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru,
    boolean_t repair)
{
	nvlist_t *fmri;
	int rc, err;

	/*
	 * Some platforms have special unums for the E$ DIMMs.	If we're dealing
	 * with a platform that has these unums, one will have been added to the
	 * fault as the resource.  We'll use that for the blacklisting.  If we
	 * can't find a resource, we'll fall back to the ASRU.
	 */
	if (nvlist_lookup_nvlist(nvl, FM_FAULT_RESOURCE, &fmri) != 0)
		fmri = asru;

	rc = cpu_blacklist_cmd(hdl, fmri, repair);
	err = errno;

	if (rc < 0 && err != ENOTSUP) {
		errno = err;
		return (-1);
	}

	return (0);
}

/*ARGSUSED*/
static int
cpu_cmd(fmd_hdl_t *hdl, nvlist_t *fmri, int cmd)
{
	int rc = 0;
	char *scheme;

	/*
	 * We're using topo retire if the fmri is in "hc" scheme.
	 */
	if (nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) == 0 &&
	    strcmp(scheme, FM_FMRI_SCHEME_HC) == 0) {
		if (cmd != P_STATUS) {
			errno = EINVAL;
			return (-1);
		}
		rc = fmd_nvl_fmri_service_state(hdl, fmri);
		switch (rc) {
		case FMD_SERVICE_STATE_UNUSABLE:
			return (P_FAULTED);
		case -1:
			return (-1);
		default:
			return (P_ONLINE);
		}
	}

	switch (cmd & ~P_FORCED) {
	case P_STATUS:
		rc = ldom_fmri_status(cma_lhp, fmri);
		break;
	case P_FAULTED:
		rc = ldom_fmri_retire(cma_lhp, fmri);
		break;
	case P_ONLINE:
		rc = ldom_fmri_unretire(cma_lhp, fmri);
		break;
	default:
		errno = EINVAL;
		return (-1);
	}

	if (rc != P_OFFLINE && rc != P_ONLINE && rc != P_FAULTED) {
		errno = rc;
		return (-1);
	}

	return (rc);
}

void
cma_cpu_start_retry(fmd_hdl_t *hdl, nvlist_t *fmri, const char *uuid,
    boolean_t repair)
{
	cma_cpu_t *cpu;
	char *scheme;
	uint_t cpuid;
	nvlist_t *asru = NULL;
	topo_hdl_t *thp;
	int err;

	if (repair || nvlist_lookup_string(fmri, FM_FMRI_SCHEME, &scheme) != 0)
		return;
	if (strcmp(scheme, FM_FMRI_SCHEME_CPU) == 0) {
		if (nvlist_lookup_uint32(fmri, FM_FMRI_CPU_ID, &cpuid) != 0)
			return;
	} else if (strcmp(scheme, FM_FMRI_SCHEME_HC) != 0) {
		return;
	} else {
		/* lookup cpuid from ASRU */
		thp = fmd_fmri_topo_hold(TOPO_VERSION);
		if (thp != NULL) {
			(void) topo_fmri_asru(thp, fmri, &asru, &err);
			fmd_fmri_topo_rele(thp);
		}
		if (nvlist_lookup_uint32(asru, FM_FMRI_CPU_ID, &cpuid) != 0) {
			nvlist_free(asru);
			return;
		}
	}

	/*
	 * check to see if the cpu has been offline.
	 */
	fmd_hdl_debug(hdl, "cpu %u is not offline yet - sleeping\n", cpuid);

	/*
	 * Create a cpu node and add to the head of the cpu list
	 */
	cpu = fmd_hdl_zalloc(hdl, sizeof (cma_cpu_t), FMD_SLEEP);
	(void) nvlist_dup(fmri, &cpu->cpu_fmri, 0);
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
}


int
cma_cpu_statechange(fmd_hdl_t *hdl, nvlist_t *asru, const char *uuid,
    int cpustate, boolean_t repair)
{
	int i;
	uint_t cpuid;

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
			if (repair)
				cma_stats.cpu_repairs.fmds_value.ui64++;
			else
				cma_stats.cpu_flts.fmds_value.ui64++;
			break;
		}
	}

	if (i >= cma.cma_cpu_tries) {
		cma_stats.cpu_fails.fmds_value.ui64++;
	}

	cma_cpu_start_retry(hdl, asru, uuid, repair);

	return (CMA_RA_FAILURE);
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

static void
cma_cpu_free(fmd_hdl_t *hdl, cma_cpu_t *cpu)
{
	nvlist_free(cpu->cpu_fmri);
	if (cpu->cpu_uuid != NULL)
		fmd_hdl_strfree(hdl, cpu->cpu_uuid);
	fmd_hdl_free(hdl, cpu, sizeof (cma_cpu_t));
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
