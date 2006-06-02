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
#include <sys/bl.h>
#include <sys/processor.h>

static int
cpu_blacklist(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru)
{
	bl_req_t blr;
	nvlist_t *fmri;
	char *fmribuf;
	size_t fmrisz;
	int fd, rc, err;
	char *class;

	/*
	 * Some platforms have special unums for the E$ DIMMs.  If we're dealing
	 * with a platform that has these unums, one will have been added to the
	 * fault as the resource.  We'll use that for the blacklisting.  If we
	 * can't find a resource, we'll fall back to the ASRU.
	 */
	if (nvlist_lookup_nvlist(nvl, FM_FAULT_RESOURCE, &fmri) != 0)
		fmri = asru;

	if ((nvlist_lookup_string(nvl, FM_CLASS, &class) != 0) ||
	    (class == NULL) || (*class == '\0')) {
		fmd_hdl_debug(hdl, "failed to get the fault class name\n");
		errno = EINVAL;
		return (-1);
	}

	if ((fd = open("/dev/bl", O_RDONLY)) < 0)
		return (-1); /* errno is set for us */

	if ((errno = nvlist_size(fmri, &fmrisz, NV_ENCODE_NATIVE)) != 0 ||
	    (fmribuf = fmd_hdl_alloc(hdl, fmrisz, FMD_SLEEP)) == NULL) {
		(void) close(fd);
		return (-1); /* errno is set for us */
	}

	if ((errno = nvlist_pack(fmri, &fmribuf, &fmrisz,
	    NV_ENCODE_NATIVE, 0)) != 0) {
		fmd_hdl_free(hdl, fmribuf, fmrisz);
		(void) close(fd);
		return (-1); /* errno is set for us */
	}

	blr.bl_fmri = fmribuf;
	blr.bl_fmrisz = fmrisz;
	blr.bl_class = class;

	rc = ioctl(fd, BLIOC_INSERT, &blr);
	err = errno;

	fmd_hdl_free(hdl, fmribuf, fmrisz);
	(void) close(fd);

	if (rc < 0 && err != ENOTSUP) {
		errno = err;
		return (-1);
	}

	return (0);
}

int
cpu_offline(fmd_hdl_t *hdl, uint_t cpuid, int cpustate)
{
	int i;

	for (i = 0; i < cma.cma_cpu_tries;
	    i++, (void) nanosleep(&cma.cma_cpu_delay, NULL)) {
		if (p_online(cpuid, cpustate) != -1) {
			fmd_hdl_debug(hdl, "offlined cpu %u\n", cpuid);
			cma_stats.cpu_flts.fmds_value.ui64++;
			return (CMA_RA_SUCCESS);
		}
	}

	fmd_hdl_debug(hdl, "failed to offline %u: %s\n", cpuid,
	    strerror(errno));
	cma_stats.cpu_fails.fmds_value.ui64++;
	return (CMA_RA_FAILURE);
}

int
/* ARGSUSED 3 */
cma_cpu_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru, const char *uuid)
{
	uint_t cpuid, cpuvid;
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

	/*
	 * If this asru's FMRI contains a virtual CPU id, use that value for
	 * p_online() call instead of (physical) cpu id.
	 */

	if (nvlist_lookup_uint32(asru, FM_FMRI_CPU_VID, &cpuvid) == 0)
		cpuid = cpuvid;

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
		if (cpu_blacklist(hdl, nvl, asru) < 0)
			cma_stats.cpu_blfails.fmds_value.ui64++;
	} else {
		fmd_hdl_debug(hdl, "suppressed blacklist of CPU %u\n", cpuid);
		cma_stats.cpu_blsupp.fmds_value.ui64++;
	}

	return (err);
}
