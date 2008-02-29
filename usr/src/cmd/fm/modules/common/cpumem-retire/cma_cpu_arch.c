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

int
cma_cpu_blacklist(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru,
    boolean_t repair)
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

	rc = ioctl(fd, repair ? BLIOC_DELETE : BLIOC_INSERT, &blr);
	err = errno;

	fmd_hdl_free(hdl, fmribuf, fmrisz);
	(void) close(fd);

	if (rc < 0 && err != ENOTSUP) {
		errno = err;
		return (-1);
	}

	return (0);
}

/* ARGSUSED */
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

	for (i = 0; i < cma.cma_cpu_tries;
	    i++, (void) nanosleep(&cma.cma_cpu_delay, NULL)) {
		int oldstate;
		if ((oldstate = p_online(cpuid, cpustate)) != -1) {
			fmd_hdl_debug(hdl, "changed cpu %u state from \"%s\" "
			    "to \"%s\"\n", cpuid, p_online_state_fmt(oldstate),
			    p_online_state_fmt(cpustate));
			if (repair)
				cma_stats.cpu_repairs.fmds_value.ui64++;
			else
				cma_stats.cpu_flts.fmds_value.ui64++;
			return (CMA_RA_SUCCESS);
		}
	}

	fmd_hdl_debug(hdl, "failed to changed cpu %u state to \"%s\": %s\n",
	    cpuid, p_online_state_fmt(cpustate), strerror(errno));
	cma_stats.cpu_fails.fmds_value.ui64++;
	return (CMA_RA_FAILURE);
}
