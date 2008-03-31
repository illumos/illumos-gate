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
#include <strings.h>
#include <unistd.h>
#include <fm/fmd_api.h>
#include <sys/fm/protocol.h>
#include <sys/mem_cache.h>

int
/* ARGSUSED 4 */
cma_cache_way_retire(fmd_hdl_t *hdl, nvlist_t *nvl, nvlist_t *asru,
    const char *uuid, boolean_t repair)
{
	uint_t 		cpuid;
	uint32_t 	index, way;
	uint16_t	bit = 0;
	uint8_t		type;
	cache_info_t    cache_info;
	int ret, fd;

	fmd_hdl_debug(hdl, "cpu cache *line* fault processing\n");

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
		fmd_hdl_debug(hdl, "cpu cache fault missing '%s'\n",
		    FM_FMRI_CPU_ID);
		cma_stats.bad_flts.fmds_value.ui64++;
		return (CMA_RA_FAILURE);
	}

	if (nvlist_lookup_uint32(asru, FM_FMRI_CPU_CACHE_INDEX, &index) != 0) {
		fmd_hdl_debug(hdl, "cpu cache fault missing '%s'\n",
		    FM_FMRI_CPU_CACHE_WAY);
		cma_stats.bad_flts.fmds_value.ui64++;
		return (CMA_RA_FAILURE);
	}

	if (nvlist_lookup_uint32(asru, FM_FMRI_CPU_CACHE_WAY, &way) != 0) {
		fmd_hdl_debug(hdl, "cpu cache fault missing '%s'\n",
		    FM_FMRI_CPU_CACHE_WAY);
		cma_stats.bad_flts.fmds_value.ui64++;
		return (CMA_RA_FAILURE);
	}

	if (nvlist_lookup_uint8(asru, FM_FMRI_CPU_CACHE_TYPE, &type) != 0) {
		fmd_hdl_debug(hdl, "cpu cache fault missing '%s'\n",
		    FM_FMRI_CPU_CACHE_TYPE);
		cma_stats.bad_flts.fmds_value.ui64++;
		return (CMA_RA_FAILURE);
	}

	/*
	 * The bit info is optional
	 * Tag faults will use it to set the bit to a stable state
	 */

	(void) nvlist_lookup_uint16(asru, FM_FMRI_CPU_CACHE_BIT, &bit);


	fd = open(mem_cache_device, O_RDWR);
	if (fd == -1) {
		fmd_hdl_debug(hdl, "Driver open failed\n");
		return (CMA_RA_FAILURE);
	}
	cache_info.cpu_id = cpuid;
	cache_info.way = way;
	cache_info.bit = bit;
	cache_info.index = index;

	cache_info.cache = type == FM_FMRI_CPU_CACHE_TYPE_L3 ?
	    L3_CACHE_DATA : L2_CACHE_DATA;

	if (repair) {
		fmd_hdl_debug(hdl,
		    "cpu %d: UnRetiring index 0x%06x, way 0x%02x\n bit 0x%04x"
		    " type 0x%02x", cpuid, index, way, bit, type);
		ret = ioctl(fd, MEM_CACHE_UNRETIRE, &cache_info);
	} else {
		fmd_hdl_debug(hdl,
		    "cpu %d: Retiring index 0x%06x, way 0x%02x\n bit 0x%04x"
		    " type 0x%02x", cpuid, index, way, bit, type);
		ret = ioctl(fd, MEM_CACHE_RETIRE, &cache_info);
	}
	if (ret == -1) {
		fmd_hdl_debug(hdl, "Driver call failed\n");
		return (CMA_RA_FAILURE);
	}

	return (CMA_RA_SUCCESS);
}
