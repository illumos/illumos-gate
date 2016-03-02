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

#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <libnvpair.h>
#include <sys/fcntl.h>
#include <sys/devfm.h>
#include <fmd_agent_impl.h>

static int
cleanup_set_errno(fmd_agent_hdl_t *hdl, nvlist_t *innvl, nvlist_t *outnvl,
    int err)
{
	nvlist_free(innvl);
	nvlist_free(outnvl);
	return (fmd_agent_seterrno(hdl, err));
}

static int
fmd_agent_physcpu_info_v1(fmd_agent_hdl_t *hdl, nvlist_t ***cpusp,
    uint_t *ncpup)
{
	int err;
	nvlist_t *nvl, **nvl_array, **cpus;
	uint_t i, n;

	if ((err = fmd_agent_nvl_ioctl(hdl, FM_IOC_PHYSCPU_INFO, 1,
	    NULL, &nvl)) != 0)
		return (cleanup_set_errno(hdl, NULL, NULL, err));
	if ((err = nvlist_lookup_nvlist_array(nvl, FM_PHYSCPU_INFO_CPUS,
	    &cpus, &n)) != 0)
		return (cleanup_set_errno(hdl, NULL, nvl, err));

	if ((nvl_array = umem_alloc(sizeof (nvlist_t *) * n, UMEM_DEFAULT))
	    == NULL)
		return (cleanup_set_errno(hdl, NULL, nvl, errno));
	for (i = 0; i < n; i++) {
		if ((err = nvlist_dup(cpus[i], nvl_array + i, 0)) != 0) {
			while (i > 0)
				nvlist_free(nvl_array[--i]);
			umem_free(nvl_array, sizeof (nvlist_t *) * n);
			return (cleanup_set_errno(hdl, NULL, nvl, err));
		}
	}

	nvlist_free(nvl);
	*cpusp = nvl_array;
	*ncpup = n;
	return (0);
}

int
fmd_agent_physcpu_info(fmd_agent_hdl_t *hdl, nvlist_t ***cpusp, uint_t *ncpu)
{
	uint32_t ver;

	if (fmd_agent_version(hdl, FM_CPU_INFO_VERSION, &ver) == -1)
		return (fmd_agent_seterrno(hdl, errno));

	switch (ver) {
	case 1:
		return (fmd_agent_physcpu_info_v1(hdl, cpusp, ncpu));

	default:
		return (fmd_agent_seterrno(hdl, ENOTSUP));
	}
}

static int
fmd_agent_cpuop_v1(fmd_agent_hdl_t *hdl, int cmd, int chipid, int coreid,
    int strandid, int *old_status)
{
	int err;
	nvlist_t *nvl = NULL, *outnvl = NULL;
	int32_t status;

	if ((err = nvlist_alloc(&nvl, NV_UNIQUE_NAME_TYPE, 0)) != 0 ||
	    (err = nvlist_add_int32(nvl, FM_CPU_RETIRE_CHIP_ID, chipid)) != 0 ||
	    (err = nvlist_add_int32(nvl, FM_CPU_RETIRE_CORE_ID, coreid)) != 0 ||
	    (err = nvlist_add_int32(nvl, FM_CPU_RETIRE_STRAND_ID, strandid))
	    != 0 || (err = fmd_agent_nvl_ioctl(hdl, cmd, 1, nvl, &outnvl)) != 0)
		return (cleanup_set_errno(hdl, nvl, NULL, err));

	nvlist_free(nvl);
	if (outnvl != NULL) {
		if (old_status != NULL) {
			(void) nvlist_lookup_int32(outnvl,
			    FM_CPU_RETIRE_OLDSTATUS, &status);
			*old_status = status;
		}
		nvlist_free(outnvl);
	}

	return (0);
}

static int
fmd_agent_cpuop(fmd_agent_hdl_t *hdl, int cmd, int chipid, int coreid,
    int strandid, int *old_status)
{
	uint32_t ver;

	if (fmd_agent_version(hdl, FM_CPU_OP_VERSION, &ver) == -1)
		return (cleanup_set_errno(hdl, NULL, NULL, errno));

	switch (ver) {
	case 1:
		return (fmd_agent_cpuop_v1(hdl, cmd, chipid, coreid, strandid,
		    old_status));

	default:
		return (fmd_agent_seterrno(hdl, ENOTSUP));
	}
}

int
fmd_agent_cpu_retire(fmd_agent_hdl_t *hdl, int chipid, int coreid, int strandid)
{
	int ret;

	ret = fmd_agent_cpuop(hdl, FM_IOC_CPU_RETIRE, chipid, coreid, strandid,
	    NULL);

	return (ret == 0 ? FMD_AGENT_RETIRE_DONE : FMD_AGENT_RETIRE_FAIL);
}

int
fmd_agent_cpu_isretired(fmd_agent_hdl_t *hdl, int chipid, int coreid,
    int strandid)
{
	int ret, status;

	ret = fmd_agent_cpuop(hdl, FM_IOC_CPU_STATUS, chipid, coreid, strandid,
	    &status);

	return (ret == 0 && status != P_ONLINE ?
	    FMD_AGENT_RETIRE_DONE : FMD_AGENT_RETIRE_FAIL);
}

int
fmd_agent_cpu_unretire(fmd_agent_hdl_t *hdl, int chipid, int coreid,
    int strandid)
{
	int ret;

	ret = fmd_agent_cpuop(hdl, FM_IOC_CPU_UNRETIRE, chipid, coreid,
	    strandid, NULL);

	return (ret == 0 ? FMD_AGENT_RETIRE_DONE : FMD_AGENT_RETIRE_FAIL);
}
