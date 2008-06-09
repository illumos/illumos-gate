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

/*
 * OPL platform specific functions for
 * CPU/Memory error diagnosis engine.
 */
#include <cmd_opl.h>
#include <string.h>
#include <errno.h>
#include <cmd_mem.h>
#include <sys/fm/protocol.h>
#include <sys/int_const.h>

cmd_list_t *
opl_cpulist_insert(fmd_hdl_t *hdl, uint32_t cpuid, int flt_type)
{
	opl_cpu_t *opl_cpu = NULL;
	cmd_list_t *list_head = NULL;
	uint32_t c, s, sib_cpuid, base_cpuid;

	switch (flt_type) {
	case IS_STRAND:
		opl_cpu = fmd_hdl_alloc(hdl, sizeof (opl_cpu_t), FMD_SLEEP);
		opl_cpu->oc_cpuid = cpuid;
		cmd_list_append(&opl_cpu_list, opl_cpu);
		list_head = &opl_cpu_list;
		break;

	case IS_CORE:
		/*
		 * Currently there are only two strands per core.
		 * Xor the least significant bit to get the sibling strand
		 */
		sib_cpuid = cpuid ^ 1;
		for (s = 0; s <= STRAND_UPPER_BOUND; s++) {
			opl_cpu = fmd_hdl_alloc(hdl, sizeof (opl_cpu_t),
			    FMD_SLEEP);
			if (s == 0) {
				opl_cpu->oc_cpuid = cpuid;
				cmd_list_append(&opl_cpu_list, opl_cpu);
				list_head = &opl_cpu_list;
			} else {
				opl_cpu->oc_cpuid = sib_cpuid;
				cmd_list_insert_after(&opl_cpu_list,
				    list_head, opl_cpu);
			}
		}
		break;

	case IS_CHIP:
		/*
		 * Enumerate all the cpus/strands based on the max # of cores
		 * within a chip and max # of strands within a core.
		 */
		base_cpuid = (cpuid >> CHIPID_SHIFT) << CHIPID_SHIFT;
		for (c = 0; c <= CORE_UPPER_BOUND; c++) {
			for (s = 0; s <= STRAND_UPPER_BOUND; s++) {
				opl_cpu = fmd_hdl_alloc(hdl,
				    sizeof (opl_cpu_t), FMD_SLEEP);
				opl_cpu->oc_cpuid = base_cpuid |
				    c << COREID_SHIFT | s;
				if (c == 0 && s == 0) {
					cmd_list_append(&opl_cpu_list, opl_cpu);
					list_head = &opl_cpu_list;
				} else
					cmd_list_insert_after(&opl_cpu_list,
					    list_head, opl_cpu);
			}
		}
		break;

	default:
		list_head = NULL;
		break;
	}

	return (list_head);
}

void
opl_cpulist_free(fmd_hdl_t *hdl, cmd_list_t *cpu_list)
{
	opl_cpu_t *opl_cpu;

	fmd_hdl_debug(hdl,
	    "Enter opl_cpulist_free for cpulist %llx\n", cpu_list);

	while ((opl_cpu = cmd_list_next(cpu_list)) != NULL) {
		cmd_list_delete(cpu_list, opl_cpu);
		fmd_hdl_free(hdl, opl_cpu, sizeof (opl_cpu_t));
	}
}

/*
 * Based on "avg" function of eversholt
 */
uint8_t
opl_avg(uint_t sum, uint_t cnt)
{
	unsigned long long s = sum * 10;

	return ((s / cnt / 10) + (((s / cnt % 10) >= 5) ? 1 : 0));
}

/*
 * This function builds the resource fmri page based on
 * the kstat "cpu_fru" of the faulted cpu and cpuid
 * using the "hc" scheme.
 */
nvlist_t *
opl_cpursrc_create(fmd_hdl_t *hdl, uint32_t cpuid)
{
	nvlist_t *fmri;
	char *frustr, *comp;
	int cmu_num;

	if ((errno = nvlist_alloc(&fmri, NV_UNIQUE_NAME, 0)) != 0)
		return (NULL);

	if ((frustr = cmd_cpu_getfrustr_by_id(hdl, cpuid)) == NULL) {
		nvlist_free(fmri);
		return (NULL);
	}

	/*
	 * get the CMU # from cpu_fru for each model
	 * exit with an error if we can not find one.
	 */
	if (strncmp(frustr, OPL_CPU_FRU_FMRI_DC,
	    sizeof (OPL_CPU_FRU_FMRI_DC) - 1) == 0) {
		comp = frustr + sizeof (OPL_CPU_FRU_FMRI_DC) - 1;
		(void) sscanf(comp, "%2d", &cmu_num);
	} else if (strncmp(frustr, OPL_CPU_FRU_FMRI_FF1,
	    sizeof (OPL_CPU_FRU_FMRI_FF1) - 1) == 0) {
		comp = frustr + sizeof (OPL_CPU_FRU_FMRI_FF1) - 1;
		(void) sscanf(comp, "%d", &cmu_num);
		cmu_num /= 2;
	} else if (strncmp(frustr, OPL_CPU_FRU_FMRI_FF2,
	    sizeof (OPL_CPU_FRU_FMRI_FF2) - 1) == 0) {
		comp = frustr + sizeof (OPL_CPU_FRU_FMRI_FF2) - 1;
		(void) sscanf(comp, "%d", &cmu_num);
		cmu_num /= 2;
	} else if (strncmp(frustr, OPL_CPU_FRU_FMRI_IKKAKU,
	    sizeof (OPL_CPU_FRU_FMRI_IKKAKU) - 1) == 0) {
		cmu_num = 0;
	} else {
		CMD_STAT_BUMP(bad_cpu_asru);
		fmd_hdl_strfree(hdl, frustr);
		nvlist_free(fmri);
		return (NULL);
	}

	if (cmd_fmri_hc_set(hdl, fmri, FM_HC_SCHEME_VERSION, NULL, NULL,
	    NPAIRS, "chassis", 0, "cmu", cmu_num, "chip",
	    ((cpuid >> CHIPID_SHIFT) & CHIP_OR_CORE_MASK),
	    "core", ((cpuid >> COREID_SHIFT) & CHIP_OR_CORE_MASK),
	    "strand", (cpuid & STRAND_MASK)) != 0) {
		fmd_hdl_strfree(hdl, frustr);
		nvlist_free(fmri);
		return (NULL);
	}

	fmd_hdl_strfree(hdl, frustr);
	return (fmri);
}

nvlist_t *
opl_mem_fru_create(fmd_hdl_t *hdl, nvlist_t *nvl)
{
	nvlist_t *fmri;
	char *unum;
	char **serids;
	size_t nserids;


	if (nvlist_lookup_string(nvl, FM_FMRI_MEM_UNUM, &unum) != 0)
		return (NULL);

	fmd_hdl_debug(hdl, "opl_mem_fru_create for mem %s\n", unum);

	if ((fmri = cmd_mem_fmri_create(unum, NULL, 0)) == NULL)
		return (NULL);

	if ((nvlist_lookup_string_array(nvl, FM_FMRI_MEM_SERIAL_ID, &serids,
	    &nserids)) == 0) {
		if ((nvlist_add_string_array(fmri, FM_FMRI_MEM_SERIAL_ID,
		    serids, nserids)) != 0) {
			nvlist_free(fmri);
			return (NULL);
		}
	}

	return (fmri);
}
