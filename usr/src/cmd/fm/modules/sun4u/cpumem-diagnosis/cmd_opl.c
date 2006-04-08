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

/*
 * OPL platform specific functions for
 * CPU/Memory error diagnosis engine.
 */
#include <cmd.h>
#include <cmd_page.h>
#include <cmd_opl.h>
#include <string.h>
#include <errno.h>
#include <kstat.h>

#include <sys/fm/protocol.h>
#include <sys/fm/io/opl_mc_fm.h>
#include <sys/async.h>
#include <sys/opl_olympus_regs.h>
#include <sys/fm/cpu/SPARC64-VI.h>
#include <sys/int_const.h>

/*
 * derived from cpu scheme function "cpu_get_serialid_kstat".
 */
static int
opl_cpu_get_serialid_kstat(uint32_t cpuid, uint64_t *serialidp)
{
	kstat_named_t *kn;
	kstat_ctl_t *kc;
	kstat_t *ksp;
	int i;

	if ((kc = kstat_open()) == NULL) /* XXX commonify */
		return (-1); /* errno is set for us */

	if ((ksp = kstat_lookup(kc, "cpu_info", cpuid, NULL)) == NULL) {
		(void) kstat_close(kc);
		return (cmd_set_errno(ENOENT));
	}

	if (kstat_read(kc, ksp, NULL) == -1) {
		int oserr = errno;
		(void) kstat_close(kc);
		return (cmd_set_errno(oserr));
	}

	for (kn = ksp->ks_data, i = 0; i < ksp->ks_ndata; i++, kn++) {
		if (strcmp(kn->name, "device_ID") == 0) {
			*serialidp = kn->value.ui64;
			(void) kstat_close(kc);
			return (0);
		}
	}

	(void) kstat_close(kc);

	return (cmd_set_errno(ENOENT));
}

/*
 * This function builds the ASRU page
 * of the given cpuid based on the CPU scheme.
 */
nvlist_t *
opl_cmd_cpu_asru_create(uint32_t cpuid, uint8_t cpumask)
{
	uint64_t serialid;
	nvlist_t *fmri;
	char sbuf[21]; /* sizeof (UINT64_MAX) + '\0' */

	if ((errno = nvlist_alloc(&fmri, NV_UNIQUE_NAME, 0)) != 0)
		return (NULL);

	if (opl_cpu_get_serialid_kstat(cpuid, &serialid) != 0) {
		nvlist_free(fmri);
		return (NULL);
	}

	/*
	 *  Version 1 calls for a string-based serial number
	 */
	(void) snprintf(sbuf, sizeof (sbuf), "%llX", (u_longlong_t)serialid);

	if (nvlist_add_uint8(fmri, FM_VERSION,
	    FM_CPU_SCHEME_VERSION) != 0 || nvlist_add_string(fmri,
	    FM_FMRI_SCHEME, FM_FMRI_SCHEME_CPU) != 0 ||
	    nvlist_add_uint32(fmri, FM_FMRI_CPU_ID, cpuid) != 0 ||
	    nvlist_add_string(fmri, FM_FMRI_CPU_SERIAL_ID, sbuf) != 0 ||
	    nvlist_add_uint8(fmri, FM_FMRI_CPU_MASK, cpumask) != 0) {
		nvlist_free(fmri);
		return (NULL);
	}

	return (fmri);
}

opl_cpu_list_t *
opl_alloc_struct(fmd_hdl_t *hdl, uint32_t cpuid, int flt_type)
{
	opl_cpu_list_t *p = NULL, *pp = NULL, *first_p = NULL;
	uint32_t c, s, sib_cpuid, cur_cpuid;

	switch (flt_type) {
	case IS_STRAND:
		p = fmd_hdl_alloc(hdl, sizeof (opl_cpu_list_t), FMD_SLEEP);
		if (p != NULL) {
			p->cpuid = cpuid;
			p->next_cpu = NULL;
			first_p = p;
		} else
			first_p = NULL;
		break;

	case IS_CORE:
		/*
		 * Based on the Olympus-C CPUID definition in multi-strands
		 * mode to flip the bits to get the sibling strands
		 */
		sib_cpuid = cpuid ^ 1;
		for (s = 0; s <= STRAND_UPPER_BOUND; s++) {
			p = fmd_hdl_alloc(hdl, sizeof (opl_cpu_list_t),
			    FMD_SLEEP);
			if (p == NULL) {
				if (s > 0)
					fmd_hdl_free(hdl, pp,
					    sizeof (opl_cpu_list_t));
				return (p);
			}
			if (s == 0) {
				p->cpuid = cpuid;
				p->next_cpu = NULL;
				pp = p;
				first_p = p;
			} else {
				p->cpuid = sib_cpuid;
				p->next_cpu = NULL;
				pp->next_cpu = p;
			}
		}
		break;

	case IS_CHIP:
		/*
		 * Based on the Olympus-C CPUID definition in multi-strand
		 * mode to flip the bits in CPUID for getting the sibling
		 * strand IDs
		 */
		cur_cpuid = cpuid;
		for (c = 0; c <= CORE_UPPER_BOUND; c++) {
			sib_cpuid = cur_cpuid;
			for (s = 0; s <= 1; s++) {
				p = fmd_hdl_alloc(hdl,
				    sizeof (opl_cpu_list_t), FMD_SLEEP);
				if (p == NULL) {
					if (c > 0)
						opl_free_struct(hdl, first_p);
					return (p);
				} else {
					if (c == 0 && s == 0) {
						p->cpuid = cpuid;
						p->next_cpu = NULL;
						first_p = p;
					} else {
						p->cpuid = sib_cpuid;
						p->next_cpu = NULL;
						pp->next_cpu = p;
					}
				}
				pp = p;
				sib_cpuid = cur_cpuid ^ 1;
			}
			cur_cpuid = cur_cpuid ^ 2;
		}
		break;

	default:
		first_p = NULL;
		break;
	}

	return (first_p);
}

void
opl_free_struct(fmd_hdl_t *hdl, opl_cpu_list_t *cpu_list)
{
	opl_cpu_list_t *p, *pp;

	for (p = cpu_list; p != NULL; ) {
		pp = p;
		if (p != NULL)
			p = p->next_cpu;
		fmd_hdl_free(hdl, pp, sizeof (opl_cpu_list_t));
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

void
opl_free_nvpairs(nvlist_t *nvpairs[], uint_t npairs)
{
	uint_t idx;

	if (!npairs) {
		for (idx = 0; idx < npairs; idx++)
			nvlist_free(nvpairs[idx]);
	}
}

/*
 * This function builds the resource fmri page based on
 * the kstat "cpu_fru" of the faulted cpu and cpuid
 * using the "hc" scheme.
 */
nvlist_t *
opl_cmd_cpu_rsrc_create(fmd_hdl_t *hdl, uint32_t cpuid)
{
	nvlist_t *fmri, *pairs[LIST_SIZE];
	uint_t npairs;
	char *frustr, *comp;
	char chip_str[STR_BUFLEN];
	char core_str[STR_BUFLEN];
	char strand_str[STR_BUFLEN];

	for (npairs = 0; npairs < LIST_SIZE; npairs++) {
		if ((errno = nvlist_alloc(&pairs[npairs],
		    NV_UNIQUE_NAME, 0)) != 0) {
			opl_free_nvpairs(pairs, npairs);
			return (NULL);
		}
	}

	if ((errno = nvlist_alloc(&fmri, NV_UNIQUE_NAME, 0)) != 0) {
		opl_free_nvpairs(pairs, npairs);
		return (NULL);
	}

	if ((frustr = cpu_getfrustr(hdl, cpuid)) == NULL) {
		opl_free_nvpairs(pairs, npairs);
		nvlist_free(fmri);
		return (NULL);
	}

	/*
	 * get the CMU # from cpu_fru
	 */
	if (strncmp(frustr, OPL_CPU_FRU_FMRI,
	    sizeof (OPL_CPU_FRU_FMRI) - 1) == 0) {
		comp = frustr + sizeof (OPL_CPU_FRU_FMRI) - 1;
	/*
	 * incorrect format; default to zero
	 */
	} else
		comp = "0";

	(void) snprintf(chip_str, STR_BUFLEN, "%u",
	    (cpuid >> CHIPID_SHIFT) & CHIP_OR_CORE_MASK);

	(void) snprintf(core_str, STR_BUFLEN, "%u",
	    (cpuid >> COREID_SHIFT) & CHIP_OR_CORE_MASK);

	(void) snprintf(strand_str, STR_BUFLEN, "%u",
	    (cpuid & STRAND_MASK));

	if (nvlist_add_string(pairs[0], FM_FMRI_HC_NAME, "chassis") != 0 ||
	    nvlist_add_string(pairs[0], FM_FMRI_HC_ID, "0") != 0 ||
	    nvlist_add_string(pairs[1], FM_FMRI_HC_NAME, "cmu") != 0 ||
	    nvlist_add_string(pairs[1], FM_FMRI_HC_ID, comp) != 0 ||
	    nvlist_add_string(pairs[2], FM_FMRI_HC_NAME, "chip") != 0 ||
	    nvlist_add_string(pairs[2], FM_FMRI_HC_ID, chip_str) != 0 ||
	    nvlist_add_string(pairs[3], FM_FMRI_HC_NAME, "core") != 0 ||
	    nvlist_add_string(pairs[3], FM_FMRI_HC_ID, core_str) != 0 ||
	    nvlist_add_string(pairs[4], FM_FMRI_HC_NAME, "strand") != 0 ||
	    nvlist_add_string(pairs[4], FM_FMRI_HC_ID, strand_str) != 0) {
		fmd_hdl_strfree(hdl, frustr);
		opl_free_nvpairs(pairs, npairs);
		nvlist_free(fmri);
		return (NULL);
	}

	if (nvlist_add_uint8(fmri, FM_VERSION, FM_HC_SCHEME_VERSION) != 0 ||
	    nvlist_add_string(fmri, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC) != 0 ||
	    nvlist_add_string(fmri, FM_FMRI_HC_ROOT, "") != 0 ||
	    nvlist_add_uint32(fmri, FM_FMRI_HC_LIST_SZ, LIST_SIZE) != 0 ||
	    nvlist_add_nvlist_array(fmri, FM_FMRI_HC_LIST,
	    pairs, npairs) != 0) {
		fmd_hdl_strfree(hdl, frustr);
		opl_free_nvpairs(pairs, npairs);
		nvlist_free(fmri);
		return (NULL);
	}

	if (fmd_nvl_fmri_expand(hdl, fmri) < 0) {
		fmd_hdl_strfree(hdl, frustr);
		opl_free_nvpairs(pairs, npairs);
		nvlist_free(fmri);
		return (NULL);
	}

	fmd_hdl_strfree(hdl, frustr);
	opl_free_nvpairs(pairs, npairs);
	return (fmri);
}

/*
 * The following is the main function to handle generating
 * the sibling cpu suspect list for the CPU detected UE
 * error cases.  This is to handle the
 * multiple strand/core architecture on the OPL platform.
 */
cmd_evdisp_t
opl_cpuue_handler(fmd_hdl_t *hdl, fmd_event_t *ep,
    const char *class, const char *fltname,
    cmd_ptrsubtype_t ptr, cmd_cpu_t *cpu,
    cmd_case_t *cc, uint8_t cpumask)
{
	const char *uuid;
	cmd_cpu_t *main_cpu, *sib_cpu;
	nvlist_t *flt, *fmri;
	opl_cpu_list_t *cpu_list, *cpu_lp;
	uint32_t main_cpuid, nsusp = 1;
	uint8_t cert;

	fmd_hdl_debug(hdl,
	    "Enter OPL_CPUUE_HANDLER for class %x\n", class);

	main_cpuid = cpu->cpu_cpuid;
	main_cpu = cpu;

	if (strcmp(fltname, "core") == 0)
		cpu_list = opl_alloc_struct(hdl, cpu->cpu_cpuid,
		    IS_CORE);
	else if (strcmp(fltname, "chip") == 0)
		cpu_list = opl_alloc_struct(hdl, cpu->cpu_cpuid,
		    IS_CHIP);
	else
		cpu_list = opl_alloc_struct(hdl, cpu->cpu_cpuid,
		    IS_STRAND);

	for (cpu_lp = cpu_list; cpu_lp != NULL; cpu_lp = cpu_lp->next_cpu) {
		if (cpu_lp->cpuid == main_cpuid) {
			sib_cpu = main_cpu;
			cpu_lp->opl_cmd_cpu = main_cpu;
		} else {
			fmri = opl_cmd_cpu_asru_create(cpu_lp->cpuid, cpumask);
			if (fmri == NULL) {
				cpu_lp->opl_cmd_cpu = NULL;
				fmd_hdl_debug(hdl,
				    "missing asru, cpuid %u excluded\n",
				    cpu_lp->cpuid);
				continue;
			}

			sib_cpu = cmd_sibcpu_lookup(hdl, fmri,
			    CPU_EREPORT_STRING);
			if (sib_cpu == NULL || sib_cpu->cpu_faulting) {
				if (fmri != NULL)
					nvlist_free(fmri);
				cpu_lp->opl_cmd_cpu = NULL;
				fmd_hdl_debug(hdl,
				"cpu not present, cpuid %u excluded\n",
				    cpu_lp->cpuid);
				continue;
			}
			cpu_lp->opl_cmd_cpu = sib_cpu;
			if (fmri != NULL)
				nvlist_free(fmri);
			nsusp++;
		}
		if (cpu->cpu_cpuid == main_cpuid) {
			if (cc->cc_cp != NULL &&
			    fmd_case_solved(hdl, cc->cc_cp)) {
				if (cpu_list != NULL)
					opl_free_struct(hdl, cpu_list);
				return (CMD_EVD_REDUND);
			}

			if (cc->cc_cp == NULL)
				cc->cc_cp = cmd_case_create(hdl,
				    &cpu->cpu_header, ptr, &uuid);

			if (cc->cc_serdnm != NULL) {
				fmd_hdl_debug(hdl,
			"destroying existing %s state for class %x\n",
				    cc->cc_serdnm, class);
				fmd_serd_destroy(hdl, cc->cc_serdnm);
				fmd_hdl_strfree(hdl, cc->cc_serdnm);
				cc->cc_serdnm = NULL;
				fmd_case_reset(hdl, cc->cc_cp);
			}
			fmd_case_add_ereport(hdl, cc->cc_cp, ep);
		}
	}
	cert = opl_avg(100, nsusp);
	for (cpu_lp = cpu_list; cpu_lp != NULL; cpu_lp = cpu_lp->next_cpu) {
		if (cpu_lp->opl_cmd_cpu != NULL) {
			nvlist_t *cpu_rsrc;

			cpu_rsrc = opl_cmd_cpu_rsrc_create(hdl, cpu_lp->cpuid);
			if (cpu_rsrc == NULL) {
				fmd_hdl_debug(hdl,
				"missing rsrc, cpuid %u excluded\n",
				    cpu_lp->cpuid);
				continue;
			}
			flt = cmd_cpu_create_fault(hdl,
			    cpu_lp->opl_cmd_cpu, fltname, cpu_rsrc, cert);
			nvlist_free(cpu_rsrc);
			fmd_case_add_suspect(hdl, cc->cc_cp, flt);
		}
	}
	fmd_case_solve(hdl, cc->cc_cp);
	if (cpu_list != NULL)
		opl_free_struct(hdl, cpu_list);
	return (CMD_EVD_OK);
}

/*
 * The following is the common function for handling
 * memory UE with EID=MEM.
 * The error could be detected by either CPU/IO.
 */
cmd_evdisp_t
opl_cmd_ue_mem(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    int hdlr_type)
{
	nvlist_t *rsrc = NULL, *asru = NULL;
	uint64_t ubc_ue_log_reg, pa;

	if (nvlist_lookup_nvlist(nvl,
	    FM_EREPORT_PAYLOAD_NAME_RESOURCE, &rsrc) != 0)
		return (CMD_EVD_BAD);

	switch (hdlr_type) {
	case CMD_OPL_HDLR_CPU:

		if (nvlist_lookup_uint64(nvl,
		    FM_EREPORT_PAYLOAD_NAME_SFAR, &pa) != 0)
			return (CMD_EVD_BAD);

		fmd_hdl_debug(hdl, "cmd_ue_mem: pa=%llx\n",
		    (u_longlong_t)pa);
		break;

	case CMD_OPL_HDLR_IO:

		if (nvlist_lookup_uint64(nvl, OBERON_UBC_MUE,
		    &ubc_ue_log_reg) != 0)
			return (CMD_EVD_BAD);

		pa = (ubc_ue_log_reg & UBC_UE_ADR_MASK);

		fmd_hdl_debug(hdl, "cmd_ue_mem: ue_log_reg=%llx\n",
		    (u_longlong_t)ubc_ue_log_reg);
		fmd_hdl_debug(hdl, "cmd_ue_mem: pa=%llx\n",
		    (u_longlong_t)pa);
		break;

	default:

		return (CMD_EVD_BAD);
	}

	if ((errno = nvlist_dup(rsrc, &asru, 0)) != 0 ||
	    (errno = nvlist_add_uint64(asru,
	    FM_FMRI_MEM_PHYSADDR, pa)) != 0)
		fmd_hdl_abort(hdl, "failed to build page fmri");

	cmd_page_fault(hdl, asru, rsrc, ep, pa);
	return (CMD_EVD_OK);
}

/*
 * This is the common entry for processing MAC detected errors.
 * It is responsible for generating the memory page fault event.
 * The permanent CE in normal mode is handled here also in the
 * same way as in the UE case.
 */
/*ARGSUSED*/
cmd_evdisp_t
opl_cmd_mac_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode)
{
	uint64_t pa;
	nvlist_t *rsrc = NULL, *asru = NULL;

	fmd_hdl_debug(hdl, "cmd_mac_common: clcode=%ll\n", clcode);

	if (nvlist_lookup_nvlist(nvl, MC_OPL_RESOURCE, &rsrc) != 0)
		return (CMD_EVD_BAD);

	if (nvlist_lookup_uint64(nvl, MC_OPL_PA, &pa)
	    != 0)
		return (CMD_EVD_BAD);

	/*
	 * Check for invalid pa.
	 * The most sig. bit should not be on.
	 * It would be out of the range of possible pa
	 * in MAC's view.
	 */
	if (((uint64_t)1 << 63) & pa)
		return (CMD_EVD_BAD);

	if ((errno = nvlist_dup(rsrc, &asru, 0)) != 0 ||
	    (errno = nvlist_add_uint64(asru, FM_FMRI_MEM_PHYSADDR, pa)) != 0)
		fmd_hdl_abort(hdl, "failed to build page fmri");

	cmd_page_fault(hdl, asru, rsrc, ep, pa);
	return (CMD_EVD_OK);
}

/*
 * Common entry points for handling CPU/IO detected UE with
 * respect to EID=MEM.
 */
/*ARGSUSED*/
cmd_evdisp_t
opl_cmd_cpu_hdlr_mem(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode)
{
	return (opl_cmd_ue_mem(hdl, ep, nvl, CMD_OPL_HDLR_CPU));
}

/*ARGSUSED*/
cmd_evdisp_t
opl_cmd_io_hdlr_mem(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode)
{
	return (opl_cmd_ue_mem(hdl, ep, nvl, CMD_OPL_HDLR_IO));
}
