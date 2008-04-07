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
 * Ereport-handling routines for memory errors
 */

#include <cmd_mem.h>
#include <cmd_dimm.h>
#include <cmd_bank.h>
#include <cmd_page.h>
#include <cmd_cpu.h>
#include <cmd_branch.h>
#include <cmd_state.h>
#include <cmd.h>
#include <cmd_hc_sun4v.h>

#include <assert.h>
#include <strings.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fm/fmd_api.h>
#include <sys/fm/ldom.h>
#include <sys/fm/protocol.h>

#include <sys/fm/cpu/UltraSPARC-T1.h>
#include <sys/mdesc.h>
#include <sys/async.h>
#include <sys/errclassify.h>
#include <sys/niagararegs.h>
#include <sys/fm/ldom.h>
#include <ctype.h>

#define	VF_TS3_FCR	0x000000000000FFFFULL
#define	VF_L2ESYR_C2C	0x8000000000000000ULL
#define	UTS2_CPUS_PER_CHIP	64
#define	FBR_ERROR	".fbr"

extern ldom_hdl_t *cpumem_diagnosis_lhp;

static fmd_hdl_t *cpumem_hdl = NULL;

static void *
cpumem_alloc(size_t size)
{
	assert(cpumem_hdl != NULL);

	return (fmd_hdl_alloc(cpumem_hdl, size, FMD_SLEEP));
}

static void
cpumem_free(void *addr, size_t size)
{
	assert(cpumem_hdl != NULL);

	fmd_hdl_free(cpumem_hdl, addr, size);
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_mem_synd_check(fmd_hdl_t *hdl, uint64_t afar, uint8_t afar_status,
    uint16_t synd, uint8_t synd_status, cmd_cpu_t *cpu)
{
	/*
	 * Niagara writebacks from L2 containing UEs are placed in memory
	 * with the poison syndrome NI_DRAM_POISON_SYND_FROM_LDWU.
	 * Memory UE ereports showing this syndrome are dropped because they
	 * indicate an L2 problem, which should be diagnosed from the
	 * corresponding L2 cache ereport.
	 */
	switch (cpu->cpu_type) {
		case CPU_ULTRASPARC_T1:
			if (synd == NI_DRAM_POISON_SYND_FROM_LDWU) {
				fmd_hdl_debug(hdl,
				    "discarding UE due to magic syndrome %x\n",
				    synd);
				return (CMD_EVD_UNUSED);
			}
			break;
		case CPU_ULTRASPARC_T2:
		case CPU_ULTRASPARC_T2plus:
			if (synd == N2_DRAM_POISON_SYND_FROM_LDWU) {
				fmd_hdl_debug(hdl,
				    "discarding UE due to magic syndrome %x\n",
				    synd);
				return (CMD_EVD_UNUSED);
			}
			break;
		default:
			break;
	}
	return (CMD_EVD_OK);
}

static int
cpu_present(fmd_hdl_t *hdl, nvlist_t *asru, uint32_t *cpuid)
{
	nvlist_t *cp_asru;
	uint32_t i;

	if (nvlist_dup(asru, &cp_asru, 0) != 0) {
		fmd_hdl_debug(hdl, "unable to alloc asru for thread\n");
		return (-1);
	}

	for (i = *cpuid; i < *cpuid + UTS2_CPUS_PER_CHIP; i++) {

		(void) nvlist_remove_all(cp_asru, FM_FMRI_CPU_ID);

		if (nvlist_add_uint32(cp_asru, FM_FMRI_CPU_ID, i) == 0) {
			if (fmd_nvl_fmri_present(hdl, cp_asru) &&
			    !fmd_nvl_fmri_unusable(hdl, cp_asru)) {
				nvlist_free(cp_asru);
				*cpuid = i;
				return (0);
			}
		}
	}
	nvlist_free(cp_asru);
	return (-1);
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_c2c(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	uint32_t cpuid;
	nvlist_t *det;
	int rc;

	(void) nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &det);
	if (nvlist_lookup_uint32(det, FM_FMRI_CPU_ID, &cpuid) == 0) {

		/*
		 * If the c2c bit is set, the sending cache of the
		 * cpu must be faulted instead of the memory.
		 * If the detector is chip0, the cache of the chip1
		 * is faulted and vice versa.
		 */
		if (cpuid < UTS2_CPUS_PER_CHIP)
			cpuid = UTS2_CPUS_PER_CHIP;
		else
			cpuid = 0;

		rc = cpu_present(hdl, det, &cpuid);

		if (rc != -1) {
			(void) nvlist_remove(det, FM_FMRI_CPU_ID,
			    DATA_TYPE_UINT32);
			if (nvlist_add_uint32(det,
			    FM_FMRI_CPU_ID, cpuid) == 0) {
				clcode |= CMD_CPU_LEVEL_CHIP;
				return (cmd_l2u(hdl, ep, nvl, class, clcode));
			}

		}
	}
	fmd_hdl_debug(hdl, "cmd_c2c: no cpuid discarding C2C error");
	return (CMD_EVD_BAD);
}

/*
 * sun4v's xe_common routine has an extra argument, clcode, compared
 * to routine of same name in sun4u.
 */

static cmd_evdisp_t
xe_common(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl,
    const char *class, cmd_errcl_t clcode, cmd_xe_handler_f *hdlr)
{
	uint64_t afar, l2_afar, dram_afar;
	uint64_t l2_afsr, dram_afsr, l2_esyr;
	uint16_t synd;
	uint8_t afar_status, synd_status;
	nvlist_t *rsrc;
	char *typenm;
	uint64_t disp = 0;
	int minorvers = 1;

	if (nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_NAME_L2_AFSR, &l2_afsr) != 0 &&
	    nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_NAME_L2_ESR, &l2_afsr) != 0)
		return (CMD_EVD_BAD);

	if (nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_NAME_DRAM_AFSR, &dram_afsr) != 0 &&
	    nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_NAME_DRAM_ESR, &dram_afsr) != 0)
		return (CMD_EVD_BAD);

	if (nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_NAME_L2_AFAR, &l2_afar) != 0 &&
	    nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_NAME_L2_EAR, &l2_afar) != 0)
		return (CMD_EVD_BAD);

	if (nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_NAME_DRAM_AFAR, &dram_afar) != 0 &&
	    nvlist_lookup_uint64(nvl,
	    FM_EREPORT_PAYLOAD_NAME_DRAM_EAR, &dram_afar) != 0)
		return (CMD_EVD_BAD);

	if (nvlist_lookup_pairs(nvl, 0,
	    FM_EREPORT_PAYLOAD_NAME_ERR_TYPE, DATA_TYPE_STRING, &typenm,
	    FM_EREPORT_PAYLOAD_NAME_RESOURCE, DATA_TYPE_NVLIST, &rsrc,
	    NULL) != 0)
		return (CMD_EVD_BAD);

	synd = dram_afsr;

	/*
	 * Niagara afar and synd validity.
	 * For a given set of error registers, the payload value is valid if
	 * no higher priority error status bit is set.  See UltraSPARC-T1.h for
	 * error status bit values and priority settings.  Note that for DAC
	 * and DAU, afar value is taken from l2 error registers, syndrome
	 * from dram error * registers; for DSC and DSU, both afar and
	 * syndrome are taken from dram * error registers.  DSU afar and
	 * syndrome are always valid because no
	 * higher priority error will override.
	 */
	switch (clcode) {
	case CMD_ERRCL_DAC:
		afar = l2_afar;
		afar_status = ((l2_afsr & NI_L2AFSR_P10) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		synd_status = ((dram_afsr & NI_DMAFSR_P01) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		break;
	case CMD_ERRCL_DSC:
		afar = dram_afar;
		afar_status = ((dram_afsr & NI_DMAFSR_P01) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		synd_status = afar_status;
		break;
	case CMD_ERRCL_DAU:
		afar = l2_afar;
		afar_status = ((l2_afsr & NI_L2AFSR_P05) == 0) ?
		    AFLT_STAT_VALID : AFLT_STAT_INVALID;
		synd_status = AFLT_STAT_VALID;

		if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_L2_ESYR,
		    &l2_esyr) == 0) {
			if (l2_esyr & VF_L2ESYR_C2C) {
				return (cmd_c2c(hdl, ep, nvl, class, clcode));
			}
		}
		break;
	case CMD_ERRCL_DSU:
		afar = dram_afar;
		afar_status = synd_status = AFLT_STAT_VALID;
		break;
	default:
		fmd_hdl_debug(hdl, "Niagara unrecognized mem error %llx\n",
		    clcode);
		return (CMD_EVD_UNUSED);
	}

	return (hdlr(hdl, ep, nvl, class, afar, afar_status, synd,
	    synd_status, cmd_mem_name2type(typenm, minorvers), disp, rsrc));
}


/*ARGSUSED*/
cmd_evdisp_t
cmd_ce(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	return (xe_common(hdl, ep, nvl, class, clcode, cmd_ce_common));
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_ue_train(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	cmd_evdisp_t rc, rc1;

	/*
	 * The DAU is cause of the DAU->DCDP/ICDP train:
	 * - process the cause of the event.
	 * - register the error to the nop event train, so the effected errors
	 * (DCDP/ICDP) will be dropped.
	 */
	rc = xe_common(hdl, ep, nvl, class, clcode, cmd_ue_common);

	rc1 = cmd_xxcu_initial(hdl, ep, nvl, class, clcode, CMD_XR_HDLR_NOP);
	if (rc1 != 0)
		fmd_hdl_debug(hdl,
		    "Fail to add error (%llx) to the train, rc = %d",
		    clcode, rc1);

	return (rc);
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_ue(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	return (xe_common(hdl, ep, nvl, class, clcode, cmd_ue_common));
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_frx(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	return (CMD_EVD_UNUSED);
}


/*ARGSUSED*/
cmd_evdisp_t
cmd_fb(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	cmd_branch_t *branch;
	const char *uuid;
	nvlist_t *asru, *det;
	uint64_t ts3_fcr;

	if (nvlist_lookup_nvlist(nvl, FM_RSRC_RESOURCE, &asru) < 0) {
		CMD_STAT_BUMP(bad_mem_asru);
		return (NULL);
	}

	if (nvlist_lookup_nvlist(nvl, FM_EREPORT_DETECTOR, &det) < 0) {
		CMD_STAT_BUMP(bad_mem_asru);
		return (NULL);
	}

	if (fmd_nvl_fmri_expand(hdl, det) < 0) {
		fmd_hdl_debug(hdl, "Failed to expand detector");
		return (NULL);
	}

	branch = cmd_branch_lookup(hdl, asru);
	if (branch == NULL) {
		if ((branch = cmd_branch_create(hdl, asru)) == NULL)
			return (CMD_EVD_UNUSED);
	}

	if (branch->branch_case.cc_cp != NULL &&
	    fmd_case_solved(hdl, branch->branch_case.cc_cp)) {
		fmd_hdl_debug(hdl, "Case solved\n");
		return (CMD_EVD_REDUND);
	}

	if (branch->branch_case.cc_cp == NULL) {
		branch->branch_case.cc_cp = cmd_case_create(hdl,
		    &branch->branch_header, CMD_PTR_BRANCH_CASE, &uuid);
	}

	if (strcmp(strrchr(class, '.'), FBR_ERROR) == 0) {
		if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_TS3_FCR,
		    &ts3_fcr) == 0 && (ts3_fcr != VF_TS3_FCR)) {
			fmd_hdl_debug(hdl,
			    "Processing fbr with lane failover\n");
			cmd_branch_create_fault(hdl, branch,
			    "fault.memory.link-f", det);

		} else {
			fmd_hdl_debug(hdl, "Adding fbr event to serd engine\n");
			if (branch->branch_case.cc_serdnm == NULL) {
				branch->branch_case.cc_serdnm =
				    cmd_mem_serdnm_create(hdl,
				    "branch", branch->branch_unum);

				fmd_serd_create(hdl,
				    branch->branch_case.cc_serdnm,
				    fmd_prop_get_int32(hdl, "fbr_n"),
				    fmd_prop_get_int64(hdl, "fbr_t"));
			}

			if (fmd_serd_record(hdl,
			    branch->branch_case.cc_serdnm, ep) == FMD_B_FALSE)
				return (CMD_EVD_OK); /* engine hasn't fired */

			fmd_hdl_debug(hdl, "fbr serd fired\n");

			fmd_case_add_serd(hdl, branch->branch_case.cc_cp,
			    branch->branch_case.cc_serdnm);

			cmd_branch_create_fault(hdl, branch,
			    "fault.memory.link-c", det);
		}
	} else {
		fmd_hdl_debug(hdl, "Processing fbu event");
		cmd_branch_create_fault(hdl, branch, "fault.memory.link-u",
		    det);
	}

	branch->branch_flags |= CMD_MEM_F_FAULTING;

	if (branch->branch_case.cc_serdnm != NULL) {
		fmd_serd_destroy(hdl, branch->branch_case.cc_serdnm);
		fmd_hdl_strfree(hdl, branch->branch_case.cc_serdnm);
		branch->branch_case.cc_serdnm = NULL;
	}

	fmd_case_add_ereport(hdl, branch->branch_case.cc_cp, ep);
	fmd_case_solve(hdl, branch->branch_case.cc_cp);
	cmd_branch_dirty(hdl, branch);

	return (CMD_EVD_OK);
}

/*ARGSUSED*/
cmd_evdisp_t
cmd_fb_train(fmd_hdl_t *hdl, fmd_event_t *ep, nvlist_t *nvl, const char *class,
    cmd_errcl_t clcode)
{
	cmd_evdisp_t rc, rc1;

	/*
	 * The FBU is cause of the FBU->DCDP/ICDP train:
	 * - process the cause of the event.
	 * - register the error to the nop event train, so the effected errors
	 * (DCDP/ICDP) will be dropped.
	 */
	rc = cmd_fb(hdl, ep, nvl, class, clcode);

	rc1 = cmd_xxcu_initial(hdl, ep, nvl, class, clcode, CMD_XR_HDLR_NOP);
	if (rc1 != 0)
		fmd_hdl_debug(hdl,
		    "Fail to add error (%llx) to the train, rc = %d",
		    clcode, rc1);

	return (rc);
}

void
cmd_branch_close(fmd_hdl_t *hdl, void *arg)
{
	cmd_branch_destroy(hdl, arg);
}


/*ARGSUSED*/
ulong_t
cmd_mem_get_phys_pages(fmd_hdl_t *hdl)
{
	/*
	 * Compute and return the total physical memory in pages from the
	 * MD/PRI.
	 * Cache its value.
	 */
	static ulong_t npage = 0;
	md_t *mdp;
	mde_cookie_t *listp;
	uint64_t bmem, physmem = 0;
	ssize_t bufsiz = 0;
	uint64_t *bufp;
	int num_nodes, nmblocks, i;

	if (npage > 0) {
		return (npage);
	}

	if (cpumem_hdl == NULL) {
		cpumem_hdl = hdl;
	}

	if ((bufsiz = ldom_get_core_md(cpumem_diagnosis_lhp, &bufp)) <= 0) {
		return (0);
	}
	if ((mdp = md_init_intern(bufp, cpumem_alloc, cpumem_free)) == NULL ||
	    (num_nodes = md_node_count(mdp)) <= 0) {
		cpumem_free(bufp, (size_t)bufsiz);
		return (0);
	}

	listp = (mde_cookie_t *)cpumem_alloc(sizeof (mde_cookie_t) *
	    num_nodes);
	nmblocks = md_scan_dag(mdp, MDE_INVAL_ELEM_COOKIE,
	    md_find_name(mdp, "mblock"),
	    md_find_name(mdp, "fwd"), listp);
	for (i = 0; i < nmblocks; i++) {
		if (md_get_prop_val(mdp, listp[i], "size", &bmem) < 0) {
			physmem = 0;
			break;
		}
		physmem += bmem;
	}
	npage = (ulong_t)(physmem / cmd.cmd_pagesize);

	cpumem_free(listp, sizeof (mde_cookie_t) * num_nodes);
	cpumem_free(bufp, (size_t)bufsiz);
	(void) md_fini(mdp);

	return (npage);
}

static int galois_mul[16][16] = {
/* 0   1   2   3   4   5   6   7   8   9   A   B   C   D   E   F */
{  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0,  0}, /* 0 */
{  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15}, /* 1 */
{  0,  2,  4,  6,  8, 10, 12, 14,  3,  1,  7,  5, 11,  9, 15, 13}, /* 2 */
{  0,  3,  6,  5, 12, 15, 10,  9, 11,  8, 13, 14,  7,  4,  1,  2}, /* 3 */
{  0,  4,  8, 12,  3,  7, 11, 15,  6,  2, 14, 10,  5,  1, 13,  9}, /* 4 */
{  0,  5, 10, 15,  7,  2, 13,  8, 14, 11,  4,  1,  9, 12,  3,  6}, /* 5 */
{  0,  6, 12, 10, 11, 13,  7,  1,  5,  3,  9, 15, 14,  8,  2,  4}, /* 6 */
{  0,  7, 14,  9, 15,  8,  1,  6, 13, 10,  3,  4,  2,  5, 12, 11}, /* 7 */
{  0,  8,  3, 11,  6, 14,  5, 13, 12,  4, 15,  7, 10,  2,  9,  1}, /* 8 */
{  0,  9,  1,  8,  2, 11,  3, 10,  4, 13,  5, 12,  6, 15,  7, 14}, /* 9 */
{  0, 10,  7, 13, 14,  4,  9,  3, 15,  5,  8,  2,  1, 11,  6, 12}, /* A */
{  0, 11,  5, 14, 10,  1, 15,  4,  7, 12,  2,  9, 13,  6,  8,  3}, /* B */
{  0, 12, 11,  7,  5,  9, 14,  2, 10,  6,  1, 13, 15,  3,  4,  8}, /* C */
{  0, 13,  9,  4,  1, 12,  8,  5,  2, 15, 11,  6,  3, 14, 10,  7}, /* D */
{  0, 14, 15,  1, 13,  3,  2, 12,  9,  7,  6,  8,  4, 10, 11,  5}, /* E */
{  0, 15, 13,  2,  9,  6,  4, 11,  1, 14, 12,  3,  8,  7,  5, 10}  /* F */
};

static int
galois_div(int num, int denom) {
	int i;

	for (i = 0; i < 16; i++) {
		if (galois_mul[denom][i] == num)
		    return (i);
	}
	return (-1);
}

/*
 * Data nibbles N0-N31 => 0-31
 * check nibbles C0-3 => 32-35
 */

int
cmd_synd2upos(uint16_t syndrome) {

	uint16_t s0, s1, s2, s3;

	if (syndrome == 0)
		return (-1); /* clean syndrome, not a CE */

	s0 = syndrome & 0xF;
	s1 = (syndrome >> 4) & 0xF;
	s2 = (syndrome >> 8) & 0xF;
	s3 = (syndrome >> 12) & 0xF;

	if (s3 == 0) {
		if (s2 == 0 && s1 == 0)
			return (32); /* 0 0 0 e => C0 */
		if (s2 == 0 && s0 == 0)
			return (33); /* 0 0 e 0 => C1 */
		if (s1 == 0 && s0 == 0)
			return (34); /* 0 e 0 0 => C2 */
		if (s2 == s1 && s1 == s0)
			return (31); /* 0 d d d => N31 */
		return (-1); /* multibit error */
	} else if (s2 == 0) {
		if (s1 == 0 && s0 == 0)
			return (35); /* e 0 0 0 => C4 */
		if (s1 == 0 || s0 == 0)
			return (-1); /* not a 0 b c */
		if (s3 != galois_div(galois_mul[s1][s1], s0))
			return (-1); /* check nibble not valid */
		return (galois_div(s0, s1) - 1); /* N0 - N14 */
	} else if (s1 == 0) {
		if (s2 == 0 || s0 == 0)
			return (-1); /* not a b 0 c */
		if (s3 != galois_div(galois_mul[s2][s2], s0))
			return (-1); /* check nibble not valid */
		return (galois_div(s0, s2) + 14); /* N15 - N29 */
	} else if (s0 == 0) {
		if (s3 == s2 && s2 == s1)
			return (30); /* d d d 0 => N30 */
		return (-1);
	} else return (-1);
}

int
cmd_upos2dram(uint16_t upos) {

	/*
	 * If and/or when x8 DIMMs are used on sun4v systems, this
	 * function will become more complicated.
	 */

	return ((int)upos);

}

nvlist_t *
cmd_mem2hc(fmd_hdl_t *hdl, nvlist_t *mem_fmri) {

	char *nac_name, *s, **sa;
	const char *unum = cmd_fmri_get_unum(mem_fmri);
	nvlist_t *fp, **hc_list;
	int i, n;
	unsigned int usi;

	nac_name = fmd_hdl_zalloc(hdl, strlen(unum)+1, FMD_SLEEP);
	if ((s = strstr(unum, ": ")) != NULL) {
		(void) strncpy(nac_name, unum, s-unum); /* up to ": " */
		(void) strncpy(nac_name+(s-unum), "/", 2); /* add "/" and \0 */
		(void) strncat(nac_name, s+2, strlen(unum)-(s+2-unum)+1);
	} else {
		(void) strcpy(nac_name, unum);
	}

	n = cmd_count_components(nac_name, '/');
	hc_list = fmd_hdl_zalloc(hdl, sizeof (nvlist_t *)*n, FMD_SLEEP);

	for (i = 0; i < n; i++) {
		(void) nvlist_alloc(&hc_list[i],
		    NV_UNIQUE_NAME|NV_UNIQUE_NAME_TYPE, 0);
	}

	if (cmd_breakup_components(nac_name, "/", hc_list) < 0) {
		fmd_hdl_error(hdl, "cannot allocate components for hc-list\n");
		for (i = 0; i < n; i++) {
			if (hc_list[i] != NULL)
			    nvlist_free(hc_list[i]);
		}
		fmd_hdl_free(hdl, hc_list, sizeof (nvlist_t *)*n);
		fmd_hdl_free(hdl, nac_name, strlen(unum)+1);
		return (NULL);
	}
	(void) nvlist_alloc(&fp, NV_UNIQUE_NAME|NV_UNIQUE_NAME_TYPE, 0);
	if ((nvlist_add_uint8(fp, FM_VERSION,
	    FM_HC_VERS0) != 0) ||
	    (nvlist_add_string(fp, FM_FMRI_SCHEME, FM_FMRI_SCHEME_HC) != 0) ||
	    (nvlist_add_string(fp, FM_FMRI_HC_ROOT, "/") != 0) ||
	    (nvlist_add_uint32(fp, FM_FMRI_HC_LIST_SZ, n) != 0) ||
	    (nvlist_add_nvlist_array(fp, FM_FMRI_HC_LIST, hc_list, n) != 0)) {
		for (i = 0; i < n; i++) {
			if (hc_list[i] != NULL)
				nvlist_free(hc_list[i]);
		}
		fmd_hdl_free(hdl, hc_list, sizeof (nvlist_t *)*n);
		fmd_hdl_free(hdl, nac_name, strlen(unum)+1);
		nvlist_free(fp);
		return (NULL);
	}

	for (i = 0; i < n; i++) {
		if (hc_list[i] != NULL)
			nvlist_free(hc_list[i]);
	}
	fmd_hdl_free(hdl, hc_list, sizeof (nvlist_t *)*n);
	fmd_hdl_free(hdl, nac_name, strlen(unum)+1);
	if (nvlist_lookup_string_array(mem_fmri, FM_FMRI_HC_SERIAL_ID,
	    &sa, &usi) == 0) {
		if (nvlist_add_string(fp, FM_FMRI_HC_SERIAL_ID, *sa) != 0) {
			nvlist_free(fp);
			return (NULL);
		}
	}
	if (nvlist_lookup_string_array(mem_fmri, FM_FMRI_HC_PART,
	    &sa, &usi) == 0) {
		if (nvlist_add_string(fp, FM_FMRI_HC_PART, *sa) != 0) {
			nvlist_free(fp);
			return (NULL);
		}
	}
	return (fp);
}
