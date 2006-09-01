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
 * Ereport-handling routines for memory errors
 */

#include <cmd_mem.h>
#include <cmd_dimm.h>
#include <cmd_bank.h>
#include <cmd_page.h>
#include <cmd_cpu.h>
#include <cmd.h>

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
	if (cpu->cpu_type == CPU_ULTRASPARC_T1) {
		if (synd == NI_DRAM_POISON_SYND_FROM_LDWU) {
			fmd_hdl_debug(hdl,
			    "discarding UE due to magic syndrome %x\n",
			    synd);
			return (CMD_EVD_UNUSED);
		}
	}
	return (CMD_EVD_OK);
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
	uint64_t l2_afsr, dram_afsr;
	uint16_t synd;
	uint8_t afar_status, synd_status;
	nvlist_t *rsrc;
	char *typenm;
	uint64_t disp;
	int minorvers = 1;

	if (nvlist_lookup_pairs(nvl, 0,
	    FM_EREPORT_PAYLOAD_NAME_L2_AFSR, DATA_TYPE_UINT64, &l2_afsr,
	    FM_EREPORT_PAYLOAD_NAME_DRAM_AFSR, DATA_TYPE_UINT64, &dram_afsr,
	    FM_EREPORT_PAYLOAD_NAME_L2_AFAR, DATA_TYPE_UINT64,
	    &l2_afar,
	    FM_EREPORT_PAYLOAD_NAME_DRAM_AFAR, DATA_TYPE_UINT64,
	    &dram_afar,
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

	if (nvlist_lookup_uint64(nvl, FM_EREPORT_PAYLOAD_NAME_ERR_DISP,
	    &disp) != 0)
		minorvers = 0;

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
