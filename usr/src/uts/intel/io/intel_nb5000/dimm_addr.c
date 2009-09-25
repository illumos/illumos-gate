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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/mc.h>
#include <sys/nvpair.h>
#include <sys/fm/protocol.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/mc_intel.h>
#include "nb_log.h"
#include "rank.h"
#include "dimm_phys.h"
#include "nb5000.h"

struct rank_base *rank_base;

static int
fmri2unum(nvlist_t *nvl, mc_unum_t *unump)
{
	int i;
	uint64_t offset;
	nvlist_t **hcl, *hcsp;
	uint_t npr;

	if (nvlist_lookup_nvlist(nvl, FM_FMRI_HC_SPECIFIC, &hcsp) != 0 ||
	    (nvlist_lookup_uint64(hcsp, "asru-" FM_FMRI_HC_SPECIFIC_OFFSET,
	    &offset) != 0 && nvlist_lookup_uint64(hcsp,
	    FM_FMRI_HC_SPECIFIC_OFFSET, &offset) != 0) ||
	    nvlist_lookup_nvlist_array(nvl, FM_FMRI_HC_LIST, &hcl, &npr) != 0)
		return (0);


	bzero(unump, sizeof (mc_unum_t));
	for (i = 0; i < MC_UNUM_NDIMM; i++)
		unump->unum_dimms[i] = MC_INVALNUM;

	for (i = 0; i < npr; i++) {
		char *hcnm, *hcid;
		long v;

		if (nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &hcnm) != 0 ||
		    nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &hcid) != 0 ||
		    ddi_strtol(hcid, NULL, 0, &v) != 0)
			return (0);

		if (strcmp(hcnm, "motherboard") == 0)
			unump->unum_board = (int)v;
		else if (strcmp(hcnm, "memory-controller") == 0)
			unump->unum_mc = (int)v;
		else if (strcmp(hcnm, "dram-channel") == 0)
			unump->unum_cs = (int)v;
		else if (strcmp(hcnm, "dimm") == 0)
			unump->unum_dimms[0] = (int)v;
		else if (strcmp(hcnm, "rank") == 0)
			unump->unum_rank = (int)v;
	}

	return (1);
}

/*ARGSUSED*/
static cmi_errno_t
inb_patounum(void *arg, uint64_t pa, uint8_t valid_hi, uint8_t valid_lo,
    uint32_t synd, int syndtype, mc_unum_t *unump)
{
	struct rank_base *rp;
	int i;
	int last;
	uint64_t offset;
	cmi_errno_t rt = CMIERR_UNKNOWN;

	last = nb_dimms_per_channel * nb_number_memory_controllers;
	for (i = 0; i < last; i++) {
		rp = &rank_base[i];
		if (rp && pa >= rp->base && pa < rp->limit)
			break;
	}
	if (i < last) {
		offset = pa - rp->base;
		if (offset > rp->hole)
			offset -= rp->hole_size;
		unump->unum_offset = offset / rp->interleave;
		unump->unum_mc = i / nb_dimms_per_channel;
		unump->unum_cs = 0;
		unump->unum_rank = i % nb_dimms_per_channel;
		rt = CMI_SUCCESS;
	}
	return (rt);
}

/*ARGSUSED*/
static cmi_errno_t
inb_unumtopa(void *arg, mc_unum_t *unump, nvlist_t *nvl, uint64_t *pap)
{
	int num_ranks_per_branch;
	mc_unum_t unum;
	uint64_t pa;
	struct rank_base *rp;

	if (unump == NULL) {
		if (!fmri2unum(nvl, &unum))
			return (CMI_SUCCESS);
		unump = &unum;
	}
	if ((unump->unum_offset & OFFSET_ROW_BANK_COL)) {
		if (&dimm_getphys) {
			pa = dimm_getphys(unump->unum_mc,
			    TCODE_OFFSET_RANK(unump->unum_offset),
			    TCODE_OFFSET_BANK(unump->unum_offset),
			    TCODE_OFFSET_RAS(unump->unum_offset),
			    TCODE_OFFSET_CAS(unump->unum_offset));
			if (pa >= MAXPHYS_ADDR)
				return (CMIERR_MC_NOADDR);
		} else {
			return (CMIERR_MC_NOADDR);
		}
		*pap = pa;
		return (CMI_SUCCESS);
	}


	/* max number of ranks per branch */
	num_ranks_per_branch = (nb_chipset == INTEL_NB_5100) ?
	    NB_5100_RANKS_PER_CHANNEL :
	    nb_dimms_per_channel * nb_channels_per_branch;
	rp = &rank_base[(unump->unum_mc * num_ranks_per_branch) +
	    unump->unum_rank];
	pa = rp->base + (unump->unum_offset * rp->interleave);

	if (rp->hole && pa >= rp->hole)
		pa += rp->hole_size;
	*pap = pa;
	return (CMI_SUCCESS);
}

void
dimm_init()
{
	int num_ranks_per_branch;


	/* max number of ranks per branch */
	num_ranks_per_branch = (nb_chipset == INTEL_NB_5100) ?
	    NB_5100_RANKS_PER_CHANNEL :
	    nb_dimms_per_channel * nb_channels_per_branch;

	rank_base = kmem_zalloc(sizeof (struct rank_base) *
	    nb_number_memory_controllers * num_ranks_per_branch, KM_SLEEP);
}

void
dimm_fini()
{
	int num_ranks_per_branch;


	/* max number of ranks per branch */
	num_ranks_per_branch = (nb_chipset == INTEL_NB_5100) ?
	    NB_5100_RANKS_PER_CHANNEL :
	    nb_dimms_per_channel * nb_channels_per_branch;

	kmem_free(rank_base, sizeof (struct rank_base) *
	    nb_number_memory_controllers * num_ranks_per_branch);
	rank_base = 0;
}

void
dimm_add_rank(int branch, int rank, int branch_interleave, int way,
    uint64_t base, uint32_t hole, uint32_t hole_size, int interleave,
    uint64_t limit)
{
	struct rank_base *rp;
	int num_ranks_per_branch;

	/* max number of ranks per branch */
	num_ranks_per_branch = (nb_chipset == INTEL_NB_5100) ?
	    NB_5100_RANKS_PER_CHANNEL :
	    nb_dimms_per_channel * nb_channels_per_branch;
	rp = &rank_base[(branch * num_ranks_per_branch) + rank];
	rp->branch_interleave = branch_interleave;
	rp->way = way;
	rp->base = base;
	rp->hole = hole;
	rp->hole_size = hole_size;
	rp->interleave = interleave;
	rp->limit = limit;
}

static const cmi_mc_ops_t inb_mc_ops = {
	inb_patounum,
	inb_unumtopa,
	nb_error_trap			/* cmi_mc_logout */
};

/*ARGSUSED*/
int
inb_mc_register(cmi_hdl_t hdl, void *arg1, void *arg2, void *arg3)
{
	cmi_mc_register(hdl, &inb_mc_ops, NULL);
	return (CMI_HDL_WALK_NEXT);
}
