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

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/mc.h>
#include <sys/nvpair.h>
#include <sys/cpu_module_impl.h>
#include <sys/fm/protocol.h>
#include <sys/cmn_err.h>
#include <sys/sunddi.h>
#include <sys/mc_intel.h>
#include "dimm_addr.h"
#include "nb_log.h"
#include "rank.h"
#include "dimm_phys.h"
#include "nb5000.h"

struct dimm_geometry **dimm_geometry;
struct rank_base *rank_base;

uint64_t
dimm_getphys(int branch, int rank, int bank, int ras, int cas)
{
	uint8_t i;
	uint64_t m;
	uint64_t pa;
	struct rank_base *rp;
	struct rank_geometry *rgp;

	ASSERT(rank < nb_dimms_per_channel * 2);
	rp = &rank_base[(branch * nb_dimms_per_channel * 2) + rank];
	rgp = (struct rank_geometry *)rp->rank_geometry;
	if (rgp == NULL)
		return (-1LL);
	pa = rp->base;

	for (i = 0, m = 1; bank; i++, m <<= 1) {
		if ((bank & m) != 0 && rgp->bank[i] != 0xff) {
			pa += 1 << rgp->bank[i];
			bank &= ~m;
		}
	}
	for (i = 0, m = 1; cas; i++, m <<= 1) {
		if ((cas & m) != 0 && rgp->col[i] != 0xff) {
			pa += 1 << rgp->col[i];
			cas &= ~m;
		}
	}
	for (i = 0, m = 1; ras; i++, m <<= 1) {
		if ((ras & m) != 0 && rgp->row[i] != 0xff) {
			pa += 1 << rgp->row[i];
			ras &= ~m;
		}
	}
	if (rp->interleave > 1) {
		i = 0;
		if (rp->branch_interleave) {
			if (branch) {
				pa += 1 << rgp->interleave[i];
			}
			i++;
		}
		if ((rp->way & 1) != 0)
			pa += 1 << rgp->interleave[i];
		i++;
		if ((rp->way & 2) != 0)
			pa += 1 << rgp->interleave[i];
	}
	if (rp->hole && pa >= rp->hole)
		pa += rp->hole_size;
	return (pa);
}

uint64_t
dimm_getoffset(int branch, int rank, int bank, int ras, int cas)
{
	uint8_t i;
	uint64_t m;
	uint64_t offset;
	struct dimm_geometry *dgp;
	struct rank_geometry *rgp;
	struct rank_base *rp;
	uint64_t pa;
	uint64_t cal_pa;

	ASSERT(rank < nb_dimms_per_channel * 2);
	rp = &rank_base[(branch * nb_dimms_per_channel * 2) + rank];
	dgp = dimm_geometry[(branch * nb_dimms_per_channel) + rank/2];
	if (dgp == NULL)
		return (TCODE_OFFSET(rank, bank, ras, cas));
	rgp = (struct rank_geometry *)&dgp->rank_geometry[0];
	offset = 0;
	pa = dimm_getphys(branch, rank, bank, ras, cas) & PAGEMASK;

	for (i = 0, m = 1; bank; i++, m <<= 1) {
		if ((bank & m) != 0 && rgp->bank[i] != 0xff) {
			offset += 1 << rgp->bank[i];
			bank &= ~m;
		}
	}
	for (i = 0, m = 1; cas; i++, m <<= 1) {
		if ((cas & m) != 0 && rgp->col[i] != 0xff) {
			offset += 1 << rgp->col[i];
			cas &= ~m;
		}
	}
	for (i = 0, m = 1; ras; i++, m <<= 1) {
		if ((ras & m) != 0 && rgp->row[i] != 0xff) {
			offset += 1 << rgp->row[i];
			ras &= ~m;
		}
	}
	cal_pa = rp->base + (offset * rp->interleave);
	if (rp->hole && cal_pa >= rp->hole)
		cal_pa += rp->hole_size;
	cal_pa &= PAGEMASK;

	if (pa != cal_pa) {
		return (-1LL);
	}
	return (offset & PAGEMASK);
}

static int
fmri2unum(nvlist_t *nvl, mc_unum_t *unump)
{
	int i;
	uint64_t offset;
	nvlist_t *fu, **hcl;
	uint_t npr;

	if (nvlist_lookup_nvlist(nvl, FM_FMRI_MEM_UNUM "-fmri", &fu) != 0 ||
	    nvlist_lookup_uint64(nvl, FM_FMRI_MEM_OFFSET, &offset) != 0||
	    nvlist_lookup_nvlist_array(fu, FM_FMRI_HC_LIST, &hcl, &npr) != 0)
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

	unump->unum_offset = offset;

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
	mc_unum_t unum;
	uint64_t pa;
	struct rank_base *rp;

	if (unump == NULL) {
		if (!fmri2unum(nvl, &unum))
			return (CMI_SUCCESS);
		unump = &unum;
	}
	if (unump->unum_offset & OFFSET_ROW_BANK_COL) {
		pa = dimm_getphys(unump->unum_mc,
		    TCODE_OFFSET_RANK(unump->unum_offset),
		    TCODE_OFFSET_BANK(unump->unum_offset),
		    TCODE_OFFSET_RAS(unump->unum_offset),
		    TCODE_OFFSET_CAS(unump->unum_offset));
		if (pa == -1LL)
			return (CMIERR_MC_NOADDR);
		*pap = pa;
		return (CMI_SUCCESS);
	}
	rp = &rank_base[(unump->unum_mc * nb_dimms_per_channel * 2) +
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
	dimm_geometry = kmem_zalloc(sizeof (void *) *
	    nb_number_memory_controllers * nb_dimms_per_channel, KM_SLEEP);
	rank_base = kmem_zalloc(sizeof (struct rank_base) *
	    nb_number_memory_controllers * nb_dimms_per_channel * 2, KM_SLEEP);
}

void
dimm_fini()
{
	kmem_free(dimm_geometry, sizeof (void *) *
	    nb_number_memory_controllers * nb_dimms_per_channel);
	dimm_geometry = 0;
	kmem_free(rank_base, sizeof (struct rank_base) *
	    nb_number_memory_controllers * nb_dimms_per_channel * 2);
	rank_base = 0;
}

void
dimm_add_geometry(int branch, int dimm, int nbanks, int width, int ncolumn,
    int nrow)
{
	int i;
	for (i = 0; i < dimm_types; i++) {
		if (dimm_data[i].row_nbits == nrow &&
		    dimm_data[i].col_nbits == ncolumn &&
		    dimm_data[i].width == width &&
		    (1 << dimm_data[i].bank_nbits) == nbanks) {
			dimm_geometry[(branch * nb_dimms_per_channel) + dimm] =
			    &dimm_data[i];
			break;
		}
	}
}

void
dimm_add_rank(int branch, int rank, int branch_interleave, int way,
    uint64_t base, uint32_t hole, uint32_t hole_size, int interleave,
    uint64_t limit)
{
	struct dimm_geometry *dimm;
	struct rank_base *rp;
	int interleave_nbits;

	dimm = dimm_geometry[(branch * nb_dimms_per_channel) + (rank / 2)];
	rp = &rank_base[(branch * nb_dimms_per_channel * 2) + rank];
	if (interleave == 1)
		interleave_nbits = 0;
	else if (interleave == 2)
		interleave_nbits = 1;
	else if (interleave == 4)
		interleave_nbits = 2;
	else
		interleave_nbits = 3;
	rp->branch_interleave = branch_interleave;
	rp->way = way;
	rp->base = base;
	rp->hole = hole;
	rp->hole_size = hole_size;
	rp->interleave = interleave;
	rp->limit = limit;
	if (dimm)
		rp->rank_geometry = &dimm->rank_geometry[interleave_nbits];
	else
		rp->rank_geometry = 0;
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
