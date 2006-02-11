/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Stub routines used to link in files from $SRC/common/mc
 */

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/varargs.h>
#include <sys/cpu_module_impl.h>
#include <sys/fm/protocol.h>
#include <sys/mc.h>

#include <mcamd.h>
#include <mcamd_off.h>

int mcamd_debug = 0; /* see mcamd_api.h for MCAMD_DBG_* values */

struct mc_propmap {
	uint_t mcpm_code;
	uint_t mcpm_offset;
};

static uint_t
nodetype(mcamd_node_t *node)
{
	mc_hdr_t *mch = (mc_hdr_t *)node;
	return (mch->mch_type);
}

static void *
node2type(mcamd_node_t *node, int type)
{
	mc_hdr_t *mch = (mc_hdr_t *)node;
	ASSERT(mch->mch_type == type);
	return (mch);
}

/*
 * Iterate over all memory controllers.
 */
/*ARGSUSED*/
mcamd_node_t *
mcamd_mc_next(mcamd_hdl_t *hdl, mcamd_node_t *root, mcamd_node_t *last)
{
	mc_t *mc;

	ASSERT(RW_LOCK_HELD(&mc_lock));

	if (last == NULL)
		return ((mcamd_node_t *)mc_list);

	mc = node2type(last, MC_NT_MC);

	return ((mcamd_node_t *)mc->mc_next);
}

/*
 * Iterate over all chip-selects of a MC or all chip-selects of a DIMM
 * depending on the node type of 'node'.  In the DIMM case we do not
 * have a linked list of associated chip-selects but an array of pointer
 * to them.
 */
/*ARGSUSED*/
mcamd_node_t *
mcamd_cs_next(mcamd_hdl_t *hdl, mcamd_node_t *node, mcamd_node_t *last)
{
	uint_t nt = nodetype(node);
	mc_t *mc;
	mc_cs_t *mccs;
	mc_dimm_t *mcd;
	int i;
	void *retval;

	ASSERT(nt == MC_NT_MC || nt == MC_NT_DIMM);

	if (last == NULL) {
		switch (nt) {
		case MC_NT_MC:
			mc = node2type(node, MC_NT_MC);
			retval = mc->mc_cslist;
			break;
		case MC_NT_DIMM:
			mcd = node2type(node, MC_NT_DIMM);
			retval = mcd->mcd_cs[0];
			break;
		}
	} else {
		mccs = node2type(last, MC_NT_CS);

		switch (nt) {
		case MC_NT_MC:
			retval = mccs->mccs_next;
			break;
		case MC_NT_DIMM:
			mcd = node2type(node, MC_NT_DIMM);
			for (i = 0; i < MC_CHIP_DIMMRANKMAX; i++) {
				if (mcd->mcd_cs[i] == mccs)
					break;
			}
			if (i == MC_CHIP_DIMMRANKMAX)
				cmn_err(CE_PANIC, "Bad last value for "
				    "mcamd_cs_next");

			if (i == MC_CHIP_DIMMRANKMAX - 1)
				retval = NULL;
			else
				retval = mcd->mcd_cs[i + 1];
			break;
		}
	}

	return ((mcamd_node_t *)retval);
}

/*
 * Iterate over all DIMMs of an MC or all DIMMs of a chip-select depending
 * on the node type of 'node'.  In the chip-select case we don not have
 * a linked list of associated DIMMs but an array of pointers to them.
 */
/*ARGSUSED*/
mcamd_node_t *
mcamd_dimm_next(mcamd_hdl_t *hdl, mcamd_node_t *node, mcamd_node_t *last)
{
	uint_t nt = nodetype(node);
	mc_t *mc;
	mc_cs_t *mccs;
	mc_dimm_t *mcd;
	int i;
	void *retval;

	ASSERT(nt == MC_NT_MC || nt == MC_NT_CS);

	if (last == NULL) {
		switch (nt) {
		case MC_NT_MC:
			mc = node2type(node, MC_NT_MC);
			retval =  mc->mc_props.mcp_dimmlist;
			break;
		case MC_NT_CS:
			mccs = node2type(node, MC_NT_CS);
			retval = mccs->mccs_dimm[0];
			break;
		}
	} else {
		mcd = node2type(last, MC_NT_DIMM);

		switch (nt) {
		case MC_NT_MC:
			retval = mcd->mcd_next;
			break;
		case MC_NT_CS:
			mccs = node2type(node, MC_NT_CS);
			for (i = 0; i < MC_CHIP_DIMMPERCS; i++) {
				if (mccs->mccs_dimm[i] == mcd)
					break;
			}
			if (i == MC_CHIP_DIMMPERCS)
				cmn_err(CE_PANIC, "Bad last value for "
				    "mcamd_dimm_next");

			if (i == MC_CHIP_DIMMPERCS - 1)
				retval = NULL;
			else
				retval = mccs->mccs_dimm[i + 1];
			break;
		}
	}

	return ((mcamd_node_t *)retval);
}

/*ARGSUSED*/
mcamd_node_t *
mcamd_cs_mc(mcamd_hdl_t *hdl, mcamd_node_t *csnode)
{
	mc_cs_t *mccs = node2type(csnode, MC_NT_CS);
	return ((mcamd_node_t *)mccs->mccs_mc);
}

/*ARGSUSED*/
mcamd_node_t *
mcamd_dimm_mc(mcamd_hdl_t *hdl, mcamd_node_t *dnode)
{
	mc_dimm_t *mcd = node2type(dnode, MC_NT_DIMM);
	return ((mcamd_node_t *)mcd->mcd_mc);
}

/*
 * Node properties.  A property is accessed through a property number code;
 * we search these tables for a match (choosing table from node type) and
 * return the uint64_t property at the indicated offset into the node
 * structure.  All properties must be of type uint64_t.  It is assumed that
 * property lookup does not have to be super-fast - we search linearly
 * down the (small) lists.
 */
static const struct mc_propmap mcamd_mc_propmap[] = {
	{ MCAMD_PROP_NUM, MCAMD_MC_OFF_NUM },
	{ MCAMD_PROP_REV, MCAMD_MC_OFF_REV },
	{ MCAMD_PROP_BASE_ADDR, MCAMD_MC_OFF_BASE_ADDR },
	{ MCAMD_PROP_LIM_ADDR, MCAMD_MC_OFF_LIM_ADDR },
	{ MCAMD_PROP_DRAM_CONFIG, MCAMD_MC_OFF_DRAMCFG },
	{ MCAMD_PROP_DRAM_HOLE, MCAMD_MC_OFF_DRAMHOLE },
	{ MCAMD_PROP_DRAM_ILEN, MCAMD_MC_OFF_DRAM_ILEN },
	{ MCAMD_PROP_DRAM_ILSEL, MCAMD_MC_OFF_DRAM_ILSEL },
	{ MCAMD_PROP_CSBANKMAP, MCAMD_MC_OFF_CSBANKMAP },
	{ MCAMD_PROP_ACCESS_WIDTH, MCAMD_MC_OFF_ACCWIDTH },
	{ MCAMD_PROP_CSBANK_INTLV, MCAMD_MC_OFF_CSBANK_INTLV },
	{ MCAMD_PROP_DISABLED_CS, MCAMD_MC_OFF_DISABLED_CS }
};

static const struct mc_propmap mcamd_cs_propmap[] = {
	{ MCAMD_PROP_NUM, MCAMD_CS_OFF_NUM },
	{ MCAMD_PROP_BASE_ADDR, MCAMD_CS_OFF_BASE_ADDR },
	{ MCAMD_PROP_MASK, MCAMD_CS_OFF_MASK },
	{ MCAMD_PROP_SIZE, MCAMD_CS_OFF_SIZE },
	{ MCAMD_PROP_LODIMM, MCAMD_CS_OFF_DIMMNUMS },
	{ MCAMD_PROP_UPDIMM, MCAMD_CS_OFF_DIMMNUMS +
	    MCAMD_CS_OFF_DIMMNUMS_INCR }
};

static const struct mc_propmap mcamd_dimm_propmap[] = {
	{ MCAMD_PROP_NUM, MCAMD_DIMM_OFF_NUM },
};

/*ARGSUSED*/
int
mcamd_get_numprop(mcamd_hdl_t *hdl, mcamd_node_t *node, uint_t code,
    uint64_t *valp)
{
	int i;
	mc_hdr_t *mch = (mc_hdr_t *)node;
	int nt = mch->mch_type;
	int found = 0;
	const struct mc_propmap *pmp;
	struct mcamd_nt_props {
		const struct mc_propmap *props;
		int numprops;
	} props[] = {
		{ mcamd_mc_propmap,	/* MC_NT_MC */
		    sizeof (mcamd_mc_propmap) / sizeof (struct mc_propmap) },
		{ mcamd_cs_propmap,	/* MC_NT_CS */
		    sizeof (mcamd_cs_propmap) / sizeof (struct mc_propmap) },
		{ mcamd_dimm_propmap,	/* MC_NT_DIMM */
		    sizeof (mcamd_dimm_propmap) / sizeof (struct mc_propmap) },
	};

	if (mch->mch_type < MC_NT_NTYPES) {
		for (i = 0, pmp = props[nt].props; i < props[nt].numprops;
		    i++, pmp++) {
			if (pmp->mcpm_code == code) {
				found = 1;
				break;
			}
		}
	}

	ASSERT(found);
	if (found) {
		*valp = *(uint64_t *)((uintptr_t)node + pmp->mcpm_offset);
	}

	return (found == 1);
}

int
mcamd_errno(mcamd_hdl_t *mcamd)
{
	return (mcamd->mcamd_errno);
}

int
mcamd_set_errno(mcamd_hdl_t *mcamd, int err)
{
	mcamd->mcamd_errno = err;
	return (-1);
}

void
mcamd_dprintf(mcamd_hdl_t *mcamd, int mask, const char *fmt, ...)
{
	va_list ap;

	if (!(mcamd->mcamd_debug & mask))
		return;

	va_start(ap, fmt);
	vcmn_err(mask & MCAMD_DBG_ERR ? CE_WARN : CE_NOTE, fmt, ap);
	va_end(ap);
}

void
mcamd_mkhdl(mcamd_hdl_t *hdl)
{
	hdl->mcamd_errno = 0;
	hdl->mcamd_debug = mcamd_debug;
}

/*ARGSUSED*/
static int
mcamd_patounum_wrap(void *arg, uint64_t pa, uint32_t synd, int syndtype,
    mc_unum_t *unump)
{
	mcamd_hdl_t mcamd;
	int rc;

	mcamd_mkhdl(&mcamd);

	rw_enter(&mc_lock, RW_READER);

	rc = mcamd_patounum(&mcamd,
	    (mcamd_node_t *)mc_list, pa, synd, syndtype, unump);

#ifdef DEBUG
	/*
	 * Apply the reverse operation to verify the result.  If there is
	 * a problem complain but continue.
	 */
	if (rc == 0 && MCAMD_RC_OFFSET_VALID(unump->unum_offset)) {
		uint64_t rpa;
		if (mcamd_unumtopa(&mcamd, (mcamd_node_t *)mc_list, unump,
		    &rpa) != 0 || rpa != pa) {
			mcamd_dprintf(&mcamd, MCAMD_DBG_ERR,
			    "mcamd_patounum_wrap: offset calculation "
			    "verification for PA 0x%llx failed\n", pa);
		}
	}
#endif
	rw_exit(&mc_lock);

	return (rc == 0);
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
		unump->unum_dimms[i] = -1;

	for (i = 0; i < npr; i++) {
		char *hcnm, *hcid;
		long v;

		if (nvlist_lookup_string(hcl[i], FM_FMRI_HC_NAME, &hcnm) != 0 ||
		    nvlist_lookup_string(hcl[i], FM_FMRI_HC_ID, &hcid) != 0 ||
		    ddi_strtol(hcid, NULL, 0, &v) != 0)
			return (0);

		if (strcmp(hcnm, "motherboard") == 0)
			unump->unum_board = (int)v;
		else if (strcmp(hcnm, "chip") == 0)
			unump->unum_chip = (int)v;
		else if (strcmp(hcnm, "memory-controller") == 0)
			unump->unum_mc = (int)v;
		else if (strcmp(hcnm, "chip-select") == 0)
			unump->unum_cs = (int)v;
		else if (strcmp(hcnm, "dimm") == 0)
			unump->unum_dimms[0] = (int)v;
	}

	unump->unum_offset = offset;

	return (1);
}

/*ARGSUSED*/
static int
mcamd_unumtopa_wrap(void *arg, mc_unum_t *unump, nvlist_t *nvl, uint64_t *pap)
{
	mcamd_hdl_t mcamd;
	int rc;
	mc_unum_t unum;

	if (unump != NULL && nvl != NULL)
		return (0);

	if (unump == NULL) {
		if (!fmri2unum(nvl, &unum))
			return (0);
		unump = &unum;
	}

	mcamd_mkhdl(&mcamd);

	rw_enter(&mc_lock, RW_READER);
	rc = mcamd_unumtopa(&mcamd, (mcamd_node_t *)mc_list, unump, pap);
	rw_exit(&mc_lock);

	return (rc == 0);
}

static const cmi_mc_ops_t mcamd_mc_ops = {
	mcamd_patounum_wrap,
	mcamd_unumtopa_wrap
};

void
mcamd_mc_register(cpu_t *cp)
{
	cmi_mc_register(cp, &mcamd_mc_ops, NULL);
}
