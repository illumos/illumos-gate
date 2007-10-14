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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/fm/util.h>
#include <sys/fm/cpu/AMD.h>
#include <sys/fm/protocol.h>
#include <sys/mc.h>

#include <mcamd.h>
#include <mcamd_off.h>

int mcamd_debug = 0; /* see mcamd_api.h for MCAMD_DBG_* values */

struct mc_offmap {
	int mcom_code;
	uint_t mcom_offset;
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
 * on the node type of 'node'.  In the chip-select case we do not have
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
			retval =  mc->mc_dimmlist;
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
static const struct mc_offmap mcamd_mc_offmap[] = {
	{ MCAMD_PROP_NUM, MCAMD_MC_OFF_NUM },
	{ MCAMD_PROP_REV, MCAMD_MC_OFF_REV },
	{ MCAMD_PROP_BASE_ADDR, MCAMD_MC_OFF_BASE_ADDR },
	{ MCAMD_PROP_LIM_ADDR, MCAMD_MC_OFF_LIM_ADDR },
	{ MCAMD_PROP_ILEN, MCAMD_MC_OFF_ILEN },
	{ MCAMD_PROP_ILSEL, MCAMD_MC_OFF_ILSEL },
	{ MCAMD_PROP_CSINTLVFCTR, MCAMD_MC_OFF_CSINTLVFCTR },
	{ MCAMD_PROP_DRAMHOLE_SIZE, MCAMD_MC_OFF_DRAMHOLE_SIZE },
	{ MCAMD_PROP_ACCESS_WIDTH, MCAMD_MC_OFF_ACCWIDTH },
	{ MCAMD_PROP_CSBANKMAPREG, MCAMD_MC_OFF_CSBANKMAPREG },
	{ MCAMD_PROP_BANKSWZL, MCAMD_MC_OFF_BNKSWZL },
	{ MCAMD_PROP_MOD64MUX, MCAMD_MC_OFF_MOD64MUX },
	{ MCAMD_PROP_SPARECS, MCAMD_MC_OFF_SPARECS },
	{ MCAMD_PROP_BADCS, MCAMD_MC_OFF_BADCS },
};

static const struct mc_offmap mcamd_cs_offmap[] = {
	{ MCAMD_PROP_NUM, MCAMD_CS_OFF_NUM },
	{ MCAMD_PROP_BASE_ADDR, MCAMD_CS_OFF_BASE_ADDR },
	{ MCAMD_PROP_MASK, MCAMD_CS_OFF_MASK },
	{ MCAMD_PROP_SIZE, MCAMD_CS_OFF_SIZE },
	{ MCAMD_PROP_CSBE, MCAMD_CS_OFF_CSBE },
	{ MCAMD_PROP_SPARE, MCAMD_CS_OFF_SPARE },
	{ MCAMD_PROP_TESTFAIL, MCAMD_CS_OFF_TESTFAIL },
	{ MCAMD_PROP_CSDIMM1, MCAMD_CS_OFF_DIMMNUMS },
	{ MCAMD_PROP_CSDIMM2, MCAMD_CS_OFF_DIMMNUMS +
	    MCAMD_CS_OFF_DIMMNUMS_INCR },
	{ MCAMD_PROP_DIMMRANK, MCAMD_CS_OFF_DIMMRANK },
};

static const struct mc_offmap mcamd_dimm_offmap[] = {
	{ MCAMD_PROP_NUM, MCAMD_DIMM_OFF_NUM },
	{ MCAMD_PROP_SIZE, MCAMD_DIMM_OFF_SIZE },
};

struct nt_offmap {
	const struct mc_offmap *omp;
	int mapents;
};

/*ARGSUSED*/
static int
findoffset(mcamd_hdl_t *hdl, mcamd_node_t *node, struct nt_offmap *arr,
    int code, uint_t *offset)
{
	int i;
	mc_hdr_t *mch = (mc_hdr_t *)node;
	int nt = mch->mch_type;
	const struct mc_offmap *omp;

	if (nt > MC_NT_NTYPES || (omp = arr[nt].omp) == NULL)
		return (0);

	for (i = 0; i < arr[nt].mapents; i++, omp++) {
		if (omp->mcom_code == code) {
			*offset = omp->mcom_offset;
			return (1);
		}
	}

	return (0);
}

/*ARGSUSED*/
int
mcamd_get_numprop(mcamd_hdl_t *hdl, mcamd_node_t *node,
    mcamd_propcode_t code, mcamd_prop_t *valp)
{
	int found;
	uint_t offset;

	struct nt_offmap props[] = {
		{ mcamd_mc_offmap,	/* MC_NT_MC */
		    sizeof (mcamd_mc_offmap) / sizeof (struct mc_offmap) },
		{ mcamd_cs_offmap,	/* MC_NT_CS */
		    sizeof (mcamd_cs_offmap) / sizeof (struct mc_offmap) },
		{ mcamd_dimm_offmap,	/* MC_NT_DIMM */
		    sizeof (mcamd_dimm_offmap) / sizeof (struct mc_offmap) }
	};

	found = findoffset(hdl, node, &props[0], code, &offset);
	ASSERT(found);

	if (found)
		*valp = *(uint64_t *)((uintptr_t)node + offset);

	return (found == 1);
}

int
mcamd_get_numprops(mcamd_hdl_t *hdl, ...)
{
	va_list ap;
	mcamd_node_t *node;
	mcamd_propcode_t code;
	mcamd_prop_t *valp;

	va_start(ap, hdl);
	while ((node = va_arg(ap, mcamd_node_t *)) != NULL) {
		code = va_arg(ap, mcamd_propcode_t);
		valp = va_arg(ap, mcamd_prop_t *);
		if (!mcamd_get_numprop(hdl, node, code, valp))
			return (0);
	}
	va_end(ap);
	return (1);
}

static const struct mc_offmap mcreg_offmap[] = {
	{ MCAMD_REG_DRAMBASE, MCAMD_MC_OFF_DRAMBASE_REG },
	{ MCAMD_REG_DRAMLIMIT, MCAMD_MC_OFF_DRAMLIMIT_REG },
	{ MCAMD_REG_DRAMHOLE, MCAMD_MC_OFF_DRAMHOLE_REG },
	{ MCAMD_REG_DRAMCFGLO, MCAMD_MC_OFF_DRAMCFGLO_REG },
	{ MCAMD_REG_DRAMCFGHI, MCAMD_MC_OFF_DRAMCFGHI_REG },
};

static const struct mc_offmap csreg_offmap[] = {
	{ MCAMD_REG_CSBASE, MCAMD_CS_OFF_CSBASE_REG },
	{ MCAMD_REG_CSMASK, MCAMD_CS_OFF_CSMASK_REG },
};

/*ARGSUSED*/
int
mcamd_get_cfgreg(struct mcamd_hdl *hdl, mcamd_node_t *node,
    mcamd_regcode_t code, uint32_t *valp)
{
	int found;
	uint_t offset;

	struct nt_offmap regs[] = {
		{ mcreg_offmap,	/* MC_NT_MC */
		    sizeof (mcreg_offmap) / sizeof (struct mc_offmap) },
		{ csreg_offmap,	/* MC_NT_CS */
		    sizeof (csreg_offmap) / sizeof (struct mc_offmap) },
		{ NULL, 0 }		/* MC_NT_DIMM */
	};

	found = findoffset(hdl, node, &regs[0], code, &offset);
	ASSERT(found);

	ASSERT(found);
	if (found)
		*valp = *(uint32_t *)((uintptr_t)node + offset);

	return (found == 1);
}

int
mcamd_get_cfgregs(mcamd_hdl_t *hdl, ...)
{
	va_list ap;
	mcamd_node_t *node;
	mcamd_regcode_t code;
	uint32_t *valp;

	va_start(ap, hdl);
	while ((node = va_arg(ap, mcamd_node_t *)) != NULL) {
		code = va_arg(ap, mcamd_regcode_t);
		valp = va_arg(ap, uint32_t *);
		if (!mcamd_get_cfgreg(hdl, node, code, valp))
			return (0);
	}
	va_end(ap);
	return (1);
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

cmi_errno_t
mcamd_cmierr(int err, mcamd_hdl_t *hdl)
{
	if (err == 0)
		return (CMI_SUCCESS);

	switch (mcamd_errno(hdl)) {
	case EMCAMD_SYNDINVALID:
		return (CMIERR_MC_SYNDROME);

	case EMCAMD_TREEINVALID:
		return (CMIERR_MC_BADSTATE);

	case EMCAMD_NOADDR:
		return (CMIERR_MC_NOADDR);

	case EMCAMD_INSUFF_RES:
		return (CMIERR_MC_ADDRBITS);

	default:
		return (CMIERR_UNKNOWN);
	}

}

/*ARGSUSED*/
cmi_errno_t
mcamd_patounum_wrap(void *arg, uint64_t pa, uint8_t valid_hi, uint8_t valid_lo,
    uint32_t synd, int syndtype, mc_unum_t *unump)
{
	mcamd_hdl_t mcamd;
	int rc;

	mcamd_mkhdl(&mcamd);

	rw_enter(&mc_lock, RW_READER);

	rc = mcamd_patounum(&mcamd, (mcamd_node_t *)mc_list, pa,
	    valid_hi, valid_lo, synd, syndtype, unump);

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

	return (mcamd_cmierr(rc, &mcamd));
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
	unump->unum_chan = MC_INVALNUM;
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
		else if (strcmp(hcnm, "chip") == 0)
			unump->unum_chip = (int)v;
		else if (strcmp(hcnm, "memory-controller") == 0)
			unump->unum_mc = (int)v;
		else if (strcmp(hcnm, "chip-select") == 0)
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
cmi_errno_t
mcamd_unumtopa_wrap(void *arg, mc_unum_t *unump, nvlist_t *nvl, uint64_t *pap)
{
	mcamd_hdl_t mcamd;
	int rc;
	mc_unum_t unum;

	ASSERT(unump == NULL || nvl == NULL);	/* enforced at cmi level */

	if (unump == NULL) {
		if (!fmri2unum(nvl, &unum))
			return (CMIERR_MC_INVALUNUM);
		unump = &unum;
	}

	mcamd_mkhdl(&mcamd);

	rw_enter(&mc_lock, RW_READER);
	rc = mcamd_unumtopa(&mcamd, (mcamd_node_t *)mc_list, unump, pap);
	rw_exit(&mc_lock);

	return (mcamd_cmierr(rc, &mcamd));
}

static void
mc_ereport_dimm_resource(mc_unum_t *unump, nvlist_t *elems[], int *nump)
{
	int i;

	for (i = 0; i < MC_UNUM_NDIMM; i++) {
		if (unump->unum_dimms[i] == MC_INVALNUM)
			break;

		elems[(*nump)++] = fm_nvlist_create(NULL);
		fm_fmri_hc_set(elems[i], FM_HC_SCHEME_VERSION, NULL, NULL, 5,
		    "motherboard",  unump->unum_board,
		    "chip", unump->unum_chip,
		    "memory-controller", unump->unum_mc,
		    "dimm", unump->unum_dimms[i],
		    "rank", unump->unum_rank);
	}
}

static void
mc_ereport_cs_resource(mc_unum_t *unump, nvlist_t *elems[], int *nump)
{
	elems[0] = fm_nvlist_create(NULL);
	fm_fmri_hc_set(elems[0], FM_HC_SCHEME_VERSION, NULL, NULL, 4,
	    "motherboard",  unump->unum_board,
	    "chip", unump->unum_chip,
	    "memory-controller", unump->unum_mc,
	    "chip-select", unump->unum_cs);
	*nump = 1;
}

/*
 * Create the 'resource' payload member from the unum info.  If valid
 * dimm numbers are present in the unum info then create members
 * identifying the dimm and rank;  otherwise if a valid chip-select
 * number is indicated then create a member identifying the chip-select
 * topology node.
 */
static void
mc_ereport_add_resource(nvlist_t *payload, mc_unum_t *unump)
{
	nvlist_t *elems[MC_UNUM_NDIMM];
	int nelems = 0;
	int i;

	if (unump->unum_dimms[0] != MC_INVALNUM)
		mc_ereport_dimm_resource(unump, elems, &nelems);
	else if (unump->unum_cs != MC_INVALNUM)
		mc_ereport_cs_resource(unump, elems, &nelems);

	if (nelems > 0) {
		fm_payload_set(payload, FM_EREPORT_PAYLOAD_NAME_RESOURCE,
		    DATA_TYPE_NVLIST_ARRAY, nelems, elems, NULL);

		for (i = 0; i < nelems; i++)
			fm_nvlist_destroy(elems[i], FM_NVA_FREE);
	}
}

static void
mc_ereport_add_payload(nvlist_t *ereport, uint64_t members, mc_unum_t *unump)
{
	if (members & FM_EREPORT_PAYLOAD_FLAG_RESOURCE &&
	    unump != NULL)
		mc_ereport_add_resource(ereport, unump);
}

static nvlist_t *
mc_fmri_create(mc_t *mc)
{
	nvlist_t *nvl = fm_nvlist_create(NULL);

	fm_fmri_hc_set(nvl, FM_HC_SCHEME_VERSION, NULL, NULL, 3,
	    "motherboard", 0,
	    "chip", mc->mc_props.mcp_num,
	    "memory-controller", 0);

	return (nvl);
}

/*
 * Simple ereport generator for errors detected by the memory controller.
 * Posts an ereport of class ereport.cpu.amd.<class_sfx> with a resource nvlist
 * derived from the given mc_unum_t.  There are no other payload members.
 * The mc argument is used to formulate a detector and this mc should
 * correspond with that identified in the mc_unum_t.
 *
 * There is no control of which members to include the the resulting ereport -
 * it will be an ereport formed using the given class suffix, detector
 * indicated as the memory-controller and with a resource generated by
 * expanding the given mc_unum_t.
 *
 * We do not use any special nv allocator here and so this is not suitable
 * for use during panic.  It is intended for use during MC topology
 * discovery and other controlled circumstances.
 */
void
mcamd_ereport_post(mc_t *mc, const char *class_sfx, mc_unum_t *unump,
    uint64_t payload)
{
	nvlist_t *ereport, *detector;
	char buf[FM_MAX_CLASS];

	ereport = fm_nvlist_create(NULL);
	detector = mc_fmri_create(mc);

	(void) snprintf(buf, FM_MAX_CLASS, "%s.%s.%s", FM_ERROR_CPU,
	    "amd", class_sfx);
	fm_ereport_set(ereport, FM_EREPORT_VERSION, buf,
	    fm_ena_generate(gethrtime(), FM_ENA_FMT1), detector, NULL);
	fm_nvlist_destroy(detector, FM_NVA_FREE);

	mc_ereport_add_payload(ereport, payload, unump);

	(void) fm_ereport_post(ereport, EVCH_TRYHARD);
	fm_nvlist_destroy(ereport, FM_NVA_FREE);
}

static const cmi_mc_ops_t mcamd_mc_ops = {
	mcamd_patounum_wrap,	/* cmi_mc_patounum */
	mcamd_unumtopa_wrap,	/* cmi_mc_unumtopa */
	NULL			/* cmi_mc_logout */
};

void
mcamd_mc_register(cmi_hdl_t hdl, mc_t *mc)
{
	cmi_mc_register(hdl, &mcamd_mc_ops, mc);
}
