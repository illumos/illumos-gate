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

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/ddifm.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/mc.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/ksynch.h>
#include <sys/rwlock.h>
#include <sys/chip.h>
#include <sys/open.h>
#include <sys/policy.h>
#include <sys/machsystm.h>
#include <sys/x86_archext.h>
#include <sys/cpu_module.h>
#include <sys/mc_amd.h>

#include <mcamd.h>
#include <mcamd_api.h>

int mc_quadranksupport = 0;	/* set to 1 for a MB with quad rank support */

mc_t *mc_list;
krwlock_t mc_lock;
int mc_hold_attached = 1;

static void
mc_snapshot_destroy(mc_t *mc)
{
	ASSERT(RW_LOCK_HELD(&mc_lock));

	if (mc->mc_snapshot == NULL)
		return;

	kmem_free(mc->mc_snapshot, mc->mc_snapshotsz);
	mc->mc_snapshot = NULL;
	mc->mc_snapshotgen++;
}

static int
mc_snapshot_update(mc_t *mc)
{
	ASSERT(RW_LOCK_HELD(&mc_lock));

	if (mc->mc_snapshot != NULL)
		return (0);

	if (nvlist_pack(mc->mc_nvl, &mc->mc_snapshot, &mc->mc_snapshotsz,
	    NV_ENCODE_XDR, KM_SLEEP) != 0)
		return (-1);

	return (0);
}

static mc_t *
mc_lookup_func(dev_info_t *dip, int instance, mc_func_t **funcp)
{
	mc_t *mc;
	int i;

	ASSERT(RW_LOCK_HELD(&mc_lock));

	for (mc = mc_list; mc != NULL; mc = mc->mc_next) {
		for (i = 0; i < MC_FUNC_NUM; i++) {
			mc_func_t *func = &mc->mc_funcs[i];
			if ((dip != NULL && func->mcf_devi == dip) ||
			    (dip == NULL && func->mcf_instance == instance)) {
				if (funcp != NULL)
					*funcp = func;
				return (mc);
			}
		}
	}

	return (NULL);
}

static mc_t *
mc_lookup_by_devi(dev_info_t *dip, mc_func_t **funcp)
{
	return (mc_lookup_func(dip, 0, funcp));
}

static mc_t *
mc_lookup_by_instance(int instance, mc_func_t **funcp)
{
	return (mc_lookup_func(NULL, instance, funcp));
}

static mc_t *
mc_lookup_by_chipid(int chipid)
{
	mc_t *mc;

	ASSERT(RW_LOCK_HELD(&mc_lock));

	for (mc = mc_list; mc != NULL; mc = mc->mc_next) {
		if (mc->mc_chip->chip_id == chipid)
			return (mc);
	}

	return (NULL);
}

typedef struct mc_rev_map {
	uint_t rm_family;
	uint_t rm_modello;
	uint_t rm_modelhi;
	uint_t rm_rev;
	const char *rm_name;
} mc_rev_map_t;

static const mc_rev_map_t mc_rev_map[] = {
	{ 0xf, 0x00, 0x0f, MC_REV_PRE_D, "B/C/CG" },
	{ 0xf, 0x10, 0x1f, MC_REV_D_E, "D" },
	{ 0xf, 0x20, 0x3f, MC_REV_D_E, "E" },
	{ 0xf, 0x40, 0x5f, MC_REV_F, "F" },
	{ 0, 0, 0, MC_REV_UNKNOWN, NULL }
};

static const mc_rev_map_t *
mc_revision(chip_t *chp)
{
	int rmn = sizeof (mc_rev_map) / sizeof (mc_rev_map[0]);
	const mc_rev_map_t *rm;
	uint8_t family, model;

	if (chp == NULL)
		return (&mc_rev_map[rmn - 1]);

	/*
	 * For the moment, we assume that both cores in multi-core chips will
	 * be of the same revision, so we'll confine our revision check to
	 * the first CPU pointed to by this chip.
	 */
	family = cpuid_getfamily(chp->chip_cpus);
	model = cpuid_getmodel(chp->chip_cpus);

	for (rm = mc_rev_map; rm->rm_rev != MC_REV_UNKNOWN; rm++) {
		if (family == rm->rm_family && model >= rm->rm_modello &&
		    model <= rm->rm_modelhi)
			break;
	}

	return (rm);
}

static void
mc_prop_read_pair(ddi_acc_handle_t cfghdl, uint32_t *r1, off_t r1addr,
    uint32_t *r2, off_t r2addr, int n, off_t incr)
{
	int i;

	for (i = 0; i < n; i++, r1addr += incr, r2addr += incr) {
		r1[i] = pci_config_get32(cfghdl, r1addr);
		r2[i] = pci_config_get32(cfghdl, r2addr);
	}
}

static void
mc_nvl_add_prop(nvlist_t *nvl, void *node, uint_t code)
{
	int valfound;
	uint64_t value;
	const char *name = mcamd_get_propname(code);

	valfound = mcamd_get_numprop(NULL, (mcamd_node_t *)node, code, &value);

	ASSERT(name != NULL && valfound);
	if (name != NULL && valfound)
		(void) nvlist_add_uint64(nvl, name, value);
}

static nvlist_t *
mc_nvl_create(mc_t *mc)
{
	mc_cs_t *mccs = mc->mc_cslist;
	nvlist_t *cslist[MC_CHIP_NCS], *dimmlist[MC_CHIP_NDIMM];
	nvlist_t *mcnvl;
	mc_dimm_t *mcd;
	int nelem, i;

	(void) nvlist_alloc(&mcnvl, NV_UNIQUE_NAME, KM_SLEEP);
	(void) nvlist_add_string(mcnvl, "revname", mc->mc_revname);

	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_NUM);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_REV);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_BASE_ADDR);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_LIM_ADDR);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_DRAM_CONFIG);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_DRAM_HOLE);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_DRAM_ILEN);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_DRAM_ILSEL);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_CSBANKMAP);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_ACCESS_WIDTH);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_CSBANK_INTLV);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_DISABLED_CS);

	for (nelem = 0; mccs != NULL; mccs = mccs->mccs_next, nelem++) {
		nvlist_t **csp = &cslist[nelem];

		(void) nvlist_alloc(csp, NV_UNIQUE_NAME, KM_SLEEP);
		mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_NUM);
		mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_BASE_ADDR);
		mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_MASK);
		mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_SIZE);

		if (mccs->mccs_dimmnums[0] != -1)
			mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_LODIMM);
		if (mccs->mccs_dimmnums[1] != -1)
			mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_UPDIMM);
	}

	(void) nvlist_add_nvlist_array(mcnvl, "cslist", cslist, nelem);
	for (i = 0; i < nelem; i++)
		nvlist_free(cslist[i]);

	for (nelem = 0, mcd = mc->mc_props.mcp_dimmlist; mcd != NULL;
	    mcd = mcd->mcd_next, nelem++) {
		nvlist_t **dimmp = &dimmlist[nelem];
		int ncs = 0;
		uint64_t csnums[MC_CHIP_DIMMRANKMAX];

		(void) nvlist_alloc(dimmp, NV_UNIQUE_NAME, KM_SLEEP);

		mc_nvl_add_prop(*dimmp, mcd, MCAMD_PROP_NUM);

		for (i = 0; i < MC_CHIP_DIMMRANKMAX; i++) {
			if (mcd->mcd_cs[i] != NULL)
				csnums[ncs++] = mcd->mcd_cs[i]->mccs_num;
		}

		(void) nvlist_add_uint64_array(*dimmp, "csnums", csnums, ncs);
	}

	(void) nvlist_add_nvlist_array(mcnvl, "dimmlist", dimmlist, nelem);
	for (i = 0; i < nelem; i++)
		nvlist_free(dimmlist[i]);

	return (mcnvl);
}

static void
mc_dimm_csadd(mc_dimm_t *mcd, mc_cs_t *mccs)
{
	int i;

	for (i = 0; i < MC_CHIP_DIMMRANKMAX; i++) {
		if (mcd->mcd_cs[i] == NULL) {
			mcd->mcd_cs[i] = mccs;
			break;
		}
	}
	ASSERT(i != MC_CHIP_DIMMRANKMAX);
}

static mc_dimm_t *
mc_dimm_create(mc_t *mc, mc_cs_t *mccs, uint_t num)
{
	mc_dimm_t *mcd = kmem_zalloc(sizeof (mc_dimm_t), KM_SLEEP);

	mcd->mcd_hdr.mch_type = MC_NT_DIMM;
	mcd->mcd_mc = mc;
	mcd->mcd_num = num;
	mc_dimm_csadd(mcd, mccs);

	return (mcd);
}

/*
 * A chip-select is associated with up to 2 dimms, and a single dimm may
 * have up to 4 associated chip-selects (in the presence of quad-rank support
 * on the motherboard).  How we number our dimms is determined by the MC
 * config.  This function may be called by multiple chip-selects for the
 * same dimm(s).
 */
static void
mc_cs_dimmlist_create(mc_t *mc, mc_cs_t *mccs, uint_t *dimm_nums, int ndimm)
{
	mc_dimm_t *mcd;
	mc_props_t *mcp = &mc->mc_props;
	int i;
	int nfound = 0;

	/*
	 * Has some other chip-select already created this dimm or dimms?
	 */
	for (mcd = mcp->mcp_dimmlist; mcd != NULL; mcd = mcd->mcd_next) {
		for (i = 0; i < ndimm; i++) {
			if (mcd->mcd_num == dimm_nums[i]) {
				mccs->mccs_dimm[i] = mcd;
				mccs->mccs_dimmnums[i] = mcd->mcd_num;
				mc_dimm_csadd(mcd, mccs);
				nfound++;
			}
		}
	}
	ASSERT(nfound == 0 || nfound == ndimm);
	if (nfound == ndimm)
		return;

	for (i = 0; i < ndimm; i++) {
		mcd = mccs->mccs_dimm[i] =
		    mc_dimm_create(mc, mccs, dimm_nums[i]);

		mccs->mccs_dimmnums[i] = mcd->mcd_num;

		if (mcp->mcp_dimmlist == NULL)
			mcp->mcp_dimmlist = mcd;
		else
			mcp->mcp_dimmlast->mcd_next = mcd;
		mcp->mcp_dimmlast = mcd;
	}

}

/*
 * A placeholder for a future implementation that works this out from
 * smbios or SPD information.  For now we will return a value that
 * can be tuned in /etc/system, and the default will cover current Sun systems.
 */
/*ARGSUSED*/
static int
mc_config_quadranksupport(mc_t *mc)
{
	return (mc_quadranksupport != 0);
}

/*
 * Create the DIMM structure for this MC.  There are a number of unkowns,
 * such as the number of DIMM slots for this MC, the number of chip-select
 * ranks supported for each DIMM, how the slots are labelled etc.
 *
 * SMBIOS information can help with some of this (if the bios implementation is
 * complete and accurate, which is often not the case):
 *
 * . A record is required for each SMB_TYPE_MEMDEVICE slot, whether populated
 *   or not.  The record should reference the associated SMB_TYPE_MEMARRAY,
 *   so we can figure out the number of slots for each MC.  In practice some
 *   smbios implementations attribute all slots (from multiple chips) to
 *   a single memory array.
 *
 * . SMB_TYPE_MEMDEVICEMAP records indicate how a particular SMB_TYPE_MEMDEVICE
 *   has been mapped.  Some smbios implementation produce rubbish here, or get
 *   confused when cs bank interleaving is enabled or disabled, but we can
 *   perform some validation of the information before using it.  The record
 *   information is not well suited to handling cs bank interleaving since
 *   it really only provides for a device to have a few contiguos mappings
 *   and with cs interleave we have lots of little chunks interleaved across
 *   the devices.  If we assume that the bios has followed the BKDG algorithm
 *   for setting up cs interleaving (which involves assinging contiguous
 *   and adjacent ranges to the chip selects and then swapping some
 *   base and mask hi and lo bits) then we can attempt to interpret the
 *   DEVICEMAP records as being the addresses prior to swapping address/mask
 *   bits to establish the interleave - that seems to cover at least some
 *   smbios implementations.  Even if that assumption appears good it is
 *   also not clear which MEMDEVICE records correspond to LODIMMs and which
 *   to UPDIMMs in a DIMM pair (128 bit MC mode) - we have to interpret the
 *   Device Locator and Bank Locator labels.
 *
 * We also do not know how many chip-select banks reside on individual
 * DIMMs.  For instance we cannot distinguish a system that supports 8
 * DIMMs slots per chip (one CS line each, thereby supporting only single-rank
 * DIMMs) vs a system that has just 4 slots per chip and which routes
 * 2 CS lines to each pair (thereby supporting dual rank DIMMs).  In each
 * we would discover 8 active chip-selects.
 *
 * So the task of establishing the real DIMM configuration is complex, likely
 * requiring some combination of good SMBIOS data and perhaps our own access
 * to SPD information.  Instead we opt for a canonical numbering scheme,
 * derived from the 'AMD Athlon (TM) 64 FX and AMD Opteron (TM) Processors
 * Motherboard Design Guide' (AMD publication #25180).
 */
static void
mc_dimmlist_create(mc_t *mc)
{
	int mcmode;
	mc_cs_t *mccs;
	int quadrank = mc_config_quadranksupport(mc);
	uint_t dimm_nums[MC_CHIP_DIMMPERCS];
	int ldimmno;			/* logical DIMM pair number, 0 .. 3 */

	mcmode = mc->mc_props.mcp_dramcfg & MC_DC_DCFG_128 ? 128 : 64;

	for (mccs = mc->mc_cslist; mccs != NULL; mccs = mccs->mccs_next) {
		if (quadrank) {
			/*
			 * Quad-rank support.  We assume that any of cs#
			 * 4/5/6/6 that we have discovered active are routed
			 * for quad rank support as described in the MB
			 * design guide:
			 *	DIMM0: CS# 0, 1, 4 and 5
			 *	DIMM1: CS# 2, 3, 6 and 7
			 */
			ldimmno = (mccs->mccs_num % 4) /2;
		} else {
			/*
			 * DIMM0: CS# 0 and 1
			 * DIMM1: CS# 2 and 3
			 * DIMM2: CS# 4 and 5
			 * DIMM3: CS# 6 and 7
			 */
			ldimmno = mccs->mccs_num / 2;
		}

		if (mcmode == 128) {
			/* 128-bit data width mode - dimms present in pairs */
			dimm_nums[0] = ldimmno * 2;		/* LODIMM */
			dimm_nums[1] = ldimmno * 2 + 1;		/* UPDIMM */
		} else {
			/* 64-bit data width mode - only even numbered dimms */
			dimm_nums[0] = ldimmno * 2;		/* LODIMM */
		}
		mc_cs_dimmlist_create(mc, mccs, dimm_nums,
		    mcmode == 128 ? 2 : 1);
	}
}

static mc_cs_t *
mc_cs_create(mc_t *mc, uint_t num, uint64_t base, uint64_t mask, size_t sz)
{
	mc_cs_t *mccs = kmem_zalloc(sizeof (mc_cs_t), KM_SLEEP);

	mccs->mccs_hdr.mch_type = MC_NT_CS;
	mccs->mccs_mc = mc;
	mccs->mccs_num = num;
	mccs->mccs_base = base;
	mccs->mccs_mask = mask;
	mccs->mccs_size = sz;

	return (mccs);
}

/*
 * Function 1 Configuration - Address Map (see BKDG 3.4.4 DRAM Address Map)
 *
 * Read the Function 1 Address Map for each potential DRAM node.  The Base
 * Address for a node gives the starting system address mapped at that node,
 * and the limit gives the last valid address mapped at that node.  Regions for
 * different nodes should not overlap, unless node-interleaving is enabled.
 * The base register also indicates the node-interleaving settings (IntlvEn).
 * The limit register includes IntlvSel which determines which 4K blocks will
 * be routed to this node and the destination node ID for addresses that fall
 * within the [base, limit] range - this must match the pair number.
 */
static void
mc_mkprops_addrmap(ddi_acc_handle_t cfghdl, mc_t *mc)
{
	uint32_t base[MC_AM_REG_NODE_NUM], lim[MC_AM_REG_NODE_NUM];
	mc_props_t *mcp = &mc->mc_props;
	int i;

	mc_prop_read_pair(cfghdl, base, MC_AM_REG_DRAMBASE_0, lim,
	    MC_AM_REG_DRAMLIM_0, MC_AM_REG_NODE_NUM, MC_AM_REG_DRAM_INCR);

	for (i = 0; i < MC_AM_REG_NODE_NUM; i++) {
		/*
		 * Don't create properties for empty nodes.
		 */
		if ((lim[i] & MC_AM_DL_DRAMLIM_MASK) == 0)
			continue;

		/*
		 * Don't create properties for DIMM ranges that aren't local
		 * to this node.
		 */
		if ((lim[i] & MC_AM_DL_DSTNODE_MASK) != mc->mc_chip->chip_id)
			continue;

		mcp->mcp_base = MC_AM_DB_DRAMBASE(base[i]);
		mcp->mcp_lim = MC_AM_DL_DRAMLIM(lim[i]);
		mcp->mcp_ilen = (base[i] & MC_AM_DB_INTLVEN_MASK) >>
		    MC_AM_DB_INTLVEN_SHIFT;
		mcp->mcp_ilsel = (lim[i] & MC_AM_DL_INTLVSEL_MASK) >>
		    MC_AM_DL_INTLVSEL_SHIFT;
	}

	/*
	 * The Function 1 DRAM Hole Address Register tells us which node(s)
	 * own the DRAM space that is hoisted above 4GB, together with the
	 * hole base and offset for this node.
	 */
	mcp->mcp_dramhole = pci_config_get32(cfghdl, MC_AM_REG_HOLEADDR);
}

/*
 * Function 2 configuration - DRAM Controller
 */
static void
mc_mkprops_dramctl(ddi_acc_handle_t cfghdl, mc_t *mc)
{
	uint32_t base[MC_CHIP_NCS], mask[MC_CHIP_NCS];
	uint64_t dramcfg;
	mc_props_t *mcp = &mc->mc_props;
	int wide = 0;	/* 128-bit access mode? */
	int i;
	mcamd_hdl_t hdl;

	mcamd_mkhdl(&hdl);	/* to call into common code */

	/*
	 * Read Function 2 DRAM Configuration High and Low registers and
	 * weld them together into a 64-bit value.  The High component
	 * is mostly concerned with memory clocks etc and we'll not have
	 * any use for that.  The Low component tells us if ECC is enabled,
	 * if we're in 64- or 128-bit MC mode, how the upper chip-selects
	 * are mapped, which chip-select pairs are using x4 parts, etc.
	 */
	dramcfg = pci_config_get32(cfghdl, MC_DC_REG_DRAMCFGLO) |
	    ((uint64_t)pci_config_get32(cfghdl, MC_DC_REG_DRAMCFGHI) << 32);
	wide = dramcfg & MC_DC_DCFG_128;

	mcp->mcp_dramcfg = dramcfg;
	mcp->mcp_accwidth = wide ? 128 : 64;

	/*
	 * Read Function 2 DRAM Bank Address Mapping.  This tells us
	 * whether bank swizzle mode is enabled, and also encodes
	 * the type of DIMM module in use for each chip-select pair.
	 */
	mcp->mcp_csbankmap = pci_config_get32(cfghdl, MC_DC_REG_BANKADDRMAP);

	/*
	 * Read Function 2 Configuration Registers for DRAM CS Base 0 thru 7
	 * and DRAM CS Mask 0 thru 7.  The Base registers give us the
	 * BaseAddrHi and BaseAddrLo from which the base can be constructed,
	 * and whether this chip-select bank is enabled (CSBE).  The
	 * Mask registers give us AddrMaskHi and AddrMaskLo from which
	 * a full mask can be constructed.
	 */
	mc_prop_read_pair(cfghdl, base, MC_DC_REG_CSBASE_0, mask,
	    MC_DC_REG_CSMASK_0, MC_CHIP_NCS, MC_DC_REG_CS_INCR);

	/*
	 * Create a cs node for each enabled chip-select
	 */
	for (i = 0; i < MC_CHIP_NCS; i++) {
		mc_cs_t *mccs;
		uint64_t csmask;
		size_t sz;

		if (!(base[i] & MC_DC_CSB_CSBE)) {
			mcp->mcp_disabled_cs++;
			continue;
		}

		if (mcamd_cs_size(&hdl, (mcamd_node_t *)mc, i, &sz) < 0)
			continue;

		csmask = MC_DC_CSM_CSMASK(mask[i]);
		mccs = mc_cs_create(mc, i, MC_DC_CSB_CSBASE(base[i]), csmask,
		    sz);

		if (mc->mc_cslist == NULL)
			mc->mc_cslist = mccs;
		else
			mc->mc_cslast->mccs_next = mccs;
		mc->mc_cslast = mccs;

		/*
		 * Check for cs bank interleaving - some bits clear in the
		 * lower mask.  All banks must/will have the same lomask bits
		 * if cs interleaving is active.
		 */
		if (!mcp->mcp_csbank_intlv) {
			int bitno, ibits = 0;
			for (bitno = MC_DC_CSM_MASKLO_LOBIT;
			    bitno <= MC_DC_CSM_MASKLO_HIBIT; bitno++) {
				if (!(csmask & (1 << bitno)))
					ibits++;
			}
			if (ibits > 0)
				mcp->mcp_csbank_intlv = 1 << ibits;
		}
	}

	/*
	 * Now that we have discovered all active chip-selects we attempt
	 * to divine the associated DIMM configuration.
	 */
	mc_dimmlist_create(mc);
}

typedef struct mc_bind_map {
	const char *bm_bindnm;	/* attachment binding name */
	uint_t bm_func;		/* PCI config space function number for bind */
	const char *bm_model;	/* value for device node model property */
	void (*bm_mkprops)(ddi_acc_handle_t, mc_t *);
} mc_bind_map_t;

static const mc_bind_map_t mc_bind_map[] = {
	{ MC_FUNC_HTCONFIG_BINDNM, MC_FUNC_HTCONFIG,
	"AMD Memory Controller (HT Configuration)", NULL },
	{ MC_FUNC_ADDRMAP_BINDNM, MC_FUNC_ADDRMAP,
	"AMD Memory Controller (Address Map)", mc_mkprops_addrmap },
	{ MC_FUNC_DRAMCTL_BINDNM, MC_FUNC_DRAMCTL,
	"AMD Memory Controller (DRAM Controller & HT Trace)",
	mc_mkprops_dramctl },
	NULL
};

/*ARGSUSED*/
static int
mc_open(dev_t *devp, int flag, int otyp, cred_t *credp)
{
	if (otyp != OTYP_CHR)
		return (EINVAL);

	rw_enter(&mc_lock, RW_READER);
	if (mc_lookup_by_chipid(getminor(*devp)) == NULL) {
		rw_exit(&mc_lock);
		return (EINVAL);
	}
	rw_exit(&mc_lock);

	return (0);
}

/*ARGSUSED*/
static int
mc_close(dev_t dev, int flag, int otyp, cred_t *credp)
{
	return (0);
}

/*ARGSUSED*/
static int
mc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	int rc = 0;
	mc_t *mc;

	if (cmd != MC_IOC_SNAPSHOT_INFO && cmd != MC_IOC_SNAPSHOT)
		return (EINVAL);

	rw_enter(&mc_lock, RW_READER);

	if ((mc = mc_lookup_by_chipid(getminor(dev))) == NULL) {
		rw_exit(&mc_lock);
		return (EINVAL);
	}

	if (mc_snapshot_update(mc) < 0) {
		rw_exit(&mc_lock);
		return (EIO);
	}

	switch (cmd) {
	case MC_IOC_SNAPSHOT_INFO: {
		mc_snapshot_info_t mcs;

		mcs.mcs_size = mc->mc_snapshotsz;
		mcs.mcs_gen = mc->mc_snapshotgen;

		if (ddi_copyout(&mcs, (void *)arg, sizeof (mc_snapshot_info_t),
		    mode) < 0)
			rc = EFAULT;
		break;
	}

	case MC_IOC_SNAPSHOT:
		if (ddi_copyout(mc->mc_snapshot, (void *)arg, mc->mc_snapshotsz,
		    mode) < 0)
			rc = EFAULT;
		break;
	}

	rw_exit(&mc_lock);

	return (rc);
}

static struct cb_ops mc_cb_ops = {
	mc_open,
	mc_close,
	nodev,		/* not a block driver */
	nodev,		/* no print routine */
	nodev,		/* no dump routine */
	nodev,		/* no read routine */
	nodev,		/* no write routine */
	mc_ioctl,
	nodev,		/* no devmap routine */
	nodev,		/* no mmap routine */
	nodev,		/* no segmap routine */
	nochpoll,	/* no chpoll routine */
	ddi_prop_op,
	0,		/* not a STREAMS driver */
	D_NEW | D_MP,	/* safe for multi-thread/multi-processor */
};

/*ARGSUSED*/
static int
mc_getinfo(dev_info_t *dip, ddi_info_cmd_t infocmd, void *arg, void **result)
{
	int rc = DDI_SUCCESS;
	mc_t *mc;

	if (infocmd != DDI_INFO_DEVT2DEVINFO &&
	    infocmd != DDI_INFO_DEVT2INSTANCE) {
		*result = NULL;
		return (DDI_FAILURE);
	}

	rw_enter(&mc_lock, RW_READER);

	if ((mc = mc_lookup_by_chipid(getminor((dev_t)arg))) == NULL ||
	    mc->mc_funcs[MC_FUNC_DEVIMAP].mcf_devi == NULL) {
		rc = DDI_FAILURE;
	} else if (infocmd == DDI_INFO_DEVT2DEVINFO) {
		*result = mc->mc_funcs[MC_FUNC_DEVIMAP].mcf_devi;
	} else {
		*result = (void *)(uintptr_t)
		    mc->mc_funcs[MC_FUNC_DEVIMAP].mcf_instance;
	}

	rw_exit(&mc_lock);

	return (rc);
}

/*ARGSUSED2*/
static int
mc_fm_handle(dev_info_t *dip, ddi_fm_error_t *fmerr, const void *arg)
{
	pci_ereport_post(dip, fmerr, NULL);
	return (DDI_FM_NONFATAL);
}

static void
mc_fm_init(dev_info_t *dip)
{
	int fmcap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE;
	ddi_fm_init(dip, &fmcap, NULL);
	pci_ereport_setup(dip);
	ddi_fm_handler_register(dip, mc_fm_handle, NULL);
}

static void
mc_fm_fini(dev_info_t *dip)
{
	pci_ereport_teardown(dip);
	ddi_fm_fini(dip);
}

static mc_t *
mc_create(chipid_t chipid)
{
	chip_t *chp = chip_lookup(chipid);
	const mc_rev_map_t *rmp = mc_revision(chp);
	mc_t *mc;

	ASSERT(RW_WRITE_HELD(&mc_lock));

	if (chp == NULL || rmp->rm_rev == MC_REV_UNKNOWN)
		return (NULL);

	mc = kmem_zalloc(sizeof (mc_t), KM_SLEEP);
	mc->mc_hdr.mch_type = MC_NT_MC;
	mc->mc_chip = chp;
	mc->mc_props.mcp_rev = rmp->rm_rev;
	mc->mc_revname = rmp->rm_name;
	mc->mc_props.mcp_num = mc->mc_chip->chip_id;

	mc->mc_next = mc_list;
	mc_list = mc;

	return (mc);
}

static int
mc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	ddi_acc_handle_t hdl;
	const mc_bind_map_t *bm;
	const char *bindnm;
	char *unitstr = NULL;
	long unitaddr;
	int chipid, func, rc;
	cpu_t *cpu;
	mc_t *mc;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	bindnm = ddi_binding_name(dip);
	for (bm = mc_bind_map; bm->bm_bindnm != NULL; bm++) {
		if (strcmp(bindnm, bm->bm_bindnm) == 0) {
			func = bm->bm_func;
			break;
		}
	}

	if (bm->bm_bindnm == NULL)
		return (DDI_FAILURE);

	/*
	 * We need the device number, which corresponds to the processor node
	 * number plus 24.  The node number can then be used to associate this
	 * memory controller device with a given processor chip.
	 */
	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "unit-address", &unitstr) != DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "failed to find unit-address for %s", bindnm);
		return (DDI_FAILURE);
	}

	rc = ddi_strtol(unitstr, NULL, 16, &unitaddr);
	ASSERT(rc == 0 && unitaddr >= MC_AMD_DEV_OFFSET);
	ddi_prop_free(unitstr);

	if (rc != 0 || unitaddr < MC_AMD_DEV_OFFSET) {
		cmn_err(CE_WARN, "failed to parse unit address %s for %s\n",
		    unitstr, bindnm);
		return (DDI_FAILURE);
	}

	chipid = unitaddr - MC_AMD_DEV_OFFSET;

	rw_enter(&mc_lock, RW_WRITER);

	for (mc = mc_list; mc != NULL; mc = mc->mc_next) {
		if (mc->mc_chip->chip_id == chipid)
			break;
	}

	/* Integrate this memory controller device into existing set */
	if (mc == NULL) {
		mc = mc_create(chipid);

		if (mc == NULL) {
			/*
			 * We don't complain here because this is a legitimate
			 * path for MP systems.  On those machines, we'll attach
			 * before all CPUs have been initialized, and thus the
			 * chip verification in mc_create will fail.  We'll be
			 * reattached later for those CPUs.
			 */
			rw_exit(&mc_lock);
			return (DDI_FAILURE);
		}
	} else {
		mc_snapshot_destroy(mc);
	}

	/* Beyond this point, we're committed to creating this node */

	mc_fm_init(dip);

	ASSERT(mc->mc_funcs[func].mcf_devi == NULL);
	mc->mc_funcs[func].mcf_devi = dip;
	mc->mc_funcs[func].mcf_instance = ddi_get_instance(dip);

	mc->mc_ref++;

	rw_downgrade(&mc_lock);

	/*
	 * Add the common properties to this node, and then add any properties
	 * that are specific to this node based upon its configuration space.
	 */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE,
	    dip, "model", (char *)bm->bm_model);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE,
	    dip, "chip-id", mc->mc_chip->chip_id);

	if (bm->bm_mkprops != NULL &&
	    pci_config_setup(dip, &hdl) == DDI_SUCCESS) {
		bm->bm_mkprops(hdl, mc);
		pci_config_teardown(&hdl);
	}

	/*
	 * If this is the last node to be attached for this memory controller,
	 * so create the minor node and set up the properties.
	 */
	if (func == MC_FUNC_DEVIMAP) {
		mc_props_t *mcp = &mc->mc_props;

		if (ddi_create_minor_node(dip, "mc-amd", S_IFCHR,
		    mc->mc_chip->chip_id, "ddi_mem_ctrl", 0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "failed to create minor node for chip "
			    "%u memory controller\n", mc->mc_chip->chip_id);
		}

		/*
		 * Register the memory controller for every CPU of this chip.
		 * Then attempt to enable h/w memory scrubbers for this node.
		 * If we are successful, disable the software memory scrubber.
		 */
		mutex_enter(&cpu_lock);

		cpu = mc->mc_chip->chip_cpus;

		if (mc->mc_props.mcp_lim != mc->mc_props.mcp_base) {
			rc = cmi_scrubber_enable(cpu, mcp->mcp_base,
			    mcp->mcp_ilen);
		} else {
			rc = 0;
		}

		do {
			mcamd_mc_register(cpu);
			cpu = cpu->cpu_next_chip;
		} while (cpu != mc->mc_chip->chip_cpus);

		mutex_exit(&cpu_lock);

		if (rc)
			memscrub_disable();
	}

	nvlist_free(mc->mc_nvl);
	mc->mc_nvl = mc_nvl_create(mc);

	rw_exit(&mc_lock);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
mc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	return (DDI_FAILURE);
}

static struct dev_ops mc_ops = {
	DEVO_REV,		/* devo_rev */
	0,			/* devo_refcnt */
	mc_getinfo,		/* devo_getinfo */
	nulldev,		/* devo_identify */
	nulldev,		/* devo_probe */
	mc_attach,		/* devo_attach */
	mc_detach,		/* devo_detach */
	nodev,			/* devo_reset */
	&mc_cb_ops,		/* devo_cb_ops */
	NULL,			/* devo_bus_ops */
	NULL			/* devo_power */
};

static struct modldrv modldrv = {
	&mod_driverops,
	"Memory Controller for AMD processors",
	&mc_ops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	(void *)&modldrv,
	NULL
};

int
_init(void)
{
	rw_init(&mc_lock, NULL, RW_DRIVER, NULL);
	return (mod_install(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

int
_fini(void)
{
	int rc;

	if ((rc = mod_remove(&modlinkage)) != 0)
		return (rc);

	rw_destroy(&mc_lock);
	return (0);
}
