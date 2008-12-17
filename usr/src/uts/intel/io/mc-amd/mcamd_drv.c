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

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/ddifm.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/stat.h>
#include <sys/modctl.h>
#include <sys/types.h>
#include <sys/cpuvar.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/ksynch.h>
#include <sys/rwlock.h>
#include <sys/pghw.h>
#include <sys/open.h>
#include <sys/policy.h>
#include <sys/x86_archext.h>
#include <sys/cpu_module.h>
#include <qsort.h>
#include <sys/pci_cfgspace.h>
#include <sys/mc.h>
#include <sys/mc_amd.h>
#include <mcamd.h>
#include <mcamd_dimmcfg.h>
#include <mcamd_pcicfg.h>
#include <mcamd_api.h>
#include <sys/fm/cpu/AMD.h>

/*
 * Set to prevent mc-amd from attaching.
 */
int mc_no_attach = 0;

/*
 * Of the 754/939/940 packages, only socket 940 supports quadrank registered
 * dimms.  Unfortunately, no memory-controller register indicates the
 * presence of quadrank dimm support or presence (i.e., in terms of number
 * of slots per cpu, and chip-select lines per slot,  The following may be set
 * in /etc/system to indicate the presence of quadrank support on a motherboard.
 *
 * There is no need to set this for F(1207) and S1g1.
 */
int mc_quadranksupport = 0;

mc_t *mc_list, *mc_last;
krwlock_t mc_lock;
int mc_hold_attached = 1;

#define	MAX(m, n) ((m) >= (n) ? (m) : (n))
#define	MIN(m, n) ((m) <= (n) ? (m) : (n))

/*
 * The following tuneable is used to determine the DRAM scrubbing rate.
 * The values range from 0x00-0x16 as described in the BKDG.  Zero
 * disables DRAM scrubbing.  Values above zero indicate rates in descending
 * order.
 *
 * The default value below is used on several Sun systems.  In the future
 * this code should assign values dynamically based on memory sizing.
 */
uint32_t mc_scrub_rate_dram = 0xd;	/* 64B every 163.8 us; 1GB per 45 min */

enum {
	MC_SCRUB_BIOSDEFAULT,	/* retain system default value */
	MC_SCRUB_FIXED,		/* assign mc_scrub_rate_* values */
	MC_SCRUB_MAX		/* assign max of system and tunables */
} mc_scrub_policy = MC_SCRUB_MAX;

static void
mc_snapshot_destroy(mc_t *mc)
{
	ASSERT(RW_LOCK_HELD(&mc_lock));

	if (mc->mc_snapshot == NULL)
		return;

	kmem_free(mc->mc_snapshot, mc->mc_snapshotsz);
	mc->mc_snapshot = NULL;
	mc->mc_snapshotsz = 0;
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
mc_lookup_by_chipid(int chipid)
{
	mc_t *mc;

	ASSERT(RW_LOCK_HELD(&mc_lock));

	for (mc = mc_list; mc != NULL; mc = mc->mc_next) {
		if (mc->mc_props.mcp_num  == chipid)
			return (mc);
	}

	return (NULL);
}

/*
 * Read config register pairs into the two arrays provided on the given
 * handle and at offsets as follows:
 *
 *	Index	Array r1 offset			Array r2 offset
 *	0	r1addr				r2addr
 *	1	r1addr + incr			r2addr + incr
 *	2	r1addr + 2 * incr		r2addr + 2 * incr
 *	...
 *	n - 1	r1addr + (n - 1) * incr		r2addr + (n - 1) * incr
 *
 * The number of registers to read into the r1 array is r1n; the number
 * for the r2 array is r2n.
 */
static void
mc_prop_read_pair(mc_pcicfg_hdl_t cfghdl, uint32_t *r1, off_t r1addr,
    int r1n, uint32_t *r2, off_t r2addr, int r2n, off_t incr)
{
	int i;

	for (i = 0; i < MAX(r1n, r2n); i++, r1addr += incr, r2addr += incr) {
		if (i < r1n)
			r1[i] = mc_pcicfg_get32(cfghdl, r1addr);
		if (i < r2n)
			r2[i] = mc_pcicfg_get32(cfghdl, r2addr);
	}
}

#define	NSKT	6

static void
mc_nvl_add_socket(nvlist_t *nvl, mc_t *mc)
{
	const char *s = "Unknown";
	int i;

	static const struct {
		uint32_t type;
		const char *name;
	} sktnames[NSKT] = {
		{ X86_SOCKET_754, "Socket 754" },
		{ X86_SOCKET_939, "Socket 939" },
		{ X86_SOCKET_940, "Socket 940" },
		{ X86_SOCKET_AM2, "Socket AM2" },
		{ X86_SOCKET_F1207, "Socket F(1207)" },
		{ X86_SOCKET_S1g1, "Socket S1g1" },
	};

	for (i = 0; i < NSKT; i++) {
		if (mc->mc_socket == sktnames[i].type) {
			s = sktnames[i].name;
			break;
		}
	}

	(void) nvlist_add_string(nvl, "socket", s);
}

static uint32_t
mc_ecc_enabled(mc_t *mc)
{
	uint32_t rev = mc->mc_props.mcp_rev;
	union mcreg_nbcfg nbcfg;

	MCREG_VAL32(&nbcfg) = mc->mc_cfgregs.mcr_nbcfg;

	return (MC_REV_MATCH(rev, MC_F_REVS_BCDE) ?
	    MCREG_FIELD_F_preF(&nbcfg, EccEn) :
	    MCREG_FIELD_F_revFG(&nbcfg, EccEn));
}

static uint32_t
mc_ck_enabled(mc_t *mc)
{
	uint32_t rev = mc->mc_props.mcp_rev;
	union mcreg_nbcfg nbcfg;

	MCREG_VAL32(&nbcfg) = mc->mc_cfgregs.mcr_nbcfg;

	return (MC_REV_MATCH(rev, MC_F_REVS_BCDE) ?
	    MCREG_FIELD_F_preF(&nbcfg, ChipKillEccEn) :
	    MCREG_FIELD_F_revFG(&nbcfg, ChipKillEccEn));
}

static void
mc_nvl_add_ecctype(nvlist_t *nvl, mc_t *mc)
{
	(void) nvlist_add_string(nvl, "ecc-type", mc_ecc_enabled(mc) ?
	    (mc_ck_enabled(mc) ? "ChipKill 128/16" : "Normal 64/8") : "None");
}

static void
mc_nvl_add_prop(nvlist_t *nvl, void *node, mcamd_propcode_t code, int reqval)
{
	int valfound;
	uint64_t value;
	const char *name = mcamd_get_propname(code);

	valfound = mcamd_get_numprop(NULL, (mcamd_node_t *)node, code, &value);

	ASSERT(name != NULL && valfound);
	if (name != NULL && valfound && (!reqval || value != MC_INVALNUM))
		(void) nvlist_add_uint64(nvl, name, value);
}

static void
mc_nvl_add_cslist(nvlist_t *mcnvl, mc_t *mc)
{
	mc_cs_t *mccs = mc->mc_cslist;
	nvlist_t *cslist[MC_CHIP_NCS];
	int nelem, i;

	for (nelem = 0; mccs != NULL; mccs = mccs->mccs_next, nelem++) {
		nvlist_t **csp = &cslist[nelem];
		char csname[MCDCFG_CSNAMELEN];

		(void) nvlist_alloc(csp, NV_UNIQUE_NAME, KM_SLEEP);
		mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_NUM, 0);
		mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_BASE_ADDR, 0);
		mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_MASK, 0);
		mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_SIZE, 0);

		/*
		 * It is possible for an mc_cs_t not to have associated
		 * DIMM info if mcdcfg_lookup failed.
		 */
		if (mccs->mccs_csl[0] != NULL) {
			mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_CSDIMM1, 1);
			mcdcfg_csname(mc->mc_socket, mccs->mccs_csl[0], csname,
			    sizeof (csname));
			(void) nvlist_add_string(*csp, "dimm1-csname", csname);
		}

		if (mccs->mccs_csl[1] != NULL) {
			mc_nvl_add_prop(*csp, mccs, MCAMD_PROP_CSDIMM2, 1);
			mcdcfg_csname(mc->mc_socket, mccs->mccs_csl[1], csname,
			    sizeof (csname));
			(void) nvlist_add_string(*csp, "dimm2-csname", csname);
		}
	}

	/* Add cslist nvlist array even if zero members */
	(void) nvlist_add_nvlist_array(mcnvl, "cslist", cslist, nelem);
	for (i = 0; i < nelem; i++)
		nvlist_free(cslist[i]);
}

static void
mc_nvl_add_dimmlist(nvlist_t *mcnvl, mc_t *mc)
{
	nvlist_t *dimmlist[MC_CHIP_NDIMM];
	mc_dimm_t *mcd;
	int nelem, i;

	for (nelem = 0, mcd = mc->mc_dimmlist; mcd != NULL;
	    mcd = mcd->mcd_next, nelem++) {
		nvlist_t **dimmp = &dimmlist[nelem];
		uint64_t csnums[MC_CHIP_DIMMRANKMAX];
		char csname[4][MCDCFG_CSNAMELEN];
		char *csnamep[4];
		int ncs = 0;

		(void) nvlist_alloc(dimmp, NV_UNIQUE_NAME, KM_SLEEP);

		mc_nvl_add_prop(*dimmp, mcd, MCAMD_PROP_NUM, 1);
		mc_nvl_add_prop(*dimmp, mcd, MCAMD_PROP_SIZE, 1);

		for (i = 0; i < MC_CHIP_DIMMRANKMAX; i++) {
			if (mcd->mcd_cs[i] != NULL) {
				csnums[ncs] =
				    mcd->mcd_cs[i]->mccs_props.csp_num;
				mcdcfg_csname(mc->mc_socket, mcd->mcd_csl[i],
				    csname[ncs], MCDCFG_CSNAMELEN);
				csnamep[ncs] = csname[ncs];
				ncs++;
			}
		}

		(void) nvlist_add_uint64_array(*dimmp, "csnums", csnums, ncs);
		(void) nvlist_add_string_array(*dimmp, "csnames", csnamep, ncs);
	}

	/* Add dimmlist nvlist array even if zero members */
	(void) nvlist_add_nvlist_array(mcnvl, "dimmlist", dimmlist, nelem);
	for (i = 0; i < nelem; i++)
		nvlist_free(dimmlist[i]);
}

static void
mc_nvl_add_htconfig(nvlist_t *mcnvl, mc_t *mc)
{
	mc_cfgregs_t *mcr = &mc->mc_cfgregs;
	union mcreg_htroute *htrp = (union mcreg_htroute *)&mcr->mcr_htroute[0];
	union mcreg_nodeid *nip = (union mcreg_nodeid *)&mcr->mcr_htnodeid;
	union mcreg_unitid *uip = (union mcreg_unitid *)&mcr->mcr_htunitid;
	int ndcnt = HT_COHERENTNODES(nip);
	uint32_t BCRte[MC_CHIP_MAXNODES];
	uint32_t RPRte[MC_CHIP_MAXNODES];
	uint32_t RQRte[MC_CHIP_MAXNODES];
	nvlist_t *nvl;
	int i;

	(void) nvlist_alloc(&nvl, NV_UNIQUE_NAME, KM_SLEEP);

	(void) nvlist_add_uint32(nvl, "NodeId", MCREG_FIELD_CMN(nip, NodeId));
	(void) nvlist_add_uint32(nvl, "CoherentNodes", HT_COHERENTNODES(nip));
	(void) nvlist_add_uint32(nvl, "SbNode", MCREG_FIELD_CMN(nip, SbNode));
	(void) nvlist_add_uint32(nvl, "LkNode", MCREG_FIELD_CMN(nip, LkNode));
	(void) nvlist_add_uint32(nvl, "SystemCoreCount",
	    HT_SYSTEMCORECOUNT(nip));

	(void) nvlist_add_uint32(nvl, "C0Unit", MCREG_FIELD_CMN(uip, C0Unit));
	(void) nvlist_add_uint32(nvl, "C1Unit", MCREG_FIELD_CMN(uip, C1Unit));
	(void) nvlist_add_uint32(nvl, "McUnit", MCREG_FIELD_CMN(uip, McUnit));
	(void) nvlist_add_uint32(nvl, "HbUnit", MCREG_FIELD_CMN(uip, HbUnit));
	(void) nvlist_add_uint32(nvl, "SbLink", MCREG_FIELD_CMN(uip, SbLink));

	if (ndcnt <= MC_CHIP_MAXNODES) {
		for (i = 0; i < ndcnt; i++, htrp++) {
			BCRte[i] = MCREG_FIELD_CMN(htrp, BCRte);
			RPRte[i] = MCREG_FIELD_CMN(htrp, RPRte);
			RQRte[i] = MCREG_FIELD_CMN(htrp, RQRte);
		}

		(void) nvlist_add_uint32_array(nvl, "BroadcastRoutes",
		    &BCRte[0], ndcnt);
		(void) nvlist_add_uint32_array(nvl, "ResponseRoutes",
		    &RPRte[0], ndcnt);
		(void) nvlist_add_uint32_array(nvl, "RequestRoutes",
		    &RQRte[0], ndcnt);
	}

	(void) nvlist_add_nvlist(mcnvl, "htconfig", nvl);
	nvlist_free(nvl);
}

static nvlist_t *
mc_nvl_create(mc_t *mc)
{
	nvlist_t *mcnvl;

	(void) nvlist_alloc(&mcnvl, NV_UNIQUE_NAME, KM_SLEEP);

	/*
	 * Since this nvlist is used in populating the topo tree changes
	 * made here may propogate through to changed property names etc
	 * in the topo tree.  Some properties in the topo tree will be
	 * contracted via ARC, so be careful what you change here.
	 */
	(void) nvlist_add_uint8(mcnvl, MC_NVLIST_VERSTR, MC_NVLIST_VERS1);

	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_NUM, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_REV, 0);
	(void) nvlist_add_string(mcnvl, "revname", mc->mc_revname);
	mc_nvl_add_socket(mcnvl, mc);
	mc_nvl_add_ecctype(mcnvl, mc);

	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_BASE_ADDR, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_LIM_ADDR, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_ILEN, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_ILSEL, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_CSINTLVFCTR, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_DRAMHOLE_SIZE, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_ACCESS_WIDTH, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_CSBANKMAPREG, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_BANKSWZL, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_MOD64MUX, 0);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_SPARECS, 1);
	mc_nvl_add_prop(mcnvl, mc, MCAMD_PROP_BADCS, 1);

	mc_nvl_add_cslist(mcnvl, mc);
	mc_nvl_add_dimmlist(mcnvl, mc);
	mc_nvl_add_htconfig(mcnvl, mc);

	return (mcnvl);
}

/*
 * Link a dimm to its associated chip-selects and chip-select lines.
 * Total the size of all ranks of this dimm.
 */
static void
mc_dimm_csadd(mc_t *mc, mc_dimm_t *mcd, mc_cs_t *mccs, const mcdcfg_csl_t *csl)
{
	int factor = (mc->mc_props.mcp_accwidth == 128) ? 2 : 1;
	uint64_t sz = 0;
	int i;

	/* Skip to first unused rank slot */
	for (i = 0; i < MC_CHIP_DIMMRANKMAX; i++) {
		if (mcd->mcd_cs[i] == NULL) {
			mcd->mcd_cs[i] = mccs;
			mcd->mcd_csl[i] = csl;
			sz += mccs->mccs_props.csp_size / factor;
			break;
		} else {
			sz += mcd->mcd_cs[i]->mccs_props.csp_size / factor;
		}
	}

	ASSERT(i != MC_CHIP_DIMMRANKMAX);

	mcd->mcd_size = sz;
}

/*
 * Create a dimm structure and call to link it to its associated chip-selects.
 */
static mc_dimm_t *
mc_dimm_create(mc_t *mc, uint_t num)
{
	mc_dimm_t *mcd = kmem_zalloc(sizeof (mc_dimm_t), KM_SLEEP);

	mcd->mcd_hdr.mch_type = MC_NT_DIMM;
	mcd->mcd_mc = mc;
	mcd->mcd_num = num;

	return (mcd);
}

/*
 * The chip-select structure includes an array of dimms associated with
 * that chip-select.  This function fills that array, and also builds
 * the list of all dimms on this memory controller mc_dimmlist.  The
 * caller has filled a structure with all there is to know about the
 * associated dimm(s).
 */
static void
mc_csdimms_create(mc_t *mc, mc_cs_t *mccs, mcdcfg_rslt_t *rsltp)
{
	mc_dimm_t *found[MC_CHIP_DIMMPERCS];
	mc_dimm_t *mcd;
	int nfound = 0;
	int i;

	/*
	 * Has some other chip-select already created this dimm or dimms?
	 * If so then link to the dimm(s) from the mccs_dimm array,
	 * record their topo numbers in the csp_dimmnums array, and link
	 * the dimm(s) to the additional chip-select.
	 */
	for (mcd = mc->mc_dimmlist; mcd != NULL; mcd = mcd->mcd_next) {
		for (i = 0; i < rsltp->ndimm; i++) {
			if (mcd->mcd_num == rsltp->dimm[i].toponum)
				found[nfound++] = mcd;
		}
	}
	ASSERT(nfound == 0 || nfound == rsltp->ndimm);

	for (i = 0; i < rsltp->ndimm; i++) {
		if (nfound == 0) {
			mcd = mc_dimm_create(mc, rsltp->dimm[i].toponum);
			if (mc->mc_dimmlist == NULL)
				mc->mc_dimmlist = mcd;
			else
				mc->mc_dimmlast->mcd_next = mcd;
			mc->mc_dimmlast = mcd;
		} else {
			mcd = found[i];
		}

		mccs->mccs_dimm[i] = mcd;
		mccs->mccs_csl[i] = rsltp->dimm[i].cslp;
		mccs->mccs_props.csp_dimmnums[i] = mcd->mcd_num;
		mc_dimm_csadd(mc, mcd, mccs, rsltp->dimm[i].cslp);

	}

	/* The rank number is constant across all constituent dimm(s) */
	mccs->mccs_props.csp_dimmrank = rsltp->dimm[0].cslp->csl_rank;
}

/*
 * mc_dimmlist_create is called after we have discovered all enabled
 * (and spare or testfailed on revs F and G) chip-selects on the
 * given memory controller.  For each chip-select we must derive
 * the associated dimms, remembering that a chip-select csbase/csmask
 * pair may be associated with up to 2 chip-select lines (in 128 bit mode)
 * and that any one dimm may be associated with 1, 2, or 4 chip-selects
 * depending on whether it is single, dual or quadrank.
 */
static void
mc_dimmlist_create(mc_t *mc)
{
	union mcreg_dramcfg_hi *drcfghip =
	    (union mcreg_dramcfg_hi *)(&mc->mc_cfgregs.mcr_dramcfghi);
	mc_props_t *mcp = &mc->mc_props;
	uint32_t rev = mcp->mcp_rev;
	mc_cs_t *mccs;
	int r4 = 0, s4 = 0;

	/*
	 * Are we dealing with quadrank registered dimms?
	 *
	 * For socket 940 we can't tell and we'll assume we're not.
	 * This can be over-ridden by the admin in /etc/system by setting
	 * mc_quadranksupport nonzero.  A possible optimisation in systems
	 * that export an SMBIOS table would be to count the number of
	 * dimm slots per cpu - more than 4 would indicate no quadrank support
	 * and 4 or fewer would indicate that if we see any of the upper
	 * chip-selects enabled then a quadrank dimm is present.
	 *
	 * For socket F(1207) we can check a bit in the dram config high reg.
	 *
	 * Other socket types do not support registered dimms.
	 */
	if (mc->mc_socket == X86_SOCKET_940)
		r4 = mc_quadranksupport != 0;
	else if (mc->mc_socket == X86_SOCKET_F1207)
		r4 = MCREG_FIELD_F_revFG(drcfghip, FourRankRDimm);

	/*
	 * Are we dealing with quadrank SO-DIMMs?  These are supported
	 * in AM2 and S1g1 packages only, but in all rev F/G cases we
	 * can detect their presence via a bit in the dram config high reg.
	 */
	if (MC_REV_MATCH(rev, MC_F_REVS_FG))
		s4 = MCREG_FIELD_F_revFG(drcfghip, FourRankSODimm);

	for (mccs = mc->mc_cslist; mccs != NULL; mccs = mccs->mccs_next) {
		mcdcfg_rslt_t rslt;

		/*
		 * If lookup fails we will not create dimm structures for
		 * this chip-select.  In the mc_cs_t we will have both
		 * csp_dimmnum members set to MC_INVALNUM and patounum
		 * code will see from those that we do not have dimm info
		 * for this chip-select.
		 */
		if (mcdcfg_lookup(rev, mcp->mcp_mod64mux, mcp->mcp_accwidth,
		    mccs->mccs_props.csp_num, mc->mc_socket,
		    r4, s4, &rslt) < 0)
			continue;

		mc_csdimms_create(mc, mccs, &rslt);
	}
}

static mc_cs_t *
mc_cs_create(mc_t *mc, uint_t num, uint64_t base, uint64_t mask, size_t sz,
    int csbe, int spare, int testfail)
{
	mc_cs_t *mccs = kmem_zalloc(sizeof (mc_cs_t), KM_SLEEP);
	mccs_props_t *csp = &mccs->mccs_props;
	int i;

	mccs->mccs_hdr.mch_type = MC_NT_CS;
	mccs->mccs_mc = mc;
	csp->csp_num = num;
	csp->csp_base = base;
	csp->csp_mask = mask;
	csp->csp_size = sz;
	csp->csp_csbe = csbe;
	csp->csp_spare = spare;
	csp->csp_testfail = testfail;

	for (i = 0; i < MC_CHIP_DIMMPERCS; i++)
		csp->csp_dimmnums[i] = MC_INVALNUM;

	if (spare)
		mc->mc_props.mcp_sparecs = num;

	return (mccs);
}

/*
 * For any cs# of this mc marked TestFail generate an ereport with
 * resource identifying the associated dimm(s).
 */
static void
mc_report_testfails(mc_t *mc)
{
	mc_unum_t unum;
	mc_cs_t *mccs;
	int i;

	for (mccs = mc->mc_cslist; mccs != NULL; mccs = mccs->mccs_next) {
		if (mccs->mccs_props.csp_testfail) {
			unum.unum_board = 0;
			unum.unum_chip = mc->mc_props.mcp_num;
			unum.unum_mc = 0;
			unum.unum_chan = MC_INVALNUM;
			unum.unum_cs = mccs->mccs_props.csp_num;
			unum.unum_rank = mccs->mccs_props.csp_dimmrank;
			unum.unum_offset = MCAMD_RC_INVALID_OFFSET;
			for (i = 0; i < MC_CHIP_DIMMPERCS; i++)
				unum.unum_dimms[i] = MC_INVALNUM;

			mcamd_ereport_post(mc, FM_EREPORT_CPU_AMD_MC_TESTFAIL,
			    &unum,
			    FM_EREPORT_PAYLOAD_FLAGS_CPU_AMD_MC_TESTFAIL);
		}
	}
}

/*
 * Function 0 - HyperTransport Technology Configuration
 */
static void
mc_mkprops_htcfg(mc_pcicfg_hdl_t cfghdl, mc_t *mc)
{
	union mcreg_nodeid nodeid;
	off_t offset;
	int i;

	mc->mc_cfgregs.mcr_htnodeid = MCREG_VAL32(&nodeid) =
	    mc_pcicfg_get32(cfghdl, MC_HT_REG_NODEID);

	mc->mc_cfgregs.mcr_htunitid = mc_pcicfg_get32(cfghdl, MC_HT_REG_UNITID);

	for (i = 0, offset = MC_HT_REG_RTBL_NODE_0;
	    i < HT_COHERENTNODES(&nodeid);
	    i++, offset += MC_HT_REG_RTBL_INCR)
		mc->mc_cfgregs.mcr_htroute[i] = mc_pcicfg_get32(cfghdl, offset);
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
mc_mkprops_addrmap(mc_pcicfg_hdl_t cfghdl, mc_t *mc)
{
	union mcreg_drambase basereg;
	union mcreg_dramlimit limreg;
	mc_props_t *mcp = &mc->mc_props;
	mc_cfgregs_t *mcr = &mc->mc_cfgregs;
	union mcreg_dramhole hole;
	int nodeid = mc->mc_props.mcp_num;

	mcr->mcr_drambase = MCREG_VAL32(&basereg) = mc_pcicfg_get32(cfghdl,
	    MC_AM_REG_DRAMBASE_0 + nodeid * MC_AM_REG_DRAM_INCR);

	mcr->mcr_dramlimit = MCREG_VAL32(&limreg) = mc_pcicfg_get32(cfghdl,
	    MC_AM_REG_DRAMLIM_0 + nodeid * MC_AM_REG_DRAM_INCR);

	/*
	 * Derive some "cooked" properties for nodes that have a range of
	 * physical addresses that are read or write enabled and for which
	 * the DstNode matches the node we are attaching.
	 */
	if (MCREG_FIELD_CMN(&limreg, DRAMLimiti) != 0 &&
	    MCREG_FIELD_CMN(&limreg, DstNode) == nodeid &&
	    (MCREG_FIELD_CMN(&basereg, WE) || MCREG_FIELD_CMN(&basereg, RE))) {
		mcp->mcp_base = MC_DRAMBASE(&basereg);
		mcp->mcp_lim = MC_DRAMLIM(&limreg);
		mcp->mcp_ilen = MCREG_FIELD_CMN(&basereg, IntlvEn);
		mcp->mcp_ilsel = MCREG_FIELD_CMN(&limreg, IntlvSel);
	}

	/*
	 * The Function 1 DRAM Hole Address Register tells us which node(s)
	 * own the DRAM space that is hoisted above 4GB, together with the
	 * hole base and offset for this node.  This was introduced in
	 * revision E.
	 */
	if (MC_REV_ATLEAST(mc->mc_props.mcp_rev, MC_F_REV_E)) {
		mcr->mcr_dramhole = MCREG_VAL32(&hole) =
		    mc_pcicfg_get32(cfghdl, MC_AM_REG_HOLEADDR);

		if (MCREG_FIELD_CMN(&hole, DramHoleValid))
			mcp->mcp_dramhole_size = MC_DRAMHOLE_SIZE(&hole);
	}
}

/*
 * Read some function 3 parameters via PCI Mechanism 1 accesses (which
 * will serialize any NB accesses).
 */
static void
mc_getmiscctl(mc_t *mc)
{
	uint32_t rev = mc->mc_props.mcp_rev;
	union mcreg_nbcfg nbcfg;
	union mcreg_sparectl sparectl;

	mc->mc_cfgregs.mcr_nbcfg = MCREG_VAL32(&nbcfg) =
	    mc_pcicfg_get32_nohdl(mc, MC_FUNC_MISCCTL, MC_CTL_REG_NBCFG);

	if (MC_REV_MATCH(rev, MC_F_REVS_FG)) {
		mc->mc_cfgregs.mcr_sparectl = MCREG_VAL32(&sparectl) =
		    mc_pcicfg_get32_nohdl(mc, MC_FUNC_MISCCTL,
		    MC_CTL_REG_SPARECTL);

		if (MCREG_FIELD_F_revFG(&sparectl, SwapDone)) {
			mc->mc_props.mcp_badcs =
			    MCREG_FIELD_F_revFG(&sparectl, BadDramCs);
		}
	}
}

static int
csbasecmp(mc_cs_t **csapp, mc_cs_t **csbpp)
{
	uint64_t basea = (*csapp)->mccs_props.csp_base;
	uint64_t baseb = (*csbpp)->mccs_props.csp_base;

	if (basea == baseb)
		return (0);
	else if (basea < baseb)
		return (-1);
	else
		return (1);
}

/*
 * The following are for use in simulating TestFail for a chip-select
 * without poking at the hardware (which tends to get upset if you do
 * since the BIOS needs to restart to map a failed cs out).  For internal
 * testing only!  Note that setting these does not give the full experience -
 * the select chip-select *is* enabled and can give errors etc and the
 * patounum logic will get confused.
 */
int testfail_mcnum = -1;
int testfail_csnum = -1;

/*
 * Function 2 configuration - DRAM Controller
 */
static void
mc_mkprops_dramctl(mc_pcicfg_hdl_t cfghdl, mc_t *mc)
{
	union mcreg_csbase base[MC_CHIP_NCS];
	union mcreg_csmask mask[MC_CHIP_NCS];
	union mcreg_dramcfg_lo drcfg_lo;
	union mcreg_dramcfg_hi drcfg_hi;
	union mcreg_drammisc drmisc;
	union mcreg_bankaddrmap baddrmap;
	mc_props_t *mcp = &mc->mc_props;
	mc_cfgregs_t *mcr = &mc->mc_cfgregs;
	int maskdivisor;
	int wide = 0;
	uint32_t rev = mc->mc_props.mcp_rev;
	int i;
	mcamd_hdl_t hdl;

	mcamd_mkhdl(&hdl);	/* to call into common code */

	/*
	 * Read Function 2 DRAM Configuration High and Low registers.  The High
	 * part is mostly concerned with memory clocks etc and we'll not have
	 * any use for that.  The Low component tells us if ECC is enabled,
	 * if we're in 64- or 128-bit MC mode, how the upper chip-selects
	 * are mapped, which chip-select pairs are using x4 parts, etc.
	 */
	MCREG_VAL32(&drcfg_lo) = mc_pcicfg_get32(cfghdl, MC_DC_REG_DRAMCFGLO);
	MCREG_VAL32(&drcfg_hi) = mc_pcicfg_get32(cfghdl, MC_DC_REG_DRAMCFGHI);
	mcr->mcr_dramcfglo = MCREG_VAL32(&drcfg_lo);
	mcr->mcr_dramcfghi = MCREG_VAL32(&drcfg_hi);

	/*
	 * Note the DRAM controller width.  The 64/128 bit is in a different
	 * bit position for revision F and G.
	 */
	if (MC_REV_MATCH(rev, MC_F_REVS_FG)) {
		wide = MCREG_FIELD_F_revFG(&drcfg_lo, Width128);
	} else {
		wide = MCREG_FIELD_F_preF(&drcfg_lo, Width128);
	}
	mcp->mcp_accwidth = wide ? 128 : 64;

	/*
	 * Read Function 2 DRAM Controller Miscellaenous Regsiter for those
	 * revs that support it.  This include the Mod64Mux indication on
	 * these revs - for rev E it is in DRAM config low.
	 */
	if (MC_REV_MATCH(rev, MC_F_REVS_FG)) {
		mcr->mcr_drammisc = MCREG_VAL32(&drmisc) =
		    mc_pcicfg_get32(cfghdl, MC_DC_REG_DRAMMISC);
		mcp->mcp_mod64mux = MCREG_FIELD_F_revFG(&drmisc, Mod64Mux);
	} else if (MC_REV_MATCH(rev, MC_F_REV_E)) {
		mcp->mcp_mod64mux = MCREG_FIELD_F_preF(&drcfg_lo, Mod64BitMux);
	}

	/*
	 * Read Function 2 DRAM Bank Address Mapping.  This encodes the
	 * type of DIMM module in use for each chip-select pair.
	 * Prior ro revision F it also tells us whether BankSwizzle mode
	 * is enabled - in rev F that has moved to dram config hi register.
	 */
	mcp->mcp_csbankmapreg = MCREG_VAL32(&baddrmap) =
	    mc_pcicfg_get32(cfghdl, MC_DC_REG_BANKADDRMAP);

	/*
	 * Determine whether bank swizzle mode is active.  Bank swizzling was
	 * introduced as an option in rev E,  but the bit that indicates it
	 * is enabled has moved in revs F/G.
	 */
	if (MC_REV_MATCH(rev, MC_F_REV_E)) {
		mcp->mcp_bnkswzl =
		    MCREG_FIELD_F_preF(&baddrmap, BankSwizzleMode);
	} else if (MC_REV_MATCH(rev, MC_F_REVS_FG)) {
		mcp->mcp_bnkswzl = MCREG_FIELD_F_revFG(&drcfg_hi,
		    BankSwizzleMode);
	}

	/*
	 * Read the DRAM CS Base and DRAM CS Mask registers.  Revisions prior
	 * to F have an equal number of base and mask registers; revision F
	 * has twice as many base registers as masks.
	 */
	maskdivisor = MC_REV_MATCH(rev, MC_F_REVS_FG) ? 2 : 1;

	mc_prop_read_pair(cfghdl,
	    (uint32_t *)base, MC_DC_REG_CSBASE_0, MC_CHIP_NCS,
	    (uint32_t *)mask, MC_DC_REG_CSMASK_0, MC_CHIP_NCS / maskdivisor,
	    MC_DC_REG_CS_INCR);

	/*
	 * Create a cs node for each enabled chip-select as well as
	 * any appointed online spare chip-selects and for any that have
	 * failed test.
	 */
	for (i = 0; i < MC_CHIP_NCS; i++) {
		mc_cs_t *mccs;
		uint64_t csbase, csmask;
		size_t sz;
		int csbe, spare, testfail;

		if (MC_REV_MATCH(rev, MC_F_REVS_FG)) {
			csbe = MCREG_FIELD_F_revFG(&base[i], CSEnable);
			spare = MCREG_FIELD_F_revFG(&base[i], Spare);
			testfail = MCREG_FIELD_F_revFG(&base[i], TestFail);
		} else {
			csbe = MCREG_FIELD_F_preF(&base[i], CSEnable);
			spare = 0;
			testfail = 0;
		}

		/* Testing hook */
		if (testfail_mcnum != -1 && testfail_csnum != -1 &&
		    mcp->mcp_num == testfail_mcnum && i == testfail_csnum) {
			csbe = spare = 0;
			testfail = 1;
			cmn_err(CE_NOTE, "Pretending MC %d CS %d failed test",
			    testfail_mcnum, testfail_csnum);
		}

		/*
		 * If the chip-select is not enabled then skip it unless
		 * it is a designated online spare or is marked with TestFail.
		 */
		if (!csbe && !(spare || testfail))
			continue;

		/*
		 * For an enabled or spare chip-select the Bank Address Mapping
		 * register will be valid as will the chip-select mask.  The
		 * base will not be valid but we'll read and store it anyway.
		 * We will not know whether the spare is already swapped in
		 * until MC function 3 attaches.
		 */
		if (csbe || spare) {
			if (mcamd_cs_size(&hdl, (mcamd_node_t *)mc, i, &sz) < 0)
				continue;
			csbase = MC_CSBASE(&base[i], rev);
			csmask = MC_CSMASK(&mask[i / maskdivisor], rev);
		} else {
			sz = 0;
			csbase = csmask = 0;
		}

		mccs = mc_cs_create(mc, i, csbase, csmask, sz,
		    csbe, spare, testfail);

		if (mc->mc_cslist == NULL)
			mc->mc_cslist = mccs;
		else
			mc->mc_cslast->mccs_next = mccs;
		mc->mc_cslast = mccs;

		mccs->mccs_cfgregs.csr_csbase = MCREG_VAL32(&base[i]);
		mccs->mccs_cfgregs.csr_csmask =
		    MCREG_VAL32(&mask[i / maskdivisor]);

		/*
		 * Check for cs bank interleaving - some bits clear in the
		 * lower mask.  All banks must/will have the same lomask bits
		 * if cs interleaving is active.
		 */
		if (csbe && !mcp->mcp_csintlvfctr) {
			int bitno, ibits = 0;
			for (bitno = MC_CSMASKLO_LOBIT(rev);
			    bitno <= MC_CSMASKLO_HIBIT(rev); bitno++) {
				if (!(csmask & (1 << bitno)))
					ibits++;
			}
			mcp->mcp_csintlvfctr = 1 << ibits;
		}
	}

	/*
	 * If there is no chip-select interleave on this node determine
	 * whether the chip-select ranks are contiguous or if there
	 * is a hole.
	 */
	if (mcp->mcp_csintlvfctr == 1) {
		mc_cs_t *csp[MC_CHIP_NCS];
		mc_cs_t *mccs;
		int ncsbe = 0;

		for (mccs = mc->mc_cslist; mccs != NULL;
		    mccs = mccs->mccs_next) {
			if (mccs->mccs_props.csp_csbe)
				csp[ncsbe++] = mccs;
		}

		if (ncsbe != 0) {
			qsort((void *)csp, ncsbe, sizeof (mc_cs_t *),
			    (int (*)(const void *, const void *))csbasecmp);

			for (i = 1; i < ncsbe; i++) {
				if (csp[i]->mccs_props.csp_base !=
				    csp[i - 1]->mccs_props.csp_base +
				    csp[i - 1]->mccs_props.csp_size)
					mc->mc_csdiscontig = 1;
			}
		}
	}


	/*
	 * Since we do not attach to MC function 3 go ahead and read some
	 * config parameters from it now.
	 */
	mc_getmiscctl(mc);

	/*
	 * Now that we have discovered all enabled/spare/testfail chip-selects
	 * we divine the associated DIMM configuration.
	 */
	mc_dimmlist_create(mc);
}

typedef struct mc_bind_map {
	const char *bm_bindnm;	 /* attachment binding name */
	enum mc_funcnum bm_func; /* PCI config space function number for bind */
	const char *bm_model;	 /* value for device node model property */
	void (*bm_mkprops)(mc_pcicfg_hdl_t, mc_t *);
} mc_bind_map_t;

/*
 * Do not attach to MC function 3 - agpgart already attaches to that.
 * Function 3 may be a good candidate for a nexus driver to fan it out
 * into virtual devices by functionality.  We will use pci_mech1_getl
 * to retrieve the function 3 parameters we require.
 */

static const mc_bind_map_t mc_bind_map[] = {
	{ MC_FUNC_HTCONFIG_BINDNM, MC_FUNC_HTCONFIG,
	    "AMD Memory Controller (HT Configuration)", mc_mkprops_htcfg },
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

/*
 * Enable swap from chip-select csnum to the spare chip-select on this
 * memory controller (if any).
 */

int mc_swapdonetime = 30;	/* max number of seconds to wait for SwapDone */

static int
mc_onlinespare(mc_t *mc, int csnum)
{
	mc_props_t *mcp = &mc->mc_props;
	union mcreg_sparectl sparectl;
	union mcreg_scrubctl scrubctl;
	mc_cs_t *mccs;
	hrtime_t tmax;
	int i = 0;

	ASSERT(RW_WRITE_HELD(&mc_lock));

	if (!MC_REV_MATCH(mcp->mcp_rev, MC_F_REVS_FG))
		return (ENOTSUP);	/* MC rev does not offer online spare */
	else if (mcp->mcp_sparecs == MC_INVALNUM)
		return (ENODEV);	/* Supported, but no spare configured */
	else if (mcp->mcp_badcs != MC_INVALNUM)
		return (EBUSY);		/* Spare already swapped in */
	else if (csnum == mcp->mcp_sparecs)
		return (EINVAL);	/* Can't spare the spare! */

	for (mccs = mc->mc_cslist; mccs != NULL; mccs = mccs->mccs_next) {
		if (mccs->mccs_props.csp_num == csnum)
			break;
	}
	if (mccs == NULL)
		return (EINVAL);	/* nominated bad CS does not exist */

	/*
	 * If the DRAM Scrubber is not enabled then the swap cannot succeed.
	 */
	MCREG_VAL32(&scrubctl) = mc_pcicfg_get32_nohdl(mc, MC_FUNC_MISCCTL,
	    MC_CTL_REG_SCRUBCTL);
	if (MCREG_FIELD_CMN(&scrubctl, DramScrub) == 0)
		return (ENODEV);	/* DRAM scrubber not enabled */

	/*
	 * Read Online Spare Comtrol Register again, just in case our
	 * state does not reflect reality.
	 */
	MCREG_VAL32(&sparectl) = mc_pcicfg_get32_nohdl(mc, MC_FUNC_MISCCTL,
	    MC_CTL_REG_SPARECTL);

	if (MCREG_FIELD_F_revFG(&sparectl, SwapDone))
		return (EBUSY);

	/* Write to the BadDramCs field */
	MCREG_FIELD_F_revFG(&sparectl, BadDramCs) = csnum;
	mc_pcicfg_put32_nohdl(mc, MC_FUNC_MISCCTL, MC_CTL_REG_SPARECTL,
	    MCREG_VAL32(&sparectl));

	/* And request that the swap to the spare start */
	MCREG_FIELD_F_revFG(&sparectl, SwapEn) = 1;
	mc_pcicfg_put32_nohdl(mc, MC_FUNC_MISCCTL, MC_CTL_REG_SPARECTL,
	    MCREG_VAL32(&sparectl));

	/*
	 * Poll for SwapDone - we have disabled notification by interrupt.
	 * Swap takes "several CPU cycles, depending on the DRAM speed, but
	 * is performed in the background" (Family 0Fh Bios Porting Guide).
	 * We're in a slow ioctl path so there is no harm in waiting around
	 * a bit - consumers of the ioctl must be aware that it may take
	 * a moment.  We will poll for up to mc_swapdonetime seconds,
	 * limiting that to 120s.
	 *
	 * The swap is performed by the DRAM scrubber (which must be enabled)
	 * whose scrub rate is accelerated for the duration of the swap.
	 * The maximum swap rate is 40.0ns per 64 bytes, so the maximum
	 * supported cs size of 16GB would take 10.7s at that max rate
	 * of 25000000 scrubs/second.
	 */
	tmax = gethrtime() + MIN(mc_swapdonetime, 120) * 1000000000ULL;
	do {
		if (i++ < 20)
			delay(drv_usectohz(100000));	/* 0.1s for up to 2s */
		else
			delay(drv_usectohz(500000));	/* 0.5s */

		MCREG_VAL32(&sparectl) = mc_pcicfg_get32_nohdl(mc,
		    MC_FUNC_MISCCTL, MC_CTL_REG_SPARECTL);
	} while (!MCREG_FIELD_F_revFG(&sparectl, SwapDone) &&
	    gethrtime() < tmax);

	if (!MCREG_FIELD_F_revFG(&sparectl, SwapDone))
		return (ETIME);		/* Operation timed out */

	mcp->mcp_badcs = csnum;
	mc->mc_cfgregs.mcr_sparectl = MCREG_VAL32(&sparectl);
	mc->mc_spareswaptime = gethrtime();

	return (0);
}

/*ARGSUSED*/
static int
mc_ioctl(dev_t dev, int cmd, intptr_t arg, int mode, cred_t *credp, int *rvalp)
{
	int rc = 0;
	mc_t *mc;

	if (cmd != MC_IOC_SNAPSHOT_INFO && cmd != MC_IOC_SNAPSHOT &&
	    cmd != MC_IOC_ONLINESPARE_EN)
		return (EINVAL);

	rw_enter(&mc_lock, RW_READER);

	if ((mc = mc_lookup_by_chipid(getminor(dev))) == NULL) {
		rw_exit(&mc_lock);
		return (EINVAL);
	}

	switch (cmd) {
	case MC_IOC_SNAPSHOT_INFO: {
		mc_snapshot_info_t mcs;

		if (mc_snapshot_update(mc) < 0) {
			rw_exit(&mc_lock);
			return (EIO);
		}

		mcs.mcs_size = mc->mc_snapshotsz;
		mcs.mcs_gen = mc->mc_snapshotgen;

		if (ddi_copyout(&mcs, (void *)arg, sizeof (mc_snapshot_info_t),
		    mode) < 0)
			rc = EFAULT;
		break;
	}

	case MC_IOC_SNAPSHOT:
		if (mc_snapshot_update(mc) < 0) {
			rw_exit(&mc_lock);
			return (EIO);
		}

		if (ddi_copyout(mc->mc_snapshot, (void *)arg, mc->mc_snapshotsz,
		    mode) < 0)
			rc = EFAULT;
		break;

	case MC_IOC_ONLINESPARE_EN:
		if (drv_priv(credp) != 0) {
			rw_exit(&mc_lock);
			return (EPERM);
		}

		if (!rw_tryupgrade(&mc_lock)) {
			rw_exit(&mc_lock);
			return (EAGAIN);
		}

		if ((rc = mc_onlinespare(mc, (int)arg)) == 0) {
			mc_snapshot_destroy(mc);
			nvlist_free(mc->mc_nvl);
			mc->mc_nvl = mc_nvl_create(mc);
		}

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
	return (fmerr->fme_status);
}

static void
mc_fm_init(dev_info_t *dip)
{
	int fmcap = DDI_FM_EREPORT_CAPABLE | DDI_FM_ERRCB_CAPABLE;
	ddi_fm_init(dip, &fmcap, NULL);
	pci_ereport_setup(dip);
	ddi_fm_handler_register(dip, mc_fm_handle, NULL);
}

/*ARGSUSED*/
static int
mc_create_cb(cmi_hdl_t whdl, void *arg1, void *arg2, void *arg3)
{
	chipid_t chipid = *((chipid_t *)arg1);
	cmi_hdl_t *hdlp = (cmi_hdl_t *)arg2;

	if (cmi_hdl_chipid(whdl) == chipid) {
		cmi_hdl_hold(whdl);	/* short-term hold */
		*hdlp = whdl;
		return (CMI_HDL_WALK_DONE);
	} else {
		return (CMI_HDL_WALK_NEXT);
	}
}

static mc_t *
mc_create(chipid_t chipid)
{
	mc_t *mc;
	cmi_hdl_t hdl = NULL;

	ASSERT(RW_WRITE_HELD(&mc_lock));

	/*
	 * Find a handle for one of a chip's CPU.
	 *
	 * We can use one of the chip's CPUs since all cores
	 * of a chip share the same revision and socket type.
	 */
	cmi_hdl_walk(mc_create_cb, (void *)&chipid, (void *)&hdl, NULL);
	if (hdl == NULL)
		return (NULL);	/* no cpu for this chipid found! */

	mc = kmem_zalloc(sizeof (mc_t), KM_SLEEP);

	mc->mc_hdr.mch_type = MC_NT_MC;
	mc->mc_props.mcp_num = chipid;
	mc->mc_props.mcp_sparecs = MC_INVALNUM;
	mc->mc_props.mcp_badcs = MC_INVALNUM;

	mc->mc_props.mcp_rev = cmi_hdl_chiprev(hdl);
	mc->mc_revname = cmi_hdl_chiprevstr(hdl);
	mc->mc_socket = cmi_hdl_getsockettype(hdl);

	if (mc_list == NULL)
		mc_list = mc;
	if (mc_last != NULL)
		mc_last->mc_next = mc;

	mc->mc_next = NULL;
	mc_last = mc;

	cmi_hdl_rele(hdl);

	return (mc);
}

/*
 * Return the maximum scrubbing rate between r1 and r2, where r2 is extracted
 * from the specified 'cfg' register value using 'mask' and 'shift'.  If a
 * value is zero, scrubbing is off so return the opposite value.  Otherwise
 * the maximum rate is the smallest non-zero value of the two values.
 */
static uint32_t
mc_scrubber_max(uint32_t r1, uint32_t cfg, uint32_t mask, uint32_t shift)
{
	uint32_t r2 = (cfg & mask) >> shift;

	if (r1 != 0 && r2 != 0)
		return (MIN(r1, r2));

	return (r1 ? r1 : r2);
}


/*
 * Enable the memory scrubber.  We must use the mc_pcicfg_{get32,put32}_nohdl
 * interfaces since we do not bind to function 3.
 */
cmi_errno_t
mc_scrubber_enable(mc_t *mc)
{
	mc_props_t *mcp = &mc->mc_props;
	mc_cfgregs_t *mcr = &mc->mc_cfgregs;
	union mcreg_scrubctl scrubctl;
	union mcreg_dramscrublo dalo;
	union mcreg_dramscrubhi dahi;

	mcr->mcr_scrubctl = MCREG_VAL32(&scrubctl) =
	    mc_pcicfg_get32_nohdl(mc, MC_FUNC_MISCCTL, MC_CTL_REG_SCRUBCTL);

	mcr->mcr_scrubaddrlo = MCREG_VAL32(&dalo) =
	    mc_pcicfg_get32_nohdl(mc, MC_FUNC_MISCCTL, MC_CTL_REG_SCRUBADDR_LO);

	mcr->mcr_scrubaddrhi = MCREG_VAL32(&dahi) =
	    mc_pcicfg_get32_nohdl(mc, MC_FUNC_MISCCTL, MC_CTL_REG_SCRUBADDR_HI);

	if (mc_scrub_policy == MC_SCRUB_BIOSDEFAULT)
		return (MCREG_FIELD_CMN(&scrubctl, DramScrub) !=
		    AMD_NB_SCRUBCTL_RATE_NONE ?
		    CMI_SUCCESS : CMIERR_MC_NOMEMSCRUB);

	/*
	 * Disable DRAM scrubbing while we fiddle.
	 */
	MCREG_FIELD_CMN(&scrubctl, DramScrub) = AMD_NB_SCRUBCTL_RATE_NONE;
	mc_pcicfg_put32_nohdl(mc, MC_FUNC_MISCCTL, MC_CTL_REG_SCRUBCTL,
	    MCREG_VAL32(&scrubctl));

	/*
	 * Setup DRAM Scrub Address Low and High registers for the
	 * base address of this node, and to select srubber redirect.
	 */
	MCREG_FIELD_CMN(&dalo, ScrubReDirEn) = 1;
	MCREG_FIELD_CMN(&dalo, ScrubAddrLo) =
	    AMD_NB_SCRUBADDR_MKLO(mcp->mcp_base);

	MCREG_FIELD_CMN(&dahi, ScrubAddrHi) =
	    AMD_NB_SCRUBADDR_MKHI(mcp->mcp_base);

	mc_pcicfg_put32_nohdl(mc, MC_FUNC_MISCCTL, MC_CTL_REG_SCRUBADDR_LO,
	    MCREG_VAL32(&dalo));
	mc_pcicfg_put32_nohdl(mc, MC_FUNC_MISCCTL, MC_CTL_REG_SCRUBADDR_HI,
	    MCREG_VAL32(&dahi));

	if (mc_scrub_rate_dram > AMD_NB_SCRUBCTL_RATE_MAX) {
		cmn_err(CE_WARN, "mc_scrub_rate_dram is too large; "
		    "resetting to 0x%x\n", AMD_NB_SCRUBCTL_RATE_MAX);
		mc_scrub_rate_dram = AMD_NB_SCRUBCTL_RATE_MAX;
	}

	switch (mc_scrub_policy) {
	case MC_SCRUB_FIXED:
		/* Use the system value checked above */
		break;

	default:
		cmn_err(CE_WARN, "Unknown mc_scrub_policy value %d - "
		    "using default policy of MC_SCRUB_MAX", mc_scrub_policy);
		/*FALLTHRU*/

	case MC_SCRUB_MAX:
		mc_scrub_rate_dram = mc_scrubber_max(mc_scrub_rate_dram,
		    mcr->mcr_scrubctl, AMD_NB_SCRUBCTL_DRAM_MASK,
		    AMD_NB_SCRUBCTL_DRAM_SHIFT);
		break;
	}

#ifdef	OPTERON_ERRATUM_99
	/*
	 * This erratum applies on revisions D and earlier.
	 * This erratum also applies on revisions E and later,
	 * if BIOS uses chip-select hoisting instead of DRAM hole
	 * mapping.
	 *
	 * Do not enable the dram scrubber if the chip-select ranges
	 * for the node are not contiguous.
	 */
	if (mc_scrub_rate_dram != AMD_NB_SCRUBCTL_RATE_NONE &&
	    mc->mc_csdiscontig)
		cmn_err(CE_CONT, "?Opteron DRAM scrubber disabled on revision "
		    "%s chip %d because DRAM hole is present on this node",
		    mc->mc_revname, chipid);
		mc_scrub_rate_dram = AMD_NB_SCRUBCTL_RATE_NONE;
	}
#endif

#ifdef OPTERON_ERRATUM_101
	/*
	 * This erratum applies on revisions D and earlier.
	 *
	 * If the DRAM Base Address register's IntlvEn field indicates that
	 * node interleaving is enabled, we must disable the DRAM scrubber
	 * and return zero to indicate that Solaris should use s/w instead.
	 */
	if (mc_scrub_rate_dram != AMD_NB_SCRUBCTL_RATE_NONE &&
	    mcp->mcp_ilen != 0 &&
	    !X86_CHIPREV_ATLEAST(rev, X86_CHIPREV_AMD_F_REV_E)) {
		cmn_err(CE_CONT, "?Opteron DRAM scrubber disabled on revision "
		    "%s chip %d because DRAM memory is node-interleaved",
		    mc->mc_revname, chipid);
		mc_scrub_rate_dram = AMD_NB_SCRUBCTL_RATE_NONE;
	}
#endif

	if (mc_scrub_rate_dram != AMD_NB_SCRUBCTL_RATE_NONE) {
		MCREG_FIELD_CMN(&scrubctl, DramScrub) = mc_scrub_rate_dram;
		mc_pcicfg_put32_nohdl(mc, MC_FUNC_MISCCTL, MC_CTL_REG_SCRUBCTL,
		    MCREG_VAL32(&scrubctl));
	}

	return (mc_scrub_rate_dram != AMD_NB_SCRUBCTL_RATE_NONE ?
	    CMI_SUCCESS : CMIERR_MC_NOMEMSCRUB);
}

/*ARGSUSED*/
static int
mc_attach_cb(cmi_hdl_t whdl, void *arg1, void *arg2, void *arg3)
{
	mc_t *mc = (mc_t *)arg1;
	mcamd_prop_t chipid = *((mcamd_prop_t *)arg2);

	if (cmi_hdl_chipid(whdl) == chipid) {
		mcamd_mc_register(whdl, mc);
	}

	return (CMI_HDL_WALK_NEXT);
}

static int mc_sw_scrub_disabled = 0;

static int
mc_attach(dev_info_t *dip, ddi_attach_cmd_t cmd)
{
	mc_pcicfg_hdl_t cfghdl;
	const mc_bind_map_t *bm;
	const char *bindnm;
	char *unitstr = NULL;
	enum mc_funcnum func;
	long unitaddr;
	int chipid, rc;
	mc_t *mc;

	/*
	 * This driver has no hardware state, but does
	 * claim to have a reg property, so it will be
	 * called on suspend.  It is probably better to
	 * make sure it doesn't get called on suspend,
	 * but it is just as easy to make sure we just
	 * return DDI_SUCCESS if called.
	 */
	if (cmd == DDI_RESUME)
		return (DDI_SUCCESS);

	if (cmd != DDI_ATTACH || mc_no_attach != 0)
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

	if (rc != 0 || unitaddr < MC_AMD_DEV_OFFSET) {
		cmn_err(CE_WARN, "failed to parse unit address %s for %s\n",
		    unitstr, bindnm);
		ddi_prop_free(unitstr);
		return (DDI_FAILURE);
	}
	ddi_prop_free(unitstr);

	chipid = unitaddr - MC_AMD_DEV_OFFSET;

	rw_enter(&mc_lock, RW_WRITER);

	for (mc = mc_list; mc != NULL; mc = mc->mc_next) {
		if (mc->mc_props.mcp_num == chipid)
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

	/*
	 * Add the common properties to this node, and then add any properties
	 * that are specific to this node based upon its configuration space.
	 */
	(void) ddi_prop_update_string(DDI_DEV_T_NONE,
	    dip, "model", (char *)bm->bm_model);

	(void) ddi_prop_update_int(DDI_DEV_T_NONE,
	    dip, "chip-id", mc->mc_props.mcp_num);

	if (bm->bm_mkprops != NULL &&
	    mc_pcicfg_setup(mc, bm->bm_func, &cfghdl) == DDI_SUCCESS) {
		bm->bm_mkprops(cfghdl, mc);
		mc_pcicfg_teardown(cfghdl);
	}

	/*
	 * If this is the last node to be attached for this memory controller,
	 * then create the minor node, enable scrubbers, and register with
	 * cpu module(s) for this chip.
	 */
	if (func == MC_FUNC_DEVIMAP) {
		mc_props_t *mcp = &mc->mc_props;
		int dram_present = 0;

		if (ddi_create_minor_node(dip, "mc-amd", S_IFCHR,
		    mcp->mcp_num, "ddi_mem_ctrl",
		    0) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "failed to create minor node for chip "
			    "%d memory controller\n",
			    (chipid_t)mcp->mcp_num);
		}

		/*
		 * Register the memory controller for every CPU of this chip.
		 *
		 * If there is memory present on this node and ECC is enabled
		 * attempt to enable h/w memory scrubbers for this node.
		 * If we are successful in enabling *any* hardware scrubbers,
		 * disable the software memory scrubber.
		 */
		cmi_hdl_walk(mc_attach_cb, (void *)mc, (void *)&mcp->mcp_num,
		    NULL);

		if (mcp->mcp_lim != mcp->mcp_base) {
			/*
			 * This node may map non-dram memory alone, so we
			 * must check for an enabled chip-select to be
			 * sure there is dram present.
			 */
			mc_cs_t *mccs;

			for (mccs = mc->mc_cslist; mccs != NULL;
			    mccs = mccs->mccs_next) {
				if (mccs->mccs_props.csp_csbe) {
					dram_present = 1;
					break;
				}
			}
		}

		if (dram_present && !mc_ecc_enabled(mc)) {
			/*
			 * On a single chip system there is no point in
			 * scrubbing if there is no ECC on the single node.
			 * On a multichip system, necessarily Opteron using
			 * registered ECC-capable DIMMs, if there is memory
			 * present on a node but no ECC there then we'll assume
			 * ECC is disabled for all nodes and we will not enable
			 * the scrubber and wll also disable the software
			 * memscrub thread.
			 */
			rc = 1;
		} else if (!dram_present) {
			/* No memory on this node - others decide memscrub */
			rc = 0;
		} else {
			/*
			 * There is memory on this node and ECC is enabled.
			 * Call via the cpu module to enable memory scrubbing
			 * on this node - we could call directly but then
			 * we may overlap with a request to enable chip-cache
			 * scrubbing.
			 */
			rc = mc_scrubber_enable(mc);
		}

		if (rc == CMI_SUCCESS && !mc_sw_scrub_disabled++)
			cmi_mc_sw_memscrub_disable();

		mc_report_testfails(mc);
	}

	/*
	 * Update nvlist for as far as we have gotten in attach/init.
	 */
	nvlist_free(mc->mc_nvl);
	mc->mc_nvl = mc_nvl_create(mc);

	rw_exit(&mc_lock);
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
static int
mc_detach(dev_info_t *dip, ddi_detach_cmd_t cmd)
{
	/*
	 * See the comment about suspend in
	 * mc_attach().
	 */
	if (cmd == DDI_SUSPEND)
		return (DDI_SUCCESS);
	else
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
	NULL,			/* devo_power */
	ddi_quiesce_not_needed,		/* devo_quiesce */
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
	/*
	 * Refuse to load if there is no PCI config space support.
	 */
	if (pci_getl_func == NULL)
		return (ENOTSUP);

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
