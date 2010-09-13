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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Given a physical address and an optional syndrome, determine the
 * name of the memory module that contains it.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/mc.h>

#include <mcamd_api.h>
#include <mcamd_err.h>

#define	MC_SYSADDR_MSB	39
#define	MC_SYSADDR_LSB	3

#define	CSDIMM1	0x1
#define	CSDIMM2	0x2

#define	BITS(val, high, low) \
	((val) & (((2ULL << (high)) - 1) & ~((1ULL << (low)) - 1)))

/*
 * iaddr_gen generates a "normalized" DRAM controller input address
 * from a system address (physical address) if it falls within the
 * mapped range for this memory controller.  Normalisation is
 * performed by subtracting the node base address from the system address,
 * allowing from hoisting, and excising any bits being used in node
 * interleaving.
 */
static int
iaddr_gen(struct mcamd_hdl *hdl, mcamd_node_t *mc, uint64_t pa,
    uint64_t *iaddrp)
{
	uint64_t orig = pa;
	uint64_t mcnum, base, lim, dramaddr, ilen, ilsel, top, holesz;

	if (!mcamd_get_numprops(hdl,
	    mc, MCAMD_PROP_NUM, &mcnum,
	    mc, MCAMD_PROP_BASE_ADDR, &base,
	    mc, MCAMD_PROP_LIM_ADDR, &lim,
	    mc, MCAMD_PROP_ILEN, &ilen,
	    mc, MCAMD_PROP_ILSEL, &ilsel,
	    mc, MCAMD_PROP_DRAMHOLE_SIZE, &holesz,
	    NULL)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "iaddr_gen: failed to "
		    "lookup required properties");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	/*
	 * A node with no mapped memory (no active chip-selects is usually
	 * mapped with base and lim both zero.  We'll cover that case and
	 * any other where the range is 0.
	 */
	if (base == lim)
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));

	if (pa < base || pa > lim) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_gen: PA 0x%llx not "
		    "in range [0x%llx, 0x%llx] of MC %d\n", pa, base, lim,
		    (int)mcnum);
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
	}

	/*
	 * Rev E and later added the DRAM Hole Address Register for
	 * memory hoisting.  In earlier revisions memory hoisting is
	 * achieved by following some algorithm to modify the CS bases etc,
	 * and this pa to unum algorithm will simply see those modified
	 * values.  But if the Hole Address Register is being used then
	 * we need to reduce any address at or above 4GB by the size of
	 * the hole.
	 */
	if (holesz != 0 && pa >= 0x100000000) {
		pa -= holesz;
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_gen: dram hole "
		    "valid; pa decremented from 0x%llx to 0x%llx for "
		    "a dramhole size of 0x%llx\n", orig, pa, holesz);
	}

	dramaddr = BITS(pa, 39, 0) - BITS(base, 39, 24);

	if (ilen != 0) {
		int pailsel;

		if (ilen != 1 && ilen != 3 && ilen != 7) {
			mcamd_dprintf(hdl, MCAMD_DBG_ERR, "Invalid intlven "
			    "of %d for MC %d\n", (int)ilen, (int)mcnum);
			return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
		}

		if ((pailsel = BITS(pa, 14, 12) >> 12 & ilen) != ilsel) {
			mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_gen: "
			    "PA 0x%llx in a %d-way node interleave indicates "
			    "selection %d, MC %d has ilsel of %d\n",
			    pa, (int)ilen + 1, pailsel, (int)mcnum, (int)ilsel);
			return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
		}

		if (ilen == 1)
			top = BITS(dramaddr, 36, 13) >> 1;
		else if (ilen == 3)
			top = BITS(dramaddr, 37, 14) >> 2;
		else if (ilen == 7)
			top = BITS(dramaddr, 38, 15) >> 3;
	} else {
		top = BITS(dramaddr, 35, 12);
	}

	*iaddrp = top | BITS(dramaddr, 11, 0);

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_gen: PA 0x%llx in range "
	    "[0x%llx, 0x%llx] of MC %d; normalized address for cs compare "
	    "is 0x%llx\n", pa, base, lim, (int)mcnum, *iaddrp);

	return (0);
}

/*
 * cs_match determines whether the given DRAM controller input address
 * would be responded to by the given chip-select (which may or may not
 * be interleaved with other chip-selects).  Since we include nodes
 * for spare chip-selects (if any) and those marked TestFail (if any)
 * we must check chip-select-bank-enable.
 */
static int
cs_match(struct mcamd_hdl *hdl, uint64_t iaddr, mcamd_node_t *cs)
{
	uint64_t csnum, csbase, csmask, csbe;
	int match = 0;

	if (!mcamd_get_numprops(hdl,
	    cs, MCAMD_PROP_NUM, &csnum,
	    cs, MCAMD_PROP_BASE_ADDR, &csbase,
	    cs, MCAMD_PROP_MASK, &csmask,
	    cs, MCAMD_PROP_CSBE, &csbe,
	    NULL)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "cs_match: failed to lookup "
		    "required properties\n");
		return (0);
	}

	if (csbe) {
		match = ((iaddr & ~csmask) == (csbase & ~csmask));

		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "cs_match: iaddr 0x%llx "
		    "does %smatch CS %d (base 0x%llx, mask 0x%llx)\n", iaddr,
		    match ? "" : "not ", (int)csnum, csbase, csmask);
	} else {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "cs_match: iaddr 0x%llx "
		    "does not match disabled CS %d\n", iaddr, (int)csnum);
	}

	return (match);
}

/*
 * Given a chip-select node determine whether it has been substituted
 * by the online spare chip-select.
 */
static mcamd_node_t *
cs_sparedto(struct mcamd_hdl *hdl, mcamd_node_t *cs, mcamd_node_t *mc)
{
	uint64_t csnum, badcsnum, sparecsnum, tmpcsnum;

	if (!mcamd_get_numprops(hdl,
	    cs, MCAMD_PROP_NUM, &csnum,
	    mc, MCAMD_PROP_BADCS, &badcsnum,
	    mc, MCAMD_PROP_SPARECS, &sparecsnum,
	    NULL)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "cs_sparedto: failed to "
		    "lookup required properties\n");
		return (NULL);
	}

	if ((badcsnum == MC_INVALNUM && sparecsnum == MC_INVALNUM) ||
	    csnum != badcsnum)
		return (NULL);

	for (cs = mcamd_cs_next(hdl, mc, NULL); cs != NULL;
	    cs = mcamd_cs_next(hdl, mc, cs)) {
		if (!mcamd_get_numprop(hdl, cs, MCAMD_PROP_NUM, &tmpcsnum)) {
			mcamd_dprintf(hdl, MCAMD_DBG_ERR, "cs_sparedto: "
			    "fail to lookup csnum - cannot reroute to spare\n");
			return (NULL);
		}
		if (tmpcsnum == sparecsnum)
			break;
	}

	if (cs != NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "cs_sparedto: cs#%d is "
		    "redirected to active online spare of cs#%d\n", csnum,
		    sparecsnum);
	} else {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "cs_sparedto: cs#%d is "
		    "redirected but cannot find spare cs# - cannout reroute to "
		    "cs#%d\n", csnum, sparecsnum);
	}

	return (cs);
}

/*
 * Having determined which node and chip-select an address maps to,
 * as well as whether it is a dimm1, dimm2 or dimm1/dimm2 pair
 * involved, fill the unum structure including an optional dimm offset
 * member.
 */
static int
unum_fill(struct mcamd_hdl *hdl, mcamd_node_t *cs, int which,
    uint64_t iaddr, mc_unum_t *unump, int incloff)
{
	uint64_t chipnum, csnum, dimm1, dimm2, ranknum;
	mcamd_node_t *mc, *dimm;
	int offsetdimm;
	int i;

	if ((mc = mcamd_cs_mc(hdl, cs)) == NULL ||
	    !mcamd_get_numprops(hdl,
	    mc, MCAMD_PROP_NUM, &chipnum,
	    cs, MCAMD_PROP_NUM, &csnum,
	    cs, MCAMD_PROP_DIMMRANK, &ranknum,
	    NULL)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "unum_fill: failed to "
		    "lookup required properties\n");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	if ((which & CSDIMM1) &&
	    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_CSDIMM1, &dimm1) ||
	    (which & CSDIMM2) &&
	    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_CSDIMM2, &dimm2)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "unum_fill: failed to "
		    "lookup dimm1/dimm2 properties\n");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	unump->unum_board = 0;
	unump->unum_chip = (int)chipnum;
	unump->unum_mc = 0;
	unump->unum_chan = MC_INVALNUM;
	unump->unum_cs = (int)csnum;
	unump->unum_rank = (int)ranknum;

	for (i = 0; i < MC_UNUM_NDIMM; i++) {
		unump->unum_dimms[i] = MC_INVALNUM;
	}
	switch (which) {
	case CSDIMM1:
		unump->unum_dimms[0] = (int)dimm1;
		offsetdimm = (int)dimm1;
		break;
	case CSDIMM2:
		unump->unum_dimms[0] = (int)dimm2;
		offsetdimm = (int)dimm2;
		break;
	case CSDIMM1 | CSDIMM2:
		unump->unum_dimms[0] = (int)dimm1;
		unump->unum_dimms[1] = (int)dimm2;
		offsetdimm = (int)dimm1;
		break;
	}

	if (!incloff) {
		unump->unum_offset = MCAMD_RC_INVALID_OFFSET;
		return (0);
	}

	/*
	 * We wish to calculate a dimm offset.  In the paired case we will
	 * lookup dimm1 (see offsetdimm above).
	 */
	for (dimm = mcamd_dimm_next(hdl, mc, NULL); dimm != NULL;
	    dimm = mcamd_dimm_next(hdl, mc, dimm)) {
		uint64_t dnum;
		if (!mcamd_get_numprop(hdl, dimm, MCAMD_PROP_NUM, &dnum)) {
			mcamd_dprintf(hdl, MCAMD_DBG_ERR, "unum_fill: failed "
			    "to lookup dimm number property\n");
			continue;
		}
		if (dnum == offsetdimm)
			break;
	}

	if (dimm == NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "unum_fill: failed to "
		    "find dimm with number %d for offset calculation\n",
		    offsetdimm);
		unump->unum_offset = MCAMD_RC_INVALID_OFFSET;
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	/*
	 * mc_pa_to_offset sets the offset to an invalid value if
	 * it hits an error.
	 */
	(void) mc_pa_to_offset(hdl, mc, cs, iaddr, &unump->unum_offset);

	return (0);
}

/*
 * We have translated a system address to a (node, chip-select), and wish
 * to determine the associated dimm or dimms.
 *
 * A (node, chip-select) pair identifies one (in 64-bit MC mode) or two (in
 * 128-bit MC mode) DIMMs.  In the case of a single dimm it is usually in a
 * lodimm (channel A) slot, but if mismatched dimm support is present it may
 * be an updimm (channel B).
 *
 * Where just one dimm is associated with the chip-select we are done.
 * Where there are two dimms associated with the chip-select we can
 * use the ECC type and/or syndrome to determine which of the pair we
 * resolve to, if the error is correctable.  If the error is uncorrectable
 * then in 64/8 ECC mode we can still resolve to a single dimm (since ECC
 * is calculated and checked on each half of the data separately), but
 * in ChipKill mode we cannot resolve down to a single dimm.
 */
static int
mc_whichdimm(struct mcamd_hdl *hdl, mcamd_node_t *cs, uint64_t pa,
    uint8_t valid_lo, uint32_t synd, int syndtype)
{
	int lobit, hibit, data, check;
	uint64_t dimm1, dimm2;
	uint_t sym, pat;
	int ndimm;

	/*
	 * Read the associated dimm instance numbers.  The provider must
	 * assure that if there is just one dimm then it is in the first
	 * property, and if there are two then the first must be on
	 * channel A.
	 */
	if (!mcamd_get_numprops(hdl,
	    cs, MCAMD_PROP_CSDIMM1, &dimm1,
	    cs, MCAMD_PROP_CSDIMM2, &dimm2,
	    NULL)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mc_whichdimm: failed to "
		    "lookup required properties");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}
	ndimm = (dimm1 != MC_INVALNUM) + (dimm2 != MC_INVALNUM);
	if (ndimm == 0) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mc_whichdimm: found no "
		    "dimms associated with chip-select");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	if (ndimm == 1) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_whichdimm: just one "
		    "dimm associated with this chip-select");
		return (CSDIMM1);
	}

	/*
	 * 64/8 ECC is checked separately for the upper and lower
	 * halves, so even an uncorrectable error is contained within
	 * one of the two halves.  If we have sufficient address resolution
	 * then we can determine which DIMM.
	 */
	if (syndtype == AMD_SYNDTYPE_ECC) {
		if (valid_lo <= MC_SYSADDR_LSB) {
			mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_whichdimm: 64/8 "
			    "ECC in 128-bit mode, PA 0x%llx is in %s half\n",
			    pa, pa & 0x8 ? "upper" : "lower");
			return (pa & 0x8 ? CSDIMM2 : CSDIMM1);
		} else {
			mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_whichdimm: "
			    "64/8 ECC in 128-bit mode, PA 0x%llx with least "
			    "significant valid bit %d cannot be resolved to "
			    "a single DIMM\n", pa, valid_lo);
			return (mcamd_set_errno(hdl, EMCAMD_INSUFF_RES));
		}
	}

	/*
	 * ChipKill ECC
	 */
	if (mcamd_cksynd_decode(hdl, synd, &sym, &pat)) {
		/*
		 * A correctable ChipKill syndrome and we can tell
		 * which half the error was in from the symbol number.
		 */
		if (mcamd_cksym_decode(hdl, sym, &lobit, &hibit, &data,
		    &check) == 0)
			return (mcamd_set_errno(hdl, EMCAMD_SYNDINVALID));

		if (data && hibit <= 63 || check && hibit <= 7) {
			mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_whichdimm: "
			    "ChipKill symbol %d (%s %d..%d), so LODIMM\n", sym,
			    data ? "data" : "check", lobit, hibit);
			return (CSDIMM1);
		} else {
			mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_whichdimm: "
			    "ChipKill symbol %d (%s %d..%d), so UPDIMM\n", sym,
			    data ? "data" : "check", lobit, hibit);
			return (CSDIMM2);
		}
	} else {
		/*
		 * An uncorrectable error while in ChipKill ECC mode - can't
		 * tell which dimm or dimms the errors lie within.
		 */
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_whichhdimm: "
		    "uncorrectable ChipKill, could be either LODIMM "
		    "or UPDIMM\n");
		return (CSDIMM1 | CSDIMM2);
	}
}

/*
 * Brute-force BKDG pa to cs translation, coded to look as much like the
 * BKDG code as possible.
 */
static int
mc_bkdg_patounum(struct mcamd_hdl *hdl, mcamd_node_t *mc, uint64_t pa,
    uint8_t valid_lo, uint32_t synd, int syndtype,
    mc_unum_t *unump)
{
	int which;
	uint64_t mcnum, rev;
	mcamd_node_t *cs;
	/*
	 * Raw registers as per BKDG
	 */
	uint32_t HoleEn;
	uint32_t DramBase, DramLimit;
	uint32_t CSBase,  CSMask;
	/*
	 * Variables as per BKDG
	 */
	int Ilog;
	uint32_t SystemAddr = (uint32_t)(pa >> 8);
	uint64_t IntlvEn, IntlvSel;
	uint32_t HoleOffset;
	uint32_t InputAddr, Temp;

	if (!mcamd_get_numprops(hdl,
	    mc, MCAMD_PROP_NUM, &mcnum,
	    mc, MCAMD_PROP_REV, &rev, NULL) || !mcamd_get_cfgregs(hdl,
	    mc, MCAMD_REG_DRAMBASE, &DramBase,
	    mc, MCAMD_REG_DRAMLIMIT, &DramLimit,
	    mc, MCAMD_REG_DRAMHOLE, &HoleEn, NULL)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mc_bkdg_patounm: failed "
		    "to lookup required properties and registers\n");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	/*
	 * BKDG line to skip		Why
	 *
	 * F1Offset = ...		Register already read,
	 * DramBase = Get_PCI()		and retrieved above.
	 * DramEn = ...			Function only called for enabled nodes.
	 */
	IntlvEn = (DramBase & 0x00000700) >> 8;
	DramBase &= 0xffff0000;
	/* DramLimit = Get_PCI()	Retrieved above */
	IntlvSel = (DramLimit & 0x00000700) >> 8;
	DramLimit |= 0x0000ffff;
	/* HoleEn = ...			Retrieved above */
	HoleOffset = (HoleEn & 0x0000ff00) << 8;
	HoleEn &= 0x00000001;

	if (!(DramBase <= SystemAddr && SystemAddr <= DramLimit)) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_bkdg_patounum: "
		    "SystemAddr 0x%x derived from PA 0x%llx is not in the "
		    "address range [0x%x, 0x%x] of MC %d\n",
		    SystemAddr, pa, DramBase, DramLimit, (int)mcnum);
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
	}

	if (HoleEn && SystemAddr > 0x00ffffff)
		InputAddr = SystemAddr - HoleOffset;

	InputAddr = SystemAddr - DramBase;

	if (IntlvEn) {
		if (IntlvSel == ((SystemAddr >> 4) & IntlvEn)) {
			switch (IntlvEn) {
			case 1:
				Ilog = 1;
				break;
			case 3:
				Ilog = 2;
				break;
			case 7:
				Ilog = 3;
				break;
			default:
				return (mcamd_set_errno(hdl,
				    EMCAMD_TREEINVALID));
			}
			Temp = (InputAddr >> (4 + Ilog)) << 4;
			InputAddr = (Temp | (SystemAddr & 0x0000000f));
		} else {
			/* not this node */
			mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_bkdg_patounum: "
			    "Node interleaving, MC node %d not selected\n",
			    (int)mcnum);
			return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
		}
	}

	if (!MC_REV_MATCH(rev, MC_F_REVS_FG))
		InputAddr <<= 4;

	for (cs = mcamd_cs_next(hdl, mc, NULL); cs != NULL;
	    cs = mcamd_cs_next(hdl, mc, cs)) {
		uint64_t csnum, CSEn;

		if (!mcamd_get_cfgregs(hdl,
		    cs, MCAMD_REG_CSBASE, &CSBase,
		    cs, MCAMD_REG_CSMASK, &CSMask,
		    NULL) ||
		    !mcamd_get_numprops(hdl,
		    cs, MCAMD_PROP_NUM, &csnum,
		    cs, MCAMD_PROP_CSBE, &CSEn,
		    NULL)) {
			mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mc_bkdg_patounm: "
			    "failed to read cs registers\n");
			return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
		}

		/*
		 * BKDG line to skip		Why
		 *
		 * F2Offset =			Register already read,
		 * F2MaskOffset (rev F)		Register already read
		 * CSBase =			Register already read
		 * CSEn =			We only keep enabled cs.
		 */
		if (MC_REV_MATCH(rev, MC_F_REVS_FG)) {
			CSBase &= 0x1ff83fe0;
			/* CSMask = Get_PCI()		Retrieved above */
			CSMask = (CSMask | 0x0007c01f) & 0x1fffffff;
		} else {
			CSBase &= 0xffe0fe00;
			/* CSMask = Get_PCI()		Retrieved above */
			CSMask = (CSMask | 0x001f01ff) & 0x3fffffff;
		}

		if (CSEn && (InputAddr & ~CSMask) == (CSBase & ~CSMask)) {
			mcamd_node_t *sparecs;

			mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_bkdg_patounum: "
			    "match for chip select %d of MC %d\n", (int)csnum,
			    (int)mcnum);

			if ((sparecs = cs_sparedto(hdl, cs, mc)) != NULL)
				cs = sparecs;

			if ((which = mc_whichdimm(hdl, cs, pa, valid_lo,
			    synd, syndtype)) < 0)
				return (-1); /* errno is set for us */

			/*
			 * The BKDG algorithm drops low-order bits that
			 * are unimportant in deriving chip-select but are
			 * included in row/col/bank mapping, so do not
			 * perform offset calculation in this case.
			 */
			if (unum_fill(hdl, cs, which, InputAddr, unump, 0) < 0)
				return (-1); /* errno is set for us */

			return (0);
		}
	}

	mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mc_bkdg_patounum: in range "
	    "for MC %d but no cs responds\n", (int)mcnum);

	return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
}

/*
 * Called for each memory controller to see if the given address is
 * mapped to this node (as determined in iaddr_gen) and, if so, which
 * chip-select on this node responds.
 */

/*ARGSUSED*/
static int
mc_patounum(struct mcamd_hdl *hdl, mcamd_node_t *mc, uint64_t pa,
    uint8_t valid_lo, uint32_t synd, int syndtype, mc_unum_t *unump)
{
	uint64_t iaddr;
	mcamd_node_t *cs, *sparecs;
	int which;
#ifdef DEBUG
	mc_unum_t bkdg_unum;
	int bkdgres;

	/*
	 * We perform the translation twice, once using the brute-force
	 * approach of the BKDG and again using a more elegant but more
	 * difficult to review against the BKDG approach.
	 */
	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "BKDG brute-force method begins\n");
	bkdgres = mc_bkdg_patounum(hdl, mc, pa, valid_lo, synd,
	    syndtype, &bkdg_unum);
	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "BKDG brute-force method ends\n");
#endif

	if (iaddr_gen(hdl, mc, pa, &iaddr) < 0)
		return (-1); /* errno is set for us */

	for (cs = mcamd_cs_next(hdl, mc, NULL); cs != NULL;
	    cs = mcamd_cs_next(hdl, mc, cs)) {
		if (cs_match(hdl, iaddr, cs))
			break;
	}

	if (cs == NULL)
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));

	/*
	 * If the spare chip-select has been swapped in for the one just
	 * matched then it is really the spare that we are after.  Note that
	 * when the swap is done the csbase, csmask and CSBE of the spare
	 * rank do not change - accesses to the bad rank (as nominated in
	 * the Online Spare Control Register) are redirect to the spare.
	 */
	if ((sparecs = cs_sparedto(hdl, cs, mc)) != NULL) {
		cs = sparecs;
	}

	if ((which = mc_whichdimm(hdl, cs, pa, valid_lo, synd,
	    syndtype)) < 0)
		return (-1); /* errno is set for us */

	if (unum_fill(hdl, cs, which, iaddr, unump, 1) < 0)
		return (-1); /* errno is set for us */

#ifdef DEBUG
	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "bkdgres=%d res=0\n", bkdgres);
	/* offset is not checked - see note in BKDG algorithm */
	if (bkdgres != 0) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "BKDG alg failed while "
		    "ours succeeded\n");
	} else if (!(unump->unum_board == bkdg_unum.unum_board &&
	    unump->unum_chip == bkdg_unum.unum_chip &&
	    unump->unum_mc == bkdg_unum.unum_mc &&
	    unump->unum_chan == bkdg_unum.unum_chan &&
	    unump->unum_cs == bkdg_unum.unum_cs &&
	    unump->unum_dimms[0] == bkdg_unum.unum_dimms[0] &&
	    unump->unum_dimms[1] == bkdg_unum.unum_dimms[1])) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR,
		    "BKDG: node %d mc %d cs %d dimm(s) %d/%d\n"
		    "Ours: node 5d mc %d cs %d dimm(s) %d/%d\n",
		    bkdg_unum.unum_chip, bkdg_unum.unum_mc, bkdg_unum.unum_cs,
		    bkdg_unum.unum_dimms[0], bkdg_unum.unum_dimms[1],
		    unump->unum_chip, unump->unum_mc, unump->unum_cs,
		    unump->unum_dimms[0], unump->unum_dimms[1]);
	}
#endif /* DEBUG */

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "Result: chip %d mc %d cs %d "
	    "offset 0x%llx\n", unump->unum_chip, unump->unum_mc,
	    unump->unum_cs, unump->unum_offset);

	return (0);
}

int
mcamd_patounum(struct mcamd_hdl *hdl, mcamd_node_t *root, uint64_t pa,
    uint8_t valid_hi, uint8_t valid_lo, uint32_t synd, int syndtype,
    mc_unum_t *unump)
{
	mcamd_node_t *mc;

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_patounum: pa=0x%llx, "
	    "synd=0x%x, syndtype=%d\n", pa, synd, syndtype);

	if (valid_hi < MC_SYSADDR_MSB) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_patounum: require "
		    "pa<%d> to be valid\n", MC_SYSADDR_MSB);
		return (mcamd_set_errno(hdl, EMCAMD_INSUFF_RES));
	}

	if (!mcamd_synd_validate(hdl, synd, syndtype))
		return (mcamd_set_errno(hdl, EMCAMD_SYNDINVALID));

	for (mc = mcamd_mc_next(hdl, root, NULL); mc != NULL;
	    mc = mcamd_mc_next(hdl, root, mc)) {
		if (mc_patounum(hdl, mc, pa, valid_lo, synd,
		    syndtype, unump) == 0)
			return (0);

		if (mcamd_errno(hdl) != EMCAMD_NOADDR)
			break;
	}

	return (-1); /* errno is set for us */
}
