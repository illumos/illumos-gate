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
 *
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

extern int mc_pa_to_offset(struct mcamd_hdl *, mcamd_node_t *, mcamd_node_t *,
    mcamd_node_t *, uint64_t, uint64_t *);

#define	LO_DIMM		0x1
#define	UP_DIMM		0x2

#define	BITS(val, high, low) \
	((val) & (((2ULL << (high)) - 1) & ~((1ULL << (low)) - 1)))

static int
iaddr_gen(struct mcamd_hdl *hdl, mcamd_node_t *mc, uint64_t pa,
    uint64_t *iaddrp)
{
	uint64_t orig = pa;
	uint64_t mcnum, base, lim, dramaddr, ilen, ilsel, top, dramhole;

	if (!mcamd_get_numprop(hdl, mc, MCAMD_PROP_NUM, &mcnum) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_BASE_ADDR, &base) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_LIM_ADDR, &lim) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_DRAM_ILEN, &ilen) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_DRAM_ILSEL, &ilsel) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_DRAM_HOLE, &dramhole)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "iaddr_gen: failed to "
		    "lookup required properties");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

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
	if (dramhole & MC_DC_HOLE_VALID && pa >= 0x100000000) {
		uint64_t holesize = (dramhole & MC_DC_HOLE_OFFSET_MASK) <<
		    MC_DC_HOLE_OFFSET_LSHIFT;
		pa -= holesize;
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_gen: dram hole "
		    "valid; pa decremented from 0x%llx to 0x%llx for "
		    "a dramhole size of 0x%llx\n", orig, pa, holesize);
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

static int
cs_match(struct mcamd_hdl *hdl, uint64_t iaddr, mcamd_node_t *cs)
{
	uint64_t csnum, csbase, csmask;
	int match;

	if (!mcamd_get_numprop(hdl, cs, MCAMD_PROP_NUM, &csnum) ||
	    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_BASE_ADDR, &csbase) ||
	    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_MASK, &csmask)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "cs_match: failed to lookup "
		    "required properties\n");
		return (0);
	}

	match = ((iaddr & ~csmask) == (csbase & ~csmask));

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "cs_match: iaddr 0x%llx does "
	    "%smatch CS %d (base 0x%llx, mask 0x%llx)\n", iaddr,
	    match ? "" : "not ", (int)csnum, csbase, csmask);

	return (match);
}

static int
unum_fill(struct mcamd_hdl *hdl, mcamd_node_t *cs, int which,
    uint64_t iaddr, struct mc_unum *unump, int incloff)
{
	mcamd_node_t *mc, *dimm;
	uint64_t chipnum, csnum, lonum, upnum;
	int i;
	int offsetdimm;

	if ((mc = mcamd_cs_mc(hdl, cs)) == NULL ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_NUM, &chipnum) ||
	    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_NUM, &csnum)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "unum_fill: failed to "
		    "lookup required properties\n");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	if ((which & LO_DIMM) &&
	    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_LODIMM, &lonum) ||
	    (which & UP_DIMM) &&
	    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_UPDIMM, &upnum)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "unum_fill: failed to "
		    "lookup lodimm/hidimm properties\n");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	unump->unum_board = 0;
	unump->unum_chip = chipnum;
	unump->unum_mc = 0;
	unump->unum_cs = csnum;

	for (i = 0; i < MC_UNUM_NDIMM; i++) {
		unump->unum_dimms[i] = -1;
	}
	switch (which) {
	case LO_DIMM:
		unump->unum_dimms[0] = lonum;
		offsetdimm = lonum;
		break;
	case UP_DIMM:
		unump->unum_dimms[0] = upnum;
		offsetdimm = upnum;
		break;
	case LO_DIMM | UP_DIMM:
		unump->unum_dimms[0] = lonum;
		unump->unum_dimms[1] = upnum;
		offsetdimm = lonum;
		break;
	}

	if (!incloff) {
		unump->unum_offset = MCAMD_RC_INVALID_OFFSET;
		return (0);
	}

	/*
	 * We wish to calculate a dimm offset.  In the paired case we will
	 * lookup the lodimm (see offsetdimm above).
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
	(void) mc_pa_to_offset(hdl, mc, cs, dimm, iaddr, &unump->unum_offset);

	return (0);
}

/*
 * We have translated a system address to a (node, chip-select).  That
 * identifies one (in 64-bit MC mode) or two (in 128-bit MC mode DIMMs,
 * either a lodimm or a lodimm/updimm pair.  For all cases except an
 * uncorrectable ChipKill error we can interpret the address alignment and
 * syndrome to deduce whether we are on the lodimm or updimm.
 */
static int
mc_whichdimm(struct mcamd_hdl *hdl, mcamd_node_t *mc, uint64_t pa,
    uint32_t synd, int syndtype)
{
	uint64_t accwidth;
	uint_t sym, pat;
	int lobit, hibit, data, check;

	if (!mcamd_get_numprop(hdl, mc, MCAMD_PROP_ACCESS_WIDTH, &accwidth) ||
	    (accwidth != 64 && accwidth != 128)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mc_whichdimm: failed "
		    "to lookup required properties\n");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	/*
	 * In 64 bit mode only LO dimms are occupied.
	 */
	if (accwidth == 64) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_whichdimm: 64-bit mode "
		    "therefore LO_DIMM\n");
		return (LO_DIMM);
	}

	if (syndtype == AMD_SYNDTYPE_ECC) {
		/*
		 * 64/8 ECC is checked separately for the upper and lower
		 * halves, so even an uncorrectable error is contained within
		 * one of the two halves.  The error address is accurate to
		 * 8 bytes, so bit 4 distinguises upper from lower.
		 */
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_whichdimm: 64/8 ECC "
		    "and PA 0x%llx is in %s half\n", pa,
		    pa & 8 ? "lower" : "upper");
		return (pa & 8 ? UP_DIMM : LO_DIMM);
	}

	/*
	 * ChipKill ECC (necessarily in 128-bit mode.
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
			return (LO_DIMM);
		} else {
			mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_whichdimm: "
			    "ChipKill symbol %d (%s %d..%d), so UPDIMM\n", sym,
			    data ? "data" : "check", lobit, hibit);
			return (UP_DIMM);
		}
	} else {
		/*
		 * An uncorrectable error while in ChipKill ECC mode - can't
		 * tell which dimm or dimms the errors lie within.
		 */
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_whichhdimm: "
		    "uncorrectable ChipKill, could be either LODIMM "
		    "or UPDIMM\n");
		return (LO_DIMM | UP_DIMM);
	}
}

/*
 * Brute-force BKDG pa to cs translation.  The following is from BKDG 3.29
 * so is for revisions prior to F.  It is coded to look as much like the
 * BKDG code as possible.
 */
static int
mc_bkdg_patounum(struct mcamd_hdl *hdl, mcamd_node_t *mc, uint64_t pa,
    uint32_t synd, int syndtype, struct mc_unum *unump)
{
	int which;
	uint64_t mcnum;
	mcamd_node_t *cs;
	/*
	 * Variables as per BKDG
	 */
	int Ilog;
	uint32_t SystemAddr = (uint32_t)(pa >> 8);
	uint64_t IntlvEn, IntlvSel;
	uint32_t DramBase, DramLimit;		/* assume DramEn */
	uint32_t HoleOffset, HoleEn;
	uint32_t CSBase,  CSMask;		/* assuume CSBE */
	uint32_t InputAddr, Temp;

	/*
	 * Additional variables which we need since we will reading
	 * MC properties instead of PCI config space, and the MC properties
	 * are stored in a cooked state.
	 */
	uint64_t prop_drambase, prop_dramlimit, prop_dramhole;
	uint64_t prop_intlven, prop_intlvsel;
	uint64_t prop_csbase, prop_csmask;

	if (!mcamd_get_numprop(hdl, mc, MCAMD_PROP_NUM, &mcnum) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_BASE_ADDR, &prop_drambase) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_LIM_ADDR, &prop_dramlimit) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_DRAM_HOLE, &prop_dramhole) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_DRAM_ILEN, &prop_intlven) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_DRAM_ILSEL,
	    &prop_intlvsel)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mc_bkdg_patounm: failed "
		    "to lookup required properties\n");
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	/*
	 * Brute force deconstruction of the MC properties.  If we decide to
	 * keep this then we need some of the mcamd.g defines available to us.
	 */
	DramBase = ((prop_drambase >> 8) & 0xffff0000) | (prop_intlven << 8);
	IntlvEn = (DramBase & 0x00000700) >> 8;
	DramBase &= 0xffff0000;
	DramLimit = ((prop_dramlimit >> 8) & 0xffff0000) | (prop_intlvsel << 8);
	IntlvSel = (DramLimit & 0x00000700) >> 8;
	DramLimit |= 0x0000ffff;
	HoleEn = prop_dramhole;	/* uncooked */
	HoleOffset = (HoleEn & 0x0000ff00) << 8;
	HoleEn &= 0x00000001;

	if (!(DramBase <= SystemAddr && SystemAddr <= DramLimit)) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_bkdg_patounum: "
		    "SystemAddr 0x%x derived from PA 0x%llx is not in the "
		    "address range [0x%x, 0x%x] of MC %d\n",
		    SystemAddr, pa, DramBase, DramLimit, (int)mcnum);
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
	}

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
			Temp = (SystemAddr >> (4 + Ilog)) << 4;
			InputAddr = (Temp | (SystemAddr & 0x0000000f)) << 4;
		} else {
			/* not this node */
			mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_bkdg_patounum: "
			    "Node interleaving, MC node %d not selected\n",
			    (int)mcnum);
			return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
		}
	} else {
		/* No interleave */
		InputAddr = (SystemAddr - DramBase) << 4;
	}

	if (HoleEn && SystemAddr > 0x00ffffff)
	    InputAddr -= HoleOffset;

	for (cs = mcamd_cs_next(hdl, mc, NULL); cs != NULL;
	    cs = mcamd_cs_next(hdl, mc, cs)) {
		uint64_t csnum;

		if (!mcamd_get_numprop(hdl, cs, MCAMD_PROP_BASE_ADDR,
		    &prop_csbase) ||
		    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_MASK,
		    &prop_csmask) ||
		    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_NUM, &csnum)) {
			mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mc_bkdg_patounm: "
			    "failed to read cs properties\n");
			return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
		}

		CSBase = ((prop_csbase >> 4) & 0xffe00000) |
		    ((prop_csbase >> 4) & 0x0000fe00);
		CSBase &= 0xffe0fe00;
		CSMask = ((prop_csmask >> 4) & 0x3fe00000) |
		    ((prop_csmask >> 4) & 0x0000fe00);
		CSMask = (CSMask | 0x001f01ff) & 0x3fffffff;

		if (((InputAddr & ~CSMask) == (CSBase & ~CSMask))) {
			mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_bkdg_patounum: "
			    "match for chip select %d of MC %d\n", (int)csnum,
			    (int)mcnum);

			if ((which = mc_whichdimm(hdl, mc, pa, synd,
			    syndtype)) < 0)
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

/*ARGSUSED*/
static int
mc_patounum(struct mcamd_hdl *hdl, mcamd_node_t *mc, uint64_t pa,
    uint32_t synd, int syndtype, struct mc_unum *unump)
{
	uint64_t iaddr;
	mcamd_node_t *cs;
	int which;
#ifdef DEBUG
	struct mc_unum bkdg_unum;
	int bkdgres;

	/*
	 * We perform the translation twice, once using the brute-force
	 * approach of the BKDG and again using a more elegant but more
	 * difficult to review against the BKDG approach.  Note that both
	 * approaches need to change for rev F since it increases max CS
	 * size and so iaddr calculation etc changes.
	 */
	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "BKDG brute-force method begins\n");
	bkdgres = mc_bkdg_patounum(hdl, mc, pa, synd, syndtype, &bkdg_unum);
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

	if ((which = mc_whichdimm(hdl, mc, pa, synd, syndtype)) < 0)
		return (-1); /* errno is set for us */

	if (unum_fill(hdl, cs, which, iaddr, unump, 1) < 0)
		return (-1); /* errno is set for us */

#ifdef DEBUG
	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "bkdgres=%d res=0\n", bkdgres);
#ifndef _KERNEL
	/* offset is not checked - see note in BKDG algorithm */
	assert(bkdgres == 0 && unump->unum_board == bkdg_unum.unum_board &&
	    unump->unum_chip == bkdg_unum.unum_chip &&
	    unump->unum_mc == bkdg_unum.unum_mc &&
	    unump->unum_cs == bkdg_unum.unum_cs &&
	    unump->unum_dimms[0] == bkdg_unum.unum_dimms[0] &&
	    unump->unum_dimms[1] == bkdg_unum.unum_dimms[1]);
#endif /* !_KERNEL */
#endif /* DEBUG */

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "Result: chip %d mc %d cs %d "
	    "offset 0x%llx\n", unump->unum_chip, unump->unum_mc,
	    unump->unum_cs, unump->unum_offset);

	return (0);
}

int
mcamd_patounum(struct mcamd_hdl *hdl, mcamd_node_t *root, uint64_t pa,
    uint32_t synd, int syndtype, struct mc_unum *unump)
{
	mcamd_node_t *mc;

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mcamd_patounum: pa=0x%llx, "
	    "synd=0x%x, syndtype=%d\n", pa, synd, syndtype);

	if (!mcamd_synd_validate(hdl, synd, syndtype))
		return (mcamd_set_errno(hdl, EMCAMD_SYNDINVALID));

	for (mc = mcamd_mc_next(hdl, root, NULL); mc != NULL;
	    mc = mcamd_mc_next(hdl, root, mc)) {
		if (mc_patounum(hdl, mc, pa, synd, syndtype, unump) == 0)
			return (0);

		if (mcamd_errno(hdl) != EMCAMD_NOADDR)
			break;
	}

	return (-1); /* errno is set for us */
}
