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

#include <mcamd_api.h>
#include <mcamd_err.h>
#include <mcamd_rowcol_impl.h>

/*
 * Convenience structures to stash MC and CS properties in.  Some of these
 * are read directly, while others are then calculated.
 */
struct rcp_mc {
	uint64_t num;		/* corresponding chip number */
	uint64_t rev;		/* revision */
	uint64_t width;		/* access width */
	uint64_t base;		/* MC base address */
	uint64_t lim;		/* MC limit address */
	uint64_t csbnkmap;	/* chip-select bank map */
	uint64_t intlven;	/* Node-interleave mask */
	uint64_t intlvsel;	/* Node-interleave selection for this node */
	uint64_t csintlvfctr;	/* chip-select interleave factor on this node */
	int bnkswzl;		/* bank-swizzle mode - derived */
};

struct rcp_cs {
	uint64_t num;		/* chip-select number */
	uint64_t base;		/* chip-select base address */
	uint64_t mask;		/* chip-select mask */
};

static int
getmcprops(struct mcamd_hdl *hdl, mcamd_node_t *mc, const char *caller,
    struct rcp_mc *pp)
{
	if (!mcamd_get_numprop(hdl, mc, MCAMD_PROP_NUM, &pp->num) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_REV, &pp->rev) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_ACCESS_WIDTH, &pp->width) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_BASE_ADDR, &pp->base) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_LIM_ADDR, &pp->lim) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_CSBANKMAP, &pp->csbnkmap) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_DRAM_ILEN, &pp->intlven) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_DRAM_ILSEL, &pp->intlvsel) ||
	    !mcamd_get_numprop(hdl, mc, MCAMD_PROP_CSBANK_INTLV,
	    &pp->csintlvfctr)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "%s: failed to read mc "
		    "props for mc 0x%p\n", caller, mc);
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	pp->bnkswzl = ((pp->csbnkmap & MC_DC_BAM_CSBANK_SWIZZLE) != 0);

	return (0);
}

static int
getcsprops(struct mcamd_hdl *hdl, mcamd_node_t *cs, const char *caller,
    struct rcp_cs *csp)
{
	if (!mcamd_get_numprop(hdl, cs, MCAMD_PROP_NUM, &csp->num) ||
	    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_BASE_ADDR, &csp->base) ||
	    !mcamd_get_numprop(hdl, cs, MCAMD_PROP_MASK, &csp->mask))  {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "%s: failed to read cs "
		    "props for cs 0x%p\n", caller, cs);
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	    }

	return (0);
}

static int
gettbls(struct mcamd_hdl *hdl, uint_t csmode, struct rcp_mc *mcpp,
    const struct bankaddr_mode **bamp, const struct csrcb_map **rcbmp,
    struct csintlv_desc *csid, const char *caller)
{
	if (bamp && (*bamp = rct_bankaddr_mode(mcpp->rev, csmode)) == NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "%s: no bank address mode "
		    "table for MC rev %d csmode %d\n", caller,
		    (int)mcpp->rev, csmode);
		return (mcamd_set_errno(hdl, EMCAMD_NOTSUP));
	}

	if (rcbmp && (*rcbmp = rct_rcbmap(mcpp->rev, mcpp->width,
	    csmode)) == NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "%s: no dram address map "
		    "table for MC rev %d csmode %d\n", caller,
		    (int)mcpp->rev, csmode);
		return (mcamd_set_errno(hdl, EMCAMD_NOTSUP));
	}

	if (csid) {
		if (mcpp->csintlvfctr != 0) {
			rct_csintlv_bits(mcpp->rev, mcpp->width, csmode,
			    mcpp->csintlvfctr, csid);
			if (csid->csi_factor == 0) {
				mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "%s: "
				    "could not work out cs interleave "
				    "paramters for MC rev %d, width %d, "
				    "csmode %d, factor %d\n", caller,
				    (int)mcpp->rev, (int)mcpp->width, csmode,
				    (int)mcpp->csintlvfctr);
				return (mcamd_set_errno(hdl, EMCAMD_NOTSUP));
			}
		} else {
			csid->csi_factor = 0;
		}
	}

	return (0);
}

static uint64_t
iaddr_add(struct mcamd_hdl *hdl, uint64_t in, uint64_t add, const char *what)
{
	uint64_t new = in | add;

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "%s: 0x%llx | 0x%llx --> 0x%llx",
	    what, in, add, new);

	return (add);
}

/*
 * Where the number of row/col address bits is ambiguous (affects CG and
 * earlier only) we will assign the "floating" bit to row address.  If
 * we adopt the same convention in address reconstruction then all should work.
 */
static uint32_t
iaddr_to_row(struct mcamd_hdl *hdl, const struct bankaddr_mode *bamp,
    const struct csrcb_map *rcbm, struct csintlv_desc *csid, uint64_t iaddr)
{
	uint32_t addr = 0;
	int abitno, ibitno;
	int nbits = bamp->bam_nrows;
	int swapped = 0;

	for (abitno = 0; abitno < nbits; abitno++) {
		ibitno = rcbm->csrcb_rowbits[abitno];
		if (MC_RC_CSI_SWAPPED_BIT(csid, ibitno)) {
			ibitno = MC_RC_CSI_BITSWAP(csid, ibitno);
			swapped++;
		}
		if (iaddr & (1 << ibitno))
			addr |= (1 << abitno);
	}

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_to_row: iaddr 0x%llx --> "
	    "row 0x%x (%d bits swapped for cs intlv)\n", iaddr, addr, swapped);

	return (addr);
}

/*ARGSUSED*/
static uint64_t
row_to_iaddr(struct mcamd_hdl *hdl, const struct bankaddr_mode *bamp,
    const struct csrcb_map *rcbm, struct csintlv_desc *csid, uint32_t rowaddr)
{
	uint64_t iaddr = 0;
	int abitno, ibitno;
	int nbits = bamp->bam_nrows;

	for (abitno = 0; abitno < nbits; abitno++) {
		if (BIT(rowaddr, abitno) == 0)
			continue;
		ibitno = rcbm->csrcb_rowbits[abitno];
		if (MC_RC_CSI_SWAPPED_BIT(csid, ibitno)) {
			ibitno = MC_RC_CSI_BITSWAP(csid, ibitno);
		}
		SETBIT(iaddr, ibitno);
	}

	return (iaddr);
}


static uint32_t
iaddr_to_col(struct mcamd_hdl *hdl, const struct bankaddr_mode *bamp,
    const struct csrcb_map *rcbm, uint64_t iaddr)
{
	uint32_t addr = 0;
	int abitno, ibitno, bias = 0;
	int nbits = bamp->bam_ncols;

	/*
	 * Knock off a column bit if the numbers are ambiguous
	 */
	if (bamp->bam_ambig)
		nbits--;

	for (abitno = 0; abitno < nbits; abitno++) {
		if (abitno == MC_PC_COLADDRBIT)
			bias = 1;

		ibitno = rcbm->csrcb_colbits[abitno + bias];

		if (iaddr & (1 << ibitno))
			SETBIT(addr, abitno);
	}

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_to_col: iaddr 0x%llx --> "
	    "col 0x%x\n", iaddr, addr);

	return (addr);
}

/*ARGSUSED*/
static uint64_t
col_to_iaddr(struct mcamd_hdl *hdl, const struct bankaddr_mode *bamp,
    const struct csrcb_map *rcbm, uint32_t coladdr)
{
	uint64_t iaddr = 0;
	int abitno, ibitno, bias = 0;
	int nbits = bamp->bam_ncols;

	/*
	 * Knock off a column bit if the numbers are ambiguous
	 */
	if (bamp->bam_ambig)
		nbits--;

	for (abitno = 0; abitno < nbits; abitno++) {
		if (BIT(coladdr, abitno) == 0)
			continue;

		if (abitno == MC_PC_COLADDRBIT)
			bias = 1;

		ibitno = rcbm->csrcb_colbits[abitno + bias];
		SETBIT(iaddr, ibitno);
	}

	return (iaddr);
}

/*
 * Extract bank bit arguments and xor them together.  Tables for
 * non bank-swizzling should have all but the first argument zero.
 */
static uint32_t
iaddr_to_bank(struct mcamd_hdl *hdl, const struct csrcb_map *rcbm,
    int bnkswzl, uint64_t iaddr)
{
	uint32_t addr = 0;
	int abitno, ibitno, i;
	int bnkargs = bnkswzl ? MC_RC_BANKARGS : 1;

	for (abitno = 0; abitno < MC_RC_BANKBITS; abitno++) {
		uint32_t val = 0;
		for (i = 0; i < bnkargs; i++) {
			ibitno = rcbm->csrcb_bankargs[abitno][i];
			val ^= ((iaddr >> ibitno) & 0x1);
		}
		addr |= (val << abitno);
	}

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_to_bank: iaddr 0x%llx --> "
	    "bank 0x%x\n", iaddr, addr);

	return (addr);
}

/*
 * bank_to_iaddr requires the iaddr reconstructed thus far with at least the
 * row bits repopulated.  That's because in bank swizzle mode
 * the bank bits are the result of xor'ing three original iaddr bits
 * together - two of which come from the row address and the third we
 * can reconstruct here.  Note that a zero bankaddr bit *can* result
 * in a nonzero iaddr bit (unlike in row and col reconstruction).
 */
/*ARGSUSED*/
static uint64_t
bank_to_iaddr(struct mcamd_hdl *hdl, const struct csrcb_map *rcbm,
    int bnkswzl, uint64_t partiaddr, uint32_t bankaddr)
{
	uint64_t iaddr = 0;
	int abitno, pibitno, i;

	for (abitno = 0; abitno < MC_RC_BANKBITS; abitno++) {
		uint32_t val = BITVAL(bankaddr, abitno);
		if (bnkswzl) {
			for (i = 1; i < MC_RC_BANKARGS; i++) {
				pibitno = rcbm->csrcb_bankargs[abitno][i];
				val ^= BITVAL(partiaddr, pibitno);
			}
		}
		if (val)
			SETBIT(iaddr, rcbm->csrcb_bankargs[abitno][0]);
	}

	return (iaddr);
}

static int
iaddr_to_rcb(struct mcamd_hdl *hdl, uint_t csmode, struct rcp_mc *mcpp,
    uint64_t iaddr, uint32_t *rowp, uint32_t *colp, uint32_t *bankp)
{
	const struct bankaddr_mode *bamp;
	const struct csrcb_map *rcbm;
	struct csintlv_desc csi;

	if (gettbls(hdl, csmode, mcpp, &bamp, &rcbm, &csi, "iaddr_to_rcb") < 0)
		return (-1);	/* errno already set */

	*rowp = iaddr_to_row(hdl, bamp, rcbm, &csi, iaddr);
	*colp = iaddr_to_col(hdl, bamp, rcbm, iaddr);
	*bankp = iaddr_to_bank(hdl, rcbm, mcpp->bnkswzl, iaddr);

	return (0);
}

/*
 * Take a reconstructed InputAddr and undo the normalization described in
 * BKDG 3.29 3.4.4 to include the base address of the MC if no node
 * interleave or to insert the node interleave selection bits.
 */
static int
iaddr_unnormalize(struct mcamd_hdl *hdl, struct rcp_mc *mcpp, uint64_t iaddr,
    uint64_t *rsltp)
{
	uint64_t dramaddr;
	int intlvbits;

	switch (mcpp->intlven) {
	case 0x0:
		intlvbits = 0;
		break;
	case 0x1:
		intlvbits = 1;
		break;
	case 0x3:
		intlvbits = 2;
		break;
	case 0x7:
		intlvbits = 3;
		break;
	default:
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "iaddr_unnormalize: "
		    "illegal IntlvEn of %d for MC 0x%p\n",
		    (int)mcpp->intlven, (int)mcpp->num);
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	if (intlvbits != 0) {
		/*
		 * For a 2/4/8 way interleave iaddr was formed by excising
		 * 1, 2, or 3 bits 12:12, 13:12, or 14:12 from dramaddr,
		 * the removed bits having done their job by selecting the
		 * responding node.  So we must move bits 35:12 of the
		 * reconstructed iaddr up to make a 1, 2 or 3 bit hole and
		 * then fill those bits with the current IntlvSel value for
		 * this node.  The node base address must be zero if nodes
		 * are interleaved.
		 */
		dramaddr = (BITS(iaddr, 35, 12) << intlvbits) |
		    (mcpp->intlvsel << 12) | BITS(iaddr, 11, 0);
	} else {
		dramaddr = iaddr + mcpp->base;
	}

	*rsltp = dramaddr;

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_unnormalize: iaddr 0x%llx "
	    "intlven 0x%x intlvsel 0x%x MC base 0x%llx --> 0x%llx\n",
	    iaddr, (int)mcpp->intlven, (int)mcpp->intlvsel, (int)mcpp->base,
	    dramaddr);

	return (0);
}

int
mc_pa_to_offset(struct mcamd_hdl *hdl, mcamd_node_t *mc, mcamd_node_t *cs,
    mcamd_node_t *dimm, uint64_t iaddr, uint64_t *offsetp)
{
	mcamd_dimm_offset_un_t offset_un;
	uint_t csmode;
	uint32_t bankaddr, rowaddr, coladdr;
	int rank;
	mcamd_node_t *tcs;
	struct rcp_mc mcp;
	struct rcp_cs csp;

	*offsetp = MCAMD_RC_INVALID_OFFSET;

	if (getmcprops(hdl, mc, "mc_dimm_offset", &mcp) < 0 ||
	    getcsprops(hdl, cs, "mc_dimm_offset", &csp) < 0)
		return (-1);	/* errno already set */

	csmode = MC_CS_MODE(mcp.csbnkmap, csp.num);

	/*
	 * Convert chip-select number 0 .. 7 to a DIMM rank 0 .. 3.  The
	 * rank is the index of the member of the dimm mcd_cs array which
	 * matches cs.
	 */
	for (rank = 0, tcs = mcamd_cs_next(hdl, (mcamd_node_t *)dimm, NULL);
	    tcs != NULL;
	    rank++, tcs = mcamd_cs_next(hdl, (mcamd_node_t *)dimm, tcs)) {
		struct rcp_cs tcsp;

		if (getcsprops(hdl, tcs, "mc_dimm_offset", &tcsp) < 0)
			return (-1);	/* errno already set */
		if (tcsp.num == csp.num)
			break;
	}
	if (rank == MC_CHIP_DIMMRANKMAX) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mcamd_dimm_offset: "
		    "iteration over chip-selects of dimm 0x%p failed "
		    "to match on expected csnum %d\n", dimm, (int)csp.num);
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	if (iaddr_to_rcb(hdl, csmode, &mcp, iaddr, &rowaddr,
	    &coladdr, &bankaddr) < 0)
		return (-1);	/* errno already set */

	offset_un.do_offset = 0;

	offset_un.do_valid = 1;
	offset_un.do_version = MCAMD_OFFSET_VERSION;
	offset_un.do_rank = rank;
	offset_un.do_row = rowaddr;
	offset_un.do_bank = bankaddr;
	offset_un.do_col = coladdr;

	*offsetp = offset_un.do_offset;

	return (0);
}

/*
 * Given a MC and DIMM and offset (dimm rank, row, col, internal bank) we
 * find the corresponding chip-select for the rank and then reconstruct
 * a system address.  In the absence of serial number support it is possible
 * that we may be asked to perform this operation on a dimm which has been
 * swapped, perhaps even for a dimm of different size and number of ranks.
 * This may happen if fmadm repair has not been used.  There are some
 * unused bits in the offset and we could guard against this a little
 * by recording in those bit some of the physical characteristic of the
 * original DIMM such as size, number of ranks etc.
 */
int
mc_offset_to_pa(struct mcamd_hdl *hdl, mcamd_node_t *mc, mcamd_node_t *dimm,
    uint64_t offset, uint64_t *pap)
{
	mcamd_node_t *cs;
	mcamd_dimm_offset_un_t off_un;
	uint32_t rank, rowaddr, bankaddr, coladdr;
	int i;
	uint64_t iaddr = 0;
	const struct bankaddr_mode *bamp;
	const struct csrcb_map *rcbm;
	struct csintlv_desc csi;
	struct rcp_mc mcp;
	struct rcp_cs csp;
	uint64_t csmode;
	int maskhi_hi = MC_DC_CSM_MASKHI_HIBIT;
	int maskhi_lo = MC_DC_CSM_MASKHI_LOBIT;
	int masklo_hi = MC_DC_CSM_MASKLO_HIBIT;
	int masklo_lo = MC_DC_CSM_MASKLO_LOBIT;

	off_un.do_offset = offset;
	rank = off_un.do_rank;
	bankaddr = off_un.do_bank;
	rowaddr = off_un.do_row;
	coladdr = off_un.do_col;

	if (getmcprops(hdl, mc, "mc_offset_to_pa", &mcp) < 0)
		return (-1);	/* errno already set */

	/*
	 * Find the rank'th chip-select on this dimm.
	 */
	i = 0;
	cs = mcamd_cs_next(hdl, dimm, NULL);
	while (i != rank && cs != NULL) {
		cs = mcamd_cs_next(hdl, dimm, cs);
		i++;
	}
	if (i != rank || cs == NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_offset_to_pa: Current "
		    "dimm in this slot does not have an %d'th cs\n",
		    rank);
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
	}

	if (getcsprops(hdl, cs, "mc_offset_to_pa", &csp) < 0)
		return (-1);	/* errno already set */

	csmode = MC_CS_MODE(mcp.csbnkmap, csp.num);

	if (gettbls(hdl, csmode, &mcp, &bamp, &rcbm, &csi,
	    "mc_offset_to_pa") < 0)
		return (-1);	/* errno already set */

	/*CONSTANTCONDITION*/
	if (MC_DC_CSM_UNMASKED_BITS != 0) {
		iaddr |= iaddr_add(hdl, iaddr,
		    BITS(csp.base, maskhi_hi + MC_DC_CSM_UNMASKED_BITS,
		    maskhi_hi + 1), "unmaskable cs basehi bits");
	}

	iaddr |= iaddr_add(hdl, iaddr,
	    BITS(csp.base, maskhi_hi, maskhi_lo) &
	    ~BITS(csp.mask, maskhi_hi, maskhi_lo),
	    "cs basehi bits not being masked");

	if (mcp.csintlvfctr != 0) {
		iaddr |= iaddr_add(hdl, iaddr,
		    BITS(csp.base, masklo_hi, masklo_lo) &
		    ~BITS(csp.mask, masklo_hi, masklo_lo),
		    "cs baselo bits not being masked");
	}

	iaddr |= iaddr_add(hdl, iaddr,
	    row_to_iaddr(hdl, bamp, rcbm, &csi, rowaddr),
	    "add iaddr bits from row");

	iaddr |= iaddr_add(hdl, iaddr,
	    col_to_iaddr(hdl, bamp, rcbm, coladdr),
	    "add iaddr bits from col");

	iaddr |= iaddr_add(hdl, iaddr,
	    bank_to_iaddr(hdl, rcbm, mcp.bnkswzl, iaddr, bankaddr),
	    "add iaddr bits from bank");

	if (iaddr_unnormalize(hdl, &mcp, iaddr, pap) < 0)
		return (-1);	/* errno already set */

	return (0);
}

int
mcamd_cs_size(struct mcamd_hdl *hdl, mcamd_node_t *mc, int csnum, size_t *szp)
{
	uint_t csmode;
	struct rcp_mc mcp;
	const struct bankaddr_mode *bamp;

	if (getmcprops(hdl, mc, "mcamd_cs_size", &mcp) < 0)
		return (-1);	/* errno already set */

	csmode = MC_CS_MODE(mcp.csbnkmap, csnum);

	if (gettbls(hdl, csmode, &mcp, &bamp, NULL, NULL, "mcamd_cs_size") < 0)
		return (-1);	/* errno already set */

	*szp = MC_CS_SIZE(bamp, mcp.width);

	return (0);
}
