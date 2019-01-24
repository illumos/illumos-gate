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

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <mcamd_api.h>
#include <mcamd_err.h>
#include <mcamd_rowcol_impl.h>

/*
 * Convenience structures to stash MC and CS properties in.
 */
struct mcprops {
	mcamd_prop_t num;		/* corresponding chip number */
	mcamd_prop_t rev;		/* revision */
	mcamd_prop_t width;		/* access width */
	mcamd_prop_t base;		/* MC base address */
	mcamd_prop_t lim;		/* MC limit address */
	mcamd_prop_t csbnkmap_reg;	/* chip-select bank map */
	mcamd_prop_t intlven;		/* Node-intlv mask */
	mcamd_prop_t intlvsel;		/* Node-intlv selection for this node */
	mcamd_prop_t csintlvfctr;	/* cs intlv factor on this node */
	mcamd_prop_t bnkswzl;		/* bank-swizzle mode */
	mcamd_prop_t sparecs;		/* spare cs#, if any */
	mcamd_prop_t badcs;		/* substituted cs#, if any */
};

struct csprops {
	mcamd_prop_t num;		/* chip-select number */
	mcamd_prop_t base;		/* chip-select base address */
	mcamd_prop_t mask;		/* chip-select mask */
	mcamd_prop_t testfail;		/* marked testFail */
	mcamd_prop_t dimmrank;		/* rank number on dimm(s) */
};

static int
getmcprops(struct mcamd_hdl *hdl, mcamd_node_t *mc, const char *caller,
    struct mcprops *pp)
{
	if (!mcamd_get_numprops(hdl,
	    mc, MCAMD_PROP_NUM, &pp->num,
	    mc, MCAMD_PROP_REV, &pp->rev,
	    mc, MCAMD_PROP_ACCESS_WIDTH, &pp->width,
	    mc, MCAMD_PROP_BASE_ADDR, &pp->base,
	    mc, MCAMD_PROP_LIM_ADDR, &pp->lim,
	    mc, MCAMD_PROP_CSBANKMAPREG, &pp->csbnkmap_reg,
	    mc, MCAMD_PROP_ILEN, &pp->intlven,
	    mc, MCAMD_PROP_ILSEL, &pp->intlvsel,
	    mc, MCAMD_PROP_CSINTLVFCTR, &pp->csintlvfctr,
	    mc, MCAMD_PROP_BANKSWZL, &pp->bnkswzl,
	    mc, MCAMD_PROP_SPARECS, &pp->sparecs,
	    mc, MCAMD_PROP_BADCS, &pp->badcs,
	    NULL)) {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "%s: failed to read mc "
		    "props for mc 0x%p\n", caller, mc);
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	return (0);
}

static int
getcsprops(struct mcamd_hdl *hdl, mcamd_node_t *cs, const char *caller,
    struct csprops *csp)
{
	if (!mcamd_get_numprops(hdl,
	    cs, MCAMD_PROP_NUM, &csp->num,
	    cs, MCAMD_PROP_BASE_ADDR, &csp->base,
	    cs, MCAMD_PROP_MASK, &csp->mask,
	    cs, MCAMD_PROP_TESTFAIL, &csp->testfail,
	    cs, MCAMD_PROP_DIMMRANK, &csp->dimmrank,
	    NULL))  {
		mcamd_dprintf(hdl, MCAMD_DBG_ERR, "%s: failed to read cs "
		    "props for cs 0x%p\n", caller, cs);
		return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
	}

	return (0);
}

static int
gettbls(struct mcamd_hdl *hdl, uint_t csmode, struct mcprops *mcpp,
    const struct rct_bnkaddrmode **bamp, const struct rct_rcbmap **rcbmp,
    const struct rct_bnkswzlinfo **swzlp, struct rct_csintlv *csid,
    const char *caller)
{
	uint_t rev = (uint_t)mcpp->rev;
	int width = (int)mcpp->width;

	if (bamp && (*bamp = rct_bnkaddrmode(rev, csmode)) == NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "%s: no bank address mode "
		    "table for MC rev %d csmode %d\n", caller, rev, csmode);
		return (mcamd_set_errno(hdl, EMCAMD_NOTSUP));
	}

	if (rcbmp && (*rcbmp = rct_rcbmap(rev, width, csmode)) == NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "%s: no dram address map "
		    "table for MC rev %d csmode %d\n", caller,
		    rev, csmode);
		return (mcamd_set_errno(hdl, EMCAMD_NOTSUP));
	}

	if (swzlp && (*swzlp = rct_bnkswzlinfo(rev, width)) == NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "%s: no bank swizzling "
		    "table for MC rev %d width %d\n", caller, rev, width);
		return (mcamd_set_errno(hdl, EMCAMD_NOTSUP));
	}

	if (csid) {
		if (mcpp->csintlvfctr > 1) {
			rct_csintlv_bits(rev, width, csmode,
			    mcpp->csintlvfctr, csid);
			if (csid->csi_factor == 0) {
				mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "%s: "
				    "could not work out cs interleave "
				    "paramters for MC rev %d, width %d, "
				    "csmode %d, factor %d\n", caller,
				    rev, width, csmode,
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
iaddr_to_row(struct mcamd_hdl *hdl, const struct rct_bnkaddrmode *bamp,
    const struct rct_rcbmap *rcbm, struct rct_csintlv *csid, uint64_t iaddr)
{
	uint32_t addr = 0;
	int abitno, ibitno;
	int nbits = bamp->bam_nrows;
	int swapped = 0;

	for (abitno = 0; abitno < nbits; abitno++) {
		ibitno = rcbm->rcb_rowbit[abitno];
		if (MC_RC_CSI_SWAPPED_BIT(csid, ibitno)) {
			ibitno = MC_RC_CSI_BITSWAP(csid, ibitno);
			swapped++;
		}
		if (BITVAL(iaddr, ibitno) != 0)
			SETBIT(addr, abitno);
	}

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_to_row: iaddr 0x%llx --> "
	    "row 0x%x (%d bits swapped for cs intlv)\n", iaddr, addr, swapped);

	return (addr);
}

/*ARGSUSED*/
static uint64_t
row_to_iaddr(struct mcamd_hdl *hdl, const struct rct_bnkaddrmode *bamp,
    const struct rct_rcbmap *rcbm, struct rct_csintlv *csid, uint32_t rowaddr)
{
	uint64_t iaddr = 0;
	int abitno, ibitno;
	int nbits = bamp->bam_nrows;

	for (abitno = 0; abitno < nbits; abitno++) {
		if (BIT(rowaddr, abitno) == 0)
			continue;
		ibitno = rcbm->rcb_rowbit[abitno];
		if (MC_RC_CSI_SWAPPED_BIT(csid, ibitno)) {
			ibitno = MC_RC_CSI_BITSWAP(csid, ibitno);
		}
		SETBIT(iaddr, ibitno);
	}

	return (iaddr);
}


static uint32_t
iaddr_to_col(struct mcamd_hdl *hdl, const struct rct_bnkaddrmode *bamp,
    const struct rct_rcbmap *rcbm, uint64_t iaddr)
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

		ibitno = rcbm->rcb_colbit[abitno + bias];

		if (BITVAL(iaddr, ibitno) != 0)
			SETBIT(addr, abitno);
	}

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "iaddr_to_col: iaddr 0x%llx --> "
	    "col 0x%x\n", iaddr, addr);

	return (addr);
}

/*ARGSUSED*/
static uint64_t
col_to_iaddr(struct mcamd_hdl *hdl, const struct rct_bnkaddrmode *bamp,
    const struct rct_rcbmap *rcbm, uint32_t coladdr)
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

		ibitno = rcbm->rcb_colbit[abitno + bias];
		SETBIT(iaddr, ibitno);
	}

	return (iaddr);
}

/*
 * Extract bank bit arguments and swizzle if requested.
 */
static uint32_t
iaddr_to_bank(struct mcamd_hdl *hdl, const struct rct_rcbmap *rcbm,
    const struct rct_bnkswzlinfo *swzlp, uint64_t iaddr)
{
	uint32_t addr = 0;
	int abitno, ibitno, i;

	for (abitno = 0; abitno < rcbm->rcb_nbankbits; abitno++) {
		uint32_t val;

		/*
		 * rcb_bankbit[abitno] tells us which iaddr bit number
		 * will form bit abitno of the bank address
		 */
		ibitno = rcbm->rcb_bankbit[abitno];
		val = BITVAL(iaddr, ibitno);

		/*
		 * If bank swizzling is in operation then xor the bit value
		 * obtained above with other iaddr bits.
		 */
		if (swzlp) {
			for (i = 0; i < MC_RC_SWZLBITS; i++) {
				ibitno = swzlp->bswz_rowbits[abitno][i];
				val ^= BITVAL(iaddr, ibitno);
			}
		}

		if (val)
			SETBIT(addr, abitno);
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
bank_to_iaddr(struct mcamd_hdl *hdl, const struct rct_rcbmap *rcbm,
    const struct rct_bnkswzlinfo *swzlp, uint64_t partiaddr, uint32_t bankaddr)
{
	uint64_t iaddr = 0;
	int abitno, pibitno, i;

	for (abitno = 0; abitno < rcbm->rcb_nbankbits; abitno++) {
		uint32_t val = BITVAL(bankaddr, abitno);
		if (swzlp) {
			for (i = 0; i < MC_RC_SWZLBITS; i++) {
				pibitno = swzlp->bswz_rowbits[abitno][i];
				val ^= BITVAL(partiaddr, pibitno);
			}
		}
		if (val)
			SETBIT(iaddr, rcbm->rcb_bankbit[abitno]);
	}

	return (iaddr);
}

static int
iaddr_to_rcb(struct mcamd_hdl *hdl, uint_t csmode, struct mcprops *mcpp,
    uint64_t iaddr, uint32_t *rowp, uint32_t *colp, uint32_t *bankp)
{
	const struct rct_bnkaddrmode *bamp;
	const struct rct_rcbmap *rcbmp;
	const struct rct_bnkswzlinfo *swzlp = NULL;
	struct rct_csintlv csi;

	if (gettbls(hdl, csmode, mcpp, &bamp, &rcbmp,
	    mcpp->bnkswzl ? &swzlp : NULL, &csi,
	    "iaddr_to_rcb") < 0)
		return (-1);	/* errno already set */

	*rowp = iaddr_to_row(hdl, bamp, rcbmp, &csi, iaddr);
	*colp = iaddr_to_col(hdl, bamp, rcbmp, iaddr);
	*bankp = iaddr_to_bank(hdl, rcbmp, swzlp, iaddr);

	return (0);
}

/*
 * Take a reconstructed InputAddr and undo the normalization described in
 * BKDG 3.29 3.4.4 to include the base address of the MC if no node
 * interleave or to insert the node interleave selection bits.
 */
static int
iaddr_unnormalize(struct mcamd_hdl *hdl, struct mcprops *mcpp, uint64_t iaddr,
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
		 *
		 * Note that the DRAM controller InputAddr is still 36 bits
		 * 35:0 on rev F.
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
    uint64_t iaddr, uint64_t *offsetp)
{
	mcamd_dimm_offset_un_t offset_un;
	uint_t csmode;
	uint32_t bankaddr, rowaddr, coladdr;
	struct mcprops mcp;
	struct csprops csp;

	*offsetp = MCAMD_RC_INVALID_OFFSET;

	if (getmcprops(hdl, mc, "mc_dimm_offset", &mcp) < 0 ||
	    getcsprops(hdl, cs, "mc_dimm_offset", &csp) < 0)
		return (-1);	/* errno already set */

	csmode = MC_CS_MODE(mcp.csbnkmap_reg, csp.num);

	if (iaddr_to_rcb(hdl, csmode, &mcp, iaddr, &rowaddr,
	    &coladdr, &bankaddr) < 0)
		return (-1);	/* errno already set */

	offset_un.do_offset = 0;

	offset_un.do_valid = 1;
	offset_un.do_version = MCAMD_OFFSET_VERSION;
	offset_un.do_rank = (uint32_t)csp.dimmrank;
	offset_un.do_row = rowaddr;
	offset_un.do_bank = bankaddr;
	offset_un.do_col = coladdr;

	*offsetp = offset_un.do_offset;

	return (0);
}

/*
 * Given an MC, DIMM and offset (dimm rank, row, col, internal bank) we
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
	uint64_t iaddr = 0;
	const struct rct_bnkaddrmode *bamp;
	const struct rct_rcbmap *rcbmp;
	const struct rct_bnkswzlinfo *swzlp = NULL;
	struct rct_csintlv csi;
	struct mcprops mcp;
	struct csprops csp;
	uint64_t csmode;
	int maskhi_hi, maskhi_lo, masklo_hi, masklo_lo;

	off_un.do_offset = offset;
	rank = off_un.do_rank;
	bankaddr = off_un.do_bank;
	rowaddr = off_un.do_row;
	coladdr = off_un.do_col;

	mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_offset_to_pa: offset 0x%llx "
	    "-> rank %d bank %d row 0x%x col 0x%x\n", offset,
	    rank, bankaddr, rowaddr, coladdr);

	if (getmcprops(hdl, mc, "mc_offset_to_pa", &mcp) < 0)
		return (-1);	/* errno already set */

	maskhi_hi = MC_CSMASKHI_HIBIT(mcp.rev);
	maskhi_lo = MC_CSMASKHI_LOBIT(mcp.rev);
	masklo_hi = MC_CSMASKLO_HIBIT(mcp.rev);
	masklo_lo = MC_CSMASKLO_LOBIT(mcp.rev);

	/*
	 * Find the chip-select on this dimm using the given rank.
	 */
	for (cs = mcamd_cs_next(hdl, dimm, NULL); cs != NULL;
	    cs = mcamd_cs_next(hdl, dimm, cs)) {
		if (getcsprops(hdl, cs, "mc_offset_to_pa", &csp) < 0)
			return (-1);	/* errno already set */

		if (csp.dimmrank == rank)
			break;
	}

	if (cs == NULL) {
		mcamd_dprintf(hdl, MCAMD_DBG_FLOW, "mc_offset_to_pa: Current "
		    "dimm in this slot does not have a cs using rank %d\n",
		    rank);
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
	}

	/*
	 * If the cs# has been substituted by the online spare then the
	 * given unum is not actually contributing to the system address
	 * map since all accesses to it are redirected.
	 *
	 * If the cs# failed BIOS test it is not in the address map.
	 *
	 * If the cs# is the online spare cs# then it is contributing to
	 * the system address map only if swapped in, and the csbase etc
	 * parameters to use must be those of the bad cs#.
	 */
	if (mcp.badcs != MC_INVALNUM && csp.num == mcp.badcs) {
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
	} else if (csp.testfail) {
		return (mcamd_set_errno(hdl, EMCAMD_NOADDR));
	} else if (mcp.sparecs != MC_INVALNUM && csp.num == mcp.sparecs &&
	    mcp.badcs != MC_INVALNUM) {
		/*
		 * Iterate over all cs# of this memory controller to find
		 * the bad one - the bad cs# need not be on the same dimm
		 * as the spare.
		 */
		for (cs = mcamd_cs_next(hdl, mc, NULL); cs != NULL;
		    cs = mcamd_cs_next(hdl, mc, cs)) {
			mcamd_prop_t csnum;

			if (!mcamd_get_numprop(hdl, cs, MCAMD_PROP_NUM,
			    &csnum)) {
				mcamd_dprintf(hdl, MCAMD_DBG_ERR,
				    "mcamd_offset_to_pa: csnum lookup failed "
				    "while looking for bad cs#");
				return (mcamd_set_errno(hdl,
				    EMCAMD_TREEINVALID));
			}
			if (csnum == mcp.badcs)
				break;
		}

		if (cs == NULL) {
			mcamd_dprintf(hdl, MCAMD_DBG_ERR, "mcamd_offset_to_pa: "
			    "failed to find cs for bad cs#%d\n", mcp.badcs);
			return (mcamd_set_errno(hdl, EMCAMD_TREEINVALID));
		}

		/* found bad cs - reread properties from it instead of spare */
		if (getcsprops(hdl, cs, "mc_offset_to_pa", &csp) < 0)
			return (-1);	/* errno already set */
	}

	csmode = MC_CS_MODE(mcp.csbnkmap_reg, csp.num);

	if (gettbls(hdl, csmode, &mcp, &bamp, &rcbmp,
	    mcp.bnkswzl ? &swzlp : NULL, &csi,
	    "mc_offset_to_pa") < 0)
		return (-1);	/* errno already set */

	/*
	 * If there are umaskable DRAM InputAddr bits the add those bits
	 * to iaddr from the cs base address.
	 */
	if (MC_CSMASK_UNMASKABLE(mcp.rev) != 0) {
		iaddr |= iaddr_add(hdl, iaddr,
		    BITS(csp.base, maskhi_hi + MC_CSMASK_UNMASKABLE(mcp.rev),
		    maskhi_hi + 1), "unmaskable cs basehi bits");
	}

	/*
	 * basehi bits not meing masked pass straight through to the
	 * iaddr.
	 */
	iaddr |= iaddr_add(hdl, iaddr,
	    BITS(csp.base, maskhi_hi, maskhi_lo) &
	    ~BITS(csp.mask, maskhi_hi, maskhi_lo),
	    "cs basehi bits not being masked");

	/*
	 * if cs interleaving is active then baselo address bit are being
	 * masked - pass the rest through.
	 */
	if (mcp.csintlvfctr > 1) {
		iaddr |= iaddr_add(hdl, iaddr,
		    BITS(csp.base, masklo_hi, masklo_lo) &
		    ~BITS(csp.mask, masklo_hi, masklo_lo),
		    "cs baselo bits not being masked");
	}

	/*
	 * Reconstruct iaddr bits from known row address
	 */
	iaddr |= iaddr_add(hdl, iaddr,
	    row_to_iaddr(hdl, bamp, rcbmp, &csi, rowaddr),
	    "add iaddr bits from row");

	/*
	 * Reconstruct iaddr bits from known column address
	 */
	iaddr |= iaddr_add(hdl, iaddr,
	    col_to_iaddr(hdl, bamp, rcbmp, coladdr),
	    "add iaddr bits from col");

	/*
	 * Reconstruct iaddr bits from known internal banksel address
	 */
	iaddr |= iaddr_add(hdl, iaddr,
	    bank_to_iaddr(hdl, rcbmp, swzlp, iaddr, bankaddr),
	    "add iaddr bits from bank");

	/*
	 * Move iaddr up into the range for this MC and insert any
	 * node interleave selection bits.
	 */
	if (iaddr_unnormalize(hdl, &mcp, iaddr, pap) < 0)
		return (-1);	/* errno already set */

	return (0);
}

int
mcamd_cs_size(struct mcamd_hdl *hdl, mcamd_node_t *mc, int csnum, size_t *szp)
{
	uint_t csmode;
	struct mcprops mcp;
	const struct rct_bnkaddrmode *bamp;

	if (getmcprops(hdl, mc, "mcamd_cs_size", &mcp) < 0)
		return (-1);	/* errno already set */

	csmode = MC_CS_MODE(mcp.csbnkmap_reg, csnum);

	if (gettbls(hdl, csmode, &mcp, &bamp, NULL, NULL, NULL,
	    "mcamd_cs_size") < 0)
		return (-1);	/* errno already set */

	*szp = MC_CS_SIZE(bamp, mcp.width);

	return (0);
}
