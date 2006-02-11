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
 * Chip-Select Bank Address Mode Encodings - BKDG 3.29 3.5.6
 */
static const struct bankaddr_mode bankaddr_modes_pre_d[];
static const struct bankaddr_mode bankaddr_modes_d_e[];

static const struct bam_desc {
	int	rev;
	int	nmodes;
	const struct bankaddr_mode *modetbl;
} bankaddr_modes[] = {
	{ MC_REV_PRE_D, 7, bankaddr_modes_pre_d },
	{ MC_REV_D_E, 11, bankaddr_modes_d_e },
};

/*
 * DRAM Address Mappings for bank/row/column - BKDG 3.29 3.5.6.1
 */
static const struct csrcb_map_tbl dram_addrmap_pre_d_128;
static const struct csrcb_map_tbl dram_addrmap_pre_d_64;
static const struct csrcb_map_tbl dram_addrmap_d_e_64;
static const struct csrcb_map_tbl dram_addrmap_d_e_128;

static const struct rcbmap_desc {
	int nmodes;
	const struct csrcb_map_tbl *rcbmap;
} rcbmaps[] = {
	{ 7, &dram_addrmap_pre_d_64 },
	{ 7, &dram_addrmap_pre_d_128 },
	{ 11, &dram_addrmap_d_e_64 },
	{ 11, &dram_addrmap_d_e_128 },
};

/*
 * Lookup the Chip-Select Bank Address Mode Encoding table for a given
 * chip revision and chip-select mode.
 */
const struct bankaddr_mode *
rct_bankaddr_mode(uint_t mcrev, uint_t csmode)
{
	int i;
	const struct bam_desc *bdp = bankaddr_modes;

	for (i = 0; i < sizeof (bankaddr_modes) / sizeof (struct bam_desc);
	    i++, bdp++) {
		if (bdp->rev == mcrev && csmode < bdp->nmodes)
			return (&bdp->modetbl[csmode]);

	}

	return (NULL);
}

/*
 * Lookup the DRAM Address Mapping table for a given chip revision, access
 * width, bank-swizzle and chip-select mode.
 */
const struct csrcb_map *
rct_rcbmap(uint_t mcrev, int width, uint_t csmode)
{
	const struct csrcb_map_tbl *rcbm;
	int i;

	for (i = 0; i < sizeof (rcbmaps) / sizeof (struct rcbmap_desc); i++) {
		rcbm = rcbmaps[i].rcbmap;
		if (rcbm->mt_rev == mcrev && rcbm->mt_width == width &&
		    csmode < rcbmaps[i].nmodes)
			return (&rcbm->mt_csmap[csmode]);
	}

	return (NULL);
}

/*
 * DRAM Address Mapping in Interleaving Mode - BKDG 3.29 section 3.5.6.2.
 *
 * Chip-select interleave is performed by addressing across the columns
 * of the first row of internal bank-select 0 on a chip-select, then the
 * next row on internal bank-select 1, then 2 then 3;  instead of then
 * moving on to the next row of this chip-select we then rotate across
 * other chip-selects in the interleave.  The row/column/bank mappings
 * described elsewhere in this file show that a DRAM InputAddr breaks down
 * as follows (example is the first line of table 7 which is for a 32MB
 * chip-select requiring 25 bits to address all of it) for the non-interleaved
 * case:
 *
 * chip-selection bits |    offset within chip-select bits      |
 *		       | row bits | bank bits | column bits | - |
 *                      24      13 12       11 10          3 2 0
 *
 * The high-order chip-selection bits select the chip-select and the
 * offset bits offset within the chosen chip-select.
 *
 * To establish say a 2-way interleave in which we consume all of one
 * row number and all internal bank numbers on one cs before moving on
 * to the next to do the same we will target the first row bit - bit 13;
 * a 4-way interleave would use bits 14 and 13, and an 8-way interleave
 * bits 15, 14 and 13.  We swap the chosen bits with the least significant
 * high order chip-selection bits.
 *
 * Tables 13-16 of BKDG 3.5.6.2 really just describe the above.  Working
 * out the high-order bits to swap is easy since that is derived directly
 * from the chip-select size.  The low-order bits depend on the device
 * parameters since we need to target the least significant row address bits -
 * but we have that information from the rcbmaps since the first row bit
 * simply follows the last bank address bit.
 *
 * Short version: we will do tables 13 to 16 programatically rather than
 * replicating those tables.
 */

/*
 * Yet another highbit function.  This really needs to go to common source.
 * Returns range 0 to 64 inclusive;
 */
static int
topbit(uint64_t i)
{
	int h = 1;

	if (i == 0)
		return (0);

	if (i & 0xffffffff00000000ULL) {
		h += 32;
		i >>= 32;
	}

	if (i & 0xffff0000) {
		h += 16;
		i >>= 16;
	}

	if (i & 0xff00) {
		h += 8;
		i >>= 8;
	}

	if (i & 0xf0) {
		h += 4;
		i >>= 4;
	}

	if (i & 0xc) {
		h += 2;
		i >>= 2;
	}

	if (i & 0x2)
		h += 1;

	return (h);
}

void
rct_csintlv_bits(uint_t mcrev, int width, uint_t csmode, int factor,
    struct csintlv_desc *csid)
{
	int i, lstbnkbit;
	size_t csz;
	const struct bankaddr_mode *bam;
	const struct csrcb_map *rcm;

	/*
	 * Dispatch the three "Not implemented" exceptions.
	 */
	if ((mcrev == MC_REV_PRE_D && width == 128 && csmode == 0x6) ||
	    (mcrev == MC_REV_D_E && width == 128 && (csmode == 0x9 ||
	    csmode == 0xa))) {
		csid->csi_factor = 0;
		return;
	}

	if ((bam = rct_bankaddr_mode(mcrev, csmode)) == NULL ||
	    (rcm = rct_rcbmap(mcrev, width, csmode)) == NULL) {
		csid->csi_factor = 0;
		return;
	}

	csz = MC_CS_SIZE(bam, width);

	switch (factor) {
		case 2:
			csid->csi_nbits = 1;
			break;
		case 4:
			csid->csi_nbits = 2;
			break;
		case 8:
			csid->csi_nbits = 3;
			break;
		default:
			csid->csi_factor = 0;
			return;
	}

	csid->csi_hibit = topbit(csz) - 1;

	lstbnkbit = 0;
	for (i = 0; i < MC_RC_BANKBITS; i++) {
		/* first bank arg for a bit is "real" bank bit */
		if (rcm->csrcb_bankargs[i][0] > lstbnkbit)
			lstbnkbit = rcm->csrcb_bankargs[i][0];
	}

	/* first row bit is immediately after last bank bit */
	csid->csi_lobit = lstbnkbit + 1;

	csid->csi_factor = factor;
}


/*
 * General notes for CS Bank Address Mode Encoding tables.
 *
 * These are the tables of BKDG 3.29 section 3.5.6.  They are indexed
 * by chip-select mode.  Where the numbers of rows and columns is
 * ambiguous (as it is for a number of rev CG and earlier cases)
 * the bam_config should be initialized to 1 and the numbers of rows
 * and columns should be the maximums.
 */

/*
 * Chip Select Bank Address Mode Encoding for rev CG and earlier.
 */
static const struct bankaddr_mode bankaddr_modes_pre_d[] = {
	{	/* 000 */
		32, 12, 8
	},
	{	/* 001 */
		64, 12, 9
	},
	{	/* 010 */
		128, 13, 10, 1
	},
	{	/* 011 */
		256, 13, 11, 1
	},
	{	/* 100 */
		512, 14, 11, 1
	},
	{	/* 101 */
		1024, 14, 12, 1
	},
	{	/* 110 */
		2048, 14, 12
	}
};

/*
 * Chip Select Bank Address Mode Encoding for revs D and E.
 */
static const struct bankaddr_mode bankaddr_modes_d_e[] = {
	{	/* 0000 */
		32, 12, 8
	},
	{	/* 0001 */
		64, 12, 9
	},
	{	/* 0010 */
		128, 13, 9
	},
	{	/* 0011 */
		128, 12, 10
	},
	{	/* 0100 */
		256, 13, 10
	},
	{	/* 0101 */
		512, 14, 10
	},
	{	/* 0110 */
		256, 12, 11
	},
	{	/* 0111 */
		512, 13, 11
	},
	{	/* 1000 */
		1024, 14, 11
	},
	{	/* 1001 */
		1024, 13, 12
	},
	{	/* 1010 */
		2048, 14, 12
	}
};

/*
 * General notes on Row/Column/Bank table initialisation.
 *
 * These are the tables 7, 8, 9, 10, 11 and 12 of BKDG 3.29 section 3.5.6.1.
 * They apply in non-interleave (node or cs) mode and describe how for
 * a given revision, access width, bank-swizzle mode, and current chip-select
 * mode the row, column and internal sdram bank are derived from the
 * normalizied InputAddr presented to the DRAM controller.
 *
 * The mt_csmap array is indexed by chip-select mode.  Within it the
 * bankargs, rowbits and colbits arrays are indexed by bit number, so
 * match the BKDG tables if the latter are read right-to-left.
 *
 * The bankargs list up to three bit numbers per bank bit.  For revisions
 * CG and earlier there is no bank swizzling, so just a single number
 * should be listed.  Revisions D and E have the same row/column/bank mapping,
 * but rev E has the additional feature of being able to xor two row bits
 * into each bank bit.  The consumer will know whether they are using bank
 * swizzling - if so then they should xor the bankargs bits together.
 * The first argument must be the bit number not already used in forming
 * part of the row address - eg in table 12 for csmode 0000b bank address
 * bit 0 is bit 12 xor bit 18 xor bit 21, and 18 and 21 are also mentioned in
 * the row address (bits 10 and 1) so we must list bit 12 first.  We will
 * use this information in chip-select interleave decoding in which we need
 * to know which is the first bit after column and bank address bits.
 *
 * Column address A10 is always used for the Precharge All signal.  Where
 * "PC" appears in the BKDG tables we will include MC_PC_ALL in the
 * corresponding bit position.
 *
 * For some rev CG and earlier chipselect modes the number of rows and columns
 * is ambiguous.  This is reflected in these tables by some bit being
 * duplicated between row and column address.  In practice we will follow
 * the convention of always assigning the floating bit to the row address.
 */

/*
 * Row/Column/Bank address mappings for rev CG in 64-bit mode, no interleave.
 * See BKDG 3.29 3.5.6 Table 7.
 */
static const struct csrcb_map_tbl dram_addrmap_pre_d_64 = {
	MC_REV_PRE_D,
	64,
	{
	{   /* 000 */
	    { { 11 }, { 12 } },
	    { 19, 20, 21, 22, 23, 24, 13, 14, 15, 16, 17, 18 },
	    { 3, 4, 5, 6, 7, 8, 9, 10 }
	},
	{   /* 001 */
	    { { 13 }, { 12 } },
	    { 19, 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11 }
	},
	{   /* 010 */
	    { { 13 }, { 12 } },
	    { 19, 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18, 26 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 26 }
	},
	{   /* 011 */
	    { { 13 }, { 14 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 27 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 27 }
	},
	{   /* 100 */
	    { { 13 }, { 14 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 28 }
	},
	{   /* 101 */
	    { { 15 }, { 14 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 29, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13, 28 }
	},
	{   /* 110 */
	    { { 15 }, { 14 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 29, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13, 30 }
	},
	/*
	 * remainder unused
	 */
	}

};

/*
 * Row/Column/Bank address mappings for rev CG in 128-bit mode, no interleave.
 * See BKDG 3.29 3.5.6 Table 8.
 */
static const struct csrcb_map_tbl dram_addrmap_pre_d_128 = {
	MC_REV_PRE_D,
	128,
	{
	{   /* 000 */
	    { { 12 }, { 13 } },
	    { 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18, 19 },
	    { 4, 5, 6, 7, 8, 9, 10, 11 }
	},
	{   /* 001 */
	    { { 14 }, { 13 } },
	    { 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 19 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 010 */
	    { { 14 }, { 13 } },
	    { 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 19, 27 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 27 }
	},
	{   /* 011 */
	    { { 14 }, { 15 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 19, 28 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 28 }
	},
	{   /* 100 */
	    { { 14 }, { 15 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 29 }
	},
	{   /* 101 */
	    { { 16 }, { 15 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 30, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14, 29 }
	},
	{   /* 110 */
	    { { 16 }, { 15 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 30, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14, 31 }
	},
	/*
	 * remainder unused
	 */
	}
};

/*
 * Row/Column/Bank address mappings for rev D/E in 64-bit mode, no interleave.
 * See BKDG 3.29 3.5.6 Table 9.
 */
static const struct csrcb_map_tbl dram_addrmap_d_e_64 = {
	MC_REV_D_E,
	64,
	{
	{   /* 0000 */
	    { { 11, 17, 20 }, { 12, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 13, 14, 15, 16, 17, 18 },
	    { 3, 4, 5, 6, 7, 8, 9, 10 }
	},
	{   /* 0001 */
	    { { 12, 17, 20 }, { 13, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18, 26 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11 }
	},
	{   /* 0010 */
	    { { 12, 17, 20 }, { 13, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18, 26 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11 }
	},
	{   /* 0011 */
	    { { 13, 17, 20 }, { 14, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 0100 */
	    { { 13, 17, 20 }, { 14, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 0101 */
	    { { 13, 17, 20 }, { 14, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 0110 */
	    { { 14, 17, 20 }, { 15, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 28, 29 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 }
	},
	{   /* 0111 */
	    { { 14, 17, 20 }, { 15, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 28, 29 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 }
	},
	{   /* 1000 */
	    { { 14, 17, 20 }, { 15, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 28, 29 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 }
	},
	{   /* 1001 */
	    { { 15, 17, 20 }, { 16, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 17, 18, 29, 30 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13, 14 }
	},
	{   /* 1010 */
	    { { 15, 17, 20 }, { 16, 18, 21 } },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 17, 18, 29, 30 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13, 14 }
	},
	/*
	 * remainder unused
	 */
	}
};

/*
 * Row/Column/Bank address mappings for rev D/E in 128-bit mode, no interleave.
 * See BKDG 3.29 3.5.6 Table 9.
 */
static const struct csrcb_map_tbl dram_addrmap_d_e_128 = {
	MC_REV_D_E,
	128,
	{
	{   /* 0000 */
	    { { 12, 18, 21 }, { 13, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18, 19 },
	    { 4, 5, 6, 7, 8, 9, 10, 11 }
	},
	{   /* 0001 */
	    { { 13, 18, 21 }, { 14, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 19, 27 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 0010 */
	    { { 13, 18, 21 }, { 14, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 19, 27 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 0011 */
	    { { 14, 18, 21 }, { 15, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 }
	},
	{   /* 0100 */
	    { { 14, 18, 21 }, { 15, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 }
	},
	{   /* 0101 */
	    { { 14, 18, 21 }, { 15, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 }
	},
	{   /* 0110 */
	    { { 15, 18, 21 }, { 16, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 28, 17, 18, 19, 29, 30 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 }
	},
	{   /* 0111 */
	    { { 15, 18, 21 }, { 16, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 28, 17, 18, 19, 29, 30 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 }
	},
	{   /* 1000 */
	    { { 15, 18, 21 }, { 16, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 28, 17, 18, 19, 29, 30 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 }
	},
	{   /* 1001 */
	    { { 16, 18, 21 }, { 17, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 18, 19, 30, 31 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14, 15 }
	},
	{   /* 1010 */
	    { { 16, 18, 21 }, { 17, 19, 22 } },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 18, 19, 30, 31 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14, 15 }
	},
	/*
	 * remainder unused
	 */
	}
};
