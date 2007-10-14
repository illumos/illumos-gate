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
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mcamd_api.h>
#include <mcamd_err.h>
#include <mcamd_rowcol_impl.h>

/*
 * =========== Chip-Select Bank Address Mode Encodings =======================
 */

/* Individual table declarations */
static const struct rct_bnkaddrmode bnkaddr_tbls_pre_d[];
static const struct rct_bnkaddrmode bnkaddr_tbls_d_e[];
static const struct rct_bnkaddrmode bnkaddr_tbls_f[];

/* Managing bank address mode tables */
static const struct _bnkaddrmode_tbldesc {
	uint_t	revmask;
	int	nmodes;
	const struct rct_bnkaddrmode *modetbl;
} bnkaddr_tbls[] = {
	{ MC_F_REVS_BC, 7, bnkaddr_tbls_pre_d },
	{ MC_F_REVS_DE, 11, bnkaddr_tbls_d_e },
	{ MC_F_REVS_FG, 12, bnkaddr_tbls_f },
};

/*
 * =========== DRAM Address Mappings for bank/row/column =====================
 */


/* Individual table declarations */
struct _rcbmap_tbl {
	uint_t mt_revmask;		/* revision to which this applies */
	int mt_width;			/* MC mode (64 or 128) */
	const struct rct_rcbmap mt_csmap[MC_RC_CSMODES];
};

static const struct _rcbmap_tbl dram_addrmap_pre_d_64;
static const struct _rcbmap_tbl dram_addrmap_pre_d_128;
static const struct _rcbmap_tbl dram_addrmap_d_e_64;
static const struct _rcbmap_tbl dram_addrmap_d_e_128;
static const struct _rcbmap_tbl dram_addrmap_f_64;
static const struct _rcbmap_tbl dram_addrmap_f_128;

/* Managing row/column/bank tables */
static const struct _rcbmap_tbldesc {
	int nmodes;
	const struct _rcbmap_tbl *rcbmap;
} rcbmap_tbls[] = {
	{ 7, &dram_addrmap_pre_d_64 },
	{ 7, &dram_addrmap_pre_d_128 },
	{ 11, &dram_addrmap_d_e_64 },
	{ 11, &dram_addrmap_d_e_128 },
	{ 12, &dram_addrmap_f_64 },
	{ 12, &dram_addrmap_f_128 },
};

/*
 * =========== Bank swizzling information ====================================
 */

/* Individual table declarations */
struct _bnkswzl_tbl {
	uint_t swzt_revmask;		/* revision to which this applies */
	int swzt_width;			/* MC mode (64 or 128) */
	const struct rct_bnkswzlinfo swzt_bits;
};

static const struct _bnkswzl_tbl bnswzl_info_e_64;
static const struct _bnkswzl_tbl bnswzl_info_e_128;
static const struct _bnkswzl_tbl bnswzl_info_f_64;
static const struct _bnkswzl_tbl bnswzl_info_f_128;

/* Managing bank swizzle tables */
static const struct _bnkswzl_tbl *bnkswzl_tbls[] = {
	&bnswzl_info_e_64,
	&bnswzl_info_e_128,
	&bnswzl_info_f_64,
	&bnswzl_info_f_128,
};

/*
 * ======================================================================
 * | Tables reflecting those in the BKDG				|
 * ======================================================================
 */

/*
 * DRAM Address Mapping in Interleaving Mode
 *
 * Chip-select interleave is performed by addressing across the columns
 * of the first row of internal bank-select 0 on a chip-select, then the
 * next row on internal bank-select 1, then 2 then 3;  instead of then
 * moving on to the next row of this chip-select we then rotate across
 * other chip-selects in the interleave.  The row/column/bank mappings
 * described elsewhere in this file show that a DRAM InputAddr breaks down
 * as follows, using an example for CS Mode 0000 revision CG and earlier 64-bit
 * mode; the cs size is 32MB, requiring 25 bits to address all of it.
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
 * The BKDG interleave tables really just describe the above.  Working
 * out the high-order bits to swap is easy since that is derived directly
 * from the chip-select size.  The low-order bits depend on the device
 * parameters since we need to target the least significant row address bits -
 * but we have that information from the rcbmap_tbls since the first row bit
 * simply follows the last bank address bit.
 */

/*
 * General notes for CS Bank Address Mode Encoding tables.
 *
 * These are indexed by chip-select mode.  Where the numbers of rows and
 * columns is ambiguous (as it is for a number of rev CG and earlier cases)
 * the bam_config should be initialized to 1 and the numbers of rows
 * and columns should be the maximums.
 */

/*
 * Chip Select Bank Address Mode Encoding for rev CG and earlier.
 */
static const struct rct_bnkaddrmode bnkaddr_tbls_pre_d[] = {
	{	/* 000 */
		32, 12, 8
	},
	{	/* 001 */
		64, 12, 9
	},
	{	/* 010 */
		128, 13, 10, 1	/* AMBIG */
	},
	{	/* 011 */
		256, 13, 11, 1	/* AMBIG */
	},
	{	/* 100 */
		512, 14, 11, 1	/* AMBIG */
	},
	{	/* 101 */
		1024, 14, 12, 1	/* AMBIG */
	},
	{	/* 110 */
		2048, 14, 12
	}
};

/*
 * Chip Select Bank Address Mode Encoding for revs D and E.
 */
static const struct rct_bnkaddrmode bnkaddr_tbls_d_e[] = {
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
 * Chip Select Bank Address Mode Encoding for rev F
 */
static const struct rct_bnkaddrmode bnkaddr_tbls_f[] = {
	{	/* 0000 */
		128, 13, 9
	},
	{	/* 0001 */
		256, 13, 10
	},
	{	/* 0010 */
		512, 14, 10
	},
	{	/* 0011 */
		512, 13, 11
	},
	{	/* 0100 */
		512, 13, 10
	},
	{	/* 0101 */
		1024, 14, 10
	},
	{	/* 0110 */
		1024, 14, 11
	},
	{	/* 0111 */
		2048, 15, 10
	},
	{	/* 1000 */
		2048, 14, 11
	},
	{	/* 1001 */
		4096, 15, 11
	},
	{	/* 1010 */
		4096, 16, 10
	},
	{	/* 1011 */
		8192, 16, 11
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
static const struct _rcbmap_tbl dram_addrmap_pre_d_64 = {
	MC_F_REVS_BC,
	64,
	{
	{   /* 000 */
	    2, { 11, 12 },
	    { 19, 20, 21, 22, 23, 24, 13, 14, 15, 16, 17, 18 },
	    { 3, 4, 5, 6, 7, 8, 9, 10 }
	},
	{   /* 001 */
	    2, { 13, 12 },
	    { 19, 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11 }
	},
	{   /* 010 */
	    2, { 13, 12 },
	    { 19, 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18, 26 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 26 }
	},
	{   /* 011 */
	    2, { 13, 14 },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 27 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 27 }
	},
	{   /* 100 */
	    2, { 13, 14 },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 28 }
	},
	{   /* 101 */
	    2, { 15, 14 },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 29, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13, 28 }
	},
	{   /* 110 */
	    2, { 15, 14 },
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
static const struct _rcbmap_tbl dram_addrmap_pre_d_128 = {
	MC_F_REVS_BC,
	128,
	{
	{   /* 000 */
	    2, { 12, 13 },
	    { 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18, 19 },
	    { 4, 5, 6, 7, 8, 9, 10, 11 }
	},
	{   /* 001 */
	    2, { 14, 13 },
	    { 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 19 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 010 */
	    2, { 14, 13 },
	    { 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 19, 27 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 27 }
	},
	{   /* 011 */
	    2, { 14, 15 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 19, 28 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 28 }
	},
	{   /* 100 */
	    2, { 14, 15 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 29 }
	},
	{   /* 101 */
	    2, { 16, 15 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 30, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14, 29 }
	},
	{   /* 110 */
	    2, { 16, 15 },
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
static const struct _rcbmap_tbl dram_addrmap_d_e_64 = {
	MC_F_REVS_DE,
	64,
	{
	{   /* 0000 */
	    2, { 11, 12 },
	    { 19, 20, 21, 22, 23, 24, 13, 14, 15, 16, 17, 18 },
	    { 3, 4, 5, 6, 7, 8, 9, 10 }
	},
	{   /* 0001 */
	    2, { 12, 13 },
	    { 19, 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18, 26 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11 }
	},
	{   /* 0010 */
	    2, { 12, 13 },
	    { 19, 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18, 26 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11 }
	},
	{   /* 0011 */
	    2, { 13, 14 },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 0100 */
	    2, { 13, 14 },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 0101 */
	    2, { 13, 14 },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 27, 28 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 0110 */
	    2, { 14, 15 },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 28, 29 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 }
	},
	{   /* 0111 */
	    2, { 14, 15 },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 28, 29 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 }
	},
	{   /* 1000 */
	    2, { 14, 15 },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 28, 29 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 }
	},
	{   /* 1001 */
	    2, { 15, 16 },
	    { 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 17, 18, 29, 30 },
	    { 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13, 14 }
	},
	{   /* 1010 */
	    2, { 15, 16 },
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
static const struct _rcbmap_tbl dram_addrmap_d_e_128 = {
	MC_F_REVS_DE,
	128,
	{
	{   /* 0000 */
	    2, { 12, 13 },
	    { 20, 21, 22, 23, 24, 25, 14, 15, 16, 17, 18, 19 },
	    { 4, 5, 6, 7, 8, 9, 10, 11 }
	},
	{   /* 0001 */
	    2, { 13, 14 },
	    { 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 19, 27 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 0010 */
	    2, { 13, 14 },
	    { 20, 21, 22, 23, 24, 25, 26, 15, 16, 17, 18, 19, 27 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{   /* 0011 */
	    2, { 14, 15 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 }
	},
	{   /* 0100 */
	    2, { 14, 15 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 }
	},
	{   /* 0101 */
	    2, { 14, 15 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 16, 17, 18, 19, 28, 29 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 }
	},
	{   /* 0110 */
	    2, { 15, 16 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 28, 17, 18, 19, 29, 30 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 }
	},
	{   /* 0111 */
	    2, { 15, 16 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 28, 17, 18, 19, 29, 30 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 }
	},
	{   /* 1000 */
	    2, { 15, 16 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 28, 17, 18, 19, 29, 30 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 }
	},
	{   /* 1001 */
	    2, { 16, 17 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 18, 19, 30, 31 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14, 15 }
	},
	{   /* 1010 */
	    2, { 16, 17 },
	    { 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 18, 19, 30, 31 },
	    { 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14, 15 }
	},
	/*
	 * remainder unused
	 */
	}
};

/*
 * Row/Column/Bank address mappings for revs F/G in 64-bit mode, no interleave.
 */
static const struct _rcbmap_tbl dram_addrmap_f_64 = {
	MC_F_REVS_FG,
	64,
	{
	{	/* 0000 */
		2, { 12, 13 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 14, 15, 16, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11 },
	},
	{	/* 0001 */
		2, { 13, 14 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 15, 16, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 },
	},
	{	/* 0010 */
		2, { 13, 14 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 15, 16, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 },
	},
	{	/* 0011 */
		2, { 14, 15 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 16, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 },
	},
	{	/* 0100 */
		3, { 13, 14, 15 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 16, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 },
	},
	{	/* 0101 */
		3, { 13, 14, 15 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 16, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{	/* 0110 */
		2, { 14, 15 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 16, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 },
	},
	{	/* 0111 */
		3, { 13, 14, 15 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 16, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{	/* 1000 */
		3, { 14, 15, 16 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 },
	},
	{	/* 1001 */
		3, { 14, 15, 16 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 },
	},
	{	/* 1010 */
		3, { 13, 14, 15 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
		    16, 17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12 }
	},
	{	/* 1011 */
		3, { 14, 15, 16 },
		{ 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		    17 },
		{ 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, MC_PC_ALL, 13 },
	},
	/*
	 * remainder unused
	 */
	}
};

/*
 * Row/Column/Bank address mappings for revs F/G in 128-bit mode, no interleave.
 */
static const struct _rcbmap_tbl dram_addrmap_f_128 = {
	MC_F_REVS_FG,
	128,
	{
	{	/* 0000 */
		2, { 13, 14 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 15, 16, 17, 18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12 },
	},
	{	/* 0001 */
		2, { 14, 15 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 16, 17, 18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 },
	},
	{	/* 0010 */
		2, { 14, 15 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 16, 17, 18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 },
	},
	{	/* 0011 */
		2, { 15, 16 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 17, 18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 },
	},
	{	/* 0100 */
		3, { 14, 15, 16 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 17, 18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 },
	},
	{	/* 0101 */
		3, { 14, 15, 16 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 17, 18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 },
	},
	{	/* 0110 */
		2, { 15, 16 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 17, 18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 },
	},
	{	/* 0111 */
		3, { 14, 15, 16 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
		    17, 18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 },
	},
	{	/* 1000 */
		3, { 15, 16, 17 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
		    18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 },
	},
	{	/* 1001 */
		3, { 15, 16, 17 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		    18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 },
	},
	{	/* 1010 */
		3, { 14, 15, 16 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32,
		    17, 18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13 },
	},
	{	/* 1011 */
		3, { 15, 16, 17 },
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33,
		    18 },
		{ 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, MC_PC_ALL, 14 },
	},
	/*
	 * remainder unused
	 */
	}
};

/*
 * Bank swizzling is an option in revisions E and later.  Each internal-bank-
 * select address bit is xor'd with two row address bits.  Which row
 * address bits to use is not dependent on bank address mode but on
 * revision and dram controller width alone.
 *
 * While rev E only supports 2 bank address bits, rev F supports 3 but not
 * all chip-select bank address modes use all 3.  These tables will list
 * the row bits to use in swizzling for the maximum number of supported
 * bank address bits - the consumer musr determine how many should be
 * applied (listed in the above row/col/bank tables).
 */

static const struct _bnkswzl_tbl bnswzl_info_e_64 = {
	MC_F_REV_E,
	64,
	{
	    {
		{ 17, 20 },		/* rows bits to swizzle with BA0 */
		{ 18, 21 },		/* rows bits to swizzle with BA1 */
		/* only 2 bankaddr bits on rev E */
	    }
	}
};

static const struct _bnkswzl_tbl bnswzl_info_e_128 = {
	MC_F_REV_E,
	128,
	{
	    {
		{ 18, 21 },		/* rows bits to swizzle with BA0 */
		{ 19, 22 },		/* rows bits to swizzle with BA1 */
		/* only 2 bankaddr bits on rev E */
	    }
	}
};

static const struct _bnkswzl_tbl bnswzl_info_f_64 = {
	MC_F_REVS_FG,
	64,
	{
	    {
		{ 17, 22 },		/* rows bits to swizzle with BA0 */
		{ 18, 23 },		/* rows bits to swizzle with BA1 */
		{ 19, 24 },		/* rows bits to swizzle with BA2 */
	    }
	}
};

static const struct _bnkswzl_tbl bnswzl_info_f_128 = {
	MC_F_REVS_FG,
	128,
	{
	    {
		{ 18, 23 },		/* rows bits to swizzle with BA0 */
		{ 19, 24 },		/* rows bits to swizzle with BA1 */
		{ 20, 25 },		/* rows bits to swizzle with BA2 */
	    }
	}
};

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

/*
 * Lookup the Chip-Select Bank Address Mode Encoding table for a given
 * chip revision and chip-select mode.
 */
const struct rct_bnkaddrmode *
rct_bnkaddrmode(uint_t mcrev, uint_t csmode)
{
	int i;
	const struct _bnkaddrmode_tbldesc *bdp = bnkaddr_tbls;

	for (i = 0; i < sizeof (bnkaddr_tbls) /
	    sizeof (struct _bnkaddrmode_tbldesc);
	    i++, bdp++) {
		if (MC_REV_MATCH(mcrev, bdp->revmask) && csmode < bdp->nmodes)
			return (&bdp->modetbl[csmode]);

	}

	return (NULL);
}

/*
 * Lookup the DRAM Address Mapping table for a given chip revision, access
 * width, bank-swizzle and chip-select mode.
 */
const struct rct_rcbmap *
rct_rcbmap(uint_t mcrev, int width, uint_t csmode)
{
	const struct _rcbmap_tbl *rcbm;
	int i;

	for (i = 0; i < sizeof (rcbmap_tbls) /
	    sizeof (struct _rcbmap_tbldesc); i++) {
		rcbm = rcbmap_tbls[i].rcbmap;
		if (MC_REV_MATCH(mcrev, rcbm->mt_revmask) &&
		    rcbm->mt_width == width && csmode < rcbmap_tbls[i].nmodes)
			return (&rcbm->mt_csmap[csmode]);
	}

	return (NULL);
}

/*
 * Lookup the bank swizzling information for a given chip revision and
 * access width.
 */
const struct rct_bnkswzlinfo *
rct_bnkswzlinfo(uint_t mcrev, int width)
{
	int i;
	const struct _bnkswzl_tbl *swztp;

	for (i = 0; i < sizeof (bnkswzl_tbls) /
	    sizeof (struct rcb_bnkswzl_tbl *); i++) {
		swztp = bnkswzl_tbls[i];
		if (MC_REV_MATCH(mcrev, swztp->swzt_revmask) &&
		    swztp->swzt_width == width)
			return (&swztp->swzt_bits);
	}

	return (NULL);
}

void
rct_csintlv_bits(uint_t mcrev, int width, uint_t csmode, int factor,
    struct rct_csintlv *csid)
{
	int i, lstbnkbit;
	size_t csz;
	const struct rct_bnkaddrmode *bam;
	const struct rct_rcbmap *rcm;

	/*
	 * 8-way cs interleave for some large cs sizes in 128-bit mode is
	 * not implemented prior to rev F.
	 */
	if (factor == 8 && width == 128 &&
	    ((MC_REV_MATCH(mcrev, MC_F_REVS_BC) && csmode == 0x6) ||
	    (MC_REV_MATCH(mcrev, MC_F_REVS_DE) &&
	    (csmode == 0x9 || csmode == 0xa)))) {
		csid->csi_factor = 0;
		return;
	}

	if ((bam = rct_bnkaddrmode(mcrev, csmode)) == NULL ||
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

	/*
	 * The first row bit is immediately after the last bank bit.
	 */
	lstbnkbit = 0;
	for (i = 0; i < rcm->rcb_nbankbits; i++)
		if (rcm->rcb_bankbit[i] > lstbnkbit)
			lstbnkbit = rcm->rcb_bankbit[i];

	csid->csi_lobit = lstbnkbit + 1;

	csid->csi_factor = factor;
}
