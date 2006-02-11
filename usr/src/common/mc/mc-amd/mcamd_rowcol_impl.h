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

#ifndef _MCAMD_ROWCOL_IMPL_H
#define	_MCAMD_ROWCOL_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <mcamd_api.h>
#include <sys/mc_amd.h>

#ifdef __cplusplus
extern "C" {
#endif

#define	MC_PC_COLADDRBIT	10	/* col address bit used for precharge */
#define	MC_PC_ALL		-1	/* marker used in tables */

#define	MC_CS_SCALE		(1024 * 1024)
#define	MC_CS_SIZE(bam, width) \
	((size_t)bam->bam_sizemb * MC_CS_SCALE * ((width) == 128 ? 2 : 1))

#define	MC_CS_MODE(csbmap, csnum) \
	(csbmap >> MC_CHIP_DIMMPAIR(csnum) * MC_DC_BAM_CSBANK_SHIFT & \
	MC_DC_BAM_CSBANK_MASK)

#define	BIT(val, num) ((val) & 1ULL << num)

#define	BITS(val, high, low) \
	((val) & (((2ULL << (high)) - 1) & ~((1ULL << (low)) - 1)))

#define	SETBIT(var, num) (var |= (1ULL << (num)))

#define	BITVAL(var, num) ((BIT(var, num) >> (num)) & 1ULL)

#define	MC_RC_ROW_MAX	14	/* maximum number of row address bits */
#define	MC_RC_COL_MAX	12	/* maximum number of col address bits */
#define	MC_RC_BANKBITS	2	/* number of internal banksel bits */
#define	MC_RC_BANKARGS	3	/* bits used for 1 banksel bit */
#define	MC_RC_CSMODES	16	/* max number of cs bankaddr modes */

/*
 * Row, column and bank mapping is derived after allowing for interleave
 * from the normalized dram address through the tables of BKDG 3.29
 * section 3.5.6.1.  We have tables for:
 *
 *	. rev CG and earlier, 64-bit MC mode
 *	. rev CG and earlier, 128-bit MC mode
 *	. rev D and later, 64-bit MC mode (no bank swizzling if rev E)
 *	. rev D and later, 128-bit MC mode (no bank swizzling if rev E)
 *	. rev E and later, 64-bit MC mode with bank swizzling
 *	. rev E and later, 128-bit MC mode with bank swizzling
 *
 * Each table is indexed by CS Mode (equivalently, CS size) and tells us
 * which bits of the normalized dram address (i.e., the address modified for
 * the local MC base address and with node interleave selection bits removed)
 * to use in forming the column address, row address and internal bank
 * selection.
 *
 * Note that for rev CG and earlier there is some overloading of CS mode
 * encoding such that we do not know the number of row and column address
 * bits from the CS mode alone, e.g., for 128MB DIMM modules we may have
 * 13 row bits and 9 column, or 12 row and 10 column.  In these case the
 * tables held in the structures defined below will have a duplicated bit
 * number in the row and column bits.  In these ambiguous cases cm_rc_ambig
 * should be set in the table.
 */

struct bankaddr_mode {
	int bam_sizemb;			/* DIMM size in MB */
	int bam_nrows;			/* number of row address bits */
	int bam_ncols;			/* number of column address bits */
	int bam_ambig;			/* numbers are maximums; keep last */
};

struct csrcb_map {
	int csrcb_bankargs[MC_RC_BANKBITS][MC_RC_BANKARGS];
	int csrcb_rowbits[MC_RC_ROW_MAX];
	int csrcb_colbits[MC_RC_COL_MAX + 1];	/* one for MC_PC_ALL */
};

struct csrcb_map_tbl {
	int mt_rev;			/* revision to which this applies */
	int mt_width;			/* MC mode (64 or 128) */
	struct csrcb_map mt_csmap[MC_RC_CSMODES];
};

struct csintlv_desc {
	int csi_factor;			/* cs interleave factor */
	int csi_hibit;			/* first non-offset bit in addr */
	int csi_lobit;			/* first row bit in addr */
	int csi_nbits;			/* number of bits to swap in mask */
};

#define	MC_RC_CSI_SWAPPED_BIT(csidp, n)				\
	(csidp->csi_factor && n >= csidp->csi_lobit &&		\
	n <= csidp->csi_lobit + csidp->csi_nbits - 1)

#define	MC_RC_CSI_BITSWAP(csidp, n)				\
	(csidp->csi_hibit + n - csidp->csi_lobit)

extern const struct bankaddr_mode *rct_bankaddr_mode(uint_t, uint_t);
extern const struct csrcb_map *rct_rcbmap(uint_t, int, uint_t);
extern void rct_csintlv_bits(uint_t, int, uint_t, int, struct csintlv_desc *);

#ifdef __cplusplus
}
#endif

#endif /* _MCAMD_ROWCOL_IMPL_H */
