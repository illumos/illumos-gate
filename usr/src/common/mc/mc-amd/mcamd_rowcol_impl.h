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

#define	MC_RC_ROW_MAX		16	/* maximum number of row address bits */
#define	MC_RC_COL_MAX		12	/* maximum number of col address bits */
#define	MC_RC_BANKBITS_MAX	3	/* number of internal banksel bits */
#define	MC_RC_CSMODES		16	/* max number of cs bankaddr modes */
#define	MC_RC_SWZLBITS		2	/* number of row bits in swizzle */

struct rct_bnkaddrmode {
	int bam_sizemb;			/* DIMM size in MB */
	int bam_nrows;			/* number of row address bits */
	int bam_ncols;			/* number of column address bits */
	int bam_ambig;			/* numbers are maximums; keep last */
};

struct rct_rcbmap {
	int rcb_nbankbits;			/* # of bank address bits */
	int rcb_bankbit[MC_RC_BANKBITS_MAX];	/* bank address bits */
	int rcb_rowbit[MC_RC_ROW_MAX];
	int rcb_colbit[MC_RC_COL_MAX + 1];	/* one for MC_PC_ALL */
};

struct rct_bnkswzlinfo {
	int bswz_rowbits[MC_RC_BANKBITS_MAX][MC_RC_SWZLBITS];
};

struct rct_csintlv {
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

extern const struct rct_bnkaddrmode *rct_bnkaddrmode(uint_t, uint_t);
extern const struct rct_rcbmap *rct_rcbmap(uint_t, int, uint_t);
extern const struct rct_bnkswzlinfo *rct_bnkswzlinfo(uint_t, int);
extern void rct_csintlv_bits(uint_t, int, uint_t, int, struct rct_csintlv *);

#ifdef __cplusplus
}
#endif

#endif /* _MCAMD_ROWCOL_IMPL_H */
