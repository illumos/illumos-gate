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

#ifndef _MC_AMD_H
#define	_MC_AMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Definitions describing various memory controller constant properties and
 * the structure of configuration registers.
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Configuration constants
 */
#define	MC_CHIP_NDIMM		8	/* max dimms per MC */
#define	MC_CHIP_NCS		8	/* number of chip-selects per MC */
#define	MC_CHIP_DIMMRANKMAX	4	/* largest number of ranks per dimm */
#define	MC_CHIP_DIMMPERCS	2	/* max number of dimms per cs */
#define	MC_CHIP_DIMMPAIR(csnum)	(csnum / MC_CHIP_DIMMPERCS)

/*
 * Encoding of chip version variations that we need to distinguish
 */
#define	MC_REV_UNKNOWN	-1u	/* unknown AMD revision */
#define	MC_REV_PRE_D	0	/* B/C/CG */
#define	MC_REV_D_E	1	/* D or E */
#define	MC_REV_F	2	/* F */

/*
 * BKDG 3.29 section 3.4.4.1 - DRAM base i registers
 */
#define	MC_AM_DB_DRAMBASE_MASK	0xffff0000
#define	MC_AM_DB_DRAMBASE_LSHFT	8
#define	MC_AM_DB_DRAMBASE(regval) \
	(((uint64_t)(regval) & MC_AM_DB_DRAMBASE_MASK) << \
	MC_AM_DB_DRAMBASE_LSHFT)
#define	MC_AM_DB_INTLVEN_MASK	0x00000700
#define	MC_AM_DB_INTLVEN_SHIFT	8
#define	MC_AM_DB_WE		0x00000002
#define	MC_AM_DB_RE		0x00000001

/*
 * BKDG 3.29 section 3.4.4.2 - DRAM limit i registers
 */
#define	MC_AM_DL_DRAMLIM_MASK	0xffff0000
#define	MC_AM_DL_DRAMLIM_SHIFT	16
#define	MC_AM_DL_DRAMLIM_LSHFT	8
#define	MC_AM_DL_DRAMLIM(regval) \
	((((uint64_t)(regval) & MC_AM_DL_DRAMLIM_MASK) << \
	MC_AM_DL_DRAMLIM_LSHFT) | ((regval) ? \
	((1 << (MC_AM_DL_DRAMLIM_SHIFT + MC_AM_DL_DRAMLIM_LSHFT)) - 1) : 0))
#define	MC_AM_DL_INTLVSEL_MASK	0x00000700
#define	MC_AM_DL_INTLVSEL_SHIFT	8
#define	MC_AM_DL_DSTNODE_MASK	0x00000007

/*
 * BKDG 3.29 section 3.5.4 - DRAM CS Base Address Registers.
 *
 * MC_DC_CSB_CSBASE combines the BaseAddrHi and BaseAddrLo into a single
 * uint64_t, shifting them into the dram address bits they describe.
 */
#define	MC_DC_CSB_BASEHI_MASK	0xffe00000
#define	MC_DC_CSB_BASEHI_LSHFT	4

#define	MC_DC_CSB_BASELO_MASK	0x0000fe00
#define	MC_DC_CSB_BASELO_LSHFT	4

#define	MC_DC_CSB_CSBASE(regval) \
	((((uint64_t)(regval) & MC_DC_CSB_BASEHI_MASK) << \
	MC_DC_CSB_BASEHI_LSHFT) | (((uint64_t)(regval) & \
	MC_DC_CSB_BASELO_MASK) << MC_DC_CSB_BASELO_LSHFT))

#define	MC_DC_CSB_CSBE		0x00000001

/*
 * BKDG 3.29 section 3.5.5 - DRAM CS Mask Registers.
 *
 * MC_DC_CSM_CSMASK combines the AddrMaskHi and AddrMaskLo into a single
 * uint64_t, shifting them into the dram address bit positions they mask.
 * It also fills the gaps between high and low mask and below the low mask.
 * MC_DC_CSM_UNMASKED_BITS indicates the number of high dram address bits
 * above MC_DC_CSM_MASKHI_HIBIT that cannot be masked.
 */
#define	MC_DC_CSM_MASKHI_MASK	0x3fe00000
#define	MC_DC_CSM_MASKHI_LSHFT	4
#define	MC_DC_CSM_MASKHI_LOBIT	25
#define	MC_DC_CSM_MASKHI_HIBIT	33

#define	MC_DC_CSM_MASKLO_MASK	0x0000fe00
#define	MC_DC_CSM_MASKLO_LOBIT	13
#define	MC_DC_CSM_MASKLO_HIBIT	19
#define	MC_DC_CSM_MASKLO_LSHFT	4

#define	MC_DC_CSM_MASKFILL	0x1f01fff	/* [24:20] and [12:0] */

#define	MC_DC_CSM_UNMASKED_BITS	2

#define	MC_DC_CSM_CSMASK(regval) \
	((((uint64_t)(regval) & MC_DC_CSM_MASKHI_MASK) << \
	MC_DC_CSM_MASKHI_LSHFT) | (((uint64_t)(regval) & \
	MC_DC_CSM_MASKLO_MASK) << MC_DC_CSM_MASKLO_LSHFT) | \
	MC_DC_CSM_MASKFILL)

/*
 * BKDG 3.29 section 3.5.6 - DRAM Bank Address Mapping Register
 */
#define	MC_DC_BAM_CSBANK_MASK	0x0000000f
#define	MC_DC_BAM_CSBANK_SHIFT	4
#define	MC_DC_BAM_CSBANK_SWIZZLE 0x40000000

/*
 * BKDG 3.29 section 3.4.8 - DRAM Hole register, revs E and later
 */
#define	MC_DC_HOLE_VALID		0x00000001
#define	MC_DC_HOLE_OFFSET_MASK		0x0000ff00
#define	MC_DC_HOLE_OFFSET_LSHIFT	16

/*
 * BKDG 3.29 section 3.5.11  - DRAM configuration high and low registers.
 * The following defines may be applied to a uint64_t made by
 * concatenating those two 32-bit registers.
 */
#define	MC_DC_DCFG_DLL_DIS		0x0000000000000001
#define	MC_DC_DCFG_D_DRV		0x0000000000000002
#define	MC_DC_DCFG_QFC_EN		0x0000000000000004
#define	MC_DC_DCFG_DISDQSYS		0x0000000000000008
#define	MC_DC_DCFG_BURST2OPT		0x0000000000000020
#define	MC_DC_DCFG_MOD64BITMUX		0x0000000000000040
#define	MC_DC_DCFG_PWRDWNTRIEN		0x0000000000000080 /* >= rev E */
#define	MC_DC_DCFG_SCRATCHBIT		0x0000000000000080 /* <= rev D */
#define	MC_DC_DCFG_DRAMINIT		0x0000000000000100
#define	MC_DC_DCFG_DUALDIMMEN		0x0000000000000200
#define	MC_DC_DCFG_DRAMENABLE		0x0000000000000400
#define	MC_DC_DCFG_MEMCLRSTATUS		0x0000000000000800
#define	MC_DC_DCFG_ESR			0x0000000000001000
#define	MC_DC_DCFG_SR_S			0x0000000000002000
#define	MC_DC_DCFG_RDWRQBYP_MASK	0x000000000000c000
#define	MC_DC_DCFG_128			0x0000000000010000
#define	MC_DC_DCFG_DIMMECEN		0x0000000000020000
#define	MC_DC_DCFG_UNBUFFDIMM		0x0000000000040000
#define	MC_DC_DCFG_32BYTEEN		0x0000000000080000
#define	MC_DC_DCFG_X4DIMMS_MASK		0x0000000000f00000
#define	MC_DC_DCFG_X4DIMMS_SHIFT	20
#define	MC_DC_DCFG_DISINRCVRS		0x0000000001000000
#define	MC_DC_DCFG_BYPMAX_MASK		0x000000000e000000
#define	MC_DC_DCFG_EN2T			0x0000000010000000
#define	MC_DC_DCFG_UPPERCSMAP		0x0000000020000000
#define	MC_DC_DCFG_PWRDOWNCTL_MASK	0x00000000c0000000
#define	MC_DC_DCFG_ASYNCLAT_MASK	0x0000000f00000000
#define	MC_DC_DCFG_RDPREAMBLE_MASK	0x00000f0000000000
#define	MC_DC_DCFG_MEMDQDRVSTREN_MASK	0x0000600000000000
#define	MC_DC_DCFG_DISABLEJITTER	0x0000800000000000
#define	MC_DC_DCFG_ILD_LMT_MASK		0x0007000000000000
#define	MC_DC_DCFG_ECC_EN		0x0008000000000000
#define	MC_DC_DCFG_MEMCLK_MASK		0x0070000000000000
#define	MC_DC_DCFG_MCR			0x0200000000000000
#define	MC_DC_DCFG_MC0_EN		0x0400000000000000
#define	MC_DC_DCFG_MC1_EN		0x0800000000000000
#define	MC_DC_DCFG_MC2_EN		0x1000000000000000
#define	MC_DC_DCFG_MC3_EN		0x2000000000000000
#define	MC_DC_DCFG_ODDDIVISORCORRECT	0x8000000000000000

#ifdef __cplusplus
}
#endif

#endif /* _MC_AMD_H */
