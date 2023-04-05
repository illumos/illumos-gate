/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _SYS_UMC_H
#define	_SYS_UMC_H

#include <sys/bitext.h>
#include <sys/amdzen/smn.h>

/*
 * Various register definitions for accessing the AMD Unified Memory Controller
 * (UMC) over SMN (the system management network). Note, that the SMN exists
 * independently in each die and must be accessed through the appropriate
 * IOHC.
 *
 * There are effectively four different revisions of the UMC that we know about
 * and support querying:
 *
 *   o DDR4 capable APUs
 *   o DDR4 capable CPUs
 *   o DDR5 capable APUs
 *   o DDR5 capable CPUs
 *
 * In general for a given revision and generation of a controller (DDR4 vs.
 * DDR5), all of the address layouts are the same whether it is for an APU or a
 * CPU. The main difference is generally in the number of features. For example,
 * most APUs may not support the same rank multiplication bits and related in a
 * device. However, unlike the DF where everything changes, the main difference
 * within a generation is just which bits are implemented. This makes it much
 * easier to define UMC information.
 *
 * Between DDR4 and DDR5 based devices, the register locations have shifted;
 * however, generally speaking, the registers themselves are actually the same.
 * Registers here, similar to the DF, have a common form:
 *
 * UMC_<reg name>_<vers>
 *
 * Here, <reg name> would be something like 'BASE', for the UMC
 * UMC::CH::BaseAddr register. <vers> is one of DDR4 or DDR5. When the same
 * register is supported at the same address between versions, then <vers> is
 * elided.
 *
 * For fields inside of these registers, everything follows the same pattern in
 * <sys/amdzen/df.h> which is:
 *
 * UMC_<reg name>_<vers>_GET_<field>
 *
 * Note, <vers> will be elided if the register is the same between the DDR4 and
 * DDR5 versions.
 *
 * Finally, a cautionary note. While the DF provided a way for us to determine
 * what version something is, we have not determined a way to programmatically
 * determine what something supports outside of making notes based on the
 * family, model, and stepping CPUID information. Unfortunately, you must look
 * towards the documentation and find what you need in the PPR (processor
 * programming reference).
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * UMC Channel registers. These are in SMN Space. DDR4 and DDR5 based UMCs share
 * the same base address, somewhat surprisingly. This constructs the appropriate
 * offset and ensures that a caller doesn't exceed the number of known instances
 * of the register.  See smn.h for additional details on SMN addressing.  All
 * UMC registers are 32 bits wide; we check for violations.
 */

static inline smn_reg_t
amdzen_umc_smn_reg(const uint8_t umcno, const smn_reg_def_t def,
    const uint16_t reginst)
{
	const uint32_t APERTURE_BASE = 0x50000;
	const uint32_t APERTURE_MASK = 0xffffe000;

	const uint32_t umc32 = (const uint32_t)umcno;
	const uint32_t reginst32 = (const uint32_t)reginst;

	const uint32_t stride = (def.srd_stride == 0) ? 4 : def.srd_stride;
	const uint32_t nents = (def.srd_nents == 0) ? 1 :
	    (const uint32_t)def.srd_nents;

	ASSERT0(def.srd_size);
	ASSERT3S(def.srd_unit, ==, SMN_UNIT_UMC);
	ASSERT0(def.srd_reg & APERTURE_MASK);
	ASSERT3U(umc32, <, 12);
	ASSERT3U(nents, >, reginst32);

	const uint32_t aperture_off = umc32 << 20;
	ASSERT3U(aperture_off, <=, UINT32_MAX - APERTURE_BASE);

	const uint32_t aperture = APERTURE_BASE + aperture_off;
	ASSERT0(aperture & ~APERTURE_MASK);

	const uint32_t reg = def.srd_reg + reginst32 * stride;
	ASSERT0(reg & APERTURE_MASK);

	return (SMN_MAKE_REG(aperture + reg));
}

/*
 * UMC::CH::BaseAddr, UMC::CH::BaseAddrSec -- determines the base address used
 * to match a chip select. Instances 0/1 always refer to DIMM 0, while
 * instances 2/3 always refer to DIMM 1.
 */
/*CSTYLED*/
#define	D_UMC_BASE	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x00,	\
	.srd_nents = 4	\
}
/*CSTYLED*/
#define	D_UMC_BASE_SEC	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x10,	\
	.srd_nents = 4	\
}
#define	UMC_BASE(u, i)		amdzen_umc_smn_reg(u, D_UMC_BASE, i)
#define	UMC_BASE_SEC(u, i)	amdzen_umc_smn_reg(u, D_UMC_BASE_SEC, i)
#define	UMC_BASE_GET_ADDR(r)	bitx32(r, 31, 1)
#define	UMC_BASE_ADDR_SHIFT	9
#define	UMC_BASE_GET_EN(r)	bitx32(r, 0, 0)

/*
 * UMC::BaseAddrExt, UMC::BaseAddrSecExt -- The first of several extensions to
 * registers that allow more address bits. Note, only present in some DDR5
 * capable SoCs.
 */
/*CSTYLED*/
#define	D_UMC_BASE_EXT_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xb00,	\
	.srd_nents = 4	\
}
/*CSTYLED*/
#define	D_UMC_BASE_EXT_SEC_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xb10,	\
	.srd_nents = 4	\
}
#define	UMC_BASE_EXT_DDR5(u, i)	amdzen_umc_smn_reg(u, D_UMC_BASE_EXT_DDR5, i)
#define	UMC_BASE_EXT_SEC_DDR5(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_BASE_EXT_SEC_DDR5, i)
#define	UMC_BASE_EXT_GET_ADDR(r)	bitx32(r, 7, 0)
#define	UMC_BASE_EXT_ADDR_SHIFT		40


/*
 * UMC::CH::AddrMask, UMC::CH::AddrMaskSec -- This register is used to compare
 * the incoming address to see it matches the base. Tweaking what is used for
 * match is often part of the interleaving strategy.
 */
/*CSTYLED*/
#define	D_UMC_MASK_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x20,	\
	.srd_nents = 2	\
}
/*CSTYLED*/
#define	D_UMC_MASK_SEC_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x28,	\
	.srd_nents = 2	\
}
/*CSTYLED*/
#define	D_UMC_MASK_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x20,	\
	.srd_nents = 4	\
}
/*CSTYLED*/
#define	D_UMC_MASK_SEC_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x30,	\
	.srd_nents = 4	\
}
#define	UMC_MASK_DDR4(u, i)	amdzen_umc_smn_reg(u, D_UMC_MASK_DDR4, i)
#define	UMC_MASK_SEC_DDR4(u, i)	amdzen_umc_smn_reg(u, D_UMC_MASK_SEC_DDR4, i)
#define	UMC_MASK_DDR5(u, i)	amdzen_umc_smn_reg(u, D_UMC_MASK_DDR5, i)
#define	UMC_MASK_SEC_DDR5(u, i)	amdzen_umc_smn_reg(u, D_UMC_MASK_SEC_DDR5, i)
#define	UMC_MASK_GET_ADDR(r)	bitx32(r, 31, 1)
#define	UMC_MASK_ADDR_SHIFT	9

/*
 * UMC::AddrMaskExt, UMC::AddrMaskSecExt -- Extended mask addresses.
 */
/*CSTYLED*/
#define	D_UMC_MASK_EXT_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xb20,	\
	.srd_nents = 4	\
}
/*CSTYLED*/
#define	D_UMC_MASK_EXT_SEC_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xb30,	\
	.srd_nents = 4	\
}
#define	UMC_MASK_EXT_DDR5(u, i)	amdzen_umc_smn_reg(u, D_UMC_MASK_EXT_DDR5, i)
#define	UMC_MASK_EXT_SEC_DDR5(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_MASK_EXT_SEC_DDR5, i)
#define	UMC_MASK_EXT_GET_ADDR(r)	bitx32(r, 7, 0)
#define	UMC_MASK_EXT_ADDR_SHIFT		40

/*
 * UMC::CH::AddrCfg -- This register contains a number of bits that describe how
 * the address is actually used, one per DIMM. Note, not all members are valid
 * for all classes of DIMMs. It's worth calling out that the total number of
 * banks value here describes the total number of banks on the entire chip, e.g.
 * it is bank groups * banks/groups. Therefore to determine the number of
 * banks/group you must subtract the number of bank group bits from the total
 * number of bank bits.
 */
/*CSTYLED*/
#define	D_UMC_ADDRCFG_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x30,	\
	.srd_nents = 2	\
}
/*CSTYLED*/
#define	D_UMC_ADDRCFG_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x40,	\
	.srd_nents = 4	\
}
#define	UMC_ADDRCFG_DDR4(u, i)	amdzen_umc_smn_reg(u, D_UMC_ADDRCFG_DDR4, i)
#define	UMC_ADDRCFG_DDR5(u, i)	amdzen_umc_smn_reg(u, D_UMC_ADDRCFG_DDR5, i)
#define	UMC_ADDRCFG_GET_NBANK_BITS(r)		bitx32(r, 21, 20)
#define	UMC_ADDRCFG_NBANK_BITS_BASE		3
#define	UMC_ADDRCFG_GET_NCOL_BITS(r)		bitx32(r, 19, 16)
#define	UMC_ADDRCFG_NCOL_BITS_BASE		5
#define	UMC_ADDRCFG_GET_NROW_BITS_LO(r)		bitx32(r, 11, 8)
#define	UMC_ADDRCFG_NROW_BITS_LO_BASE		10
#define	UMC_ADDRCFG_GET_NBANKGRP_BITS(r)	bitx32(r, 3, 2)

#define	UMC_ADDRCFG_DDR4_GET_NROW_BITS_HI(r)	bitx32(r, 15, 12)
#define	UMC_ADDRCFG_DDR4_GET_NRM_BITS(r)	bitx32(r, 5, 4)
#define	UMC_ADDRCFG_DDR5_GET_CSXOR(r)		bitx32(r, 31, 30)
#define	UMC_ADDRCFG_DDR5_GET_NRM_BITS(r)	bitx32(r, 6, 4)

/*
 * UMC::CH::AddrSel -- This register is used to program how the actual bits in
 * the normalized address map to the row and bank. While the bank can select
 * which bits in the normalized address are used to construct the bank number,
 * row bits are contiguous from the starting number.
 */
/*CSTYLED*/
#define	D_UMC_ADDRSEL_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x40,	\
	.srd_nents = 2	\
}
/*CSTYLED*/
#define	D_UMC_ADDRSEL_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x50,	\
	.srd_nents = 4	\
}
#define	UMC_ADDRSEL_DDR4(u, i)	amdzen_umc_smn_reg(u, D_UMC_ADDRSEL_DDR4, i)
#define	UMC_ADDRSEL_DDR5(u, i)	amdzen_umc_smn_reg(u, D_UMC_ADDRSEL_DDR5, i)
#define	UMC_ADDRSEL_GET_ROW_LO(r)	bitx32(r, 27, 24)
#define	UMC_ADDRSEL_ROW_LO_BASE		12
#define	UMC_ADDRSEL_GET_BANK4(r)	bitx32(r, 19, 16)
#define	UMC_ADDRSEL_GET_BANK3(r)	bitx32(r, 15, 12)
#define	UMC_ADDRSEL_GET_BANK2(r)	bitx32(r, 11, 8)
#define	UMC_ADDRSEL_GET_BANK1(r)	bitx32(r, 7, 4)
#define	UMC_ADDRSEL_GET_BANK0(r)	bitx32(r, 3, 0)
#define	UMC_ADDRSEL_BANK_BASE		5

#define	UMC_ADDRSEL_DDR4_GET_ROW_HI(r)	bitx32(r, 31, 28)
#define	UMC_ADDRSEL_DDR4_ROW_HI_BASE	24

/*
 * UMC::CH::ColSelLo, UMC::CH::ColSelHi -- This register selects which address
 * bits map to the various column select bits. These registers interleave so in
 * the case of DDR4, it's 0x50, 0x54 for DIMM 0 lo, hi. Then 0x58, 0x5c for
 * DIMM1. DDR5 based entries do something similar; however, instead of being
 * per-DIMM, there is one of these for each CS.
 */
/*CSTYLED*/
#define	D_UMC_COLSEL_LO_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x50,	\
	.srd_nents = 2,	\
	.srd_stride = 8	\
}
/*CSTYLED*/
#define	D_UMC_COLSEL_HI_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x54,	\
	.srd_nents = 2,	\
	.srd_stride = 8	\
}
/*CSTYLED*/
#define	D_UMC_COLSEL_LO_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x60,	\
	.srd_nents = 4,	\
	.srd_stride = 8	\
}
/*CSTYLED*/
#define	D_UMC_COLSEL_HI_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x64,	\
	.srd_nents = 4,	\
	.srd_stride = 8	\
}
#define	UMC_COLSEL_LO_DDR4(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_COLSEL_LO_DDR4, i)
#define	UMC_COLSEL_HI_DDR4(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_COLSEL_HI_DDR4, i)
#define	UMC_COLSEL_LO_DDR5(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_COLSEL_LO_DDR5, i)
#define	UMC_COLSEL_HI_DDR5(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_COLSEL_HI_DDR5, i)

#define	UMC_COLSEL_REMAP_GET_COL(r, x)	bitx32(r, (3 + (4 * (x))), (4 * ((x))))
#define	UMC_COLSEL_LO_BASE		2
#define	UMC_COLSEL_HI_BASE		8

/*
 * UMC::CH::RmSel -- This register contains the bits that determine how the rank
 * is determined. Which fields of this are valid vary a lot in the different
 * parts. The DDR4 and DDR5 versions are different enough that we use totally
 * disjoint definitions. It's also worth noting that DDR5 doesn't have a
 * secondary version of this as it is included in the main register.
 *
 * In general, APUs have some of the MSBS (most significant bit swap) related
 * fields; however, they do not have rank multiplication bits.
 */
/*CSTYLED*/
#define	D_UMC_RMSEL_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x70,	\
	.srd_nents = 2	\
}
/*CSTYLED*/
#define	D_UMC_RMSEL_SEC_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x78,	\
	.srd_nents = 2	\
}
#define	UMC_RMSEL_DDR4(u, i)	amdzen_umc_smn_reg(u, D_UMC_RMSEL_DDR4, i)
#define	UMC_RMSEL_SEC_DDR4(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_RMSEL_SEC_DDR4, i)
#define	UMC_RMSEL_DDR4_GET_INV_MSBO(r)	bitx32(r, 19, 18)
#define	UMC_RMSEL_DDR4_GET_INV_MSBE(r)	bitx32(r, 17, 16)
#define	UMC_RMSEL_DDR4_GET_RM2(r)	bitx32(r, 11, 8)
#define	UMC_RMSEL_DDR4_GET_RM1(r)	bitx32(r, 7, 4)
#define	UMC_RMSEL_DDR4_GET_RM0(r)	bitx32(r, 3, 0)
#define	UMC_RMSEL_BASE			12

/*CSTYLED*/
#define	D_UMC_RMSEL_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x80,	\
	.srd_nents = 4	\
}
#define	UMC_RMSEL_DDR5(u, i)	amdzen_umc_smn_reg(u, D_UMC_RMSEL_DDR5, i)
#define	UMC_RMSEL_DDR5_GET_INV_MSBS_SEC(r)	bitx32(r, 31, 30)
#define	UMC_RMSEL_DDR5_GET_INV_MSBS(r)		bitx32(r, 29, 28)
#define	UMC_RMSEL_DDR5_GET_SUBCHAN(r)	bitx32(r, 19, 16)
#define	UMC_RMSEL_DDR5_SUBCHAN_BASE	5
#define	UMC_RMSEL_DDR5_GET_RM3(r)	bitx32(r, 15, 12)
#define	UMC_RMSEL_DDR5_GET_RM2(r)	bitx32(r, 11, 8)
#define	UMC_RMSEL_DDR5_GET_RM1(r)	bitx32(r, 7, 4)
#define	UMC_RMSEL_DDR5_GET_RM0(r)	bitx32(r, 3, 0)


/*
 * UMC::CH::DimmCfg -- This describes several properties of the DIMM that is
 * installed, such as its overall width or type.
 */
/*CSTYLED*/
#define	D_UMC_DIMMCFG_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x80,	\
	.srd_nents = 2	\
}
/*CSTYLED*/
#define	D_UMC_DIMMCFG_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x90,	\
	.srd_nents = 2	\
}
#define	UMC_DIMMCFG_DDR4(u, i)	amdzen_umc_smn_reg(u, D_UMC_DIMMCFG_DDR4, i)
#define	UMC_DIMMCFG_DDR5(u, i)	amdzen_umc_smn_reg(u, D_UMC_DIMMCFG_DDR5, i)
#define	UMC_DIMMCFG_GET_PKG_RALIGN(r)	bitx32(r, 10, 10)
#define	UMC_DIMMCFG_GET_REFRESH_DIS(r)	bitx32(r, 9, 9)
#define	UMC_DIMMCFG_GET_DQ_SWAP_DIS(r)	bitx32(r, 8, 8)
#define	UMC_DIMMCFG_GET_X16(r)		bitx32(r, 7, 7)
#define	UMC_DIMMCFG_GET_X4(r)		bitx32(r, 6, 6)
#define	UMC_DIMMCFG_GET_LRDIMM(r)	bitx32(r, 5, 5)
#define	UMC_DIMMCFG_GET_RDIMM(r)	bitx32(r, 4, 4)
#define	UMC_DIMMCFG_GET_CISCS(r)	bitx32(r, 3, 3)
#define	UMC_DIMMCFG_GET_3DS(r)		bitx32(r, 2, 2)

#define	UMC_DIMMCFG_DDR4_GET_NVDIMMP(r)	bitx32(r, 12, 12)
#define	UMC_DIMMCFG_DDR4_GET_DDR4e(r)	bitx32(r, 11, 11)
#define	UMC_DIMMCFG_DDR5_GET_RALIGN(r)	bitx32(r, 13, 12)
#define	UMC_DIMMCFG_DDR5_GET_ASYM(r)	bitx32(r, 11, 11)

#define	UMC_DIMMCFG_DDR4_GET_OUTPUT_INV(r)	bitx32(r, 1, 1)
#define	UMC_DIMMCFG_DDR4_GET_MRS_MIRROR(r)	bitx32(r, 0, 0)

/*
 * UMC::CH::AddrHashBank -- These registers contain various instructions about
 * how to hash an address across a bank to influence which bank is used.
 */
/*CSTYLED*/
#define	D_UMC_BANK_HASH_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xc8,	\
	.srd_nents = 5	\
}
/*CSTYLED*/
#define	D_UMC_BANK_HASH_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x98,	\
	.srd_nents = 5	\
}
#define	UMC_BANK_HASH_DDR4(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_BANK_HASH_DDR4, i)
#define	UMC_BANK_HASH_DDR5(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_BANK_HASH_DDR5, i)
#define	UMC_BANK_HASH_GET_ROW(r)	bitx32(r, 31, 14)
#define	UMC_BANK_HASH_GET_COL(r)	bitx32(r, 13, 1)
#define	UMC_BANK_HASH_GET_EN(r)		bitx32(r, 0, 0)

/*
 * UMC::CH::AddrHashRM -- This hash register describes how to transform a UMC
 * address when trying to do rank hashing. Note, instance 3 is is reserved in
 * DDR5 modes.
 */
/*CSTYLED*/
#define	D_UMC_RANK_HASH_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xdc,	\
	.srd_nents = 3	\
}
/*CSTYLED*/
#define	D_UMC_RANK_HASH_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xb0,	\
	.srd_nents = 4	\
}
#define	UMC_RANK_HASH_DDR4(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_RANK_HASH_DDR4, i)
#define	UMC_RANK_HASH_DDR5(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_RANK_HASH_DDR5, i)
#define	UMC_RANK_HASH_GET_ADDR(r)	bitx32(r, 31, 1)
#define	UMC_RANK_HASH_SHIFT		9
#define	UMC_RANK_HASH_GET_EN(r)		bitx32(r, 0, 0)

/*
 * UMC::AddrHashRMExt -- Extended rank hash addresses.
 */
/*CSTYLED*/
#define	D_UMC_RANK_HASH_EXT_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xbb0,	\
	.srd_nents = 4	\
}
#define	UMC_RANK_HASH_EXT_DDR5(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_RANK_HASH_EXT_DDR5, i)
#define	UMC_RANK_HASH_EXT_GET_ADDR(r)	bitx32(r, 7, 0)
#define	UMC_RANK_HASH_EXT_ADDR_SHIFT	40

/*
 * UMC::CH::AddrHashPC, UMC::CH::AddrHashPC2 -- These registers describe a hash
 * to use for the DDR5 sub-channel. Note, in the DDR4 case this is actually the
 * upper two rank hash registers defined above because on the systems where this
 * occurs for DDR4, they only have up to one rank hash.
 */
/*CSTYLED*/
#define	D_UMC_PC_HASH_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xc0	\
}
/*CSTYLED*/
#define	D_UMC_PC_HASH2_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xc4	\
}
#define	UMC_PC_HASH_DDR4(u)	UMC_RANK_HASH_DDR4(u, 1)
#define	UMC_PC_HASH2_DDR4(u)	UMC_RANK_HASH_DDR4(u, 2)
#define	UMC_PC_HASH_DDR5(u)	amdzen_umc_smn_reg(u, D_UMC_PC_HASH_DDR5, 0)
#define	UMC_PC_HASH2_DDR5(u)	amdzen_umc_smn_reg(u, D_UMC_PC_HASH2_DDR5, 0)
#define	UMC_PC_HASH_GET_ROW(r)		bitx32(r, 31, 14)
#define	UMC_PC_HASH_GET_COL(r)		bitx32(r, 13, 1)
#define	UMC_PC_HASH_GET_EN(r)		bitx32(r, 0, 0)
#define	UMC_PC_HASH2_GET_BANK(r)	bitx32(r, 4, 0)

/*
 * UMC::CH::AddrHashCS -- Hashing: chip-select edition. Note, these can
 * ultimately cause you to change which DIMM is being actually accessed.
 */
/*CSTYLED*/
#define	D_UMC_CS_HASH_DDR4	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xe8,	\
	.srd_nents = 2	\
}
/*CSTYLED*/
#define	D_UMC_CS_HASH_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xc8,	\
	.srd_nents = 2	\
}
#define	UMC_CS_HASH_DDR4(u, i)	amdzen_umc_smn_reg(u, D_UMC_CS_HASH_DDR4, i)
#define	UMC_CS_HASH_DDR5(u, i)	amdzen_umc_smn_reg(u, D_UMC_CS_HASH_DDR5, i)
#define	UMC_CS_HASH_GET_ADDR(r)		bitx32(r, 31, 1)
#define	UMC_CS_HASH_SHIFT		9
#define	UMC_CS_HASH_GET_EN(r)		bitx32(r, 0, 0)

/*
 * UMC::AddrHashExtCS -- Extended chip-select hash addresses.
 */
/*CSTYLED*/
#define	D_UMC_CS_HASH_EXT_DDR5	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xbc8,	\
	.srd_nents = 2	\
}
#define	UMC_CS_HASH_EXT_DDR5(u, i)	\
    amdzen_umc_smn_reg(u, D_UMC_CS_HASH_EXT_DDR5, i)
#define	UMC_CS_HASH_EXT_GET_ADDR(r)	bitx32(r, 7, 0)
#define	UMC_CS_HASH_EXT_ADDR_SHIFT	40

/*
 * UMC::CH::UmcConfig -- This register controls various features of the device.
 * For our purposes we mostly care about seeing if ECC is enabled and a DIMM
 * type.
 */
/*CSTYLED*/
#define	D_UMC_UMCCFG	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x100	\
}
#define	UMC_UMCCFG(u)	amdzen_umc_smn_reg(u, D_UMC_UMCCFG, 0)
#define	UMC_UMCCFG_GET_READY(r)		bitx32(r, 31, 31)
#define	UMC_UMCCFG_GET_ECC_EN(r)	bitx32(r, 12, 12)
#define	UMC_UMCCFG_GET_BURST_CTL(r)	bitx32(r, 11, 10)
#define	UMC_UMCCFG_GET_BURST_LEN(r)	bitx32(r, 9, 8)
#define	UMC_UMCCFG_GET_DDR_TYPE(r)	bitx32(r, 2, 0)
#define	UMC_UMCCFG_DDR4_T_DDR4		0
#define	UMC_UMCCFG_DDR4_T_LPDDR4	5

#define	UMC_UMCCFG_DDR5_T_DDR4		0
#define	UMC_UMCCFG_DDR5_T_DDR5		1
#define	UMC_UMCCFG_DDR5_T_LPDDR4	5
#define	UMC_UMCCFG_DDR5_T_LPDDR5	6

/*
 * UMC::CH::DataCtrl -- Various settings around whether data encryption or
 * scrambling is enabled. Note, this register really changes a bunch from family
 * to family.
 */
/*CSTYLED*/
#define	D_UMC_DATACTL	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x144	\
}
#define	UMC_DATACTL(u)		amdzen_umc_smn_reg(u, D_UMC_DATACTL, 0)
#define	UMC_DATACTL_GET_ENCR_EN(r)	bitx32(r, 8, 8)
#define	UMC_DATACTL_GET_SCRAM_EN(r)	bitx32(r, 0, 0)

#define	UMC_DATACTL_DDR4_GET_TWEAK(r)		bitx32(r, 19, 16)
#define	UMC_DATACTL_DDR4_GET_VMG2M(r)		bitx32(r, 12, 12)
#define	UMC_DATACTL_DDR4_GET_FORCE_ENCR(r)	bitx32(r, 11, 11)

#define	UMC_DATACTL_DDR5_GET_TWEAK(r)	bitx32(r, 16, 16)
#define	UMC_DATACTL_DDR5_GET_XTS(r)	bitx32(r, 14, 14)
#define	UMC_DATACTL_DDR5_GET_AES256(r)	bitx32(r, 13, 13)

/*
 * UMC::CH:EccCtrl -- Various settings around how ECC operates.
 */
/*CSTYLED*/
#define	D_UMC_ECCCTL	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0x14c	\
}
#define	UMC_ECCCTL(u)	amdzen_umc_smn_reg(u, D_UMC_ECCCTL, 0)
#define	UMC_ECCCTL_GET_RD_EN(r)		bitx32(x, 10, 10)
#define	UMC_ECCCTL_GET_X16(r)		bitx32(x, 9, 9)
#define	UMC_ECCCTL_GET_UC_FATAL(r)	bitx32(x, 8, 8)
#define	UMC_ECCCTL_GET_SYM_SIZE(r)	bitx32(x, 7, 7)
#define	UMC_ECCCTL_GET_BIT_IL(r)	bitx32(x, 6, 6)
#define	UMC_ECCCTL_GET_HIST_EN(r)	bitx32(x, 5, 5)
#define	UMC_ECCCTL_GET_SW_SYM_EN(r)	bitx32(x, 4, 4)
#define	UMC_ECCCTL_GET_WR_EN(r)		bitx32(x, 0, 0)

/*
 * Note, while this group appears generic and is the same in both DDR4/DDR5
 * systems, this is not always present on every SoC and seems to depend on
 * something else inside the chip.
 */
#define	UMC_ECCCTL_DDR_GET_PI(r)	bitx32(r, 13, 13)
#define	UMC_ECCCTL_DDR_GET_PF_DIS(r)	bitx32(r, 12, 12)
#define	UMC_ECCCTL_DDR_GET_SDP_OVR(r)	bitx32(x, 11, 11)
#define	UMC_ECCCTL_DDR_GET_REPLAY_EN(r)	bitx32(x, 1, 1)

#define	UMC_ECCCTL_DDR5_GET_PIN_RED(r)	bitx32(r, 14, 14)

/*
 * UMC::CH::DramConfiguration -- Various configuration settings for the channel
 * as a whole. The definition of this register is unfortunately a mess across
 * lots of different families. Here are the unique variants that we know of:
 *
 *  o Pure DDR4/LPDDR4 support: Zen 1-3, exceptions below
 *  o DDR4 UMC extended for LPDDR5: Van Gogh and Mendocino
 *  o Pure DDR5/LPDDR5 support: Zen 4+, Rembrandt
 *
 * We call these DDR4, HYB, and DDR5 respectively. The LPDDR bits only have
 * additions to the existing DDR4 base registers and a different set of MEMCLK
 * values for LPDDR5. The DDR4 and DDR5 registers are very different, so we just
 * have entirely separate register bit definitions.
 *
 * But wait, there's more. The hardware has support for up to four different
 * memory P-states, each of which is 0x100 bytes apart. Memory P-state 0 appears
 * to be the primary Memory P-state active.
 *
 * Care must be taken with the memory clock in all cases. The memory clock is
 * measured in MHz; however, DIMMs often are operating in MT/s. In particular
 * LPDDR5 based settings have more nuance here around determining the actual
 * MT/s. See also UMC::CH::DebugMisc.
 */
/*CSTYLED*/
#define	D_UMC_DRAMCFG	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC, \
	.srd_reg = 0x200,	\
	.srd_nents = 4,	\
	.srd_stride = 0x100,	\
}

#define	UMC_DRAMCFG(u, i)	amdzen_umc_smn_reg(u, D_UMC_DRAMCFG, i)

/*
 * All known DDR4 based UMCs whether for APUs or targetting LPDDR4 generally
 * have the same set of values listed here; however, we've only seen bits 16 and
 * 17 defined on platforms with LPDDR4 support (Renoir and Cezanne) and bits 13
 * and 14 on some Zen 3 platforms (e.g. Milan).
 */
#define	UMC_DRAMCFG_LPDDR4_GET_WRPST(r)	bitx32(r, 17, 17)
#define	UMC_DRAMCFG_LPDDR4_GET_RDPST(r)	bitx32(r, 16, 16)
#define	UMC_DRAMCFG_DDR4_GET_PARDIS(r)	bitx32(r, 14, 14)
#define	UMC_DRAMCFG_DDR4_GET_CRCDIS(r)	bitx32(r, 13, 13)
#define	UMC_DRAMCFG_DDR4_GET_PRE2T(r)	bitx32(r, 12, 12)
#define	UMC_DRAMCFG_DDR4_GET_GRDNEN(r)	bitx32(r, 11, 11)
#define	UMC_DRAMCFG_DDR4_GET_CMD2T(r)	bitx32(r, 10, 10)
#define	UMC_DRAMCFG_DDR4_GET_BNKGRP(r)	bitx32(r, 8, 8)
#define	UMC_DRAMCFG_DDR4_GET_MEMCLK(r)	bitx32(r, 6, 0)
#define	UMC_DRAMCFG_DDR4_MEMCLK_667	0x14
#define	UMC_DRAMCFG_DDR4_MEMCLK_800	0x18
#define	UMC_DRAMCFG_DDR4_MEMCLK_933	0x1c
#define	UMC_DRAMCFG_DDR4_MEMCLK_1067	0x20
#define	UMC_DRAMCFG_DDR4_MEMCLK_1200	0x24
#define	UMC_DRAMCFG_DDR4_MEMCLK_1333	0x28
#define	UMC_DRAMCFG_DDR4_MEMCLK_1467	0x2c
#define	UMC_DRAMCFG_DDR4_MEMCLK_1600	0x30

/*
 * The following are core registers supported by the pure DDR5 based
 * implementations. Registers that are only valid when operating in LPDDR5 use
 * LPDDR5 as a prefix.
 */
#define	UMC_DRAMCFG_DDR5_GET_UGTFCLK(r)		bitx32(r, 31, 31)
#define	UMC_DRAMCFG_LPDDR5_GET_RDECCEN(r)	bitx32(r, 29, 29)
#define	UMC_DRAMCFG_LPDDR5_GET_WRECCEN(r)	bitx32(r, 28, 28)
#define	UMC_DRAMCFG_LPDDR5_GET_WCKRATIO(r)	bitx32(r, 27, 26)
#define	UMC_DRAMCFG_WCLKRATIO_SAME	0
#define	UMC_DRAMCFG_WCLKRATIO_1TO2	1
#define	UMC_DRAMCFG_WCLKRATIO_1TO4	2
#define	UMC_DRAMCFG_LPDDR5_GET_WCKALWAYS(r)	bitx32(r, 25, 25)
#define	UMC_DRAMCFG_LPDDR5_GET_WRPOST(r)	bitx32(r, 23, 23)
#define	UMC_DRAMCFG_LPDDR5_GET_RDPOST(r)	bitx32(r, 22, 22)
#define	UMC_DRAMCFG_DDR5_GET_CMDPARDIS(r)	bitx32(r, 21, 21)
#define	UMC_DRAMCFG_DDR5_GET_WRCRCDIS(r)	bitx32(r, 20, 20)
#define	UMC_DRAMCFG_DDR5_GET_PRE2T(r)		bitx32(r, 19, 19)
#define	UMC_DRAMCFG_DDR5_GET_GRDNEN(r)		bitx32(r, 18, 18)
#define	UMC_DRAMCFG_DDR5_GET_CMD2T(r)		bitx32(r, 17, 17)
#define	UMC_DRAMCFG_DDR5_GET_BNKGRP(r)		bitx32(r, 16, 16)
/*
 * The memory clock here is defined as a value in MHz. In DDR5 platforms this is
 * always multiplied by 2 to get to the actual transfer rate due to the double
 * data rate. In LPDDR5 this is more nuanced. In particular, one needs to check
 * the WCKRATIO value. When it is 1:2 or 1:4 you multiply the value we have in
 * the register and we're good to go. When the value is 0, then the only thing
 * the data clock is the same ratio as the memory clock. It is possible that a
 * ratio is present for the command clock though, but we cannot determine that.
 */
#define	UMC_DRAMCFG_DDR5_GET_MEMCLK(r)		bitx32(r, 15, 0)

/*
 * Our Hybrid DDR4 + LPDDDR5 UMC follows the same group as above with the
 * following additions.
 *
 * In LPDDR4 mode the memory clock uses the DDR4 values. In LPDDR5 mode it has
 * its own set of values. These frequencies assume a 1:2 ratio between the WCLK
 * and related. While the PPR discusses that these could have a 1:4 ratio, there
 * is no setting to indicate a 1:4 ratio is supported.
 */
#define	UMC_DRAMCFG_HYB_GET_LP5ECCORD(r)	bitx32(r, 26, 26)
#define	UMC_DRAMCFG_HYB_GET_LP5RDECCEN(r)	bitx32(r, 25, 25)
#define	UMC_DRAMCFG_HYB_GET_LP5WRECCEN(r)	bitx32(r, 24, 24)
#define	UMC_DRAMCFG_HYB_GET_WCLKRATIO(r)	bitx32(r, 22, 21)
#define	UMC_DRAMCFG_HYB_GET_MEMCLK(r)		bitx32(r, 7, 0)
#define	UMC_DRAMCFG_HYB_MEMCLK_333	0x5
#define	UMC_DRAMCFG_HYB_MEMCLK_400	0x6
#define	UMC_DRAMCFG_HYB_MEMCLK_533	0x8
#define	UMC_DRAMCFG_HYB_MEMCLK_687	0x0a
#define	UMC_DRAMCFG_HYB_MEMCLK_750	0x0b
#define	UMC_DRAMCFG_HYB_MEMCLK_800	0x0c
#define	UMC_DRAMCFG_HYB_MEMCLK_933	0x0e
#define	UMC_DRAMCFG_HYB_MEMCLK_1066	0x10
#define	UMC_DRAMCFG_HYB_MEMCLK_1200	0x12
#define	UMC_DRAMCFG_HYB_MEMCLK_1375	0x14
#define	UMC_DRAMCFG_HYB_MEMCLK_1500	0x16
#define	UMC_DRAMCFG_HYB_MEMCLK_1600	0x18

/*
 * UMC::Ch::UmcCap, UMC::CH::UmcCapHi -- Various capability registers and
 * feature disables. We mostly just record these for future us for debugging
 * purposes. They aren't used as part of memory decoding.
 */
/*CSTYLED*/
#define	D_UMC_UMCCAP	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xdf0	\
}
/*CSTYLED*/
#define	D_UMC_UMCCAP_HI	(const smn_reg_def_t){	\
	.srd_unit = SMN_UNIT_UMC,	\
	.srd_reg = 0xdf4	\
}
#define	UMC_UMCCAP(u)		amdzen_umc_smn_reg(u, D_UMC_UMCCAP, 0)
#define	UMC_UMCCAP_GET_CHAN_DIS(r)	bitx32(r, 19, 19)
#define	UMC_UMCCAP_GET_ENC_DIS(r)	bitx32(r, 18, 18)
#define	UMC_UMCCAP_GET_ECC_DIS(r)	bitx32(r, 17, 17)
#define	UMC_UMCCAP_GET_REG_DIS(r)	bitx32(r, 16, 16)
#define	UMC_UMCCAP_HI(u)	amdzen_umc_smn_reg(u, D_UMC_UMCCAP_HI, 0)
#define	UMC_UMCACAP_HI_GET_CHIPKILL(r)	bitx32(r, 31, 31)
#define	UMC_UMCACAP_HI_GET_ECC_EN(r)	bitx32(r, 30, 30)

#ifdef __cplusplus
}
#endif

#endif /* _SYS_UMC_H */
