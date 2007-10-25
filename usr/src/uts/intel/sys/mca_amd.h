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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MCA_AMD_H
#define	_SYS_MCA_AMD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/mca_x86.h>

/*
 * Constants for the Machine Check Architecture as implemented on AMD CPUs.
 */

#ifdef __cplusplus
extern "C" {
#endif

#define	AMD_MSR_MCG_CAP			0x179
#define	AMD_MSR_MCG_STATUS		0x17a
#define	AMD_MSR_MCG_CTL			0x17b

#define	AMD_MCA_BANK_DC			0	/* Data Cache */
#define	AMD_MCA_BANK_IC			1	/* Instruction Cache */
#define	AMD_MCA_BANK_BU			2	/* Bus Unit */
#define	AMD_MCA_BANK_LS			3	/* Load/Store Unit */
#define	AMD_MCA_BANK_NB			4	/* Northbridge */
#define	AMD_MCA_BANK_COUNT		5

#define	AMD_MSR_DC_CTL			0x400
#define	AMD_MSR_DC_MASK			0xc0010044
#define	AMD_MSR_DC_STATUS		0x401
#define	AMD_MSR_DC_ADDR			0x402
#define	AMD_MSR_DC_MISC			0x403

#define	AMD_MSR_IC_CTL			0x404
#define	AMD_MSR_IC_MASK			0xc0010045
#define	AMD_MSR_IC_STATUS		0x405
#define	AMD_MSR_IC_ADDR			0x406
#define	AMD_MSR_IC_MISC			0x407

#define	AMD_MSR_BU_CTL			0x408
#define	AMD_MSR_BU_MASK			0xc0010046
#define	AMD_MSR_BU_STATUS		0x409
#define	AMD_MSR_BU_ADDR			0x40a
#define	AMD_MSR_BU_MISC			0x40b

#define	AMD_MSR_LS_CTL			0x40c
#define	AMD_MSR_LS_MASK			0xc0010047
#define	AMD_MSR_LS_STATUS		0x40d
#define	AMD_MSR_LS_ADDR			0x40e
#define	AMD_MSR_LS_MISC			0x40f

#define	AMD_MSR_NB_CTL			0x410
#define	AMD_MSR_NB_MASK			0xc0010048
#define	AMD_MSR_NB_STATUS		0x411
#define	AMD_MSR_NB_ADDR			0x412
#define	AMD_MSR_NB_MISC			0x413

#define	AMD_MCG_EN_DC			0x01
#define	AMD_MCG_EN_IC			0x02
#define	AMD_MCG_EN_BU			0x04
#define	AMD_MCG_EN_LS			0x08
#define	AMD_MCG_EN_NB			0x10

/*
 * Data Cache (DC) bank error-detection enabling bits and CTL register
 * initializer value.
 */

#define	AMD_DC_EN_ECCI			0x00000001ULL
#define	AMD_DC_EN_ECCM			0x00000002ULL
#define	AMD_DC_EN_DECC			0x00000004ULL
#define	AMD_DC_EN_DMTP			0x00000008ULL
#define	AMD_DC_EN_DSTP			0x00000010ULL
#define	AMD_DC_EN_L1TP			0x00000020ULL
#define	AMD_DC_EN_L2TP			0x00000040ULL

#define	AMD_DC_CTL_INIT_CMN \
	(AMD_DC_EN_ECCI | AMD_DC_EN_ECCM | AMD_DC_EN_DECC | AMD_DC_EN_DMTP | \
	AMD_DC_EN_DSTP | AMD_DC_EN_L1TP | AMD_DC_EN_L2TP)

/*
 * Instruction Cache (IC) bank error-detection enabling bits and CTL register
 * initializer value.
 *
 * The Northbridge will handle Read Data errors.  Our initializer will enable
 * all but the RDDE detector.
 */

#define	AMD_IC_EN_ECCI			0x00000001ULL
#define	AMD_IC_EN_ECCM			0x00000002ULL
#define	AMD_IC_EN_IDP			0x00000004ULL
#define	AMD_IC_EN_IMTP			0x00000008ULL
#define	AMD_IC_EN_ISTP			0x00000010ULL
#define	AMD_IC_EN_L1TP			0x00000020ULL
#define	AMD_IC_EN_L2TP			0x00000040ULL
#define	AMD_IC_EN_RDDE			0x00000200ULL

#define	AMD_IC_CTL_INIT_CMN \
	(AMD_IC_EN_ECCI | AMD_IC_EN_ECCM | AMD_IC_EN_IDP | AMD_IC_EN_IMTP | \
	AMD_IC_EN_ISTP | AMD_IC_EN_L1TP | AMD_IC_EN_L2TP)

/*
 * Bus Unit (BU) bank error-detection enabling bits and CTL register
 * initializer value.
 *
 * The Northbridge will handle Read Data errors.  Our initializer will enable
 * all but the S_RDE_* detectors.
 */

#define	AMD_BU_EN_S_RDE_HP		0x00000001ULL
#define	AMD_BU_EN_S_RDE_TLB		0x00000002ULL
#define	AMD_BU_EN_S_RDE_ALL		0x00000004ULL
#define	AMD_BU_EN_S_ECC1_TLB		0x00000008ULL
#define	AMD_BU_EN_S_ECC1_HP		0x00000010ULL
#define	AMD_BU_EN_S_ECCM_TLB		0x00000020ULL
#define	AMD_BU_EN_S_ECCM_HP		0x00000040ULL
#define	AMD_BU_EN_L2T_PAR_ICDC		0x00000080ULL
#define	AMD_BU_EN_L2T_PAR_TLB		0x00000100ULL
#define	AMD_BU_EN_L2T_PAR_SNP		0x00000200ULL
#define	AMD_BU_EN_L2T_PAR_CPB		0x00000400ULL
#define	AMD_BU_EN_L2T_PAR_SCR		0x00000800ULL
#define	AMD_BU_EN_L2D_ECC1_TLB		0x00001000ULL
#define	AMD_BU_EN_L2D_ECC1_SNP		0x00002000ULL
#define	AMD_BU_EN_L2D_ECC1_CPB		0x00004000ULL
#define	AMD_BU_EN_L2D_ECCM_TLB		0x00008000ULL
#define	AMD_BU_EN_L2D_ECCM_SNP		0x00010000ULL
#define	AMD_BU_EN_L2D_ECCM_CPB		0x00020000ULL
#define	AMD_BU_EN_L2T_ECC1_SCR		0x00040000ULL
#define	AMD_BU_EN_L2T_ECCM_SCR		0x00080000ULL

#define	AMD_BU_CTL_INIT_CMN \
	(AMD_BU_EN_S_ECC1_TLB | AMD_BU_EN_S_ECC1_HP | \
	AMD_BU_EN_S_ECCM_TLB | AMD_BU_EN_S_ECCM_HP | \
	AMD_BU_EN_L2T_PAR_ICDC | AMD_BU_EN_L2T_PAR_TLB | \
	AMD_BU_EN_L2T_PAR_SNP |	AMD_BU_EN_L2T_PAR_CPB | \
	AMD_BU_EN_L2T_PAR_SCR |	AMD_BU_EN_L2D_ECC1_TLB | \
	AMD_BU_EN_L2D_ECC1_SNP | AMD_BU_EN_L2D_ECC1_CPB | \
	AMD_BU_EN_L2D_ECCM_TLB | AMD_BU_EN_L2D_ECCM_SNP | \
	AMD_BU_EN_L2D_ECCM_CPB | AMD_BU_EN_L2T_ECC1_SCR | \
	AMD_BU_EN_L2T_ECCM_SCR)

/*
 * Load/Store (LS) bank error-detection enabling bits and CTL register
 * initializer value.
 *
 * The Northbridge will handle Read Data errors.  That's the only type of
 * error the LS unit can detect at present, so we won't be enabling any
 * LS detectors.
 */

#define	AMD_LS_EN_S_RDE_S		0x00000001ULL
#define	AMD_LS_EN_S_RDE_L		0x00000002ULL

#define	AMD_LS_CTL_INIT_CMN			0ULL

/*
 * NorthBridge (NB) MCi_MISC - DRAM Errors Threshold Register.
 */
#define	AMD_NB_MISC_VALID		(0x1ULL << 63)
#define	AMD_NB_MISC_CTRP		(0x1ULL << 62)
#define	AMD_NB_MISC_LOCKED		(0x1ULL << 61)
#define	AMD_NB_MISC_CNTEN		(0x1ULL << 51)
#define	AMD_NB_MISC_INTTYPE		(0x1ULL << 49)
#define	AMD_NB_MISC_INTTYPE_MASK	(0x3ULL << 49)
#define	AMD_NB_MISC_OVRFLW		(0x1ULL << 48)
#define	AMD_NB_MISC_ERRCOUNT_MASK	(0xfffULL << 32)

/*
 * The Northbridge (NB) is configured using both the standard MCA CTL register
 * and a NB-specific configuration register (NB CFG).  The AMD_NB_EN_* macros
 * are the detector enabling bits for the NB MCA CTL register.  The
 * AMD_NB_CFG_* bits are for the NB CFG register.
 *
 * The CTL register can be initialized statically, but portions of the NB CFG
 * register must be initialized based on the current machine's configuration.
 *
 * The MCA NB Control Register maps to MC4_CTL[31:0], but we initialize it
 * via and MSR write of 64 bits so define all as ULL.
 *
 */
#define	AMD_NB_EN_CORRECC		0x00000001ULL
#define	AMD_NB_EN_UNCORRECC		0x00000002ULL
#define	AMD_NB_EN_CRCERR0		0x00000004ULL
#define	AMD_NB_EN_CRCERR1		0x00000008ULL
#define	AMD_NB_EN_CRCERR2		0x00000010ULL
#define	AMD_NB_EN_SYNCPKT0		0x00000020ULL
#define	AMD_NB_EN_SYNCPKT1		0x00000040ULL
#define	AMD_NB_EN_SYNCPKT2		0x00000080ULL
#define	AMD_NB_EN_MSTRABRT		0x00000100ULL
#define	AMD_NB_EN_TGTABRT		0x00000200ULL
#define	AMD_NB_EN_GARTTBLWK		0x00000400ULL
#define	AMD_NB_EN_ATOMICRMW		0x00000800ULL
#define	AMD_NB_EN_WCHDOGTMR		0x00001000ULL
#define	AMD_NB_EN_DRAMPAR		0x00040000ULL	/* revs F and G */

#define	AMD_NB_CTL_INIT_CMN /* Revs B to G; All but GARTTBLWK */ \
	(AMD_NB_EN_CORRECC | AMD_NB_EN_UNCORRECC | \
	AMD_NB_EN_CRCERR0 | AMD_NB_EN_CRCERR1 | AMD_NB_EN_CRCERR2 | \
	AMD_NB_EN_SYNCPKT0 | AMD_NB_EN_SYNCPKT1 | AMD_NB_EN_SYNCPKT2 | \
	AMD_NB_EN_MSTRABRT | AMD_NB_EN_TGTABRT | \
	AMD_NB_EN_ATOMICRMW | AMD_NB_EN_WCHDOGTMR)

#define	AMD_NB_CTL_INIT_REV_FG /* Additional bits for revs F and G */ \
	AMD_NB_EN_DRAMPAR

/*
 * NB MCA Configuration register
 */
#define	AMD_NB_CFG_CPUECCERREN			0x00000001
#define	AMD_NB_CFG_CPURDDATERREN		0x00000002
#define	AMD_NB_CFG_SYNCONUCECCEN		0x00000004
#define	AMD_NB_CFG_SYNCPKTGENDIS		0x00000008
#define	AMD_NB_CFG_SYNCPKTPROPDIS		0x00000010
#define	AMD_NB_CFG_IOMSTABORTDIS		0x00000020
#define	AMD_NB_CFG_CPUERRDIS			0x00000040
#define	AMD_NB_CFG_IOERRDIS			0x00000080
#define	AMD_NB_CFG_WDOGTMRDIS			0x00000100
#define	AMD_NB_CFG_SYNCONWDOGEN			0x00100000
#define	AMD_NB_CFG_SYNCONANYERREN		0x00200000
#define	AMD_NB_CFG_ECCEN			0x00400000
#define	AMD_NB_CFG_CHIPKILLECCEN		0x00800000
#define	AMD_NB_CFG_IORDDATERREN			0x01000000
#define	AMD_NB_CFG_DISPCICFGCPUERRRSP		0x02000000
#define	AMD_NB_CFG_NBMCATOMSTCPUEN		0x08000000
#define	AMD_NB_CFG_DISTGTABTCPUERRRSP		0x10000000
#define	AMD_NB_CFG_DISMSTABTCPUERRRSP		0x20000000
#define	AMD_NB_CFG_SYNCONDRAMADRPARERREN	0x40000000 /* Revs F & G */

/*
 * We do not initialize the NB config with an absolute value; instead we
 * selectively add some bits and remove others.  Note that
 * AMD_NB_CFG_{ADD,REMOVE}_{CMN,REV_FG} below are not the whole
 * story here - additional config is performed regarding the watchdog (see
 * ao_mca.c for details).
 */
#define	AMD_NB_CFG_ADD_CMN		/* Revs B to G */ \
	(AMD_NB_CFG_DISPCICFGCPUERRRSP | AMD_NB_CFG_SYNCONUCECCEN | \
	AMD_NB_CFG_CPUECCERREN)

#define	AMD_NB_CFG_REMOVE_CMN		/* Revs B to G */ \
	(AMD_NB_CFG_NBMCATOMSTCPUEN | \
	AMD_NB_CFG_IORDDATERREN | AMD_NB_CFG_SYNCONANYERREN | \
	AMD_NB_CFG_SYNCONWDOGEN | AMD_NB_CFG_IOERRDIS | \
	AMD_NB_CFG_IOMSTABORTDIS | AMD_NB_CFG_SYNCPKTPROPDIS | \
	AMD_NB_CFG_SYNCPKTGENDIS)

#define	AMD_NB_CFG_ADD_REV_FG		/* Revs F and G */ \
	AMD_NB_CFG_SYNCONDRAMADRPARERREN

#define	AMD_NB_CFG_REMOVE_REV_FG 0x0	/* Revs F and G */

#define	AMD_NB_CFG_WDOGTMRCNTSEL_4095	0x00000000
#define	AMD_NB_CFG_WDOGTMRCNTSEL_2047	0x00000200
#define	AMD_NB_CFG_WDOGTMRCNTSEL_1023	0x00000400
#define	AMD_NB_CFG_WDOGTMRCNTSEL_511	0x00000600
#define	AMD_NB_CFG_WDOGTMRCNTSEL_255	0x00000800
#define	AMD_NB_CFG_WDOGTMRCNTSEL_127	0x00000a00
#define	AMD_NB_CFG_WDOGTMRCNTSEL_63	0x00000c00
#define	AMD_NB_CFG_WDOGTMRCNTSEL_31	0x00000e00
#define	AMD_NB_CFG_WDOGTMRCNTSEL_MASK	0x00000e00
#define	AMD_NB_CFG_WDOGTMRCNTSEL_SHIFT	9

#define	AMD_NB_CFG_WDOGTMRBASESEL_1MS	0x00000000
#define	AMD_NB_CFG_WDOGTMRBASESEL_1US	0x00001000
#define	AMD_NB_CFG_WDOGTMRBASESEL_5NS	0x00002000
#define	AMD_NB_CFG_WDOGTMRBASESEL_MASK	0x00003000
#define	AMD_NB_CFG_WDOGTMRBASESEL_SHIFT	12

#define	AMD_NB_CFG_LDTLINKSEL_MASK	0x0000c000
#define	AMD_NB_CFG_LDTLINKSEL_SHIFT	14

#define	AMD_NB_CFG_GENCRCERRBYTE0	0x00010000
#define	AMD_NB_CFG_GENCRCERRBYTE1	0x00020000

/*
 * The AMD extended error code is just one nibble of the upper 16 bits
 * of the bank status (the resy being used for syndrome etc).  So we use
 * AMD_EXT_ERRCODE to retrieve that extended error code, not the generic
 * MCAX86_MSERRCODE.
 */
#define	_AMD_ERREXT_MASK		0x00000000000f0000ULL
#define	_AMD_ERREXT_SHIFT		16
#define	AMD_EXT_ERRCODE(stat) \
	(((stat) & _AMD_ERREXT_MASK) >> _AMD_ERREXT_SHIFT)
#define	AMD_EXT_MKERRCODE(errcode) \
	(((errcode) << _AMD_ERREXT_SHIFT) & _AMD_ERREXT_MASK)

#define	AMD_BANK_STAT_CECC		0x0000400000000000ULL
#define	AMD_BANK_STAT_UECC		0x0000200000000000ULL
#define	AMD_BANK_STAT_SCRUB		0x0000010000000000ULL

	/* syndrome[7:0] */
#define	AMD_BANK_STAT_SYND_MASK		0x007f800000000000ULL
#define	AMD_BANK_STAT_SYND_SHIFT	47

#define	AMD_BANK_SYND(stat) \
	(((stat) & AMD_BANK_STAT_SYND_MASK) >> AMD_BANK_STAT_SYND_SHIFT)
#define	AMD_BANK_MKSYND(synd) \
	(((uint64_t)(synd) << AMD_BANK_STAT_SYND_SHIFT) & \
	AMD_BANK_STAT_SYND_MASK)

#define	AMD_NB_STAT_DRAMCHANNEL		0x0000020000000000ULL
#define	AMD_NB_STAT_LDTLINK_MASK	0x0000007000000000ULL
#define	AMD_NB_STAT_LDTLINK_SHIFT	4
#define	AMD_NB_STAT_ERRCPU1		0x0000000200000000ULL
#define	AMD_NB_STAT_ERRCPU0		0x0000000100000000ULL

#define	AMD_NB_STAT_CKSYND_MASK		0x00000000ff000000 /* syndrome[15:8] */
#define	AMD_NB_STAT_CKSYND_SHIFT	(24 - 8) /* shift [31:24] to [15:8] */

#define	AMD_NB_STAT_CKSYND(stat) \
	((((stat) & AMD_NB_STAT_CKSYND_MASK) >> AMD_NB_STAT_CKSYND_SHIFT) | \
	AMD_BANK_SYND((stat)))

#define	AMD_NB_STAT_MKCKSYND(synd) \
	((((uint64_t)(synd) << AMD_NB_STAT_CKSYND_SHIFT) & \
	AMD_NB_STAT_CKSYND_MASK) | AMD_BANK_MKSYND(synd))

#define	AMD_ERREXT_MASK			0x00000000000f0000ULL
#define	AMD_ERREXT_SHIFT		16

#define	AMD_ERRCODE_TLB_BIT		4
#define	AMD_ERRCODE_MEM_BIT		8
#define	AMD_ERRCODE_BUS_BIT		11

#define	AMD_ERRCODE_TLB_MASK		0xfff0
#define	AMD_ERRCODE_MEM_MASK		0xff00
#define	AMD_ERRCODE_BUS_MASK		0xf800

#define	AMD_ERRCODE_MKTLB(tt, ll) MCAX86_MKERRCODE_TLB(tt, ll)
#define	AMD_ERRCODE_ISTLB(code) MCAX86_ERRCODE_ISTLB(code)

#define	AMD_ERRCODE_MKMEM(r4, tt, ll) MCAX86_MKERRCODE_MEMHIER(r4, tt, ll)
#define	AMD_ERRCODE_ISMEM(code) MCAX86_ERRCODE_ISMEMHIER(code)

#define	AMD_ERRCODE_MKBUS(pp, t, r4, ii, ll) \
	MCAX86_MKERRCODE_BUS_INTERCONNECT(pp, t, r4, ii, ll)
#define	AMD_ERRCODE_ISBUS(code) MCAX86_ERRCODE_ISBUS_INTERCONNECT(code)

#define	AMD_NB_ADDRLO_MASK		0xfffffff8
#define	AMD_NB_ADDRHI_MASK		0x000000ff

#define	AMD_SYNDTYPE_ECC		0
#define	AMD_SYNDTYPE_CHIPKILL		1

#define	AMD_NB_SCRUBCTL_DRAM_MASK	0x0000001f
#define	AMD_NB_SCRUBCTL_DRAM_SHIFT	0
#define	AMD_NB_SCRUBCTL_L2_MASK		0x00001f00
#define	AMD_NB_SCRUBCTL_L2_SHIFT	8
#define	AMD_NB_SCRUBCTL_DC_MASK		0x001f0000
#define	AMD_NB_SCRUBCTL_DC_SHIFT	16
#define	AMD_NB_SCRUBCTL_L3_MASK		0x1f000000
#define	AMD_NB_SCRUBCTL_L3_SHIFT	24

#define	AMD_NB_SCRUBCTL_RATE_NONE	0
#define	AMD_NB_SCRUBCTL_RATE_MAX	0x16

#define	AMD_NB_SCRUBADDR_LO_MASK	0xffffffc0
#define	AMD_NB_SCRUBADDR_LO_SHIFT	6
#define	AMD_NB_SCRUBADDR_LO_SCRUBREDIREN 0x1
#define	AMD_NB_SCRUBADDR_HI_MASK	0x000000ff

#define	AMD_NB_SCRUBADDR_MKLO(addr) \
	(((addr) & AMD_NB_SCRUBADDR_LO_MASK) >> AMD_NB_SCRUBADDR_LO_SHIFT)

#define	AMD_NB_SCRUBADDR_MKHI(addr) \
	(((addr) >> 32) & AMD_NB_SCRUBADDR_HI_MASK)

#define	AMD_NB_MKSCRUBCTL(l3, dc, l2, dr) ( \
	(((l3) << AMD_NB_SCRUBCTL_L3_SHIFT) & AMD_NB_SCRUBCTL_L3_MASK) | \
	(((dc) << AMD_NB_SCRUBCTL_DC_SHIFT) & AMD_NB_SCRUBCTL_DC_MASK) | \
	(((l2) << AMD_NB_SCRUBCTL_L2_SHIFT) & AMD_NB_SCRUBCTL_L2_MASK) | \
	(((dr) << AMD_NB_SCRUBCTL_DRAM_SHIFT) & AMD_NB_SCRUBCTL_DRAM_MASK))

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MCA_AMD_H */
