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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_MCA_X86_H
#define	_SYS_MCA_X86_H

/*
 * Constants for the Memory Check Architecture as implemented on generic x86
 * CPUs.
 */

#include <sys/types.h>
#include <sys/isa_defs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Architectural MSRs from the IA-32 Software Developer's Manual - IA32_MSR_*
 */
#define	IA32_MSR_MCG_CAP		0x179
#define	IA32_MSR_MCG_STATUS		0x17a
#define	IA32_MSR_MCG_CTL		0x17b

#define	MCG_CAP_CTL_P			0x00000100ULL
#define	MCG_CAP_EXT_P			0x00000200ULL
#define	MCG_CAP_TES_P			0x00000800ULL
#define	MCG_CAP_CTL2_P			0x00000400ULL

#define	MCG_CAP_COUNT_MASK		0x000000ffULL
#define	MCG_CAP_COUNT(cap) ((cap) & MCG_CAP_COUNT_MASK)

#define	MCG_CAP_EXT_CNT_MASK		0x00ff0000ULL
#define	MCG_CAP_EXT_CNT_SHIFT		16
#define	MCG_CAP_EXT_CNT(cap) \
	(((cap) & MCG_CAP_EXT_CNT_MASK) >> MCG_CAP_EXT_CNT_SHIFT)

#define	MCG_STATUS_RIPV			0x01
#define	MCG_STATUS_EIPV			0x02
#define	MCG_STATUS_MCIP			0x04

/*
 * There are as many error detector "banks" as indicated by
 * IA32_MSR_MCG_CAP.COUNT.  Each bank has a minimum of 3 associated
 * registers (MCi_CTL, MCi_STATUS, and MCi_ADDR) and some banks
 * may implement a fourth (MCi_MISC) which should only be read
 * when MCi_STATUS.MISCV indicates that it exists and has valid data.
 *
 * The first bank features at MSR offsets 0x400 to 0x403, the next at
 * 0x404 to 0x407, and so on.  Current processors implement up to 6
 * banks (sixth one at 0x414 to 0x417).
 *
 * It is, sadly, not the case that the i'th set of 4 registers starting
 * at 0x400 corresponds to MCi_{CTL,STATUS,ADDR,MISC} - for some Intel
 * processors, for example, the order is 0/1/2/4/3.  Nonetheless, we can
 * still iterate through the banks and read all telemetry - there'll just
 * be some potential confusion as to which processor unit a bank is
 * associated with.  Error reports should seek to disambiguate.
 *
 * IA32_MSR_MC(i, which) calculates the MSR address for th i'th bank
 * of registers (not for MCi_*, as above) and one of CTL, STATUS, ADDR, MISC
 */

#define	_IA32_MSR_MC0_CTL		0x400ULL /* first/base reg */
#define	_IA32_MSR_OFFSET_CTL		0x0	/* offset within a bank */
#define	_IA32_MSR_OFFSET_STATUS		0x1	/* offset within a bank */
#define	_IA32_MSR_OFFSET_ADDR		0x2	/* offset within a bank */
#define	_IA32_MSR_OFFSET_MISC		0x3	/* offset within a bank */

#define	_IA32_MSR_MC0_CTL2		0x280ULL /* first MCi_CTL2 reg */

#define	IA32_MSR_MC(i, which) \
	(_IA32_MSR_MC0_CTL + (i) * 4 + _IA32_MSR_OFFSET_##which)

#define	IA32_MSR_MC_CTL2(i)	(_IA32_MSR_MC0_CTL2 + (i))

/*
 * IA32_MSR_MCG_CAP.MCG_EXT_P indicates that a processor implements
 * a set of extended machine-check registers starting at MSR 0x180;
 * when that is set, IA32_MSR_MCG_CAP.MCG_EXT_CNT indicates how
 * many of these extended registers (addresses 0x180, 0x181, ...)
 * are present.  Which registers are present depends on whether support
 * for 64-bit architecture is present.
 */

#define	_IA32_MCG_RAX			0x180ULL /* first/base extended reg */

#define	IA32_MSR_EXT(i)	(_IA32_MCG_RAX + (i))

#ifdef _BIT_FIELDS_LTOH
typedef union mca_x86_mcistatus {
	uint64_t _val64;
	struct {
		/*
		 * Lower 32 bits of MCi_STATUS
		 */
		struct {
			uint32_t _errcode:16;		/* <15:0> */
			uint32_t _ms_errcode:16;	/* <31:16> */
		} _mcis_lo;
		/*
		 * Upper 32 bits of MCi_STATUS
		 */
		union {
			/*
			 * If IA32_MCG_CAP.MCG_TES_P is set then <54:53>
			 * and <56:55> are architectural.
			 */
			struct {
				uint32_t _otherinfo:21;		/* <52:32> */
				uint32_t _tbes:2;		/* <54:53> */
				uint32_t _reserved:2;		/* <56:55> */
				uint32_t _pcc:1;		/* <57> */
				uint32_t _addrv:1;		/* <58> */
				uint32_t _miscv:1;		/* <59> */
				uint32_t _en:1;			/* <60> */
				uint32_t _uc:1;			/* <61> */
				uint32_t _over:1;		/* <62> */
				uint32_t _val:1;		/* <63> */
			} _mcis_hi_tes_p;
			/*
			 * If IA32_MCG_CAP.MCG_TES_P is clear then <56:53>
			 * are model-specific.
			 */
			struct {
				uint32_t _otherinfo:25;		/* <56:32> */
				uint32_t _pcc:1;		/* <57> */
				uint32_t _addrv:1;		/* <58> */
				uint32_t _miscv:1;		/* <59> */
				uint32_t _en:1;			/* <60> */
				uint32_t _uc:1;			/* <61> */
				uint32_t _over:1;		/* <62> */
				uint32_t _val:1;		/* <63> */
			} _mcis_hi_tes_np;
		} _mcis_hi;
	} _mcis_hilo;
} mca_x86_mcistatus_t;

#define	mcistatus_errcode	_mcis_hilo._mcis_lo._errcode
#define	mcistatus_mserrcode	_mcis_hilo._mcis_lo._ms_errcode
#define	mcistatus_pcc	_mcis_hilo._mcis_hi._mcis_hi_tes_np._pcc
#define	mcistatus_addrv	_mcis_hilo._mcis_hi._mcis_hi_tes_np._addrv
#define	mcistatus_miscv	_mcis_hilo._mcis_hi._mcis_hi_tes_np._miscv
#define	mcistatus_en	_mcis_hilo._mcis_hi._mcis_hi_tes_np._en
#define	mcistatus_uc	_mcis_hilo._mcis_hi._mcis_hi_tes_np._uc
#define	mcistatus_over	_mcis_hilo._mcis_hi._mcis_hi_tes_np._over
#define	mcistatus_val	_mcis_hilo._mcis_hi._mcis_hi_tes_np._val

/*
 * The consumer must check for TES_P before using these.
 */
#define	mcistatus_tbes	_mcis_hilo._mcis_hi._mcis_hi_tes_p._tbes
#define	mcistatus_reserved \
	_mcis_hilo._mcis_hi._mcis_hi_tes_p._reserved
#define	mcistatus_otherinfo_tes_p \
	_mcis_hilo._mcis_hi._mcis_hi_tes_p._otherinfo
#define	mcistatus_otherinfo_tes_np \
	_mcis_hilo._mcis_hi._mcis_hi_tes_np._otherinfo

#endif /* _BIT_FIELDS_LTOH */

#define	MSR_MC_STATUS_VAL		0x8000000000000000ULL
#define	MSR_MC_STATUS_OVER		0x4000000000000000ULL
#define	MSR_MC_STATUS_UC		0x2000000000000000ULL
#define	MSR_MC_STATUS_EN		0x1000000000000000ULL
#define	MSR_MC_STATUS_MISCV		0x0800000000000000ULL
#define	MSR_MC_STATUS_ADDRV		0x0400000000000000ULL
#define	MSR_MC_STATUS_PCC		0x0200000000000000ULL
#define	MSR_MC_STATUS_RESERVED_MASK	0x0180000000000000ULL
#define	MSR_MC_STATUS_TBES_MASK		0x0060000000000000ULL
#define	MSR_MC_STATUS_TBES_SHIFT	53
#define	MSR_MC_STATUS_CEC_MASK		0x001fffc000000000ULL
#define	MSR_MC_STATUS_CEC_SHIFT	38
#define	MSR_MC_STATUS_MSERR_MASK	0x00000000ffff0000ULL
#define	MSR_MC_STATUS_MSERR_SHIFT	16
#define	MSR_MC_STATUS_MCAERR_MASK	0x000000000000ffffULL

#define	MSR_MC_CTL2_EN			0x0000000040000000ULL
#define	MSR_MC_CTL2_THRESHOLD_MASK	0x0000000000007fffULL
#define	MSR_MC_CTL2_THRESHOLD_OVERFLOW	0x0000000000004000ULL

/*
 * Macros to extract error code and model-specific error code.
 */
#define	MCAX86_ERRCODE(stat)		((stat) & MSR_MC_STATUS_MCAERR_MASK)
#define	MCAX86_MSERRCODE(stat) \
	(((stat) & MSR_MC_STATUS_MSERR_MASK) >> MSR_MC_STATUS_MSERR_SHIFT)

/*
 * Macro to extract threshold based error state (if MCG_CAP.TES_P)
 */
#define	MCAX86_TBES_VALUE(stat) \
	(((stat) & MSR_MC_STATUS_TBES_MASK) >> MSR_MC_STATUS_TBES_SHIFT)

/*
 * Bit definitions for the architectural error code.
 */

#define	MCAX86_ERRCODE_TT_MASK		0x000c
#define	MCAX86_ERRCODE_TT_SHIFT		2
#define	MCAX86_ERRCODE_TT_INSTR		0x0
#define	MCAX86_ERRCODE_TT_DATA		0x1
#define	MCAX86_ERRCODE_TT_GEN		0x2
#define	MCAX86_ERRCODE_TT(code) \
	(((code) & MCAX86_ERRCODE_TT_MASK) >> MCAX86_ERRCODE_TT_SHIFT)

#define	MCAX86_ERRCODE_LL_MASK		0x0003
#define	MCAX86_ERRCODE_LL_SHIFT		0
#define	MCAX86_ERRCODE_LL_L0		0x0
#define	MCAX86_ERRCODE_LL_L1		0x1
#define	MCAX86_ERRCODE_LL_L2		0x2
#define	MCAX86_ERRCODE_LL_LG		0x3
#define	MCAX86_ERRCODE_LL(code) \
	((code) & MCAX86_ERRCODE_LL_MASK)

#define	MCAX86_ERRCODE_RRRR_MASK	0x00f0
#define	MCAX86_ERRCODE_RRRR_SHIFT	4
#define	MCAX86_ERRCODE_RRRR_ERR		0x0
#define	MCAX86_ERRCODE_RRRR_RD		0x1
#define	MCAX86_ERRCODE_RRRR_WR		0x2
#define	MCAX86_ERRCODE_RRRR_DRD		0x3
#define	MCAX86_ERRCODE_RRRR_DWR		0x4
#define	MCAX86_ERRCODE_RRRR_IRD		0x5
#define	MCAX86_ERRCODE_RRRR_PREFETCH	0x6
#define	MCAX86_ERRCODE_RRRR_EVICT	0x7
#define	MCAX86_ERRCODE_RRRR_SNOOP	0x8
#define	MCAX86_ERRCODE_RRRR(code) \
	(((code) & MCAX86_ERRCODE_RRRR_MASK) >> MCAX86_ERRCODE_RRRR_SHIFT)

#define	MCAX86_ERRCODE_PP_MASK		0x0600
#define	MCAX86_ERRCODE_PP_SHIFT		9
#define	MCAX86_ERRCODE_PP_SRC		0x0
#define	MCAX86_ERRCODE_PP_RES		0x1
#define	MCAX86_ERRCODE_PP_OBS		0x2
#define	MCAX86_ERRCODE_PP_GEN		0x3
#define	MCAX86_ERRCODE_PP(code) \
	(((code) & MCAX86_ERRCODE_PP_MASK) >> MCAX86_ERRCODE_PP_SHIFT)

#define	MCAX86_ERRCODE_II_MASK		0x000c
#define	MCAX86_ERRCODE_II_SHIFT		2
#define	MCAX86_ERRCODE_II_MEM		0x0
#define	MCAX86_ERRCODE_II_IO		0x2
#define	MCAX86_ERRCODE_II_GEN		0x3
#define	MCAX86_ERRCODE_II(code) \
	(((code) & MCAX86_ERRCODE_II_MASK) >> MCAX86_ERRCODE_II_SHIFT)

#define	MCAX86_ERRCODE_T_MASK		0x0100
#define	MCAX86_ERRCODE_T_SHIFT		8
#define	MCAX86_ERRCODE_T_NONE		0x0
#define	MCAX86_ERRCODE_T_TIMEOUT	0x1
#define	MCAX86_ERRCODE_T(code) \
	(((code) & MCAX86_ERRCODE_T_MASK) >> MCAX86_ERRCODE_T_SHIFT)

#define	MCAX86_ERRCODE_MMM_MASK		0x0070
#define	MCAX86_ERRCODE_MMM_SHIFT	4
#define	MCAX86_ERRCODE_MMM_GEN		0x0
#define	MCAX86_ERRCODE_MMM_RD		0x1
#define	MCAX86_ERRCODE_MMM_WR		0x2
#define	MCAX86_ERRCODE_MMM_ADRCMD	0x3
#define	MCAX86_ERRCODE_MMM(code) \
	(((code) & MCAX86_ERRCODE_MMM_MASK) >> MCAX86_ERRCODE_MMM_SHIFT)

#define	MCAX86_ERRCODE_CCCC_MASK	0x000f
#define	MCAX86_ERRCODE_CCCC_SHIFT	0
#define	MCAX86_ERRCODE_CCCC_CH0		0x0
#define	MCAX86_ERRCODE_CCCC_CH1		0x1
#define	MCAX86_ERRCODE_CCCC_CH2		0x2
#define	MCAX86_ERRCODE_CCCC_CH3		0x3
#define	MCAX86_ERRCODE_CCCC_CH4		0x4
#define	MCAX86_ERRCODE_CCCC_CH5		0x5
#define	MCAX86_ERRCODE_CCCC_CH6		0x6
#define	MCAX86_ERRCODE_CCCC_CH7		0x7
#define	MCAX86_ERRCODE_CCCC_CH8		0x8
#define	MCAX86_ERRCODE_CCCC_CH9		0x9
#define	MCAX86_ERRCODE_CCCC_CH10	0xa
#define	MCAX86_ERRCODE_CCCC_CH11	0xb
#define	MCAX86_ERRCODE_CCCC_CH12	0xc
#define	MCAX86_ERRCODE_CCCC_CH13	0xd
#define	MCAX86_ERRCODE_CCCC_CH14	0xe
#define	MCAX86_ERRCODE_CCCC_GEN		0xf
#define	MCAX86_ERRCODE_CCCC(code) \
	(((code) & MCAX86_ERRCODE_CCCC_MASK) >> MCAX86_ERRCODE_CCCC_SHIFT)

/*
 * Simple error encoding.  MASKON are bits that must be set for a match
 * at the same time bits indicated by MASKOFF are clear.
 */
#define	MCAX86_SIMPLE_UNCLASSIFIED_MASKON		0x0001
#define	MCAX86_SIMPLE_UNCLASSIFIED_MASKOFF		0xfffe

#define	MCAX86_SIMPLE_MC_CODE_PARITY_MASKON		0x0002
#define	MCAX86_SIMPLE_MC_CODE_PARITY_MASKOFF		0xfffd

#define	MCAX86_SIMPLE_EXTERNAL_MASKON			0x0003
#define	MCAX86_SIMPLE_EXTERNAL_MASKOFF			0xfffc

#define	MCAX86_SIMPLE_FRC_MASKON			0x0004
#define	MCAX86_SIMPLE_FRC_MASKOFF			0xfffb

#define	MCAX86_SIMPLE_INTERNAL_PARITY_MASKON		0x0005
#define	MCAX86_SIMPLE_INTERNAL_PARITY_MASKOFF		0xfffa

#define	MCAX86_SIMPLE_INTERNAL_TIMER_MASKON		0x0400
#define	MCAX86_SIMPLE_INTERNAL_TIMER_MASKOFF		0xfbff

#define	MCAX86_SIMPLE_INTERNAL_UNCLASS_MASK_MASKON	0x0400
#define	MCAX86_SIMPLE_INTERNAL_UNCLASS_MASK_MASKOFF	0xf800
#define	MCAX86_SIMPLE_INTERNAL_UNCLASS_VALUE_MASK	0x03ff

/*
 * Macros to make an internal unclassified error code, and to test if
 * a given code is internal unclassified.
 */
#define	MCAX86_MKERRCODE_INTERNAL_UNCLASS(val) \
	(MCAX86_SIMPLE_INTERNAL_UNCLASS_MASK_MASKON | \
	((val) & MCAX86_SIMPLE_INTERNAL_UNCLASS_VALUE_MASK))
#define	MCAX86_ERRCODE_ISSIMPLE_INTERNAL_UNCLASS(code) \
	(((code) & MCAX86_SIMPLE_INTERNAL_UNCLASS_MASK_MASKON) == \
	MCAX86_SIMPLE_INTERNAL_UNCLASS_MASK_MASKON && \
	((code) & MCAX86_SIMPLE_INTERNAL_UNCLASS_MASK_MASKOFF) == 0 && \
	((code) & MCAX86_SIMPLE_INTERNAL_UNCLASS_VALUE_MASK) != 0)

/*
 * Is the given error code a simple error encoding?
 */
#define	MCAX86_ERRCODE_ISSIMPLE(code) \
	((code) >= MCAX86_SIMPLE_UNCLASSIFIED_MASKON && \
	(code) <= MCAX86_SIMPLE_INTERNAL_PARITY_MASKON || \
	(code) == MCAX86_SIMPLE_INTERNAL_TIMER_MASKON || \
	MCAX86_ERRCODE_ISSIMPLE_INTERNAL_UNCLASS(code))

/*
 * Compound error encoding.  We always ignore the 'F' bit (which indicates
 * "correction report filtering") in classifying the error type.
 */
#define	MCAX86_COMPOUND_GENERIC_MEMHIER_MASKON		0x000c
#define	MCAX86_COMPOUND_GENERIC_MEMHIER_MASKOFF		0xeff0

#define	MCAX86_COMPOUND_TLB_MASKON			0x0010
#define	MCAX86_COMPOUND_TLB_MASKOFF			0xefe0

#define	MCAX86_COMPOUND_MEMHIER_MASKON			0x0100
#define	MCAX86_COMPOUND_MEMHIER_MASKOFF			0xee00

#define	MCAX86_COMPOUND_BUS_INTERCONNECT_MASKON		0x0800
#define	MCAX86_COMPOUND_BUS_INTERCONNECT_MASKOFF	0xe000

#define	MCAX86_COMPOUND_MEMORY_CONTROLLER_MASKON	0x0080
#define	MCAX86_COMPOUND_MEMORY_CONTROLLER_MASKOFF	0xff00

/*
 * Macros to make compound error codes and to test for each type.
 */
#define	MCAX86_MKERRCODE_GENERIC_MEMHIER(ll) \
	(MCAX86_COMPOUND_GENERIC_MEMHIER_MASKON | \
	((ll) & MCAX86_ERRCODE_LL_MASK))
#define	MCAX86_ERRCODE_ISGENERIC_MEMHIER(code) \
	(((code) & MCAX86_COMPOUND_GENERIC_MEMHIER_MASKON) == \
	MCAX86_COMPOUND_GENERIC_MEMHIER_MASKON && \
	((code) & MCAX86_COMPOUND_GENERIC_MEMHIER_MASKOFF) == 0)

#define	MCAX86_MKERRCODE_TLB(tt, ll) \
	(MCAX86_COMPOUND_TLB_MASKON | \
	((tt) << MCAX86_ERRCODE_TT_SHIFT & MCAX86_ERRCODE_TT_MASK) | \
	((ll) & MCAX86_ERRCODE_LL_MASK))
#define	MCAX86_ERRCODE_ISTLB(code) \
	(((code) & MCAX86_COMPOUND_TLB_MASKON) == \
	MCAX86_COMPOUND_TLB_MASKON && \
	((code) & MCAX86_COMPOUND_TLB_MASKOFF) == 0)

#define	MCAX86_MKERRCODE_MEMHIER(rrrr, tt, ll) \
	(MCAX86_COMPOUND_MEMHIER_MASKON | \
	((rrrr) << MCAX86_ERRCODE_RRRR_SHIFT & MCAX86_ERRCODE_RRRR_MASK) | \
	((tt) << MCAX86_ERRCODE_TT_SHIFT & MCAX86_ERRCODE_TT_MASK) | \
	((ll) & MCAX86_ERRCODE_LL_MASK))
#define	MCAX86_ERRCODE_ISMEMHIER(code) \
	(((code) & MCAX86_COMPOUND_MEMHIER_MASKON) == \
	MCAX86_COMPOUND_MEMHIER_MASKON && \
	((code) & MCAX86_COMPOUND_MEMHIER_MASKOFF) == 0)

#define	MCAX86_MKERRCODE_BUS_INTERCONNECT(pp, t, rrrr, ii, ll) \
	(MCAX86_COMPOUND_BUS_INTERCONNECT_MASKON | \
	((pp) << MCAX86_ERRCODE_PP_SHIFT & MCAX86_ERRCODE_PP_MASK) | \
	((t) << MCAX86_ERRCODE_T_SHIFT & MCAX86_ERRCODE_T_MASK) | \
	((rrrr) << MCAX86_ERRCODE_RRRR_SHIFT & MCAX86_ERRCODE_RRRR_MASK) | \
	((ii) << MCAX86_ERRCODE_II_SHIFT & MCAX86_ERRCODE_II_MASK) | \
	((ll) & MCAX86_ERRCODE_LL_MASK))
#define	MCAX86_ERRCODE_ISBUS_INTERCONNECT(code) \
	(((code) & MCAX86_COMPOUND_BUS_INTERCONNECT_MASKON) == \
	MCAX86_COMPOUND_BUS_INTERCONNECT_MASKON && \
	((code) & MCAX86_COMPOUND_BUS_INTERCONNECT_MASKOFF) == 0)

#define	MCAX86_MKERRCODE_MEMORY_CONTROLLER (mmm, cccc) \
	(MCAX86_COMPOUNT_MEMORY_CONTROLLER_MASKON | \
	((mmm) << MCAX86_ERRCODE_MMM_SHIFT & MCAX86_ERRCODE_MMM_MASK) | \
	((cccc) << MCAX86_ERRCODE_CCCC_SHIFT & MCAX86_ERRCODE_CCCC_MASK))
#define	MCAX86_ERRCODE_ISMEMORY_CONTROLLER(code) \
	(((code) & MCAX86_COMPOUND_MEMORY_CONTROLLER_MASKON) == \
	MCAX86_COMPOUND_MEMORY_CONTROLLER_MASKON && \
	((code) & MCAX86_COMPOUND_MEMORY_CONTROLLER_MASKOFF) == 0)

#define	MCAX86_ERRCODE_ISCOMPOUND(code) \
	(MCAX86_ERRCODE_ISGENERIC_MEMHIER(code) || \
	MCAX86_ERRCODE_ISTLB(code) || \
	MCAX86_ERRCODE_ISMEMHIER(code) || \
	MCAX86_ERRCODE_ISBUS_INTERCONNECT(code) || \
	MCAX86_ERRCODE_ISMEMORY_CONTROLLER(code))

#define	MCAX86_ERRCODE_UNKNOWN(code) \
	(!MCAX86_ERRCODE_ISSIMPLE(code) && !MCAX86_ERRCODE_ISCOMPOUND(code))

#ifdef __cplusplus
}
#endif

#endif /* _SYS_MCA_X86_H */
