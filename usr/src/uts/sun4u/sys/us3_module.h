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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_US3_MODULE_H
#define	_SYS_US3_MODULE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"
#include <sys/async.h>

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _KERNEL

/*
 * Macros to access the "cheetah cpu private" data structure.
 */
#define	CPU_PRIVATE_PTR(cp, x)	(&(((cheetah_private_t *)CPU_PRIVATE(cp))->x))
#define	CPU_PRIVATE_VAL(cp, x)	(((cheetah_private_t *)CPU_PRIVATE(cp))->x)

#define	CHP_WORD_TO_OFF(word, off)	(((word) * 8) == off)

#if defined(JALAPENO) || defined(SERRANO)
/* JP J_REQ errors */
#define	C_AFSR_JREQ_ERRS	(C_AFSR_RUE | C_AFSR_BP | C_AFSR_WBP | \
			C_AFSR_RCE | C_AFSR_TO | C_AFSR_BERR | C_AFSR_UMS)
/* JP AID errors */
#define	C_AFSR_AID_ERRS		(C_AFSR_CPU | C_AFSR_FRU | C_AFSR_CPC | \
			C_AFSR_FRC)

#if defined(SERRANO)
/* SERRANO AFSR bits from Disrupting (Corrected) ECC error Trap (Trap 0x63) */
#define	C_AFSR_CECC_ERRS	(C_AFSR_UMS | C_AFSR_IVPE | C_AFSR_CPC | \
			C_AFSR_CPU | C_AFSR_WDC | C_AFSR_WDU | C_AFSR_EDC | \
			C_AFSR_CE | C_AFSR_RCE | C_AFSR_WBP | C_AFSR_FRC | \
			C_AFSR_FRU | C_AFSR_EDU | C_AFSR_ETI | C_AFSR_ETC)

#else /* SERRANO */
/* JP AFSR bits from Disrupting (Corrected) ECC error Trap (Trap 0x63) */
#define	C_AFSR_CECC_ERRS	(C_AFSR_UMS | C_AFSR_IVPE | C_AFSR_CPC | \
			C_AFSR_CPU | C_AFSR_WDC | C_AFSR_WDU | C_AFSR_EDC | \
			C_AFSR_CE | C_AFSR_RCE | C_AFSR_WBP | C_AFSR_FRC | \
			C_AFSR_FRU | C_AFSR_EDU)
#endif /* SERRANO */

#if defined(SERRANO)
/*
 * SERRANO AFSR bits from {Instruction,Data}_access_error traps
 * (Traps 0xa, 0x32)
 */
#define	C_AFSR_ASYNC_ERRS	(C_AFSR_OM | C_AFSR_TO | C_AFSR_BERR | \
			C_AFSR_UE | C_AFSR_RUE | C_AFSR_EDU | C_AFSR_BP | \
			C_AFSR_ETU | C_AFSR_ETS)
#else /* SERRANO */
/* JP AFSR bits from {Instruction,Data}_access_error traps (Traps 0xa, 0x32) */
#define	C_AFSR_ASYNC_ERRS	(C_AFSR_OM | C_AFSR_TO | C_AFSR_BERR | \
			C_AFSR_UE | C_AFSR_RUE | C_AFSR_EDU | C_AFSR_BP)
#endif /* SERRANO */

#if defined(SERRANO)
/* SERRANO AFSR bits from Fast_ECC_error trap (Trap 0x70) */
#define	C_AFSR_FECC_ERRS	(C_AFSR_UCU | C_AFSR_UCC | C_AFSR_ETI | \
				C_AFSR_ETC)

#else /* SERRANO */
/* JP AFSR bits from Fast_ECC_error trap (Trap 0x70) */
#define	C_AFSR_FECC_ERRS	(C_AFSR_UCU | C_AFSR_UCC)
#endif /* SERRANO */

#if defined(SERRANO)
/* SERRANO AFSR bits from Fatal errors (processor asserts ERROR pin) */
#define	C_AFSR_FATAL_ERRS	(C_AFSR_JETO | C_AFSR_SCE | C_AFSR_JEIC | \
			C_AFSR_JEIT | C_AFSR_JEIS | C_AFSR_IERR | \
			C_AFSR_ISAP | C_AFSR_EFES | C_AFSR_ETS | C_AFSR_ETU)

#else /* SERRANO */
/* JP AFSR bits from Fatal errors (processor asserts ERROR pin) */
#define	C_AFSR_FATAL_ERRS	(C_AFSR_JETO | C_AFSR_SCE | C_AFSR_JEIC | \
			C_AFSR_JEIT | C_AFSR_JEIS | C_AFSR_IERR | \
			C_AFSR_ISAP | C_AFSR_ETP)
#endif /* SERRANO */

/* JP AFSR all valid error status bits */
#define	C_AFSR_ALL_ERRS	(C_AFSR_FATAL_ERRS | C_AFSR_FECC_ERRS | \
			C_AFSR_CECC_ERRS | C_AFSR_ASYNC_ERRS | C_AFSR_ME)

#if defined(SERRANO)
/* SERRANO AFSR all ME status bits */
#define	C_AFSR_ALL_ME_ERRS	(C_AFSR_ISAP | C_AFSR_UE | C_AFSR_UCU | \
			C_AFSR_EDU | C_AFSR_WDU | C_AFSR_CPU | C_AFSR_UCC | \
			C_AFSR_BERR | C_AFSR_TO | C_AFSR_ETU | C_AFSR_OM | \
			C_AFSR_UMS | C_AFSR_IVPE | C_AFSR_RUE | C_AFSR_BP | \
			C_AFSR_WBP | C_AFSR_FRU | C_AFSR_JETO | C_AFSR_SCE | \
			C_AFSR_JEIC | C_AFSR_JEIT | C_AFSR_JEIS | \
			C_AFSR_ETC | C_AFSR_ETI)

#else /* SERRANO */
/* JP AFSR all ME status bits */
#define	C_AFSR_ALL_ME_ERRS	(C_AFSR_ISAP | C_AFSR_UE | C_AFSR_UCU | \
			C_AFSR_EDU | C_AFSR_WDU | C_AFSR_CPU | C_AFSR_UCC | \
			C_AFSR_BERR | C_AFSR_TO | C_AFSR_ETP | C_AFSR_OM | \
			C_AFSR_UMS | C_AFSR_IVPE | C_AFSR_RUE | C_AFSR_BP | \
			C_AFSR_WBP | C_AFSR_FRU | C_AFSR_JETO | C_AFSR_SCE | \
			C_AFSR_JEIC | C_AFSR_JEIT | C_AFSR_JEIS)
#endif /* SERRANO */

/* JP AFSR bits due to a Memory error */
#define	C_AFSR_MEMORY	(C_AFSR_UE | C_AFSR_CE | C_AFSR_FRC | C_AFSR_FRU |\
			C_AFSR_RCE | C_AFSR_RUE)

/* JP AFSR bits due to parity errors and have a valid BSYND */
#define	C_AFSR_MSYND_ERRS	(C_AFSR_IVPE | C_AFSR_BP | C_AFSR_WBP)

/* JP AFSR bits with a valid ESYND field */
#define	C_AFSR_ESYND_ERRS	(C_AFSR_UE | C_AFSR_CE | \
			C_AFSR_UCU | C_AFSR_UCC | C_AFSR_EDU | C_AFSR_EDC | \
			C_AFSR_WDU | C_AFSR_WDC | C_AFSR_CPU | C_AFSR_CPC | \
			C_AFSR_FRC | C_AFSR_FRU)

/* JP AFSR error bits for AFT Level 1 messages (uncorrected + TO + BERR) */
#define	C_AFSR_LEVEL1	(C_AFSR_UE | C_AFSR_RUE | C_AFSR_UCU | C_AFSR_EDU | \
			C_AFSR_WDU | C_AFSR_CPU | C_AFSR_IVPE | C_AFSR_TO | \
			C_AFSR_BERR | C_AFSR_UMS | C_AFSR_OM | C_AFSR_WBP | \
			C_AFSR_FRU | C_AFSR_BP)

#elif defined(CHEETAH_PLUS)

/* Ch+ AFSR bits from Disrupting (Corrected) ECC error Trap (Trap 0x63) */
#define	C_AFSR_CECC_ERRS	(C_AFSR_CE | C_AFSR_EMC | C_AFSR_EDU | \
			C_AFSR_EDC | C_AFSR_WDU | C_AFSR_WDC | C_AFSR_CPU | \
			C_AFSR_CPC | C_AFSR_IVU | C_AFSR_IVC | C_AFSR_DUE | \
			C_AFSR_THCE | C_AFSR_DBERR | C_AFSR_DTO | C_AFSR_IMU | \
			C_AFSR_IMC)

/* Ch+ AFSR bits from {Instruction,Data}_access_error traps (Traps 0xa, 0x32) */
#define	C_AFSR_ASYNC_ERRS	(C_AFSR_UE | C_AFSR_EMU | C_AFSR_EDU | \
			C_AFSR_TO | C_AFSR_BERR)

/* Ch+ AFSR bits from Fast_ECC_error trap (Trap 0x70) */
#define	C_AFSR_FECC_ERRS	(C_AFSR_UCU | C_AFSR_UCC | C_AFSR_TSCE)

/* Ch+ AFSR bits from Fatal errors (processor asserts ERROR pin) */
#define	C_AFSR_FATAL_ERRS	(C_AFSR_PERR | C_AFSR_IERR | C_AFSR_ISAP | \
			C_AFSR_TUE | C_AFSR_TUE_SH | C_AFSR_IMU | C_AFSR_EMU)

/* Ch+ AFSR all valid error status bits */
#define	C_AFSR_ALL_ERRS	(C_AFSR_FATAL_ERRS | C_AFSR_FECC_ERRS | \
			C_AFSR_CECC_ERRS | C_AFSR_ASYNC_ERRS | C_AFSR_ME)

/* Ch+ AFSR all errors that set ME bit, in both AFSR and AFSR_EXT */
#define	C_AFSR_ALL_ME_ERRS	(C_AFSR_TUE_SH | C_AFSR_IMU | C_AFSR_DTO | \
			C_AFSR_DBERR | C_AFSR_TSCE | C_AFSR_TUE | C_AFSR_DUE | \
			C_AFSR_ISAP | C_AFSR_EMU | C_AFSR_IVU | C_AFSR_TO | \
			C_AFSR_BERR | C_AFSR_UCC | C_AFSR_UCU | C_AFSR_CPU | \
			C_AFSR_WDU | C_AFSR_EDU | C_AFSR_UE | \
			C_AFSR_L3_TUE_SH | C_AFSR_L3_TUE | C_AFSR_L3_EDU | \
			C_AFSR_L3_UCC | C_AFSR_L3_UCU | C_AFSR_L3_CPU | \
			C_AFSR_L3_WDU)

/* Ch+ AFSR bits due to an Ecache data error */
#define	C_AFSR_EC_DATA_ERRS	(C_AFSR_UCU | C_AFSR_UCC | C_AFSR_EDU | \
			C_AFSR_EDC | C_AFSR_WDU | C_AFSR_WDC | C_AFSR_CPU | \
			C_AFSR_CPC)

/* Ch+ AFSR bits due to a Memory error */
#define	C_AFSR_MEMORY	(C_AFSR_UE | C_AFSR_CE | C_AFSR_EMU | C_AFSR_EMC | \
			C_AFSR_DUE)

/* Ch+ AFSR bits due to an Mtag error and have a valid MSYND */
#define	C_AFSR_MSYND_ERRS	(C_AFSR_EMU | C_AFSR_EMC | C_AFSR_IMU | \
			C_AFSR_IMC)

/* Ch+ AFSR bits with a valid ESYND field */
#define	C_AFSR_ESYND_ERRS	(C_AFSR_UE | C_AFSR_CE | \
			C_AFSR_UCU | C_AFSR_UCC | C_AFSR_EDU | C_AFSR_EDC | \
			C_AFSR_WDU | C_AFSR_WDC | C_AFSR_CPU | C_AFSR_CPC | \
			C_AFSR_IVU | C_AFSR_IVC | C_AFSR_DUE)

/* Ch+ AFSR error bits for AFT Level 1 messages (uncorrected + TO + BERR) */
#define	C_AFSR_LEVEL1	(C_AFSR_UE | C_AFSR_UCU | C_AFSR_EMU | C_AFSR_EDU | \
			C_AFSR_WDU | C_AFSR_CPU | C_AFSR_IVU | C_AFSR_TO | \
			C_AFSR_BERR | C_AFSR_DUE | C_AFSR_TUE | C_AFSR_DTO | \
			C_AFSR_DBERR | C_AFSR_TUE_SH | C_AFSR_IMU)

#else	/* CHEETAH_PLUS */

/* AFSR bits from Disrupting (Corrected) ECC error Trap (Trap 0x63) */
#define	C_AFSR_CECC_ERRS	(C_AFSR_CE | C_AFSR_EMC | C_AFSR_EDU | \
			C_AFSR_EDC | C_AFSR_WDU | C_AFSR_WDC | C_AFSR_CPU | \
			C_AFSR_CPC | C_AFSR_IVU | C_AFSR_IVC)

/* AFSR bits from {Instruction,Data}_access_error traps (Traps 0xa, 0x32) */
#define	C_AFSR_ASYNC_ERRS	(C_AFSR_UE | C_AFSR_EMU | C_AFSR_EDU | \
			C_AFSR_TO | C_AFSR_BERR)

/* AFSR bits from Fast_ECC_error trap (Trap 0x70) */
#define	C_AFSR_FECC_ERRS	(C_AFSR_UCU | C_AFSR_UCC)

/* AFSR bits from Fatal errors (processor asserts ERROR pin) */
#define	C_AFSR_FATAL_ERRS	(C_AFSR_PERR | C_AFSR_IERR | C_AFSR_ISAP | \
			C_AFSR_EMU)

/* AFSR all valid error status bits */
#define	C_AFSR_ALL_ERRS	(C_AFSR_FATAL_ERRS | C_AFSR_FECC_ERRS | \
			C_AFSR_CECC_ERRS | C_AFSR_ASYNC_ERRS | C_AFSR_ME)

/* AFSR all ME status bits */
#define	C_AFSR_ALL_ME_ERRS	(C_AFSR_ISAP | C_AFSR_UE | C_AFSR_IVU | \
			C_AFSR_EMU | C_AFSR_UCU | C_AFSR_EDU | C_AFSR_WDU | \
			C_AFSR_CPU | C_AFSR_UCC | C_AFSR_BERR | C_AFSR_TO)

/* AFSR bits due to an Ecache error */
#define	C_AFSR_EC_DATA_ERRS	(C_AFSR_UCU | C_AFSR_UCC | C_AFSR_EDU | \
			C_AFSR_EDC | C_AFSR_WDU | C_AFSR_WDC | C_AFSR_CPU | \
			C_AFSR_CPC)

/* AFSR bits due to a Memory error */
#define	C_AFSR_MEMORY	(C_AFSR_UE | C_AFSR_CE | C_AFSR_EMU | C_AFSR_EMC)

/* AFSR bits due to an Mtag error and have a valid MSYND */
#define	C_AFSR_MSYND_ERRS	(C_AFSR_EMU | C_AFSR_EMC)

/* AFSR bits with a valid ESYND field */
#define	C_AFSR_ESYND_ERRS	(C_AFSR_UE | C_AFSR_CE | \
			C_AFSR_UCU | C_AFSR_UCC | C_AFSR_EDU | C_AFSR_EDC | \
			C_AFSR_WDU | C_AFSR_WDC | C_AFSR_CPU | C_AFSR_CPC | \
			C_AFSR_IVU | C_AFSR_IVC)

/* AFSR error bits for AFT Level 1 messages (uncorrected + TO + BERR) */
#define	C_AFSR_LEVEL1	(C_AFSR_UE | C_AFSR_UCU | C_AFSR_EMU | C_AFSR_EDU | \
			C_AFSR_WDU | C_AFSR_CPU | C_AFSR_IVU | C_AFSR_TO | \
			C_AFSR_BERR)

#endif	/* CHEETAH_PLUS */

#if defined(JALAPENO) || defined(SERRANO)
/* AFSR all valid bits (except for ETW) */
#define	C_AFSR_MASK	(C_AFSR_ALL_ERRS | C_AFSR_PRIV | C_AFSR_B_SYND | \
			C_AFSR_E_SYND | C_AFSR_AID | C_AFSR_JREQ)
#else /* JALAPENO || SERRANO */
/* AFSR all valid bits */
#define	C_AFSR_MASK	(C_AFSR_ALL_ERRS | C_AFSR_PRIV | C_AFSR_M_SYND | \
			C_AFSR_E_SYND)
#endif /* JALAPENO || SERRANO */

/*
 * Panther AFSR_EXT bits from Disrupting (Corrected) ECC error Trap
 * (Trap 0x63)
 */
#define	C_AFSR_EXT_CECC_ERRS	(C_AFSR_L3_EDU | C_AFSR_L3_EDC | \
			C_AFSR_L3_WDU | C_AFSR_L3_WDC | C_AFSR_L3_CPU | \
			C_AFSR_L3_CPC | C_AFSR_L3_THCE)

/*
 * Panther AFSR_EXT bits from {Instruction,Data}_access_error traps
 * (Traps 0xa, 0x32)
 */
#define	C_AFSR_EXT_ASYNC_ERRS	(C_AFSR_L3_EDU)

/* Panther AFSR_EXT bits from Fast_ECC_error trap (Trap 0x70) */
#define	C_AFSR_EXT_FECC_ERRS	(C_AFSR_L3_UCU | C_AFSR_L3_UCC)

/* Panther AFSR_EXT bits from Fatal errors (processor asserts ERROR pin) */
#define	C_AFSR_EXT_FATAL_ERRS	(C_AFSR_L3_TUE | C_AFSR_L3_TUE_SH | \
			C_AFSR_RED_ERR | C_AFSR_EFA_PAR_ERR)

/* Panther AFSR_EXT all valid error status bits */
#define	C_AFSR_EXT_ALL_ERRS	(C_AFSR_EXT_FATAL_ERRS | \
			C_AFSR_EXT_FECC_ERRS | C_AFSR_EXT_CECC_ERRS | \
			C_AFSR_EXT_ASYNC_ERRS | C_AFSR_L3_MECC)

/* Panther AFSR_EXT bits for errors to report a L3 cache data resource */
#define	C_AFSR_EXT_L3_DATA_ERRS	(C_AFSR_L3_WDU | C_AFSR_L3_WDC | \
			C_AFSR_L3_CPU | C_AFSR_L3_CPC | C_AFSR_L3_UCU | \
			C_AFSR_L3_UCC | C_AFSR_L3_EDU | C_AFSR_L3_EDC | \
			C_AFSR_L3_MECC)

/* Panther AFSR_EXT bits with a valid ESYND field */
#define	C_AFSR_EXT_ESYND_ERRS	(C_AFSR_L3_UCU | C_AFSR_L3_UCC | \
			C_AFSR_L3_EDU | C_AFSR_L3_EDC | C_AFSR_L3_WDU | \
			C_AFSR_L3_WDC | C_AFSR_L3_CPU | C_AFSR_L3_CPC)

/* PANTHER AFSR_EXT error bits for AFT Level 1 messages (uncorrected) */
#define	C_AFSR_EXT_LEVEL1	(C_AFSR_L3_UCU | C_AFSR_L3_EDU | \
			C_AFSR_L3_WDU | C_AFSR_L3_CPU | C_AFSR_L3_TUE | \
			C_AFSR_L3_TUE_SH)

/*
 * AFSR / AFSR_EXT bits for which we need to panic the system.
 */
#define	C_AFSR_PANIC(errs)	(((errs) & (C_AFSR_FATAL_ERRS | \
			C_AFSR_EXT_FATAL_ERRS)) != 0)

/*
 * For the Fast ECC TL1 handler, we are limited in how many registers
 * we can use, so we need to store the AFSR_EXT bits within the AFSR
 * register using some of the AFSR reserved bits.
 */
#define	AFSR_EXT_IN_AFSR_MASK	C_AFSR_EXT_ALL_ERRS
#define	AFSR_EXT_IN_AFSR_SHIFT	20

/*
 * Defines for the flag field in the CPU logout structure.  See the
 * definition of ch_cpu_logout_t for further description.
 */
#define	CLO_FLAGS_TT_MASK	0xff000
#define	CLO_FLAGS_TT_SHIFT	12
#define	CLO_FLAGS_TL_MASK	0xf00
#define	CLO_FLAGS_TL_SHIFT	8
#define	CLO_NESTING_MAX		20	/* Arbitrary maximum value */

#define	C_M_SYND_SHIFT	16
#define	GET_M_SYND(afsr)	(((afsr) & C_AFSR_M_SYND) >> C_M_SYND_SHIFT)
#define	GET_E_SYND(afsr)	((afsr) & C_AFSR_E_SYND)

/*
 * Bits of Cheetah Asynchronous Fault Address Register
 */
#define	C_AFAR_PA INT64_C(0x000007fffffffff0) /* PA<42:4> physical address */

/*
 * Defines for the different types of dcache_flush
 * it is stored in dflush_type
 */
#define	FLUSHALL_TYPE	0x0		/* blasts all cache lines */
#define	FLUSHMATCH_TYPE	0x1		/* flush entire cache but check each */
					/* each line for a match */
#define	FLUSHPAGE_TYPE	0x2		/* flush only one page and check */
					/* each line for a match */

/*
 * D-Cache Tag Data Register
 *
 * +----------+--------+----------+
 * | Reserved | DC_Tag | DC_Valid |
 * +----------+--------+----------+
 *  63	    31 30     1		 0
 *
 */
#define	ICACHE_FLUSHSZ	0x20	/* one line in i$ */
#define	CHEETAH_DC_VBIT_SHIFT	1
#define	CHEETAH_DC_VBIT_MASK	0x1

/*
 * Define for max size of "reason" string in panic flows.  Since this is on
 * the stack, we want to keep it as small as is reasonable.
 */
#define	MAX_REASON_STRING	40

/*
 * These error types are specific to Cheetah and are used internally for the
 * Cheetah fault structure flt_type field.
 */
#define	CPU_TO			1	/* Timeout */
#define	CPU_BERR		2	/* Bus Error */
#define	CPU_CE			3	/* Correctable Memory Error */
#define	CPU_UE			4	/* Uncorrectable Memory Error */
#define	CPU_CE_ECACHE		5	/* Correctable Ecache Error */
#define	CPU_UE_ECACHE		6	/* Uncorrectable Ecache Error */
#define	CPU_EMC			7	/* Correctable Mtag Error */
#define	CPU_FATAL		8	/* Fatal Error */
#define	CPU_ORPH		9	/* Orphaned UCC/UCU error */
#define	CPU_IV			10	/* IVU or IVC */
#define	CPU_INV_AFSR		11	/* Invalid AFSR */
#define	CPU_UE_ECACHE_RETIRE	12	/* Uncorrectable Ecache, retire page */
#define	CPU_IC_PARITY		13	/* Icache parity error trap */
#define	CPU_DC_PARITY		14	/* Dcache parity error trap */
#define	CPU_DUE			15	/* Disrupting UE */
#define	CPU_FPUERR		16	/* FPU Error */
/*
 * These next six error types (17-22) are only used in Jalapeno code
 */
#define	CPU_RCE			17	/* Correctable remote memory error */
#define	CPU_RUE			18	/* Uncorrectable remote memory error */
#define	CPU_FRC			19	/* Correctable foreign memory error */
#define	CPU_FRU			20	/* Uncorrectable foreign memory error */
#define	CPU_BPAR		21	/* Bus parity (BP or WBP) errorrs */
#define	CPU_UMS			22	/* Unsupported memory store */
/*
 * These next four error types (23-26) are only used in Panther code
 */
#define	CPU_PC_PARITY		23	/* Pcache parity error */
#define	CPU_ITLB_PARITY		24	/* Panther ITLB parity error */
#define	CPU_DTLB_PARITY		25	/* Panther DTLB parity error */
#define	CPU_L3_ADDR_PE		26	/* Panther L3$ address parity error */

/*
 * Sets trap table entry ttentry by overwriting eight instructions from ttlabel
 */
#define	CH_SET_TRAP(ttentry, ttlabel)			\
		bcopy((const void *)&ttlabel, &ttentry, 32);		\
		flush_instr_mem((caddr_t)&ttentry, 32);

/*
 * Return values for implementation specific error logging in the routine
 * cpu_impl_async_log_err()
 */
#define	CH_ASYNC_LOG_DONE	0	/* finished logging the error */
#define	CH_ASYNC_LOG_CONTINUE	1	/* continue onto handle panicker */
#define	CH_ASYNC_LOG_UNKNOWN	2	/* unknown error type */
#define	CH_ASYNC_LOG_RECIRC	3	/* suppress logging of error */

#ifndef	_ASM

/*
 * Define Cheetah family (UltraSPARC-III) specific asynchronous error structure
 */
typedef struct cheetah_async_flt {
	struct async_flt cmn_asyncflt;	/* common - see sun4u/sys/async.h */
	ushort_t flt_type;		/* types of faults - cpu specific */
	uint64_t flt_bit;		/* fault bit for this log msg */
	uint64_t afsr_ext;		/* Panther has an AFSR_EXT register */
	uint64_t afsr_errs;		/* Store all AFSR error bits together */
	uint64_t afar2;			/* Serrano has an AFAR2 for FRC/FRU */
	ch_diag_data_t flt_diag_data;	/* Diagnostic data */
	int flt_data_incomplete;	/* Diagnostic data is incomplete */
	int flt_trapped_ce;		/* CEEN fault caught by trap handler */
#if defined(CPU_IMP_L1_CACHE_PARITY)
	ch_l1_parity_log_t parity_data;	/* L1$ Parity error logging info */
#endif	/* CPU_IMP_L1_CACHE_PARITY */
	pn_tlb_logout_t tlb_diag_data;	/* TLB parity error Diagnostic data */
	uint32_t flt_fpdata[16];	/* Data from fpras failure */
	uint64_t flt_sdw_afar;		/* Shadow AFAR */
	uint64_t flt_sdw_afsr;		/* Shadow AFSR */
	uint64_t flt_sdw_afsr_ext;	/* Shadow Extended AFSR */
} ch_async_flt_t;

#define	ECC_ALL_TRAPS	(ECC_D_TRAP | ECC_I_TRAP | ECC_C_TRAP | ECC_F_TRAP)
#define	ECC_ORPH_TRAPS	(ECC_D_TRAP | ECC_I_TRAP | ECC_C_TRAP)
#define	ECC_ASYNC_TRAPS	(ECC_D_TRAP | ECC_I_TRAP)
#define	ECC_MECC_TRAPS	(ECC_D_TRAP | ECC_C_TRAP | ECC_F_TRAP)

/*
 * Error type table struct.
 */
typedef struct ecc_type_to_info {
	uint64_t	ec_afsr_bit;	/* AFSR bit of error */
	char		*ec_reason;	/* Short error description */
	uint_t		ec_flags;	/* Trap type error should be seen at */
	int		ec_flt_type;	/* Used by cpu_async_log_err */
	char		*ec_desc;	/* Long error description */
	uint64_t	ec_err_payload;	/* FM ereport payload information */
	char		*ec_err_class;	/* FM ereport class */
} ecc_type_to_info_t;

typedef struct bus_config_eclk {
	uint_t		divisor;
	uint64_t	mask;
} bus_config_eclk_t;

#endif /* _ASM */

#endif /* _KERNEL */

#ifndef _ASM

#include <sys/cpuvar.h>

/*
 * Since all the US3_* files share a bunch of routines between each other
 * we will put all the "extern" definitions in this header file so that we
 * don't have to repeat it all in every file.
 */

/*
 * functions that are defined in the US3 cpu module:
 * -------------------------------------------------
 */
extern uint64_t get_safari_config(void);
extern void set_safari_config(uint64_t safari_config);
extern void shipit(int, int);
extern void cpu_aflt_log(int ce_code, int tagnum, ch_async_flt_t *aflt,
    uint_t logflags, const char *endstr, const char *fmt, ...);
extern uint8_t flt_to_trap_type(struct async_flt *aflt);
extern void cpu_log_err(struct async_flt *aflt);
extern void cpu_page_retire(ch_async_flt_t *ch_flt);
extern int clear_errors(ch_async_flt_t *ch_flt);
extern void cpu_init_ecache_scrub_dr(struct cpu *cp);
extern void get_cpu_error_state(ch_cpu_errors_t *);
extern void set_cpu_error_state(ch_cpu_errors_t *);
extern int cpu_flt_in_memory(ch_async_flt_t *ch_flt, uint64_t t_afsr_bit);
extern int cpu_queue_events(ch_async_flt_t *ch_flt, char *reason,
    uint64_t t_afsr, ch_cpu_logout_t *clop);
extern void cpu_error_ecache_flush(ch_async_flt_t *);
extern void cpu_clearphys(struct async_flt *aflt);
extern void cpu_async_log_ic_parity_err(ch_async_flt_t *);
extern void cpu_async_log_dc_parity_err(ch_async_flt_t *);
extern uint64_t get_ecache_ctrl(void);
extern uint64_t get_jbus_config(void);
extern void set_jbus_config(uint64_t jbus_config);
extern uint64_t get_mcu_ctl_reg1(void);
extern void set_mcu_ctl_reg1(uint64_t mcu_ctl);
extern void cpu_init_trap(void);
extern int cpu_ecache_nway(void);
extern void cpu_delayed_logout(size_t, ch_cpu_logout_t *);
extern void cpu_payload_add_pcache(struct async_flt *, nvlist_t *);
extern void cpu_payload_add_tlb(struct async_flt *, nvlist_t *);
extern int cpu_scrub_cpu_setup(cpu_setup_t, int, void *);
#if defined(JALAPENO) || defined(SERRANO)
extern int afsr_to_jaid_status(uint64_t afsr, uint64_t afsr_bit);
#endif	/* JALAPENO || SERRANO */
/*
 * Address of the level 15 interrupt handler preamble, used to log Fast ECC
 * at TL>0 errors, which will be moved to the trap table address above.
 */
extern void ch_pil15_interrupt_instr();
#ifdef CHEETAHPLUS_ERRATUM_25
extern int mondo_recover(uint16_t, int);
#endif	/* CHEETAHPLUS_ERRATUM_25 */
/*
 * Adddresses of the Fast ECC Error trap handler preambles which will be
 * moved to the appropriate trap table addresses.
 */
extern void fecc_err_instr(void);
extern void fecc_err_tl1_instr(void);
extern void fecc_err_tl1_cont_instr(void);

extern int afsr_to_overw_status(uint64_t afsr, uint64_t afsr_bit,
    uint64_t *ow_bits);
#if defined(CHEETAH_PLUS)
extern int afsr_to_pn_esynd_status(uint64_t afsr, uint64_t afsr_bit);
#endif	/* CHEETAH_PLUS */
extern void flush_ecache(uint64_t physaddr, size_t ecachesize, size_t linesize);
extern void flush_dcache(void);
extern void flush_icache(void);
extern void flush_pcache(void);
extern void flush_ipb(void);
extern uint64_t get_dcu(void);
extern void set_dcu(uint64_t ncc);
extern void scrubphys(uint64_t paddr, int ecache_set_size);
extern void clearphys(uint64_t paddr, int ecache_set_size, int ecache_linesize);
extern void stick_adj(int64_t skew);
extern void stick_timestamp(int64_t *ts);
extern void icache_inval_all(void);
extern void dcache_inval_line(int index);
extern void ecache_flush_line(uint64_t flushaddr, int ec_size);
extern int ecache_get_lineinfo(uint32_t ecache_index, uint64_t *tag,
		uint64_t *data);
#if defined(CPU_IMP_L1_CACHE_PARITY)
extern void get_dcache_dtag(uint32_t dcache_idx, uint64_t *data);
extern void get_icache_dtag(uint32_t icache_idx, uint64_t *data);
extern void get_pcache_dtag(uint32_t pcache_idx, uint64_t *data);
extern void correct_dcache_parity(size_t dcache_size, size_t dcache_linesize);
#endif	/* CPU_IMP_L1_CACHE_PARITY */
extern void cpu_check_block(caddr_t, uint_t);
extern uint32_t us3_gen_ecc(uint64_t data_low, uint64_t data_high);
extern int cpu_impl_async_log_err(void *, errorq_elem_t *);
extern void cpu_fast_ecc_error(struct regs *rp, ulong_t p_clo_flags);
extern void cpu_tl1_error(struct regs *rp, int panic);
extern void cpu_tl1_err_panic(struct regs *rp, ulong_t flags);
extern void cpu_disrupting_error(struct regs *rp, ulong_t p_clo_flags);
extern void cpu_deferred_error(struct regs *rp, ulong_t p_clo_flags);
#if defined(CPU_IMP_L1_CACHE_PARITY)
extern void cpu_parity_error(struct regs *rp, uint_t flags, caddr_t tpc);
#endif	/* CPU_IMP_L1_CACHE_PARITY */
extern void claimlines(uint64_t startpa, size_t len, int stride);
extern void copy_tsb_entry(uintptr_t src, uintptr_t dest);
extern void hwblkpagecopy(const void *src, void *dst);
#if defined(CHEETAH_PLUS)
extern void pn_cpu_log_diag_l2_info(ch_async_flt_t *ch_flt);
extern void set_afsr_ext(uint64_t afsr_ext);
#endif
extern void cpu_tlb_parity_error(struct regs *rp, ulong_t trap_va,
    ulong_t tlb_info);
extern void log_flt_func(struct async_flt *aflt, char *unum);
extern uint64_t pn_get_tlb_index(uint64_t va, uint64_t pg_sz);
extern int popc64(uint64_t val);

/*
 * variables and structures that are defined in the US3 cpu module:
 * ----------------------------------------------------------------
 */
extern bus_config_eclk_t bus_config_eclk[];
extern ecc_type_to_info_t ecc_type_to_info[];
extern uint64_t ch_err_tl1_paddrs[];
extern uchar_t ch_err_tl1_pending[];
#ifdef CHEETAHPLUS_ERRATUM_25
/*
 * Tunable defined in us3_common.c
 */
extern int cheetah_sendmondo_recover;
#endif	/* CHEETAHPLUS_ERRATUM_25 */
/*
 * The following allows for a one time calculation of the number of dcache
 * lines vs. calculating the number every time through the scrub routine.
 */
int dcache_nlines;			/* max number of D$ lines */

extern uint64_t afar_overwrite[];
extern uint64_t esynd_overwrite[];
extern uint64_t msynd_overwrite[];

#if defined(JALAPENO) || defined(SERRANO)
extern uint64_t jreq_overwrite[];
#if defined(SERRANO)
extern uint64_t	afar2_overwrite[];
#endif	/* SERRANO */
#endif	/* JALAPENO || SERRANO */

/*
 * variables and structures that are defined outside the US3 cpu module:
 * ---------------------------------------------------------------------
 */
extern uint64_t xc_tick_limit;
extern uint64_t xc_tick_jump_limit;
extern struct kmem_cache *ch_private_cache;

#if defined(CPU_IMP_L1_CACHE_PARITY)
/*
 * Addresses of the Dcache and Icache parity error trap table entries.
 * If L1 cache parity protection is implemented, need to replace Dcache and
 * Icache parity error handlers.
 */
extern void *tt0_dperr;
extern void *tt1_dperr;
extern void *tt1_swtrap1;
extern void *tt0_iperr;
extern void *tt1_iperr;
extern void *tt1_swtrap2;
/*
 * Addresses of the Dcache and Icache parity error trap preambles, which will
 * be moved to the appropriate trap table addresses.
 */
extern void dcache_parity_instr();
extern void dcache_parity_tl1_instr();
extern void dcache_parity_tl1_cont_instr();
extern void icache_parity_instr();
extern void icache_parity_tl1_instr();
extern void icache_parity_tl1_cont_instr();
#endif	/* CPU_IMP_L1_CACHE_PARITY */

/*
 * Addresses of the Fast ECC error trap table entries.
 */
extern void *tt0_fecc;
extern void *tt1_fecc;
extern void *tt1_swtrap0;
/*
 * Address of trap table level 15 interrupt handler in the trap table.
 */
extern void *tt_pil15;
/*
 * D$ and I$ global parameters.
 */
extern int dcache_size;
extern int dcache_linesize;
extern int icache_size;
extern int icache_linesize;

/*
 * Set of all offline cpus
 */
extern cpuset_t cpu_offline_set;

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_US3_MODULE_H */
