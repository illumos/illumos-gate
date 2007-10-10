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

#ifndef _SYS_CHEETAHREGS_H
#define	_SYS_CHEETAHREGS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/machasi.h>
#include <sys/cpu_impl.h>
#ifdef _KERNEL
#include <sys/fpras.h>
#endif /* _KERNEL */

/*
 * This file is cpu dependent.
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Cheetah includes the process info in its mask to make things
 * more difficult.  The process is the low bit of the major mask,
 * so to convert to the netlist major:
 * netlist_major = ((mask_major >> 1) + 1)
 */
#define	REMAP_CHEETAH_MASK(x)	(((((x) >> 1) + 0x10) & 0xf0) | ((x) & 0xf))

#ifdef _ASM
/*
 * assembler doesn't understand the 'ull' suffix for C constants so
 * use the inttypes.h macros and undefine them here for assembly code
 */
#undef INT64_C
#undef UINT64_C
#define	INT64_C(x)	(x)
#define	UINT64_C(x)	(x)
#endif	/* _ASM */

/*
 * DCU Control Register
 *
 * +------+----+----+----+----+----+-----+-----+----+----+----+
 * | Resv | CP | CV | ME | RE | PE | HPE | SPE | SL | WE | PM |
 * +------+----+----+----+----+----+-----+-----+----+----+----+
 *  63:50   49   48   47   46	45    44    43   42   41 40:33
 *
 * +----+----+----+----+----+----------+-----+----+----+----+---+
 * | VM | PR | PW | VR | VW | Reserved | WIH | DM | IM | DC | IC|
 * +----+----+----+----+----+----------+-----+----+----+----+---+
 * 32:25  24   23   22   21      20:5     4     3    2    1   0
 */

#define	ASI_DCU	ASI_LSU			    /* same as spitfire ASI_LSU 0x45 */
#define	DCU_IC	INT64_C(0x0000000000000001) /* icache enable		*/
#define	DCU_DC	INT64_C(0x0000000000000002) /* dcache enable		*/
#define	DCU_IM	INT64_C(0x0000000000000004) /* immu enable		*/
#define	DCU_DM	INT64_C(0x0000000000000008) /* dmmu enable		*/
#define	DCU_WIH	INT64_C(0x0000000000000010) /* Jaguar only - W$ hash index */
#define	DCU_VW	INT64_C(0x0000000000200000) /* virt watchpoint write enable  */
#define	DCU_VR	INT64_C(0x0000000000400000) /* virt watchpoint read enable   */
#define	DCU_PW	INT64_C(0x0000000000800000) /* phys watchpoint write enable  */
#define	DCU_PR	INT64_C(0x0000000001000000) /* phys watchpoint read enable   */
#define	DCU_VM	INT64_C(0x00000001FE000000) /* virtual watchpoint write mask */
#define	DCU_PM	INT64_C(0x000001FE00000000) /* phys watchpoint write mask    */
#define	DCU_WE	INT64_C(0x0000020000000000) /* write cache enable	*/
#define	DCU_SL	INT64_C(0x0000040000000000) /* second load control	*/
#define	DCU_SPE	INT64_C(0x0000080000000000) /* software prefetch enable */
#define	DCU_HPE	INT64_C(0x0000100000000000) /* hardware prefetch enable */
#define	DCU_PE	INT64_C(0x0000200000000000) /* prefetch enable		*/
#define	DCU_RE	INT64_C(0x0000400000000000) /* RAW bypass enable	*/
#define	DCU_ME	INT64_C(0x0000800000000000) /* noncache store merging enable */
#define	DCU_CV	INT64_C(0x0001000000000000) /* virt cacheability when DM=0   */
#define	DCU_CP	INT64_C(0x0002000000000000) /* phys cacheable when DM,IM=0   */
#define	DCU_CACHE (DCU_IC|DCU_DC|DCU_WE|DCU_SPE|DCU_HPE|DCU_PE)

/*
 * bit shifts for the prefetch enable bit
 */
#define	DCU_PE_SHIFT	45

/*
 * Safari Configuration Register
 */
#define	ASI_SAFARI_CONFIG	ASI_UPA_CONFIG /* Safari Config Reg, 0x4A */
#define	SAFARI_CONFIG_ECLK_1	INT64_C(0x0000000000000000) /* 1/1 clock */
#define	SAFARI_CONFIG_ECLK_1_DIV	1	/* clock divisor: 1 */
#define	SAFARI_CONFIG_ECLK_2	INT64_C(0x0000000040000000) /* 1/2 clock */
#define	SAFARI_CONFIG_ECLK_2_DIV	2	/* clock divisor: 2 */
#define	SAFARI_CONFIG_ECLK_32	INT64_C(0x0000000080000000) /* 1/32 clock */
#define	SAFARI_CONFIG_ECLK_32_DIV	32	/* clock divisor: 32 */
#define	SAFARI_CONFIG_ECLK_MASK	(SAFARI_CONFIG_ECLK_32 | SAFARI_CONFIG_ECLK_2)

#if defined(JALAPENO) || defined(SERRANO)
/*
 * JBUS Configuration Register
 */
#define	ASI_JBUS_CONFIG		ASI_UPA_CONFIG /* JBUS Config Reg, 0x4A */
#define	JBUS_CONFIG_ECLK_1	INT64_C(0x0000000000000000) /* 1/1 clock */
#define	JBUS_CONFIG_ECLK_1_DIV	1	/* clock divisor: 1 */
#define	JBUS_CONFIG_ECLK_2	INT64_C(0x0000000000002000) /* 1/2 clock */
#define	JBUS_CONFIG_ECLK_2_DIV	2	/* clock divisor: 2 */
#define	JBUS_CONFIG_ECLK_32	INT64_C(0x0000000000004000) /* 1/32 clock */
#define	JBUS_CONFIG_ECLK_32_DIV	32	/* clock divisor: 32 */
#define	JBUS_CONFIG_ECLK_MASK	(JBUS_CONFIG_ECLK_32 | JBUS_CONFIG_ECLK_2)
#define	JBUS_CONFIG_ECLK_SHIFT	13

/*
 * Jalapeno/Serrano MCU control registers and ASI
 */
#define	ASI_MCU_CTRL		0x72		/* MCU Control Reg ASI */
#define	JP_MCU_FSM_MASK		INT64_C(0x0000000006000000) /* 26..25 */
#define	JP_MCU_FSM_SHIFT	25
#endif /* JALAPENO || SERRANO */

#if defined(SERRANO)
#define	ASI_MCU_AFAR2_VA	0x18	/* captures FRC/FRU addr */
#endif	/* SERRANO */

#if defined(JALAPENO) && defined(JALAPENO_ERRATA_85)
/*
 * Tomatillo Estar control registers (for JP Errataum 85)
 */
#define	JBUS_SLAVE_T_PORT_BIT	48
#define	TOM_HIGH_PA		0x400		/* Hi 32 bit of Tom reg PA */
#define	M_T_ESTAR_CTRL_PA	0x0f410050	/* M T estar PA */
#define	S_T_ESTAR_CTRL_PA	0x0e410050	/* S T estar PA */
#define	M_T_J_CHNG_INIT_PA	0x0f410058	/* Master T estar PA */
#define	TOM_ESTAR_ELCK_MASK	0x23		/* bit 5,1,0 */
#define	TOM_FULL_SPEED		0x1
#define	TOM_HALF_SPEED		0x2
#define	TOM_SLOW_SPEED		0x20
#define	TOM_TRIGGER_MASK	0x18
#define	TOM_TRIGGER		0x10

#endif /* JALAPENO && JALAPENO_ERRATA_85 */


/*
 * Miscellaneous ASI definitions not in machasi.h
 */
#define	ASI_DC_UTAG		0x43	/* Dcache Microtag Fields */
#define	ASI_DC_SNP_TAG		0x44	/* Dcache Snoop Tag Fields */
#define	ASI_IC_SNP_TAG		0x68	/* Icache Snoop Tag Fields */
#define	ASI_IPB_DATA		0x69	/* Instruction Prefetch Buffer Data */
#define	ASI_IPB_TAG		0x6A	/* Instruction Prefetch Buffer Tag */
#define	ASI_MC_DECODE		0x72	/* Memory Address Decoding Registers */
#define	ASI_EC_CFG_TIMING	0x73	/* Jaguar shared Ecache Control Reg */
#define	ASI_EC_DATA		0x74	/* Ecache Data Staging Registers */
#define	ASI_EC_CTRL		0x75	/* Ecache Control Register */
#define	ASI_PC_STATUS_DATA	0x30	/* Pcache Status Data Access */
#define	ASI_PC_DATA		0x31	/* Pcache Diagnostic Data Register */
#define	ASI_PC_TAG		0x32	/* Pcache Virtual Tag/Valid Field */
#define	ASI_PC_SNP_TAG		0x33	/* Pcache Snoop Tag Register */
#define	ASI_L2_DATA		0x6B	/* L2 cache Data Diagnostic Access */
#define	ASI_L2_TAG		0x6C	/* L2 cache Tag Diagnostic Access */

/*
 * Bits of Cheetah Asynchronous Fault Status Register
 *
 * +---+--+----+----+----+----+---+---+---+---+--+----
 * |rsv|ME|PRIV|PERR|IERR|ISAP|EMC|EMU|IVC|IVU|TO|BERR
 * +---+--+----+----+----+----+---+---+---+---+--+----
 * 63:54 53 52   51   50   49   48  47  46  45 44  43
 * +---+---+---+---+---+---+---+---+--+--+---+------+---+-------+
 * |UCC|UCU|CPC|CPU|WDC|WDU|EDC|EDU|UE|CE|rsv|M_SYND|rsv||E_SYND|
 * +---+---+---+---+---+---+---+---+--+--+---+------+---+-------+
 *   42  41  40  39  38  37  36  35 34 33 32:20 19:16 15:9 8:0
 *
 */
#if defined(CHEETAH_PLUS)
/*
 * Bits of Cheetah+ Asynchronous Fault Status Register
 *
 * +------------------+----------------------------
 * |rsv|TUE_SH|IMC|IMU|DTO|DBERR|THCE|TSCE|TUE|DUE|
 * +------------------+---------------------------- . . .
 *   63    62   61  60  59    58   57   56  55  54
 *
 * Note that bits 60-62 are only implemented in Panther (reserved
 * in Cheetah+ and Jaguar. Also, bit 56 is reserved in Panther instead
 * of TSCE since those errors are HW corrected in Panther.
 */
#define	C_AFSR_TUE_SH INT64_C(0x4000000000000000) /* uncorrectable tag UE  */
#define	C_AFSR_IMC  INT64_C(0x2000000000000000)	/* intr vector MTAG ECC */
#define	C_AFSR_IMU  INT64_C(0x1000000000000000)	/* intr vector MTAG ECC */
#define	C_AFSR_DTO  INT64_C(0x0800000000000000)	/* disrupting TO error */
#define	C_AFSR_DBERR INT64_C(0x0400000000000000) /* disrupting BERR error */
#define	C_AFSR_THCE INT64_C(0x0200000000000000)	/* h/w correctable E$ tag err */
#define	C_AFSR_TSCE INT64_C(0x0100000000000000)	/* s/w correctable E$ tag err */
#define	C_AFSR_TUE  INT64_C(0x0080000000000000)	/* uncorrectable E$ tag error */
#define	C_AFSR_DUE  INT64_C(0x0040000000000000)	/* disrupting UE error */
#endif	/* CHEETAH_PLUS */
#define	C_AFSR_ME   INT64_C(0x0020000000000000)	/* errors > 1, same type!=CE */
#define	C_AFSR_PRIV INT64_C(0x0010000000000000)	/* priv code access error    */
#define	C_AFSR_PERR INT64_C(0x0008000000000000)	/* system interface protocol */
#define	C_AFSR_IERR INT64_C(0x0004000000000000)	/* internal system interface */
#define	C_AFSR_ISAP INT64_C(0x0002000000000000)	/* system request parity err */
#define	C_AFSR_EMC  INT64_C(0x0001000000000000)	/* mtag   with   CE   error  */
#define	C_AFSR_EMU  INT64_C(0x0000800000000000)	/* mtag   with   UE   error  */
#define	C_AFSR_IVC  INT64_C(0x0000400000000000)	/* intr vector with CE error */
#define	C_AFSR_IVU  INT64_C(0x0000200000000000)	/* intr vector with UE error */
#define	C_AFSR_TO   INT64_C(0x0000100000000000)	/* bus timeout from sys bus  */
#define	C_AFSR_BERR INT64_C(0x0000080000000000)	/* bus error from system bus */
#define	C_AFSR_UCC  INT64_C(0x0000040000000000)	/* E$ with software CE error */
#define	C_AFSR_UCU  INT64_C(0x0000020000000000)	/* E$ with software UE error */
#define	C_AFSR_CPC  INT64_C(0x0000010000000000) /* copyout  with  CE  error  */
#define	C_AFSR_CPU  INT64_C(0x0000008000000000) /* copyout  with  UE  error  */
#define	C_AFSR_WDC  INT64_C(0x0000004000000000) /* writeback ecache CE error */
#define	C_AFSR_WDU  INT64_C(0x0000002000000000) /* writeback ecache UE error */
#define	C_AFSR_EDC  INT64_C(0x0000001000000000) /* ecache  CE  ECC  error    */
#define	C_AFSR_EDU  INT64_C(0x0000000800000000) /* ecache  UE  ECC  error    */
#define	C_AFSR_UE   INT64_C(0x0000000400000000) /* uncorrectable ECC error   */
#define	C_AFSR_CE   INT64_C(0x0000000200000000) /* correctable   ECC error   */
#define	C_AFSR_M_SYND	INT64_C(0x00000000000f0000) /* mtag  ECC  syndrome   */
#define	C_AFSR_E_SYND	INT64_C(0x00000000000001ff) /* data  ECC  syndrome   */

/* AFSR bits that could result in CPU removal due to E$ error */
#define	C_AFSR_L2_SERD_FAIL_UE	(C_AFSR_UCU | C_AFSR_CPU | C_AFSR_WDU | \
				C_AFSR_EDU)
#define	C_AFSR_L2_SERD_FAIL_CE	(C_AFSR_UCC | C_AFSR_CPC | C_AFSR_WDC | \
				C_AFSR_EDC)
/*
 * Bits of the Panther Extended Asynchronous Fault Status Register (AFSR_EXT)
 *
 * +-----+-------+-----------+-------+-------+---------+------+------+------+
 * | rsv |RED_ERR|EFA_PAR_ERR|L3_MECC|L3_THCE|L3_TUE_SH|L3_TUE|L3_EDC|L3_EDU|
 * +-----+-------+-----------+-------+-------+---------+------+------+------+
 *  63:14   13        12        11       10       9        8      7      6
 *
 * +------+------+------+------+------+------+
 * |L3_UCC|L3_UCU|L3_CPC|L3_CPU|L3_WDC|L3_WDU|
 * +------+------+------+------+------+------+
 *     5      4      3      2      1      0
 *
 * If the L3_MECC bit is set along with any of the L3 cache errors (bits 0-7)
 * above, it indicates that an address parity error has occured.
 */
#define	C_AFSR_RED_ERR   INT64_C(0x0000000000002000) /* redunancy Efuse error */
#define	C_AFSR_EFA_PAR_ERR INT64_C(0x0000000000001000) /* Efuse parity error */
#define	C_AFSR_L3_MECC   INT64_C(0x0000000000000800) /* L3 address parity */
#define	C_AFSR_L3_THCE   INT64_C(0x0000000000000400) /* tag CE */
#define	C_AFSR_L3_TUE_SH INT64_C(0x0000000000000200) /* tag UE from snp/cpy */
#define	C_AFSR_L3_TUE    INT64_C(0x0000000000000100) /* tag UE */
#define	C_AFSR_L3_EDC    INT64_C(0x0000000000000080) /* L3 cache CE */
#define	C_AFSR_L3_EDU    INT64_C(0x0000000000000040) /* L3 cache UE */
#define	C_AFSR_L3_UCC    INT64_C(0x0000000000000020) /* software recover CE */
#define	C_AFSR_L3_UCU    INT64_C(0x0000000000000010) /* software recover UE */
#define	C_AFSR_L3_CPC    INT64_C(0x0000000000000008) /* copyout with CE */
#define	C_AFSR_L3_CPU    INT64_C(0x0000000000000004) /* copyout with UE */
#define	C_AFSR_L3_WDC    INT64_C(0x0000000000000002) /* writeback CE */
#define	C_AFSR_L3_WDU    INT64_C(0x0000000000000001) /* writeback UE */

#if defined(JALAPENO) || defined(SERRANO)
/*
 * Bits of Jalapeno Asynchronous Fault Status Register
 *
 * +-----+------------------------------------------------------------------
 * | rsv |JETO|SCE|JEIC|JEIT|ME|PRIV|JEIS|IERR|ISAP|ETP|OM|UMS|IVPE|TO|BERR|
 * +-----+------------------------------------------------------------------
 * 63:58   57   56   55  54  53  52   51   50   49  48  47  46  45  44  43
 *
 * +---+---+---+---+---+---+---+---+--+--+---+---+--+---+-------+
 * |UCC|UCU|CPC|CPU|WDC|WDU|EDC|EDU|UE|CE|RUE|RCE|BP|WBP|FRC|FRU|
 * +---+---+---+---+---+---+---+---+--+--+---+---+--+---+-------+
 *   42  41  40  39  38  37  36  35 34 33 32  31  30 29  28  27
 *
 * +-----+-----+-----+------+-----------+-------+
 * | JREQ| ETW | rsv |B_SYND| rsv | AID | E_SYND|
 * +-----+-----+-----+------+-----+-----+-------+
 *  26:24 23:22 21:20  19:16 15:14 13:9   8:0
 *
 */

/*
 * Bits of Serrano Asynchronous Fault Status Register
 *
 * +-----+------------------------------------------------------------------
 * | rsv |JETO|SCE|JEIC|JEIT|ME|PRIV|JEIS|IERR|ISAP|ETU|OM|UMS|IVPE|TO|BERR|
 * +-----+------------------------------------------------------------------
 * 63:58   57   56   55  54  53  52   51   50   49  48  47  46  45  44  43
 *
 * +---+---+---+---+---+---+---+---+--+--+---+---+--+---+-------+
 * |UCC|UCU|CPC|CPU|WDC|WDU|EDC|EDU|UE|CE|RUE|RCE|BP|WBP|FRC|FRU|
 * +---+---+---+---+---+---+---+---+--+--+---+---+--+---+-------+
 *   42  41  40  39  38  37  36  35 34 33 32  31  30 29  28  27
 *
 * +-----+-----+------+---+------+---+---+-----+-------+
 * | JREQ| ETW | EFES |ETS|B_SYND|ETI|ETC| AID | E_SYND|
 * +-----+-----+------+---+------+---+---+-----+-------+
 *  26:24 23:22    21   20  19:16  15  14  13:9    8:0
 *
 */

#define	C_AFSR_JETO	INT64_C(0x0200000000000000) /* JBus Timeout */
#define	C_AFSR_SCE	INT64_C(0x0100000000000000) /* Snoop parity error */
#define	C_AFSR_JEIC	INT64_C(0x0080000000000000) /* JBus Illegal Cmd */
#define	C_AFSR_JEIT	INT64_C(0x0040000000000000) /* Illegal ADTYPE */
#define	C_AFSR_JEIS	INT64_C(0x0008000000000000) /* Illegal Install State */
#if defined(SERRANO)
#define	C_AFSR_ETU	INT64_C(0x0001000000000000) /* L2$ tag CE error */
#elif defined(JALAPENO)
#define	C_AFSR_ETP	INT64_C(0x0001000000000000) /* L2$ tag parity error */
#endif /* JALAPENO */
#define	C_AFSR_OM	INT64_C(0x0000800000000000) /* out of range mem error */
#define	C_AFSR_UMS	INT64_C(0x0000400000000000) /* Unsupported store */
#define	C_AFSR_IVPE	INT64_C(0x0000200000000000) /* intr vector parity err */
#define	C_AFSR_RUE	INT64_C(0x0000000100000000) /* remote mem UE error */
#define	C_AFSR_RCE	INT64_C(0x0000000080000000) /* remote mem CE error */
#define	C_AFSR_BP	INT64_C(0x0000000040000000) /* read data parity err */
#define	C_AFSR_WBP	INT64_C(0x0000000020000000) /* wb/bs data parity err */
#define	C_AFSR_FRC	INT64_C(0x0000000010000000) /* foregin mem CE error */
#define	C_AFSR_FRU	INT64_C(0x0000000008000000) /* foregin mem UE error */
#define	C_AFSR_JREQ	INT64_C(0x0000000007000000) /* Active JBus req at err */
#define	C_AFSR_ETW	INT64_C(0x0000000000c00000) /* AID causing UE/CE */

#if defined(SERRANO)
#define	C_AFSR_EFES	INT64_C(0x0000000000200000) /* E-fuse error summary */
#define	C_AFSR_ETS	INT64_C(0x0000000000100000) /* L2$ tag SRAM stuck-at */
#endif /* SERRANO */

#define	C_AFSR_B_SYND	INT64_C(0x00000000000f0000) /* jbus parity syndrome */

#if defined(SERRANO)
#define	C_AFSR_ETI	INT64_C(0x0000000000008000) /* L2$ tag intermittent */
#define	C_AFSR_ETC	INT64_C(0x0000000000004000) /* L2$ tag CE */
#endif /* SERRANO */

#define	C_AFSR_AID	INT64_C(0x0000000000003e00) /* AID causing UE/CE */

/* bit shifts for selected errors */
#define	C_AFSR_WDU_SHIFT	37
#define	C_AFSR_UCU_SHIFT	41
#define	C_AFSR_UCC_SHIFT	42
#define	C_AFSR_JREQ_SHIFT	24
#define	C_AFSR_AID_SHIFT	9

/*
 * Overloaded AFSR fields. During error processing, some of the reserved
 * fields within the saved AFSR are overwritten with extra information.
 */
#define	C_AFSR_PANIC_SHIFT		62
#define	C_AFSR_IPE_SHIFT		59
#define	C_AFSR_DPE_SHIFT		58

#else /* JALAPENO || SERRANO */

/* bit shifts for selected errors */
#define	C_AFSR_WDU_SHIFT	37
#define	C_AFSR_UCU_SHIFT	41
#define	C_AFSR_UCC_SHIFT	42
#define	C_AFSR_L3_UCU_SHIFT	4

/*
 * Overloaded AFSR fields. During error processing, some of the reserved fields
 * within the saved AFSR are overwritten with extra information.
 */
#define	C_AFSR_FIRSTFLT_SHIFT	63
#define	C_AFSR_PANIC_SHIFT	30
#define	C_AFSR_DPE_SHIFT	20
#define	C_AFSR_IPE_SHIFT	21

#endif /* JALAPENO || SERRANO */

#if defined(JALAPENO) || defined(SERRANO)
/*
 * Jalapeno L2 Cache Control Register Bits.
 *
 *	Bit#	Name		Description
 *	63-24	-		reserved
 *	23:20	EC_ACT_WAY	(read only) indicates which sets are present
 *	19:16	EC_BLK_WAY	Bit mask indicating which sets are blocked
 *				from replacement
 *	15:14	EC_SIZE		L2 cache size
 *	13:12	-		reserved
 *	11	EC_PAR_EN	Enables parity checking on L2 cache tags
 *	10	EC_ECC_EN	Enables ECC checking on L2 cache data
 *	9	EC_ECC_FORCE	Enables EC_CHECK[8:0] onto L2 cache ECC bits
 *	8:0	EC_CHECK	ECC check vector to force onto ECC bits
 */

#define	JP_ECCTRL_ECSIZE_MASK		0xc000
#define	JP_ECCTRL_ECSIZE_SHIFT		14
#define	JP_ECCTRL_ECSIZE_MIN		0x80000

/*
 * Jalapeno L2 Cache Error Enable Register Bits
 *
 *	Bit#	Name	Description
 *	63-33	-	reserved
 *	32	SCDE	Enable detection of JBUS control parity error
 *	31:24	-	reserved
 *	23	IAEN	Enable trap on illegal physical address
 *	22	IERREN	Enable FERR system reset on CPU internal errors
 *	21	PERREN	Enable FERR system reset on JBUS protocol errors
 *	20	SCEN	Enable FERR system reset on JBUS control parity error
 *	19:11	FMED	Forced error on the memory ECC
 *	10	FME	Force error on memory ECC
 *	9:6	FPD	Bits to use when FSP forces JBUS addr/data parity error
 *	5	FSP	Force error on outgoing JBUS addr/data parity
 *	4	ETPEN	Enable FERR system reset on L2 tags parity error
 *	3	UCEEN	Enable trap on SW handled external cache error
 *	2	ISAPEN	Enable FERR system reset on request parity error
 *	1	NCEEN	Enable trap on uncorrectable ECC error and system err
 *	0	CEEN	Enable trap on correctable ECC errors
 */

#define	EN_REG_UCEEN	INT64_C(0x0000000000000008) /* enable UCC,UCU */
#define	EN_REG_ISAPEN	INT64_C(0x0000000000000004) /* enable ISAP */
#define	EN_REG_NCEEN INT64_C(0x0000000000000002) /* UE,EDU,WDU,BERR,IVU,EMU */
#define	EN_REG_CEEN INT64_C(0x0000000000000001) /* enable CE,EDC,WDC,IVC,EMC */

#define	EN_REG_DISABLE	INT64_C(0x0000000000000000) /* no errors enabled */
#define	EN_REG_ECC_DISABLE (EN_REG_UCEEN | EN_REG_ISAPEN)
#define	EN_REG_CE_DISABLE (EN_REG_UCEEN | EN_REG_ISAPEN | EN_REG_NCEEN)
#define	EN_REG_ENABLE \
	(EN_REG_UCEEN | EN_REG_ISAPEN | EN_REG_NCEEN | EN_REG_CEEN)

#else /* JALAPENO || SERRANO */
#if defined(CHEETAH_PLUS)
/*
 * Cheetah+ External Cache Control Register Bits.
 */
#define	ECCR_ASSOC	INT64_C(0x0000000001000000) /* Ecache Assoc. */
#define	ECCR_ASSOC_SHIFT	24
#endif	/* CHEETAH_PLUS */

/*
 * Bits of Cheetah External Cache Error Enable Register
 *
 * +-----+-----+-------+-----+-------+-------+--------+-------+------+
 * | rsv | FMT | FMECC | FMD | FDECC | UCEEN | ISAPEN | NCEEN | CEEN |
 * +-----+-----+-------+-----+-------+-------+--------+-------+------+
 *  63:19   18  17  14    13    12:4     3        2       1       0
 *
 */
#define	EN_REG_FMT	INT64_C(0x0000000000040000) /* force system mtag ECC */
#define	EN_REG_FMECC	INT64_C(0x000000000003C000) /* forced mtag ECC vector */
#define	EN_REG_FMD	INT64_C(0x0000000000002000) /* force system data ECC */
#define	EN_REG_FDECC	INT64_C(0x0000000000001ff0) /* forced data ECC vector */
#define	EN_REG_UCEEN	INT64_C(0x0000000000000008) /* enable UCC,UCU */
#define	EN_REG_ISAPEN	INT64_C(0x0000000000000004) /* enable ISAP */
#define	EN_REG_NCEEN INT64_C(0x0000000000000002) /* UE,EDU,WDU,BERR,IVU,EMU */
#define	EN_REG_CEEN INT64_C(0x0000000000000001) /* enable CE,EDC,WDC,IVC,EMC */
#define	EN_REG_DISABLE	INT64_C(0x0000000000000000) /* no errors enabled */
#define	EN_REG_ECC_DISABLE (EN_REG_UCEEN | EN_REG_ISAPEN)
#define	EN_REG_CE_DISABLE (EN_REG_UCEEN | EN_REG_ISAPEN | EN_REG_NCEEN)
#define	EN_REG_ENABLE \
	(EN_REG_UCEEN | EN_REG_ISAPEN | EN_REG_NCEEN | EN_REG_CEEN)
#endif	/* JALAPENO || SERRANO */

/*
 * bit shifts for selected bits
 */
#define	EN_REG_CEEN_SHIFT	0

/* Cheetah/Cheetah+ Dcache size */
#define	CH_DCACHE_SIZE		0x10000

/* Cheetah/Cheetah+ Dcache linesize */
#define	CH_DCACHE_LSIZE		0x20

/* Cheetah/Cheetah+/Jaguar Icache size */
#define	CH_ICACHE_SIZE		0x8000

/* Cheetah/Cheetah+/Jaguar Icache linesize */
#define	CH_ICACHE_LSIZE		0x20

/* Panther Icache size */
#define	PN_ICACHE_SIZE		0x10000

/* Panther Icache linesize */
#define	PN_ICACHE_LSIZE		0x40

/* Pcache size for the cheetah family of CPUs */
#define	CH_PCACHE_SIZE		0x800

/* Pcache linesize  for the cheetah family of CPUs */
#define	CH_PCACHE_LSIZE		0x40

/*
 * The cheetah+ CPU module handles Cheetah+, Jaguar, and Panther so
 * we have to pick max size and min linesize values for the Icache
 * accordingly.
 */
#define	CHP_ICACHE_MAX_SIZE	PN_ICACHE_SIZE
#define	CHP_ICACHE_MIN_LSIZE	CH_ICACHE_LSIZE

/*
 * The minimum size needed to ensure consistency on a virtually address
 * cache.  Computed by taking the largest virtually indexed cache and dividing
 * by its associativity.
 */
#define	CH_VAC_SIZE		0x4000

/*
 * The following definitions give the syndromes that will be seen when attempts
 * are made to read data that has been intentionally poisoned.  Intentional
 * poisoning is performed when an error has been detected, and is designed to
 * allow software to effectively distinguish between root problems and secondary
 * effects.  The following syndromes and their descriptions are taken from the
 * UltraSPARC-III Cu Error Manual, Section 5.4.3.1.
 */

/*
 * For a DSTAT = 2 or 3 event (see Sec 5.3.4.4) from the system bus for a
 * cacheable load, data bits [1:0] are inverted in the data stored in the
 * L2-cache.  The syndrome seen when one of these signalling words is read will
 * be 0x11c.
 */
#define	CH_POISON_SYND_FROM_DSTAT23	0x11c

/*
 * For an uncorrectable data ECC error from the L2-cache, data bits [127:126]
 * are inverted in data sent to the system bus as part of a writeback or
 * copyout.  The syndrome seen when one of these signalling words is read will
 * be 0x071.
 */
#define	CH_POISON_SYND_FROM_XXU_WRITE	0x71

/*
 * For uncorrectable data ECC error on the L2-cache read done to complete a
 * store merge event, where bytes written by the processor are merged with
 * bytes from an L2-cache line, ECC check bits [1:0] are inverted in the data
 * scrubbed back to the L2-cache.  The syndrome seen when one of these
 * signalling words is read will be 0x003.
 */
#define	CH_POISON_SYND_FROM_XXU_WRMERGE	0x3

/*
 * To help understand the following definitions, this block of comments
 * provides information on Cheetah's E$.
 *
 * Cheetah supports three different E$ sizes (1MB, 4MB, and 8MB). The
 * number of E$ lines remains constant regardless of the size of the E$
 * as does the subblock size, however the number of 64-byte subblocks per
 * line varies depending on the E$ size.
 *
 * An E$ tag (for an E$ line) contains an EC_tag field, corresponding to the
 * high order physical address bits of that E$ line's contents, and 1 to 8
 * EC_state fields, indicating the state of each subblock. Due to the E$ line
 * size variance depending on the total size of the E$, the number of bits in
 * the EC_tag field varies as does the number of subblocks (and EC_state
 * fields) per E$ line.
 *
 * A 1MB E$ has a line size of 64 bytes, containing 1 subblock per line.
 * A 4MB E$ has a line size of 256 bytes, containing 4 subblocks per line.
 * An 8MB E$ has a line size of 512 bytes, containing 8 subblocks per line.
 *
 * An E$ tag for a particular E$ line can be read via a diagnostic ASI
 * as a 64-bit value.
 * Within the E$ tag 64-bit value, the EC_tag field is interpreted as follows:
 *	- for a 1MB E$, the EC_tag is in bits <43:21> and corresponds
 *		to physical address bits <42:20> (bits <41:19> for Cheetah+)
 *	- for a 4MB E$, the EC_tag is in bits <43:23> and corresponds
 *		to physical address bits <42:22> (bits <41:21> for Cheetah+)
 *	- for an 8MB E$, the EC_tag is in bits <43:24> and corresponds
 *		to physical address bits <42:23> (bits <41:22> for Cheetah+)
 * Within the E$ tag 64-bit value, the EC_state field(s) is(are) interpreted
 * as follows:
 *	- for a 1MB E$, EC_state0 is in bits <2:0>
 *	- for a 4MB E$, EC_state0 is in bits <2:0>, EC_state1 is in
 *		bits <5:3>, EC_state2 is in bits <8:6>, EC_state3 is
 *		in bits <11:9>
 *	- for an 8MB E$, EC_state0 is in bits <2:0>, EC_state1 is in
 *		bits <5:3>, EC_state2 is in bits <8:6>, EC_state3 is
 *		in bits <11:9>, EC_state4 is in bits <14:12>, EC_state5
 *		is in bits <17:15>, EC_state6 is in bits <20:18>,
 *		EC_state7 is in bits <23:21>
 * Note that each EC_state field contains a value representing the state
 * of its corresponding subblock.
 *
 */
/*
 * Jaguar changes from Cheetah/Cheetah+ Ecache:
 *
 * The Jaguar Ecache is similiar to that used for Cheetah/Cheetah+ with a
 * couple of differences :
 *	- Jaguar Ecache only comes in 4MB and 8MB versions.
 *		- 8MB E$ has 2 64 byte subblocks per line.
 *		- 4MB E$ has 1 64 byte subblock per line.
 *
 * An E$ tag for a particular E$ line can be read via a diagnostic ASI
 * as a 64-bit value.
 * Within the E$ tag 64-bit value, the EC_tag field is interpreted as follows:
 *	- for a 4MB E$, the EC_tag is in bits <41:21> and corresponds
 *		to physical address bits <41:21>
 *	- for a 8MB E$, the EC_tag is in bits <41:22> and corresponds
 *		to physical address bits <41:22>
 *
 * The Jaguar E$ tag also contains LRU field in bit <42> which must be
 * masked off when the tag value is being compared to a PA.
 *
 * Within the E$ tag 64-bit value, the EC_state field(s) is(are) interpreted
 * as follows:
 *	- for 4MB E$, EC_state0 is in bits <2:0>
 *	- for 8MB E$, EC_state0 is in bits <2:0>, EC_state1 is in bits <5:3>.
 * Each EC_state field contains a value representing the state of its
 * corresponding subblock.
 *
 * Note that the subblock size and state values are the same for both
 * Cheetah/Cheetah+ and Jaguar.
 */

/* Ecache sizes */
#define	CH_ECACHE_8M_SIZE	0x800000
#define	CH_ECACHE_4M_SIZE	0x400000
#define	CH_ECACHE_1M_SIZE	0x100000

#define	PN_L2_SIZE		0x200000
#define	PN_L2_LINESIZE		64
#define	PN_L2_ECC_WORDS		2
#define	PN_L2_NWAYS		4
#define	PN_L2_SET_SIZE		(PN_L2_SIZE / PN_L2_NWAYS)
#define	PN_L2_MAX_SET		(PN_L2_SIZE - PN_L2_SET_SIZE)
#define	PN_L2_DATA_ECC_SEL	0x200000 /* bit 21 selects ECC */
#define	PN_L2_ECC_LO_REG	0x20 /* bit 5 set for L2 tag access */
#define	PN_L2_INDEX_MASK	0x7ffc0 /* bits 18:6 */
#define	PN_L2_WAY_INCR		0x80000	/* l2-ec-way = <20:19> */
#define	PN_L2_WAY_LIM		INT64_C(0x200000)
#define	PN_L2_WAY_SHIFT		19

#define	PN_L3_SIZE		0x2000000
#define	PN_L3_LINESIZE		64
#define	PN_L3_NWAYS		4
#define	PN_L3_SET_SIZE		(PN_L3_SIZE / PN_L3_NWAYS)
#define	PN_L3_MAX_SET		(PN_L3_SIZE - PN_L3_SET_SIZE)
#define	PN_L3_WAY_SHIFT		23
#define	PN_L3_TAG_RD_MASK	0x7fffc0	/* ec_tag = PA<22:6>  */
#define	PN_L3_WAY_INCR		0x800000	/* ec_way = <24:23> */
#define	PN_L3_WAY_LIM		INT64_C(0x2000000)

/* Pcache Defines */
#define	PN_PCACHE_ADDR_MASK	0x1c0		/* PC_addr = <8:6> */
#define	PN_PCACHE_WAY_INCR	0x200		/* PC_way = <10:9> */
#define	PN_PCACHE_WORD_SHIFT	3		/* PC_dbl_word = <5:3> */
#define	PN_PCACHE_NWAYS		4

/* Cheetah Ecache is direct-mapped, Cheetah+ can be 2-way or direct-mapped */
#define	CH_ECACHE_NWAY		1
#if defined(CHEETAH_PLUS)
#define	CHP_ECACHE_NWAY		2
#define	PN_ECACHE_NWAY		4
#endif	/* CHEETAH_PLUS */
#if defined(JALAPENO) || defined(SERRANO)
#define	JP_ECACHE_NWAY		4
#define	JP_ECACHE_NWAY_SHIFT	2
#endif /* JALAPENO || SERRANO */

/* Maximum Ecache size */
#define	CH_ECACHE_MAX_SIZE	CH_ECACHE_8M_SIZE

/* Minimum Ecache line size */
#define	CH_ECACHE_MIN_LSIZE	64

/* Maximum Ecache line size - 8Mb Ecache has 512 byte linesize */
#define	CH_ECACHE_MAX_LSIZE	512

/* Size of Ecache data staging register size (see Cheetah PRM 10.7.2) */
#define	CH_ECACHE_STGREG_SIZE	32
#define	CH_ECACHE_STGREG_TOTALSIZE	40	/* data regs + ecc */

/* The number of staging registers containing data, for ASI_EC_DATA */
#define	CH_ECACHE_STGREG_NUM	(CH_ECACHE_STGREG_SIZE / sizeof (uint64_t))

/* Size of Ecache data subblock which has state field in Ecache tag */
#define	CH_ECACHE_SUBBLK_SIZE	64
#define	CH_ECACHE_SUBBLK_SHIFT	6

#if defined(JALAPENO) || defined(SERRANO)
#define	JP_ECACHE_MAX_LSIZE	CH_ECACHE_SUBBLK_SIZE
#define	JP_ECACHE_MAX_SIZE	0x400000
#endif /* JALAPENO || SERRANO */

/*
 * Maximum ecache setsize to support page coloring of heterogenous
 * cheetah+ cpus. Max ecache setsize is calculated to be the max ecache size
 * divided by the minimum associativity of the max ecache.
 *
 * NOTE: CHP_ECACHE_MAX_SIZE and CHP_ECACHE_MIN_NWAY need to be updated with
 * new cheetah+ cpus. The maximum setsize may not necessarily be associated with
 * the max ecache size if the cache associativity is large. If so, MAX_SETSIZE
 * needs to be updated accordingly.
 */
#if defined(CHEETAH_PLUS)
#define	CHP_ECACHE_MIN_NWAY	1	/* direct-mapped */
#define	CHP_ECACHE_MAX_SIZE	CH_ECACHE_MAX_SIZE
#define	CHP_ECACHE_MAX_SETSIZE	(CHP_ECACHE_MAX_SIZE / CHP_ECACHE_MIN_NWAY)
#endif	/* CHEETAH_PLUS */

/*
 * Bits to shift EC_tag field of E$ tag to form PA
 * (See Cheetah PRM 10.7.4, Cheetah+ Delta PRM 10.7)
 */
#if defined(JALAPENO) || defined(SERRANO)
#define	CH_ECTAG_PA_SHIFT	18
#elif defined(CHEETAH_PLUS)
#define	CH_ECTAG_PA_SHIFT	2
#else	/* CHEETAH_PLUS */
#define	CH_ECTAG_PA_SHIFT	1
#endif	/* CHEETAH_PLUS */
#define	PN_L3TAG_PA_SHIFT	1
#define	PN_L3TAG_PA_MASK	0xfffff000000	/* tag bits[43:24] */
#define	PN_L2TAG_PA_MASK	0x7fffff80000	/* tag bits[42:19] */

#if defined(JALAPENO) || defined(SERRANO)
/*
 * Macros for Jalapeno L2 Cache Tag/State/Parity
 *
 * +-----------+--------+--------+----------------------+
 * |   -       | EC_par |EC_state|  EC_tag = PA[42:18]  |
 * +-----------+--------+--------+----------------------+
 *    63:29        28      27:25         24:0
 */
/*
 * Constants representing the complete Jalapeno Ecache tag state:
 */
#define	JP_ECSTATE_SIZE		3		/* three bits */
#define	JP_ECSTATE_MASK		0x7		/* three bit field */
#define	JP_ECSTATE_INV		0x0		/* invalid */
#define	JP_ECSTATE_SHR		0x1		/* shared */
#define	JP_ECSTATE_RES1		0x2		/* reserved */
#define	JP_ECSTATE_EXL		0x3		/* exclusive */
#define	JP_ECSTATE_RES2		0x4		/* reserved */
#define	JP_ECSTATE_OWN		0x5		/* owner */
#define	JP_ECSTATE_MOD		0x7		/* modified */
#define	JP_ECSTATE_RES3		0x6		/* reserved */
#define	JP_ECTAG_STATE_SHIFT	25

#define	CH_ECSTATE_SIZE		JP_ECSTATE_SIZE
#define	CH_ECSTATE_MASK		JP_ECSTATE_MASK
#define	CH_ECSTATE_INV		JP_ECSTATE_INV
#define	CH_ECSTATE_SHR		JP_ECSTATE_SHR
#define	CH_ECSTATE_EXL		JP_ECSTATE_EXL
#define	CH_ECSTATE_OWN		JP_ECSTATE_OWN
#define	CH_ECSTATE_MOD		JP_ECSTATE_MOD
#define	CH_ECSTATE_RES1		JP_ECSTATE_RES1
#define	CH_ECSTATE_OWS		JP_ECSTATE_RES3
#define	CH_ECSTATE_RES2		JP_ECSTATE_RES2

/* Number of subblock states per Ecache line. */
#define	CH_ECTAG_NSUBBLKS(totalsize)	1

/* Mask for Tag state(s) field, 3 bits per subblock state. */
#define	CH_ECTAG_STATE_SHIFT(subblk)	JP_ECTAG_STATE_SHIFT
#define	CH_ECTAG_STATE_MASK(totalsize)			\
	((uint64_t)(JP_ECSTATE_MASK<<JP_ECTAG_STATE_SHIFT))

/* For a line to be invalid, all of its subblock states must be invalid. */
#define	CH_ECTAG_LINE_INVALID(totalsize, tag)		\
	(((tag) & CH_ECTAG_STATE_MASK(totalsize)) == 0)

/* Build address mask for tag physical address bits. */
#define	CH_ECTAG_PA_MASK(setsize)	P2ALIGN(C_AFAR_PA, (int)(setsize))

/* Get physical address bits from the EC_tag field of an E$ tag */
#define	CH_ECTAG_TO_PA(setsize, tag)	(((tag) << CH_ECTAG_PA_SHIFT) &	\
	CH_ECTAG_PA_MASK(setsize))

/* Given a physical address, compute index for subblock tag state. */
#define	CH_ECTAG_PA_TO_SUBBLK(totalsize, pa)		1

/* Given a physical address and assoc. tag, get the subblock state. */
#define	CH_ECTAG_PA_TO_SUBBLK_STATE(totalsize, pa, tag)			\
	(((tag) >> JP_ECTAG_STATE_SHIFT) &	JP_ECSTATE_MASK)

#else /* JALAPENO || SERRANO */

/*
 * Constants representing the complete Cheetah Ecache tag state:
 */
#define	CH_ECSTATE_SIZE		3		/* three bits per subblock */
#define	CH_ECSTATE_MASK		0x7		/* three bit field */
#define	CH_ECSTATE_INV		0x0		/* invalid */
#define	CH_ECSTATE_SHR		0x1		/* shared */
#define	CH_ECSTATE_EXL		0x2		/* exclusive */
#define	CH_ECSTATE_OWN		0x3		/* owner */
#define	CH_ECSTATE_MOD		0x4		/* modified */
#define	CH_ECSTATE_RES1		0x5		/* reserved */
#define	CH_ECSTATE_OWS		0x6		/* owner/shared */
#define	CH_ECSTATE_RES2		0x7		/* reserved */

/*
 * Macros for Cheetah Ecache tags
 */

/* Number of subblock states per Ecache line. */
#define	CH_ECTAG_NSUBBLKS(totalsize)	((totalsize) / CH_ECACHE_1M_SIZE)

/* Mask for Tag state(s) field, 3 bits per subblock state. */
#define	CH_ECTAG_STATE_SHIFT(subblk)	(subblk * CH_ECSTATE_SIZE)
#define	CH_ECTAG_STATE_MASK(totalsize)			\
	((uint64_t)					\
	((1 << (CH_ECTAG_NSUBBLKS(totalsize) * CH_ECSTATE_SIZE)) - 1))

/* For a line to be invalid, all of its subblock states must be invalid. */
#define	CH_ECTAG_LINE_INVALID(totalsize, tag)		\
	(((tag) & CH_ECTAG_STATE_MASK(totalsize)) == 0)

/* Build address mask for tag physical address bits. */
#define	CH_ECTAG_PA_MASK(setsize)	P2ALIGN(C_AFAR_PA, (int)(setsize))

/* Get physical address bits from the EC_tag field of an E$ tag */
#define	CH_ECTAG_TO_PA(setsize, tag)	(((tag) >> CH_ECTAG_PA_SHIFT) &	\
	CH_ECTAG_PA_MASK(setsize))

/* Given a physical address, compute index for subblock tag state. */
#define	CH_ECTAG_PA_TO_SUBBLK(totalsize, pa)		\
	(((pa) >> CH_ECACHE_SUBBLK_SHIFT) & (CH_ECTAG_NSUBBLKS(totalsize) - 1))

/* Given a physical address and assoc. tag, get the subblock state. */
#define	CH_ECTAG_PA_TO_SUBBLK_STATE(totalsize, pa, tag)			\
	(((tag) >>							\
	(CH_ECTAG_PA_TO_SUBBLK(totalsize, pa) * CH_ECSTATE_SIZE)) &	\
	CH_ECSTATE_MASK)
#endif /* JALAPENO || SERRANO */

/* Panther only has one EC_State field in the L3 tag */
#define	PN_L3_LINE_INVALID(tag)		(((tag) & CH_ECSTATE_MASK) == 0)

/* Panther only has one State field in the L2 tag */
#define	PN_L2_LINE_INVALID(tag)		(((tag) & CH_ECSTATE_MASK) == 0)

/* Get physical address bits from the EC_tag field of an L3$ tag */
#define	PN_L3TAG_TO_PA(tag)		(((tag) & PN_L3TAG_PA_MASK) >> \
	PN_L3TAG_PA_SHIFT)

/* Get physical address bits from the tag field of an L2$ tag */
#define	PN_L2TAG_TO_PA(tag)		((tag) & PN_L2TAG_PA_MASK)

#if defined(JALAPENO) || defined(SERRANO)
/*
 * Jalapeno L2 Cache ASI_ECACHE_FLUSH:
 * +-------+-----------------+--------+---+-----+-------------+------+
 * |   -   | Port_ID |   -   | EC_Way | 1 |  -  | EC_Tag_Addr |   -  |
 * +-------+-----------------+--------+---+-----+-------------+------+
 *  63:41     40:36    35:34    33:32  31  30:18      17:6       5:0
 */

#define	JP_EC_TO_SET_SIZE_SHIFT		2
#define	JP_ECACHE_IDX_DISP_FLUSH	INT64_C(0x0000000080000000)
#define	JP_ECFLUSH_PORTID_SHIFT		36
#define	JP_ECFLUSH_EC_WAY_SHIFT		32
#define	JP_EC_TAG_DATA_WAY_SHIFT	JP_ECFLUSH_EC_WAY_SHIFT
#endif	/* JALAPENO || SERRANO */

/*
 * Macros for Jaguar Ecache tags
 */

/* Ecache sizes */
#define	JG_ECACHE_8M_SIZE	0x800000
#define	JG_ECACHE_4M_SIZE	0x400000

/* Jaguar E$ tag LRU mask */
#define	JG_LRU_MASK UINT64_C(0x0000040000000000) /* PA<42> LRU bit */

/*
 * Note that Jaguar and Cheetah/Cheetah+ have the same subblock state size
 * so rather than duplicating existing defn's we can use the Cheetah+ versions
 * in the Jaguar defn's below.
 */
/* Number of subblock states per Ecache line. */
#define	JG_ECTAG_NSUBBLKS(cachesize)	((cachesize) / JG_ECACHE_4M_SIZE)

/* Mask for Tag state(s) field, 3 bits per subblock state. */
#define	JG_ECTAG_STATE_MASK(totalsize)			\
	((uint64_t)					\
	((1 << (JG_ECTAG_NSUBBLKS(totalsize) * CH_ECSTATE_SIZE)) - 1))

/* For a line to be invalid, all of its subblock states must be invalid. */
#define	JG_ECTAG_LINE_INVALID(totalsize, tag)		\
	(((tag) & JG_ECTAG_STATE_MASK(totalsize)) == 0)

/* Build address mask for tag physical address bits. */
#define	JG_ECTAG_PA_MASK(setsize)	P2ALIGN(((~JG_LRU_MASK) & C_AFAR_PA), \
							(int)(setsize))

/* Get physical address bits from the EC_tag field of an E$ tag */
#define	JG_ECTAG_TO_PA(setsize, tag)	((tag & JG_ECTAG_PA_MASK(setsize)))

/* Given a physical address, compute index for subblock tag state. */
#define	JG_ECTAG_PA_TO_SUBBLK(totalsize, pa)		\
	(((pa) >> CH_ECACHE_SUBBLK_SHIFT) & (JG_ECTAG_NSUBBLKS(totalsize) - 1))

/* Given a physical address and assoc. tag, get the subblock state. */
#define	JG_ECTAG_PA_TO_SUBBLK_STATE(totalsize, pa, tag)			\
	(((tag) >>							\
	(JG_ECTAG_PA_TO_SUBBLK(totalsize, pa) * CH_ECSTATE_SIZE)) &	\
	CH_ECSTATE_MASK)


#if defined(CHEETAH_PLUS)
/*
 * Cheetah+ Tag ECC Bit and Displacement Flush Bit in Ecache Tag Access.
 * See Cheetah+ Delta PRM 10.7
 */
#define	CHP_ECACHE_IDX_TAG_ECC		INT64_C(0x0000000000800000)
#define	CHP_ECACHE_IDX_DISP_FLUSH	INT64_C(0x0000000001000000)
#define	PN_L2_IDX_DISP_FLUSH		INT64_C(0x0000000000800000)
#define	PN_L3_IDX_DISP_FLUSH		INT64_C(0x0000000004000000)
#endif	/* CHEETAH_PLUS */

/*
 * Macros for Cheetah Dcache diagnostic accesses.
 */

/*
 * Dcache Index Mask for bits from *AFAR*.  Note that Dcache is virtually
 * indexed, so only bits [12:5] are valid from the AFAR.  This
 * means we have to search through the 4 ways + bit 13 (i.e. we have
 * to try 8 indexes).
 */
#define	CH_DCACHE_IDX_MASK		0x01fe0
#define	CH_DCACHE_IDX_INCR		0x02000
#define	CH_DCACHE_IDX_LIMIT		0x10000
#define	CH_DCACHE_NWAY			4
#define	CH_DCACHE_WAY_MASK		0x0c000
#define	CH_DCACHE_WAY_SHIFT		14
#define	CH_DCIDX_TO_WAY(idx)		(((idx) & CH_DCACHE_WAY_MASK) >> \
						CH_DCACHE_WAY_SHIFT)
#define	CH_DCTAG_PA_MASK		INT64_C(0x000007ffffffe000)
#define	CH_DCTAG_PA_SHIFT		12
#define	CH_DCTAG_VALID_BIT		INT64_C(0x0000000000000001)
#define	CH_DCTAG_LINE_INVALID(tag)	(((tag) & CH_DCTAG_VALID_BIT) == 0)
#define	CH_DCIDX_TO_ADDR(idx)		((idx) & CH_DCACHE_IDX_MASK)
#define	CH_DCTAG_TO_PA(tag)		(((tag) << CH_DCTAG_PA_SHIFT) & \
					    CH_DCTAG_PA_MASK)
#define	CH_DCTAG_MATCH(tag, pa)		(!CH_DCTAG_LINE_INVALID(tag) && \
			    ((pa) & CH_DCTAG_PA_MASK) == CH_DCTAG_TO_PA(tag))
#define	CH_DCSNTAG_MASK			INT64_C(0x000007ffffffe000)
#define	CH_DCSNTAG_TO_PA(tag)		((tag << CH_DCTAG_PA_SHIFT) \
							& CH_DCSNTAG_MASK)
#define	CH_DCUTAG_TO_UTAG(tag)		((tag) & 0xff)
#define	CH_DCUTAG_TO_VA(tag)		((tag & 0xff) << 14)
#define	CH_DCUTAG_IDX_MASK		0x03fe0
#define	CH_DC_DATA_REG_SIZE		32
#define	CH_DC_UTAG_MASK			0xff
#if defined(CHEETAH_PLUS) || defined(JALAPENO) || defined(SERRANO)
#define	CHP_DCTAG_PARMASK		INT64_C(0x000000007ffffffe)
#define	CHP_DCSNTAG_PARMASK		INT64_C(0x000000007ffffffe)
#define	CHP_DCTAG_MASK			INT64_C(0x000003ffffffe000)
#define	CHP_DCSNTAG_MASK		INT64_C(0x000003ffffffe000)
#define	CHP_DCWAY_MASK			INT64_C(0x0000000000003fe0)
#define	CHP_DCUTAG_TO_UTAG(tag)		((tag) & 0xffff)
#define	CHP_DCPATAG_TO_PA(tag)		((tag << CH_DCTAG_PA_SHIFT) \
							& CHP_DCTAG_MASK)
#define	CHP_DCSNTAG_TO_PA(tag)		((tag << CH_DCTAG_PA_SHIFT) \
							& CHP_DCSNTAG_MASK)
#define	CHP_DC_IDX(dcp)			((dcp->dc_idx & 0x1fc0) >> 5)
#define	CHP_DCTAG_PARITY(tag)		(tag & CHP_DC_TAG)
#define	CHP_DCSNTAG_PARITY(tag)		(tag & CHP_DC_SNTAG)
#define	CHP_DC_TAG			0x1
#define	CHP_DC_SNTAG			0x2
#define	PN_DC_DATA_PARITY_SHIFT    	8
#define	PN_DC_DATA_PARITY_MASK    	0xff
#define	PN_DC_DATA_ALL_PARITY_MASK    	0xffffffff
#endif	/* CHEETAH_PLUS || JALAPENO || SERRANO */
#define	PN_DC_DATA_PARITY_BIT_SHIFT    	16

/*
 * Macros for Cheetah Icache diagnostic accesses.
 */

/*
 * Icache Index Mask for bits from *AFAR*. Note that the Icache is virtually
 * indexed for Panther and physically indexed for other CPUs. For Panther,
 * we obtain an index by looking at bits[12:6] of the AFAR PA and we check
 * both lines associated with bit 13 = 0 or 1 (total of 8 entries to check).
 * For non-Panther CPUs we get our index by just looking at bits[12:5] of
 * the AFAR PA (total of 4 entries to check). The Icache index is also
 * confusing because we need to shift the virtual address bits left by one
 * for the index.
 */
#define	CH_ICACHE_IDX_MASK		0x01fe0
#define	PN_ICACHE_IDX_MASK		0x03fc0
#define	PN_ICACHE_VA_IDX_MASK		0x01fc0
#define	CH_ICACHE_IDX_SHIFT		1
#define	CH_ICACHE_IDX_INCR		0x04000
#define	PN_ICACHE_IDX_INCR		0x08000
#define	CH_ICACHE_IDX_LIMIT		0x10000
#define	PN_ICACHE_IDX_LIMIT		0x20000
#define	CH_ICACHE_NWAY			4
#define	CH_ICACHE_WAY_MASK		0x0c000
#define	CH_ICACHE_WAY_SHIFT		14
#define	PN_ICACHE_WAY_MASK		0x18000
#define	PN_ICACHE_WAY_SHIFT		15
#define	CH_ICTAG_PA			0x00
#define	CH_ICTAG_UTAG			0x08
#define	CH_ICTAG_UPPER			0x10
#define	CH_ICTAG_LOWER			0x30
#define	CH_ICTAG_TMASK			0x3f
#define	CH_ICPATAG_MASK			INT64_C(0x000007ffffffe000)
#define	CH_ICPATAG_LBITS		0xff	/* lower 8 bits undefined */
#define	CH_ICPATAG_SHIFT		5
#define	CH_ICIDX_TO_WAY(idx)		(((idx) & CH_ICACHE_WAY_MASK) >> \
						CH_ICACHE_WAY_SHIFT)
#define	PN_ICIDX_TO_WAY(idx)		(((idx) & PN_ICACHE_WAY_MASK) >> \
						PN_ICACHE_WAY_SHIFT)
#define	CH_ICIDX_TO_ADDR(idx)		(((idx) >> CH_ICACHE_IDX_SHIFT) & \
						CH_ICACHE_IDX_MASK)
#define	PN_ICIDX_TO_ADDR(idx)		(((idx) >> CH_ICACHE_IDX_SHIFT) & \
						PN_ICACHE_IDX_MASK)
#define	CH_ICPATAG_TO_PA(tag)		(((tag) << CH_ICPATAG_SHIFT) & \
						CH_ICPATAG_MASK)
#define	CH_ICPATAG_MATCH(tag, pa)	(CH_ICPATAG_TO_PA(tag) == \
						((pa) & CH_ICPATAG_MASK))
#define	CH_ICUTAG_MASK			INT64_C(0x00000000001fe000)
#define	CH_ICUTAG_TO_UTAG(tag)		(((tag) >> 38) & 0xff)
#define	CH_ICUTAG_TO_VA(tag)		(((tag) >> 25) & CH_ICUTAG_MASK)
#define	CH_ICSNTAG_MASK			INT64_C(0x000007ffffffe000)
#define	CH_ICSNTAG_TO_PA(tag)		(((tag) << 5) & CH_ICSNTAG_MASK)
#define	CH_ICLOWER_VALID		INT64_C(0x0004000000000000)
#define	CH_ICUPPER_VALID		INT64_C(0x0004000000000000)
#define	CH_ICLOWER_TO_VPRED(lower)	(((lower) >> 46) & 0xf)
#define	CH_ICUPPER_TO_VPRED(upper)	(((upper) >> 46) & 0xf)
#if defined(CHEETAH_PLUS)
#define	CH_ICTAG_MATCH(icp, pa)		(((icp->ic_lower | icp->ic_upper) & \
					    CH_ICLOWER_VALID) && \
					    CH_ICPATAG_MATCH(icp->ic_patag, pa))
#define	PN_ICUTAG_TO_VA(tag)		((tag >> 24) & PN_ICUTAG_MASK)
#else	/* CHEETAH_PLUS */
#define	CH_ICTAG_MATCH(icp, pa)		((icp->ic_lower & CH_ICLOWER_VALID) &&\
					    CH_ICPATAG_MATCH(icp->ic_patag, pa))
#define	PN_ICUTAG_TO_VA(tag)		0
#endif	/* CHEETAH_PLUS */

#define	CH_IC_DATA_REG_SIZE		64
#define	PN_IC_DATA_REG_SIZE		128
#if defined(CHEETAH_PLUS) || defined(JALAPENO) || defined(SERRANO)
#define	CHP_IC_IDX(icp)			((icp->ic_idx & 0x3fc0) >> 6)
#define	PN_IC_IDX(icp)			((icp->ic_idx & 0x7f80) >> 7)
#define	CHP_ICPATAG_MASK		INT64_C(0x000003ffffffe000)
#define	CHP_ICSNTAG_MASK		INT64_C(0x000003ffffffe000)
#define	CHP_ICUTAG_MASK			INT64_C(0x00000000001fe000)
#define	PN_ICUTAG_MASK			INT64_C(0x00000000003fc000)
#define	CHP_ICWAY_MASK			INT64_C(0x0000000000003fe0)
#define	CHP_ICPATAG_TO_PA(tag)		((tag << 5) & CHP_ICPATAG_MASK)
#define	CHP_ICSNTAG_TO_PA(tag)		((tag << 5) & CHP_ICSNTAG_MASK)
#define	CHP_ICUTAG_TO_VA(tag)		((tag >> 25) & CHP_ICUTAG_MASK)
#define	CHP_ICPATAG_PARMASK		INT64_C(0x0000003fffffff00)
#define	CHP_ICSNTAG_PARMASK		INT64_C(0x0000003fffffff00)

/*
 * Cheetah+ Icache data parity masks, see Cheetah+ Delta PRM 7.3
 * PC-relative instructions have different bits protected by parity.
 * Predecode bit 7 is not parity protected and indicates if the instruction
 * is PC-relative or not.
 */
#define	CH_ICDATA_PRED_ISPCREL		INT64_C(0x0000008000000000)
#define	CHP_ICDATA_PCREL_PARMASK	INT64_C(0x0000039ffffff800)
#define	CHP_ICDATA_NPCREL_PARMASK	INT64_C(0x000003bfffffffff)
#define	PN_ICDATA_PARITY_BIT_MASK	INT64_C(0x40000000000)
#define	CHP_ICTAG_PARITY(tag)		(tag & CHP_IC_TAG)
#define	CHP_ICSNTAG_PARITY(tag)		(tag & CHP_IC_SNTAG)
#define	CHP_IC_TAG			0x1
#define	CHP_IC_SNTAG			0x2
#endif	/* CHEETAH_PLUS || JALAPENO || SERRANO */
#if defined(CHEETAH_PLUS)
#define	PN_IPB_TAG_ADDR_LINESIZE	0x40
#define	PN_IPB_TAG_ADDR_MAX		0x3c0
#endif	/* CHEETAH_PLUS */

/*
 * Macros for Pcache diagnostic accesses.
 */
#define	CH_PC_WAY_MASK			0x600
#define	CH_PC_WAY_SHIFT			9
#define	CH_PCIDX_TO_WAY(idx)		(((idx) & CH_PC_WAY_MASK) >> \
						CH_PC_WAY_SHIFT)
#define	CH_PC_DATA_REG_SIZE		64
#define	CH_PCACHE_NWAY			4
#define	PN_PC_PARITY_SHIFT		50
#define	PN_PC_PARITY_MASK		0xff
#define	PN_PC_PARITY_BITS(status)	\
	(((status) >> PN_PC_PARITY_SHIFT) & PN_PC_PARITY_MASK)
#define	CH_PC_IDX_ADR(pcp)		((pcp->pc_idx & 0x1c0) >> 6)
#define	CH_PCTAG_ADDR_SHIFT		6
#define	CH_PC_PA_MASK			0x7ffffffffc0
#define	CH_PCTAG_TO_VA(tag)		((tag) << CH_PCTAG_ADDR_SHIFT)
#define	CH_PCSTAG_TO_PA(tag)		(((tag) << CH_PCTAG_ADDR_SHIFT) & \
					    CH_PC_PA_MASK)
#define	CH_PCTAG_BNK0_VALID_MASK	0x2000000000000000
#define	CH_PCTAG_BNK1_VALID_MASK	0x1000000000000000
#define	CH_PCTAG_BNK0_INVALID(tag)	(((tag) & CH_PCTAG_BNK0_VALID_MASK) == \
					    0)
#define	CH_PCTAG_BNK1_INVALID(tag)	(((tag) & CH_PCTAG_BNK1_VALID_MASK) == \
					    0)

/*
 * CPU Log Out Structure parameters.
 * This structure is filled in by the Error Trap handlers and captures the
 * Ecache/Dcache/Icache line(s) associated with the AFAR.
 * For Cheetah Phase II, this structure is filled in at the TL=0 code.  For
 * Cheetah Phase III, this will be filled in at the trap handlers.
 */

/*
 * We use this to mark the LOGOUT structure as invalid.  Note that
 * this cannot be a valid AFAR, as AFAR bits outside of [41:5] should always
 * be zero.
 */
#define	LOGOUT_INVALID_U32	0xecc1ecc1
#define	LOGOUT_INVALID_L32	0xecc1ecc1
#define	LOGOUT_INVALID		UINT64_C(0xecc1ecc1ecc1ecc1)

/*
 * Max number of TLs to support for Fast ECC or Cache Parity Errors
 * at TL>0.  Traps are OK from TL=1-2, at TL>=3, we will Red Mode.
 */
#define	CH_ERR_TL1_TLMAX	2

/*
 * Software traps used by TL>0 handlers.
 */
#define	SWTRAP_0		0	/* Used by Fast ECC */
#define	SWTRAP_1		1	/* Used by Dcache Parity */
#define	SWTRAP_2		2	/* Used by Icache Parity */

/*
 * Bit mask defines for various Cheetah Error conditions.
 */
#define	CH_ERR_FECC	0x01	/* Data/Event is Fast ECC */
#define	CH_ERR_IPE	0x02	/* Data/Event is Icache Parity Error */
#define	CH_ERR_DPE	0x04	/* Data/Event is Dcache Parity Error */
#define	CH_ERR_PANIC	0x08	/* Fatal error in TL>0 handler */
#define	CH_ERR_TL	0x10	/* Error occured at TL>0 */
#define	CH_ERR_ME_SHIFT	   8	/* If multiple errors, shift left newest */
#define	CH_ERR_ME_FLAGS(x)	((x) >> CH_ERR_ME_SHIFT)

/*
 * Defines for Bit8 (CH_ERR_TSTATE_IC_ON) and Bit9 (CH_ERR_TSTATE_DC_ON)
 * in %tstate, which is used to remember D$/I$ state on Fast ECC handler
 * at TL>0.  Note that DCU_IC=0x1, DCU_DC=0x2.
 */
#define	CH_ERR_G2_TO_TSTATE_SHFT	10
#define	CH_ERR_DCU_TO_TSTATE_SHFT	8
#define	CH_ERR_TSTATE_IC_ON	(DCU_IC << CH_ERR_DCU_TO_TSTATE_SHFT)
#define	CH_ERR_TSTATE_DC_ON	(DCU_DC << CH_ERR_DCU_TO_TSTATE_SHFT)

/*
 * Multiple offset TL>0 handler structure elements
 */
#define	CH_ERR_TL1_DATA		(CH_ERR_TL1_LOGOUT + CH_CLO_DATA)
#define	CH_ERR_TL1_SDW_DATA	(CH_ERR_TL1_LOGOUT + CH_CLO_SDW_DATA)
#define	CH_ERR_TL1_NEST_CNT	(CH_ERR_TL1_LOGOUT + CH_CLO_NEST_CNT)
#define	CH_ERR_TL1_AFAR		(CH_ERR_TL1_DATA + CH_CHD_AFAR)
#define	CH_ERR_TL1_AFSR		(CH_ERR_TL1_DATA + CH_CHD_AFSR)
#define	CH_ERR_TL1_SDW_AFAR	(CH_ERR_TL1_SDW_DATA + CH_CHD_AFAR)
#define	CH_ERR_TL1_SDW_AFSR	(CH_ERR_TL1_SDW_DATA + CH_CHD_AFSR)
#define	CH_ERR_TL1_SDW_AFSR_EXT	(CH_ERR_TL1_SDW_DATA + CH_CHD_AFSR_EXT)

/*
 * Interval for deferred CEEN reenable
 */
#define	CPU_CEEN_DELAY_SECS		6

/*
 * flags for flt_trapped_ce variable
 */
#define	CE_CEEN_DEFER		0x1	/* no CEEN reenable in trap handler */
#define	CE_CEEN_NODEFER		0x2	/* reenable CEEN in handler */
#define	CE_CEEN_TIMEOUT		0x4	/* CE caught by timeout */
#define	CE_CEEN_TRAPPED		0x8	/* CE caught by trap */

/*
 * default value for cpu_ce_not_deferred
 */
#if defined(JALAPENO) || defined(SERRANO)
#define	CPU_CE_NOT_DEFERRED	(C_AFSR_CECC_ERRS & \
		~(C_AFSR_CE | C_AFSR_FRC | C_AFSR_RCE | C_AFSR_EMC))
#else /* JALAPENO || SERRANO */
#if defined(CHEETAH_PLUS)
#define	CPU_CE_NOT_DEFERRED	(C_AFSR_CECC_ERRS & \
		~(C_AFSR_CE | C_AFSR_EMC | C_AFSR_THCE))
#else /* CHEETAH_PLUS */
#define	CPU_CE_NOT_DEFERRED	(C_AFSR_CECC_ERRS & \
		~(C_AFSR_CE | C_AFSR_EMC))
#endif /* CHEETAH_PLUS */
#endif /* JALAPENO || SERRANO */

#define	CPU_CE_NOT_DEFERRED_EXT	(C_AFSR_EXT_CECC_ERRS & \
		~(C_AFSR_L3_THCE))

#if defined(CHEETAH_PLUS)

/*
 * VA for primary and shadow AFSR/AFAR/AFSR_EXT registers
 */
#define	ASI_SHADOW_REG_VA	0x8
#define	ASI_AFSR_EXT_VA		0x10
#define	ASI_SHADOW_AFSR_EXT_VA	0x18

/*
 * Bitmask for keeping track of core parking in ECC error handlers.
 * We share a register that also saves the DCUCR value so we use
 * one of the reserved bit positions of the DCUCR register to keep
 * track of whether or not we have parked our sibling core.
 */
#define	PN_PARKED_OTHER_CORE	0x20
#define	PN_BOTH_CORES_RUNNING	0x3

/*
 * Panther EMU Activity Status Register Bits.
 */
#define	ASI_EMU_ACT_STATUS_VA	0x18
#define	MCU_ACT_STATUS		INT64_C(0x0000000000000001)
#define	SIU_ACT_STATUS		INT64_C(0x0000000000000002)
#endif	/* CHEETAH_PLUS */

#define	ASI_CESR_ID_VA		0x40    /* ASI_CESRD_ID per-core registers */

#define	ASR_DISPATCH_CONTROL		%asr18
#define	ASR_DISPATCH_CONTROL_BPE	0x20

/*
 * Max number of E$ sets logged in ch_diag_data structure
 */
#define	CHD_EC_DATA_SETS	4	/* max 4 sets of E$ data */

/*
 * Definitions for Panther TLB parity handling.
 */
#define	PN_ITLB_NWAYS		2
#define	PN_NUM_512_ITLBS	1
#define	PN_DTLB_NWAYS		2
#define	PN_NUM_512_DTLBS	2
#define	PN_SFSR_PARITY_SHIFT	12
#define	PN_ITLB_PGSZ_SHIFT	22
#define	PN_ITLB_PGSZ_MASK	(7 << PN_ITLB_PGSZ_SHIFT)
#define	PN_DTLB_PGSZ0_SHIFT	16
#define	PN_DTLB_PGSZ0_MASK	(7 << PN_DTLB_PGSZ0_SHIFT)
#define	PN_DTLB_PGSZ1_SHIFT	19
#define	PN_DTLB_PGSZ1_MASK	(7 << PN_DTLB_PGSZ1_SHIFT)
#define	PN_DTLB_PGSZ_MASK	(PN_DTLB_PGSZ1_MASK | PN_DTLB_PGSZ0_MASK)
#define	PN_DTLB_T512_0		(2 << 16)
#define	PN_DTLB_T512_1		(3 << 16)
#define	PN_TLO_INFO_IMMU_SHIFT	14
#define	PN_TLO_INFO_IMMU	(1 << PN_TLO_INFO_IMMU_SHIFT)
#define	PN_TLO_INFO_TL1_SHIFT	13
#define	PN_TLO_INFO_TL1		(1 << PN_TLO_INFO_TL1_SHIFT)
#define	PN_ITLB_T512		(2 << 16)
#define	PN_TLB_ACC_IDX_SHIFT	3
#define	PN_TLB_ACC_WAY_BIT	(1 << 11)
#define	PN_TLB_DIAGACC_OFFSET	0x40000	/* Diag Acc ASI VA offset */
/*
 * tag parity = XOR(Size[2:0],Global,VA[63:21],Context[12:0])
 * which requires looking at both the tag and the data.
 */
#define	PN_TLB_TAG_PARITY_TAG_MASK	0xffffffffffe01fff
#define	PN_TLB_TAG_PARITY_DATA_MASK	0x6001400000000001
/* data parity = XOR(NFO,IE,PA[42:13],CP,CV,E,P,W) */
#define	PN_TLB_DATA_PARITY_DATA_MASK	0x180087ffffffe03e

#ifdef _KERNEL

#ifndef	_ASM

#include <sys/kstat.h>

/*
 * One Ecache data element, 32 bytes of data, 8 bytes of ECC.
 * See Cheetah PRM 10.7.2.
 */
typedef struct ec_data_elm {
	uint64_t ec_d8[CH_ECACHE_STGREG_NUM];
	uint64_t ec_eccd;	/* EC_data_ECC field */
} ec_data_elm_t;

/*
 * L2 and L3 cache data captured by cpu log out code.
 * See Cheetah PRM 10.7.4.
 */
typedef struct ch_ec_data {
	uint64_t ec_logflag;	/* Flag indicates if data was logged */
	uint64_t ec_idx;	/* Ecache index */
	uint64_t ec_way;	/* Ecache way */
	uint64_t ec_tag;	/* Ecache Tag */
	uint64_t ec_tag_ecc;	/* Ecache Tag ECC (Cheetah+ only) */
	ec_data_elm_t ec_data[CH_ECACHE_SUBBLK_SIZE/CH_ECACHE_STGREG_SIZE];
} ch_ec_data_t;

/*
 * Dcache data captured by cpu log out code and get_dcache_dtag.
 * See Cheetah PRM 10.6.[1-4].
 */
typedef struct ch_dc_data {
	uint64_t dc_logflag;	/* Flag indicates if data was logged */
	uint64_t dc_idx;	/* Dcache index */
	uint64_t dc_way;	/* Dcache way */
	uint64_t dc_tag;	/* Tag/Valid Fields */
	uint64_t dc_utag;	/* Microtag */
	uint64_t dc_sntag;	/* Snoop Tag */
	uint64_t dc_data[CH_DC_DATA_REG_SIZE/sizeof (uint64_t)]; /* Data */
	uint64_t dc_pn_data_parity;	/* Data parity bits for Panther */
} ch_dc_data_t;

/*
 * Icache data captured by cpu log out code and get_icache_dtag.
 * See Cheetah PRM 10.4.[1-3].
 */
typedef struct ch_ic_data {
	uint64_t ic_logflag;	/* Flag indicates if data was logged */
	uint64_t ic_idx;	/* Icache index */
	uint64_t ic_way;	/* Icache way */
	uint64_t ic_patag;	/* Physical address tag */
	uint64_t ic_utag;	/* Microtag */
	uint64_t ic_upper;	/* Upper valid/predict tag */
	uint64_t ic_lower;	/* Lower valid/predict tag */
	uint64_t ic_sntag;	/* Snoop Tag */
	uint64_t ic_data[PN_IC_DATA_REG_SIZE/sizeof (uint64_t)]; /* Data */
} ch_ic_data_t;

/*
 * Pcache data captured by get_pcache_dtag
 */
typedef struct ch_pc_data {
	uint64_t pc_logflag;	/* Flag indicates if data was logged */
	uint64_t pc_idx;	/* Pcache index */
	uint64_t pc_way;	/* Pcache way */
	uint64_t pc_status;	/* Pcache status data */
	uint64_t pc_tag;	/* Tag/Valid Fields */
	uint64_t pc_sntag;	/* Snoop Tag */
	uint64_t pc_data[CH_PC_DATA_REG_SIZE/sizeof (uint64_t)]; /* Data */
} ch_pc_data_t;

/*
 * CPU Error State
 */
typedef struct ch_cpu_errors {
	uint64_t afsr;		/* AFSR */
	uint64_t afar;		/* AFAR */
	/*
	 * The following registers don't exist on cheetah
	 */
	uint64_t shadow_afsr;	/* Shadow AFSR */
	uint64_t shadow_afar;	/* Shadow AFAR */
	uint64_t afsr_ext;	/* AFSR1_EXT */
	uint64_t shadow_afsr_ext;	/* AFSR2_EXT */
	uint64_t afar2;		/* AFAR2 - Serrano only */
} ch_cpu_errors_t;

/*
 * CPU logout structures.
 * NOTE: These structures should be the same for Cheetah, Cheetah+,
 *	 Jaguar, Panther, and Jalapeno since the assembler code relies
 *	 on one set of offsets. Panther is the only processor that
 *	 uses the chd_l2_data field since it has both L3 and L2 caches.
 */
typedef struct ch_diag_data {
	uint64_t chd_afar;				/* AFAR */
	uint64_t chd_afsr;				/* AFSR */
	uint64_t chd_afsr_ext;				/* AFSR_EXT */
	uint64_t chd_afar2;			/* AFAR2 - Serrano only */
	ch_ec_data_t chd_ec_data[CHD_EC_DATA_SETS];	/* Ecache data */
	ch_ec_data_t chd_l2_data[PN_L2_NWAYS];		/* L2 cache data */
	ch_dc_data_t chd_dc_data;			/* Dcache data */
	ch_ic_data_t chd_ic_data;			/* Icache data */
} ch_diag_data_t;


/*
 * Top level CPU logout structure.
 * clo_flags is used to hold information such as trap type, trap level,
 * CEEN value, etc that is needed by the individual trap handlers. Not
 * all fields in this flag are used by all trap handlers but when they
 * are used, here's how they are laid out:
 *
 * |-------------------------------------------------------|
 * |        | trap type | trap level |  |UCEEN| |NCEEN|CEEN|
 * |-------------------------------------------------------|
 *  63       19       12 11         8      3   2   1    0
 *
 * Note that the *CEEN bits correspond exactly to the same bit positions
 * that are used in the error enable register.
 */
typedef struct ch_cpu_logout {
	uint64_t clo_flags;		/* Information about this trap */
	uint64_t clo_nest_cnt;		/* To force an upper bound */
	ch_diag_data_t clo_data;	/* Diag data for primary AFAR */
	ch_diag_data_t clo_sdw_data;	/* Diag data for shadow AFAR */
} ch_cpu_logout_t;

typedef struct ch_tte_entry {
	uint64_t ch_tte_tag;
	uint64_t ch_tte_data;
} ch_tte_entry_t;

/*
 * Top level CPU logout structure for TLB parity errors.
 *
 * tlo_logflag  - Flag indicates if data was logged
 * tlo_info	- Used to keep track of a number of values:
 *   itlb pgsz	  - Page size of the VA whose lookup in the ITLB caused
 *		    the exception (from ASI_IMMU_TAG_ACCESS_EXT.)
 *   dtlb pgsz1	  - Page size of the VA whose lookup in the DTLB T512_1
 *		    caused the exception (from ASI_DMMU_TAG_ACCESS_EXT.).
 *   dtlb pgsz0	  - Page size of the VA whose lookup in the DTLB T512_0
 *		    caused the exception (from ASI_DMMU_TAG_ACCESS_EXT.).
 *   immu	  - Trap is the result of an ITLB exception if immu == 1.
 *		    Otherwise, for DTLB exceptions immu == 0.
 *   tl1	  - Set to 1 if the exception occured at TL>0.
 *   context	  - Context of the VA whose lookup in the TLB caused the
 *		    exception (from ASI_[I|D]MMU_TAG_ACCESS.)
 * |---------------------------------------------------------------------|
 * |...| itlb pgsz  | dtlb pgsz1 | dtlb pgsz0 |...| immu | tl1 | context |
 * |---------------------------------------------------------------------|
 *      24        22 21        19 18        16       14    13   12      0
 *
 * tlo_addr	- VA that cause the MMU exception trap.
 * tlo_pc	- PC where the exception occured.
 * tlo_itlb_tte	- TTEs that were in the ITLB after the trap at the index
 *		  specific to the VA and page size in question.
 * tlo_dtlb_tte	- TTEs that were in the DTLB after the trap at the index
 *		  specific to the VA and page size in question.
 */
typedef struct pn_tlb_logout {
	uint64_t tlo_logflag;
	uint64_t tlo_info;
	uint64_t tlo_addr;
	uint64_t tlo_pc;
	ch_tte_entry_t tlo_itlb_tte[PN_ITLB_NWAYS * PN_NUM_512_ITLBS];
	ch_tte_entry_t tlo_dtlb_tte[PN_DTLB_NWAYS * PN_NUM_512_DTLBS];
} pn_tlb_logout_t;

#if defined(CPU_IMP_L1_CACHE_PARITY)
/*
 * Parity error logging structure.
 */
typedef union ch_l1_parity_log {
	struct {
		int cpl_way;				/* Faulty line way */
		int cpl_off;				/* Faulty line offset */
		int cpl_tag;				/* Faulty tags list */
		int cpl_lcnt;				/* Faulty cache lines */
		ch_dc_data_t cpl_dc[CH_DCACHE_NWAY];	/* D$ data nWays */
		ch_pc_data_t cpl_pc[CH_PCACHE_NWAY];	/* P$ data nWays */
		int cpl_cache;				/* error in D$ or P$? */
	} dpe;	/* D$ parity error */
	struct {
		int cpl_way;				/* Faulty line way */
		int cpl_off;				/* Faulty line offset */
		int cpl_tag;				/* Faulty tags list */
		int cpl_lcnt;				/* Faulty cache lines */
		ch_ic_data_t cpl_ic[CH_ICACHE_NWAY];	/* I$ data nWays */
	} ipe;	/* I$ parity error */
} ch_l1_parity_log_t;

#endif	/* CPU_IMP_L1_CACHE_PARITY */

/*
 * Error at TL>0 CPU logout data.
 *   Needs some extra space to save %g registers and miscellaneous info.
 */
typedef struct ch_err_tl1_data {
	uint64_t ch_err_tl1_g1;		/* Saved %g1 */
	uint64_t ch_err_tl1_g2;		/* Saved %g2 */
	uint64_t ch_err_tl1_g3;		/* Saved %g3 */
	uint64_t ch_err_tl1_g4;		/* Saved %g4 */
	uint64_t ch_err_tl1_g5;		/* Saved %g5 */
	uint64_t ch_err_tl1_g6;		/* Saved %g6 */
	uint64_t ch_err_tl1_g7;		/* Saved %g7 */
	uint64_t ch_err_tl1_tpc;	/* Trap PC */
	uint64_t ch_err_tl1_flags;	/* miscellaneous flags */
	uint64_t ch_err_tl1_tmp;	/* some handlers may use as tmp */
	ch_cpu_logout_t ch_err_tl1_logout;	/* logout */
} ch_err_tl1_data_t;

/* Indices into chsm_outstanding and friends */
#define	CACHE_SCRUBBER_INFO_E	0
#define	CACHE_SCRUBBER_INFO_D	1
#define	CACHE_SCRUBBER_INFO_I	2

/* We define 3 scrubbers: E$, D$, and I$ */
#define	CACHE_SCRUBBER_COUNT	3

/*
 * The ch_scrub_misc structure contains miscellaneous bookkeeping
 * items for scrubbing the I$, D$, and E$.
 *
 * For a description of the use of chsm_core_state and why it's not needed
 * on Jaguar, see the comment above cpu_scrub_cpu_setup() in us3_cheetahplus.c.
 */
typedef struct ch_scrub_misc {
	uint32_t	chsm_outstanding[CACHE_SCRUBBER_COUNT];
						/* outstanding requests */
	int		chsm_flush_index[CACHE_SCRUBBER_COUNT];
						/* next line to flush */
	int		chsm_enable[CACHE_SCRUBBER_COUNT];
				/* is this scrubber enabled on this core? */
	int		chsm_ecache_nlines;	/* no. of E$ lines */
	int		chsm_ecache_busy;	/* keeps track if cpu busy */
	int		chsm_icache_nlines;	/* no. of I$ lines */
	int		chsm_core_state;	/* which core the scrubber is */
						/* running on (Panther only) */
} ch_scrub_misc_t;

/*
 * Cheetah module private data structure.  One of these is allocated for
 * each valid cpu at setup time and is pointed to by the machcpu
 * "cpu_private" pointer.  For Cheetah, we have the miscellaneous scrubber
 * variables and cpu log out structures for Fast ECC traps at TL=0,
 * Disrupting (correctable) traps and Deferred (asynchronous) traps.  For
 * Disrupting traps only one log out structure is needed because we cannot
 * get a TL>0 disrupting trap since it obeys IE.  For Deferred traps we
 * cannot get a TL>0 because we turn off NCEEN during log out capture.  E$
 * set size (E$ size / nways) is saved here to avoid repeated calculations.
 * NB: The ch_err_tl1_data_t structures cannot cross a page boundary
 *      because we use physical addresses to access them.  We ensure this
 *      by allocating them near the front of cheetah_private_t, which is
 *      aligned on PAGESIZE (8192) via kmem_cache_create, and by ASSERTing
 *	sizeof (chpr_tl1_err_data) <= CH_ECACHE_MAX_LSIZE in the
 *	cpu_init_private routines.
 * NB:  chpr_icache_size and chpr_icache_linesize need to be at the front
 *	of cheetah_private_t because putting them after chpr_tl1_err_data
 *	would make their offsets > 4195.
 */
typedef struct cheetah_private {
	int			chpr_icache_size;
	int			chpr_icache_linesize;
	ch_err_tl1_data_t	chpr_tl1_err_data[CH_ERR_TL1_TLMAX];
	ch_scrub_misc_t		chpr_scrub_misc;
	int			chpr_ec_set_size;
	ch_cpu_logout_t		chpr_fecctl0_logout;
	ch_cpu_logout_t		chpr_cecc_logout;
	ch_cpu_logout_t		chpr_async_logout;
	pn_tlb_logout_t		chpr_tlb_logout;
	uint64_t		chpr_fpras_timestamp[FPRAS_NCOPYOPS];
	hrtime_t		chpr_ceptnr_seltime;
	int			chpr_ceptnr_id;
} cheetah_private_t;

#endif /* _ASM */

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_CHEETAHREGS_H */
