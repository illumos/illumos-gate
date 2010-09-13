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

#ifndef _SYS_OPL_OLYMPUS_REGS_H
#define	_SYS_OPL_OLYMPUS_REGS_H

#include <sys/machasi.h>
#include <sys/cpu_impl.h>

/*
 * This file is cpu dependent.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _ASM
/*
 * assembler doesn't understand the 'ull' suffix for C constants so
 * use the inttypes.h macros and undefine them here for assembly code
 */
#undef	INT64_C
#define	INT64_C(x)	(x)
#undef	UINT64_C
#define	UINT64_C(x)	(x)
#endif	/* _ASM */

/*
 * Synchronous Fault Physical Address Register
 */
#define	OPL_MMU_SFPAR	0x78

/*
 * ASI_MCNTL: MEMORY CONTROL Register layout (ASI 0x45, VA 8)
 *
 * +-------------------------+---------+--------+--------+-----+---------+
 * |   reserved [63:17]      | NC_Cache|fw_fITLB|fw_fDTLB|00000|JPS1_TSBP|
 * +-------------------------+---------+--------+--------+-----+---------+
 *                              16       15       14      13-9   8
 * +---------+---------+------+
 * |mpg_sITLB|mpg_sDTLB|000000|
 * +---------+---------+------+
 *  7         6         5-0
 */
#define	ASI_MCNTL	0x45
#define	LSU_MCNTL	0x8		/* vaddr offset of ASI_MCNTL	*/
#define	MCNTL_FW_FDTLB	INT64_C(0x0000000000004000)
#define	MCNTL_FW_FITLB	INT64_C(0x0000000000008000)
#define	MCNTL_JPS1_TSBP	INT64_C(0x0000000000000100)
#define	MCNTL_MPG_SITLB	INT64_C(0x0000000000000080)
#define	MCNTL_MPG_SDTLB	INT64_C(0x0000000000000040)
#define	MCNTL_SPECULATIVE_SHIFT	41	/* bit 41 is speculative mode bit */

/*
 * ASI_UGESR: URGENT ERROR STATES layout (ASI 0x4C, VA 0x8)
 *
 * +--------+---+----+----+---+---+--+--+---+---+-+----+----+----+
 * |0[63:23]|CRE|TSBX|TSBP|PST|TST| F| R|SDC|WDT|0|DTLB|ITLB|CORE|
 * +--------+---+----+----+---+---+--+--+---+---+-+----+----+----+
 *           22  21   20   19  18 17 16  15  14    10    9    8
 * +-------+----+---+---+---+
 * |INSTEND|PRIV|DAE|IAE|UGE|
 * +-------+----+---+---+---+
 *  5  4    3    2   1   0
 *
 */
#define	ASI_UGERSR		0x8
#define	UGESR_IAUG_CRE		INT64_C(0x0000000000400000)
#define	UGESR_IAUG_TSBCTXT	INT64_C(0x0000000000200000)
#define	UGESR_IUG_TSBP		INT64_C(0x0000000000100000)
#define	UGESR_IUG_PSTATE	INT64_C(0x0000000000080000)
#define	UGESR_IUG_TSTATE	INT64_C(0x0000000000040000)
#define	UGESR_IUG_F		INT64_C(0x0000000000020000)
#define	UGESR_IUG_R		INT64_C(0x0000000000010000)
#define	UGESR_AUG_SDC		INT64_C(0x0000000000008000)
#define	UGESR_IUG_WDT		INT64_C(0x0000000000004000)
#define	UGESR_IUG_DTLB		INT64_C(0x0000000000000400)
#define	UGESR_IUG_ITLB		INT64_C(0x0000000000000200)
#define	UGESR_IUG_COREERR	INT64_C(0x0000000000000100)
#define	UGESR_PRIV		INT64_C(0x0000000000000008)
#define	UGESR_MULTI_DAE		INT64_C(0x0000000000000004)
#define	UGESR_MULTI_IAE		INT64_C(0x0000000000000002)
#define	UGESR_MULTI_UGE		INT64_C(0x0000000000000001)

#define	UGESR_CAN_RECOVER	(UGESR_IUG_DTLB |	\
				UGESR_IUG_ITLB |	\
				UGESR_IUG_COREERR)

#define	UGESR_MULTI	(UGESR_MULTI_DAE |	\
			UGESR_MULTI_IAE |	\
			UGESR_MULTI_UGE)

#define	UGESR_NOSYNC_PANIC	(UGESR_IAUG_CRE  |	\
				UGESR_AUG_SDC   |	\
				UGESR_MULTI_DAE |	\
				UGESR_MULTI_IAE |	\
				UGESR_MULTI_UGE)
/*
 * The value means 10000 Mz per 10ms.
 */
#define	OPL_UGER_STICK_DIFF	10000


/*
 * ASI_ECR: Control of Error Action layout (ASI 0x4C, VA 0x10)
 *
 * +-------------------------+------+--------+-----+-------+-----------+
 * |   reserved [63:10]      |RTE_UE|RTE_CEDG|0...0|WEAK_ED|UGE_HANDLER|
 * +-------------------------+------+--------+-----+-------+-----------+
 *                              9        8    7 - 2    1       0
 *
 */
#define	ASI_ECR			ASI_AFSR
#define	AFSR_ECR		0x10
#define	ASI_ECR_RTE_UE		INT64_C(0x0000000000000200)
#define	ASI_ECR_RTE_CEDG	INT64_C(0x0000000000000100)
#define	ASI_ECR_WEAK_ED		INT64_C(0x0000000000000002)
#define	ASI_ECR_UGE_HANDLER	INT64_C(0x0000000000000001)


/*
 * ASI_L2_CTRL: Level-2 Cache Control Register (ASI 0x6A, VA 0x10)
 *
 * +---------------------+--------+-----+---------+----+--------+
 * |   reserved[63:25]   |UGE_TRAP|0...0|NUMINSWAY|0..0|U2_FLUSH|
 * +---------------------+--------+-----+---------+----+--------+
 *                          24    23  19 18     16 15 1     0
 *
 */
#define	ASI_L2_CTRL			0x6A	/* L2$ Control Register */
#define	ASI_L2_CTRL_RW_ADDR		0x10
#define	ASI_L2_CTRL_UGE_TRAP		INT64_C(0x0000000001000000)
#define	ASI_L2_CTRL_NUMINSWAY_MASK	INT64_C(0x0000000000070000)
#define	ASI_L2_CTRL_U2_FLUSH		INT64_C(0x0000000000000001)


/*
 * Synchronous Fault Status Register Layout (ASI 0x50/0x58, VA 0x18)
 *
 * IMMU and DMMU maintain their own SFSR Register
 *
 * +----+----+-----+----+--+-----+--+---+-+----+--+--+-----+--+-+
 * |TLB#|0..0|index|0..0|MK| EID |UE|UPA|0|mTLB|NC|NF| ASI |TM|0|
 * +----+----+-----+----+--+-----+--+---+-+----+--+--+-----+--+-+
 * 63 62 61    58   48   46 45 32 31 30 28 27   25 24 23 16 15 14
 * +----+-+---+--+-+--+--+
 * | FT |E| CT|PR|W|OW|FV|
 * +----+-+---+--+-+--+--+
 *  13 7 6 5 4 3  2 1  0
 *
 */
#define	SFSR_MK_UE	INT64_C(0x0000400000000000)
#define	SFSR_EID_MOD	INT64_C(0x0000300000000000)
#define	SFSR_EID_SID	INT64_C(0x00000FFF00000000)
#define	SFSR_UE		INT64_C(0x0000000080000000)
#define	SFSR_BERR	INT64_C(0x0000000040000000)
#define	SFSR_TO		INT64_C(0x0000000020000000)
#define	SFSR_TLB_MUL	INT64_C(0x0000000008000000)
#define	SFSR_TLB_PRT	INT64_C(0x0000000004000000)

#define	SFSR_EID_MOD_SHIFT		44
#define	SFSR_EID_SID_SHIFT		32

/*
 * Error Mark ID: Module Type
 */
#define	OPL_ERRID_MEM		0
#define	OPL_ERRID_CHANNEL	1
#define	OPL_ERRID_CPU		2
#define	OPL_ERRID_PATH		3


#define	SFSR_ERRS	(SFSR_UE | SFSR_BERR |	\
	    SFSR_TO | SFSR_TLB_MUL |		\
	    SFSR_TLB_PRT)

#define	SFSR_MEMORY	(SFSR_UE |	\
	    SFSR_BERR |			\
	    SFSR_TO)

/*
 * Miscellaneous ASI definitions
 */
#define	ASI_IIU_INST_TRAP	0x60	/* Instruction breakpoint */
#define	ASI_ALL_FLUSH_L1I	0x67	/* Flush Level-1 Inst. cache */
#define	ASI_L2_TAG_READ		0x6B	/* L2 Diagnostics Tag Read */
#define	ASI_L2_TAG_READ_REG	0x6C	/* L2 Diagnostics Tag Read Register */
#define	ASI_EIDR		0x6E	/* Urgent errors */
#define	ASI_CACHE_INV		0x74	/* Cache invalidation */
#define	ASI_ERR_INJCT		0x76	/* Error injection */
/*
 * Address of ASI scratch register. ASI 0x4F
 */
#define	OPL_SCRATCHPAD_SAVE_AG1	0x00	/* used for saving global registers */
#define	OPL_SCRATCHPAD_SAVE_AG2	0x08	/* used for saving global registers */
#define	OPL_SCRATCHPAD_SAVE_AG3	0x10	/* used for saving global registers */
#define	OPL_SCRATCHPAD_ERRLOG	0x18	/* keeps EIDR, log's PA & err counter */
#define	OPL_SCRATCHPAD_UTSBREG4	0x20
#define	OPL_SCRATCHPAD_UTSBREG5 0x28
#define	OPL_SCRATCHPAD_UTSBREG6 0x30
#define	OPL_SCRATCHPAD_UNUSED7  0x38

/*
 * Error log scratchpad register format.
 *
 * +--------+-------------------+----------+
 * |ASI_EIDR| PA to logging buf | # of err |
 * +--------+-------------------+----------+
 *  63    50 49                6 5        0
 *
 */

#define	ERRLOG_REG_LOGPA_MASK	INT64_C(0x0003ffffffffffc0) /* PA to log */
#define	ERRLOG_REG_NUMERR_MASK	INT64_C(0x000000000000003f) /* Counter */
#define	ERRLOG_REG_EIDR_MASK	INT64_C(0x0000000000003fff) /* EIDR */

#define	ERRLOG_REG_EIDR_SHIFT	50
#define	ERRLOG_REG_ERR_SHIFT	6
#define	ERRLOG_REG_EIDR(reg)	((reg >> ERRLOG_REG_EIDR_SHIFT) &	\
	    ERRLOG_REG_EIDR_MASK)
#define	ERRLOG_REG_LOGPA(reg)	(reg & ERRLOG_REG_LOGPA_MASK)
#define	ERRLOG_REG_NUMERR(reg)	(reg & ERRLOG_REG_NUMERR_MASK)

#define	ERRLOG_BUFSZ		0x2000
#define	ERRLOG_SZ		(1 << ERRLOG_REG_ERR_SHIFT)
#define	ERRLOG_ALLOC_SZ		(ERRLOG_BUFSZ * 512)

/*
 * Olympus-C default cache parameters.
 */
#define	OPL_DCACHE_SIZE		0x20000
#define	OPL_DCACHE_LSIZE	0x40
#define	OPL_ICACHE_SIZE		0x20000
#define	OPL_ICACHE_LSIZE	0x40
#define	OPL_ECACHE_SIZE		0x600000
#define	OPL_ECACHE_LSIZE	0x100
#define	OPL_ECACHE_NWAY		12
#define	OPL_ECACHE_SETSIZE	0x80000

/*
 * OPL platform has no vac consistent issue. So set it to 8KB.
 */
#define	OPL_VAC_SIZE		0x2000

/* these are field offsets for opl_errlog structure */
#define	LOG_STICK_OFF	0x0
#define	LOG_TL_OFF	0x8
#define	LOG_ASI3_OFF	0x10
#define	LOG_SFSR_OFF	0x18
#define	LOG_SFAR_OFF	0x20

#define	LOG_UGER_OFF	0x18
#define	LOG_TSTATE_OFF	0x20
#define	LOG_TPC_OFF	0x28

#ifndef	_ASM
typedef struct opl_errlog {
	uint64_t stick;
	uint32_t tl;
	uint32_t tt;
	uint64_t asi3;
	union {
		struct {
			uint64_t sfsr;
			union {
				uint64_t sfar;
				uint64_t sfpar;
			} sync_addr;
		} sync;
		struct {
			uint64_t ugesr;
			uint64_t tstate;
		} ugesr;
	} reg;
	uint64_t tpc;
} opl_errlog_t;
#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_OPL_OLYMPUS_REGS_H */
