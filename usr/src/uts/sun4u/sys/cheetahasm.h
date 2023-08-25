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

#ifndef	_CHEETAHASM_H
#define	_CHEETAHASM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef _ASM
/* BEGIN CSTYLED */

#define	ASM_LD(reg, symbol)						\
	sethi	%hi(symbol), reg;					\
	ld	[reg + %lo(symbol)], reg;				\

#define	ASM_LDX(reg, symbol)						\
	sethi	%hi(symbol), reg;					\
	ldx	[reg + %lo(symbol)], reg;				\

#define	ASM_JMP(reg, symbol)						\
	sethi	%hi(symbol), reg;					\
	jmp	reg + %lo(symbol);					\
	nop

/*
 * Macro for getting to offset from 'cpu_private' ptr.  The 'cpu_private'
 * ptr is in the machcpu structure.
 *  off_reg:  Register offset from 'cpu_private' ptr.
 *  scr1:    Scratch, ptr is returned in this register.
 *  scr2:    Scratch
 *  label:   Label to branch to if cpu_private ptr is null/zero.
 */
#define	GET_CPU_PRIVATE_PTR(off_reg, scr1, scr2, label)			\
	CPU_ADDR(scr1, scr2);						\
	ldn	[scr1 + CPU_PRIVATE], scr1;				\
	cmp	scr1, 0;						\
	be	label;							\
	  nop;								\
	add	scr1, off_reg, scr1

/*
 * Macro version of get_dcache_dtag.  We use this macro in the
 * CPU logout code. Since the Dcache is virtually indexed, only
 * bits [12:5] of the AFAR can be used so we need to search through
 * 8 indexes (4 ways + bit 13) in order to find the tag we want.
 *   afar:  input AFAR, not modified.
 *   datap: input ptr to ch_dc_data_t, at end pts to end of ch_dc_data_t.
 *   scr1:  scratch.
 *   scr2:  scratch, will hold tag to look for.
 *   scr3:  used for Dcache index, loops through 4 ways.
 */
#define	GET_DCACHE_DTAG(afar, datap, scr1, scr2, scr3)			\
	set	CH_DCACHE_IDX_MASK, scr3;				\
	and	afar, scr3, scr3;					\
	srlx	afar, CH_DCTAG_PA_SHIFT, scr2;				\
	b	1f;							\
	  or	scr2, CH_DCTAG_VALID_BIT, scr2; /* tag we want */	\
	.align	128;							\
1:									\
	ldxa	[scr3]ASI_DC_TAG, scr1;		/* read tag */		\
	cmp	scr1, scr2;						\
	bne	4f;				/* not found? */	\
	  nop;								\
	stxa	scr3, [datap + CH_DC_IDX]%asi;	/* store index */	\
	stxa	scr1, [datap + CH_DC_TAG]%asi;	/* store tag */		\
	membar	#Sync;			/* Cheetah PRM 10.6.3 */	\
	ldxa	[scr3]ASI_DC_UTAG, scr1;	/* read utag */		\
	membar	#Sync;			/* Cheetah PRM 10.6.3 */	\
	stxa	scr1, [datap + CH_DC_UTAG]%asi;				\
	ldxa	[scr3]ASI_DC_SNP_TAG, scr1;	/* read snoop tag */	\
	stxa	scr1, [datap + CH_DC_SNTAG]%asi;			\
	add	datap, CH_DC_DATA, datap;				\
	clr	scr2;							\
2:									\
	membar	#Sync;			/* Cheetah PRM 10.6.1 */	\
	ldxa	[scr3 + scr2]ASI_DC_DATA, scr1;	/* read data */		\
	membar	#Sync;			/* Cheetah PRM 10.6.1 */	\
	stxa	scr1, [datap]%asi;					\
	add	datap, 8, datap;					\
	cmp	scr2, CH_DC_DATA_REG_SIZE - 8;				\
	blt	2b;							\
	  add	scr2, 8, scr2;						\
									\
	GET_CPU_IMPL(scr2);	/* Parity bits are elsewhere for */	\
	cmp	scr2, PANTHER_IMPL;	/* panther processors. */	\
	bne,a	5f;			/* Done if not panther. */	\
	  add	datap, 8, datap; /* Skip to the end of the struct. */	\
	clr	scr2;							\
	add	datap, 7, datap; /* offset of the last parity byte */	\
	mov	1, scr1;						\
	sll	scr1, PN_DC_DATA_PARITY_BIT_SHIFT, scr1;		\
	or	scr3, scr1, scr3; /* add DC_data_parity bit to index */	\
3:									\
	membar	#Sync;			/* Cheetah PRM 10.6.1 */	\
	ldxa	[scr3 + scr2]ASI_DC_DATA, scr1;	/* read parity bits */	\
	membar	#Sync;			/* Cheetah PRM 10.6.1 */	\
	stba	scr1, [datap]%asi;					\
	dec	datap;							\
	cmp	scr2, CH_DC_DATA_REG_SIZE - 8;				\
	blt	3b;							\
	  add	scr2, 8, scr2;						\
	b	5f;							\
	  add	datap, 5, datap; /* set pointer to end of our struct */	\
4:									\
	set	CH_DCACHE_IDX_INCR, scr1;	/* incr. idx (scr3) */	\
	add	scr3, scr1, scr3;					\
	set	CH_DCACHE_IDX_LIMIT, scr1;	/* done? */		\
	cmp	scr3, scr1;						\
	blt	1b;							\
	  nop;								\
	add	datap, CH_DC_DATA_SIZE, datap;				\
5:

/*
 * Macro version of get_icache_dtag.  We use this macro in the CPU
 * logout code. If the Icache is on, we don't want to capture the data.
 *   afar:  input AFAR, not modified.
 *   datap: input ptr to ch_ic_data_t, at end pts to end of ch_ic_data_t.
 *   scr1:  scratch.
 *   scr2:  scratch, will hold tag to look for.
 *   scr3:  used for Icache index, loops through 4 ways.
 * Note: For Panther, the Icache is virtually indexed and increases in
 * size to 64KB (instead of 32KB) with a line size of 64 bytes (instead
 * of 32). This means the IC_addr index bits[14:7] for Panther now
 * correspond to VA bits[13:6]. But since it is virtually indexed, we
 * still mask out only bits[12:5] from the AFAR (we have to manually
 * check bit 13). In order to make this code work for all processors,
 * we end up checking twice as many indexes (8 instead of 4) as required
 * for non-Panther CPUs and saving off twice as much data (16 instructions
 * instead of just 8).
 */
#define	GET_ICACHE_DTAG(afar, datap, scr1, scr2, scr3)			\
	ldxa	[%g0]ASI_DCU, scr1;					\
	btst	DCU_IC, scr1;		/* is Icache enabled? */	\
	bne,a	6f;			/* yes, don't capture */	\
	  add	datap, CH_IC_DATA_SIZE, datap;	/* anul if no branch */	\
	GET_CPU_IMPL(scr2);	/* Panther only uses VA[13:6] */	\
	cmp	scr2, PANTHER_IMPL;	/* and we also want to mask */	\
	be	1f;			/* out bit 13 since the */	\
	  nop;				/* Panther I$ is VIPT. */	\
	set	CH_ICACHE_IDX_MASK, scr3;				\
	b	2f;							\
	  nop;								\
1:									\
	set	PN_ICACHE_VA_IDX_MASK, scr3;				\
2:									\
	and	afar, scr3, scr3;					\
	sllx	scr3, CH_ICACHE_IDX_SHIFT, scr3;			\
	srlx	afar, CH_ICPATAG_SHIFT, scr2;	/* pa tag we want */	\
	andn	scr2, CH_ICPATAG_LBITS, scr2;	/* mask off lower */	\
	b	3f;							\
	  nop;								\
	.align	128;							\
3:									\
	ldxa	[scr3]ASI_IC_TAG, scr1;		/* read pa tag */	\
	andn	scr1, CH_ICPATAG_LBITS, scr1;	/* mask off lower */	\
	cmp	scr1, scr2;						\
	bne	5f;				/* not found? */	\
	  nop;								\
	stxa	scr3, [datap + CH_IC_IDX]%asi;	/* store index */	\
	stxa	scr1, [datap + CH_IC_PATAG]%asi; /* store pa tag */	\
	add	scr3, CH_ICTAG_UTAG, scr3;	/* read utag */		\
	ldxa	[scr3]ASI_IC_TAG, scr1;					\
	add	scr3, (CH_ICTAG_UPPER - CH_ICTAG_UTAG), scr3;		\
	stxa	scr1, [datap + CH_IC_UTAG]%asi;				\
	ldxa	[scr3]ASI_IC_TAG, scr1;		/* read upper tag */	\
	add	scr3, (CH_ICTAG_LOWER - CH_ICTAG_UPPER), scr3;		\
	stxa	scr1, [datap + CH_IC_UPPER]%asi;			\
	ldxa	[scr3]ASI_IC_TAG, scr1;		/* read lower tag */	\
	andn	scr3, CH_ICTAG_TMASK, scr3;				\
	stxa	scr1, [datap + CH_IC_LOWER]%asi;			\
	ldxa	[scr3]ASI_IC_SNP_TAG, scr1;	/* read snoop tag */	\
	stxa	scr1, [datap + CH_IC_SNTAG]%asi;			\
	add	datap, CH_IC_DATA, datap;				\
	clr	scr2;							\
4:									\
	ldxa	[scr3 + scr2]ASI_IC_DATA, scr1;	/* read ins. data */	\
	stxa	scr1, [datap]%asi;					\
	add	datap, 8, datap;					\
	cmp	scr2, PN_IC_DATA_REG_SIZE - 8;				\
	blt	4b;							\
	  add	scr2, 8, scr2;						\
	b	6f;							\
	  nop;								\
5:									\
	set	CH_ICACHE_IDX_INCR, scr1;	/* incr. idx (scr3) */	\
	add	scr3, scr1, scr3;					\
	set	PN_ICACHE_IDX_LIMIT, scr1;	/* done? */		\
	cmp	scr3, scr1;						\
	blt	3b;							\
	  nop;								\
	add	datap, CH_IC_DATA_SIZE, datap;				\
6:

#if defined(JALAPENO) || defined(SERRANO)
/*
 * Macro version of get_ecache_dtag.  We use this macro in the
 * CPU logout code.
 *   afar:	input AFAR, not modified
 *   datap:	Ptr to ch_ec_data_t, at end pts just past ch_ec_data_t.
 *   ec_way:	Constant value (way number)
 *   scr1:      Scratch
 *   scr2:	Scratch.
 *   scr3:	Scratch.
 */
#define	GET_ECACHE_DTAG(afar, datap, ec_way, scr1, scr2, scr3)		\
	mov	ec_way, scr1;						\
	and	scr1, JP_ECACHE_NWAY - 1, scr1;	/* mask E$ way bits */	\
	sllx	scr1, JP_EC_TAG_DATA_WAY_SHIFT, scr1;			\
	set	((JP_ECACHE_MAX_SIZE / JP_ECACHE_NWAY) - 1), scr2;	\
	and	afar, scr2, scr3;		/* get set offset */	\
	andn	scr3, (JP_ECACHE_MAX_LSIZE - 1), scr3; /* VA<5:0>=0 */	\
	or	scr3, scr1, scr3;		/* or WAY bits */	\
	b	1f;							\
	  stxa	scr3, [datap + CH_EC_IDX]%asi;	/* store E$ index */	\
	.align	64;							\
1:									\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	ldxa    [scr3]ASI_EC_DIAG, scr1;	/* get E$ tag */	\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	stxa	scr1, [datap + CH_EC_TAG]%asi;				\
	add	datap, CH_EC_DATA, datap;				\
2:									\
	ldxa	[scr3]ASI_EC_R, %g0;		/* ld E$ stging regs */	\
	clr	scr1;							\
3:						/* loop thru 5 regs */	\
	ldxa	[scr1]ASI_EC_DATA, scr2;				\
	stxa	scr2, [datap]%asi;					\
	add	datap, 8, datap;					\
	cmp	scr1, CH_ECACHE_STGREG_TOTALSIZE - 8;			\
	bne	3b;							\
	   add	scr1, 8, scr1;						\
	btst	CH_ECACHE_STGREG_SIZE, scr3;	/* done? */		\
	beq	2b;							\
	   add	scr3, CH_ECACHE_STGREG_SIZE, scr3

#define	GET_ECACHE_DTAGS(afar, datap, scr1, scr2, scr3)			\
	GET_ECACHE_DTAG(afar, datap, 0, scr1, scr2, scr3);		\
	GET_ECACHE_DTAG(afar, datap, 1, scr1, scr2, scr3);		\
	GET_ECACHE_DTAG(afar, datap, 2, scr1, scr2, scr3);		\
	GET_ECACHE_DTAG(afar, datap, 3, scr1, scr2, scr3);		\
	add	datap, (CHD_EC_DATA_SETS-4)*CH_EC_DATA_SIZE, datap;	\
	add	datap, CH_EC_DATA_SIZE * PN_L2_NWAYS, datap;		\

/*
 * Jalapeno does not have cores so these macros are null.
 */
#define	PARK_SIBLING_CORE(dcucr_reg, scr1, scr2)
#define	UNPARK_SIBLING_CORE(dcucr_reg, scr1, scr2)

#if defined(JALAPENO)
/*
 * Jalapeno gets primary AFSR and AFAR.  All bits in the AFSR except
 * the fatal error bits are cleared.
 *	datap:		pointer to cpu logout structure.
 *	afar:		returned primary AFAR value.
 *	scr1:		scratch
 *	scr2:		scratch
 */
#define	GET_AFSR_AFAR(datap, afar, scr1, scr2)				\
	ldxa	[%g0]ASI_AFAR, afar;					\
	stxa	afar, [datap + (CH_CLO_DATA + CH_CHD_AFAR)]%asi;	\
	ldxa	[%g0]ASI_AFSR, scr2;					\
	stxa	scr2, [datap + (CH_CLO_DATA + CH_CHD_AFSR)]%asi;	\
	sethi	%hh(C_AFSR_FATAL_ERRS), scr1;				\
	sllx	scr1, 32, scr1;						\
	bclr	scr1, scr2;	/* Clear fatal error bits here, so */	\
	stxa	scr2, [%g0]ASI_AFSR; /* they're left as is in AFSR */	\
	membar	#Sync

/*
 * Jalapeno has no shadow AFAR, null operation.
 */
#define	GET_SHADOW_DATA(afar, datap, scr1, scr2, scr3)

#elif defined(SERRANO)
/*
 * Serrano gets primary AFSR and AFAR.  All bits in the AFSR except
 * the fatal error bits are cleared.  For Serrano, we also save the
 * AFAR2 register.
 *	datap:	pointer to cpu logout structure.
 *	afar:	returned primary AFAR value.
 *	scr1:	scratch
 *	scr2:	scratch
 */
#define GET_AFSR_AFAR(datap, afar, scr1, scr2)				\
	set	ASI_MCU_AFAR2_VA, scr1;					\
	ldxa	[scr1]ASI_MCU_CTRL, afar;				\
	stxa	afar, [datap + (CH_CLO_DATA + CH_CHD_AFAR2)]%asi;	\
	ldxa	[%g0]ASI_AFAR, afar;					\
	stxa	afar, [datap + (CH_CLO_DATA + CH_CHD_AFAR)]%asi;	\
	ldxa	[%g0]ASI_AFSR, scr2;					\
	stxa	scr2, [datap + (CH_CLO_DATA + CH_CHD_AFSR)]%asi;	\
	sethi	%hh(C_AFSR_FATAL_ERRS), scr1;				\
	sllx	scr1, 32, scr1;						\
	bclr	scr1, scr2;	/* Clear fatal error bits here, so */	\
	stxa	scr2, [%g0]ASI_AFSR; /* they're left as is in AFSR */ 	\
	membar	#Sync

/*
 * Serrano needs to capture E$, D$ and I$ lines associated with afar2.
 *      afar:   scratch, holds afar2.
 *      datap:  pointer to cpu logout structure
 *      scr1:   scratch
 *      scr2:   scratch
 *      scr3:   scratch
 */
#define	GET_SHADOW_DATA(afar, datap, scr1, scr2, scr3)		\
	ldxa	[datap + (CH_CLO_DATA + CH_CHD_AFAR2)]%asi, afar;	\
	add	datap, CH_CLO_SDW_DATA + CH_CHD_EC_DATA, datap;		\
	GET_ECACHE_DTAGS(afar, datap, scr1, scr2, scr3);		\
	GET_DCACHE_DTAG(afar, datap, scr1, scr2, scr3);			\
	GET_ICACHE_DTAG(afar, datap, scr1, scr2, scr3);			\
	sub	datap, CH_CPU_LOGOUT_SIZE, datap
#endif /* SERRANO */

#elif defined(CHEETAH_PLUS)
/*
 * Macro version of get_ecache_dtag.  We use this macro in the
 * CPU logout code.
 *   afar:	input AFAR, not modified.
 *   datap:	Ptr to ch_ec_data_t, at end pts just past ch_ec_data_t.
 *   pn_way:	ecache way for panther (value = 0-3). For non-panther
 *		cpus, this macro will be called with pn_way = 0.
 *   scr1:	Scratch.
 *   scr2:	Scratch.
 *   scr3:	Scratch.
 */
#define	GET_ECACHE_DTAG(afar, datap, pn_way, scr1, scr2, scr3)		\
	mov	afar, scr3;						\
	andn	scr3, (CH_ECACHE_SUBBLK_SIZE - 1), scr3; /* VA<5:0>=0 */\
	set	(CH_ECACHE_8M_SIZE - 1), scr2;				\
	and	scr3, scr2, scr3;		/* VA<63:23>=0 */	\
	mov	pn_way, scr1;	/* panther L3$ is 4-way so we ...    */	\
	sllx	scr1, PN_L3_WAY_SHIFT, scr1;	/* need to mask...   */	\
	or	scr3, scr1, scr3;	/* in the way bits <24:23>.  */	\
	b	1f;							\
	   stxa	scr3, [datap + CH_EC_IDX]%asi;	/* store E$ index */	\
	.align	64;							\
1:									\
	ldxa    [scr3]ASI_EC_DIAG, scr1;	/* get E$ tag */	\
	stxa     scr1, [datap + CH_EC_TAG]%asi;				\
	set	CHP_ECACHE_IDX_TAG_ECC, scr1;				\
	or	scr3, scr1, scr1;					\
	ldxa    [scr1]ASI_EC_DIAG, scr1;	/* get E$ tag ECC */	\
	stxa	scr1, [datap + CH_EC_TAG_ECC]%asi;			\
	add	datap, CH_EC_DATA, datap;				\
2:									\
	ldxa	[scr3]ASI_EC_R, %g0;		/* ld E$ stging regs */	\
	clr	scr1;							\
3:						/* loop thru 5 regs */	\
	ldxa	[scr1]ASI_EC_DATA, scr2;				\
	stxa	scr2, [datap]%asi;					\
	add	datap, 8, datap;					\
	cmp	scr1, CH_ECACHE_STGREG_TOTALSIZE - 8;			\
	bne	3b;							\
	   add	scr1, 8, scr1;						\
	btst	CH_ECACHE_STGREG_SIZE, scr3;	/* done? */		\
	beq	2b;							\
	   add	scr3, CH_ECACHE_STGREG_SIZE, scr3

/*
 * If this is a panther, we need to make sure the sibling core is
 * parked so that we avoid any race conditions during diagnostic
 * accesses to the shared L2 and L3 caches.
 * dcucr_reg:	This register will be used to keep track of whether
 *		or not we need to unpark the core later.
 *		It just so happens that we also use this same register
 *		to keep track of our saved DCUCR value so we only touch
 *		bit 4 of the register (which is a "reserved" bit in the
 *		DCUCR) for keeping track of core parking.
 * scr1:	Scratch register.
 * scr2:	Scratch register.
 */
#define	PARK_SIBLING_CORE(dcucr_reg, scr1, scr2)			\
	GET_CPU_IMPL(scr1);						\
	cmp	scr1, PANTHER_IMPL;	/* only park for panthers */	\
	bne,a	%xcc, 2f;						\
	  andn	dcucr_reg, PN_PARKED_OTHER_CORE, dcucr_reg;		\
	set	ASI_CORE_RUNNING_STATUS, scr1;	/* check other core */	\
	ldxa	[scr1]ASI_CMP_SHARED, scr2;	/* is it running?   */	\
	cmp	scr2, PN_BOTH_CORES_RUNNING;				\
	bne,a	%xcc, 2f;	/* if not running, we are done */	\
	  andn	dcucr_reg, PN_PARKED_OTHER_CORE, dcucr_reg;		\
	or	dcucr_reg, PN_PARKED_OTHER_CORE, dcucr_reg;		\
	set	ASI_CORE_ID, scr1;					\
	ldxa	[scr1]ASI_CMP_PER_CORE, scr2;				\
	and	scr2, COREID_MASK, scr2;				\
	or	%g0, 1, scr1;		/* find out which core... */	\
	sll	scr1, scr2, scr2;	/* ... we need to park... */	\
1:									\
	set	ASI_CORE_RUNNING_RW, scr1;				\
	ldxa    [scr1]ASI_CMP_SHARED, scr1;	/* ...but are we? */	\
	btst    scr1, scr2;        /* check our own parked status */	\
	bz      %xcc, 1b;        /* if we are then go round again */	\
	nop;								\
	set	ASI_CORE_RUNNING_RW, scr1;	/* else proceed... */	\
	stxa	scr2, [scr1]ASI_CMP_SHARED;	/* ... and park it. */	\
	membar	#Sync;							\
	set	ASI_CORE_RUNNING_STATUS, scr1;	/* spin until... */	\
	ldxa	[scr1]ASI_CMP_SHARED, scr1;	/* ... the other...  */	\
	cmp	scr1, scr2;	/* ...core is parked according to... */	\
	bne,a	%xcc, 1b;	/* ...the core running status reg.  */	\
	  nop;								\
2:

/*
 * The core running this code will unpark its sibling core if the
 * sibling core had been parked by the current core earlier in this
 * trap handler.
 * dcucr_reg:	This register is used to keep track of whether or not
 *		we need to unpark our sibling core.
 *		It just so happens that we also use this same register
 *		to keep track of our saved DCUCR value so we only touch
 *		bit 4 of the register (which is a "reserved" bit in the
 *		DCUCR) for keeping track of core parking.
 * scr1:	Scratch register.
 * scr2:	Scratch register.
 */
#define	UNPARK_SIBLING_CORE(dcucr_reg, scr1, scr2)			\
	btst	PN_PARKED_OTHER_CORE, dcucr_reg;			\
	bz,pt	%xcc, 1f;	/* if nothing to unpark, we are done */	\
	  andn	dcucr_reg, PN_PARKED_OTHER_CORE, dcucr_reg;		\
	set	ASI_CORE_RUNNING_RW, scr1;				\
	set	PN_BOTH_CORES_RUNNING, scr2;	/* we want both...   */	\
	stxa	scr2, [scr1]ASI_CMP_SHARED;	/* ...cores running. */	\
	membar	#Sync;							\
1:

/*
 * Cheetah+ and Jaguar get both primary and secondary AFSR/AFAR.  All bits
 * in the primary AFSR are cleared except the fatal error bits.  For Panther,
 * we also have to read and clear the AFSR_EXT, again leaving the fatal
 * error bits alone.
 *	datap:		pointer to cpu logout structure.
 *	afar:		returned primary AFAR value.
 *	scr1:		scratch
 *	scr2:		scratch
 */
#define	GET_AFSR_AFAR(datap, afar, scr1, scr2)				\
	set	ASI_SHADOW_REG_VA, scr1;				\
	ldxa	[scr1]ASI_AFAR, scr2;					\
	stxa	scr2, [datap + (CH_CLO_SDW_DATA + CH_CHD_AFAR)]%asi;	\
	ldxa	[scr1]ASI_AFSR, scr2;					\
	stxa	scr2, [datap + (CH_CLO_SDW_DATA + CH_CHD_AFSR)]%asi;	\
	ldxa	[%g0]ASI_AFAR, afar;					\
	stxa	afar, [datap + (CH_CLO_DATA + CH_CHD_AFAR)]%asi;	\
	ldxa	[%g0]ASI_AFSR, scr2;					\
	stxa	scr2, [datap + (CH_CLO_DATA + CH_CHD_AFSR)]%asi;	\
	sethi	%hh(C_AFSR_FATAL_ERRS), scr1;				\
	sllx	scr1, 32, scr1;						\
	bclr	scr1, scr2;	/* Clear fatal error bits here, so */ 	\
	stxa	scr2, [%g0]ASI_AFSR; /* they're left as is in AFSR */	\
	membar	#Sync;							\
	GET_CPU_IMPL(scr1);						\
	cmp	scr1, PANTHER_IMPL;					\
	bne	%xcc, 1f;						\
	   nop;								\
	set	ASI_SHADOW_AFSR_EXT_VA, scr1;	/* shadow AFSR_EXT */	\
	ldxa	[scr1]ASI_AFSR, scr2;					\
	stxa	scr2, [datap + (CH_CLO_SDW_DATA + CH_CHD_AFSR_EXT)]%asi; \
	set	ASI_AFSR_EXT_VA, scr1;		/* primary AFSR_EXT */	\
	ldxa	[scr1]ASI_AFSR, scr2;					\
	stxa	scr2, [datap + (CH_CLO_DATA + CH_CHD_AFSR_EXT)]%asi;	\
	set	C_AFSR_EXT_FATAL_ERRS, scr1;				\
	bclr	scr1, scr2;	/* Clear fatal error bits here, */	\
	set	ASI_AFSR_EXT_VA, scr1;	/* so they're left */		\
	stxa	scr2, [scr1]ASI_AFSR;	/* as is in AFSR_EXT */		\
	membar	#Sync;							\
1:

/*
 * This macro is used in the CPU logout code to capture diagnostic
 * information from the L2 cache on panther processors.
 *   afar:	input AFAR, not modified.
 *   datap:	Ptr to pn_l2_data_t, at end pts just past pn_l2_data_t.
 *   scr1:	Scratch.
 *   scr2:	Scratch.
 *   scr3:	Scratch.
 */
#define	GET_PN_L2_CACHE_DTAGS(afar, datap, scr1, scr2, scr3)		\
	mov	afar, scr3;						\
	set	PN_L2_INDEX_MASK, scr1;					\
	and	scr3, scr1, scr3;					\
	b	1f;	/* code to read tags and data should be ...  */	\
	   nop;		/* ...on the same cache line if possible.    */	\
	.align	128;	/* update this line if you add lines below. */	\
1:									\
	stxa	scr3, [datap + CH_EC_IDX]%asi;	/* store L2$ index  */	\
	ldxa	[scr3]ASI_L2_TAG, scr1;		/* read the L2$ tag */	\
	stxa	scr1, [datap + CH_EC_TAG]%asi;				\
	add	datap, CH_EC_DATA, datap;				\
	clr	scr1;							\
2:									\
	ldxa	[scr3 + scr1]ASI_L2_DATA, scr2;	/* loop through     */	\
	stxa	scr2, [datap]%asi;		/* <511:256> of L2  */	\
	add	datap, 8, datap;		/* data and record  */	\
	cmp	scr1, (PN_L2_LINESIZE / 2) - 8;	/* it in the cpu    */	\
	bne	2b;				/* logout struct.   */	\
	  add	scr1, 8, scr1;						\
	set	PN_L2_DATA_ECC_SEL, scr2;	/* ECC_sel bit.     */	\
	ldxa	[scr3 + scr2]ASI_L2_DATA, scr2;	/* Read and record  */	\
	stxa	scr2, [datap]%asi;		/* ecc of <511:256> */	\
	add	datap, 8, datap;					\
3:									\
	ldxa	[scr3 + scr1]ASI_L2_DATA, scr2;	/* loop through     */	\
	stxa	scr2, [datap]%asi;		/* <255:0> of L2    */	\
	add	datap, 8, datap;		/* data and record  */	\
	cmp	scr1, PN_L2_LINESIZE - 8;	/* it in the cpu    */	\
	bne	3b;				/* logout struct.   */	\
	  add	scr1, 8, scr1;						\
	set	PN_L2_DATA_ECC_SEL, scr2;	/* ECC_sel bit.     */	\
	add	scr2, PN_L2_ECC_LO_REG, scr2;				\
	ldxa	[scr3 + scr2]ASI_L2_DATA, scr2;	/* Read and record  */	\
	stxa	scr2, [datap]%asi;		/* ecc of <255:0>.  */	\
	add	datap, 8, datap;		/* Advance pointer  */	\
	set	PN_L2_SET_SIZE, scr2;					\
	set	PN_L2_MAX_SET, scr1;					\
	cmp	scr1, scr3;	/* more ways to try for this line? */	\
	bg,a	%xcc, 1b;	/* if so, start over with next way */	\
	  add	scr3, scr2, scr3

/*
 * Cheetah+ assumes E$ is 2-way and grabs both E$ lines associated with afar.
 *	afar:	AFAR from access.
 *	datap:	pointer to cpu logout structure.
 *	scr1:	scratch
 *	scr2:	scratch
 *	scr3:	scratch
 */
#define	GET_ECACHE_DTAGS(afar, datap, scr1, scr2, scr3)			\
	GET_CPU_IMPL(scr1);						\
	cmp	scr1, PANTHER_IMPL;					\
	bne	%xcc, 4f;						\
	  nop;								\
	GET_ECACHE_DTAG(afar, datap, 0, scr1, scr2, scr3);		\
	GET_ECACHE_DTAG(afar, datap, 1, scr1, scr2, scr3);		\
	GET_ECACHE_DTAG(afar, datap, 2, scr1, scr2, scr3);		\
	GET_ECACHE_DTAG(afar, datap, 3, scr1, scr2, scr3);		\
	add	datap, (CHD_EC_DATA_SETS-4)*CH_EC_DATA_SIZE, datap;	\
	GET_PN_L2_CACHE_DTAGS(afar, datap, scr1, scr2, scr3);		\
	b	5f;							\
	  nop;								\
4:									\
	GET_ECACHE_DTAG(afar, datap, 0, scr1, scr2, scr3);		\
	GET_ECACHE_WAY_BIT(scr1, scr2);					\
	xor	afar, scr1, afar;					\
	GET_ECACHE_DTAG(afar, datap, 0, scr1, scr2, scr3);		\
	GET_ECACHE_WAY_BIT(scr1, scr2);		/* restore AFAR */	\
	xor	afar, scr1, afar;					\
	add	datap, (CHD_EC_DATA_SETS-2)*CH_EC_DATA_SIZE, datap;	\
	add	datap, CH_EC_DATA_SIZE * PN_L2_NWAYS, datap;		\
5:

/*
 * Cheetah+ needs to capture E$, D$ and I$ lines associated with
 * shadow afar.
 *	afar:	scratch, holds shadow afar.
 *	datap:	pointer to cpu logout structure
 *	scr1:	scratch
 *	scr2:	scratch
 *	scr3:	scratch
 */
#define	GET_SHADOW_DATA(afar, datap, scr1, scr2, scr3)		\
	ldxa	[datap + (CH_CLO_SDW_DATA + CH_CHD_AFAR)]%asi, afar;	\
	add	datap, CH_CLO_SDW_DATA + CH_CHD_EC_DATA, datap;	\
	GET_ECACHE_DTAGS(afar, datap, scr1, scr2, scr3);		\
	GET_DCACHE_DTAG(afar, datap, scr1, scr2, scr3);			\
	GET_ICACHE_DTAG(afar, datap, scr1, scr2, scr3);			\
	sub	datap, CH_CPU_LOGOUT_SIZE, datap

/*
 * Compute the "Way" bit for 2-way Ecache for Cheetah+.
 */
#define	GET_ECACHE_WAY_BIT(scr1, scr2)					\
	CPU_INDEX(scr1, scr2);						\
	mulx	scr1, CPU_NODE_SIZE, scr1;				\
	add	scr1, ECACHE_SIZE, scr1;				\
	set	cpunodes, scr2;						\
	ld	[scr1 + scr2], scr1;					\
	srlx	scr1, 1, scr1

#else /* CHEETAH_PLUS */
/*
 * Macro version of get_ecache_dtag.  We use this macro in the
 * CPU logout code.
 *   afar:	input AFAR, not modified.
 *   datap:	Ptr to ch_ec_data_t, at end pts just past ch_ec_data_t.
 *   scr1:      Scratch.
 *   scr2:	Scratch.
 *   scr3:	Scratch.
 */
#define	GET_ECACHE_DTAG(afar, datap, scr1, scr2, scr3)			\
	mov	afar, scr3;						\
	andn	scr3, (CH_ECACHE_SUBBLK_SIZE - 1), scr3; /* VA<5:0>=0 */\
	set	(CH_ECACHE_8M_SIZE - 1), scr2;				\
	and	scr3, scr2, scr3;		/* VA<63:23>=0 */	\
	b	1f;							\
	   stxa	scr3, [datap + CH_EC_IDX]%asi;	/* store E$ index */	\
	.align	64;							\
1:									\
	ldxa    [scr3]ASI_EC_DIAG, scr1;	/* get E$ tag */	\
	stxa	scr1, [datap + CH_EC_TAG]%asi;				\
	add	datap, CH_EC_DATA, datap;				\
2:									\
	ldxa	[scr3]ASI_EC_R, %g0;		/* ld E$ stging regs */	\
	clr	scr1;							\
3:						/* loop thru 5 regs */	\
	ldxa	[scr1]ASI_EC_DATA, scr2;				\
	stxa	scr2, [datap]%asi;					\
	add	datap, 8, datap;					\
	cmp	scr1, CH_ECACHE_STGREG_TOTALSIZE - 8;			\
	bne	3b;							\
	   add	scr1, 8, scr1;						\
	btst	CH_ECACHE_STGREG_SIZE, scr3;	/* done? */		\
	beq	2b;							\
	   add	scr3, CH_ECACHE_STGREG_SIZE, scr3

/*
 * Cheetah does not have cores so these macros are null.
 */
#define	PARK_SIBLING_CORE(dcucr_reg, scr1, scr2)
#define	UNPARK_SIBLING_CORE(dcucr_reg, scr1, scr2)

/*
 * Cheetah gets primary AFSR and AFAR and clears the AFSR, except for the
 * fatal error bits.
 *	datap:		pointer to cpu logout structure.
 *	afar:		returned primary AFAR value.
 *	scr1:		scratch
 *	scr2:		scratch
 */
#define	GET_AFSR_AFAR(datap, afar, scr1, scr2)	\
	ldxa	[%g0]ASI_AFAR, afar;					\
	stxa	afar, [datap + (CH_CLO_DATA + CH_CHD_AFAR)]%asi;	\
	ldxa	[%g0]ASI_AFSR, scr2;					\
	stxa	scr2, [datap + (CH_CLO_DATA + CH_CHD_AFSR)]%asi;	\
	sethi	%hh(C_AFSR_FATAL_ERRS), scr1;				\
	sllx	scr1, 32, scr1;						\
	bclr	scr1, scr2;	/* Clear fatal error bits here, so */	\
	stxa	scr2, [%g0]ASI_AFSR; /* they're left as is in AFSR */	\
	membar	#Sync

/*
 * Cheetah E$ is direct-mapped, so we grab line data and skip second line.
 *	afar:	AFAR from access.
 *	datap:	pointer to cpu logout structure.
 *	scr1:	scratch
 *	scr2:	scratch
 *	scr3:	scratch
 */
#define	GET_ECACHE_DTAGS(afar, datap, scr1, scr2, scr3)			\
	GET_ECACHE_DTAG(afar, datap, scr1, scr2, scr3);			\
	add	datap, (CHD_EC_DATA_SETS-1)*CH_EC_DATA_SIZE, datap;	\
	add	datap, CH_EC_DATA_SIZE * PN_L2_NWAYS, datap;		\

/*
 * Cheetah has no shadow AFAR, null operation.
 */
#define	GET_SHADOW_DATA(afar, datap, scr1, scr2, scr3)

#endif	/* CHEETAH_PLUS */

/*
 * Cheetah/(Cheetah+ Jaguar Panther)/Jalapeno Macro for capturing CPU
 * logout data at TL>0. r_val is a register that returns the "failure count"
 * to the caller, and may be used as a scratch register until the end of
 * the macro.  afar is used to return the primary AFAR value to the caller
 * and it too can be used as a scratch register until the end. r_or_s is
 * a reg or symbol that has the offset within the "cpu_private" data area
 * to deposit the logout data.  t_flags is a register that has the
 * trap-type/trap-level/CEEN info. This t_flags register may be used after
 * the GET_AFSR_AFAR macro.
 *
 * The CPU logout operation will fail (r_val > 0) if the logout
 * structure in question is already being used. Otherwise, the CPU
 * logout operation will succeed (r_val = 0). For failures, r_val
 * returns the busy count (# of times we tried using this CPU logout
 * structure when it was busy.)
 *
 *   Register usage:
 *	%asi:   Must be set to either ASI_MEM if the address in datap
 *		is a physical address or to ASI_N if the address in
 *		datap is a virtual address.
 *	r_val:	This register is the return value which tells the
 *		caller whether or not the LOGOUT operation was successful.
 *		For failures, r_val returns the fail count (i.e. number of
 *		times we have tried to use this logout structure when it was
 *		already being used.
 *	afar:	output: contains AFAR on exit
 *	t_flags: input trap type info, may be used as scratch after stored
 *		to cpu log out structure.
 *	datap:	Points to log out data area.
 *	scr1:	Scratch
 *	scr2:	Scratch (may be r_val)
 *	scr3:   Scratch (may be t_flags)
 */
#define	DO_TL1_CPU_LOGOUT(r_val, afar, t_flags, datap, scr1, scr2, scr3) \
	setx	LOGOUT_INVALID, scr2, scr1;				\
	ldxa	[datap + (CH_CLO_DATA + CH_CHD_AFAR)]%asi, scr2;	\
	cmp	scr2, scr1;						\
	bne	8f;							\
	  nop;								\
	stxa	t_flags, [datap + CH_CLO_FLAGS]%asi;			\
	GET_AFSR_AFAR(datap, afar, scr1, scr2);				\
	add	datap, CH_CLO_DATA + CH_CHD_EC_DATA, datap;		\
	GET_ECACHE_DTAGS(afar, datap, scr1, scr2, scr3);		\
	GET_DCACHE_DTAG(afar, datap, scr1, scr2, scr3);			\
	GET_ICACHE_DTAG(afar, datap, scr1, scr2, scr3);			\
	sub	datap, CH_CLO_DATA + CH_DIAG_DATA_SIZE, datap;		\
	GET_SHADOW_DATA(afar, datap, scr1, scr2, scr3);			\
	ldxa	[datap + (CH_CLO_DATA + CH_CHD_AFAR)]%asi, afar;	\
	set	0, r_val;	/* return value for success */		\
	ba	9f;							\
	  nop;								\
8:									\
	ldxa	[%g0]ASI_AFAR, afar;					\
	ldxa	[datap + CH_CLO_NEST_CNT]%asi, r_val;			\
	inc	r_val;		/* return value for failure */		\
	stxa	r_val, [datap + CH_CLO_NEST_CNT]%asi;			\
	membar	#Sync;							\
9:

/*
 * Cheetah/(Cheetah+ Jaguar Panther)/Jalapeno Macro for capturing CPU
 * logout data.  Uses DO_TL1_CPU_LOGOUT macro defined above, and sets
 * up the expected data pointer in the scr1 register and sets the %asi
 * register to ASI_N for kernel virtual addresses instead of ASI_MEM as
 * is used at TL>0.
 *
 * The CPU logout operation will fail (r_val > 0) if the logout
 * structure in question is already being used. Otherwise, the CPU
 * logout operation will succeed (r_val = 0). For failures, r_val
 * returns the busy count (# of times we tried using this CPU logout
 * structure when it was busy.)
 *
 *   Register usage:
 *	r_val:	This register is the return value which tells the
 *		caller whether or not the LOGOUT operation was successful.
 *		For failures, r_val returns the fail count (i.e. number of
 *		times we have tried to use this logout structure when it was
 *		already being used.
 *	afar:	returns AFAR, used internally as afar value.
 *		output: if the cpu_private struct has not been initialized,
 *		        then we return the t_flags value listed below.
 *	r_or_s:	input offset, either register or constant (symbol).  It's
 *		OK for r_or_s to be a register as long as it's not scr1 or
 *		scr3.
 *	t_flags: input trap type info, may be used as scratch after stored
 *		to cpu log out structure.
 *	scr1:	Scratch, points to log out data area.
 *	scr2:	Scratch (may be r_or_s)
 *	scr3:	Scratch (may be r_val)
 *	scr4:   Scratch (may be t_flags)
 */
#define	DO_CPU_LOGOUT(r_val, afar, r_or_s, t_flags, scr1, scr2, scr3, scr4) \
	GET_CPU_PRIVATE_PTR(r_or_s, scr1, scr3, 7f); /* can't use scr2/4 */ \
	wr	%g0, ASI_N, %asi;					\
	DO_TL1_CPU_LOGOUT(r_val, afar, t_flags, scr1, scr2, scr3, scr4)	\
	ba	6f;							\
	  nop;								\
7:									\
	mov	t_flags, afar;		/* depends on afar = %g2  */	\
	set	0, r_val;		/* success in this case.  */	\
6:

/*
 * The P$ is flushed as a side effect of writing to the Primary
 * or Secondary Context Register. After writing to a context
 * register, every line of the P$ in the Valid state is invalidated,
 * regardless of which context it belongs to.
 * This routine simply touches the Primary context register by
 * reading the current value and writing it back. The Primary
 * context is not changed.
 */
#define	PCACHE_FLUSHALL(tmp1, tmp2, tmp3)				\
	sethi	%hi(FLUSH_ADDR), tmp1					;\
	set	MMU_PCONTEXT, tmp2					;\
	ldxa	[tmp2]ASI_DMMU, tmp3					;\
	stxa	tmp3, [tmp2]ASI_DMMU					;\
	flush	tmp1	/* See Cheetah PRM 8.10.2 */

/*
 * Macro that flushes the entire Dcache.
 *
 * arg1 = dcache size
 * arg2 = dcache linesize
 */
#define	CH_DCACHE_FLUSHALL(arg1, arg2, tmp1)				\
	sub	arg1, arg2, tmp1;					\
1:									\
	stxa	%g0, [tmp1]ASI_DC_TAG;					\
	membar	#Sync;							\
	cmp	%g0, tmp1;						\
	bne,pt	%icc, 1b;						\
	  sub	tmp1, arg2, tmp1;

/*
 * Macro that flushes the entire Icache.
 *
 * Note that we cannot access ASI 0x67 (ASI_IC_TAG) with the Icache on,
 * because accesses to ASI 0x67 interfere with Icache coherency.  We
 * must make sure the Icache is off, then turn it back on after the entire
 * cache has been invalidated.  If the Icache is originally off, we'll just
 * clear the tags but not turn the Icache on.
 *
 * arg1 = icache size
 * arg2 = icache linesize
 */
#define	CH_ICACHE_FLUSHALL(arg1, arg2, tmp1, tmp2)			\
	ldxa	[%g0]ASI_DCU, tmp2;					\
	andn	tmp2, DCU_IC, tmp1;					\
	stxa	tmp1, [%g0]ASI_DCU;					\
	flush	%g0;	/* flush required after changing the IC bit */	\
	sllx	arg2, 1, arg2;		/* arg2 = linesize * 2 */	\
	sllx	arg1, 1, arg1;		/* arg1 = size * 2 */		\
	sub	arg1, arg2, arg1;					\
	or	arg1, CH_ICTAG_LOWER, arg1;	/* "write" tag */	\
1:									\
	stxa	%g0, [arg1]ASI_IC_TAG;					\
	membar	#Sync;				/* Cheetah PRM 8.9.3 */	\
	cmp	arg1, CH_ICTAG_LOWER;					\
	bne,pt	%icc, 1b;						\
	  sub	arg1, arg2, arg1;					\
	stxa	tmp2, [%g0]ASI_DCU;					\
	flush	%g0;	/* flush required after changing the IC bit */


#if defined(JALAPENO) || defined(SERRANO)

/*
 * ASI access to the L2 tag or L2 flush can hang the cpu when interacting
 * with combinations of L2 snoops, victims and stores.
 *
 * A possible workaround is to surround each L2 ASI access with membars
 * and make sure that the code is hitting in the Icache.  This requires
 * aligning code sequence at E$ boundary and forcing I$ fetch by
 * jumping to selected offsets so that we don't take any I$ misses
 * during ASI access to the L2 tag or L2 flush.  This also requires
 * making sure that we don't take any interrupts or traps (such as
 * fast ECC trap, I$/D$ tag parity error) which can result in eviction
 * of this code sequence from I$, thus causing a miss.
 *
 * Because of the complexity/risk, we have decided to do a partial fix
 * of adding membar around each ASI access to the L2 tag or L2 flush.
 */

#define	JP_EC_DIAG_ACCESS_MEMBAR	\
	membar	#Sync

/*
 * Jalapeno version of macro that flushes the entire Ecache.
 *
 * Uses Jalapeno displacement flush feature of ASI_EC_DIAG.
 *
 * arg1 = ecache size
 * arg2 = ecache linesize - not modified; can be an immediate constant.
 */
#define	ECACHE_FLUSHALL(arg1, arg2, tmp1, tmp2)	\
	CPU_INDEX(tmp1, tmp2);						\
	set	JP_ECACHE_IDX_DISP_FLUSH, tmp2;				\
	sllx	tmp1, JP_ECFLUSH_PORTID_SHIFT, tmp1;			\
	or	tmp1, tmp2, tmp1;					\
	srlx	arg1, JP_EC_TO_SET_SIZE_SHIFT, tmp2;			\
1:									\
	subcc	tmp2, arg2, tmp2;					\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	ldxa	[tmp1 + tmp2]ASI_EC_DIAG, %g0;				\
	JP_EC_DIAG_ACCESS_MEMBAR;					\
	bg,pt	%xcc, 1b;						\
	  nop;								\
	mov	1, tmp2;						\
	sllx	tmp2, JP_ECFLUSH_EC_WAY_SHIFT, tmp2;			\
	add	tmp1, tmp2, tmp1;					\
	mov	(JP_ECACHE_NWAY-1), tmp2;				\
	sllx	tmp2, JP_ECFLUSH_EC_WAY_SHIFT, tmp2;			\
	andcc	tmp1, tmp2, tmp2;					\
	bnz,pt	%xcc, 1b;						\
	  srlx	arg1, JP_EC_TO_SET_SIZE_SHIFT, tmp2

#else	/* JALAPENO || SERRANO */

/*
 * Cheetah version of macro that flushes the entire Ecache.
 *
 *  Need to displacement flush 2x ecache size from Ecache flush area.
 *
 * arg1 = ecache size
 * arg2 = ecache linesize
 * arg3 = ecache flush address - for cheetah only
 */
#define	CH_ECACHE_FLUSHALL(arg1, arg2, arg3)				\
	sllx	arg1, 1, arg1;						\
1:									\
	subcc	arg1, arg2, arg1;					\
	bg,pt	%xcc, 1b;						\
	  ldxa	[arg1 + arg3]ASI_MEM, %g0;

/*
 * Cheetah+ version of macro that flushes the entire Ecache.
 *
 * Uses the displacement flush feature.
 *
 * arg1 = ecache size
 * arg2 = ecache linesize
 * impl = CPU implementation as returned from GET_CPU_IMPL()
 *        The value in this register is destroyed during execution
 *        of the macro.
 */
#if defined(CHEETAH_PLUS)
#define	CHP_ECACHE_FLUSHALL(arg1, arg2, impl)				\
	cmp	impl, PANTHER_IMPL;					\
	bne	%xcc, 1f;						\
	  nop;								\
	set	PN_L3_IDX_DISP_FLUSH, impl;				\
	b	2f;							\
	  nop;								\
1:									\
	set	CHP_ECACHE_IDX_DISP_FLUSH, impl;			\
2:									\
	subcc	arg1, arg2, arg1;					\
	bg,pt	%xcc, 2b;						\
	  ldxa	[arg1 + impl]ASI_EC_DIAG, %g0;
#else	/* CHEETAH_PLUS */
#define	CHP_ECACHE_FLUSHALL(arg1, arg2, impl)
#endif	/* CHEETAH_PLUS */

/*
 * Macro that flushes the entire Ecache.
 *
 * arg1 = ecache size
 * arg2 = ecache linesize
 * arg3 = ecache flush address - for cheetah only
 */
#define	ECACHE_FLUSHALL(arg1, arg2, arg3, tmp1)				\
	GET_CPU_IMPL(tmp1);						\
	cmp	tmp1, CHEETAH_IMPL;					\
	bne	%xcc, 2f;						\
	  nop;								\
	CH_ECACHE_FLUSHALL(arg1, arg2, arg3);				\
	ba	3f;							\
	  nop;								\
2:									\
	CHP_ECACHE_FLUSHALL(arg1, arg2, tmp1);				\
3:

#endif	/* JALAPENO || SERRANO */

/*
 * Macro that flushes the Panther L2 cache.
 */
#if defined(CHEETAH_PLUS)
#define	PN_L2_FLUSHALL(scr1, scr2, scr3)				\
	GET_CPU_IMPL(scr3);						\
	cmp	scr3, PANTHER_IMPL;					\
	bne	%xcc, 2f;						\
	  nop;								\
	set	PN_L2_SIZE, scr1;					\
	set	PN_L2_LINESIZE, scr2;					\
	set	PN_L2_IDX_DISP_FLUSH, scr3;				\
1:									\
	subcc	scr1, scr2, scr1;					\
	bg,pt	%xcc, 1b;						\
	  ldxa	[scr1 + scr3]ASI_L2_TAG, %g0;				\
2:
#else	/* CHEETAH_PLUS */
#define	PN_L2_FLUSHALL(scr1, scr2, scr3)
#endif	/* CHEETAH_PLUS */

/*
 * Given a VA and page size (page size as encoded in ASI_MMU_TAG_ACCESS_EXT),
 * this macro returns the TLB index for that mapping based on a 512 entry
 * (2-way set associative) TLB. Aaside from the 16 entry fully associative
 * TLBs, all TLBs in Panther are 512 entry, 2-way set associative.
 *
 * To find the index, we shift the VA right by 13 + (3 * pg_sz) and then
 * mask out all but the lower 8 bits because:
 *
 *    ASI_[D|I]MMU_TAG_ACCESS_EXT.PgSz = 0 for   8K
 *    ASI_[D|I]MMU_TAG_ACCESS_EXT.PgSz = 1 for  64K
 *    ASI_[D|I]MMU_TAG_ACCESS_EXT.PgSz = 2 for 512K
 *    ASI_[D|I]MMU_TAG_ACCESS_EXT.PgSz = 3 for   4M
 *    ASI_[D|I]MMU_TAG_ACCESS_EXT.PgSz = 4 for  32M
 *    ASI_[D|I]MMU_TAG_ACCESS_EXT.PgSz = 5 for 256M
 *
 * and
 *
 *    array index for   8K pages = VA[20:13]
 *    array index for  64K pages = VA[23:16]
 *    array index for 512K pages = VA[26:19]
 *    array index for   4M pages = VA[29:22]
 *    array index for  32M pages = VA[32:25]
 *    array index for 256M pages = VA[35:28]
 *
 * Inputs:
 *
 *    va	- Register.
 *		  Input: Virtual address in which we are interested.
 *		  Output: TLB index value.
 *    pg_sz	- Register. Page Size of the TLB in question as encoded
 *		  in the ASI_[D|I]MMU_TAG_ACCESS_EXT register.
 */
#if defined(CHEETAH_PLUS)
#define	PN_GET_TLB_INDEX(va, pg_sz)					\
	srlx	va, 13, va;	/* first shift the 13 bits and then */	\
	srlx	va, pg_sz, va;	/* shift by pg_sz three times. */	\
	srlx	va, pg_sz, va;						\
	srlx	va, pg_sz, va;						\
	and	va, 0xff, va;	/* mask out all but the lower 8 bits */
#endif	/* CHEETAH_PLUS */

/*
 * The following macros are for error traps at TL>0.
 * The issue with error traps at TL>0 is that there are no safely
 * available global registers.  So we use the trick of generating a
 * software trap, then using the %tpc, %tnpc and %tstate registers to
 * temporarily save the values of %g1 and %g2.
 */

/*
 * Macro to generate 8-instruction trap table entry for TL>0 trap handlers.
 * Does the following steps:
 *	1. membar #Sync - required for USIII family errors.
 *	2. Specified software trap.
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */
#define	CH_ERR_TL1_TRAPENTRY(trapno)		\
	membar	#Sync;				\
	ta	trapno;				\
	nop; nop; nop; nop; nop; nop

/*
 * Macro to generate 8-instruction trap table entry for TL>0 software trap.
 * We save the values of %g1 and %g2 in %tpc, %tnpc and %tstate (since
 * the low-order two bits of %tpc/%tnpc are reserved and read as zero,
 * we need to put the low-order two bits of %g1 and %g2 in %tstate).
 * Note that %tstate has a reserved hole from bits 3-7, so we put the
 * low-order two bits of %g1 in bits 0-1 and the low-order two bits of
 * %g2 in bits 10-11 (insuring bits 8-9 are zero for use by the D$/I$
 * state bits).  Note that we must do a jmp instruction, since this
 * is moved into the trap table entry.
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */
#define	CH_ERR_TL1_SWTRAPENTRY(label)		\
	wrpr	%g1, %tpc;			\
	and	%g1, 3, %g1;			\
	wrpr	%g2, %tnpc;			\
	sllx	%g2, CH_ERR_G2_TO_TSTATE_SHFT, %g2; \
	or	%g1, %g2, %g2;			\
	sethi	%hi(label), %g1;		\
	jmp	%g1+%lo(label);			\
	  wrpr	%g2, %tstate

/*
 * Macro to get ptr to ch_err_tl1_data.
 * reg1 will either point to a physaddr with ASI_MEM in %asi OR it
 * will point to a kernel nucleus virtual address with ASI_N in %asi.
 * This allows us to:
 *   1. Avoid getting MMU misses.  We may have gotten the original
 *	Fast ECC error in an MMU handler and if we get an MMU trap
 *	in the TL>0 handlers, we'll scribble on the MMU regs.
 *   2. Allows us to use the same code in the TL>0 handlers whether
 *	we're accessing kernel nucleus virtual addresses or physical
 *	addresses.
 * pseudo-code:
 *	reg1 <- ch_err_tl1_paddrs[CPUID];
 *	if (reg1 == NULL) {
 *		reg1 <- &ch_err_tl1_data
 *		%asi <- ASI_N
 *	} else {
 *		reg1 <- reg1 + offset +
 *		    sizeof (ch_err_tl1_data) * (%tl - 3)
 *		%asi <- ASI_MEM
 *	}
 */
#define	GET_CH_ERR_TL1_PTR(reg1, reg2, offset)	\
	CPU_INDEX(reg1, reg2);			\
	sllx	reg1, 3, reg1;			\
	set	ch_err_tl1_paddrs, reg2;	\
	ldx	[reg1+reg2], reg1;		\
	brnz	reg1, 1f;			\
	add	reg1, offset, reg1;		\
	set	ch_err_tl1_data, reg1;		\
	ba	2f;				\
	wr	%g0, ASI_N, %asi;		\
1:	rdpr	%tl, reg2;			\
	sub	reg2, 3, reg2;			\
	mulx	reg2, CH_ERR_TL1_DATA_SIZE, reg2;	\
	add	reg1, reg2, reg1;		\
	wr	%g0, ASI_MEM, %asi;		\
2:

/*
 * Macro to generate entry code for TL>0 error handlers.
 * At the end of this macro, %g1 will point to the ch_err_tl1_data
 * structure and %g2 will have the original flags in the ch_err_tl1_data
 * structure and %g5 will have the value of %tstate where the Fast ECC
 * routines will save the state of the D$ in Bit2 CH_ERR_TSTATE_DC_ON.
 * All %g registers except for %g1, %g2 and %g5 will be available after
 * this macro.
 * Does the following steps:
 *   1. Compute physical address of per-cpu/per-tl save area using
 *	only %g1+%g2 (which we've saved in %tpc, %tnpc, %tstate)
 *	leaving address in %g1 and updating the %asi register.
 *	If there is no data area available, we branch to label.
 *   2. Save %g3-%g7 in save area.
 *   3. Save %tpc->%g3, %tnpc->%g4, %tstate->%g5, which contain
 *	original %g1+%g2 values (because we're going to change %tl).
 *   4. set %tl <- %tl - 1.  We do this ASAP to make window of
 *	running at %tl+1 as small as possible.
 *   5. Reconstitute %g1+%g2 from %tpc (%g3), %tnpc (%g4),
 *	%tstate (%g5) and save in save area, carefully preserving %g5
 *	because it has the CH_ERR_TSTATE_DC_ON value.
 *   6. Load existing ch_err_tl1_data flags in %g2
 *   7. Compute the new flags
 *   8. If %g2 is non-zero (the structure was busy), shift the new
 *	flags by CH_ERR_ME_SHIFT and or them with the old flags.
 *   9. Store the updated flags into ch_err_tl1_data flags.
 *   10. If %g2 is non-zero, read the %tpc and store it in
 *	ch_err_tl1_data.
 */
#define	CH_ERR_TL1_ENTER(flags)			\
	GET_CH_ERR_TL1_PTR(%g1, %g2, CHPR_TL1_ERR_DATA);	\
	stxa	%g3, [%g1 + CH_ERR_TL1_G3]%asi;	\
	stxa	%g4, [%g1 + CH_ERR_TL1_G4]%asi;	\
	stxa	%g5, [%g1 + CH_ERR_TL1_G5]%asi;	\
	stxa	%g6, [%g1 + CH_ERR_TL1_G6]%asi;	\
	stxa	%g7, [%g1 + CH_ERR_TL1_G7]%asi;	\
	rdpr	%tpc, %g3;			\
	rdpr	%tnpc, %g4;			\
	rdpr	%tstate, %g5;			\
	rdpr	%tl, %g6;			\
	sub	%g6, 1, %g6;			\
	wrpr	%g6, %tl;			\
	and	%g5, 3, %g6;			\
	andn	%g3, 3, %g3;			\
	or	%g3, %g6, %g3;			\
	stxa	%g3, [%g1 + CH_ERR_TL1_G1]%asi;	\
	srlx	%g5, CH_ERR_G2_TO_TSTATE_SHFT, %g6;	\
	and	%g6, 3, %g6;			\
	andn	%g4, 3, %g4;			\
	or	%g6, %g4, %g4;			\
	stxa	%g4, [%g1 + CH_ERR_TL1_G2]%asi;	\
	ldxa	[%g1 + CH_ERR_TL1_FLAGS]%asi, %g2;	\
	set	flags | CH_ERR_TL, %g3;		\
	brz	%g2, 9f;			\
	sllx	%g3, CH_ERR_ME_SHIFT, %g4;	\
	or	%g2, %g4, %g3;			\
9:	stxa	%g3, [%g1 + CH_ERR_TL1_FLAGS]%asi;	\
	brnz	%g2, 8f;			\
	rdpr	%tpc, %g4;			\
	stxa	%g4, [%g1 + CH_ERR_TL1_TPC]%asi;	\
8:

/*
 * Turns off D$/I$ and saves the state of DCU_DC+DCU_IC in %tstate Bits 8+9
 * (CH_ERR_TSTATE_DC_ON/CH_ERR_TSTATE_IC_ON).  This is invoked on Fast ECC
 * at TL>0 handlers because the D$ may have corrupted data and we need to
 * turn off the I$ to allow for diagnostic accesses.  We then invoke
 * the normal entry macro and after it is done we save the values of
 * the original D$/I$ state, which is in %g5 bits CH_ERR_TSTATE_DC_ON/
 * CH_ERR_TSTATE_IC_ON in ch_err_tl1_tmp.
 */
#define	CH_ERR_TL1_FECC_ENTER			\
	ldxa	[%g0]ASI_DCU, %g1;		\
	andn	%g1, DCU_DC + DCU_IC, %g2;	\
	stxa	%g2, [%g0]ASI_DCU;		\
	flush	%g0;	/* DCU_IC need flush */	\
	rdpr	%tstate, %g2;			\
	and	%g1, DCU_DC + DCU_IC, %g1;	\
	sllx	%g1, CH_ERR_DCU_TO_TSTATE_SHFT, %g1;	\
	or	%g1, %g2, %g2;			\
	wrpr	%g2, %tstate;			\
	CH_ERR_TL1_ENTER(CH_ERR_FECC);		\
	and	%g5, CH_ERR_TSTATE_DC_ON + CH_ERR_TSTATE_IC_ON, %g5;	\
	stxa	%g5, [%g1 + CH_ERR_TL1_TMP]%asi

/*
 * Macro to generate exit code for TL>0 error handlers.
 * We fall into this macro if we've successfully logged the error in
 * the ch_err_tl1_data structure and want the PIL15 softint to pick
 * it up and log it.
 * Does the following steps:
 *   1.	Set pending flag for this cpu in ch_err_tl1_pending.
 *   2.	Write %set_softint with (1<<pil) to cause a pil level trap
 *   3.	Restore registers from ch_err_tl1_data, which is pointed to
 *	by %g1, last register to restore is %g1 since it's pointing
 *	to the save area.
 *   4. Execute retry
 */
#define	CH_ERR_TL1_EXIT				\
	CPU_INDEX(%g2, %g3);			\
	set	ch_err_tl1_pending, %g3;	\
	set	-1, %g4;			\
	stb	%g4, [%g2 + %g3];		\
	mov	1, %g2;				\
	sll	%g2, PIL_15, %g2;		\
	wr	%g2, SET_SOFTINT;		\
	ldxa	[%g1 + CH_ERR_TL1_G7]%asi, %g7;	\
	ldxa	[%g1 + CH_ERR_TL1_G6]%asi, %g6;	\
	ldxa	[%g1 + CH_ERR_TL1_G5]%asi, %g5;	\
	ldxa	[%g1 + CH_ERR_TL1_G4]%asi, %g4;	\
	ldxa	[%g1 + CH_ERR_TL1_G3]%asi, %g3;	\
	ldxa	[%g1 + CH_ERR_TL1_G2]%asi, %g2;	\
	ldxa	[%g1 + CH_ERR_TL1_G1]%asi, %g1;	\
	retry

/*
 * Generates unrecoverable error label for TL>0 handlers.
 * At label (Unrecoverable error routine)
 *   1. Sets flags in ch_err_tl1_data and leaves in %g2 (first
 *	argument to cpu_tl1_err_panic).
 *   2.	Call cpu_tl1_err_panic via systrap at PIL 15
 */
#define	CH_ERR_TL1_PANIC_EXIT(label)		\
label:	ldxa	[%g1 + CH_ERR_TL1_FLAGS]%asi, %g2;	\
	or	%g2, CH_ERR_TL | CH_ERR_PANIC, %g2;	\
	stxa	%g2, [%g1 + CH_ERR_TL1_FLAGS]%asi;	\
	set	cpu_tl1_err_panic, %g1;		\
	ba	sys_trap;			\
	  mov	PIL_15, %g4



/* END CSTYLED */
#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif /* _CHEETAHASM_H */
