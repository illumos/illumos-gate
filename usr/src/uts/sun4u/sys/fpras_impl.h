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
 */
/*
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FPRAS_IMPL_H
#define	_SYS_FPRAS_IMPL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/fpras.h>

#if !defined(_ASM)
#include <sys/types.h>
#else
#include <sys/intreg.h>
#include <sys/errno.h>
#endif	/* _ASM */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * sun4u/cheetah fpRAS implementation.  Arrays etc will be allocated in sun4u
 * post_startup() if fpras_implemented is set.  This file may belong at
 * the cpu level (eg, cheetahregs.h) but most of it should be common
 * when fpRAS support is added for additional cpu types so we introduce
 * it at the sun4u level (and set fpras_implemented in cpu_setup).
 *
 * If fpRAS is implemented on a sun4u/cpu combination that does not use
 * an ASR for %stick then the FPRAS_INTERVAL macro will need some
 * modification.
 */

/*
 * Upper bound for check frequency per cpu and per operation.  For example, if
 * this is 100 then for cpuid N performing a bcopy if that cpu has not
 * performed a checked bcopy in the the last 1/100th of a second then
 * we'll check the current operation.  A value of 0 will check every operation.
 * Modifying fpras_frequency from its default is not recommended.
 * fpras_interval is computed from fpras_frequency.
 */
#if !defined(_ASM)
extern int fpras_frequency;
extern int64_t fpras_interval;
#endif	/* _ASM */
#define	FPRAS_DEFAULT_FREQUENCY	100

#if !defined(_ASM)

/*
 * Structure of a check function.  The preamble prepares registers for the
 * upcoming calculation that is performed in blk0 and blk1.  One of those
 * blocks will be rewritten as part of an FPRAS_REWRITE operation.  Finally
 * the result checked in chkresult should be as predetermined, and we should
 * return zero on success and nonzero on failure.  If an illegal instruction
 * is encountered in the execution of the check function then we trampoline
 * to the final three instructions to return a different value.
 *
 * Note that the size of this structure is a power of 2 as is the
 * size of a struct fpras_chkfngrp.  The asm macros below rely on this
 * in performing bit shifts instead of mulx.
 */
struct fpras_chkfn {
	uint32_t	fpras_preamble[16];
	uint32_t	fpras_blk0[16];
	uint32_t	fpras_blk1[16];
	uint32_t	fpras_chkresult[13];
	uint32_t	fpras_trampoline[3];
};

/*
 * Check function constructed to match a struct fpras_chkfn
 */
extern int fpras_chkfn_type1(void);

/*
 * A group of check functions, one for each operation type.  These will
 * be the check functions for copy operations on a particular processor.
 */
struct fpras_chkfngrp {
	struct fpras_chkfn fpras_fn[FPRAS_NCOPYOPS];
};

/*
 * Where we store check functions for execution.  Indexed by cpuid and
 * function within that for cacheline friendliness.  Startup code
 * copies the check function into this array.  The fpRAS mechanism will
 * rewrite one of fpras_blk0 or fpras_blk1 before calling the check function
 * for a cpuid & copy function combination.
 */
extern struct fpras_chkfngrp *fpras_chkfngrps;

#endif	/* !_ASM */

#if defined(_ASM)

/* BEGIN CSTYLED */

/*
 * The INTERVAL macro decides whether we will check this copy operation,
 * based on performing no more than 1 check per cpu & operation in a specified
 * time interval.  If it decides to abort this check (ie, we have checked
 * recently) then it returns doex NULL, otherwise doex is the address of the
 * check function to execute later.  Migration must have been prevented before
 * calling this macro.  Args:
 *
 *	operation (immediate): one of FPRAS_BCOPY etc
 *	blk (immediate): which block to copy
 *	doex (register): register in which to return check function address
 *	tmp1 (register): used for scratch, not preserved
 *	tmp2 (register): used for scratch, not preserved
 *	tmp3 (register): used for scratch, not preserved
 *	tmp4 (register): used for scratch, not preserved
 *	label: free local numeric label
 */

#define	FPRAS_INTERVAL(operation, blk, doex, tmp1, tmp2, tmp3, tmp4, label) \
	sethi	%hi(fpras_interval), tmp1				;\
	ldx	[tmp1 + %lo(fpras_interval)], tmp1			;\
	brlz,pn	tmp1, label/**/f	/* not initialized? */		;\
	  clr	doex							;\
	sethi	%hi(fpras_disableids), tmp2				;\
	ld	[tmp2 + %lo(fpras_disableids)], tmp2			;\
	mov	0x1, tmp3						;\
	sll	tmp3, operation, tmp3					;\
	btst	tmp3, tmp2						;\
	bnz,a,pn %icc, label/**/f	/* disabled for this op? */	;\
	  nop								;\
	set	fpras_chkfn_type1, tmp2					;\
	prefetch [tmp2 + (FPRAS_BLK0 + blk * 64)], #one_read		;\
	ldn	[THREAD_REG + T_CPU], tmp2				;\
	ldn	[tmp2 + CPU_PRIVATE], tmp2				;\
	brz,pn	tmp2, label/**/f	/* early in startup? */		;\
	  mov	operation, tmp3						;\
	sll	tmp3, 3, tmp3						;\
	set	CHPR_FPRAS_TIMESTAMP, tmp4				;\
	add	tmp2, tmp4, tmp2					;\
	add	tmp2, tmp3, tmp2	/* keep ptr for update */	;\
	ldx	[tmp2], tmp3		/* last timestamp */		;\
	rd	STICK, doex		/* doex is a scratch here */	;\
	sub	doex, tmp3, tmp4	/* delta since last check */	;\
	cmp	tmp4, tmp1		/* compare delta to interval */	;\
	blu,a,pn %xcc, label/**/f					;\
	  clr	doex							;\
	stx	doex, [tmp2]		/* updated timestamp */		;\
	ldn	[THREAD_REG + T_CPU], tmp1				;\
	ld	[tmp1 + CPU_ID], tmp1					;\
	sethi	%hi(fpras_chkfngrps), doex				;\
	ldn	[doex + %lo(fpras_chkfngrps)], doex			;\
	sll	tmp1, FPRAS_CHKFNGRP_SIZE_SHIFT, tmp1			;\
	add	doex, tmp1, doex					;\
	mov	operation, tmp1						;\
	sll	tmp1, FPRAS_CHKFN_SIZE_SHIFT, tmp1			;\
	add	doex, tmp1, doex	/* address of check function */	;\
label:

/*
 * The REWRITE macro copies an instruction block from fpras_chkfn_type1
 * into a per-cpu fpras check function.
 * If doex is NULL it must not attempt any copy, and must leave doex NULL.
 * CPU migration of this thread must be prevented before we call this macro.
 * We must have checked for fp in use (and saved state, including the
 * quadrant of registers indicated by the fpq argument and fp enabled before
 * using this macro.  Args:
 *
 *	blk (immediate): as above
 *	doex (register): register in which to return check function addr
 *	[fpq (fp register): frf quadrant to be used (%f0/%f16/%f32/%f48)]
 *		This is used on type 1 rewrite only - on others the
 *		quadrant is implicit/hardcoded in the macro name.
 *	tmp1 (register): used for scratch, not preserved
 *	label1: free local numeric label
 *	[label2: free local numeric label]
 *		This is used in type 2 only.
 *
 * Note that the REWRITE macros do not perform a flush instruction -
 * flush is not necessary on Cheetah derivative processors in which
 * i$ snoops for invalidations.
 */

/*
 * Rewrite type 1 will work with any instruction pattern - it just block
 * loads and block stores the given block.  A membar after block store
 * forces the block store to complete before upcoming reuse of the
 * fpregs in the block;  the block load is blocking on sun4u/cheetah
 * so no need for a membar after it.
 */

#define	FPRAS_REWRITE_TYPE1(blk, doex, fpq, tmp1, label)	\
	brz,pn  doex, label/**/f				;\
	  sethi	%hi(fpras_chkfn_type1), tmp1			;\
	add	tmp1, %lo(fpras_chkfn_type1), tmp1		;\
	add	tmp1, FPRAS_BLK0 + blk * 64, tmp1		;\
	ldda	[tmp1]ASI_BLK_P, fpq				;\
	add	doex, FPRAS_BLK0 + blk * 64, tmp1		;\
	stda	fpq, [tmp1]ASI_BLK_P				;\
	membar	#Sync						;\
label:

/*
 * Rewrite type 2 will only work with instruction blocks that satisfy
 * this particular repeat pattern.  Note that the frf quadrant to
 * use is implicit in the macro name and had better match what the
 * copy function is preserving.
*
 * The odd looking repetition in the initial loop is designed to open
 * up boths paths from prefetch cache to the frf - unrolling the loop
 * would defeat this.  In addition we perform idempotent faligndata
 * manipulations using %tick as a randomly aligned address (this only
 * works for address that aren't doubleword aligned).
 */
#define	FPRAS_REWRITE_TYPE2Q1(blk, doex, tmp1, tmp2, label1, label2)	\
	brz,pn	doex, label1/**/f					;\
	  mov	0x2, tmp1						;\
	set	fpras_chkfn_type1, tmp2					;\
label2:									;\
	deccc		tmp1						;\
	ldd		[tmp2 + (FPRAS_BLK0 + blk * 64)], %f4		;\
	ldd		[tmp2 + (FPRAS_BLK0 + blk * 64) + 8], %f2	;\
	bnz,a,pt	%icc, label2/**/b				;\
	  fsrc1		%f4, %f0					;\
	rdpr		%tick, tmp1					;\
	fsrc1		%f4, %f8					;\
	fsrc1		%f2, %f10					;\
	btst		0x7, tmp1					;\
	alignaddr	tmp1, %g0, %g0	/* changes %gsr */		;\
	bz,pn		%icc, label2/**/f				;\
	  faligndata	%f2, %f4, %f6					;\
	faligndata	%f0, %f2, %f12					;\
	alignaddrl	tmp1, %g0, %g0					;\
	faligndata	%f12, %f6, %f6					;\
label2:									;\
	add		doex, FPRAS_BLK0 + blk * 64, tmp1		;\
	fsrc2		%f8, %f12					;\
	fsrc1		%f6, %f14					;\
	stda		%f0, [tmp1]ASI_BLK_P				;\
	membar		#Sync						;\
label1:

#define	FPRAS_REWRITE_TYPE2Q2(blk, doex, tmp1, tmp2, label1, label2)	\
	brz,pn	doex, label1/**/f					;\
	  mov	0x2, tmp1						;\
	set	fpras_chkfn_type1, tmp2					;\
label2:									;\
	deccc		tmp1						;\
	ldd		[tmp2 + (FPRAS_BLK0 + blk * 64)], %f20	;\
	ldd		[tmp2 + (FPRAS_BLK0 + blk * 64) + 8], %f18	;\
	bnz,a,pt	%icc, label2/**/b				;\
	  fsrc1		%f20, %f16					;\
	rdpr		%tick, tmp1					;\
	fsrc1		%f20, %f24					;\
	fsrc1		%f18, %f26					;\
	btst		0x7, tmp1					;\
	alignaddr	tmp1, %g0, %g0	/* changes %gsr */		;\
	bz,pn		%icc, label2/**/f				;\
	  faligndata	%f18, %f20, %f22				;\
	faligndata	%f16, %f18, %f28				;\
	alignaddrl	tmp1, %g0, %g0					;\
	faligndata	%f28, %f22, %f22				;\
label2:									;\
	add		doex, FPRAS_BLK0 + blk * 64, tmp1		;\
	fsrc2		%f24, %f28					;\
	fsrc1		%f22, %f30					;\
	stda		%f16, [tmp1]ASI_BLK_P				;\
	membar		#Sync						;\
label1:

/*
 * The CHECK macro takes the 'doex' address of the check function to
 * execute and jumps to it (if not NULL). If the check function returns
 * nonzero then the check has failed and the CHECK macro must initiate
 * an appropriate failure action.  Illegal instruction trap handlers
 * will also recognise traps in this PC range as fp failures.  Thread
 * migration must only be reallowed after completion of this check.  The
 * CHECK macro should be treated as a CALL/JMPL - output registers are
 * forfeit after using it.  If the call to fpras_failure returns
 * (it may decide to panic) then invoke lofault handler (which must exist)
 * to return an error (be sure to use this macro before restoring original
 * lofault setup in copy functions).  Note that the lofault handler is the
 * copyops aware proxy handler which will perform other tidy up operations
 * (unbind, fp state restore) that would normally have been done in the tail
 * of the copy function.
 *
 *	operation (immedidate): as above
 *	doex (register): doex value returned from the REWRITE
 *	label: free local numeric label
 */

#define	FPRAS_CHECK(operation, doex, label)				\
	brz,pn	doex, label/**/f					;\
	  nop								;\
	jmpl	doex, %o7						;\
	  nop								;\
	cmp	%o0, FPRAS_OK						;\
	be	%icc, label/**/f					;\
	  nop								;\
	mov	%o0, %o1	/* how detected */			;\
	call	fpras_failure	/* take failure action */		;\
	  mov	operation, %o0						;\
	ldn	[THREAD_REG + T_LOFAULT], doex				;\
	jmp	doex							;\
	  mov	EFAULT, %g1						;\
label:

/* END CSTYLED */

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FPRAS_IMPL_H */
