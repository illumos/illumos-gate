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

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/asm_linkage.h>
#include <sys/vtrace.h>
#include <sys/machthread.h>
#include <sys/clock.h>
#include <sys/asi.h>
#include <sys/fsr.h>
#include <sys/privregs.h>
#include <sys/rockasi.h>

#if !defined(lint)
#include "assym.h"
#endif	/* lint */

/*
 * VIS_COPY_THRESHOLD indicates the minimum number of bytes needed
 * to "break even" using FP/VIS-accelerated memory operations.
 * The FPBLK code assumes a minimum number of bytes are available
 * to be moved on entry.  Check that code carefully before 
 * reducing VIS_COPY_THRESHOLD below 256.
 */
/*
 * This shadows sys/machsystm.h which can't be included due to
 * the lack of _ASM guards in include files it references.
 * Change it here, change it there.
 */
#define VIS_COPY_THRESHOLD 256

/*
 * TEST for very short copies
 * Be aware that the maximum unroll for the short unaligned case
 * is SHORTCOPY+1
 */
#define SHORTCOPY 3
#define CHKSIZE  39

/*
 * Indicates that we're to trampoline to the error handler.
 * Entry points bcopy, copyin_noerr, and copyout_noerr use this flag.
 * kcopy, copyout, xcopyout, copyin, and xcopyin do not set this flag.
 */
#define	FPUSED_FLAG	1
#define	TRAMP_FLAG	2
#define	MASK_FLAGS	3

/*
 * LOFAULT_SET : Flag set by kzero and kcopy to indicate that t_lofault
 * handler was set
 */
#define	LOFAULT_SET 2

/*
 * Number of outstanding prefetches.
 * Testing with 1200 MHz Cheetah+ and Jaguar gives best results with
 * two prefetches, one with a reach of 8*BLOCK_SIZE+8 and one with a
 * reach of 5*BLOCK_SIZE.  The double prefetch gives an typical improvement
 * of 5% for large copies as compared to a single prefetch.  The reason
 * for the improvement is that with Cheetah and Jaguar, some prefetches
 * are dropped due to the prefetch queue being full.  The second prefetch
 * reduces the number of cache lines that are dropped. 
 * Do not remove the double prefetch or change either FIRST_PREFETCH
 * or SECOND_PREFETCH without extensive performance tests to prove
 * there is no loss of performance.
 * XXX: For ROCK, the prefetch depth can be upto 16, but sticking
 *      with 8 as of now pending more clarity on this.
 */
#define	FIRST_PREFETCH	8
#define	SECOND_PREFETCH	5

#define	VIS_BLOCKSIZE		64

/*
 * Size of stack frame in order to accomodate a 64-byte aligned
 * floating-point register save area and 2 64-bit temp locations.
 * All copy functions use two quadrants of fp registers; to assure a
 * block-aligned two block buffer in which to save we must reserve
 * three blocks on stack.  Not all functions preserve %pfrs on stack
 * or need to preserve %gsr but we use HWCOPYFRAMESIZE for all.
 *
 *    _______________________________________ <-- %fp + STACK_BIAS
 *    | We may need to preserve 2 quadrants |
 *    | of fp regs, but since we do so with |
 *    | BST/BLD we need room in which to    |
 *    | align to VIS_BLOCKSIZE bytes.  So   |
 *    | this area is 3 * VIS_BLOCKSIZE.     | <--  - SAVED_FPREGS_OFFSET
 *    |-------------------------------------|
 *    | 8 bytes to save %fprs               | <--  - SAVED_FPRS_OFFSET
 *    |-------------------------------------|
 *    | 8 bytes to save %gsr                | <--  - SAVED_GSR_OFFSET
 *    ---------------------------------------
 */
#define	HWCOPYFRAMESIZE		((VIS_BLOCKSIZE * (2 + 1)) + (2 * 8))
#define SAVED_FPREGS_OFFSET	(VIS_BLOCKSIZE * 3)
#define SAVED_FPREGS_ADJUST	((VIS_BLOCKSIZE * 2) - 1)
#define	SAVED_FPRS_OFFSET	(SAVED_FPREGS_OFFSET + 8)
#define	SAVED_GSR_OFFSET	(SAVED_FPRS_OFFSET + 8)

#define	ICACHE_LINE_SIZE	64

#define	MEDIUM_MAX	255
#define	MED_WMAX	256 /* max copy for medium word-aligned case */
#define	MED_MAX		256 /* max copy for medium longword-aligned case */

#define	PAGE_MASK	8191
#define	ST_CACHE_ALIGN	127

#ifndef	BSTORE_SIZE
#define	BSTORE_SIZE	256	/* min copy size for block store */
#endif

/*
 * Common macros used by the various versions of the block copy
 * routines in this file.
 */

/*
 * In FP copies if we do not have preserved data to restore over
 * the fp regs we used then we must zero those regs to avoid
 * exposing portions of the data to later threads (data security).
 *
 * Copy functions use either quadrants 1 and 3 or 2 and 4.
 *
 * FZEROQ3Q4: Zero quadrants 3 and 4, ie %d32 - %d46 and %d48 - %d62
 *
 */
#define	FZEROQ3Q4		\
	movxtod	%g0, %d32	;\
	movxtod	%g0, %d34	;\
	fsrc1	%d0, %d36	;\
	fsrc1	%d0, %d38	;\
	fsrc1	%d0, %d40	;\
	fsrc1	%d0, %d42	;\
	fsrc1	%d0, %d44	;\
	fsrc1	%d0, %d46	;\
	fsrc1	%d0, %d48	;\
	fsrc1	%d0, %d50	;\
	fsrc1	%d0, %d52	;\
	fsrc1	%d0, %d54	;\
	fsrc1	%d0, %d56	;\
	fsrc1	%d0, %d58	;\
	fsrc1	%d0, %d60	;\
	fsrc1	%d0, %d62


/*
 * Macros to save and restore quadrants 1 and 3 or 2 and 4 to/from the stack.
 * Used to save and restore in-use fp registers when we want to use FP
 * and find fp already in use and copy size still large enough to justify
 * the additional overhead of this save and restore.
 *
 * A membar #Sync is needed before save to sync fp ops initiated before
 * the call to the copy function (by whoever has fp in use); for example
 * an earlier block load to the quadrant we are about to save may still be
 * "in flight".  A membar #Sync is required at the end of the save to
 * sync our block store (the copy code is about to begin ldd's to the
 * first quadrant).  Note, however, that since Cheetah pipeline block load
 * is blocking we can omit the initial membar before saving fp state (they're
 * commented below in case of future porting to a chip that does not block
 * on block load).
 *
 * Similarly: a membar #Sync before restore allows the block stores of
 * the copy operation to complete before we fill the quadrants with their
 * original data, and a membar #Sync after restore lets the block loads
 * of the restore complete before we return to whoever has the fp regs
 * in use.  To avoid repeated membar #Sync we make it the responsibility
 * of the copy code to membar #Sync immediately after copy is complete
 * and before using the BLD_*_FROMSTACK macro.
 */
#if !defined(lint)
#define BST_FPQ3Q4_TOSTACK(tmp1)				\
	/* membar #Sync	*/					;\
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, tmp1	;\
	and	tmp1, -VIS_BLOCKSIZE, tmp1 /* block align */	;\
	stda	%d32, [tmp1]ASI_BLK_P				;\
	add	tmp1, VIS_BLOCKSIZE, tmp1			;\
	stda	%d48, [tmp1]ASI_BLK_P				;\
	membar	#Sync

#define	BLD_FPQ3Q4_FROMSTACK(tmp1)				\
	/* membar #Sync - provided at copy completion */	;\
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, tmp1	;\
	and	tmp1, -VIS_BLOCKSIZE, tmp1 /* block align */	;\
	ldda	[tmp1]ASI_BLK_P, %d32				;\
	add	tmp1, VIS_BLOCKSIZE, tmp1			;\
	ldda	[tmp1]ASI_BLK_P, %d48				;\
	membar	#Sync
#endif

/*
 * FP_NOMIGRATE and FP_ALLOWMIGRATE.  Prevent migration (or, stronger,
 * prevent preemption if there is no t_lwp to save FP state to on context
 * switch) before commencing a FP copy, and reallow it on completion or
 * in error trampoline paths when we were using FP copy.
 *
 * Both macros may call other functions, so be aware that all outputs are
 * forfeit after using these macros.  For this reason we do not pass registers
 * to use - we just use any outputs we want.
 *
 * For fpRAS we need to perform the fpRAS mechanism test on the same
 * CPU as we use for the copy operation, both so that we validate the
 * CPU we perform the copy on and so that we know which CPU failed
 * if a failure is detected.  Hence we need to be bound to "our" CPU.
 * This could be achieved through disabling preemption (and we have do it that
 * way for threads with no t_lwp) but for larger copies this may hold
 * higher priority threads off of cpu for too long (eg, realtime).  So we
 * make use of the lightweight t_nomigrate mechanism where we can (ie, when
 * we have a t_lwp).
 *
 * Pseudo code:
 *
 * FP_NOMIGRATE:
 *
 * if (curthread->t_lwp) {
 *	thread_nomigrate();
 * } else {
 *	kpreempt_disable();
 * }
 *
 * FP_ALLOWMIGRATE:
 *
 * if (curthread->t_lwp) {
 *	thread_allowmigrate();
 * } else {
 *	kpreempt_enable();
 * }
 */

#define	FP_NOMIGRATE(label1, label2)				\
	ldn	[THREAD_REG + T_LWP], %o0			;\
	brz,a,pn %o0, label1/**/f				;\
	  ldsb	[THREAD_REG + T_PREEMPT], %o1			;\
	call	thread_nomigrate				;\
	  nop							;\
	ba	label2/**/f					;\
	  nop							;\
label1:								;\
	inc	%o1						;\
	stb	%o1, [THREAD_REG + T_PREEMPT]			;\
label2:

#define	FP_ALLOWMIGRATE(label1, label2)			\
	ldn	[THREAD_REG + T_LWP], %o0			;\
	brz,a,pn %o0, label1/**/f				;\
	  ldsb	[THREAD_REG + T_PREEMPT], %o1			;\
	call thread_allowmigrate				;\
	  nop							;\
	ba	label2/**/f					;\
	  nop							;\
label1:								;\
	dec	%o1						;\
	brnz,pn	%o1, label2/**/f				;\
	  stb	%o1, [THREAD_REG + T_PREEMPT]			;\
	ldn	[THREAD_REG + T_CPU], %o0			;\
	ldub	[%o0 + CPU_KPRUNRUN], %o0			;\
	brz,pt	%o0, label2/**/f				;\
	  nop							;\
	call	kpreempt					;\
	  rdpr	%pil, %o0					;\
label2:

/*
 * Copy a block of storage, returning an error code if `from' or
 * `to' takes a kernel pagefault which cannot be resolved.
 * Returns errno value on pagefault error, 0 if all ok
 */

#if defined(lint)

/* ARGSUSED */
int
kcopy(const void *from, void *to, size_t count)
{ return(0); }

#else	/* lint */

	.seg	".text"
	.align	4

	ENTRY(kcopy)

	cmp	%o2, VIS_COPY_THRESHOLD		! check for leaf rtn case
	bleu,pt	%ncc, .kcopy_small		! go to larger cases
	  xor	%o0, %o1, %o3			! are src, dst alignable?
	btst	7, %o3				!
	bz,pt	%ncc, .kcopy_8			! check for longword alignment
	  nop
	btst	1, %o3				! 
	bz,pt	%ncc, .kcopy_2			! check for half-word
	  nop
	sethi	%hi(hw_copy_limit_1), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_1)], %o3
	tst	%o3
	bz,pn	%icc, .kcopy_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .kcopy_small		! go to small copy
	  nop
	ba,pt	%ncc, .kcopy_more		! otherwise go to large copy
	  nop
.kcopy_2:
	btst	3, %o3				!
	bz,pt	%ncc, .kcopy_4			! check for word alignment
	  nop
	sethi	%hi(hw_copy_limit_2), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_2)], %o3
	tst	%o3
	bz,pn	%icc, .kcopy_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .kcopy_small		! go to small copy
	  nop
	ba,pt	%ncc, .kcopy_more		! otherwise go to large copy
	  nop
.kcopy_4:
	! already checked longword, must be word aligned
	sethi	%hi(hw_copy_limit_4), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_4)], %o3
	tst	%o3
	bz,pn	%icc, .kcopy_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .kcopy_small		! go to small copy
	  nop
	ba,pt	%ncc, .kcopy_more		! otherwise go to large copy
	  nop
.kcopy_8:
	sethi	%hi(hw_copy_limit_8), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_8)], %o3
	tst	%o3
	bz,pn	%icc, .kcopy_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .kcopy_small		! go to small copy
	  nop
	ba,pt	%ncc, .kcopy_more		! otherwise go to large copy
	  nop

.kcopy_small:
	sethi	%hi(.sm_copyerr), %o5		! sm_copyerr is lofault value
	or	%o5, %lo(.sm_copyerr), %o5
	ldn	[THREAD_REG + T_LOFAULT], %o4	! save existing handler
	membar	#Sync				! sync error barrier
	ba,pt	%ncc, .sm_do_copy		! common code
	 stn	%o5, [THREAD_REG + T_LOFAULT]	! set t_lofault

.kcopy_more:
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	sethi	%hi(.copyerr), %l7		! copyerr is lofault value
	or	%l7, %lo(.copyerr), %l7
	ldn	[THREAD_REG + T_LOFAULT], %l6	! save existing handler
	membar	#Sync				! sync error barrier
	ba,pt	%ncc, .do_copy			! common code
	  stn	%l7, [THREAD_REG + T_LOFAULT]	! set t_lofault


/*
 * We got here because of a fault during bcopy_more, called from kcopy or bcopy.
 * Errno value is in %g1.  bcopy_more uses fp quadrants 3 and 4.
 */
.copyerr:
	set	.copyerr2, %l0
	membar	#Sync				! sync error barrier
	stn	%l0, [THREAD_REG + T_LOFAULT]	! set t_lofault
	btst	FPUSED_FLAG, %l6
	bz	%ncc, 1f
	  and	%l6, TRAMP_FLAG, %l0		! copy trampoline flag to %l0

	ldx	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2	! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	! No need to save regs if either FEF or DU are clear
    	and	%o3, FPRS_FEF|FPRS_DU, %o2
	xorcc   %o2, FPRS_FEF|FPRS_DU, %g0
	bnz,pt  %icc, 4f
	  nop

	BLD_FPQ3Q4_FROMSTACK(%o2)

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZEROQ3Q4
	wr	%o3, 0, %fprs		! restore fprs

	!
	! Need to cater for the different expectations of kcopy
	! and bcopy. kcopy will *always* set a t_lofault handler
	! If it fires, we're expected to just return the error code
	! and *not* to invoke any existing error handler. As far as
	! bcopy is concerned, we only set t_lofault if there was an
	! existing lofault handler. In that case we're expected to
	! invoke the previously existing handler after resetting the
	! t_lofault value.
	!
1:
	andn	%l6, MASK_FLAGS, %l6		! turn trampoline flag off
	membar	#Sync				! sync error barrier
	stn	%l6, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	FP_ALLOWMIGRATE(5, 6)

	btst	TRAMP_FLAG, %l0
	bnz,pn	%ncc, 3f
	  nop
	ret
	  restore	%g1, 0, %o0

3:
	!
	! We're here via bcopy. There *must* have been an error handler
	! in place otherwise we would have died a nasty death already.
	!
	jmp	%l6				! goto real handler
	  restore	%g0, 0, %o0		! dispose of copy window

/*
 * We got here because of a fault in .copyerr.  We can't safely restore fp
 * state, so we panic.
 */
fp_panic_msg:
	.asciz	"Unable to restore fp state after copy operation"

	.align	4
.copyerr2:
	set	fp_panic_msg, %o0
	call	panic
	  nop

/*
 * We got here because of a fault during a small kcopy or bcopy.
 * No floating point registers are used by the small copies.
 * Errno value is in %g1.
 */
.sm_copyerr:
1:
	btst	TRAMP_FLAG, %o4
	membar	#Sync
	andn	%o4, TRAMP_FLAG, %o4
	bnz,pn	%ncc, 3f
	  stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g1, %o0
3:
	jmp	%o4				! goto real handler
	  mov	%g0, %o0			! 

	SET_SIZE(kcopy)
#endif	/* lint */


/*
 * Copy a block of storage - must not overlap (from + len <= to).
 * Registers: l6 - saved t_lofault
 * (for short copies, o4 - saved t_lofault)
 *
 * Copy a page of memory.
 * Assumes double word alignment and a count >= 256.
 */
#if defined(lint)

/* ARGSUSED */
void
bcopy(const void *from, void *to, size_t count)
{}

#else	/* lint */

	ENTRY(bcopy)

	cmp	%o2, VIS_COPY_THRESHOLD		! check for leaf rtn case
	bleu,pt	%ncc, .bcopy_small		! go to larger cases
	  xor	%o0, %o1, %o3			! are src, dst alignable?
	btst	7, %o3				!
	bz,pt	%ncc, .bcopy_8			! check for longword alignment
	  nop
	btst	1, %o3				!
	bz,pt	%ncc, .bcopy_2			! check for half-word
	  nop
	sethi	%hi(hw_copy_limit_1), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_1)], %o3
	tst	%o3
	bz,pn	%icc, .bcopy_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .bcopy_small		! go to small copy
	  nop
	ba,pt	%ncc, .bcopy_more		! otherwise go to large copy
	  nop
.bcopy_2:
	btst	3, %o3				!
	bz,pt	%ncc, .bcopy_4			! check for word alignment
	  nop
	sethi	%hi(hw_copy_limit_2), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_2)], %o3
	tst	%o3
	bz,pn	%icc, .bcopy_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .bcopy_small		! go to small copy
	  nop
	ba,pt	%ncc, .bcopy_more		! otherwise go to large copy
	  nop
.bcopy_4:
	! already checked longword, must be word aligned
	sethi	%hi(hw_copy_limit_4), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_4)], %o3
	tst	%o3
	bz,pn	%icc, .bcopy_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .bcopy_small		! go to small copy
	  nop
	ba,pt	%ncc, .bcopy_more		! otherwise go to large copy
	  nop
.bcopy_8:
	sethi	%hi(hw_copy_limit_8), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_8)], %o3
	tst	%o3
	bz,pn	%icc, .bcopy_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .bcopy_small		! go to small copy
	  nop
	ba,pt	%ncc, .bcopy_more		! otherwise go to large copy
	  nop

	.align	16
.bcopy_small:
	ldn	[THREAD_REG + T_LOFAULT], %o4	! save t_lofault
	tst	%o4
	bz,pt	%icc, .sm_do_copy
	  nop
	sethi	%hi(.sm_copyerr), %o5
	or	%o5, %lo(.sm_copyerr), %o5
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! install new vector
	or	%o4, TRAMP_FLAG, %o4		! error should trampoline
.sm_do_copy:
	cmp	%o2, SHORTCOPY		! check for really short case
	bleu,pt	%ncc, .bc_sm_left	!
	  cmp	%o2, CHKSIZE		! check for medium length cases
	bgu,pn	%ncc, .bc_med		!
	  or	%o0, %o1, %o3		! prepare alignment check
	andcc	%o3, 0x3, %g0		! test for alignment
	bz,pt	%ncc, .bc_sm_word	! branch to word aligned case
.bc_sm_movebytes:
	  sub	%o2, 3, %o2		! adjust count to allow cc zero test
.bc_sm_notalign4:
	ldub	[%o0], %o3		! read byte
	stb	%o3, [%o1]		! write byte
	subcc	%o2, 4, %o2		! reduce count by 4
	ldub	[%o0 + 1], %o3		! repeat for a total of 4 bytes
	add	%o0, 4, %o0		! advance SRC by 4
	stb	%o3, [%o1 + 1]
	ldub	[%o0 - 2], %o3
	add	%o1, 4, %o1		! advance DST by 4
	stb	%o3, [%o1 - 2]
	ldub	[%o0 - 1], %o3
	bgt,pt	%ncc, .bc_sm_notalign4	! loop til 3 or fewer bytes remain
	  stb	%o3, [%o1 - 1]
	add	%o2, 3, %o2		! restore count
.bc_sm_left:
	tst	%o2
	bz,pt	%ncc, .bc_sm_exit	! check for zero length
	  deccc	%o2			! reduce count for cc test
	ldub	[%o0], %o3		! move one byte
	bz,pt	%ncc, .bc_sm_exit
	  stb	%o3, [%o1]
	ldub	[%o0 + 1], %o3		! move another byte
	deccc	%o2			! check for more
	bz,pt	%ncc, .bc_sm_exit
	  stb	%o3, [%o1 + 1]
	ldub	[%o0 + 2], %o3		! move final byte
	stb	%o3, [%o1 + 2]
	membar	#Sync				! sync error barrier
	andn	%o4, TRAMP_FLAG, %o4
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return 0
	.align	16
	nop				! instruction alignment
					! see discussion at start of file
.bc_sm_words:
	lduw	[%o0], %o3		! read word
.bc_sm_wordx:
	subcc	%o2, 8, %o2		! update count
	stw	%o3, [%o1]		! write word
	add	%o0, 8, %o0		! update SRC
	lduw	[%o0 - 4], %o3		! read word
	add	%o1, 8, %o1		! update DST
	bgt,pt	%ncc, .bc_sm_words	! loop til done
	  stw	%o3, [%o1 - 4]		! write word
	addcc	%o2, 7, %o2		! restore count
	bz,pt	%ncc, .bc_sm_exit
	  deccc	%o2
	bz,pt	%ncc, .bc_sm_byte
.bc_sm_half:
	  subcc	%o2, 2, %o2		! reduce count by 2
	add	%o0, 2, %o0		! advance SRC by 2
	lduh	[%o0 - 2], %o3		! read half word
	add	%o1, 2, %o1		! advance DST by 2
	bgt,pt	%ncc, .bc_sm_half	! loop til done
	  sth	%o3, [%o1 - 2]		! write half word
	addcc	%o2, 1, %o2		! restore count
	bz,pt	%ncc, .bc_sm_exit
	  nop
.bc_sm_byte:
	ldub	[%o0], %o3
	stb	%o3, [%o1]
	membar	#Sync				! sync error barrier
	andn	%o4, TRAMP_FLAG, %o4
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return 0

.bc_sm_word:
	subcc	%o2, 4, %o2		! update count
	bgt,pt	%ncc, .bc_sm_wordx
	  lduw	[%o0], %o3		! read word
	addcc	%o2, 3, %o2		! restore count
	bz,pt	%ncc, .bc_sm_exit
	  stw	%o3, [%o1]		! write word
	deccc	%o2			! reduce count for cc test
	ldub	[%o0 + 4], %o3		! load one byte
	bz,pt	%ncc, .bc_sm_exit
	  stb	%o3, [%o1 + 4]		! store one byte
	ldub	[%o0 + 5], %o3		! load second byte
	deccc	%o2
	bz,pt	%ncc, .bc_sm_exit
	  stb	%o3, [%o1 + 5]		! store second byte
	ldub	[%o0 + 6], %o3		! load third byte
	stb	%o3, [%o1 + 6]		! store third byte
.bc_sm_exit:
	membar	#Sync				! sync error barrier
	andn	%o4, TRAMP_FLAG, %o4
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return 0

	.align 16
.bc_med:
	xor	%o0, %o1, %o3		! setup alignment check
	btst	1, %o3
	bnz,pt	%ncc, .bc_sm_movebytes	! unaligned
	  nop
	btst	3, %o3
	bnz,pt	%ncc, .bc_med_half	! halfword aligned
	  nop
	btst	7, %o3
	bnz,pt	%ncc, .bc_med_word	! word aligned
	  nop
.bc_med_long:
	btst	3, %o0			! check for
	bz,pt	%ncc, .bc_med_long1	! word alignment
	  nop
.bc_med_long0:
	ldub	[%o0], %o3		! load one byte
	inc	%o0
	stb	%o3,[%o1]		! store byte
	inc	%o1
	btst	3, %o0
	bnz,pt	%ncc, .bc_med_long0
	  dec	%o2
.bc_med_long1:			! word aligned
	btst	7, %o0			! check for long word
	bz,pt	%ncc, .bc_med_long2
	  nop
	lduw	[%o0], %o3		! load word
	add	%o0, 4, %o0		! advance SRC by 4
	stw	%o3, [%o1]		! store word
	add	%o1, 4, %o1		! advance DST by 4
	sub	%o2, 4, %o2		! reduce count by 4
!
!  Now long word aligned and have at least 32 bytes to move
!
.bc_med_long2:
	sub	%o2, 31, %o2		! adjust count to allow cc zero test
.bc_med_lmove:
	ldx	[%o0], %o3		! read long word
	stx	%o3, [%o1]		! write long word
	subcc	%o2, 32, %o2		! reduce count by 32
	ldx	[%o0 + 8], %o3		! repeat for a total for 4 long words
	add	%o0, 32, %o0		! advance SRC by 32
	stx	%o3, [%o1 + 8]
	ldx	[%o0 - 16], %o3
	add	%o1, 32, %o1		! advance DST by 32
	stx	%o3, [%o1 - 16]
	ldx	[%o0 - 8], %o3
	bgt,pt	%ncc, .bc_med_lmove	! loop til 31 or fewer bytes left
	  stx	%o3, [%o1 - 8]
	addcc	%o2, 24, %o2		! restore count to long word offset
	ble,pt	%ncc, .bc_med_lextra	! check for more long words to move
	  nop
.bc_med_lword:
	ldx	[%o0], %o3		! read long word
	subcc	%o2, 8, %o2		! reduce count by 8
	stx	%o3, [%o1]		! write long word
	add	%o0, 8, %o0		! advance SRC by 8
	bgt,pt	%ncc, .bc_med_lword	! loop til 7 or fewer bytes left
	  add	%o1, 8, %o1		! advance DST by 8
.bc_med_lextra:
	addcc	%o2, 7, %o2		! restore rest of count
	bz,pt	%ncc, .bc_sm_exit	! if zero, then done
	  deccc	%o2
	bz,pt	%ncc, .bc_sm_byte
	  nop
	ba,pt	%ncc, .bc_sm_half
	  nop

	.align 16
.bc_med_word:
	btst	3, %o0			! check for
	bz,pt	%ncc, .bc_med_word1	! word alignment
	  nop
.bc_med_word0:
	ldub	[%o0], %o3		! load one byte
	inc	%o0
	stb	%o3,[%o1]		! store byte
	inc	%o1
	btst	3, %o0
	bnz,pt	%ncc, .bc_med_word0
	  dec	%o2
!
!  Now word aligned and have at least 36 bytes to move
!
.bc_med_word1:
	sub	%o2, 15, %o2		! adjust count to allow cc zero test
.bc_med_wmove:
	lduw	[%o0], %o3		! read word
	stw	%o3, [%o1]		! write word
	subcc	%o2, 16, %o2		! reduce count by 16
	lduw	[%o0 + 4], %o3		! repeat for a total for 4 words
	add	%o0, 16, %o0		! advance SRC by 16
	stw	%o3, [%o1 + 4]
	lduw	[%o0 - 8], %o3
	add	%o1, 16, %o1		! advance DST by 16
	stw	%o3, [%o1 - 8]
	lduw	[%o0 - 4], %o3
	bgt,pt	%ncc, .bc_med_wmove	! loop til 15 or fewer bytes left
	  stw	%o3, [%o1 - 4]
	addcc	%o2, 12, %o2		! restore count to word offset
	ble,pt	%ncc, .bc_med_wextra	! check for more words to move
	  nop
.bc_med_word2:
	lduw	[%o0], %o3		! read word
	subcc	%o2, 4, %o2		! reduce count by 4
	stw	%o3, [%o1]		! write word
	add	%o0, 4, %o0		! advance SRC by 4
	bgt,pt	%ncc, .bc_med_word2	! loop til 3 or fewer bytes left
	  add	%o1, 4, %o1		! advance DST by 4
.bc_med_wextra:
	addcc	%o2, 3, %o2		! restore rest of count
	bz,pt	%ncc, .bc_sm_exit	! if zero, then done
	  deccc	%o2
	bz,pt	%ncc, .bc_sm_byte
	  nop
	ba,pt	%ncc, .bc_sm_half
	  nop

	.align 16
.bc_med_half:
	btst	1, %o0			! check for
	bz,pt	%ncc, .bc_med_half1	! half word alignment
	  nop
	ldub	[%o0], %o3		! load one byte
	inc	%o0
	stb	%o3,[%o1]		! store byte
	inc	%o1
	dec	%o2
!
!  Now half word aligned and have at least 38 bytes to move
!
.bc_med_half1:
	sub	%o2, 7, %o2		! adjust count to allow cc zero test
.bc_med_hmove:
	lduh	[%o0], %o3		! read half word
	sth	%o3, [%o1]		! write half word
	subcc	%o2, 8, %o2		! reduce count by 8
	lduh	[%o0 + 2], %o3		! repeat for a total for 4 halfwords
	add	%o0, 8, %o0		! advance SRC by 8
	sth	%o3, [%o1 + 2]
	lduh	[%o0 - 4], %o3
	add	%o1, 8, %o1		! advance DST by 8
	sth	%o3, [%o1 - 4]
	lduh	[%o0 - 2], %o3
	bgt,pt	%ncc, .bc_med_hmove	! loop til 7 or fewer bytes left
	  sth	%o3, [%o1 - 2]
	addcc	%o2, 7, %o2		! restore count
	bz,pt	%ncc, .bc_sm_exit
	  deccc	%o2
	bz,pt	%ncc, .bc_sm_byte
	  nop
	ba,pt	%ncc, .bc_sm_half
	  nop

	SET_SIZE(bcopy)

/*
 * The _more entry points are not intended to be used directly by
 * any caller from outside this file.  They are provided to allow
 * profiling and dtrace of the portions of the copy code that uses
 * the floating point registers.
 * This entry is particularly important as DTRACE (at least as of
 * 4/2004) does not support leaf functions.
 */

	ENTRY(bcopy_more)
.bcopy_more:
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	ldn	[THREAD_REG + T_LOFAULT], %l6	! save t_lofault
	tst	%l6
	bz,pt	%ncc, .do_copy
	  nop
	sethi	%hi(.copyerr), %o2
	or	%o2, %lo(.copyerr), %o2
	membar	#Sync				! sync error barrier
	stn	%o2, [THREAD_REG + T_LOFAULT]	! install new vector
	!
	! We've already captured whether t_lofault was zero on entry.
	! We need to mark ourselves as being from bcopy since both
	! kcopy and bcopy use the same code path. If TRAMP_FLAG is set
	! and the saved lofault was zero, we won't reset lofault on
	! returning.
	!
	or	%l6, TRAMP_FLAG, %l6

/*
 * Copies that reach here are larger than VIS_COPY_THRESHOLD bytes
 * Also, use of FP registers has been tested to be enabled
 */
.do_copy:
	FP_NOMIGRATE(6, 7)

	mov	%i1, %g5		! save dest addr start
	mov	%i2, %g2		! save size

	rd	%fprs, %o2		! check for unused fp
	st	%o2, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET] ! save orig %fprs

	! FPU enabled ?  If not, enable it.
	btst	FPRS_FEF, %o2
	bz,a,pt	%icc, .do_blockcopy
	  wr	%g0, FPRS_FEF, %fprs

	! FPU enabled, but is Q3Q4 dirty ?  If yes, save them.
	btst	FPRS_DU, %o2
	bz,pn	%icc, .do_blockcopy
	  nop

	BST_FPQ3Q4_TOSTACK(%o2)

.do_blockcopy:
	rd	%gsr, %o2
	stx	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]	! save gsr
	or	%l6, FPUSED_FLAG, %l6
	ba,a,pt	%xcc, .medium
	  nop

#define	REALSRC	%i0
#define	DST	%i1
#define	CNT	%i2
#define	SRC	%i3
#define	TMP	%i5

	.align 16
.medium:
	neg	DST, TMP
	neg	REALSRC, SRC
	andcc	TMP, 7, TMP	! bytes till DST 8 byte aligned
	and	SRC, 7, SRC	! bytes till REALSRC 8 byte aligned
	
	bz	%ncc, .med2
	  sub	TMP, SRC, SRC
		! -(bytes till REALSRC aligned after DST aligned)
		! SRC = {-7, -6, ... 7} SRC > 0 => REALSRC overaligned

	sub	CNT, TMP, CNT	! update count

.med1:
	ldub	[REALSRC], %i4
	deccc	TMP
	inc	REALSRC
	stb	%i4, [DST]
	bgu,pt	%ncc, .med1
	  inc	DST

	! Now DST is 8-byte aligned.  DST, REALSRC, CNT are current.

.med2:
	andcc	REALSRC, 0x3, %g0	! test alignment
	bnz,pt	%ncc, .mediumsetup	! branch to skip aligned cases
					! if src, dst not aligned
	  prefetch [REALSRC + (1 * VIS_BLOCKSIZE)], #n_reads

/*
 * Handle all cases where src and dest are aligned on word
 * or long word boundaries.  Use unrolled loops for better
 * performance.  This option wins over standard large data
 * move when source and destination is in cache for medium
 * to short data moves.
 */
	andcc	REALSRC, 0x7, %g0	! test word alignment
	bz,pt	%ncc, .medlword		! branch to long word aligned case
	  prefetch [REALSRC + (2 * VIS_BLOCKSIZE)], #n_reads
	cmp	CNT, MED_WMAX		! limit to store buffer size
	bgu,pt	%ncc, .mediumrejoin	! otherwise rejoin main loop
	  nop
	subcc	CNT, 15, CNT		! adjust length to allow cc test
					! for end of loop
	ble,pt	%ncc, .medw15		! skip big loop if less than 16
	  prefetch [REALSRC + (3 * VIS_BLOCKSIZE)], #n_reads
/*
 * no need to put prefetch in loop as prefetches have
 * already been issued for maximum loop size
 */
.medw16:
	ld	[REALSRC], %i4		! load
	subcc	CNT, 16, CNT		! decrement length count
	stw	%i4, [DST]		! and store
	ld	[REALSRC+4], SRC	! a block of 16 bytes
	add	REALSRC, 16, REALSRC	! increase src ptr by 16
	stw	SRC, [DST+4]
	ld	[REALSRC-8], %i4
	add	DST, 16, DST		! increase dst ptr by 16
	stw	%i4, [DST-8]
	ld	[REALSRC-4], SRC
	bgu,pt	%ncc, .medw16		! repeat if at least 16 bytes left
	  stw	SRC, [DST-4]
.medw15:
	addcc	CNT, 15, CNT		! restore count
	bz,pt	%ncc, .bcb_exit		! exit if finished
	  nop
	cmp	CNT, 8
	blt,pt	%ncc, .medw7		! skip if 7 or fewer bytes left
	  nop				!
	ld	[REALSRC], %i4		! load 4 bytes
	subcc	CNT, 8, CNT		! decrease count by 8
	stw	%i4, [DST]		! and store 4 bytes
	add	REALSRC, 8, REALSRC	! increase src ptr by 8
	ld	[REALSRC-4], SRC	! load 4 bytes
	add	DST, 8, DST		! increase dst ptr by 8
	stw	SRC, [DST-4]		! and store 4 bytes
	bz	%ncc, .bcb_exit		! exit if finished
	  nop
.medw7:					! count is ge 1, less than 8
	cmp	CNT, 3			! check for 4 bytes left
	ble,pt	%ncc, .medw3		! skip if 3 or fewer bytes left
	  nop				!
	ld	[REALSRC], %i4		! load 4 bytes
	sub	CNT, 4, CNT		! decrease count by 4
	add	REALSRC, 4, REALSRC	! increase src ptr by 4
	stw	%i4, [DST]		! and store 4 bytes
	add	DST, 4, DST		! increase dst ptr by 4
	tst	CNT			! check for zero bytes left
	bz	%ncc, .bcb_exit		! exit if finished
	  nop
.medw3:					! count is known to be 1, 2, or 3
	deccc	CNT			! reduce count by one
	ldub	[REALSRC], SRC		! load one byte
	bz,pt	%ncc, .bcb_exit		! exit if last byte
	  stb	SRC, [DST]		! store one byte
	ldub	[REALSRC+1], SRC	! load second byte
	deccc	CNT			! reduce count by one
	bz,pt	%ncc, .bcb_exit		! exit if last byte
	  stb	SRC, [DST+1]		! store second byte
	ldub	[REALSRC+2], SRC	! load third byte
	stb	SRC, [DST+2]		! store third byte
	ba,a,pt	%ncc, .bcb_exit		! exit
	  nop

/*
 * Special case for handling when src and dest are both long word aligned
 * and total data to move is between SMALL_MAX and MED_MAX bytes
 */
	.align 16
	nop
.medlword:				! long word aligned
					! length > SMALL_MAX
	cmp	CNT, MED_MAX		! limit to store buffer size
	bgu,pt	%ncc, .mediumrejoin	! otherwise rejoin main loop
	  nop
	subcc	CNT, 31, CNT		! adjust length to allow cc test
					! for end of loop
	ble,pt	%ncc, .medl31		! skip big loop if less than 32
	  prefetch [REALSRC + (3 * VIS_BLOCKSIZE)], #n_reads
/*
 * no need to put prefetch in loop as prefetches have
 * already been issued for maximum loop size
 */
.medl32:
	ldx	[REALSRC], %i4		! load
	subcc	CNT, 32, CNT		! decrement length count
	stx	%i4, [DST]		! and store
	ldx	[REALSRC+8], SRC	! a block of 32 bytes
	add	REALSRC, 32, REALSRC	! increase src ptr by 32
	stx	SRC, [DST+8]
	ldx	[REALSRC-16], %i4
	add	DST, 32, DST		! increase dst ptr by 32
	stx	%i4, [DST-16]
	ldx	[REALSRC-8], SRC
	bgu,pt	%ncc, .medl32		! repeat if at least 32 bytes left
	  stx	SRC, [DST-8]
.medl31:
	addcc	CNT, 16, CNT		! adjust remaining count
	ble,pt	%ncc, .medl15		! skip if 15 or fewer bytes left
	  nop				!
	ldx	[REALSRC], %i4		! load and store 16 bytes
	add	REALSRC, 16, REALSRC	! increase src ptr by 16
	stx	%i4, [DST]		!
	sub	CNT, 16, CNT		! decrease count by 16
	ldx	[REALSRC-8], SRC	!
	add	DST, 16, DST		! increase dst ptr by 16
	stx	SRC, [DST-8]
.medl15:
	addcc	CNT, 15, CNT		! restore count
	bz,pt	%ncc, .bcb_exit		! exit if finished
	  nop
	cmp	CNT, 8
	blt,pt	%ncc, .medw7		! skip if 7 or fewer bytes left
	  nop
	ldx	[REALSRC], %i4		! load 8 bytes
	add	REALSRC, 8, REALSRC	! increase src ptr by 8
	stx	%i4, [DST]		! and store 8 bytes
	subcc	CNT, 8, CNT		! decrease count by 8
	bz	%ncc, .bcb_exit		! exit if finished
	  add	DST, 8, DST		! increase dst ptr by 8
	ba	.medw7
	  nop

	.align 16
	nop
	nop
	nop
.mediumsetup:
	prefetch [REALSRC + (2 * VIS_BLOCKSIZE)], #one_read
.mediumrejoin:
	add	REALSRC, 8, REALSRC	! prepare to round REALSRC upward
	sethi	%hi(0x1234567f), TMP	! For GSR.MASK 
	or	TMP, 0x67f, TMP

	cmp	CNT, MEDIUM_MAX
	bmask	TMP, %g0, %g0

	! Compute TMP (no of bytes that need copying using the main loop).
	! First, compute for the medium case.
	! Then, if large case, TMP is replaced by count for block alignment.
	! Be careful not to read past end of REALSRC
	! Currently, CNT is the actual count remaining
	!            SRC is how much sooner we'll cross the alignment
	!            boundary in REALSRC compared to in DST
	!
	! Examples:  Let # denote bytes that should not be accessed
	!            Let x denote a byte already copied to align DST
	!            Let . and - denote bytes not yet copied
	!            Let | denote double alignment boundaries
	!
	!            DST:  ######xx|........|--------|..######   CNT = 18
	!                          i1
	!
	!  SRC = -3:  REALSRC:  ###xx...|.....---|-----..#|########   TMP = 8
	!                          i0
	!
	!  SRC =  0:  REALSRC:  ######xx|........|--------|..######   TMP = 16-8 = 8
	!                                   i0
	!
	!  SRC = +1:  REALSRC:  #######x|x.......|.-------|-..#####   TMP = 16-8 = 8
	!                                   i0

	wr	%g0, ASI_CACHE_SPARING_P, %asi

	or	%g0, -8, TMP
	alignaddr REALSRC, %g0, REALSRC	! set GSR.ALIGN and align REALSRC

	movrlz	SRC, %g0, TMP		! subtract 8 from i2+i3 only if i3>=0
	add	TMP, CNT, TMP
	add	TMP, SRC, TMP

	bleu	%ncc, .med4
	  andn	TMP, 7, TMP		! 8 byte aligned count
	neg	DST, TMP		! 'large' case
	and	TMP, VIS_BLOCKSIZE-1, TMP  ! bytes till DST block aligned
.med4:
	brgez,a	SRC, .beginmedloop
	  ldda	[REALSRC-8]%asi, %d32

	add	REALSRC, SRC, REALSRC	! back up REALSRC
.med5:
	ldda	[REALSRC]ASI_FL8_P, %d34
	inc	REALSRC
	andcc	REALSRC, 7, %g0
	bnz	%ncc, .med5
	  bshuffle %d32, %d34, %d32 ! shifts d32 left 1 byte and or's in d34

.beginmedloop:
	tst	TMP
	bz	%ncc, .endmedloop
	  sub	CNT, TMP, CNT		! update count for later

	! Main loop to write out doubles.  Note: TMP & 7 == 0

	ldd	[REALSRC], %d34
	subcc	TMP, 8, TMP		! update local count
	bz,pn	%ncc, .medloop1
	add	REALSRC, 8, REALSRC	! update REALSRC

.medloop:
	faligndata %d32, %d34, %d36
	ldda	[REALSRC]%asi, %d32
	subcc	TMP, 8, TMP		! update local count
	add	REALSRC, 16, REALSRC	! update REALSRC
	std	%d36, [DST]
	bz,pn	%ncc, .medloop2
	faligndata %d34, %d32, %d38
	ldda	[REALSRC - 8]%asi, %d34
	subcc	TMP, 8, TMP		! update local count
	std	%d38, [DST + 8]
	bnz,pt	%ncc, .medloop
	add	DST, 16, DST		! update DST

.medloop1:
	faligndata %d32, %d34, %d36
	fsrc1	%d34, %d32
	std	%d36, [DST]
	ba	.endmedloop
	add	DST, 8, DST

.medloop2:
	std	%d38, [DST + 8]
	sub	REALSRC, 8, REALSRC
	add	DST, 16, DST


.endmedloop:
	! Currently, i0 is pointing to the next double-aligned byte in REALSRC
	! The 8 bytes starting at [REALSRC-8] are available in d32
	! At least one, and possibly all, of these need to be written.

	cmp	CNT, VIS_BLOCKSIZE
	bgu	%ncc, .large		! otherwise, less than 16 bytes left

	andcc	SRC, 7, TMP		! Number of bytes needed to completely
					! fill %d32 with good (unwritten) data.
	bz	%ncc, .medpst2
	  sub	TMP, 8, SRC		! -(number of good bytes in %d32)
	cmp	CNT, 8
	bl,a	%ncc, .medpst3		! Not enough bytes to fill %d32
	add	REALSRC, SRC, REALSRC 	! Back up REALSRC

.medpst1:
	deccc	TMP
	ldda	[REALSRC]ASI_FL8_P, %d34
	inc	REALSRC
	bgu	%ncc, .medpst1
	  bshuffle %d32, %d34, %d32 ! shifts d32 left 1 byte and or's in d34

.medpst2:
	subcc	CNT, 8, CNT
	std	%d32, [DST]
	bz	%ncc, .mediumexit
	  add	DST, 8, DST

.medpst3:
	ldub	[REALSRC], SRC
	deccc	CNT
	inc	REALSRC
	stb	SRC, [DST]
	bgu	%ncc, .medpst3
	  inc	DST

.mediumexit:
	ba,pt	%ncc, .bcb_exit
	  nop

	.align	ICACHE_LINE_SIZE
.large:
	! The following test for BSTORE_SIZE is used to decide whether
	! to store data with a block store or with individual stores.
	! The block store wins when the amount of data is so large
	! that it is causes other application data to be moved out
	! of the L1 or L2 cache.
	! On a Panther, block store can lose more often because block
	! store forces the stored data to be removed from the L3 cache.
	!
	sethi   %hi(BSTORE_SIZE), TMP
	or      TMP, %lo(BSTORE_SIZE), TMP
	cmp     CNT, TMP
	bgu     %ncc, .xlarge

	! DST     I/O Destination is 64-byte aligned
	! REALSRC I/O Source is 8-byte aligned (and we've set GSR.ALIGN)
	! %d32     I/O Already loaded with Source data from [REALSRC-8]
	! CNT     I/O Count (number of bytes that need to be written)
	! SRC     I   Not written. If zero, then REALSRC is double aligned.
	! TMP     O   The number of doubles that remain to be written.

	! Load the rest of the current block
	! Recall that REALSRC is further into source buffer
	! than DST is into the destination buffer.

	prefetch [DST + (0 * VIS_BLOCKSIZE)], #n_writes
	prefetch [DST + (1 * VIS_BLOCKSIZE)], #n_writes
	prefetch [DST + (2 * VIS_BLOCKSIZE)], #n_writes
	ldda	[REALSRC]%asi, %d34
	prefetch [REALSRC + (3 * VIS_BLOCKSIZE)], #one_read
	ldda	[REALSRC + 0x08]%asi, %d36
	faligndata %d32, %d34, %d48
	ldda	[REALSRC + 0x10]%asi, %d38
	faligndata %d34, %d36, %d50
	ldda	[REALSRC + 0x18]%asi, %d40
	faligndata %d36, %d38, %d52
	ldda	[REALSRC + 0x20]%asi, %d42
	or	%g0, -8, TMP	! if SRC >=0, TMP = -8
	prefetch [REALSRC + (4 * VIS_BLOCKSIZE)], #one_read
	faligndata %d38, %d40, %d54
	ldda	[REALSRC + 0x28]%asi, %d44
	movrlz	SRC, %g0, TMP	! if SRC < 0, TMP = 0  (needed later)
	faligndata %d40, %d42, %d56
	ldda	[REALSRC + 0x30]%asi, %d46
	faligndata %d42, %d44, %d58
	ldda	[REALSRC + 0x38]%asi, %d32
	sub	CNT, VIS_BLOCKSIZE, CNT
	prefetch [REALSRC + (5 * VIS_BLOCKSIZE)], #one_read
	add	REALSRC, VIS_BLOCKSIZE, REALSRC	! update REALSRC

	! Main loop.  Write previous block.  Load rest of current block.
	! Some bytes will be loaded that won't yet be written.
.large1:
	ldda	[REALSRC]%asi, %d34
	faligndata %d44, %d46, %d60
	ldda	[REALSRC + 0x08]%asi, %d36
	faligndata %d46, %d32, %d62
	std     %d48, [DST]
	std     %d50, [DST+8]
	std     %d52, [DST+16]
	std     %d54, [DST+24]
	std     %d56, [DST+32]
	std     %d58, [DST+40]
	std     %d60, [DST+48]
	std     %d62, [DST+56]
	sub     CNT, VIS_BLOCKSIZE, CNT		! update count
	prefetch [DST + (6 * VIS_BLOCKSIZE)], #n_writes
	prefetch [DST + (3 * VIS_BLOCKSIZE)], #n_writes
	add     DST, VIS_BLOCKSIZE, DST		! update DST
	ldda	[REALSRC + 0x10]%asi, %d38
	faligndata %d32, %d34, %d48
	ldda	[REALSRC + 0x18]%asi, %d40
	faligndata %d34, %d36, %d50
	ldda	[REALSRC + 0x20]%asi, %d42
	faligndata %d36, %d38, %d52
	ldda	[REALSRC + 0x28]%asi, %d44
	faligndata %d38, %d40, %d54
	ldda	[REALSRC + 0x30]%asi, %d46
	faligndata %d40, %d42, %d56
	ldda	[REALSRC + 0x38]%asi, %d32
	faligndata %d42, %d44, %d58
	cmp	CNT, VIS_BLOCKSIZE + 8
	prefetch [REALSRC + (5 * VIS_BLOCKSIZE)], #one_read
	bgu,pt	%ncc, .large1
	  add	REALSRC, VIS_BLOCKSIZE, REALSRC

	faligndata %d44, %d46, %d60
	faligndata %d46, %d32, %d62
	stda	%d48, [DST]ASI_BLK_P	! store 64 bytes, bypass cache
	cmp	CNT, VIS_BLOCKSIZE
	bne	%ncc, .large2		! exactly 1 blk remaining?
	  add	DST, VIS_BLOCKSIZE, DST	! update DST

	brz,a	SRC, .large3		! is SRC double aligned ?
	  ldd	[REALSRC], %d34

.large2:
	add	TMP, CNT, TMP		! TMP was already set to 0 or -8
	add	TMP, SRC, TMP

	ba	.beginmedloop
	  andn	TMP, 7, TMP

.large3:
	ldd	[REALSRC + 0x08], %d36
	ldd	[REALSRC + 0x10], %d38
	ldd	[REALSRC + 0x18], %d40
	ldd	[REALSRC + 0x20], %d42
	ldd	[REALSRC + 0x28], %d44
	ldd	[REALSRC + 0x30], %d46
	! Don't need to load [REALSRC + 0x38] since we were
	! already 8 bytes ahead in REALSRC to start with.
	stda	%d32, [DST]ASI_BLK_P

	ba,a,pt	%ncc, .bcb_exit
	  nop

	.align 16
	! two nops here causes loop starting at .xlarge1 below to be
	! on a cache line boundary, improving performance
	nop
	nop
.xlarge:
	! DST     I/O Destination is 64-byte aligned
	! REALSRC I/O Source is 8-byte aligned (and we've set GSR.ALIGN)
	! %d32     I/O Already loaded with Source data from [REALSRC-8]
	! CNT     I/O Count (number of bytes that need to be written)
	! SRC     I   Not written. If zero, then REALSRC is double aligned.
	! TMP     O   The number of doubles that remain to be written.

	! Load the rest of the current block
	! Recall that REALSRC is further into source buffer
	! than DST is into the destination buffer.

	! prefetch [REALSRC + (3 * VIS_BLOCKSIZE)], #one_read
	! executed in delay slot for branch to .xlarge
	prefetch [REALSRC + (4 * VIS_BLOCKSIZE)], #one_read
	prefetch [REALSRC + (5 * VIS_BLOCKSIZE)], #one_read
	ldda    [REALSRC]%asi, %d34
	prefetch [REALSRC + (6 * VIS_BLOCKSIZE)], #one_read
	ldda    [REALSRC + 0x8]%asi, %d36
	faligndata %d32, %d34, %d48
	ldda    [REALSRC + 0x10]%asi, %d38
	faligndata %d34, %d36, %d50
	ldda    [REALSRC + 0x18]%asi, %d40
	faligndata %d36, %d38, %d52
	ldda    [REALSRC + 0x20]%asi, %d42
	or      %g0, -8, TMP            ! if SRC >= 0, TMP = -8
	faligndata %d38, %d40, %d54
	ldda    [REALSRC + 0x28]%asi, %d44
	movrlz  SRC, %g0, TMP           ! if SRC < 0, TMP = 0  (needed later)
	faligndata %d40, %d42, %d56
	ldda    [REALSRC + 0x30]%asi, %d46
	faligndata %d42, %d44, %d58
	ldda    [REALSRC + 0x38]%asi, %d32
	sub     CNT, VIS_BLOCKSIZE, CNT    ! update count
	prefetch [REALSRC + (7 * VIS_BLOCKSIZE)], #one_read
	add     REALSRC, VIS_BLOCKSIZE, REALSRC    ! update REALSRC

	! This point is 32-byte aligned since 24 instructions appear since
	! the previous alignment directive.


	! Main loop.  Write previous block.  Load rest of current block.
	! Some bytes will be loaded that won't yet be written.
.xlarge1:
	ldda    [REALSRC]%asi, %d34
	faligndata %d44, %d46, %d60
	ldda    [REALSRC + 0x8]%asi, %d36
	faligndata %d46, %d32, %d62
	stda    %d48, [DST]ASI_BLK_P
	sub     CNT, VIS_BLOCKSIZE, CNT            ! update count
	ldda    [REALSRC + 0x10]%asi, %d38
	faligndata %d32, %d34, %d48
	ldda    [REALSRC + 0x18]%asi, %d40
	faligndata %d34, %d36, %d50
	ldda    [REALSRC + 0x20]%asi, %d42
	faligndata %d36, %d38, %d52
	ldda    [REALSRC + 0x28]%asi, %d44
	faligndata %d38, %d40, %d54
	ldda    [REALSRC + 0x30]%asi, %d46
	faligndata %d40, %d42, %d56
	ldda    [REALSRC + 0x38]%asi, %d32
	faligndata %d42, %d44, %d58
	! offset of 8*BLK+8 bytes works best over range of (src-dst) mod 1K
	prefetch [REALSRC + (8 * VIS_BLOCKSIZE) + 8], #one_read
	add     DST, VIS_BLOCKSIZE, DST            ! update DST
	cmp     CNT, VIS_BLOCKSIZE + 8
	! second prefetch important to correct for occasional dropped
	! initial prefetches, 5*BLK works best over range of (src-dst) mod 1K
	! strong prefetch prevents drops on Panther, but Jaguar and earlier
	! US-III models treat strong prefetches as weak prefetchs
	! to avoid regressions on customer hardware, we retain the prefetch
	prefetch [REALSRC + (5 * VIS_BLOCKSIZE)], #one_read
	bgu,pt	%ncc, .xlarge1
	  add	REALSRC, VIS_BLOCKSIZE, REALSRC	! update REALSRC
	faligndata %d44, %d46, %d60
	faligndata %d46, %d32, %d62
	stda	%d48, [DST]ASI_BLK_P	! store 64 bytes, bypass cache
	cmp	CNT, VIS_BLOCKSIZE
	bne	%ncc, .xlarge2		! exactly 1 block remaining?
	  add	DST, VIS_BLOCKSIZE, DST	! update DST
	brz,a	SRC, .xlarge3		! is SRC double aligned?
	  ldd	[REALSRC], %d34
.xlarge2:
	add	TMP, CNT, TMP		! TMP was already set to 0 or -8
	add	TMP, SRC, TMP

	ba	.beginmedloop
	  andn	TMP, 7, TMP		! 8 byte aligned count

 
	! This is when there is exactly 1 block remaining
	! and Source is aligned
.xlarge3:
	ldd     [REALSRC + 0x08], %d36
	ldd     [REALSRC + 0x10], %d38
	ldd     [REALSRC + 0x18], %d40
	ldd     [REALSRC + 0x20], %d42
	ldd     [REALSRC + 0x28], %d44
	ldd     [REALSRC + 0x30], %d46
	! Don't need to load [REALSRC + 0x38] since we were
	! already 8 bytes ahead in REALSRC to start with.
	stda    %d32, [DST]ASI_BLK_P

.bcb_exit:
	membar	#Sync

	ldx	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2	! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	! No need to save regs if either FEF or DU are clear
    	and	%o3, FPRS_FEF|FPRS_DU, %o2
	xorcc   %o2, FPRS_FEF|FPRS_DU, %g0
	bnz,pt  %icc, 4f
	  nop

	BLD_FPQ3Q4_FROMSTACK(%o2)

	ba,pt	%ncc, 5f
	  wr	%o3, 0, %fprs		! restore fprs
4:
	FZEROQ3Q4
	wr	%o3, 0, %fprs		! restore fprs
5:
	mov	%g5, %o0		! copy dest address
	call	rock_sync_icache
	mov	%g2, %o1		! saved size

	membar	#Sync				! sync error barrier
	andn	%l6, MASK_FLAGS, %l6
	stn	%l6, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	FP_ALLOWMIGRATE(5, 6)
	ret
	  restore	%g0, 0, %o0

	SET_SIZE(bcopy_more)

#endif	/* lint */

/*
 * Block copy with possibly overlapped operands.
 */

#if defined(lint)

/*ARGSUSED*/
void
ovbcopy(const void *from, void *to, size_t count)
{}

#else	/* lint */

	ENTRY(ovbcopy)
	tst	%o2			! check count
	bgu,a	%ncc, 1f		! nothing to do or bad arguments
	  subcc	%o0, %o1, %o3		! difference of from and to address

	retl				! return
	  nop
1:
	bneg,a	%ncc, 2f
	  neg	%o3			! if < 0, make it positive
2:	cmp	%o2, %o3		! cmp size and abs(from - to)
	bleu	%ncc, bcopy		! if size <= abs(diff): use bcopy,
	  .empty				!   no overlap
	  cmp	%o0, %o1		! compare from and to addresses
	blu	%ncc, .ov_bkwd		! if from < to, copy backwards
	  nop
	!
	! Copy forwards.
	!
.ov_fwd:
	ldub	[%o0], %o3		! read from address
	inc	%o0			! inc from address
	stb	%o3, [%o1]		! write to address
	deccc	%o2			! dec count
	bgu	%ncc, .ov_fwd		! loop till done
	  inc	%o1			! inc to address

	retl				! return
	  nop
	!
	! Copy backwards.
	!
.ov_bkwd:
	deccc	%o2			! dec count
	ldub	[%o0 + %o2], %o3	! get byte at end of src
	bgu	%ncc, .ov_bkwd		! loop till done
	  stb	%o3, [%o1 + %o2]	! delay slot, store at end of dst

	retl				! return
	  nop

	SET_SIZE(ovbcopy)

#endif	/* lint */


/*
 * hwblkpagecopy()
 *
 * Copies exactly one page.  This routine assumes the caller (ppcopy)
 * has already disabled kernel preemption and has checked
 * use_hw_bcopy.  Preventing preemption also prevents cpu migration.
 */
#ifdef lint
/*ARGSUSED*/
void
hwblkpagecopy(const void *src, void *dst)
{ }
#else /* lint */
	ENTRY(hwblkpagecopy)
	! get another window w/space for three aligned blocks of saved fpregs
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp

	! %i0 - source address (arg)
	! %i1 - destination address (arg)
	! %i2 - length of region (not arg)
	! %l0 - saved fprs
	! %l1 - pointer to saved fpregs

	rd	%fprs, %l0		! check for unused fp

	! FPU enabled ?  If not, enable it.
	btst	FPRS_FEF, %l0
	bz,a,pt	%icc, 1f
	  wr	%g0, FPRS_FEF, %fprs

	! FPU enabled, but is Q3Q4 dirty ?  If yes, save them.
	btst	FPRS_DU, %l0
	bz,pn	%icc, 1f
	  nop

	BST_FPQ3Q4_TOSTACK(%l1)

1:	set	PAGESIZE, CNT
	mov	%i1, %o0		! store destination address for flushing
	mov	REALSRC, SRC

	prefetch [SRC], #one_read
	prefetch [SRC + (1 * VIS_BLOCKSIZE)], #one_read
	prefetch [SRC + (2 * VIS_BLOCKSIZE)], #one_read
	prefetch [SRC + (3 * VIS_BLOCKSIZE)], #one_read
	ldd	[SRC], %d32
#if FIRST_PREFETCH > 4
	prefetch [SRC + (4 * VIS_BLOCKSIZE)], #one_read
#endif
	ldd	[SRC + 0x08], %d34
#if FIRST_PREFETCH > 5
	prefetch [SRC + (5 * VIS_BLOCKSIZE)], #one_read
#endif
	ldd	[SRC + 0x10], %d36
#if FIRST_PREFETCH > 6
	prefetch [SRC + (6 * VIS_BLOCKSIZE)], #one_read
#endif
	faligndata %d32, %d34, %d48
	ldd	[SRC + 0x18], %d38
#if FIRST_PREFETCH > 7
	prefetch [SRC + (7 * VIS_BLOCKSIZE)], #one_read
#endif
	faligndata %d34, %d36, %d50
	ldd	[SRC + 0x20], %d40
	faligndata %d36, %d38, %d52
	ldd	[SRC + 0x28], %d42
	faligndata %d38, %d40, %d54
	ldd	[SRC + 0x30], %d44
	faligndata %d40, %d42, %d56
	ldd	[SRC + 0x38], %d46
	faligndata %d42, %d44, %d58
	ldd	[SRC + VIS_BLOCKSIZE], %d32
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	SRC, VIS_BLOCKSIZE, SRC
	ba,a,pt	%ncc, 2f
	  nop
	.align	ICACHE_LINE_SIZE
2:
	ldd	[SRC + 0x08], %d34
	faligndata %d44, %d46, %d60
	ldd	[SRC + 0x10], %d36
	faligndata %d46, %d32, %d62
	stda	%d48, [DST]ASI_BLK_P
	ldd	[SRC + 0x18], %d38
	faligndata %d32, %d34, %d48
	ldd	[SRC + 0x20], %d40
	faligndata %d34, %d36, %d50
	ldd	[SRC + 0x28], %d42
	faligndata %d36, %d38, %d52
	ldd	[SRC + 0x30], %d44
	faligndata %d38, %d40, %d54
	ldd	[SRC + 0x38], %d46
	faligndata %d40, %d42, %d56
	ldd	[SRC + VIS_BLOCKSIZE], %d32
	faligndata %d42, %d44, %d58
	prefetch [SRC + ((FIRST_PREFETCH) * VIS_BLOCKSIZE) + 8], #one_read
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST
	cmp	CNT, VIS_BLOCKSIZE + 8
	prefetch [SRC + ((SECOND_PREFETCH) * VIS_BLOCKSIZE)], #one_read
	bgu,pt	%ncc, 2b
	  add	SRC, VIS_BLOCKSIZE, SRC

	! trailing block
	ldd	[SRC + 0x08], %d34
	faligndata %d44, %d46, %d60
	ldd	[SRC + 0x10], %d36
	faligndata %d46, %d32, %d62
	stda	%d48, [DST]ASI_BLK_P
	ldd	[SRC + 0x18], %d38
	ldd	[SRC + 0x20], %d40
	ldd	[SRC + 0x28], %d42
	ldd	[SRC + 0x30], %d44
	ldd	[SRC + 0x38], %d46
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST
	add	SRC, VIS_BLOCKSIZE, SRC
	stda	%d32, [DST]ASI_BLK_P

	set	PAGESIZE, %o1
	call	rock_sync_icache
	nop

	membar	#Sync

	btst	FPRS_DU, %l0
	bz,pt	%icc, 2f
	  nop

	BLD_FPQ3Q4_FROMSTACK(%l3)
	ba	3f
	  nop

2:	FZEROQ3Q4

3:	wr	%l0, 0, %fprs		! restore fprs
	ret
	  restore	%g0, 0, %o0

	SET_SIZE(hwblkpagecopy)
#endif	/* lint */


/*
 * Transfer data to and from user space -
 * Note that these routines can cause faults
 * It is assumed that the kernel has nothing at
 * less than KERNELBASE in the virtual address space.
 *
 * Note that copyin(9F) and copyout(9F) are part of the
 * DDI/DKI which specifies that they return '-1' on "errors."
 *
 * Sigh.
 *
 * So there's two extremely similar routines - xcopyin() and xcopyout()
 * which return the errno that we've faithfully computed.  This
 * allows other callers (e.g. uiomove(9F)) to work correctly.
 * Given that these are used pretty heavily, we expand the calling
 * sequences inline for all flavours (rather than making wrappers).
 *
 * There are also stub routines for xcopyout_little and xcopyin_little,
 * which currently are intended to handle requests of <= 16 bytes from
 * do_unaligned. Future enhancement to make them handle 8k pages efficiently
 * is left as an exercise...
 */

/*
 * Copy user data to kernel space (copyOP/xcopyOP/copyOP_noerr)
 *	
 * General theory of operation:
 *
 * The only difference between copy{in,out} and
 * xcopy{in,out} is in the error handling routine they invoke
 * when a memory access error occurs. xcopyOP returns the errno
 * while copyOP returns -1 (see above). copy{in,out}_noerr set
 * a special flag (by oring the TRAMP_FLAG into the fault handler address)
 * if they are called with a fault handler already in place. That flag
 * causes the default handlers to trampoline to the previous handler
 * upon an error.
 *
 * None of the copyops routines grab a window until it's decided that
 * we need to do a HW block copy operation. This saves a window
 * spill/fill when we're called during socket ops. The typical IO
 * path won't cause spill/fill traps.
 *
 * This code uses a set of 4 limits for the maximum size that will
 * be copied given a particular input/output address alignment.
 * If the value for a particular limit is zero, the copy will be performed
 * by the plain copy loops rather than FPBLK.
 *
 * See the description of bcopy above for more details of the
 * data copying algorithm and the default limits.
 *
 */

/*
 * Copy kernel data to user space (copyout/xcopyout/xcopyout_little).
 */

#if defined(lint)


#else	/* lint */
/*
 * We save the arguments in the following registers in case of a fault:
 *	kaddr - %l1
 *	uaddr - %l2
 *	count - %l3
 */
#define SAVE_SRC	%l1
#define SAVE_DST	%l2
#define SAVE_COUNT	%l3

#define SM_SAVE_SRC		%g4
#define SM_SAVE_DST		%g5
#define SM_SAVE_COUNT		%o5
#define ERRNO		%l5


#define REAL_LOFAULT	%l4
/*
 * Generic copyio fault handler.  This is the first line of defense when a
 * fault occurs in (x)copyin/(x)copyout.  In order for this to function
 * properly, the value of the 'real' lofault handler should be in REAL_LOFAULT.
 * This allows us to share common code for all the flavors of the copy
 * operations, including the _noerr versions.
 *
 * Note that this function will restore the original input parameters before
 * calling REAL_LOFAULT.  So the real handler can vector to the appropriate
 * member of the t_copyop structure, if needed.
 */
	ENTRY(copyio_fault)
	membar	#Sync
	mov	%g1,ERRNO			! save errno in ERRNO
	btst	FPUSED_FLAG, %l6
	bz	%ncc, 1f
	  nop

	ldx	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2
	wr	%o2, 0, %gsr    	! restore gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_DU, %o3
	bz,pt	%icc, 4f
	  nop

	BLD_FPQ3Q4_FROMSTACK(%o2)

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs   	! restore fprs

4:
	FZEROQ3Q4
	wr	%o3, 0, %fprs   	! restore fprs

1:
	andn	%l6, FPUSED_FLAG, %l6
	membar	#Sync
	stn	%l6, [THREAD_REG + T_LOFAULT]   ! restore old t_lofault
	FP_ALLOWMIGRATE(5, 6)

	mov	SAVE_SRC, %i0
	mov	SAVE_DST, %i1
	jmp	REAL_LOFAULT
	  mov	SAVE_COUNT, %i2

	SET_SIZE(copyio_fault)


#endif

#if defined(lint)

/*ARGSUSED*/
int
copyout(const void *kaddr, void *uaddr, size_t count)
{ return (0); }

#else	/* lint */

	ENTRY(copyout)

	cmp	%o2, VIS_COPY_THRESHOLD		! check for leaf rtn case
	bleu,pt	%ncc, .copyout_small		! go to larger cases
	  xor	%o0, %o1, %o3			! are src, dst alignable?
	btst	7, %o3				!
	bz,pt	%ncc, .copyout_8		! check for longword alignment
	  nop
	btst	1, %o3				! 
	bz,pt	%ncc, .copyout_2		! check for half-word
	  nop
	sethi	%hi(hw_copy_limit_1), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_1)], %o3
	tst	%o3
	bz,pn	%icc, .copyout_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyout_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyout_more		! otherwise go to large copy
	  nop
.copyout_2:
	btst	3, %o3				!
	bz,pt	%ncc, .copyout_4		! check for word alignment
	  nop
	sethi	%hi(hw_copy_limit_2), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_2)], %o3
	tst	%o3
	bz,pn	%icc, .copyout_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyout_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyout_more		! otherwise go to large copy
	  nop
.copyout_4:
	! already checked longword, must be word aligned
	sethi	%hi(hw_copy_limit_4), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_4)], %o3
	tst	%o3
	bz,pn	%icc, .copyout_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyout_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyout_more		! otherwise go to large copy
	  nop
.copyout_8:
	sethi	%hi(hw_copy_limit_8), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_8)], %o3
	tst	%o3
	bz,pn	%icc, .copyout_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyout_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyout_more		! otherwise go to large copy
	  nop

	.align	16
	nop				! instruction alignment
					! see discussion at start of file
.copyout_small:
	sethi	%hi(.sm_copyout_err), %o5	! .sm_copyout_err is lofault
	or	%o5, %lo(.sm_copyout_err), %o5
	ldn	[THREAD_REG + T_LOFAULT], %o4	! save existing handler
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! set t_lofault
.sm_do_copyout:
	mov	%o0, SM_SAVE_SRC
	mov	%o1, SM_SAVE_DST
	cmp	%o2, SHORTCOPY		! check for really short case
	bleu,pt	%ncc, .co_sm_left	!
	  mov	%o2, SM_SAVE_COUNT
	cmp	%o2, CHKSIZE		! check for medium length cases
	bgu,pn	%ncc, .co_med		!
	  or	%o0, %o1, %o3		! prepare alignment check
	andcc	%o3, 0x3, %g0		! test for alignment
	bz,pt	%ncc, .co_sm_word	! branch to word aligned case
.co_sm_movebytes:
	  sub	%o2, 3, %o2		! adjust count to allow cc zero test
.co_sm_notalign4:
	ldub	[%o0], %o3		! read byte
	subcc	%o2, 4, %o2		! reduce count by 4
	stba	%o3, [%o1]ASI_USER	! write byte
	inc	%o1			! advance DST by 1
	ldub	[%o0 + 1], %o3		! repeat for a total of 4 bytes
	add	%o0, 4, %o0		! advance SRC by 4
	stba	%o3, [%o1]ASI_USER
	inc	%o1			! advance DST by 1
	ldub	[%o0 - 2], %o3
	stba	%o3, [%o1]ASI_USER
	inc	%o1			! advance DST by 1
	ldub	[%o0 - 1], %o3
	stba	%o3, [%o1]ASI_USER
	bgt,pt	%ncc, .co_sm_notalign4	! loop til 3 or fewer bytes remain
	  inc	%o1			! advance DST by 1
	add	%o2, 3, %o2		! restore count
.co_sm_left:
	tst	%o2
	bz,pt	%ncc, .co_sm_exit	! check for zero length
	  nop
	ldub	[%o0], %o3		! load one byte
	deccc	%o2			! reduce count for cc test
	bz,pt	%ncc, .co_sm_exit
	  stba	%o3,[%o1]ASI_USER	! store one byte
	ldub	[%o0 + 1], %o3		! load second byte
	deccc	%o2
	inc	%o1
	bz,pt	%ncc, .co_sm_exit
	  stba	%o3,[%o1]ASI_USER	! store second byte
	ldub	[%o0 + 2], %o3		! load third byte
	inc	%o1
	stba	%o3,[%o1]ASI_USER	! store third byte
	membar	#Sync				! sync error barrier
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return 0
	.align	16
.co_sm_words:
	lduw	[%o0], %o3		! read word
.co_sm_wordx:
	subcc	%o2, 8, %o2		! update count
	stwa	%o3, [%o1]ASI_USER	! write word
	add	%o0, 8, %o0		! update SRC
	lduw	[%o0 - 4], %o3		! read word
	add	%o1, 4, %o1		! update DST
	stwa	%o3, [%o1]ASI_USER	! write word
	bgt,pt	%ncc, .co_sm_words	! loop til done
	  add	%o1, 4, %o1		! update DST
	addcc	%o2, 7, %o2		! restore count
	bz,pt	%ncc, .co_sm_exit
	  nop
	deccc	%o2
	bz,pt	%ncc, .co_sm_byte
.co_sm_half:
	  subcc	%o2, 2, %o2		! reduce count by 2
	lduh	[%o0], %o3		! read half word
	add	%o0, 2, %o0		! advance SRC by 2
	stha	%o3, [%o1]ASI_USER	! write half word
	bgt,pt	%ncc, .co_sm_half	! loop til done
	  add	%o1, 2, %o1		! advance DST by 2
	addcc	%o2, 1, %o2		! restore count
	bz,pt	%ncc, .co_sm_exit
	  nop
.co_sm_byte:
	ldub	[%o0], %o3
	stba	%o3, [%o1]ASI_USER
	membar	#Sync				! sync error barrier
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return 0
	.align 16
.co_sm_word:
	subcc	%o2, 4, %o2		! update count
	bgt,pt	%ncc, .co_sm_wordx
	  lduw	[%o0], %o3		! read word
	addcc	%o2, 3, %o2		! restore count
	bz,pt	%ncc, .co_sm_exit
	  stwa	%o3, [%o1]ASI_USER	! write word
	deccc	%o2			! reduce count for cc test
	ldub	[%o0 + 4], %o3		! load one byte
	add	%o1, 4, %o1
	bz,pt	%ncc, .co_sm_exit
	  stba	%o3, [%o1]ASI_USER	! store one byte
	ldub	[%o0 + 5], %o3		! load second byte
	deccc	%o2
	inc	%o1
	bz,pt	%ncc, .co_sm_exit
	  stba	%o3, [%o1]ASI_USER	! store second byte
	ldub	[%o0 + 6], %o3		! load third byte
	inc	%o1
	stba	%o3, [%o1]ASI_USER	! store third byte
.co_sm_exit:
	  membar	#Sync				! sync error barrier
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return 0

	.align 16
.co_med:
	xor	%o0, %o1, %o3		! setup alignment check
	btst	1, %o3
	bnz,pt	%ncc, .co_sm_movebytes	! unaligned
	  nop
	btst	3, %o3
	bnz,pt	%ncc, .co_med_half	! halfword aligned
	  nop
	btst	7, %o3
	bnz,pt	%ncc, .co_med_word	! word aligned
	  nop
.co_med_long:
	btst	3, %o0			! check for
	bz,pt	%ncc, .co_med_long1	! word alignment
	  nop
.co_med_long0:
	ldub	[%o0], %o3		! load one byte
	inc	%o0
	stba	%o3,[%o1]ASI_USER	! store byte
	inc	%o1
	btst	3, %o0
	bnz,pt	%ncc, .co_med_long0
	  dec	%o2
.co_med_long1:			! word aligned
	btst	7, %o0			! check for long word
	bz,pt	%ncc, .co_med_long2
	  nop
	lduw	[%o0], %o3		! load word
	add	%o0, 4, %o0		! advance SRC by 4
	stwa	%o3, [%o1]ASI_USER	! store word
	add	%o1, 4, %o1		! advance DST by 4
	sub	%o2, 4, %o2		! reduce count by 4
!
!  Now long word aligned and have at least 32 bytes to move
!
.co_med_long2:
	sub	%o2, 31, %o2		! adjust count to allow cc zero test
	sub	%o1, 8, %o1		! adjust pointer to allow store in
					! branch delay slot instead of add
.co_med_lmove:
	add	%o1, 8, %o1		! advance DST by 8
	ldx	[%o0], %o3		! read long word
	subcc	%o2, 32, %o2		! reduce count by 32
	stxa	%o3, [%o1]ASI_USER	! write long word
	add	%o1, 8, %o1		! advance DST by 8
	ldx	[%o0 + 8], %o3		! repeat for a total for 4 long words
	add	%o0, 32, %o0		! advance SRC by 32
	stxa	%o3, [%o1]ASI_USER
	ldx	[%o0 - 16], %o3
	add	%o1, 8, %o1		! advance DST by 8
	stxa	%o3, [%o1]ASI_USER
	ldx	[%o0 - 8], %o3
	add	%o1, 8, %o1		! advance DST by 8
	bgt,pt	%ncc, .co_med_lmove	! loop til 31 or fewer bytes left
	  stxa	%o3, [%o1]ASI_USER
	add	%o1, 8, %o1		! advance DST by 8
	addcc	%o2, 24, %o2		! restore count to long word offset
	ble,pt	%ncc, .co_med_lextra	! check for more long words to move
	  nop
.co_med_lword:
	ldx	[%o0], %o3		! read long word
	subcc	%o2, 8, %o2		! reduce count by 8
	stxa	%o3, [%o1]ASI_USER	! write long word
	add	%o0, 8, %o0		! advance SRC by 8
	bgt,pt	%ncc, .co_med_lword	! loop til 7 or fewer bytes left
	  add	%o1, 8, %o1		! advance DST by 8
.co_med_lextra:
	addcc	%o2, 7, %o2		! restore rest of count
	bz,pt	%ncc, .co_sm_exit	! if zero, then done
	  deccc	%o2
	bz,pt	%ncc, .co_sm_byte
	  nop
	ba,pt	%ncc, .co_sm_half
	  nop

	.align 16
	nop				! instruction alignment
					! see discussion at start of file
.co_med_word:
	btst	3, %o0			! check for
	bz,pt	%ncc, .co_med_word1	! word alignment
	  nop
.co_med_word0:
	ldub	[%o0], %o3		! load one byte
	inc	%o0
	stba	%o3,[%o1]ASI_USER	! store byte
	inc	%o1
	btst	3, %o0
	bnz,pt	%ncc, .co_med_word0
	  dec	%o2
!
!  Now word aligned and have at least 36 bytes to move
!
.co_med_word1:
	sub	%o2, 15, %o2		! adjust count to allow cc zero test
.co_med_wmove:
	lduw	[%o0], %o3		! read word
	subcc	%o2, 16, %o2		! reduce count by 16
	stwa	%o3, [%o1]ASI_USER	! write word
	add	%o1, 4, %o1		! advance DST by 4
	lduw	[%o0 + 4], %o3		! repeat for a total for 4 words
	add	%o0, 16, %o0		! advance SRC by 16
	stwa	%o3, [%o1]ASI_USER
	add	%o1, 4, %o1		! advance DST by 4
	lduw	[%o0 - 8], %o3
	stwa	%o3, [%o1]ASI_USER
	add	%o1, 4, %o1		! advance DST by 4
	lduw	[%o0 - 4], %o3
	stwa	%o3, [%o1]ASI_USER
	bgt,pt	%ncc, .co_med_wmove	! loop til 15 or fewer bytes left
	  add	%o1, 4, %o1		! advance DST by 4
	addcc	%o2, 12, %o2		! restore count to word offset
	ble,pt	%ncc, .co_med_wextra	! check for more words to move
	  nop
.co_med_word2:
	lduw	[%o0], %o3		! read word
	subcc	%o2, 4, %o2		! reduce count by 4
	stwa	%o3, [%o1]ASI_USER	! write word
	add	%o0, 4, %o0		! advance SRC by 4
	bgt,pt	%ncc, .co_med_word2	! loop til 3 or fewer bytes left
	  add	%o1, 4, %o1		! advance DST by 4
.co_med_wextra:
	addcc	%o2, 3, %o2		! restore rest of count
	bz,pt	%ncc, .co_sm_exit	! if zero, then done
	  deccc	%o2
	bz,pt	%ncc, .co_sm_byte
	  nop
	ba,pt	%ncc, .co_sm_half
	  nop

	.align 16
	nop				! instruction alignment
	nop				! see discussion at start of file
	nop
.co_med_half:
	btst	1, %o0			! check for
	bz,pt	%ncc, .co_med_half1	! half word alignment
	  nop
	ldub	[%o0], %o3		! load one byte
	inc	%o0
	stba	%o3,[%o1]ASI_USER	! store byte
	inc	%o1
	dec	%o2
!
!  Now half word aligned and have at least 38 bytes to move
!
.co_med_half1:
	sub	%o2, 7, %o2		! adjust count to allow cc zero test
.co_med_hmove:
	lduh	[%o0], %o3		! read half word
	subcc	%o2, 8, %o2		! reduce count by 8
	stha	%o3, [%o1]ASI_USER	! write half word
	add	%o1, 2, %o1		! advance DST by 2
	lduh	[%o0 + 2], %o3		! repeat for a total for 4 halfwords
	add	%o0, 8, %o0		! advance SRC by 8
	stha	%o3, [%o1]ASI_USER
	add	%o1, 2, %o1		! advance DST by 2
	lduh	[%o0 - 4], %o3
	stha	%o3, [%o1]ASI_USER
	add	%o1, 2, %o1		! advance DST by 2
	lduh	[%o0 - 2], %o3
	stha	%o3, [%o1]ASI_USER
	bgt,pt	%ncc, .co_med_hmove	! loop til 7 or fewer bytes left
	  add	%o1, 2, %o1		! advance DST by 2
	addcc	%o2, 7, %o2		! restore count
	bz,pt	%ncc, .co_sm_exit
	  deccc	%o2
	bz,pt	%ncc, .co_sm_byte
	  nop
	ba,pt	%ncc, .co_sm_half
	  nop

/*
 * We got here because of a fault during short copyout.
 * Errno value is in ERRNO, but DDI/DKI says return -1 (sigh).
 */
.sm_copyout_err:
	membar	#Sync
	stn	%o4, [THREAD_REG + T_LOFAULT]   ! restore old t_lofault
	mov	SM_SAVE_SRC, %o0
	mov	SM_SAVE_DST, %o1
	mov	SM_SAVE_COUNT, %o2
	ldn	[THREAD_REG + T_COPYOPS], %o3	! check for copyop handler
	tst	%o3
	bz,pt	%ncc, 3f			! if not, return error
	  nop
	ldn	[%o3 + CP_COPYOUT], %o5		! if handler, invoke it with
	jmp	%o5				! original arguments
	  nop
3:
	retl
	  or	%g0, -1, %o0		! return error value

	SET_SIZE(copyout)

/*
 * The _more entry points are not intended to be used directly by
 * any caller from outside this file.  They are provided to allow
 * profiling and dtrace of the portions of the copy code that uses
 * the floating point registers.
 * This entry is particularly important as DTRACE (at least as of
 * 4/2004) does not support leaf functions.
 */

	ENTRY(copyout_more)
.copyout_more:
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	set	.copyout_err, REAL_LOFAULT

/*
 * Copy outs that reach here are larger than VIS_COPY_THRESHOLD bytes
 */
.do_copyout:
        set     copyio_fault, %l7		! .copyio_fault is lofault val

	ldn	[THREAD_REG + T_LOFAULT], %l6	! save existing handler
	membar	#Sync				! sync error barrier
	stn	%l7, [THREAD_REG + T_LOFAULT]	! set t_lofault

	mov	%i0, SAVE_SRC
	mov	%i1, SAVE_DST
	mov	%i2, SAVE_COUNT

	FP_NOMIGRATE(6, 7)

	rd	%fprs, %o2		! check for unused fp
	st	%o2, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET] ! save orig %fprs

	! FPU enabled ?  If not, enable it.
	btst	FPRS_FEF, %o2
	bz,a,pt	%icc, .do_blockcopyout
	  wr	%g0, FPRS_FEF, %fprs

	! FPU enabled, but is Q3Q4 dirty ?  If yes, save them.
	btst	FPRS_DU, %o2
	bz,pn	%icc, .do_blockcopyout
	  nop

	BST_FPQ3Q4_TOSTACK(%o2)

.do_blockcopyout:
	rd	%gsr, %o2
	stx	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]	! save gsr
	or	%l6, FPUSED_FLAG, %l6

	andcc	DST, VIS_BLOCKSIZE - 1, TMP
	mov	ASI_USER, %asi
	bz,pt	%ncc, 2f
	  neg	TMP
	add	TMP, VIS_BLOCKSIZE, TMP

	! TMP = bytes required to align DST on FP_BLOCK boundary
	! Using SRC as a tmp here
	cmp	TMP, 3
	bleu,pt	%ncc, 1f
	  sub	CNT,TMP,CNT		! adjust main count
	sub	TMP, 3, TMP		! adjust for end of loop test
.co_blkalign:
	ldub	[REALSRC], SRC		! move 4 bytes per loop iteration
	stba	SRC, [DST]%asi
	subcc	TMP, 4, TMP
	ldub	[REALSRC + 1], SRC
	add	REALSRC, 4, REALSRC
	stba	SRC, [DST + 1]%asi
	ldub	[REALSRC - 2], SRC
	add	DST, 4, DST
	stba	SRC, [DST - 2]%asi
	ldub	[REALSRC - 1], SRC
	bgu,pt	%ncc, .co_blkalign
	  stba	SRC, [DST - 1]%asi

	addcc	TMP, 3, TMP		! restore count adjustment
	bz,pt	%ncc, 2f		! no bytes left?
	  nop
1:	ldub	[REALSRC], SRC
	inc	REALSRC
	inc	DST
	deccc	TMP
	bgu	%ncc, 1b
	  stba	SRC, [DST - 1]%asi

2:
	andn	REALSRC, 0x7, SRC
	alignaddr REALSRC, %g0, %g0

	! SRC - 8-byte aligned
	! DST - 64-byte aligned
	prefetch [SRC], #one_read
	prefetch [SRC + (1 * VIS_BLOCKSIZE)], #one_read
	prefetch [SRC + (2 * VIS_BLOCKSIZE)], #one_read
	prefetch [SRC + (3 * VIS_BLOCKSIZE)], #one_read
	ldd	[SRC], %d32
#if FIRST_PREFETCH > 4
	prefetch [SRC + (4 * VIS_BLOCKSIZE)], #one_read
#endif
	ldd	[SRC + 0x08], %d34
#if FIRST_PREFETCH > 5
	prefetch [SRC + (5 * VIS_BLOCKSIZE)], #one_read
#endif
	ldd	[SRC + 0x10], %d36
#if FIRST_PREFETCH > 6
	prefetch [SRC + (6 * VIS_BLOCKSIZE)], #one_read
#endif
	faligndata %d32, %d34, %d48
	ldd	[SRC + 0x18], %d38
#if FIRST_PREFETCH > 7
	prefetch [SRC + (7 * VIS_BLOCKSIZE)], #one_read
#endif
	faligndata %d34, %d36, %d50
	ldd	[SRC + 0x20], %d40
	faligndata %d36, %d38, %d52
	ldd	[SRC + 0x28], %d42
	faligndata %d38, %d40, %d54
	ldd	[SRC + 0x30], %d44
	faligndata %d40, %d42, %d56
	ldd	[SRC + 0x38], %d46
	faligndata %d42, %d44, %d58
	ldd	[SRC + VIS_BLOCKSIZE], %d32
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	SRC, VIS_BLOCKSIZE, SRC
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	ba,a,pt	%ncc, 1f
	  nop
	.align	ICACHE_LINE_SIZE
1:
	ldd	[SRC + 0x08], %d34
	faligndata %d44, %d46, %d60
	ldd	[SRC + 0x10], %d36
	faligndata %d46, %d32, %d62
	stda	%d48, [DST]ASI_BLK_AIUS
	ldd	[SRC + 0x18], %d38
	faligndata %d32, %d34, %d48
	ldd	[SRC + 0x20], %d40
	faligndata %d34, %d36, %d50
	ldd	[SRC + 0x28], %d42
	faligndata %d36, %d38, %d52
	ldd	[SRC + 0x30], %d44
	faligndata %d38, %d40, %d54
	ldd	[SRC + 0x38], %d46
	faligndata %d40, %d42, %d56
	sub	CNT, VIS_BLOCKSIZE, CNT
	ldd	[SRC + VIS_BLOCKSIZE], %d32
	faligndata %d42, %d44, %d58
	prefetch [SRC + ((FIRST_PREFETCH) * VIS_BLOCKSIZE) + 8], #one_read
	add	DST, VIS_BLOCKSIZE, DST
	prefetch [SRC + ((SECOND_PREFETCH) * VIS_BLOCKSIZE)], #one_read
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	cmp	CNT, VIS_BLOCKSIZE + 8
	bgu,pt	%ncc, 1b
	  add	SRC, VIS_BLOCKSIZE, SRC

	! only if REALSRC & 0x7 is 0
	cmp	CNT, VIS_BLOCKSIZE
	bne	%ncc, 3f
	  andcc	REALSRC, 0x7, %g0
	bz,pt	%ncc, 2f
	  nop
3:
	faligndata %d44, %d46, %d60
	faligndata %d46, %d32, %d62
	stda	%d48, [DST]ASI_BLK_AIUS
	add	DST, VIS_BLOCKSIZE, DST
	ba,pt	%ncc, 3f
	  nop
2:
	ldd	[SRC + 0x08], %d34
	faligndata %d44, %d46, %d60
	ldd	[SRC + 0x10], %d36
	faligndata %d46, %d32, %d62
	stda	%d48, [DST]ASI_BLK_AIUS
	ldd	[SRC + 0x18], %d38
	ldd	[SRC + 0x20], %d40
	ldd	[SRC + 0x28], %d42
	ldd	[SRC + 0x30], %d44
	ldd	[SRC + 0x38], %d46
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST
	add	SRC, VIS_BLOCKSIZE, SRC
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	stda	%d32, [DST]ASI_BLK_AIUS
	add	DST, VIS_BLOCKSIZE, DST
	ba,a,pt	%ncc, 4f
	  nop

3:	tst	CNT
	bz,a	%ncc, 4f
	  nop

5:	ldub	[REALSRC], TMP
	inc	REALSRC
	inc	DST
	deccc	CNT
	bgu	%ncc, 5b
	  stba	TMP, [DST - 1]%asi
4:

.copyout_exit:
	membar	#Sync

	ldx	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2
	wr	%o2, 0, %gsr		! restore gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_DU, %o3
	bz,pt	%icc, 4f
	  nop

	BLD_FPQ3Q4_FROMSTACK(%o2)

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZEROQ3Q4
	wr	%o3, 0, %fprs		! restore fprs

1:
	membar	#Sync
	andn	%l6, FPUSED_FLAG, %l6
	stn	%l6, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	FP_ALLOWMIGRATE(5, 6)
	ret
	  restore	%g0, 0, %o0

/*
 * We got here because of a fault during copyout.
 * Errno value is in ERRNO, but DDI/DKI says return -1 (sigh).
 */
.copyout_err:
	ldn	[THREAD_REG + T_COPYOPS], %o4	! check for copyop handler
	tst	%o4
	bz,pt	%ncc, 2f			! if not, return error
	  nop
	ldn	[%o4 + CP_COPYOUT], %g2		! if handler, invoke it with
	jmp	%g2				! original arguments
	  restore %g0, 0, %g0			! dispose of copy window
2:
        ret
	  restore %g0, -1, %o0			! return error value


	SET_SIZE(copyout_more)

#endif	/* lint */


#ifdef	lint

/*ARGSUSED*/
int
xcopyout(const void *kaddr, void *uaddr, size_t count)
{ return (0); }

#else	/* lint */

	ENTRY(xcopyout)
	cmp	%o2, VIS_COPY_THRESHOLD		! check for leaf rtn case
	bleu,pt	%ncc, .xcopyout_small		! go to larger cases
	  xor	%o0, %o1, %o3			! are src, dst alignable?
	btst	7, %o3				!
	bz,pt	%ncc, .xcopyout_8		!
	  nop
	btst	1, %o3				! 
	bz,pt	%ncc, .xcopyout_2		! check for half-word
	  nop
	sethi	%hi(hw_copy_limit_1), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_1)], %o3
	tst	%o3
	bz,pn	%icc, .xcopyout_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .xcopyout_small		! go to small copy
	  nop
	ba,pt	%ncc, .xcopyout_more		! otherwise go to large copy
	  nop
.xcopyout_2:
	btst	3, %o3				!
	bz,pt	%ncc, .xcopyout_4		! check for word alignment
	  nop
	sethi	%hi(hw_copy_limit_2), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_2)], %o3
	tst	%o3
	bz,pn	%icc, .xcopyout_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .xcopyout_small		! go to small copy
	  nop
	ba,pt	%ncc, .xcopyout_more		! otherwise go to large copy
	  nop
.xcopyout_4:
	! already checked longword, must be word aligned
	sethi	%hi(hw_copy_limit_4), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_4)], %o3
	tst	%o3
	bz,pn	%icc, .xcopyout_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .xcopyout_small		! go to small copy
	  nop
	ba,pt	%ncc, .xcopyout_more		! otherwise go to large copy
	  nop
.xcopyout_8:
	sethi	%hi(hw_copy_limit_8), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_8)], %o3
	tst	%o3
	bz,pn	%icc, .xcopyout_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .xcopyout_small		! go to small copy
	  nop
	ba,pt	%ncc, .xcopyout_more		! otherwise go to large copy
	  nop

.xcopyout_small:
	sethi	%hi(.sm_xcopyout_err), %o5	! .sm_xcopyout_err is lofault
	or	%o5, %lo(.sm_xcopyout_err), %o5
	ldn	[THREAD_REG + T_LOFAULT], %o4	! save existing handler
	membar	#Sync				! sync error barrier
	ba,pt	%ncc, .sm_do_copyout		! common code
	  stn	%o5, [THREAD_REG + T_LOFAULT]	! set t_lofault

.xcopyout_more:
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	sethi	%hi(.xcopyout_err), REAL_LOFAULT
	ba,pt	%ncc, .do_copyout		! common code
	  or	REAL_LOFAULT, %lo(.xcopyout_err), REAL_LOFAULT

/*
 * We got here because of fault during xcopyout
 * Errno value is in ERRNO
 */
.xcopyout_err:
	ldn	[THREAD_REG + T_COPYOPS], %o4	! check for copyop handler
	tst	%o4
	bz,pt	%ncc, 2f			! if not, return error
	  nop
	ldn	[%o4 + CP_XCOPYOUT], %g2	! if handler, invoke it with
	jmp	%g2				! original arguments
	  restore %g0, 0, %g0			! dispose of copy window
2:
        ret
	  restore ERRNO, 0, %o0			! return errno value

.sm_xcopyout_err:

	membar	#Sync
	stn	%o4, [THREAD_REG + T_LOFAULT]   ! restore old t_lofault
	mov	SM_SAVE_SRC, %o0
	mov	SM_SAVE_DST, %o1
	mov	SM_SAVE_COUNT, %o2
	ldn	[THREAD_REG + T_COPYOPS], %o3	! check for copyop handler
	tst	%o3
	bz,pt	%ncc, 3f			! if not, return error
	  nop
	ldn	[%o3 + CP_XCOPYOUT], %o5	! if handler, invoke it with
	jmp	%o5				! original arguments
	  nop
3:
	retl
	  or	%g1, 0, %o0		! return errno value

	SET_SIZE(xcopyout)

#endif	/* lint */
	
#ifdef	lint

/*ARGSUSED*/
int
xcopyout_little(const void *kaddr, void *uaddr, size_t count)
{ return (0); }

#else	/* lint */

	ENTRY(xcopyout_little)
	sethi	%hi(.xcopyio_err), %o5
	or	%o5, %lo(.xcopyio_err), %o5
	ldn	[THREAD_REG + T_LOFAULT], %o4
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]
	mov	%o4, %o5

	subcc	%g0, %o2, %o3
	add	%o0, %o2, %o0
	bz,pn	%ncc, 2f		! check for zero bytes
	  sub	%o2, 1, %o4
	add	%o0, %o4, %o0		! start w/last byte
	add	%o1, %o2, %o1
	ldub	[%o0 + %o3], %o4

1:	stba	%o4, [%o1 + %o3]ASI_AIUSL
	inccc	%o3
	sub	%o0, 2, %o0		! get next byte
	bcc,a,pt %ncc, 1b
	  ldub	[%o0 + %o3], %o4

2:
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return (0)

	SET_SIZE(xcopyout_little)

#endif	/* lint */

/*
 * Copy user data to kernel space (copyin/xcopyin/xcopyin_little)
 */

#if defined(lint)

/*ARGSUSED*/
int
copyin(const void *uaddr, void *kaddr, size_t count)
{ return (0); }

#else	/* lint */

	ENTRY(copyin)
	cmp	%o2, VIS_COPY_THRESHOLD		! check for leaf rtn case
	bleu,pt	%ncc, .copyin_small		! go to larger cases
	  xor	%o0, %o1, %o3			! are src, dst alignable?
	btst	7, %o3				!
	bz,pt	%ncc, .copyin_8			! check for longword alignment
	  nop
	btst	1, %o3				! 
	bz,pt	%ncc, .copyin_2			! check for half-word
	  nop
	sethi	%hi(hw_copy_limit_1), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_1)], %o3
	tst	%o3
	bz,pn	%icc, .copyin_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyin_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyin_more		! otherwise go to large copy
	  nop
.copyin_2:
	btst	3, %o3				!
	bz,pt	%ncc, .copyin_4			! check for word alignment
	  nop
	sethi	%hi(hw_copy_limit_2), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_2)], %o3
	tst	%o3
	bz,pn	%icc, .copyin_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyin_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyin_more		! otherwise go to large copy
	  nop
.copyin_4:
	! already checked longword, must be word aligned
	sethi	%hi(hw_copy_limit_4), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_4)], %o3
	tst	%o3
	bz,pn	%icc, .copyin_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyin_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyin_more		! otherwise go to large copy
	  nop
.copyin_8:
	sethi	%hi(hw_copy_limit_8), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_8)], %o3
	tst	%o3
	bz,pn	%icc, .copyin_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyin_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyin_more		! otherwise go to large copy
	  nop

	.align	16
	nop				! instruction alignment
					! see discussion at start of file
.copyin_small:
	sethi	%hi(.sm_copyin_err), %o5	! .sm_copyin_err is lofault 
	or	%o5, %lo(.sm_copyin_err), %o5
	ldn	[THREAD_REG + T_LOFAULT], %o4	! set/save t_lofault, no tramp
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]
.sm_do_copyin:
	mov	%o0, SM_SAVE_SRC
	mov	%o1, SM_SAVE_DST
	cmp	%o2, SHORTCOPY		! check for really short case
	bleu,pt	%ncc, .ci_sm_left	!
	  mov	%o2, SM_SAVE_COUNT
	cmp	%o2, CHKSIZE		! check for medium length cases
	bgu,pn	%ncc, .ci_med		!
	  or	%o0, %o1, %o3		! prepare alignment check
	andcc	%o3, 0x3, %g0		! test for alignment
	bz,pt	%ncc, .ci_sm_word	! branch to word aligned case
.ci_sm_movebytes:
	  sub	%o2, 3, %o2		! adjust count to allow cc zero test
.ci_sm_notalign4:
	lduba	[%o0]ASI_USER, %o3	! read byte
	subcc	%o2, 4, %o2		! reduce count by 4
	stb	%o3, [%o1]		! write byte
	add	%o0, 1, %o0		! advance SRC by 1
	lduba	[%o0]ASI_USER, %o3	! repeat for a total of 4 bytes
	add	%o0, 1, %o0		! advance SRC by 1
	stb	%o3, [%o1 + 1]
	add	%o1, 4, %o1		! advance DST by 4
	lduba	[%o0]ASI_USER, %o3
	add	%o0, 1, %o0		! advance SRC by 1
	stb	%o3, [%o1 - 2]
	lduba	[%o0]ASI_USER, %o3
	add	%o0, 1, %o0		! advance SRC by 1
	bgt,pt	%ncc, .ci_sm_notalign4	! loop til 3 or fewer bytes remain
	  stb	%o3, [%o1 - 1]
	add	%o2, 3, %o2		! restore count
.ci_sm_left:
	tst	%o2
	bz,pt	%ncc, .ci_sm_exit
	  nop
	lduba	[%o0]ASI_USER, %o3		! load one byte
	deccc	%o2			! reduce count for cc test
	bz,pt	%ncc, .ci_sm_exit
	  stb	%o3,[%o1]		! store one byte
	inc	%o0
	lduba	[%o0]ASI_USER, %o3	! load second byte
	deccc	%o2
	bz,pt	%ncc, .ci_sm_exit
	  stb	%o3,[%o1 + 1]		! store second byte
	inc	%o0
	lduba	[%o0]ASI_USER, %o3	! load third byte
	stb	%o3,[%o1 + 2]		! store third byte
	membar	#Sync				! sync error barrier
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return 0
	.align	16
.ci_sm_words:
	lduwa	[%o0]ASI_USER, %o3		! read word
.ci_sm_wordx:
	subcc	%o2, 8, %o2		! update count
	stw	%o3, [%o1]		! write word
	add	%o0, 4, %o0		! update SRC
	add	%o1, 8, %o1		! update DST
	lduwa	[%o0]ASI_USER, %o3	! read word
	add	%o0, 4, %o0		! update SRC
	bgt,pt	%ncc, .ci_sm_words	! loop til done
	  stw	%o3, [%o1 - 4]		! write word
	addcc	%o2, 7, %o2		! restore count
	bz,pt	%ncc, .ci_sm_exit
	  nop
	deccc	%o2
	bz,pt	%ncc, .ci_sm_byte
.ci_sm_half:
	  subcc	%o2, 2, %o2		! reduce count by 2
	lduha	[%o0]ASI_USER, %o3	! read half word
	add	%o0, 2, %o0		! advance SRC by 2
	add	%o1, 2, %o1		! advance DST by 2
	bgt,pt	%ncc, .ci_sm_half	! loop til done
	  sth	%o3, [%o1 - 2]		! write half word
	addcc	%o2, 1, %o2		! restore count
	bz,pt	%ncc, .ci_sm_exit
	  nop
.ci_sm_byte:
	lduba	[%o0]ASI_USER, %o3
	stb	%o3, [%o1]
	membar	#Sync				! sync error barrier
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return 0
	.align	16
.ci_sm_word:
	subcc	%o2, 4, %o2		! update count
	bgt,pt	%ncc, .ci_sm_wordx
	  lduwa	[%o0]ASI_USER, %o3		! read word
	addcc	%o2, 3, %o2		! restore count
	bz,pt	%ncc, .ci_sm_exit
	  stw	%o3, [%o1]		! write word
	deccc	%o2			! reduce count for cc test
	add	%o0, 4, %o0
	lduba	[%o0]ASI_USER, %o3	! load one byte
	bz,pt	%ncc, .ci_sm_exit
	  stb	%o3, [%o1 + 4]		! store one byte
	inc	%o0
	lduba	[%o0]ASI_USER, %o3	! load second byte
	deccc	%o2
	bz,pt	%ncc, .ci_sm_exit
	  stb	%o3, [%o1 + 5]		! store second byte
	inc	%o0
	lduba	[%o0]ASI_USER, %o3	! load third byte
	stb	%o3, [%o1 + 6]		! store third byte
.ci_sm_exit:
	membar	#Sync				! sync error barrier
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return 0

	.align 16
.ci_med:
	xor	%o0, %o1, %o3		! setup alignment check
	btst	1, %o3
	bnz,pt	%ncc, .ci_sm_movebytes	! unaligned
	  nop
	btst	3, %o3
	bnz,pt	%ncc, .ci_med_half	! halfword aligned
	  nop
	btst	7, %o3
	bnz,pt	%ncc, .ci_med_word	! word aligned
	  nop
.ci_med_long:
	btst	3, %o0			! check for
	bz,pt	%ncc, .ci_med_long1	! word alignment
	  nop
.ci_med_long0:
	lduba	[%o0]ASI_USER, %o3		! load one byte
	inc	%o0
	stb	%o3,[%o1]		! store byte
	inc	%o1
	btst	3, %o0
	bnz,pt	%ncc, .ci_med_long0
	  dec	%o2
.ci_med_long1:			! word aligned
	btst	7, %o0			! check for long word
	bz,pt	%ncc, .ci_med_long2
	  nop
	lduwa	[%o0]ASI_USER, %o3	! load word
	add	%o0, 4, %o0		! advance SRC by 4
	stw	%o3, [%o1]		! store word
	add	%o1, 4, %o1		! advance DST by 4
	sub	%o2, 4, %o2		! reduce count by 4
!
!  Now long word aligned and have at least 32 bytes to move
!
.ci_med_long2:
	sub	%o2, 31, %o2		! adjust count to allow cc zero test
.ci_med_lmove:
	ldxa	[%o0]ASI_USER, %o3	! read long word
	subcc	%o2, 32, %o2		! reduce count by 32
	stx	%o3, [%o1]		! write long word
	add	%o0, 8, %o0		! advance SRC by 8
	ldxa	[%o0]ASI_USER, %o3	! repeat for a total for 4 long words
	add	%o0, 8, %o0		! advance SRC by 8
	stx	%o3, [%o1 + 8]
	add	%o1, 32, %o1		! advance DST by 32
	ldxa	[%o0]ASI_USER, %o3
	add	%o0, 8, %o0		! advance SRC by 8
	stx	%o3, [%o1 - 16]
	ldxa	[%o0]ASI_USER, %o3
	add	%o0, 8, %o0		! advance SRC by 8
	bgt,pt	%ncc, .ci_med_lmove	! loop til 31 or fewer bytes left
	  stx	%o3, [%o1 - 8]
	addcc	%o2, 24, %o2		! restore count to long word offset
	ble,pt	%ncc, .ci_med_lextra	! check for more long words to move
	  nop
.ci_med_lword:
	ldxa	[%o0]ASI_USER, %o3	! read long word
	subcc	%o2, 8, %o2		! reduce count by 8
	stx	%o3, [%o1]		! write long word
	add	%o0, 8, %o0		! advance SRC by 8
	bgt,pt	%ncc, .ci_med_lword	! loop til 7 or fewer bytes left
	  add	%o1, 8, %o1		! advance DST by 8
.ci_med_lextra:
	addcc	%o2, 7, %o2		! restore rest of count
	bz,pt	%ncc, .ci_sm_exit	! if zero, then done
	  deccc	%o2
	bz,pt	%ncc, .ci_sm_byte
	  nop
	ba,pt	%ncc, .ci_sm_half
	  nop

	.align 16
	nop				! instruction alignment
					! see discussion at start of file
.ci_med_word:
	btst	3, %o0			! check for
	bz,pt	%ncc, .ci_med_word1	! word alignment
	  nop
.ci_med_word0:
	lduba	[%o0]ASI_USER, %o3	! load one byte
	inc	%o0
	stb	%o3,[%o1]		! store byte
	inc	%o1
	btst	3, %o0
	bnz,pt	%ncc, .ci_med_word0
	  dec	%o2
!
!  Now word aligned and have at least 36 bytes to move
!
.ci_med_word1:
	sub	%o2, 15, %o2		! adjust count to allow cc zero test
.ci_med_wmove:
	lduwa	[%o0]ASI_USER, %o3	! read word
	subcc	%o2, 16, %o2		! reduce count by 16
	stw	%o3, [%o1]		! write word
	add	%o0, 4, %o0		! advance SRC by 4
	lduwa	[%o0]ASI_USER, %o3	! repeat for a total for 4 words
	add	%o0, 4, %o0		! advance SRC by 4
	stw	%o3, [%o1 + 4]
	add	%o1, 16, %o1		! advance DST by 16
	lduwa	[%o0]ASI_USER, %o3
	add	%o0, 4, %o0		! advance SRC by 4
	stw	%o3, [%o1 - 8]
	lduwa	[%o0]ASI_USER, %o3
	add	%o0, 4, %o0		! advance SRC by 4
	bgt,pt	%ncc, .ci_med_wmove	! loop til 15 or fewer bytes left
	  stw	%o3, [%o1 - 4]
	addcc	%o2, 12, %o2		! restore count to word offset
	ble,pt	%ncc, .ci_med_wextra	! check for more words to move
	  nop
.ci_med_word2:
	lduwa	[%o0]ASI_USER, %o3	! read word
	subcc	%o2, 4, %o2		! reduce count by 4
	stw	%o3, [%o1]		! write word
	add	%o0, 4, %o0		! advance SRC by 4
	bgt,pt	%ncc, .ci_med_word2	! loop til 3 or fewer bytes left
	  add	%o1, 4, %o1		! advance DST by 4
.ci_med_wextra:
	addcc	%o2, 3, %o2		! restore rest of count
	bz,pt	%ncc, .ci_sm_exit	! if zero, then done
	  deccc	%o2
	bz,pt	%ncc, .ci_sm_byte
	  nop
	ba,pt	%ncc, .ci_sm_half
	  nop

	.align 16
	nop				! instruction alignment
					! see discussion at start of file
.ci_med_half:
	btst	1, %o0			! check for
	bz,pt	%ncc, .ci_med_half1	! half word alignment
	  nop
	lduba	[%o0]ASI_USER, %o3	! load one byte
	inc	%o0
	stb	%o3,[%o1]		! store byte
	inc	%o1
	dec	%o2
!
!  Now half word aligned and have at least 38 bytes to move
!
.ci_med_half1:
	sub	%o2, 7, %o2		! adjust count to allow cc zero test
.ci_med_hmove:
	lduha	[%o0]ASI_USER, %o3	! read half word
	subcc	%o2, 8, %o2		! reduce count by 8
	sth	%o3, [%o1]		! write half word
	add	%o0, 2, %o0		! advance SRC by 2
	lduha	[%o0]ASI_USER, %o3	! repeat for a total for 4 halfwords
	add	%o0, 2, %o0		! advance SRC by 2
	sth	%o3, [%o1 + 2]
	add	%o1, 8, %o1		! advance DST by 8
	lduha	[%o0]ASI_USER, %o3
	add	%o0, 2, %o0		! advance SRC by 2
	sth	%o3, [%o1 - 4]
	lduha	[%o0]ASI_USER, %o3
	add	%o0, 2, %o0		! advance SRC by 2
	bgt,pt	%ncc, .ci_med_hmove	! loop til 7 or fewer bytes left
	  sth	%o3, [%o1 - 2]
	addcc	%o2, 7, %o2		! restore count
	bz,pt	%ncc, .ci_sm_exit
	  deccc	%o2
	bz,pt	%ncc, .ci_sm_byte
	  nop
	ba,pt	%ncc, .ci_sm_half
	  nop

.sm_copyin_err:
	membar	#Sync
	stn	%o4, [THREAD_REG + T_LOFAULT]   ! restore old t_lofault
	mov	SM_SAVE_SRC, %o0
	mov	SM_SAVE_DST, %o1
	mov	SM_SAVE_COUNT, %o2
	ldn	[THREAD_REG + T_COPYOPS], %o3	! check for copyop handler
	tst	%o3
	bz,pt	%ncc, 3f			! if not, return error
	  nop
	ldn	[%o3 + CP_COPYIN], %o5		! if handler, invoke it with
	jmp	%o5				! original arguments
	  nop
3:
	retl
	  or	%g0, -1, %o0		! return errno value

	SET_SIZE(copyin)


/*
 * The _more entry points are not intended to be used directly by
 * any caller from outside this file.  They are provided to allow
 * profiling and dtrace of the portions of the copy code that uses
 * the floating point registers.
 * This entry is particularly important as DTRACE (at least as of
 * 4/2004) does not support leaf functions.
 */

	ENTRY(copyin_more)
.copyin_more:
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	set	.copyin_err, REAL_LOFAULT

/*
 * Copy ins that reach here are larger than VIS_COPY_THRESHOLD bytes
 */
.do_copyin:
	set	copyio_fault, %l7		! .copyio_fault is lofault val

	ldn	[THREAD_REG + T_LOFAULT], %l6	! save existing handler
	membar	#Sync				! sync error barrier
	stn	%l7, [THREAD_REG + T_LOFAULT]	! set t_lofault

	mov	%i0, SAVE_SRC
	mov	%i1, SAVE_DST
	mov	%i2, SAVE_COUNT

	FP_NOMIGRATE(6, 7)

	rd	%fprs, %o2		! check for unused fp
	st	%o2, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET] ! save orig %fprs

	! FPU enabled ?  If not, enable it.
	btst	FPRS_FEF, %o2
	bz,a,pt	%icc, .do_blockcopyin
	  wr	%g0, FPRS_FEF, %fprs

	! FPU enabled, but is Q3Q4 dirty ?  If yes, save them.
	btst	FPRS_DU, %o2
	bz,pn	%icc, .do_blockcopyin
	  nop

	BST_FPQ3Q4_TOSTACK(%o2)

.do_blockcopyin:
	rd	%gsr, %o2
	stx	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]	! save gsr
	or	%l6, FPUSED_FLAG, %l6

	andcc	DST, VIS_BLOCKSIZE - 1, TMP
	mov	ASI_USER, %asi
	bz,pt	%ncc, 2f
	  neg	TMP
	add	TMP, VIS_BLOCKSIZE, TMP

	! TMP = bytes required to align DST on FP_BLOCK boundary
	! Using SRC as a tmp here
	cmp	TMP, 3
	bleu,pt	%ncc, 1f
	  sub	CNT,TMP,CNT		! adjust main count
	sub	TMP, 3, TMP		! adjust for end of loop test
.ci_blkalign:
	lduba	[REALSRC]%asi, SRC	! move 4 bytes per loop iteration
	stb	SRC, [DST]
	subcc	TMP, 4, TMP
	lduba	[REALSRC + 1]%asi, SRC
	add	REALSRC, 4, REALSRC
	stb	SRC, [DST + 1]
	lduba	[REALSRC - 2]%asi, SRC
	add	DST, 4, DST
	stb	SRC, [DST - 2]
	lduba	[REALSRC - 1]%asi, SRC
	bgu,pt	%ncc, .ci_blkalign
	  stb	SRC, [DST - 1]

	addcc	TMP, 3, TMP		! restore count adjustment
	bz,pt	%ncc, 2f		! no bytes left?
	  nop
1:	lduba	[REALSRC]%asi, SRC
	inc	REALSRC
	inc	DST
	deccc	TMP
	bgu	%ncc, 1b
	  stb	SRC, [DST - 1]

2:
	andn	REALSRC, 0x7, SRC
	alignaddr REALSRC, %g0, %g0

	! SRC - 8-byte aligned
	! DST - 64-byte aligned
	prefetcha [SRC]%asi, #one_read
	prefetcha [SRC + (1 * VIS_BLOCKSIZE)]%asi, #one_read
	prefetcha [SRC + (2 * VIS_BLOCKSIZE)]%asi, #one_read
	prefetcha [SRC + (3 * VIS_BLOCKSIZE)]%asi, #one_read
	ldda	[SRC]%asi, %d32
#if FIRST_PREFETCH > 4
	prefetcha [SRC + (4 * VIS_BLOCKSIZE)]%asi, #one_read
#endif
	ldda	[SRC + 0x08]%asi, %d34
#if FIRST_PREFETCH > 5
	prefetcha [SRC + (5 * VIS_BLOCKSIZE)]%asi, #one_read
#endif
	ldda	[SRC + 0x10]%asi, %d36
#if FIRST_PREFETCH > 6
	prefetcha [SRC + (6 * VIS_BLOCKSIZE)]%asi, #one_read
#endif
	faligndata %d32, %d34, %d48
	ldda	[SRC + 0x18]%asi, %d38
#if FIRST_PREFETCH > 7
	prefetcha [SRC + (7 * VIS_BLOCKSIZE)]%asi, #one_read
#endif
	faligndata %d34, %d36, %d50
	ldda	[SRC + 0x20]%asi, %d40
	faligndata %d36, %d38, %d52
	ldda	[SRC + 0x28]%asi, %d42
	faligndata %d38, %d40, %d54
	ldda	[SRC + 0x30]%asi, %d44
	faligndata %d40, %d42, %d56
	ldda	[SRC + 0x38]%asi, %d46
	faligndata %d42, %d44, %d58
	ldda	[SRC + VIS_BLOCKSIZE]%asi, %d32
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	SRC, VIS_BLOCKSIZE, SRC
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	ba,a,pt	%ncc, 1f
	  nop
	.align	ICACHE_LINE_SIZE
1:
	ldda	[SRC + 0x08]%asi, %d34
	faligndata %d44, %d46, %d60
	ldda	[SRC + 0x10]%asi, %d36
	faligndata %d46, %d32, %d62
	stda	%d48, [DST]ASI_BLK_P
	ldda	[SRC + 0x18]%asi, %d38
	faligndata %d32, %d34, %d48
	ldda	[SRC + 0x20]%asi, %d40
	faligndata %d34, %d36, %d50
	ldda	[SRC + 0x28]%asi, %d42
	faligndata %d36, %d38, %d52
	ldda	[SRC + 0x30]%asi, %d44
	faligndata %d38, %d40, %d54
	ldda	[SRC + 0x38]%asi, %d46
	faligndata %d40, %d42, %d56
	sub	CNT, VIS_BLOCKSIZE, CNT
	ldda	[SRC + VIS_BLOCKSIZE]%asi, %d32
	faligndata %d42, %d44, %d58
	prefetcha [SRC + ((FIRST_PREFETCH) * VIS_BLOCKSIZE) + 8]%asi, #one_read
	add	DST, VIS_BLOCKSIZE, DST
	prefetcha [SRC + ((SECOND_PREFETCH) * VIS_BLOCKSIZE)]%asi, #one_read
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	cmp	CNT, VIS_BLOCKSIZE + 8
	bgu,pt	%ncc, 1b
	  add	SRC, VIS_BLOCKSIZE, SRC

	! only if REALSRC & 0x7 is 0
	cmp	CNT, VIS_BLOCKSIZE
	bne	%ncc, 3f
	  andcc	REALSRC, 0x7, %g0
	bz,pt	%ncc, 2f
	  nop
3:	
	faligndata %d44, %d46, %d60
	faligndata %d46, %d32, %d62
	stda	%d48, [DST]ASI_BLK_P
	add	DST, VIS_BLOCKSIZE, DST
	ba,pt	%ncc, 3f
	  nop
2:
	ldda	[SRC + 0x08]%asi, %d34
	faligndata %d44, %d46, %d60
	ldda	[SRC + 0x10]%asi, %d36
	faligndata %d46, %d32, %d62
	stda	%d48, [DST]ASI_BLK_P
	ldda	[SRC + 0x18]%asi, %d38
	ldda	[SRC + 0x20]%asi, %d40
	ldda	[SRC + 0x28]%asi, %d42
	ldda	[SRC + 0x30]%asi, %d44
	ldda	[SRC + 0x38]%asi, %d46
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST
	add	SRC, VIS_BLOCKSIZE, SRC
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	stda	%d32, [DST]ASI_BLK_P
	add	DST, VIS_BLOCKSIZE, DST
	ba,a,pt	%ncc, 4f
	  nop

3:	tst	CNT
	bz,a	%ncc, 4f
	  nop

5:	lduba	[REALSRC]ASI_USER, TMP
	inc	REALSRC
	inc	DST
	deccc	CNT
	bgu	%ncc, 5b
	  stb	TMP, [DST - 1]
4:

.copyin_exit:
	membar	#Sync

	ldx	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2	! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_DU, %o3
	bz,pt	%icc, 4f
	  nop

	BLD_FPQ3Q4_FROMSTACK(%o2)

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZEROQ3Q4
	wr	%o3, 0, %fprs		! restore fprs

1:
	membar	#Sync				! sync error barrier
	andn	%l6, FPUSED_FLAG, %l6
	stn	%l6, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	FP_ALLOWMIGRATE(5, 6)
	ret
	  restore	%g0, 0, %o0
/*
 * We got here because of a fault during copyin
 * Errno value is in ERRNO, but DDI/DKI says return -1 (sigh).
 */
.copyin_err:
	ldn	[THREAD_REG + T_COPYOPS], %o4	! check for copyop handler
	tst	%o4
	bz,pt	%ncc, 2f			! if not, return error
	nop
	ldn	[%o4 + CP_COPYIN], %g2		! if handler, invoke it with
	jmp	%g2				! original arguments
	restore %g0, 0, %g0			! dispose of copy window
2:
	ret
	restore %g0, -1, %o0			! return error value


	SET_SIZE(copyin_more)

#endif	/* lint */

#ifdef	lint

/*ARGSUSED*/
int
xcopyin(const void *uaddr, void *kaddr, size_t count)
{ return (0); }

#else	/* lint */

	ENTRY(xcopyin)

	cmp	%o2, VIS_COPY_THRESHOLD		! check for leaf rtn case
	bleu,pt	%ncc, .xcopyin_small		! go to larger cases
	  xor	%o0, %o1, %o3			! are src, dst alignable?
	btst	7, %o3				!
	bz,pt	%ncc, .xcopyin_8		! check for longword alignment
	  nop
	btst	1, %o3				! 
	bz,pt	%ncc, .xcopyin_2		! check for half-word
	  nop
	sethi	%hi(hw_copy_limit_1), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_1)], %o3
	tst	%o3
	bz,pn	%icc, .xcopyin_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .xcopyin_small		! go to small copy
	  nop
	ba,pt	%ncc, .xcopyin_more		! otherwise go to large copy
	  nop
.xcopyin_2:
	btst	3, %o3				!
	bz,pt	%ncc, .xcopyin_4		! check for word alignment
	  nop
	sethi	%hi(hw_copy_limit_2), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_2)], %o3
	tst	%o3
	bz,pn	%icc, .xcopyin_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .xcopyin_small		! go to small copy
	  nop
	ba,pt	%ncc, .xcopyin_more		! otherwise go to large copy
	  nop
.xcopyin_4:
	! already checked longword, must be word aligned
	sethi	%hi(hw_copy_limit_4), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_4)], %o3
	tst	%o3
	bz,pn	%icc, .xcopyin_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .xcopyin_small		! go to small copy
	  nop
	ba,pt	%ncc, .xcopyin_more		! otherwise go to large copy
	  nop
.xcopyin_8:
	sethi	%hi(hw_copy_limit_8), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_8)], %o3
	tst	%o3
	bz,pn	%icc, .xcopyin_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .xcopyin_small		! go to small copy
	  nop
	ba,pt	%ncc, .xcopyin_more		! otherwise go to large copy
	  nop

.xcopyin_small:
	sethi	%hi(.sm_xcopyin_err), %o5  ! .sm_xcopyin_err is lofault value
	or	%o5, %lo(.sm_xcopyin_err), %o5
	ldn	[THREAD_REG + T_LOFAULT], %o4	! set/save t_lofaul
	membar	#Sync				! sync error barrier
	ba,pt	%ncc, .sm_do_copyin		! common code
	  stn	%o5, [THREAD_REG + T_LOFAULT]
	
.xcopyin_more:
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	sethi	%hi(.xcopyin_err), REAL_LOFAULT	! .xcopyin_err is lofault value
	ba,pt	%ncc, .do_copyin
	  or	REAL_LOFAULT, %lo(.xcopyin_err), REAL_LOFAULT

/*
 * We got here because of fault during xcopyin
 * Errno value is in ERRNO
 */
.xcopyin_err:
	ldn	[THREAD_REG + T_COPYOPS], %o4	! check for copyop handler
	tst	%o4
	bz,pt	%ncc, 2f			! if not, return error
	  nop
	ldn	[%o4 + CP_XCOPYIN], %g2		! if handler, invoke it with
	jmp	%g2				! original arguments
	  restore %g0, 0, %g0			! dispose of copy window
2:
        ret
	  restore ERRNO, 0, %o0			! return errno value

.sm_xcopyin_err:

	membar	#Sync
	stn	%o4, [THREAD_REG + T_LOFAULT]   ! restore old t_lofault
	mov	SM_SAVE_SRC, %o0
	mov	SM_SAVE_DST, %o1
	mov	SM_SAVE_COUNT, %o2
	ldn	[THREAD_REG + T_COPYOPS], %o3	! check for copyop handler
	tst	%o3
	bz,pt	%ncc, 3f			! if not, return error
	  nop
	ldn	[%o3 + CP_XCOPYIN], %o5		! if handler, invoke it with
	jmp	%o5				! original arguments
	  nop
3:
	retl
	  or	%g1, 0, %o0		! return errno value

	SET_SIZE(xcopyin)

#endif	/* lint */

#ifdef	lint

/*ARGSUSED*/
int
xcopyin_little(const void *uaddr, void *kaddr, size_t count)
{ return (0); }

#else	/* lint */

	ENTRY(xcopyin_little)
	sethi	%hi(.xcopyio_err), %o5
	or	%o5, %lo(.xcopyio_err), %o5
	ldn	[THREAD_REG + T_LOFAULT], %o4
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	
	mov	%o4, %o5

	subcc	%g0, %o2, %o3
	add	%o0, %o2, %o0
	bz,pn	%ncc, 2f		! check for zero bytes
	  sub	%o2, 1, %o4
	add	%o0, %o4, %o0		! start w/last byte	
	add	%o1, %o2, %o1
	lduba	[%o0 + %o3]ASI_AIUSL, %o4

1:	stb	%o4, [%o1 + %o3]
	inccc	%o3
	sub	%o0, 2, %o0		! get next byte
	bcc,a,pt %ncc, 1b
	  lduba	[%o0 + %o3]ASI_AIUSL, %o4

2:
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g0, %o0		! return (0)

.xcopyio_err:
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	  mov	%g1, %o0

	SET_SIZE(xcopyin_little)

#endif	/* lint */


/*
 * Copy a block of storage - must not overlap (from + len <= to).
 * No fault handler installed (to be called under on_fault())
 */
#if defined(lint)

/* ARGSUSED */
void
copyin_noerr(const void *ufrom, void *kto, size_t count)
{}

#else	/* lint */
	ENTRY(copyin_noerr)

	cmp	%o2, VIS_COPY_THRESHOLD		! check for leaf rtn case
	bleu,pt	%ncc, .copyin_ne_small		! go to larger cases
	  xor	%o0, %o1, %o3			! are src, dst alignable?
	btst	7, %o3				!
	bz,pt	%ncc, .copyin_ne_8		! check for longword alignment
	  nop
	btst	1, %o3				! 
	bz,pt	%ncc, .copyin_ne_2		! check for half-word
	  nop
	sethi	%hi(hw_copy_limit_1), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_1)], %o3
	tst	%o3
	bz,pn	%icc, .copyin_ne_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyin_ne_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyin_noerr_more	! otherwise go to large copy
	  nop
.copyin_ne_2:
	btst	3, %o3				!
	bz,pt	%ncc, .copyin_ne_4		! check for word alignment
	  nop
	sethi	%hi(hw_copy_limit_2), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_2)], %o3
	tst	%o3
	bz,pn	%icc, .copyin_ne_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyin_ne_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyin_noerr_more	! otherwise go to large copy
	  nop
.copyin_ne_4:
	! already checked longword, must be word aligned
	sethi	%hi(hw_copy_limit_4), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_4)], %o3
	tst	%o3
	bz,pn	%icc, .copyin_ne_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyin_ne_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyin_noerr_more	! otherwise go to large copy
	  nop
.copyin_ne_8:
	sethi	%hi(hw_copy_limit_8), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_8)], %o3
	tst	%o3
	bz,pn	%icc, .copyin_ne_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyin_ne_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyin_noerr_more	! otherwise go to large copy
	  nop

.copyin_ne_small:
	ldn	[THREAD_REG + T_LOFAULT], %o4
	tst	%o4
	bz,pn	%ncc, .sm_do_copyin
	  nop
	sethi	%hi(.sm_copyio_noerr), %o5
	or	%o5, %lo(.sm_copyio_noerr), %o5
	membar	#Sync				! sync error barrier
	ba,pt	%ncc, .sm_do_copyin
	  stn	%o5, [THREAD_REG + T_LOFAULT]	! set/save t_lofault

.copyin_noerr_more:
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	sethi	%hi(.copyio_noerr), REAL_LOFAULT
	ba,pt	%ncc, .do_copyin
	  or	REAL_LOFAULT, %lo(.copyio_noerr), REAL_LOFAULT

.copyio_noerr:
	jmp	%l6
	  restore %g0,0,%g0

.sm_copyio_noerr:
	membar	#Sync
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore t_lofault
	jmp	%o4
	  nop

	SET_SIZE(copyin_noerr)
#endif /* lint */

/*
 * Copy a block of storage - must not overlap (from + len <= to).
 * No fault handler installed (to be called under on_fault())
 */

#if defined(lint)

/* ARGSUSED */
void
copyout_noerr(const void *kfrom, void *uto, size_t count)
{}

#else	/* lint */
	ENTRY(copyout_noerr)

	cmp	%o2, VIS_COPY_THRESHOLD		! check for leaf rtn case
	bleu,pt	%ncc, .copyout_ne_small		! go to larger cases
	  xor	%o0, %o1, %o3			! are src, dst alignable?
	btst	7, %o3				!
	bz,pt	%ncc, .copyout_ne_8		! check for longword alignment
	  nop
	btst	1, %o3				! 
	bz,pt	%ncc, .copyout_ne_2		! check for half-word
	  nop
	sethi	%hi(hw_copy_limit_1), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_1)], %o3
	tst	%o3
	bz,pn	%icc, .copyout_ne_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyout_ne_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyout_noerr_more	! otherwise go to large copy
	  nop
.copyout_ne_2:
	btst	3, %o3				!
	bz,pt	%ncc, .copyout_ne_4		! check for word alignment
	  nop
	sethi	%hi(hw_copy_limit_2), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_2)], %o3
	tst	%o3
	bz,pn	%icc, .copyout_ne_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyout_ne_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyout_noerr_more	! otherwise go to large copy
	  nop
.copyout_ne_4:
	! already checked longword, must be word aligned
	sethi	%hi(hw_copy_limit_4), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_4)], %o3
	tst	%o3
	bz,pn	%icc, .copyout_ne_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyout_ne_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyout_noerr_more	! otherwise go to large copy
	  nop
.copyout_ne_8:
	sethi	%hi(hw_copy_limit_8), %o3	! Check copy limit
	ld	[%o3 + %lo(hw_copy_limit_8)], %o3
	tst	%o3
	bz,pn	%icc, .copyout_ne_small		! if zero, disable HW copy
	  cmp	%o2, %o3			! if length <= limit
	bleu,pt	%ncc, .copyout_ne_small		! go to small copy
	  nop
	ba,pt	%ncc, .copyout_noerr_more	! otherwise go to large copy
	  nop

.copyout_ne_small:
	ldn	[THREAD_REG + T_LOFAULT], %o4
	tst	%o4
	bz,pn	%ncc, .sm_do_copyout
	  nop
	sethi	%hi(.sm_copyio_noerr), %o5
	or	%o5, %lo(.sm_copyio_noerr), %o5
	membar	#Sync				! sync error barrier
	ba,pt	%ncc, .sm_do_copyout
	stn	%o5, [THREAD_REG + T_LOFAULT]	! set/save t_lofault

.copyout_noerr_more:
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	sethi	%hi(.copyio_noerr), REAL_LOFAULT
	ba,pt	%ncc, .do_copyout
	  or	REAL_LOFAULT, %lo(.copyio_noerr), REAL_LOFAULT

	SET_SIZE(copyout_noerr)
#endif /* lint */


/*
 * hwblkclr - clears block-aligned, block-multiple-sized regions that are
 * longer than 256 bytes in length using spitfire's block stores.  If
 * the criteria for using this routine are not met then it calls bzero
 * and returns 1.  Otherwise 0 is returned indicating success.
 * Caller is responsible for ensuring use_hw_bzero is true and that
 * kpreempt_disable() has been called.
 */
#ifdef lint
/*ARGSUSED*/
int
hwblkclr(void *addr, size_t len)
{ 
	return(0);
}
#else /* lint */
	! %i0 - start address
	! %i1 - length of region (multiple of 64)
	! %l0 - saved fprs
	! %l1 - pointer to saved %d32 block
	! %l2 - saved curthread->t_lwp


	ENTRY(hwblkclr)
	! get another window w/space for one aligned block of saved fpregs
	save	%sp, -SA(MINFRAME + 2*VIS_BLOCKSIZE), %sp

#ifdef ROCK_CR_6654578
	! Address aligned to 128 byte
	andcc	%i0, ST_CACHE_ALIGN, %g0
	bnz,pn  %ncc, .normal_hwblkclr
	 nop
	! multiple of 8k len, call page_hwblkclr
	set	PAGE_MASK, %i3
	andcc	%i1, %i3, %g0
	bnz,pn	%ncc, .normal_hwblkclr
	 nop
	mov     %i0, %o0
	call page_hwblkclr
	 mov     %i1, %o1
	ret
	restore %g0, 0, %o0     ! I$ sync not required

.normal_hwblkclr:
#endif
	! Must be block-aligned
	andcc	%i0, (VIS_BLOCKSIZE-1), %g0
	bnz,pn	%ncc, 1f
	  nop

	! ... and must be 256 bytes or more
	cmp	%i1, 256
	blu,pn	%ncc, 1f
	  nop

	! ... and length must be a multiple of VIS_BLOCKSIZE
	andcc	%i1, (VIS_BLOCKSIZE-1), %g0
	bz,pn	%ncc, 2f
	  nop

1:	! punt, call bzero but notify the caller that bzero was used
	mov	%i0, %o0
	call	bzero
	mov	%i1, %o1
	! call rock_sync_icache
	mov     %i0, %o0
	call	rock_sync_icache
	mov     %i0, %o0
	ret
	  restore	%g0, 0, %o0 !  did not use block operations

2:	mov	%g0, %l3		! clear flag to say fp regs not saved
	rd	%fprs, %l0		! check for unused fp

	! FPU enabled ?  If not, enable it.
	btst	FPRS_FEF, %l0
	bz,a,pt	%icc, 1f
	  wr	%g0, FPRS_FEF, %fprs

	! FPU enabled, but is Q3Q4 dirty ?  If yes, save them.
	btst	FPRS_DU, %l0
	bz,pn	%icc, 1f
	  nop

	! save in-use fpregs on stack
	membar	#Sync
	add	%fp, STACK_BIAS - 65, %l1
	and	%l1, -VIS_BLOCKSIZE, %l1
	stda	%d32, [%l1]ASI_BLK_P
        ! Set a flag saying fp regs are saved.
	mov	1, %l3

        ! Need to wait only here for the above save to be completed
	membar	#StoreStore|#StoreLoad|#LoadStore

1:	wr	%g0, ASI_BLK_P, %asi

	! Clear block
	movxtod	%g0, %d32
	movxtod	%g0, %d34
	fsrc1	%d32, %d36
	fsrc1	%d32, %d38
	fsrc1	%d32, %d40
	fsrc1	%d32, %d42
	fsrc1	%d32, %d44
	fsrc1	%d32, %d46

	mov	256, %i3
	ba,pt	%ncc, .pz_doblock
	  nop

.pz_blkstart:	
      ! stda	%d32, [%i0 + 192]%asi  ! in dly slot of branch that got us here
#ifdef ROCK_CR_6654578
	prefetcha [%i0 + VIS_COPY_THRESHOLD + 128]%asi, #n_writes
#endif
	stda	%d32, [%i0 + 128]%asi
#ifdef ROCK_CR_6654578
	prefetcha [%i0 + VIS_COPY_THRESHOLD + 64]%asi, #n_writes
#endif
	stda	%d32, [%i0 + 64]%asi
#ifdef ROCK_CR_6654578
	prefetcha [%i0 + VIS_COPY_THRESHOLD + 0]%asi, #n_writes
#endif
	stda	%d32, [%i0]%asi
.pz_zinst:
	add	%i0, %i3, %i0
	sub	%i1, %i3, %i1
.pz_doblock:
#ifdef ROCK_CR_6654578
	prefetcha [%i0 + VIS_COPY_THRESHOLD + 192]%asi, #n_writes
#endif
	cmp	%i1, 256
	bgeu,a	%ncc, .pz_blkstart
	  stda	%d32, [%i0 + 192]%asi

	cmp	%i1, 64
	blu	%ncc, .pz_finish
	
	  andn	%i1, (64-1), %i3
	srl	%i3, 4, %i2		! using blocks, 1 instr / 16 words
	set	.pz_zinst, %i4
	sub	%i4, %i2, %i4
	jmp	%i4
	  nop

.pz_finish:
	brz,a	%l3, .pz_finished
	  wr	%l0, 0, %fprs		! restore fprs

	! restore fpregs from stack
	ldda	[%l1]ASI_BLK_P, %d32
	wr	%l0, 0, %fprs		! restore fprs

.pz_finished:
	membar	#Sync
	ret
	  restore	%g0, 0, %o0		! return (bzero or not)

	SET_SIZE(hwblkclr)
#endif	/* lint */

#ifdef lint
/*ARGSUSED*/
void
hw_pa_bcopy32(uint64_t src, uint64_t dst)
{}
#else /*!lint */
	/*
	 * Copy 32 bytes of data from src (%o0) to dst (%o1)
	 * using physical addresses.
	 */
	ENTRY_NP(hw_pa_bcopy32)
	rdpr	%pstate, %g1
	andn	%g1, PSTATE_IE, %g2
	wrpr	%g0, %g2, %pstate

	rdpr	%pstate, %g0
	ldxa	[%o0]ASI_MEM, %o2
	add	%o0, 8, %o0
	ldxa	[%o0]ASI_MEM, %o3
	add	%o0, 8, %o0
	ldxa	[%o0]ASI_MEM, %o4
	add	%o0, 8, %o0
	ldxa	[%o0]ASI_MEM, %o5
	stxa	%o2, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa	%o3, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa	%o4, [%o1]ASI_MEM
	add	%o1, 8, %o1
	stxa	%o5, [%o1]ASI_MEM

	retl
	  wrpr	  %g0, %g1, %pstate

	SET_SIZE(hw_pa_bcopy32)

#endif /* lint */


/*
 * Zero a block of storage.
 *
 * uzero is used by the kernel to zero a block in user address space.
 */


#if defined(lint)

/* ARGSUSED */
int
kzero(void *addr, size_t count)
{ return(0); }

/* ARGSUSED */
void
uzero(void *addr, size_t count)
{}

#else	/* lint */

	ENTRY(uzero)
	!
	! Set a new lo_fault handler only if we came in with one
	! already specified.
	!
	wr	%g0, ASI_USER, %asi
	ldn	[THREAD_REG + T_LOFAULT], %o5
	tst	%o5
	bz,pt	%ncc, .do_zero
	sethi	%hi(.zeroerr), %o2
	or	%o2, %lo(.zeroerr), %o2
	membar	#Sync
	ba,pt	%ncc, .do_zero
	stn	%o2, [THREAD_REG + T_LOFAULT]

	ENTRY(kzero)
	!
	! Always set a lo_fault handler
	!
	wr	%g0, ASI_P, %asi
	ldn	[THREAD_REG + T_LOFAULT], %o5
	sethi	%hi(.zeroerr), %o2
	or	%o5, LOFAULT_SET, %o5
	or	%o2, %lo(.zeroerr), %o2
	membar	#Sync
	ba,pt	%ncc, .do_zero
	stn	%o2, [THREAD_REG + T_LOFAULT]

/*
 * We got here because of a fault during kzero or if
 * uzero or bzero was called with t_lofault non-zero.
 * Otherwise we've already run screaming from the room.
 * Errno value is in %g1. Note that we're here iff
 * we did set t_lofault.
 */
.zeroerr:
	!
	! Undo asi register setting. Just set it to be the
        ! kernel default without checking.
	!
	wr	%g0, ASI_P, %asi

	!
	! We did set t_lofault. It may well have been zero coming in.
	!
1:
	tst	%o5
	membar #Sync
	bne,pn	%ncc, 3f		
	andncc	%o5, LOFAULT_SET, %o5
2:
	!
	! Old handler was zero. Just return the error.
	!
	retl				! return
	mov	%g1, %o0		! error code from %g1
3:
	!
	! We're here because %o5 was non-zero. It was non-zero
	! because either LOFAULT_SET was present, a previous fault
	! handler was present or both. In all cases we need to reset
	! T_LOFAULT to the value of %o5 after clearing LOFAULT_SET
	! before we either simply return the error or we invoke the
	! previously specified handler.
	!
	be	%ncc, 2b
	stn	%o5, [THREAD_REG + T_LOFAULT]
	jmp	%o5			! goto real handler
	  nop
	SET_SIZE(kzero)
	SET_SIZE(uzero)

#endif	/* lint */

/*
 * Zero a block of storage.
 */

#if defined(lint)

/* ARGSUSED */
void
bzero(void *addr, size_t count)
{}

#else	/* lint */

	ENTRY(bzero)
	wr	%g0, ASI_P, %asi

	ldn	[THREAD_REG + T_LOFAULT], %o5	! save old vector
	tst	%o5
	bz,pt	%ncc, .do_zero
	sethi	%hi(.zeroerr), %o2
	or	%o2, %lo(.zeroerr), %o2
	membar	#Sync				! sync error barrier
	stn	%o2, [THREAD_REG + T_LOFAULT]	! install new vector

.do_zero:
	cmp	%o1, 7
	blu,pn	%ncc, .byteclr
	nop

	cmp	%o1, 15
	blu,pn	%ncc, .wdalign
	nop

	andcc	%o0, 7, %o3		! is add aligned on a 8 byte bound
	bz,pt	%ncc, .blkalign		! already double aligned
	sub	%o3, 8, %o3		! -(bytes till double aligned)
	add	%o1, %o3, %o1		! update o1 with new count

1:
	stba	%g0, [%o0]%asi
	inccc	%o3
	bl,pt	%ncc, 1b
	inc	%o0

	! Now address is double aligned
.blkalign:
	cmp	%o1, 0x80		! check if there are 128 bytes to set
	blu,pn	%ncc, .bzero_small
	mov	%o1, %o3

	andcc	%o0, 0x3f, %o3		! is block aligned?
	bz,pt	%ncc, .bzero_blk
	sub	%o3, 0x40, %o3		! -(bytes till block aligned)
	add	%o1, %o3, %o1		! o1 is the remainder
	
	! Clear -(%o3) bytes till block aligned
1:
	stxa	%g0, [%o0]%asi
	addcc	%o3, 8, %o3
	bl,pt	%ncc, 1b
	add	%o0, 8, %o0

.bzero_blk:
	and	%o1, 0x3f, %o3		! calc bytes left after blk clear
	andn	%o1, 0x3f, %o4		! calc size of blocks in bytes

	cmp	%o4, 0x100		! 256 bytes or more
	blu,pn	%ncc, 3f
	nop

2:
	stxa	%g0, [%o0+0x0]%asi
	stxa	%g0, [%o0+0x40]%asi
	stxa	%g0, [%o0+0x80]%asi
	stxa	%g0, [%o0+0xc0]%asi

	stxa	%g0, [%o0+0x8]%asi
	stxa	%g0, [%o0+0x10]%asi
	stxa	%g0, [%o0+0x18]%asi
	stxa	%g0, [%o0+0x20]%asi
	stxa	%g0, [%o0+0x28]%asi
	stxa	%g0, [%o0+0x30]%asi
	stxa	%g0, [%o0+0x38]%asi

	stxa	%g0, [%o0+0x48]%asi
	stxa	%g0, [%o0+0x50]%asi
	stxa	%g0, [%o0+0x58]%asi
	stxa	%g0, [%o0+0x60]%asi
	stxa	%g0, [%o0+0x68]%asi
	stxa	%g0, [%o0+0x70]%asi
	stxa	%g0, [%o0+0x78]%asi

	stxa	%g0, [%o0+0x88]%asi
	stxa	%g0, [%o0+0x90]%asi
	stxa	%g0, [%o0+0x98]%asi
	stxa	%g0, [%o0+0xa0]%asi
	stxa	%g0, [%o0+0xa8]%asi
	stxa	%g0, [%o0+0xb0]%asi
	stxa	%g0, [%o0+0xb8]%asi

	stxa	%g0, [%o0+0xc8]%asi
	stxa	%g0, [%o0+0xd0]%asi
	stxa	%g0, [%o0+0xd8]%asi
	stxa	%g0, [%o0+0xe0]%asi
	stxa	%g0, [%o0+0xe8]%asi
	stxa	%g0, [%o0+0xf0]%asi
	stxa	%g0, [%o0+0xf8]%asi

	sub	%o4, 0x100, %o4
	cmp	%o4, 0x100
	bgu,pt	%ncc, 2b
	add	%o0, 0x100, %o0

3:
	! ... check if 64 bytes to set
	cmp	%o4, 0x40
	blu	%ncc, .bzero_blk_done
	nop

4:
	stxa	%g0, [%o0+0x0]%asi
	stxa	%g0, [%o0+0x8]%asi
	stxa	%g0, [%o0+0x10]%asi
	stxa	%g0, [%o0+0x18]%asi
	stxa	%g0, [%o0+0x20]%asi
	stxa	%g0, [%o0+0x28]%asi
	stxa	%g0, [%o0+0x30]%asi
	stxa	%g0, [%o0+0x38]%asi

	subcc	%o4, 0x40, %o4
	bgu,pt	%ncc, 3b
	add	%o0, 0x40, %o0

.bzero_blk_done:
	membar	#Sync

.bzero_small:
	! Set the remaining doubles
	subcc	%o3, 8, %o3		! Can we store any doubles?
	blu,pn	%ncc, .byteclr
	and	%o1, 7, %o1		! calc bytes left after doubles

.dbclr:
	stxa	%g0, [%o0]%asi		! Clear the doubles
	subcc	%o3, 8, %o3
	bgeu,pt	%ncc, .dbclr
	add	%o0, 8, %o0

	ba	.byteclr
	nop

.wdalign:			
	andcc	%o0, 3, %o3		! is add aligned on a word boundary
	bz,pn	%ncc, .wdclr
	andn	%o1, 3, %o3		! create word sized count in %o3

	dec	%o1			! decrement count
	stba	%g0, [%o0]%asi		! clear a byte
	ba	.wdalign
	inc	%o0			! next byte

.wdclr:
	sta	%g0, [%o0]%asi		! 4-byte clearing loop
	subcc	%o3, 4, %o3
	bnz,pt	%ncc, .wdclr
	inc	4, %o0

	and	%o1, 3, %o1		! leftover count, if any

.byteclr:
	! Set the leftover bytes
	brz	%o1, .bzero_exit
	nop

7:
	deccc	%o1			! byte clearing loop
	stba	%g0, [%o0]%asi
	bgu,pt	%ncc, 7b
	inc	%o0

.bzero_exit:
	!
	! We're just concerned with whether t_lofault was set
	! when we came in. We end up here from either kzero()
	! or bzero(). kzero() *always* sets a lofault handler.
	! It ors LOFAULT_SET into %o5 to indicate it has done
	! this even if the value of %o5 is otherwise zero.
	! bzero() sets a lofault handler *only* if one was
	! previously set. Accordingly we need to examine
	! %o5 and if it is non-zero be sure to clear LOFAULT_SET
	! before resetting the error handler.
	!
	tst	%o5
	bz	%ncc, 1f
	andn	%o5, LOFAULT_SET, %o5
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
1:
	retl
	clr	%o0			! return (0)

	SET_SIZE(bzero)
#endif	/* lint */

#ifdef ROCK_CR_6654578
/* This code tries to maximize bandwidth by being clever about accessing
 * the two cache lines that are BUDDY PAIRS in the L3 cache.  When line 0
 * of a pair is accessed, it will take hundreds of cycles to get the line
 * from memory, which brings in a 128-byte line to L3.  Until the line is
 * installed in L3, any other access to that line (such as buddy line 1)
 * is blocked.  For best throughput, we access many lines that are the first
 * of their buddy pairs, and only after many such accesses have been made,
 * we access the sequence of second buddy pair lines.  Hopefully the second
 * set of accesses comes after the L3 lines are installed, so the accesses
 * hitin L3 without being delayed.  This should yield better throughput. 
 * To keep this code simple, we assume the addresses given are aligned at
 * least on a 128 byte boundary, and the length is assumed to be a multiple
 * of 8k bytes.
 */

#ifdef lint
/*ARGSUSED*/
int
page_hwblkclr(void *addr, size_t len)
{ 
	return(0);
}
#else /* lint */
	ENTRY(page_hwblkclr)
	save	%sp, -SA(MINFRAME + 2*VIS_BLOCKSIZE), %sp

	! %i0 address
	! %i1 len
        
	rd      %fprs, %l0
	mov     %g0, %l2		! clear flag to say fp regs not saved

	! FPU enabled ?  If not, enable it.
	btst    FPRS_FEF, %l0
	bz,a,pt   %icc, 1f
          wr      %g0, FPRS_FEF, %fprs

	! FPU enabled, but is Q3Q4 dirty ?  If yes, save them.
        btst    FPRS_DU, %l0
        bz,pn   %icc, 1f
          nop

        ! save in-use fpregs on stack

        add     %fp, STACK_BIAS - 65, %l1       ! get stack frame for fp regs
        and     %l1, -VIS_BLOCKSIZE, %l1        ! block align frame
        stda    %d32, [%l1]ASI_BLK_P            ! %l1 = addr of saved fp regs

        ! Set a flag saying fp regs are saved.
        mov     1, %l2

        ! enable fp

1:      membar  #StoreStore|#StoreLoad|#LoadStore

        movxtod %g0, %d32
        movxtod %g0, %d34
        movxtod %g0, %d36
        movxtod %g0, %d38
        movxtod %g0, %d40
        movxtod %g0, %d42
        movxtod %g0, %d44
        movxtod %g0, %d46

        ba      myloop2
        srl     %i1,12,%i1
.align 64
myloop2:
        mov      2,%l5
        mov      %i0, %l3 
buddyloop:
        set      4096, %l4    
        add      %i0, %l4, %l4
        prefetcha [%l4]ASI_BLK_P, #n_writes
        mov      32,%l6
innerloop:          

        subcc   %l6,1,%l6
        stda    %d32,[%i0]ASI_BLK_P
        bg,pt   %icc,innerloop
        add     %i0, 128, %i0

        subcc   %l5,1,%l5
        add     %l3, 64, %i0
        bg,pt   %icc,buddyloop
	nop
	subcc	%i1,1,%i1
        add     %i0, 4032, %i0
        bg,pt   %icc,myloop2
        nop

        brz,a   %l2, 2f
          wr    %l0, 0, %fprs           ! restore fprs

        ! restore fpregs from stack
        ldda    [%l1]ASI_BLK_P, %d32

        wr      %l0, 0, %fprs           ! restore fprs
2:
        membar  #Sync

        ret
        restore  %g0, 0, %o0

	SET_SIZE(page_hwblkclr)
#endif	/* lint */
#endif	/* ROCK_CR_6654578 */

#if defined(lint)

int use_hw_bcopy = 1;
int use_hw_bzero = 1;
uint_t hw_copy_limit_1 = 0x100;
uint_t hw_copy_limit_2 = 0x200;
uint_t hw_copy_limit_4 = 0x400;
uint_t hw_copy_limit_8 = 0x400;

#else /* !lint */

	DGDEF(use_hw_bcopy)
	.word	1
	DGDEF(use_hw_bzero)
	.word	1
	DGDEF(hw_copy_limit_1)
	.word	0x100
	DGDEF(hw_copy_limit_2)
	.word	0x200
	DGDEF(hw_copy_limit_4)
	.word	0x400
	DGDEF(hw_copy_limit_8)
	.word	0x400

	.align	64
	.section ".text"
#endif /* !lint */
