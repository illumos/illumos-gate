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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
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
#include <sys/machasi.h>
#include <sys/niagaraasi.h>

#include "assym.h"


/*
 * Pseudo-code to aid in understanding the control flow of the
 * bcopy/kcopy routine.
 *
 *	! WARNING : <Register usage convention>
 *	! In kcopy() the %o5, holds previous error handler and a flag
 *	! LOFAULT_SET (low bits). The %o5 is null in bcopy().
 *	! The %o5 is not available for any other use.
 *
 * On entry:
 *	! Determine whether to use the FP register version or the
 *	! the leaf routine version depending on the size of the copy.
 *	! Set up error handling accordingly.
 *	! The transition point depends on FP_COPY
 *	! For both versions %o5 is reserved
 *
 * kcopy():
 *	if(length > FP_COPY)
 *		go to regular_kcopy
 *
 *	! Setup_leaf_rtn_error_handler
 *	%o5 = curthread->t_lofault;		! save existing handler in %o5
 *	%o5 |= LOFAULT_SET;			! ORed with LOFAULT_SET flag
 *	curthread->t_lofault = .sm_copyerr;
 *	goto small_bcopy();
 *
 * regular_kcopy:
 *	save_registers()
 *	%o5 = curthread->t_lofault;		! save existing handler in %o5
 *	%o5 |= LOFAULT_SET;			! ORed with LOFAULT_SET flag
 *	curthread->t_lofault = .copyerr;
 *	goto do_copy();
 *
 * bcopy():
 *	if(length > FP_COPY)
 *		go to regular_bcopy
 *
 *	! Setup_leaf_rtn_error_handler
 *	%o5 = curthread->t_lofault;		! save existing handler in %o5
 *	curthread->t_lofault = .sm_copyerr;
 *	goto small_bcopy();
 *
 * regular_bcopy:
 *	%o5 = curthread->t_lofault;		! save existing handler in %o5
 *	curthread->t_lofault = .copyerr;
 *	goto do_copy();
 *
 * small_bcopy:
 *	! handle copies smaller than FP_COPY
 *	restore t_lofault handler
 *	exit
 *
 * do_copy:
 *	! handle copies larger than FP_COPY
 *	save fp_regs
 * 	blockcopy;
 *	restore fp_regs
 *	restore t_lofault handler if came from kcopy();
 *
 *
 * In leaf lofault handler:
 *	curthread->t_lofault = (%o5 & ~LOFAULT_SET);	! restore old t_lofault
 *	return (errno)
 *
 * In lofault handler:
 *	curthread->t_lofault = (%o5 & ~LOFAULT_SET);	! restore old t_lofault
 *	restore fp_regs
 *	return (errno)
 *
 *
 *
 * For all of bcopy/copyin/copyout the copy logic is specialized according
 * to how the src and dst is aligned and how much data needs to be moved.
 * The following comments apply to the N2/RF code (#if !defined(NIAGARA_IMPL))
 * 
 * N2/RF Flow :
 *
 * if (count < FP_COPY) {  (584 bytes)
 *   set small fault handler (no register window save/restore)
 *   if count < SHORTCOPY  (7 bytes)
 *	copy bytes; go to short_exit
 *   else
 *   determine dst alignment, move minimum bytes/halfwords to
 *   get dst aligned on long word boundary
 *     if( src is on long word boundary ) {
 * medlong:					   src/dst aligned on 8 bytes
 *	 copy with ldx/stx in 4-way unrolled loop;
 *       copy final 0-31 bytes; go to short_exit
 *     } else {					src/dst not aligned on 8 bytes
 *     if src is word aligned, ld/st words in 32-byte chunks
 *     if src is half word aligned, ld half, ld word, ld half; pack 
 *		into long word, store long words in 32-byte chunks
 *     if src is byte aligned, ld byte,half,word parts;  pack into long
 *	   word, store long words in 32-byte chunks
 *     move final 0-31 bytes according to src alignment;  go to short_exit
 * short_exit:
 *     restore trap handler if needed, retl
 * else {					   More than FP_COPY bytes
 *     set fault handler
 *     disable kernel preemption
 *     save registers, save FP registers if in use
 *     move bytes to align destination register on long word boundary
 *     if(src is on long word boundary) {	   src/dst aligned on 8 bytes
 *       align dst on 64 byte boundary;  use 8-way test for each of 8 possible
 *       src alignments relative to a 64 byte boundary to select the
 *       16-way unrolled loop (128 bytes) to use for
 *       block load, fmovd, block-init-store, block-store, fmovd operations
 *       then go to remain_stuff.
 * remain_stuff: move remaining bytes. go to long_exit
 *     } else {
 *       setup alignaddr for faligndata instructions
 *       align dst on 64 byte boundary; use 8-way test for each of 8 possible
 *       src alignments to nearest long word relative to 64 byte boundary to
 *       select the 8-way unrolled loop (64 bytes) to use for
 *       block load, falign, fmovd, block-store loop
 *	 (only use block-init-store when src/dst on 8 byte boundaries.)
 *       goto unalign_done.
 * unalign_done:
 *       move remaining bytes for unaligned cases. go to long_exit
 * long_exit:
 *       restore %gsr, FP regs (either from stack or set to zero),
 *       restore trap handler, check for kernel preemption request,
 *       handle if needed, ret.
 * }
 *
 * Other platforms include hw_bcopy_limit_[1248] to control the exact
 * point where the FP register code is used. On those platforms, the
 * FP register code did not leave data in L2 cache, potentially affecting
 * performance more than the gain/loss from the algorithm difference.
 * For N2/RF, block store places data in the L2 cache, so use or non-use
 * of the FP registers has no effect on L2 cache behavior.
 * The cost for testing hw_bcopy_limit_* according to different
 * alignments exceeds 50 cycles for all cases, even when hw_bcopy_limits
 * were not used. That cost was judged too high relative to the benefits,
 * so the hw_bcopy_limit option is omitted from this code.
 */

/*
 * Less then or equal this number of bytes we will always copy byte-for-byte
 */
#define	SMALL_LIMIT	7

/*
 * LOFAULT_SET : Flag set by kzero and kcopy to indicate that t_lofault
 * handler was set
 */
#define	LOFAULT_SET 2

/*
 * This define is to align data for the unaligned source cases.
 * The data1, data2 and data3 is merged into data1 and data2.
 * The data3 is preserved for next merge.
 */
#define	ALIGN_DATA(data1, data2, data3, lshift, rshift, tmp)	\
	sllx	data1, lshift, data1				;\
	srlx	data2, rshift, tmp				;\
	or	data1, tmp, data1				;\
	sllx	data2, lshift, data2				;\
	srlx	data3, rshift, tmp				;\
	or	data2, tmp, data2
/*
 * This macro is to align the data. Basically it merges
 * data1 and data2 to form double word.
 */
#define	ALIGN_DATA_EW(data1, data2, lshift, rshift, tmp)	\
	sllx	data1, lshift, data1				;\
	srlx	data2, rshift, tmp				;\
	or	data1, tmp, data1

#if !defined(NIAGARA_IMPL)
/*
 * Flags set in the lower bits of the t_lofault address:
 * FPUSED_FLAG: The FP registers were in use and must be restored
 * LOFAULT_SET: Set for bcopy calls, cleared for kcopy calls
 * COPY_FLAGS: Both of the above
 *
 * Other flags:
 * KPREEMPT_FLAG: kpreempt needs to be called
 */
#define	FPUSED_FLAG	1
#define	LOFAULT_SET	2
#define	COPY_FLAGS	(FPUSED_FLAG | LOFAULT_SET)
#define	KPREEMPT_FLAG	4

#define	ALIGN_OFF_1_7			\
	faligndata %d0, %d2, %d48	;\
	faligndata %d2, %d4, %d50	;\
	faligndata %d4, %d6, %d52	;\
	faligndata %d6, %d8, %d54	;\
	faligndata %d8, %d10, %d56	;\
	faligndata %d10, %d12, %d58	;\
	faligndata %d12, %d14, %d60	;\
	faligndata %d14, %d16, %d62

#define	ALIGN_OFF_8_15			\
	faligndata %d2, %d4, %d48	;\
	faligndata %d4, %d6, %d50	;\
	faligndata %d6, %d8, %d52	;\
	faligndata %d8, %d10, %d54	;\
	faligndata %d10, %d12, %d56	;\
	faligndata %d12, %d14, %d58	;\
	faligndata %d14, %d16, %d60	;\
	faligndata %d16, %d18, %d62

#define	ALIGN_OFF_16_23			\
	faligndata %d4, %d6, %d48	;\
	faligndata %d6, %d8, %d50	;\
	faligndata %d8, %d10, %d52	;\
	faligndata %d10, %d12, %d54	;\
	faligndata %d12, %d14, %d56	;\
	faligndata %d14, %d16, %d58	;\
	faligndata %d16, %d18, %d60	;\
	faligndata %d18, %d20, %d62

#define	ALIGN_OFF_24_31			\
	faligndata %d6, %d8, %d48	;\
	faligndata %d8, %d10, %d50	;\
	faligndata %d10, %d12, %d52	;\
	faligndata %d12, %d14, %d54	;\
	faligndata %d14, %d16, %d56	;\
	faligndata %d16, %d18, %d58	;\
	faligndata %d18, %d20, %d60	;\
	faligndata %d20, %d22, %d62

#define	ALIGN_OFF_32_39			\
	faligndata %d8, %d10, %d48	;\
	faligndata %d10, %d12, %d50	;\
	faligndata %d12, %d14, %d52	;\
	faligndata %d14, %d16, %d54	;\
	faligndata %d16, %d18, %d56	;\
	faligndata %d18, %d20, %d58	;\
	faligndata %d20, %d22, %d60	;\
	faligndata %d22, %d24, %d62

#define	ALIGN_OFF_40_47			\
	faligndata %d10, %d12, %d48	;\
	faligndata %d12, %d14, %d50	;\
	faligndata %d14, %d16, %d52	;\
	faligndata %d16, %d18, %d54	;\
	faligndata %d18, %d20, %d56	;\
	faligndata %d20, %d22, %d58	;\
	faligndata %d22, %d24, %d60	;\
	faligndata %d24, %d26, %d62

#define	ALIGN_OFF_48_55			\
	faligndata %d12, %d14, %d48	;\
	faligndata %d14, %d16, %d50	;\
	faligndata %d16, %d18, %d52	;\
	faligndata %d18, %d20, %d54	;\
	faligndata %d20, %d22, %d56	;\
	faligndata %d22, %d24, %d58	;\
	faligndata %d24, %d26, %d60	;\
	faligndata %d26, %d28, %d62

#define	ALIGN_OFF_56_63			\
	faligndata %d14, %d16, %d48	;\
	faligndata %d16, %d18, %d50	;\
	faligndata %d18, %d20, %d52	;\
	faligndata %d20, %d22, %d54	;\
	faligndata %d22, %d24, %d56	;\
	faligndata %d24, %d26, %d58	;\
	faligndata %d26, %d28, %d60	;\
	faligndata %d28, %d30, %d62

/*
 * FP_COPY indicates the minimum number of bytes needed
 * to justify using FP/VIS-accelerated memory operations.
 * The FPBLK code assumes a minimum number of bytes are available
 * to be moved on entry.  Check that code carefully before
 * reducing FP_COPY below 256.
 */
#define FP_COPY			584
#define SHORTCOPY		7
#define ASI_STBI_P		ASI_BLK_INIT_ST_QUAD_LDD_P
#define ASI_STBI_AIUS		ASI_BLK_INIT_QUAD_LDD_AIUS
#define CACHE_LINE		64
#define	VIS_BLOCKSIZE		64

/*
 * Size of stack frame in order to accomodate a 64-byte aligned
 * floating-point register save area and 2 64-bit temp locations.
 * All copy functions use three quadrants of fp registers; to assure a
 * block-aligned three block buffer in which to save we must reserve
 * four blocks on stack.
 *
 *    _______________________________________ <-- %fp + STACK_BIAS
 *    | We may need to preserve 3 quadrants |
 *    | of fp regs, but since we do so with |
 *    | BST/BLD we need room in which to    |
 *    | align to VIS_BLOCKSIZE bytes.  So   |
 *    | this area is 4 * VIS_BLOCKSIZE.     | <--  - SAVED_FPREGS_OFFSET
 *    |-------------------------------------|
 *    | 8 bytes to save %fprs		    | <--  - SAVED_FPRS_OFFSET
 *    |-------------------------------------|
 *    | 8 bytes to save %gsr		    | <--  - SAVED_GSR_OFFSET
 *    ---------------------------------------
 */
#define HWCOPYFRAMESIZE		((VIS_BLOCKSIZE * (3 + 1)) + (2 * 8))
#define SAVED_FPREGS_OFFSET	(VIS_BLOCKSIZE * 4)
#define SAVED_FPREGS_ADJUST	((VIS_BLOCKSIZE * 3) + 1)
#define SAVED_FPRS_OFFSET	(SAVED_FPREGS_OFFSET + 8)
#define SAVED_GSR_OFFSET	(SAVED_FPRS_OFFSET + 8)

/*
 * In FP copies if we do not have preserved data to restore over
 * the fp regs we used then we must zero those regs to avoid
 * exposing portions of the data to later threads (data security).
 */
#define	FZERO				\
	fzero	%f0			;\
	fzero	%f2			;\
	faddd	%f0, %f2, %f4		;\
	fmuld	%f0, %f2, %f6		;\
	faddd	%f0, %f2, %f8		;\
	fmuld	%f0, %f2, %f10		;\
	faddd	%f0, %f2, %f12		;\
	fmuld	%f0, %f2, %f14		;\
	faddd	%f0, %f2, %f16		;\
	fmuld	%f0, %f2, %f18		;\
	faddd	%f0, %f2, %f20		;\
	fmuld	%f0, %f2, %f22		;\
	faddd	%f0, %f2, %f24		;\
	fmuld	%f0, %f2, %f26		;\
	faddd	%f0, %f2, %f28		;\
	fmuld	%f0, %f2, %f30		;\
	faddd	%f0, %f2, %f48		;\
	fmuld	%f0, %f2, %f50		;\
	faddd	%f0, %f2, %f52		;\
	fmuld	%f0, %f2, %f54		;\
	faddd	%f0, %f2, %f56		;\
	fmuld	%f0, %f2, %f58		;\
	faddd	%f0, %f2, %f60		;\
	fmuld	%f0, %f2, %f62

/*
 * Macros to save and restore fp registers to/from the stack.
 * Used to save and restore in-use fp registers when we want to use FP.
 */
#define BST_FP_TOSTACK(tmp1)					\
	/* membar #Sync	*/					;\
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, tmp1	;\
	and	tmp1, -VIS_BLOCKSIZE, tmp1 /* block align */	;\
	stda	%f0, [tmp1]ASI_BLK_P				;\
	add	tmp1, VIS_BLOCKSIZE, tmp1			;\
	stda	%f16, [tmp1]ASI_BLK_P				;\
	add	tmp1, VIS_BLOCKSIZE, tmp1			;\
	stda	%f48, [tmp1]ASI_BLK_P				;\
	membar	#Sync

#define	BLD_FP_FROMSTACK(tmp1)					\
	/* membar #Sync - provided at copy completion */	;\
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, tmp1	;\
	and	tmp1, -VIS_BLOCKSIZE, tmp1 /* block align */	;\
	ldda	[tmp1]ASI_BLK_P, %f0				;\
	add	tmp1, VIS_BLOCKSIZE, tmp1			;\
	ldda	[tmp1]ASI_BLK_P, %f16				;\
	add	tmp1, VIS_BLOCKSIZE, tmp1			;\
	ldda	[tmp1]ASI_BLK_P, %f48				;\
	membar	#Sync

#endif /* !NIAGARA_IMPL */

/*
 * Copy a block of storage, returning an error code if `from' or
 * `to' takes a kernel pagefault which cannot be resolved.
 * Returns errno value on pagefault error, 0 if all ok
 */

	.seg	".text"
	.align	4

	ENTRY(kcopy)
#if !defined(NIAGARA_IMPL)
	cmp	%o2, FP_COPY			! check for small copy/leaf case
	bgt,pt	%ncc, .kcopy_more		!
	nop
.kcopy_small:					! setup error handler
	sethi	%hi(.sm_copyerr), %o4
	or	%o4, %lo(.sm_copyerr), %o4	! .sm_copyerr is lofault value
	ldn	[THREAD_REG + T_LOFAULT], %o5	! save existing handler
	! Note that we carefully do *not* flag the setting of
	! t_lofault.
	membar	#Sync				! sync error barrier
	b	.sm_do_copy			! common code
	stn	%o4, [THREAD_REG + T_LOFAULT]	! set t_lofault


.kcopy_more:
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	sethi	%hi(.copyerr), %l7		! copyerr is lofault value
	or	%l7, %lo(.copyerr), %l7
	ldn	[THREAD_REG + T_LOFAULT], %o5	! save existing handler
	! Note that we carefully do *not* flag the setting of
	! t_lofault.
	membar	#Sync				! sync error barrier
	b	.do_copy			! common code
	stn	%l7, [THREAD_REG + T_LOFAULT]	! set t_lofault

/*
 * We got here because of a fault during a small kcopy or bcopy.
 * if a fault handler existed when bcopy was called.
 * No floating point registers are used by the small copies.
 * Small copies are from a leaf routine
 * Errno value is in %g1.
 */
.sm_copyerr:
	! The kcopy will always set a t_lofault handler. If it fires,
	! we're expected to just return the error code and not to
	! invoke any existing error handler. As far as bcopy is concerned,
	! we only set t_lofault if there was an existing lofault handler.
	! In that case we're expected to invoke the previously existing
	! handler after resetting the t_lofault value.
	btst	LOFAULT_SET, %o5
	membar	#Sync				! sync error barrier
	andn	%o5, LOFAULT_SET, %o5		! clear fault flag
	bnz,pn	%ncc, 3f
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	mov	%g1, %o0
3:
	! We're here via bcopy. There must have been an error handler
	! in place otherwise we would have died a nasty death already.
	jmp	%o5				! goto real handler
	mov	%g0, %o0
/*
 *  end of .sm_copyerr
 */

/*
 * We got here because of a fault during kcopy or bcopy if a fault
 * handler existed when bcopy was called.
 * stack and fp registers need to be restored
 * Errno value is in %g1.
 */
.copyerr:
	sethi	%hi(.copyerr2), %l1
	or	%l1, %lo(.copyerr2), %l1
	membar	#Sync				! sync error barrier
	stn	%l1, [THREAD_REG + T_LOFAULT]	! set t_lofault
	btst	FPUSED_FLAG, %o5
	bz,pt	%xcc, 1f
	and	%o5, LOFAULT_SET, %l1	! copy flag to %l1

	membar	#Sync				! sync error barrier
	wr	%l5, 0, %gsr
	btst	FPRS_FEF, %g5
	bz,pt	%icc, 4f
	nop
	! restore fpregs from stack
	BLD_FP_FROMSTACK(%o2)
	ba,pt	%ncc, 2f
	wr	%g5, 0, %fprs		! restore fprs
4:
	FZERO
	wr	%g5, 0, %fprs		! restore fprs
2:
	ldn	[THREAD_REG + T_LWP], %o2
	brnz,pt	%o2, 1f
	nop

	ldsb	[THREAD_REG + T_PREEMPT], %l0
	deccc	%l0
	bnz,pn	%ncc, 1f
	stb	%l0, [THREAD_REG + T_PREEMPT]

	! Check for a kernel preemption request
	ldn	[THREAD_REG + T_CPU], %l0
	ldub	[%l0 + CPU_KPRUNRUN], %l0
	brnz,a,pt	%l0, 1f	! Need to call kpreempt?
	or	%l1, KPREEMPT_FLAG, %l1	! If so, set the flag

	! The kcopy will always set a t_lofault handler. If it fires,
	! we're expected to just return the error code and not to
	! invoke any existing error handler. As far as bcopy is concerned,
	! we only set t_lofault if there was an existing lofault handler.
	! In that case we're expected to invoke the previously existing
	! handler after resetting the t_lofault value.
1:
	andn	%o5, COPY_FLAGS, %o5	! remove flags from lofault address
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault

	! call kpreempt if necessary
	btst	KPREEMPT_FLAG, %l1
	bz,pt	%icc, 2f
	nop
	call	kpreempt
	rdpr	%pil, %o0	! pass %pil
2:
	btst	LOFAULT_SET, %l1
	bnz,pn	%ncc, 3f
	nop
	ret
	restore	%g1, 0, %o0
3:
	! We're here via bcopy. There must have been an error handler
	! in place otherwise we would have died a nasty death already.
	jmp	%o5				! goto real handler
	restore	%g0, 0, %o0			! dispose of copy window

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
 *  end of .copyerr
 */

#else	/* NIAGARA_IMPL */
	save	%sp, -SA(MINFRAME), %sp
	set	.copyerr, %l7			! copyerr is lofault value
	ldn	[THREAD_REG + T_LOFAULT], %o5	! save existing handler
	or	%o5, LOFAULT_SET, %o5
	membar	#Sync				! sync error barrier
	b	.do_copy			! common code
	stn	%l7, [THREAD_REG + T_LOFAULT]	! set t_lofault

/*
 * We got here because of a fault during kcopy.
 * Errno value is in %g1.
 */
.copyerr:
	! The kcopy() *always* sets a t_lofault handler and it ORs LOFAULT_SET
	! into %o5 to indicate it has set t_lofault handler. Need to clear
	! LOFAULT_SET flag before restoring the error handler.
	andn	%o5, LOFAULT_SET, %o5
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	ret
	restore	%g1, 0, %o0
#endif	/* NIAGARA_IMPL */

	SET_SIZE(kcopy)


/*
 * Copy a block of storage - must not overlap (from + len <= to).
 */

	ENTRY(bcopy)
#if !defined(NIAGARA_IMPL)
	cmp	%o2, FP_COPY			! check for small copy/leaf case
	bgt,pt	%ncc, .bcopy_more		!
	nop
.bcopy_small:					! setup error handler
	ldn	[THREAD_REG + T_LOFAULT], %o5	! save existing handler
	tst	%o5
	bz,pt	%icc, .sm_do_copy
	sethi	%hi(.sm_copyerr), %o4
	or	%o4, %lo(.sm_copyerr), %o4	! .sm_copyerr is lofault value
	membar	#Sync				! sync error barrier
	stn	%o4, [THREAD_REG + T_LOFAULT]	! set t_lofault
	or	%o5, LOFAULT_SET, %o5		! Error should trampoline
.sm_do_copy:
	mov	%o0, %g1		! save %o0
	cmp	%o2, SHORTCOPY		! make sure there is enough to align
	ble,pt	%ncc, .bc_smallest
	andcc	%o1, 0x7, %o3		! is dest long aligned
	bnz,pn	%ncc, .bc_align
	andcc	%o1, 1, %o3		! is dest byte aligned

! Destination is long word aligned
.bc_al_src:
	andcc	%o0, 7, %o3
	brnz,pt	%o3, .bc_src_dst_unal8
	nop
/*
 * Special case for handling when src and dest are both long word aligned
 * and total data to move is less than FP_COPY bytes
 * Also handles finish up for large block moves, so may be less than 32 bytes
 */
.bc_medlong:
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .bc_medl31
	nop
.bc_medl32:
	ldx	[%o0], %o4		! move 32 bytes
	subcc	%o2, 32, %o2		! decrement length count by 32
	stx	%o4, [%o1]
	ldx	[%o0+8], %o4
	stx	%o4, [%o1+8]
	ldx	[%o0+16], %o4
	add	%o0, 32, %o0		! increase src ptr by 32
	stx	%o4, [%o1+16]
	ldx	[%o0-8], %o4
	add	%o1, 32, %o1		! increase dst ptr by 32
	bgu,pt	%ncc, .bc_medl32	! repeat if at least 32 bytes left
	stx	%o4, [%o1-8]
.bc_medl31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .bc_medl7		! skip if 7 or fewer bytes left
	nop
.bc_medl8:
	ldx	[%o0], %o4		! move 8 bytes
	add	%o0, 8, %o0		! increase src ptr by 8
	subcc	%o2, 8, %o2		! decrease count by 8
	add	%o1, 8, %o1		! increase dst ptr by 8
	bgu,pt	%ncc, .bc_medl8
	stx	%o4, [%o1-8]
.bc_medl7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bnz,pt	%ncc, .bc_small4	! do final bytes if not finished

.bc_smallx:				! finish up and exit
	tst	%o5
	bz,pt	%ncc, .bc_sm_done
	andn	%o5, COPY_FLAGS, %o5	! remove flags from lofault address
	membar	#Sync			! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
.bc_sm_done:
	retl
	mov	%g0, %o0

.bc_small4:
	cmp	%o2, 4
	blt,pt	%ncc, .bc_small3x	! skip if less than 4 bytes left
	nop				!
	ld	[%o0], %o4		! move 4 bytes
	add	%o0, 4, %o0		! increase src ptr by 4
	add	%o1, 4, %o1		! increase dst ptr by 4
	subcc	%o2, 4, %o2		! decrease count by 4
	bz,pt	%ncc, .bc_smallx
	stw	%o4, [%o1-4]

.bc_small3x:				! Exactly 1, 2, or 3 bytes remain
	subcc	%o2, 1, %o2		! reduce count for cc test
	ldub	[%o0], %o4		! load one byte
	bz,pt	%ncc, .bc_smallx
	stb	%o4, [%o1]		! store one byte
	ldub	[%o0+1], %o4		! load second byte
	subcc	%o2, 1, %o2
	bz,pt	%ncc, .bc_smallx
	stb	%o4, [%o1+1]		! store second byte
	ldub	[%o0+2], %o4		! load third byte
	ba	.bc_smallx
	stb	%o4, [%o1+2]		! store third byte

.bc_smallest:				! 7 or fewer bytes remain
	tst	%o2
	bz,pt	%ncc, .bc_smallx
	cmp	%o2, 4
	blt,pt	%ncc, .bc_small3x
	nop
	ldub	[%o0], %o4		! read byte
	subcc	%o2, 4, %o2		! reduce count by 4
	stb	%o4, [%o1]		! write byte
	ldub	[%o0+1], %o4		! repeat for total of 4 bytes
	add	%o0, 4, %o0		! advance src by 4
	stb	%o4, [%o1+1]
	ldub	[%o0-2], %o4
	add	%o1, 4, %o1		! advance dst by 4
	stb	%o4, [%o1-2]
	ldub	[%o0-1], %o4
	bnz,pt	%ncc, .bc_small3x
	stb	%o4, [%o1-1]
	ba	.bc_smallx
	nop

/*
 * Align destination to long word boundary
 */
.bc_align:				! byte align test in prior branch delay
	bnz,pt	%ncc, .bc_al_d1
.bc_al_d1f:				! dest is now half word aligned
	andcc	%o1, 2, %o3
	bnz,pt	%ncc, .bc_al_d2
.bc_al_d2f:				! dest is now word aligned
	andcc	%o1, 4, %o3		! is dest longword aligned?
	bz,pt	%ncc, .bc_al_src
	nop
.bc_al_d4:				! dest is word aligned;  src is unknown
	ldub	[%o0], %o4		! move a word (src align unknown)
	ldub	[%o0+1], %o3
	sll	%o4, 24, %o4		! position
	sll	%o3, 16, %o3		! position
	or	%o4, %o3, %o3		! merge
	ldub	[%o0+2], %o4
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o3		! merge
	ldub	[%o0+3], %o4
	or	%o4, %o3, %o4		! merge
	stw	%o4,[%o1]		! store four bytes
	add	%o0, 4, %o0		! adjust src by 4
	add	%o1, 4, %o1		! adjust dest by 4
	sub	%o2, 4, %o2		! adjust count by 4
	andcc	%o0, 7, %o3		! check for src long word alignment
	brz,pt	%o3, .bc_medlong
.bc_src_dst_unal8:
	! dst is 8-byte aligned, src is not
	! Size is less than FP_COPY
	! Following code is to select for alignment
	andcc	%o0, 0x3, %o3		! test word alignment
	bz,pt	%ncc, .bc_medword
	nop
	andcc	%o0, 0x1, %o3		! test halfword alignment
	bnz,pt	%ncc, .bc_med_byte	! go to byte move if not halfword
	andcc	%o0, 0x2, %o3		! test which byte alignment
	ba	.bc_medhalf
	nop
.bc_al_d1:				! align dest to half word
	ldub	[%o0], %o4		! move a byte
	add	%o0, 1, %o0
	stb	%o4, [%o1]
	add	%o1, 1, %o1
	andcc	%o1, 2, %o3
	bz,pt	%ncc, .bc_al_d2f
	sub	%o2, 1, %o2
.bc_al_d2:				! align dest to word
	ldub	[%o0], %o4		! move a half-word (src align unknown)
	ldub	[%o0+1], %o3
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o4		! merge
	sth	%o4, [%o1]
	add	%o0, 2, %o0
	add	%o1, 2, %o1
	andcc	%o1, 4, %o3		! is dest longword aligned?
	bz,pt	%ncc, .bc_al_src
	sub	%o2, 2, %o2
	ba	.bc_al_d4
	nop
/*
 * Handle all cases where src and dest are aligned on word
 * boundaries. Use unrolled loops for better performance.
 * This option wins over standard large data move when 
 * source and destination is in cache for medium
 * to short data moves.
 */
.bc_medword:
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .bc_medw31
	nop
.bc_medw32:
	ld	[%o0], %o4		! move a block of 32 bytes
	stw	%o4, [%o1]
	ld	[%o0+4], %o4
	stw	%o4, [%o1+4]
	ld	[%o0+8], %o4
	stw	%o4, [%o1+8]
	ld	[%o0+12], %o4
	stw	%o4, [%o1+12]
	ld	[%o0+16], %o4
	stw	%o4, [%o1+16]
	ld	[%o0+20], %o4
	subcc	%o2, 32, %o2		! decrement length count
	stw	%o4, [%o1+20]
	ld	[%o0+24], %o4
	add	%o0, 32, %o0		! increase src ptr by 32
	stw	%o4, [%o1+24]
	ld	[%o0-4], %o4
	add	%o1, 32, %o1		! increase dst ptr by 32
	bgu,pt	%ncc, .bc_medw32	! repeat if at least 32 bytes left
	stw	%o4, [%o1-4]
.bc_medw31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .bc_medw7		! skip if 7 or fewer bytes left
	nop				!
.bc_medw15:
	ld	[%o0], %o4		! move a block of 8 bytes
	subcc	%o2, 8, %o2		! decrement length count
	stw	%o4, [%o1]
	add	%o0, 8, %o0		! increase src ptr by 8
	ld	[%o0-4], %o4
	add	%o1, 8, %o1		! increase dst ptr by 8
	bgu,pt	%ncc, .bc_medw15
	stw	%o4, [%o1-4]
.bc_medw7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bz,pt	%ncc, .bc_smallx	! exit if finished
	cmp	%o2, 4
	blt,pt	%ncc, .bc_small3x	! skip if less than 4 bytes left
	nop				!
	ld	[%o0], %o4		! move 4 bytes
	add	%o0, 4, %o0		! increase src ptr by 4
	add	%o1, 4, %o1		! increase dst ptr by 4
	subcc	%o2, 4, %o2		! decrease count by 4
	bnz	.bc_small3x
	stw	%o4, [%o1-4]
	ba	.bc_smallx
	nop

.bc_medhalf:
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .bc_medh31
	nop
.bc_medh32:				! load and store block of 32 bytes
	subcc	%o2, 32, %o2		! decrement length count

	lduh	[%o0], %o4		! move 32 bytes
	lduw	[%o0+2], %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduh	[%o0+6], %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1]

	lduh	[%o0+8], %o4
	lduw	[%o0+10], %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduh	[%o0+14], %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+8]

	lduh	[%o0+16], %o4
	lduw	[%o0+18], %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduh	[%o0+22], %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+16]

	add	%o0, 32, %o0		! increase src ptr by 32
	add	%o1, 32, %o1		! increase dst ptr by 32

	lduh	[%o0-8], %o4
	lduw	[%o0-6], %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduh	[%o0-2], %o4
	or	%o3, %o4, %o4
	bgu,pt	%ncc, .bc_medh32	! repeat if at least 32 bytes left
	stx	%o4, [%o1-8]

.bc_medh31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .bc_medh7		! skip if 7 or fewer bytes left
	nop				!
.bc_medh15:
	lduh	[%o0], %o4		! move 16 bytes
	subcc	%o2, 8, %o2		! decrement length count
	lduw	[%o0+2], %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	add	%o1, 8, %o1		! increase dst ptr by 8
	lduh	[%o0+6], %o4
	add	%o0, 8, %o0		! increase src ptr by 8
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .bc_medh15
	stx	%o4, [%o1-8]
.bc_medh7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bz,pt	%ncc, .bc_smallx	! exit if finished
	cmp	%o2, 4
	blt,pt	%ncc, .bc_small3x	! skip if less than 4 bytes left
	nop				!
	lduh	[%o0], %o4
	sll	%o4, 16, %o4
	lduh	[%o0+2], %o3
	or	%o3, %o4, %o4
	subcc	%o2, 4, %o2
	add	%o0, 4, %o0
	add	%o1, 4, %o1
	bnz	.bc_small3x
	stw	%o4, [%o1-4]
	ba	.bc_smallx
	nop

	.align 16
.bc_med_byte:
	bnz,pt	%ncc, .bc_medbh32a	! go to correct byte move
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .bc_medb31
	nop
.bc_medb32:				! Alignment 1 or 5
	subcc	%o2, 32, %o2		! decrement length count

	ldub	[%o0], %o4		! load and store a block of 32 bytes
	sllx	%o4, 56, %o3
	lduh	[%o0+1], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduw	[%o0+3], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+7], %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1]

	ldub	[%o0+8], %o4
	sllx	%o4, 56, %o3
	lduh	[%o0+9], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduw	[%o0+11], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+15], %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+8]

	ldub	[%o0+16], %o4
	sllx	%o4, 56, %o3
	lduh	[%o0+17], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduw	[%o0+19], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+23], %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+16]

	add	%o0, 32, %o0		! increase src ptr by 32
	add	%o1, 32, %o1		! increase dst ptr by 32

	ldub	[%o0-8], %o4
	sllx	%o4, 56, %o3
	lduh	[%o0-7], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduw	[%o0-5], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0-1], %o4
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .bc_medb32	! repeat if at least 32 bytes left
	stx	%o4, [%o1-8]

.bc_medb31:				! 31 or fewer bytes remaining
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .bc_medb7		! skip if 7 or fewer bytes left
	nop				!
.bc_medb15:

	ldub	[%o0], %o4		! load and store a block of 8 bytes
	subcc	%o2, 8, %o2		! decrement length count
	sllx	%o4, 56, %o3
	lduh	[%o0+1], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduw	[%o0+3], %o4
	add	%o1, 8, %o1		! increase dst ptr by 16
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+7], %o4
	add	%o0, 8, %o0		! increase src ptr by 16
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .bc_medb15
	stx	%o4, [%o1-8]
.bc_medb7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bz,pt	%ncc, .bc_smallx	! exit if finished
	cmp	%o2, 4
	blt,pt	%ncc, .bc_small3x	! skip if less than 4 bytes left
	nop				!
	ldub	[%o0], %o4		! move 4 bytes
	sll	%o4, 24, %o3
	lduh	[%o0+1], %o4
	sll	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+3], %o4
	or	%o4, %o3, %o4
	subcc	%o2, 4, %o2
	add	%o0, 4, %o0
	add	%o1, 4, %o1
	bnz	.bc_small3x
	stw	%o4, [%o1-4]
	ba	.bc_smallx
	nop

	.align 16
.bc_medbh32a:				! Alignment 3 or 7
	ble,pt	%ncc, .bc_medbh31
	nop
.bc_medbh32:				! Alignment 3 or 7
	subcc	%o2, 32, %o2		! decrement length count

	ldub	[%o0], %o4		! load and store a block of 32 bytes
	sllx	%o4, 56, %o3
	lduw	[%o0+1], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduh	[%o0+5], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+7], %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1]

	ldub	[%o0+8], %o4
	sllx	%o4, 56, %o3
	lduw	[%o0+9], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduh	[%o0+13], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+15], %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+8]

	ldub	[%o0+16], %o4
	sllx	%o4, 56, %o3
	lduw	[%o0+17], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduh	[%o0+21], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+23], %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+16]

	add	%o0, 32, %o0		! increase src ptr by 32
	add	%o1, 32, %o1		! increase dst ptr by 32

	ldub	[%o0-8], %o4
	sllx	%o4, 56, %o3
	lduw	[%o0-7], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduh	[%o0-3], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0-1], %o4
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .bc_medbh32	! repeat if at least 32 bytes left
	stx	%o4, [%o1-8]

.bc_medbh31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .bc_medb7		! skip if 7 or fewer bytes left
	nop				!
.bc_medbh15:
	ldub	[%o0], %o4		! load and store a block of 8 bytes
	sllx	%o4, 56, %o3
	lduw	[%o0+1], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduh	[%o0+5], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+7], %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1]
	subcc	%o2, 8, %o2		! decrement length count
	add	%o1, 8, %o1		! increase dst ptr by 8
	add	%o0, 8, %o0		! increase src ptr by 8
	bgu,pt	%ncc, .bc_medbh15
	stx	%o4, [%o1-8]
	ba	.bc_medb7
	nop
	
	SET_SIZE(bcopy)
/*
 * The _more entry points are not intended to be used directly by
 * any caller from outside this file.  They are provided to allow
 * profiling and dtrace of the portions of the copy code that uses
 * the floating point registers.
*/
	ENTRY(bcopy_more)
.bcopy_more:
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	ldn	[THREAD_REG + T_LOFAULT], %o5	! save existing handler
	brz,pt	%o5, .do_copy
	nop
	sethi	%hi(.copyerr), %l7		! copyerr is lofault value
	or	%l7, %lo(.copyerr), %l7
	membar	#Sync				! sync error barrier
	stn	%l7, [THREAD_REG + T_LOFAULT]	! set t_lofault
	! We've already captured whether t_lofault was zero on entry.
	! We need to mark ourselves as being from bcopy since both
	! kcopy and bcopy use the same code path. If LOFAULT_SET is
	! set and the saved lofault was zero, we won't reset lofault on
	! returning.
	or	%o5, LOFAULT_SET, %o5
.do_copy:
	ldn	[THREAD_REG + T_LWP], %o3
	brnz,pt	%o3, 1f
	nop
/*
 * kpreempt_disable();
 */
	ldsb	[THREAD_REG +T_PREEMPT], %o3
	inc	%o3
	stb	%o3, [THREAD_REG + T_PREEMPT]
1:
/*
 * Following code is for large copies. We know there is at
 * least FP_COPY bytes available. FP regs are used, so
 *  we save registers and fp regs before starting
 */
	rd	%fprs, %g5		! check for unused fp
	or	%o5,FPUSED_FLAG,%o5
	! if fprs.fef == 0, set it.
	! Setting it when already set costs more than checking
	andcc	%g5, FPRS_FEF, %g5	! test FEF, fprs.du = fprs.dl = 0
	bz,pt	%ncc, .bc_fp_unused
	prefetch [%i0 + (1 * CACHE_LINE)], #one_read
	BST_FP_TOSTACK(%o3)
	ba	.bc_fp_ready
.bc_fp_unused:
	andcc	%i1, 1, %o3		! is dest byte aligned
	wr	%g0, FPRS_FEF, %fprs	! fprs.fef = 1
.bc_fp_ready:
	rd	%gsr, %l5		! save %gsr value
	bnz,pt	%ncc, .bc_big_d1
.bc_big_d1f:				! dest is now half word aligned
	andcc	%i1, 2, %o3
	bnz,pt	%ncc, .bc_big_d2
.bc_big_d2f:				! dest is now word aligned
	andcc	%i1, 4, %o3
	bnz,pt	%ncc, .bc_big_d4
.bc_big_d4f:				! dest is now long word aligned
	andcc	%i0, 7, %o3		! is src long word aligned
	brnz,pt	%o3, .bc_big_unal8
	prefetch [%i0 + (2 * CACHE_LINE)], #one_read
	
	! Src and dst are long word aligned
	! align dst to 64 byte boundary
	andcc	%i1, 0x3f, %o3		! %o3 == 0 means dst is 64 byte aligned
	brz,pn	%o3, .bc_al_to_64
	nop
	sub	%o3, 64, %o3		! %o3 has negative bytes to move
	add	%i2, %o3, %i2		! adjust remaining count
	andcc	%o3, 8, %o4		! odd long words to move?
	brz,pt	%o4, .bc_al_to_16
	nop
	add	%o3, 8, %o3
	ldx	[%i0], %o4
	add	%i0, 8, %i0		! increment src ptr
	add	%i1, 8, %i1		! increment dst ptr
	stx	%o4, [%i1-8]
! Dest is aligned on 16 bytes, src 8 byte aligned
.bc_al_to_16:
	andcc	%o3, 0x30, %o4		! pair of long words to move?
	brz,pt	%o4, .bc_al_to_64
	nop
.bc_al_mv_16:
	add	%o3, 16, %o3
	ldx	[%i0], %o4
	stx	%o4, [%i1]
	ldx	[%i0+8], %o4
	add	%i0, 16, %i0		! increment src ptr
	stx	%o4, [%i1+8]
	andcc	%o3, 48, %o4
	brnz,pt	%o4, .bc_al_mv_16
	add	%i1, 16, %i1		! increment dst ptr
! Dest is aligned on 64 bytes, src 8 byte aligned
.bc_al_to_64:
	! Determine source alignment
	! to correct 8 byte offset
	andcc	%i0, 32, %o3
	brnz,pn	%o3, .bc_aln_1
	andcc	%i0, 16, %o3
	brnz,pn	%o3, .bc_aln_01
	andcc	%i0, 8, %o3
	brz,pn	%o3, .bc_aln_000
	prefetch [%i0 + (3 * CACHE_LINE)], #one_read
	ba	.bc_aln_001
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read

.bc_aln_01:
	brnz,pn	%o3, .bc_aln_011
	prefetch [%i0 + (3 * CACHE_LINE)], #one_read
	ba	.bc_aln_010
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
.bc_aln_1:
	andcc	%i0, 16, %o3
	brnz,pn	%o3, .bc_aln_11
	andcc	%i0, 8, %o3
	brnz,pn	%o3, .bc_aln_101
	prefetch [%i0 + (3 * CACHE_LINE)], #one_read
	ba	.bc_aln_100
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
.bc_aln_11:
	brz,pn	%o3, .bc_aln_110
	prefetch [%i0 + (3 * CACHE_LINE)], #one_read

.bc_aln_111:
! Alignment off by 8 bytes
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	ldd	[%i0], %d0
	add	%i0, 8, %i0
	sub	%i2, 8, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.bc_aln_111_loop:
	ldda	[%i0]ASI_BLK_P,%d16		! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d2
	fmovd	%d18, %d4
	fmovd	%d20, %d6
	fmovd	%d22, %d8
	fmovd	%d24, %d10
	fmovd	%d26, %d12
	fmovd	%d28, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d30, %d0
	bgt,pt	%ncc, .bc_aln_111_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	ba	.bc_remain_stuff
	add	%i1, 8, %i1
	! END OF aln_111

.bc_aln_110:
! Alignment off by 16 bytes
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	add	%i0, 16, %i0
	sub	%i2, 16, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.bc_aln_110_loop:
	ldda	[%i0]ASI_BLK_P,%d16		! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d4
	fmovd	%d18, %d6
	fmovd	%d20, %d8
	fmovd	%d22, %d10
	fmovd	%d24, %d12
	fmovd	%d26, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d28, %d0
	fmovd	%d30, %d2
	bgt,pt	%ncc, .bc_aln_110_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	ba	.bc_remain_stuff
	add	%i1, 16, %i1
	! END OF aln_110

.bc_aln_101:
! Alignment off by 24 bytes
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	ldd	[%i0+16], %d4
	add	%i0, 24, %i0
	sub	%i2, 24, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.bc_aln_101_loop:
	ldda	[%i0]ASI_BLK_P,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d6
	fmovd	%d18, %d8
	fmovd	%d20, %d10
	fmovd	%d22, %d12
	fmovd	%d24, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d26, %d0
	fmovd	%d28, %d2
	fmovd	%d30, %d4
	bgt,pt	%ncc, .bc_aln_101_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	std	%d4, [%i1+16]
	ba	.bc_remain_stuff
	add	%i1, 24, %i1
	! END OF aln_101

.bc_aln_100:
! Alignment off by 32 bytes
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	ldd	[%i0+16],%d4
	ldd	[%i0+24],%d6
	add	%i0, 32, %i0
	sub	%i2, 32, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.bc_aln_100_loop:
	ldda	[%i0]ASI_BLK_P,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d8
	fmovd	%d18, %d10
	fmovd	%d20, %d12
	fmovd	%d22, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d24, %d0
	fmovd	%d26, %d2
	fmovd	%d28, %d4
	fmovd	%d30, %d6
	bgt,pt	%ncc, .bc_aln_100_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	std	%d4, [%i1+16]
	std	%d6, [%i1+24]
	ba	.bc_remain_stuff
	add	%i1, 32, %i1
	! END OF aln_100

.bc_aln_011:
! Alignment off by 40 bytes
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	ldd	[%i0+16], %d4
	ldd	[%i0+24], %d6
	ldd	[%i0+32], %d8
	add	%i0, 40, %i0
	sub	%i2, 40, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.bc_aln_011_loop:
	ldda	[%i0]ASI_BLK_P,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d10
	fmovd	%d18, %d12
	fmovd	%d20, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d22, %d0
	fmovd	%d24, %d2
	fmovd	%d26, %d4
	fmovd	%d28, %d6
	fmovd	%d30, %d8
	bgt,pt	%ncc, .bc_aln_011_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	std	%d4, [%i1+16]
	std	%d6, [%i1+24]
	std	%d8, [%i1+32]
	ba	.bc_remain_stuff
	add	%i1, 40, %i1
	! END OF aln_011

.bc_aln_010:
! Alignment off by 48 bytes
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	ldd	[%i0+16], %d4
	ldd	[%i0+24], %d6
	ldd	[%i0+32], %d8
	ldd	[%i0+40], %d10
	add	%i0, 48, %i0
	sub	%i2, 48, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.bc_aln_010_loop:
	ldda	[%i0]ASI_BLK_P,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d12
	fmovd	%d18, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d20, %d0
	fmovd	%d22, %d2
	fmovd	%d24, %d4
	fmovd	%d26, %d6
	fmovd	%d28, %d8
	fmovd	%d30, %d10
	bgt,pt	%ncc, .bc_aln_010_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	std	%d4, [%i1+16]
	std	%d6, [%i1+24]
	std	%d8, [%i1+32]
	std	%d10, [%i1+40]
	ba	.bc_remain_stuff
	add	%i1, 48, %i1
	! END OF aln_010

.bc_aln_001:
! Alignment off by 56 bytes
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	ldd	[%i0+16], %d4
	ldd	[%i0+24], %d6
	ldd	[%i0+32], %d8
	ldd	[%i0+40], %d10
	ldd	[%i0+48], %d12
	add	%i0, 56, %i0
	sub	%i2, 56, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.bc_aln_001_loop:
	ldda	[%i0]ASI_BLK_P,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d18, %d0
	fmovd	%d20, %d2
	fmovd	%d22, %d4
	fmovd	%d24, %d6
	fmovd	%d26, %d8
	fmovd	%d28, %d10
	fmovd	%d30, %d12
	bgt,pt	%ncc, .bc_aln_001_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	std	%d4, [%i1+16]
	std	%d6, [%i1+24]
	std	%d8, [%i1+32]
	std	%d10, [%i1+40]
	std	%d12, [%i1+48]
	ba	.bc_remain_stuff
	add	%i1, 56, %i1
	! END OF aln_001

.bc_aln_000:
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.bc_aln_000_loop:
	ldda	[%i0]ASI_BLK_P,%d0
	subcc	%o3, 64, %o3
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	bgt,pt	%ncc, .bc_aln_000_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	! END OF aln_000

.bc_remain_stuff:
	subcc	%i2, 31, %i2		! adjust length to allow cc test
	ble,pt	%ncc, .bc_aln_31
	nop
.bc_aln_32:
	ldx	[%i0], %o4		! move 32 bytes
	subcc	%i2, 32, %i2		! decrement length count by 32
	stx	%o4, [%i1]
	ldx	[%i0+8], %o4
	stx	%o4, [%i1+8]
	ldx	[%i0+16], %o4
	add	%i0, 32, %i0		! increase src ptr by 32
	stx	%o4, [%i1+16]
	ldx	[%i0-8], %o4
	add	%i1, 32, %i1		! increase dst ptr by 32
	bgu,pt	%ncc, .bc_aln_32	! repeat if at least 32 bytes left
	stx	%o4, [%i1-8]
.bc_aln_31:
	addcc	%i2, 24, %i2		! adjust count to be off by 7
	ble,pt	%ncc, .bc_aln_7		! skip if 7 or fewer bytes left
	nop				!
.bc_aln_15:
	ldx	[%i0], %o4		! move 8 bytes
	add	%i0, 8, %i0		! increase src ptr by 8
	subcc	%i2, 8, %i2		! decrease count by 8
	add	%i1, 8, %i1		! increase dst ptr by 8
	bgu,pt	%ncc, .bc_aln_15
	stx	%o4, [%i1-8]		!
.bc_aln_7:
	addcc	%i2, 7, %i2		! finish adjustment of remaining count
	bz,pt	%ncc, .bc_exit		! exit if finished
	cmp	%i2, 4
	blt,pt	%ncc, .bc_unaln3x	! skip if less than 4 bytes left
	nop				!
	ld	[%i0], %o4		! move 4 bytes
	add	%i0, 4, %i0		! increase src ptr by 4
	add	%i1, 4, %i1		! increase dst ptr by 4
	subcc	%i2, 4, %i2		! decrease count by 4
	bnz	.bc_unaln3x
	stw	%o4, [%i1-4]
	ba	.bc_exit
	nop

	! destination alignment code
.bc_big_d1:
	ldub	[%i0], %o4		! move a byte
	add	%i0, 1, %i0
	stb	%o4, [%i1]
	add	%i1, 1, %i1
	andcc	%i1, 2, %o3
	bz,pt	%ncc, .bc_big_d2f
	sub	%i2, 1, %i2
.bc_big_d2:
	ldub	[%i0], %o4		! move a half-word (src align unknown)
	ldub	[%i0+1], %o3
	add	%i0, 2, %i0
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o4		! merge
	sth	%o4, [%i1]
	add	%i1, 2, %i1
	andcc	%i1, 4, %o3
	bz,pt	%ncc, .bc_big_d4f
	sub	%i2, 2, %i2
.bc_big_d4:
	ldub	[%i0], %o4		! move a word (src align unknown)
	ldub	[%i0+1], %o3
	sll	%o4, 24, %o4		! position
	sll	%o3, 16, %o3		! position
	or	%o4, %o3, %o3		! merge
	ldub	[%i0+2], %o4
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o3		! merge
	ldub	[%i0+3], %o4
	or	%o4, %o3, %o4		! merge
	stw	%o4,[%i1]		! store four bytes
	add	%i0, 4, %i0		! adjust src by 4
	add	%i1, 4, %i1		! adjust dest by 4
	ba	.bc_big_d4f
	sub	%i2, 4, %i2		! adjust count by 4


	! Dst is on 8 byte boundary; src is not;
.bc_big_unal8:
	andcc	%i1, 0x3f, %o3		! is dst 64-byte block aligned?
	bz	%ncc, .bc_unalnsrc
	sub	%o3, 64, %o3		! %o3 will be multiple of 8
	neg	%o3			! bytes until dest is 64 byte aligned
	sub	%i2, %o3, %i2		! update cnt with bytes to be moved
	! Move bytes according to source alignment
	andcc	%i0, 0x1, %o4
	bnz	%ncc, .bc_unalnbyte	! check for byte alignment
	nop
	andcc	%i0, 2, %o4		! check for half word alignment
	bnz	%ncc, .bc_unalnhalf
	nop
	! Src is word aligned, move bytes until dest 64 byte aligned
.bc_unalnword:
	ld	[%i0], %o4		! load 4 bytes
	stw	%o4, [%i1]		! and store 4 bytes
	ld	[%i0+4], %o4		! load 4 bytes
	add	%i0, 8, %i0		! increase src ptr by 8
	stw	%o4, [%i1+4]		! and store 4 bytes
	subcc	%o3, 8, %o3		! decrease count by 8
	bnz	%ncc, .bc_unalnword
	add	%i1, 8, %i1		! increase dst ptr by 8
	ba	.bc_unalnsrc
	nop

	! Src is half-word aligned, move bytes until dest 64 byte aligned
.bc_unalnhalf:
	lduh	[%i0], %o4		! load 2 bytes
	sllx	%o4, 32, %i3		! shift left
	lduw	[%i0+2], %o4
	or	%o4, %i3, %i3
	sllx	%i3, 16, %i3
	lduh	[%i0+6], %o4
	or	%o4, %i3, %i3
	stx	%i3, [%i1]
	add	%i0, 8, %i0
	subcc	%o3, 8, %o3
	bnz	%ncc, .bc_unalnhalf
	add	%i1, 8, %i1
	ba	.bc_unalnsrc
	nop

	! Src is Byte aligned, move bytes until dest 64 byte aligned
.bc_unalnbyte:
	sub	%i1, %i0, %i1		! share pointer advance
.bc_unalnbyte_loop:
	ldub	[%i0], %o4
	sllx	%o4, 56, %i3
	lduh	[%i0+1], %o4
	sllx	%o4, 40, %o4
	or	%o4, %i3, %i3
	lduh	[%i0+3], %o4
	sllx	%o4, 24, %o4
	or	%o4, %i3, %i3
	lduh	[%i0+5], %o4
	sllx	%o4, 8, %o4
	or	%o4, %i3, %i3
	ldub	[%i0+7], %o4
	or	%o4, %i3, %i3
	stx	%i3, [%i1+%i0]
	subcc	%o3, 8, %o3
	bnz	%ncc, .bc_unalnbyte_loop
	add	%i0, 8, %i0
	add	%i1,%i0, %i1		! restore pointer

	! Destination is now block (64 byte aligned), src is not 8 byte aligned
.bc_unalnsrc:
	andn	%i2, 0x3f, %i3		! %i3 is multiple of block size
	and	%i2, 0x3f, %i2		! residue bytes in %i2
	add	%i2, 64, %i2		! Insure we don't load beyond
	sub	%i3, 64, %i3		! end of source buffer

	andn	%i0, 0x3f, %o4		! %o4 has block aligned src address
	prefetch [%o4 + (3 * CACHE_LINE)], #one_read
	alignaddr %i0, %g0, %g0		! generate %gsr
	add	%i0, %i3, %i0		! advance %i0 to after blocks
	!
	! Determine source alignment to correct 8 byte offset
	andcc	%i0, 0x20, %o3
	brnz,pn	%o3, .bc_unaln_1
	andcc	%i0, 0x10, %o3
	brnz,pn	%o3, .bc_unaln_01
	andcc	%i0, 0x08, %o3
	brz,a	%o3, .bc_unaln_000
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.bc_unaln_001
	nop
.bc_unaln_01:
	brnz,a	%o3, .bc_unaln_011
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.bc_unaln_010
	nop
.bc_unaln_1:
	brnz,pn	%o3, .bc_unaln_11
	andcc	%i0, 0x08, %o3
	brnz,a	%o3, .bc_unaln_101
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.bc_unaln_100
	nop
.bc_unaln_11:
	brz,pn	%o3, .bc_unaln_110
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read

.bc_unaln_111:
	ldd	[%o4+56], %d14
.bc_unaln_111_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d14, %d16, %d48
	faligndata %d16, %d18, %d50
	faligndata %d18, %d20, %d52
	faligndata %d20, %d22, %d54
	faligndata %d22, %d24, %d56
	faligndata %d24, %d26, %d58
	faligndata %d26, %d28, %d60
	faligndata %d28, %d30, %d62
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .bc_unaln_111_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.bc_unaln_done
	nop

.bc_unaln_110:
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.bc_unaln_110_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d12, %d14, %d48
	faligndata %d14, %d16, %d50
	faligndata %d16, %d18, %d52
	faligndata %d18, %d20, %d54
	faligndata %d20, %d22, %d56
	faligndata %d22, %d24, %d58
	faligndata %d24, %d26, %d60
	faligndata %d26, %d28, %d62
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .bc_unaln_110_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.bc_unaln_done
	nop

.bc_unaln_101:
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.bc_unaln_101_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d10, %d12, %d48
	faligndata %d12, %d14, %d50
	faligndata %d14, %d16, %d52
	faligndata %d16, %d18, %d54
	faligndata %d18, %d20, %d56
	faligndata %d20, %d22, %d58
	faligndata %d22, %d24, %d60
	faligndata %d24, %d26, %d62
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .bc_unaln_101_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.bc_unaln_done
	nop

.bc_unaln_100:
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.bc_unaln_100_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d8, %d10, %d48
	faligndata %d10, %d12, %d50
	faligndata %d12, %d14, %d52
	faligndata %d14, %d16, %d54
	faligndata %d16, %d18, %d56
	faligndata %d18, %d20, %d58
	faligndata %d20, %d22, %d60
	faligndata %d22, %d24, %d62
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .bc_unaln_100_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.bc_unaln_done
	nop

.bc_unaln_011:
	ldd	[%o4+24], %d6
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.bc_unaln_011_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d6, %d8, %d48
	faligndata %d8, %d10, %d50
	faligndata %d10, %d12, %d52
	faligndata %d12, %d14, %d54
	faligndata %d14, %d16, %d56
	faligndata %d16, %d18, %d58
	faligndata %d18, %d20, %d60
	faligndata %d20, %d22, %d62
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .bc_unaln_011_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.bc_unaln_done
	nop

.bc_unaln_010:
	ldd	[%o4+16], %d4
	ldd	[%o4+24], %d6
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.bc_unaln_010_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d4, %d6, %d48
	faligndata %d6, %d8, %d50
	faligndata %d8, %d10, %d52
	faligndata %d10, %d12, %d54
	faligndata %d12, %d14, %d56
	faligndata %d14, %d16, %d58
	faligndata %d16, %d18, %d60
	faligndata %d18, %d20, %d62
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .bc_unaln_010_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.bc_unaln_done
	nop

.bc_unaln_001:
	ldd	[%o4+8], %d2
	ldd	[%o4+16], %d4
	ldd	[%o4+24], %d6
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.bc_unaln_001_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d2, %d4, %d48
	faligndata %d4, %d6, %d50
	faligndata %d6, %d8, %d52
	faligndata %d8, %d10, %d54
	faligndata %d10, %d12, %d56
	faligndata %d12, %d14, %d58
	faligndata %d14, %d16, %d60
	faligndata %d16, %d18, %d62
	fmovd	%d18, %d2
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .bc_unaln_001_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.bc_unaln_done
	nop

.bc_unaln_000:
	ldda	[%o4]ASI_BLK_P, %d0
.bc_unaln_000_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d0, %d2, %d48
	faligndata %d2, %d4, %d50
	faligndata %d4, %d6, %d52
	faligndata %d6, %d8, %d54
	faligndata %d8, %d10, %d56
	faligndata %d10, %d12, %d58
	faligndata %d12, %d14, %d60
	faligndata %d14, %d16, %d62
	fmovd	%d16, %d0
	fmovd	%d18, %d2
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .bc_unaln_000_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read

.bc_unaln_done:
	! Handle trailing bytes, 64 to 127
	! Dest long word aligned, Src not long word aligned
	cmp	%i2, 15
	bleu	%ncc, .bc_unaln_short

	andn	%i2, 0x7, %i3		! %i3 is multiple of 8
	and	%i2, 0x7, %i2		! residue bytes in %i2
	add	%i2, 8, %i2
	sub	%i3, 8, %i3		! insure we don't load past end of src
	andn	%i0, 0x7, %o4		! %o4 has long word aligned src address
	add	%i0, %i3, %i0		! advance %i0 to after multiple of 8
	ldd	[%o4], %d0		! fetch partial word
.bc_unaln_by8:
	ldd	[%o4+8], %d2
	add	%o4, 8, %o4
	faligndata %d0, %d2, %d16
	subcc	%i3, 8, %i3
	std	%d16, [%i1]
	fmovd	%d2, %d0
	bgu,pt	%ncc, .bc_unaln_by8
	add	%i1, 8, %i1

.bc_unaln_short:
	cmp	%i2, 8
	blt,pt	%ncc, .bc_unalnfin
	nop
	ldub	[%i0], %o4
	sll	%o4, 24, %o3
	ldub	[%i0+1], %o4
	sll	%o4, 16, %o4
	or	%o4, %o3, %o3
	ldub	[%i0+2], %o4
	sll	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%i0+3], %o4
	or	%o4, %o3, %o3
	stw	%o3, [%i1]
	ldub	[%i0+4], %o4
	sll	%o4, 24, %o3
	ldub	[%i0+5], %o4
	sll	%o4, 16, %o4
	or	%o4, %o3, %o3
	ldub	[%i0+6], %o4
	sll	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%i0+7], %o4
	or	%o4, %o3, %o3
	stw	%o3, [%i1+4]
	add	%i0, 8, %i0
	add	%i1, 8, %i1
	sub	%i2, 8, %i2
.bc_unalnfin:
	cmp	%i2, 4
	blt,pt	%ncc, .bc_unalnz
	tst	%i2
	ldub	[%i0], %o3		! read byte
	subcc	%i2, 4, %i2		! reduce count by 4
	sll	%o3, 24, %o3		! position
	ldub	[%i0+1], %o4
	sll	%o4, 16, %o4		! position
	or	%o4, %o3, %o3		! merge
	ldub	[%i0+2], %o4
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o3		! merge
	add	%i1, 4, %i1		! advance dst by 4
	ldub	[%i0+3], %o4
	add	%i0, 4, %i0		! advance src by 4
	or	%o4, %o3, %o4		! merge
	bnz,pt	%ncc, .bc_unaln3x
	stw	%o4, [%i1-4]
	ba	.bc_exit
	nop
.bc_unalnz:
	bz,pt	%ncc, .bc_exit
.bc_unaln3x:				! Exactly 1, 2, or 3 bytes remain
	subcc	%i2, 1, %i2		! reduce count for cc test
	ldub	[%i0], %o4		! load one byte
	bz,pt	%ncc, .bc_exit
	stb	%o4, [%i1]		! store one byte
	ldub	[%i0+1], %o4		! load second byte
	subcc	%i2, 1, %i2
	bz,pt	%ncc, .bc_exit
	stb	%o4, [%i1+1]		! store second byte
	ldub	[%i0+2], %o4		! load third byte
	stb	%o4, [%i1+2]		! store third byte
.bc_exit:
	wr	%l5, %g0, %gsr		! restore %gsr
	brnz	%g5, .bc_fp_restore
	and	%o5, COPY_FLAGS, %l1	! save flags in %l1
	FZERO
	wr	%g5, %g0, %fprs
	ba,pt	%ncc, .bc_ex2
	nop
.bc_fp_restore:
	BLD_FP_FROMSTACK(%o4)
.bc_ex2:
	ldn	[THREAD_REG + T_LWP], %o2
	brnz,pt	%o2, 1f
	nop

	ldsb	[THREAD_REG + T_PREEMPT], %l0
	deccc	%l0
	bnz,pn	%ncc, 1f
	stb	%l0, [THREAD_REG + T_PREEMPT]

	! Check for a kernel preemption request
	ldn	[THREAD_REG + T_CPU], %l0
	ldub	[%l0 + CPU_KPRUNRUN], %l0
	brnz,a,pt	%l0, 1f	! Need to call kpreempt?
	or	%l1, KPREEMPT_FLAG, %l1	! If so, set the flag
1:
	btst	LOFAULT_SET, %l1
	bz,pn	%icc, 3f
	andncc	%o5, COPY_FLAGS, %o5
	! Here via bcopy. Check to see if the handler was NULL.
	! If so, just return quietly. Otherwise, reset the
	! handler and return.
	bz,pn %ncc, 2f
	nop
	membar	#Sync
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
2:
	btst	KPREEMPT_FLAG, %l1
	bz,pt	%icc, 3f
	nop
	call	kpreempt
	rdpr	%pil, %o0		! pass %pil
3:
	ret
	restore	%g0, 0, %o0
	
	SET_SIZE(bcopy_more)


#else	/* NIAGARA_IMPL */
	save	%sp, -SA(MINFRAME), %sp
	clr	%o5			! flag LOFAULT_SET is not set for bcopy
.do_copy:
	cmp	%i2, 12			! for small counts
	blu	%ncc, .bytecp		! just copy bytes
	.empty

	cmp	%i2, 128		! for less than 128 bytes
	blu,pn	%ncc, .bcb_punt		! no block st/quad ld
	nop

	set	use_hw_bcopy, %o2
	ld	[%o2], %o2
	brz,pn	%o2, .bcb_punt
	nop

	subcc	%i1, %i0, %i3
	bneg,a,pn %ncc, 1f
	neg	%i3
1:
	/*
	 * Compare against 256 since we should be checking block addresses
	 * and (dest & ~63) - (src & ~63) can be 3 blocks even if
	 * src = dest + (64 * 3) + 63.
	 */
	cmp	%i3, 256
	blu,pn	%ncc, .bcb_punt
	nop

	/*
	 * Copy that reach here have at least 2 blocks of data to copy.
	 */
.do_blockcopy:
	! Swap src/dst since the code below is memcpy code
	! and memcpy/bcopy have different calling sequences
	mov	%i1, %i5
	mov	%i0, %i1
	mov	%i5, %i0

	! Block (64 bytes) align the destination.
	andcc	%i0, 0x3f, %i3		! is dst aligned on a 64 bytes
	bz	%xcc, .chksrc		! dst is already double aligned
	sub	%i3, 0x40, %i3
	neg	%i3			! bytes till dst 64 bytes aligned
	sub	%i2, %i3, %i2		! update i2 with new count

	! Based on source and destination alignment do
	! either 8 bytes, 4 bytes, 2 bytes or byte copy.

	! Is dst & src 8B aligned
	or	%i0, %i1, %o2
	andcc	%o2, 0x7, %g0
	bz	%ncc, .alewdcp
	nop

	! Is dst & src 4B aligned
	andcc	%o2, 0x3, %g0
	bz	%ncc, .alwdcp
	nop

	! Is dst & src 2B aligned
	andcc	%o2, 0x1, %g0
	bz	%ncc, .alhlfwdcp
	nop

	! 1B aligned
1:	ldub	[%i1], %o2
	stb	%o2, [%i0]
	inc	%i1
	deccc	%i3
	bgu,pt	%ncc, 1b
	inc	%i0

	ba	.chksrc
	nop

	! dst & src 4B aligned
.alwdcp:
	ld	[%i1], %o2
	st	%o2, [%i0]
	add	%i1, 0x4, %i1
	subcc	%i3, 0x4, %i3
	bgu,pt	%ncc, .alwdcp
	add	%i0, 0x4, %i0

	ba	.chksrc
	nop

	! dst & src 2B aligned
.alhlfwdcp:
	lduh	[%i1], %o2
	stuh	%o2, [%i0]
	add	%i1, 0x2, %i1
	subcc	%i3, 0x2, %i3
	bgu,pt	%ncc, .alhlfwdcp
	add	%i0, 0x2, %i0

	ba	.chksrc
	nop

	! dst & src 8B aligned
.alewdcp:
	ldx	[%i1], %o2
	stx	%o2, [%i0]
	add	%i1, 0x8, %i1
	subcc	%i3, 0x8, %i3
	bgu,pt	%ncc, .alewdcp
	add	%i0, 0x8, %i0

	! Now Destination is block (64 bytes) aligned
.chksrc:
	andn	%i2, 0x3f, %i3		! %i3 count is multiple of block size
	sub	%i2, %i3, %i2		! Residue bytes in %i2

	mov	ASI_BLK_INIT_ST_QUAD_LDD_P, %asi

	andcc	%i1, 0xf, %o2		! is src quadword aligned
	bz,pn	%xcc, .blkcpy		! src offset in %o2
	nop
	cmp	%o2, 0x8
	bg	.cpy_upper_double
	nop
	bl	.cpy_lower_double
	nop

	! Falls through when source offset is equal to 8 i.e.
	! source is double word aligned.
	! In this case no shift/merge of data is required
	sub	%i1, %o2, %i1		! align the src at 16 bytes.
	andn	%i1, 0x3f, %l0		! %l0 has block aligned source
	prefetch [%l0+0x0], #one_read
	ldda	[%i1+0x0]%asi, %l2
loop0:
	ldda	[%i1+0x10]%asi, %l4
	prefetch [%l0+0x40], #one_read

	stxa	%l3, [%i0+0x0]%asi
	stxa	%l4, [%i0+0x8]%asi

	ldda	[%i1+0x20]%asi, %l2
	stxa	%l5, [%i0+0x10]%asi
	stxa	%l2, [%i0+0x18]%asi

	ldda	[%i1+0x30]%asi, %l4
	stxa	%l3, [%i0+0x20]%asi
	stxa	%l4, [%i0+0x28]%asi

	ldda	[%i1+0x40]%asi, %l2
	stxa	%l5, [%i0+0x30]%asi
	stxa	%l2, [%i0+0x38]%asi

	add	%l0, 0x40, %l0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, loop0
	add	%i0, 0x40, %i0
	ba	.blkdone
	add	%i1, %o2, %i1		! increment the source by src offset
					! the src offset was stored in %o2

.cpy_lower_double:
	sub	%i1, %o2, %i1		! align the src at 16 bytes.
	sll	%o2, 3, %o0		! %o0 left shift
	mov	0x40, %o1
	sub	%o1, %o0, %o1		! %o1 right shift = (64 - left shift)
	andn	%i1, 0x3f, %l0		! %l0 has block aligned source
	prefetch [%l0+0x0], #one_read
	ldda	[%i1+0x0]%asi, %l2	! partial data in %l2 and %l3 has
					! complete data
loop1:
	ldda	[%i1+0x10]%asi, %l4	! %l4 has partial data for this read.
	ALIGN_DATA(%l2, %l3, %l4, %o0, %o1, %l6)	! merge %l2, %l3 and %l4
							! into %l2 and %l3
	prefetch [%l0+0x40], #one_read
	stxa	%l2, [%i0+0x0]%asi
	stxa	%l3, [%i0+0x8]%asi

	ldda	[%i1+0x20]%asi, %l2
	ALIGN_DATA(%l4, %l5, %l2, %o0, %o1, %l6)	! merge %l2 with %l5 and
	stxa	%l4, [%i0+0x10]%asi			! %l4 from previous read
	stxa	%l5, [%i0+0x18]%asi			! into %l4 and %l5

	! Repeat the same for next 32 bytes.

	ldda	[%i1+0x30]%asi, %l4
	ALIGN_DATA(%l2, %l3, %l4, %o0, %o1, %l6)
	stxa	%l2, [%i0+0x20]%asi
	stxa	%l3, [%i0+0x28]%asi

	ldda	[%i1+0x40]%asi, %l2
	ALIGN_DATA(%l4, %l5, %l2, %o0, %o1, %l6)
	stxa	%l4, [%i0+0x30]%asi
	stxa	%l5, [%i0+0x38]%asi

	add	%l0, 0x40, %l0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, loop1
	add	%i0, 0x40, %i0
	ba	.blkdone
	add	%i1, %o2, %i1		! increment the source by src offset
					! the src offset was stored in %o2

.cpy_upper_double:
	sub	%i1, %o2, %i1		! align the src at 16 bytes.
	mov	0x8, %o0
	sub	%o2, %o0, %o0
	sll	%o0, 3, %o0		! %o0 left shift
	mov	0x40, %o1
	sub	%o1, %o0, %o1		! %o1 right shift = (64 - left shift)
	andn	%i1, 0x3f, %l0		! %l0 has block aligned source
	prefetch [%l0+0x0], #one_read
	ldda	[%i1+0x0]%asi, %l2	! partial data in %l3 for this read and
					! no data in %l2
loop2:
	ldda	[%i1+0x10]%asi, %l4	! %l4 has complete data and %l5 has
					! partial
	ALIGN_DATA(%l3, %l4, %l5, %o0, %o1, %l6)	! merge %l3, %l4 and %l5
							! into %l3 and %l4
	prefetch [%l0+0x40], #one_read
	stxa	%l3, [%i0+0x0]%asi
	stxa	%l4, [%i0+0x8]%asi

	ldda	[%i1+0x20]%asi, %l2
	ALIGN_DATA(%l5, %l2, %l3, %o0, %o1, %l6)	! merge %l2 and %l3 with
	stxa	%l5, [%i0+0x10]%asi			! %l5 from previous read
	stxa	%l2, [%i0+0x18]%asi			! into %l5 and %l2

	! Repeat the same for next 32 bytes.

	ldda	[%i1+0x30]%asi, %l4
	ALIGN_DATA(%l3, %l4, %l5, %o0, %o1, %l6)
	stxa	%l3, [%i0+0x20]%asi
	stxa	%l4, [%i0+0x28]%asi

	ldda	[%i1+0x40]%asi, %l2
	ALIGN_DATA(%l5, %l2, %l3, %o0, %o1, %l6)
	stxa	%l5, [%i0+0x30]%asi
	stxa	%l2, [%i0+0x38]%asi

	add	%l0, 0x40, %l0
	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, loop2
	add	%i0, 0x40, %i0
	ba	.blkdone
	add	%i1, %o2, %i1		! increment the source by src offset
					! the src offset was stored in %o2


	! Both Source and Destination are block aligned.
	! Do fast copy using ASI_BLK_INIT_ST_QUAD_LDD_P
.blkcpy:
	prefetch [%i1+0x0], #one_read
1:
	ldda	[%i1+0x0]%asi, %l0
	ldda	[%i1+0x10]%asi, %l2
	prefetch [%i1+0x40], #one_read

	stxa	%l0, [%i0+0x0]%asi
	ldda	[%i1+0x20]%asi, %l4
	ldda	[%i1+0x30]%asi, %l6

	stxa	%l1, [%i0+0x8]%asi
	stxa	%l2, [%i0+0x10]%asi
	stxa	%l3, [%i0+0x18]%asi
	stxa	%l4, [%i0+0x20]%asi
	stxa	%l5, [%i0+0x28]%asi
	stxa	%l6, [%i0+0x30]%asi
	stxa	%l7, [%i0+0x38]%asi

	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, 1b
	add	%i0, 0x40, %i0

.blkdone:
	membar	#Sync

	brz,pt	%i2, .blkexit
	nop

	! Handle trailing bytes
	cmp	%i2, 0x8
	blu,pt	%ncc, .residue
	nop

	! Can we do some 8B ops
	or	%i1, %i0, %o2
	andcc	%o2, 0x7, %g0
	bnz	%ncc, .last4
	nop

	! Do 8byte ops as long as possible
.last8:
	ldx	[%i1], %o2
	stx	%o2, [%i0]
	add	%i1, 0x8, %i1
	sub	%i2, 0x8, %i2
	cmp	%i2, 0x8
	bgu,pt	%ncc, .last8
	add	%i0, 0x8, %i0

	brz,pt	%i2, .blkexit
	nop

	ba	.residue
	nop

.last4:
	! Can we do 4B ops
	andcc	%o2, 0x3, %g0
	bnz	%ncc, .last2
	nop
1:
	ld	[%i1], %o2
	st	%o2, [%i0]
	add	%i1, 0x4, %i1
	sub	%i2, 0x4, %i2
	cmp	%i2, 0x4
	bgu,pt	%ncc, 1b
	add	%i0, 0x4, %i0

	brz,pt	%i2, .blkexit
	nop

	ba	.residue
	nop

.last2:
	! Can we do 2B ops
	andcc	%o2, 0x1, %g0
	bnz	%ncc, .residue
	nop

1:
	lduh	[%i1], %o2
	stuh	%o2, [%i0]
	add	%i1, 0x2, %i1
	sub	%i2, 0x2, %i2
	cmp	%i2, 0x2
	bgu,pt	%ncc, 1b
	add	%i0, 0x2, %i0

	brz,pt	%i2, .blkexit
	nop

.residue:
	ldub	[%i1], %o2
	stb	%o2, [%i0]
	inc	%i1
	deccc	%i2
	bgu,pt	%ncc, .residue
	inc	%i0

.blkexit:

	membar	#Sync				! sync error barrier
	! Restore t_lofault handler, if came here from kcopy().
	tst	%o5
	bz	%ncc, 1f
	andn	%o5, LOFAULT_SET, %o5
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
1:
	ret
	restore	%g0, 0, %o0


.bcb_punt:
	!
	! use aligned transfers where possible
	!
	xor	%i0, %i1, %o4		! xor from and to address
	btst	7, %o4			! if lower three bits zero
	bz	.aldoubcp		! can align on double boundary
	.empty	! assembler complaints about label

	xor	%i0, %i1, %o4		! xor from and to address
	btst	3, %o4			! if lower two bits zero
	bz	.alwordcp		! can align on word boundary
	btst	3, %i0			! delay slot, from address unaligned?
	!
	! use aligned reads and writes where possible
	! this differs from wordcp in that it copes
	! with odd alignment between source and destnation
	! using word reads and writes with the proper shifts
	! in between to align transfers to and from memory
	! i0 - src address, i1 - dest address, i2 - count
	! i3, i4 - tmps for used generating complete word
	! i5 (word to write)
	! l0 size in bits of upper part of source word (US)
	! l1 size in bits of lower part of source word (LS = 32 - US)
	! l2 size in bits of upper part of destination word (UD)
	! l3 size in bits of lower part of destination word (LD = 32 - UD)
	! l4 number of bytes leftover after aligned transfers complete
	! l5 the number 32
	!
	mov	32, %l5			! load an oft-needed constant
	bz	.align_dst_only
	btst	3, %i1			! is destnation address aligned?
	clr	%i4			! clear registers used in either case
	bz	.align_src_only
	clr	%l0
	!
	! both source and destination addresses are unaligned
	!
1:					! align source
	ldub	[%i0], %i3		! read a byte from source address
	add	%i0, 1, %i0		! increment source address
	or	%i4, %i3, %i4		! or in with previous bytes (if any)
	btst	3, %i0			! is source aligned?
	add	%l0, 8, %l0		! increment size of upper source (US)
	bnz,a	1b
	sll	%i4, 8, %i4		! make room for next byte

	sub	%l5, %l0, %l1		! generate shift left count (LS)
	sll	%i4, %l1, %i4		! prepare to get rest
	ld	[%i0], %i3		! read a word
	add	%i0, 4, %i0		! increment source address
	srl	%i3, %l0, %i5		! upper src bits into lower dst bits
	or	%i4, %i5, %i5		! merge
	mov	24, %l3			! align destination
1:
	srl	%i5, %l3, %i4		! prepare to write a single byte
	stb	%i4, [%i1]		! write a byte
	add	%i1, 1, %i1		! increment destination address
	sub	%i2, 1, %i2		! decrement count
	btst	3, %i1			! is destination aligned?
	bnz,a	1b
	sub	%l3, 8, %l3		! delay slot, decrement shift count (LD)
	sub	%l5, %l3, %l2		! generate shift left count (UD)
	sll	%i5, %l2, %i5		! move leftover into upper bytes
	cmp	%l2, %l0		! cmp # reqd to fill dst w old src left
	bgu	%ncc, .more_needed	! need more to fill than we have
	nop

	sll	%i3, %l1, %i3		! clear upper used byte(s)
	srl	%i3, %l1, %i3
	! get the odd bytes between alignments
	sub	%l0, %l2, %l0		! regenerate shift count
	sub	%l5, %l0, %l1		! generate new shift left count (LS)
	and	%i2, 3, %l4		! must do remaining bytes if count%4 > 0
	andn	%i2, 3, %i2		! # of aligned bytes that can be moved
	srl	%i3, %l0, %i4
	or	%i5, %i4, %i5
	st	%i5, [%i1]		! write a word
	subcc	%i2, 4, %i2		! decrement count
	bz	%ncc, .unalign_out
	add	%i1, 4, %i1		! increment destination address

	b	2f
	sll	%i3, %l1, %i5		! get leftover into upper bits
.more_needed:
	sll	%i3, %l0, %i3		! save remaining byte(s)
	srl	%i3, %l0, %i3
	sub	%l2, %l0, %l1		! regenerate shift count
	sub	%l5, %l1, %l0		! generate new shift left count
	sll	%i3, %l1, %i4		! move to fill empty space
	b	3f
	or	%i5, %i4, %i5		! merge to complete word
	!
	! the source address is aligned and destination is not
	!
.align_dst_only:
	ld	[%i0], %i4		! read a word
	add	%i0, 4, %i0		! increment source address
	mov	24, %l0			! initial shift alignment count
1:
	srl	%i4, %l0, %i3		! prepare to write a single byte
	stb	%i3, [%i1]		! write a byte
	add	%i1, 1, %i1		! increment destination address
	sub	%i2, 1, %i2		! decrement count
	btst	3, %i1			! is destination aligned?
	bnz,a	1b
	sub	%l0, 8, %l0		! delay slot, decrement shift count
.xfer:
	sub	%l5, %l0, %l1		! generate shift left count
	sll	%i4, %l1, %i5		! get leftover
3:
	and	%i2, 3, %l4		! must do remaining bytes if count%4 > 0
	andn	%i2, 3, %i2		! # of aligned bytes that can be moved
2:
	ld	[%i0], %i3		! read a source word
	add	%i0, 4, %i0		! increment source address
	srl	%i3, %l0, %i4		! upper src bits into lower dst bits
	or	%i5, %i4, %i5		! merge with upper dest bits (leftover)
	st	%i5, [%i1]		! write a destination word
	subcc	%i2, 4, %i2		! decrement count
	bz	%ncc, .unalign_out	! check if done
	add	%i1, 4, %i1		! increment destination address
	b	2b			! loop
	sll	%i3, %l1, %i5		! get leftover
.unalign_out:
	tst	%l4			! any bytes leftover?
	bz	%ncc, .cpdone
	.empty				! allow next instruction in delay slot
1:
	sub	%l0, 8, %l0		! decrement shift
	srl	%i3, %l0, %i4		! upper src byte into lower dst byte
	stb	%i4, [%i1]		! write a byte
	subcc	%l4, 1, %l4		! decrement count
	bz	%ncc, .cpdone		! done?
	add	%i1, 1, %i1		! increment destination
	tst	%l0			! any more previously read bytes
	bnz	%ncc, 1b		! we have leftover bytes
	mov	%l4, %i2		! delay slot, mv cnt where dbytecp wants
	b	.dbytecp		! let dbytecp do the rest
	sub	%i0, %i1, %i0		! i0 gets the difference of src and dst
	!
	! the destination address is aligned and the source is not
	!
.align_src_only:
	ldub	[%i0], %i3		! read a byte from source address
	add	%i0, 1, %i0		! increment source address
	or	%i4, %i3, %i4		! or in with previous bytes (if any)
	btst	3, %i0			! is source aligned?
	add	%l0, 8, %l0		! increment shift count (US)
	bnz,a	.align_src_only
	sll	%i4, 8, %i4		! make room for next byte
	b,a	.xfer
	!
	! if from address unaligned for double-word moves,
	! move bytes till it is, if count is < 56 it could take
	! longer to align the thing than to do the transfer
	! in word size chunks right away
	!
.aldoubcp:
	cmp	%i2, 56			! if count < 56, use wordcp, it takes
	blu,a	%ncc, .alwordcp		! longer to align doubles than words
	mov	3, %o0			! mask for word alignment
	call	.alignit		! copy bytes until aligned
	mov	7, %o0			! mask for double alignment
	!
	! source and destination are now double-word aligned
	! i3 has aligned count returned by alignit
	!
	and	%i2, 7, %i2		! unaligned leftover count
	sub	%i0, %i1, %i0		! i0 gets the difference of src and dst
5:
	ldx	[%i0+%i1], %o4		! read from address
	stx	%o4, [%i1]		! write at destination address
	subcc	%i3, 8, %i3		! dec count
	bgu	%ncc, 5b
	add	%i1, 8, %i1		! delay slot, inc to address
	cmp	%i2, 4			! see if we can copy a word
	blu	%ncc, .dbytecp		! if 3 or less bytes use bytecp
	.empty
	!
	! for leftover bytes we fall into wordcp, if needed
	!
.wordcp:
	and	%i2, 3, %i2		! unaligned leftover count
5:
	ld	[%i0+%i1], %o4		! read from address
	st	%o4, [%i1]		! write at destination address
	subcc	%i3, 4, %i3		! dec count
	bgu	%ncc, 5b
	add	%i1, 4, %i1		! delay slot, inc to address
	b,a	.dbytecp

	! we come here to align copies on word boundaries
.alwordcp:
	call	.alignit		! go word-align it
	mov	3, %o0			! bits that must be zero to be aligned
	b	.wordcp
	sub	%i0, %i1, %i0		! i0 gets the difference of src and dst

	!
	! byte copy, works with any alignment
	!
.bytecp:
	b	.dbytecp
	sub	%i0, %i1, %i0		! i0 gets difference of src and dst

	!
	! differenced byte copy, works with any alignment
	! assumes dest in %i1 and (source - dest) in %i0
	!
1:
	stb	%o4, [%i1]		! write to address
	inc	%i1			! inc to address
.dbytecp:
	deccc	%i2			! dec count
	bgeu,a	%ncc, 1b		! loop till done
	ldub	[%i0+%i1], %o4		! read from address
.cpdone:

	membar	#Sync				! sync error barrier
	! Restore t_lofault handler, if came here from kcopy().
	tst	%o5
	bz	%ncc, 1f
	andn	%o5, LOFAULT_SET, %o5
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
1:
	ret
	restore %g0, 0, %o0		! return (0)

/*
 * Common code used to align transfers on word and doubleword
 * boundaries.  Aligns source and destination and returns a count
 * of aligned bytes to transfer in %i3
 */
1:
	inc	%i0			! inc from
	stb	%o4, [%i1]		! write a byte
	inc	%i1			! inc to
	dec	%i2			! dec count
.alignit:
	btst	%o0, %i0		! %o0 is bit mask to check for alignment
	bnz,a	1b
	ldub	[%i0], %o4		! read next byte

	retl
	andn	%i2, %o0, %i3		! return size of aligned bytes
	
	SET_SIZE(bcopy)

#endif	/* NIAGARA_IMPL */

/*
 * Block copy with possibly overlapped operands.
 */

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

/*
 * hwblkpagecopy()
 *
 * Copies exactly one page.  This routine assumes the caller (ppcopy)
 * has already disabled kernel preemption and has checked
 * use_hw_bcopy.
 */
	ENTRY(hwblkpagecopy)
	save	%sp, -SA(MINFRAME), %sp

	! %i0 - source address (arg)
	! %i1 - destination address (arg)
	! %i2 - length of region (not arg)

	set	PAGESIZE, %i2

	/*
	 * Copying exactly one page and PAGESIZE is in mutliple of 0x80. 
	 */
	mov	ASI_BLK_INIT_ST_QUAD_LDD_P, %asi
	prefetch [%i0+0x0], #one_read
	prefetch [%i0+0x40], #one_read
1:
	prefetch [%i0+0x80], #one_read
	prefetch [%i0+0xc0], #one_read
	ldda	[%i0+0x0]%asi, %l0
	ldda	[%i0+0x10]%asi, %l2
	ldda	[%i0+0x20]%asi, %l4
	ldda	[%i0+0x30]%asi, %l6
	stxa	%l0, [%i1+0x0]%asi
	stxa	%l1, [%i1+0x8]%asi
	stxa	%l2, [%i1+0x10]%asi
	stxa	%l3, [%i1+0x18]%asi
	stxa	%l4, [%i1+0x20]%asi
	stxa	%l5, [%i1+0x28]%asi
	stxa	%l6, [%i1+0x30]%asi
	stxa	%l7, [%i1+0x38]%asi
	ldda	[%i0+0x40]%asi, %l0
	ldda	[%i0+0x50]%asi, %l2
	ldda	[%i0+0x60]%asi, %l4
	ldda	[%i0+0x70]%asi, %l6
	stxa	%l0, [%i1+0x40]%asi
	stxa	%l1, [%i1+0x48]%asi
	stxa	%l2, [%i1+0x50]%asi
	stxa	%l3, [%i1+0x58]%asi
	stxa	%l4, [%i1+0x60]%asi
	stxa	%l5, [%i1+0x68]%asi
	stxa	%l6, [%i1+0x70]%asi
	stxa	%l7, [%i1+0x78]%asi

	add	%i0, 0x80, %i0
	subcc	%i2, 0x80, %i2
	bgu,pt	%xcc, 1b
	add	%i1, 0x80, %i1

	membar #Sync
	ret
	restore	%g0, 0, %o0
	SET_SIZE(hwblkpagecopy)


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
 * None of the copyops routines grab a window until it's decided that
 * we need to do a HW block copy operation. This saves a window
 * spill/fill when we're called during socket ops. The typical IO
 * path won't cause spill/fill traps.
 *
 * This code uses a set of 4 limits for the maximum size that will
 * be copied given a particular input/output address alignment.
 * the default limits are:
 *
 * single byte aligned - 256 (hw_copy_limit_1)
 * two byte aligned - 512 (hw_copy_limit_2)
 * four byte aligned - 1024 (hw_copy_limit_4)
 * eight byte aligned - 1024 (hw_copy_limit_8)
 *
 * If the value for a particular limit is zero, the copy will be done
 * via the copy loops rather than block store/quad load instructions.
 *
 * Flow:
 *
 * If count == zero return zero.
 *
 * Store the previous lo_fault handler into %g6.
 * Place our secondary lofault handler into %g5.
 * Place the address of our nowindow fault handler into %o3.
 * Place the address of the windowed fault handler into %o4.
 * --> We'll use this handler if we end up grabbing a window
 * --> before we use block initializing store and quad load ASIs
 *
 * If count is less than or equal to SMALL_LIMIT (7) we
 * always do a byte for byte copy.
 *
 * If count is > SMALL_LIMIT, we check the alignment of the input
 * and output pointers. Based on the alignment we check count
 * against a limit based on detected alignment.  If we exceed the
 * alignment value we copy via block initializing store and quad
 * load instructions.
 *
 * If we don't exceed one of the limits, we store -count in %o3,
 * we store the number of chunks (8, 4, 2 or 1 byte) operated
 * on in our basic copy loop in %o2. Following this we branch 
 * to the appropriate copy loop and copy that many chunks.
 * Since we've been adding the chunk size to %o3 each time through
 * as well as decrementing %o2, we can tell if any data is
 * is left to be copied by examining %o3. If that is zero, we're
 * done and can go home. If not, we figure out what the largest
 * chunk size left to be copied is and branch to that copy loop
 * unless there's only one byte left. We load that as we're
 * branching to code that stores it just before we return.
 *
 * Fault handlers are invoked if we reference memory that has no
 * current mapping.  All forms share the same copyio_fault handler.
 * This routine handles fixing up the stack and general housecleaning.
 * Each copy operation has a simple fault handler that is then called
 * to do the work specific to the invidual operation.  The handler
 * for copyOP and xcopyOP are found at the end of individual function.
 * The handlers for xcopyOP_little are found at the end of xcopyin_little.
 * The handlers for copyOP_noerr are found at the end of copyin_noerr.
 */

/*
 * Copy kernel data to user space (copyout/xcopyout/xcopyout_little).
 */

/*
 * We save the arguments in the following registers in case of a fault:
 * 	kaddr - %g2
 * 	uaddr - %g3
 * 	count - %g4
 */
#define	SAVE_SRC	%g2
#define	SAVE_DST	%g3
#define	SAVE_COUNT	%g4

#define	REAL_LOFAULT		%g5
#define	SAVED_LOFAULT		%g6

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
#if !defined(NIAGARA_IMPL)
	btst	FPUSED_FLAG, SAVED_LOFAULT
	bz	1f
	andn	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT

	wr	%l5, 0, %gsr		! restore gsr

	btst	FPRS_FEF, %g1
	bz	%icc, 4f
	nop

	! restore fpregs from stack
	BLD_FP_FROMSTACK(%o2)

	ba,pt	%ncc, 1f
	nop
4:
	FZERO				! zero all of the fpregs
	wr	%g1, %g0, %fprs		! restore fprs
1:
	restore
	mov	SAVE_SRC, %o0
	mov	SAVE_DST, %o1
	jmp	REAL_LOFAULT
	mov	SAVE_COUNT, %o2

#else	/* NIAGARA_IMPL */
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	restore
	mov	SAVE_SRC, %o0
	mov	SAVE_DST, %o1
	jmp	REAL_LOFAULT
	mov	SAVE_COUNT, %o2

#endif	/* NIAGARA_IMPL */

	SET_SIZE(copyio_fault)

	ENTRY(copyio_fault_nowindow)
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]	! restore old t_lofault

	mov	SAVE_SRC, %o0
	mov	SAVE_DST, %o1
	jmp	REAL_LOFAULT
	mov	SAVE_COUNT, %o2
	SET_SIZE(copyio_fault_nowindow)

	ENTRY(copyout)
	sethi	%hi(.copyout_err), REAL_LOFAULT
	or	REAL_LOFAULT, %lo(.copyout_err), REAL_LOFAULT

#if !defined(NIAGARA_IMPL)
.do_copyout:
	tst	%o2			! check for zero count;  quick exit
	bz,pt	%ncc, .co_smallqx
	mov	%o0, SAVE_SRC
	mov	%o1, SAVE_DST
	mov	%o2, SAVE_COUNT
	cmp	%o2, FP_COPY		! check for small copy/leaf case
	bgt,pt	%ncc, .co_copy_more
	ldn	[THREAD_REG + T_LOFAULT], SAVED_LOFAULT
/*
 * Small copy out code
 * 
 */
	sethi	%hi(copyio_fault_nowindow), %o3
	or	%o3, %lo(copyio_fault_nowindow), %o3
	membar	#Sync
	stn	%o3, [THREAD_REG + T_LOFAULT]

	mov	ASI_USER, %asi
	cmp	%o2, SHORTCOPY		! make sure there is enough to align
	ble,pt	%ncc, .co_smallest
	andcc	%o1, 0x7, %o3		! is dest long word aligned
	bnz,pn	%ncc, .co_align
	andcc	%o1, 1, %o3		! is dest byte aligned

! Destination is long word aligned
! 8 cases for src alignment; load parts, store long words
.co_al_src:
	andcc	%o0, 7, %o3
	brnz,pt	%o3, .co_src_dst_unal8
	nop
/*
 * Special case for handling when src and dest are both long word aligned
 * and total data to move is less than FP_COPY bytes
 * Also handles finish up for large block moves, so may be less than 32 bytes
 */
.co_medlong:
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .co_medl31
	nop
.co_medl32:
	ldx	[%o0], %o4		! move 32 bytes
	subcc	%o2, 32, %o2		! decrement length count by 32
	stxa	%o4, [%o1]%asi
	ldx	[%o0+8], %o4
	stxa	%o4, [%o1+8]%asi
	ldx	[%o0+16], %o4
	add	%o0, 32, %o0		! increase src ptr by 32
	stxa	%o4, [%o1+16]%asi
	ldx	[%o0-8], %o4
	add	%o1, 32, %o1		! increase dst ptr by 32
	bgu,pt	%ncc, .co_medl32	! repeat if at least 32 bytes left
	stxa	%o4, [%o1-8]%asi
.co_medl31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .co_medl7		! skip if 7 or fewer bytes left
	nop
.co_medl8:
	ldx	[%o0], %o4		! move 8 bytes
	add	%o0, 8, %o0		! increase src ptr by 8
	subcc	%o2, 8, %o2		! decrease count by 8
	add	%o1, 8, %o1		! increase dst ptr by 8
	bgu,pt	%ncc, .co_medl8
	stxa	%o4, [%o1-8]%asi
.co_medl7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bnz,pt	%ncc, .co_small4	! do final bytes if not finished

.co_smallx:				! finish up and exit
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
.co_smallqx:
	retl
	mov	%g0, %o0

.co_small4:
	cmp	%o2, 4
	blt,pt	%ncc, .co_small3x	! skip if less than 4 bytes left
	nop				!
	ld	[%o0], %o4		! move 4 bytes
	add	%o0, 4, %o0		! increase src ptr by 4
	add	%o1, 4, %o1		! increase dst ptr by 4
	subcc	%o2, 4, %o2		! decrease count by 4
	bz,pt	%ncc, .co_smallx
	stwa	%o4, [%o1-4]%asi

.co_small3x:				! Exactly 1, 2, or 3 bytes remain
	subcc	%o2, 1, %o2		! reduce count for cc test
	ldub	[%o0], %o4		! load one byte
	bz,pt	%ncc, .co_smallx
	stba	%o4, [%o1]%asi		! store one byte
	ldub	[%o0+1], %o4		! load second byte
	subcc	%o2, 1, %o2
	bz,pt	%ncc, .co_smallx
	stba	%o4, [%o1+1]%asi	! store second byte
	ldub	[%o0+2], %o4		! load third byte
	ba	.co_smallx
	stba	%o4, [%o1+2]%asi	! store third byte

.co_smallest:				! 7 or fewer bytes remain
	cmp	%o2, 4
	blt,pt	%ncc, .co_small3x
	nop
	ldub	[%o0], %o4		! read byte
	subcc	%o2, 4, %o2		! reduce count by 4
	stba	%o4, [%o1]%asi		! write byte
	ldub	[%o0+1], %o4		! repeat for total of 4 bytes
	add	%o0, 4, %o0		! advance src by 4
	stba	%o4, [%o1+1]%asi
	ldub	[%o0-2], %o4
	add	%o1, 4, %o1		! advance dst by 4
	stba	%o4, [%o1-2]%asi
	ldub	[%o0-1], %o4
	bnz,pt	%ncc, .co_small3x
	stba	%o4, [%o1-1]%asi
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
	retl
	mov	%g0, %o0

.co_align:				! byte align test in prior branch delay
	bnz,pt	%ncc, .co_al_d1
.co_al_d1f:				! dest is now half word aligned
	andcc	%o1, 2, %o3
	bnz,pt	%ncc, .co_al_d2
.co_al_d2f:				! dest is now word aligned
	andcc	%o1, 4, %o3		! is dest longword aligned?
	bz,pt	%ncc, .co_al_src
	nop
.co_al_d4:				! dest is word aligned;  src is unknown
	ldub	[%o0], %o4		! move a word (src align unknown)
	ldub	[%o0+1], %o3
	sll	%o4, 24, %o4		! position
	sll	%o3, 16, %o3		! position
	or	%o4, %o3, %o3		! merge
	ldub	[%o0+2], %o4
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o3		! merge
	ldub	[%o0+3], %o4
	or	%o4, %o3, %o4		! merge
	stwa	%o4,[%o1]%asi		! store four bytes
	add	%o0, 4, %o0		! adjust src by 4
	add	%o1, 4, %o1		! adjust dest by 4
	sub	%o2, 4, %o2		! adjust count by 4
	andcc	%o0, 7, %o3		! check for src long word alignment
	brz,pt	%o3, .co_medlong
.co_src_dst_unal8:
	! dst is 8-byte aligned, src is not
	! Size is less than FP_COPY
	! Following code is to select for alignment
	andcc	%o0, 0x3, %o3		! test word alignment
	bz,pt	%ncc, .co_medword
	nop
	andcc	%o0, 0x1, %o3		! test halfword alignment
	bnz,pt	%ncc, .co_med_byte	! go to byte move if not halfword
	andcc	%o0, 0x2, %o3		! test which byte alignment
	ba	.co_medhalf
	nop
.co_al_d1:				! align dest to half word
	ldub	[%o0], %o4		! move a byte
	add	%o0, 1, %o0
	stba	%o4, [%o1]%asi
	add	%o1, 1, %o1
	andcc	%o1, 2, %o3
	bz,pt	%ncc, .co_al_d2f
	sub	%o2, 1, %o2
.co_al_d2:				! align dest to word
	ldub	[%o0], %o4		! move a half-word (src align unknown)
	ldub	[%o0+1], %o3
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o4		! merge
	stha	%o4, [%o1]%asi
	add	%o0, 2, %o0
	add	%o1, 2, %o1
	andcc	%o1, 4, %o3		! is dest longword aligned?
	bz,pt	%ncc, .co_al_src
	sub	%o2, 2, %o2
	ba	.co_al_d4
	nop
/*
 * Handle all cases where src and dest are aligned on word
 * boundaries. Use unrolled loops for better performance.
 * This option wins over standard large data move when 
 * source and destination is in cache for medium
 * to short data moves.
 */
.co_medword:
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .co_medw31
	nop
.co_medw32:
	ld	[%o0], %o4		! move a block of 32 bytes
	stwa	%o4, [%o1]%asi
	ld	[%o0+4], %o4
	stwa	%o4, [%o1+4]%asi
	ld	[%o0+8], %o4
	stwa	%o4, [%o1+8]%asi
	ld	[%o0+12], %o4
	stwa	%o4, [%o1+12]%asi
	ld	[%o0+16], %o4
	stwa	%o4, [%o1+16]%asi
	ld	[%o0+20], %o4
	subcc	%o2, 32, %o2		! decrement length count
	stwa	%o4, [%o1+20]%asi
	ld	[%o0+24], %o4
	add	%o0, 32, %o0		! increase src ptr by 32
	stwa	%o4, [%o1+24]%asi
	ld	[%o0-4], %o4
	add	%o1, 32, %o1		! increase dst ptr by 32
	bgu,pt	%ncc, .co_medw32	! repeat if at least 32 bytes left
	stwa	%o4, [%o1-4]%asi
.co_medw31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .co_medw7		! skip if 7 or fewer bytes left
	nop				!
.co_medw15:
	ld	[%o0], %o4		! move a block of 8 bytes
	subcc	%o2, 8, %o2		! decrement length count
	stwa	%o4, [%o1]%asi
	add	%o0, 8, %o0		! increase src ptr by 8
	ld	[%o0-4], %o4
	add	%o1, 8, %o1		! increase dst ptr by 8
	bgu,pt	%ncc, .co_medw15
	stwa	%o4, [%o1-4]%asi
.co_medw7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bz,pt	%ncc, .co_smallx	! exit if finished
	cmp	%o2, 4
	blt,pt	%ncc, .co_small3x	! skip if less than 4 bytes left
	nop				!
	ld	[%o0], %o4		! move 4 bytes
	add	%o0, 4, %o0		! increase src ptr by 4
	add	%o1, 4, %o1		! increase dst ptr by 4
	subcc	%o2, 4, %o2		! decrease count by 4
	bnz	.co_small3x
	stwa	%o4, [%o1-4]%asi
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
	retl
	mov	%g0, %o0

.co_medhalf:
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .co_medh31
	nop
.co_medh32:				! load and store block of 32 bytes

	lduh	[%o0], %o4		! move 32 bytes
	subcc	%o2, 32, %o2		! decrement length count
	lduw	[%o0+2], %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduh	[%o0+6], %o4
	or	%o4, %o3, %o4
	stxa	%o4, [%o1]%asi

	lduh	[%o0+8], %o4
	lduw	[%o0+10], %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduh	[%o0+14], %o4
	or	%o4, %o3, %o4
	stxa	%o4, [%o1+8]%asi

	lduh	[%o0+16], %o4
	lduw	[%o0+18], %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduh	[%o0+22], %o4
	or	%o4, %o3, %o4
	stxa	%o4, [%o1+16]%asi

	add	%o0, 32, %o0		! increase src ptr by 32
	add	%o1, 32, %o1		! increase dst ptr by 32

	lduh	[%o0-8], %o4
	lduw	[%o0-6], %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduh	[%o0-2], %o4
	or	%o3, %o4, %o4
	bgu,pt	%ncc, .co_medh32	! repeat if at least 32 bytes left
	stxa	%o4, [%o1-8]%asi

.co_medh31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .co_medh7		! skip if 7 or fewer bytes left
	nop				!
.co_medh15:
	lduh	[%o0], %o4		! move 16 bytes
	subcc	%o2, 8, %o2		! decrement length count
	lduw	[%o0+2], %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	add	%o1, 8, %o1		! increase dst ptr by 8
	lduh	[%o0+6], %o4
	add	%o0, 8, %o0		! increase src ptr by 8
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .co_medh15
	stxa	%o4, [%o1-8]%asi
.co_medh7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bz,pt	%ncc, .co_smallx	! exit if finished
	cmp	%o2, 4
	blt,pt	%ncc, .co_small3x	! skip if less than 4 bytes left
	nop				!
	lduh	[%o0], %o4
	sll	%o4, 16, %o4
	lduh	[%o0+2], %o3
	or	%o3, %o4, %o4
	subcc	%o2, 4, %o2
	add	%o0, 4, %o0
	add	%o1, 4, %o1
	bnz	.co_small3x
	stwa	%o4, [%o1-4]%asi
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
	retl
	mov	%g0, %o0

	.align 16
.co_med_byte:
	bnz,pt	%ncc, .co_medbh32a	! go to correct byte move
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .co_medb31
	nop
.co_medb32:				! Alignment 1 or 5
	subcc	%o2, 32, %o2		! decrement length count

	ldub	[%o0], %o4		! load and store a block of 32 bytes
	sllx	%o4, 56, %o3
	lduh	[%o0+1], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduw	[%o0+3], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+7], %o4
	or	%o4, %o3, %o4
	stxa	%o4, [%o1]%asi

	ldub	[%o0+8], %o4
	sllx	%o4, 56, %o3
	lduh	[%o0+9], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduw	[%o0+11], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+15], %o4
	or	%o4, %o3, %o4
	stxa	%o4, [%o1+8]%asi

	ldub	[%o0+16], %o4
	sllx	%o4, 56, %o3
	lduh	[%o0+17], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduw	[%o0+19], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+23], %o4
	or	%o4, %o3, %o4
	stxa	%o4, [%o1+16]%asi

	add	%o0, 32, %o0		! increase src ptr by 32
	add	%o1, 32, %o1		! increase dst ptr by 32

	ldub	[%o0-8], %o4
	sllx	%o4, 56, %o3
	lduh	[%o0-7], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduw	[%o0-5], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0-1], %o4
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .co_medb32	! repeat if at least 32 bytes left
	stxa	%o4, [%o1-8]%asi

.co_medb31:				! 31 or fewer bytes remaining
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .co_medb7		! skip if 7 or fewer bytes left
	nop				!
.co_medb15:

	ldub	[%o0], %o4		! load and store a block of 8 bytes
	subcc	%o2, 8, %o2		! decrement length count
	sllx	%o4, 56, %o3
	lduh	[%o0+1], %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduw	[%o0+3], %o4
	add	%o1, 8, %o1		! increase dst ptr by 16
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+7], %o4
	add	%o0, 8, %o0		! increase src ptr by 16
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .co_medb15
	stxa	%o4, [%o1-8]%asi
.co_medb7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bz,pt	%ncc, .co_smallx	! exit if finished
	cmp	%o2, 4
	blt,pt	%ncc, .co_small3x	! skip if less than 4 bytes left
	nop				!
	ldub	[%o0], %o4		! move 4 bytes
	sll	%o4, 24, %o3
	lduh	[%o0+1], %o4
	sll	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+3], %o4
	or	%o4, %o3, %o4
	subcc	%o2, 4, %o2
	add	%o0, 4, %o0
	add	%o1, 4, %o1
	bnz	.co_small3x
	stwa	%o4, [%o1-4]%asi
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
	retl
	mov	%g0, %o0

	.align 16
.co_medbh32a:
	ble,pt	%ncc, .co_medbh31
	nop
.co_medbh32:				! Alignment 3 or 7
	subcc	%o2, 32, %o2		! decrement length count

	ldub	[%o0], %o4		! load and store a block of 32 bytes
	sllx	%o4, 56, %o3
	lduw	[%o0+1], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduh	[%o0+5], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+7], %o4
	or	%o4, %o3, %o4
	stxa	%o4, [%o1]%asi

	ldub	[%o0+8], %o4
	sllx	%o4, 56, %o3
	lduw	[%o0+9], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduh	[%o0+13], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+15], %o4
	or	%o4, %o3, %o4
	stxa	%o4, [%o1+8]%asi

	ldub	[%o0+16], %o4
	sllx	%o4, 56, %o3
	lduw	[%o0+17], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduh	[%o0+21], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+23], %o4
	or	%o4, %o3, %o4
	stxa	%o4, [%o1+16]%asi

	add	%o0, 32, %o0		! increase src ptr by 32
	add	%o1, 32, %o1		! increase dst ptr by 32

	ldub	[%o0-8], %o4
	sllx	%o4, 56, %o3
	lduw	[%o0-7], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduh	[%o0-3], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0-1], %o4
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .co_medbh32	! repeat if at least 32 bytes left
	stxa	%o4, [%o1-8]%asi

.co_medbh31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .co_medb7		! skip if 7 or fewer bytes left
	nop				!
.co_medbh15:
	ldub	[%o0], %o4		! load and store a block of 8 bytes
	sllx	%o4, 56, %o3
	lduw	[%o0+1], %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduh	[%o0+5], %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%o0+7], %o4
	or	%o4, %o3, %o4
	stxa	%o4, [%o1]%asi
	subcc	%o2, 8, %o2		! decrement length count
	add	%o1, 8, %o1		! increase dst ptr by 8
	add	%o0, 8, %o0		! increase src ptr by 8
	bgu,pt	%ncc, .co_medbh15
	stxa	%o4, [%o1-8]%asi
	ba	.co_medb7
	nop
/*
 * End of small copy (no window) code
 */

/*
 * Long copy code
 */
.co_copy_more:
	sethi	%hi(copyio_fault), %o3
	or	%o3, %lo(copyio_fault), %o3
	membar	#Sync
	stn	%o3, [THREAD_REG + T_LOFAULT]

/*
 * Following code is for large copies. We know there is at
 * least FP_COPY bytes available. FP regs are used, so
 *  we save registers and fp regs before starting
 */
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	or	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT
	rd	%fprs, %g1		! check for unused fp
	! if fprs.fef == 0, set it.
	! Setting it when already set costs more than checking
	andcc	%g1, FPRS_FEF, %g1	! test FEF, fprs.du = fprs.dl = 0
	bz,pt	%ncc, .co_fp_unused
	mov	ASI_USER, %asi
	BST_FP_TOSTACK(%o3)
	ba	.co_fp_ready
.co_fp_unused:
	prefetch [%i0 + (1 * CACHE_LINE)], #one_read
	wr	%g0, FPRS_FEF, %fprs	! fprs.fef = 1
.co_fp_ready:
	rd	%gsr, %l5		! save %gsr value
	andcc	%i1, 1, %o3		! is dest byte aligned
	bnz,pt	%ncc, .co_big_d1
.co_big_d1f:				! dest is now half word aligned
	andcc	%i1, 2, %o3
	bnz,pt	%ncc, .co_big_d2
.co_big_d2f:				! dest is now word aligned
	andcc	%i1, 4, %o3		! is dest longword aligned
	bnz,pt	%ncc, .co_big_d4
.co_big_d4f:				! dest is now long word aligned
	andcc	%i0, 7, %o3		! is src long word aligned
	brnz,pt	%o3, .co_big_unal8
	prefetch [%i0 + (2 * CACHE_LINE)], #one_read
	! Src and dst are long word aligned
	! align dst to 64 byte boundary
	andcc	%i1, 0x3f, %o3		! %o3 == 0 means dst is 64 byte aligned
	brz,pn	%o3, .co_al_to_64
	nop
	sub	%o3, 64, %o3		! %o3 has negative bytes to move
	add	%i2, %o3, %i2		! adjust remaining count
	andcc	%o3, 8, %o4		! odd long words to move?
	brz,pt	%o4, .co_al_to_16
	nop
	add	%o3, 8, %o3
	ldx	[%i0], %o4
	add	%i0, 8, %i0		! increment src ptr
	stxa	%o4, [%i1]ASI_USER
	add	%i1, 8, %i1		! increment dst ptr
! Dest is aligned on 16 bytes, src 8 byte aligned
.co_al_to_16:
	andcc	%o3, 0x30, %o4		! move to move?
	brz,pt	%o4, .co_al_to_64
	nop
.co_al_mv_16:
	add	%o3, 16, %o3
	ldx	[%i0], %o4
	stxa	%o4, [%i1]ASI_USER
	add	%i0, 16, %i0		! increment src ptr
	ldx	[%i0-8], %o4
	add	%i1, 8, %i1		! increment dst ptr
	stxa	%o4, [%i1]ASI_USER
	andcc	%o3, 0x30, %o4
	brnz,pt	%o4, .co_al_mv_16
	add	%i1, 8, %i1		! increment dst ptr
! Dest is aligned on 64 bytes, src 8 byte aligned
.co_al_to_64:
	! Determine source alignment
	! to correct 8 byte offset
	andcc	%i0, 32, %o3
	brnz,pn	%o3, .co_aln_1
	andcc	%i0, 16, %o3
	brnz,pn	%o3, .co_aln_01
	andcc	%i0, 8, %o3
	brz,pn	%o3, .co_aln_000
	prefetch [%i0 + (3 * CACHE_LINE)], #one_read
	ba	.co_aln_001
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
.co_aln_01:
	brnz,pn	%o3, .co_aln_011
	prefetch [%i0 + (3 * CACHE_LINE)], #one_read
	ba	.co_aln_010
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
.co_aln_1:
	andcc	%i0, 16, %o3
	brnz,pn	%o3, .co_aln_11
	andcc	%i0, 8, %o3
	brnz,pn	%o3, .co_aln_101
	prefetch [%i0 + (3 * CACHE_LINE)], #one_read
	ba	.co_aln_100
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
.co_aln_11:
	brz,pn	%o3, .co_aln_110
	prefetch [%i0 + (3 * CACHE_LINE)], #one_read

.co_aln_111:
! Alignment off by 8 bytes
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	ldd	[%i0], %d0
	add	%i0, 8, %i0
	sub	%i2, 8, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.co_aln_111_loop:
	ldda	[%i0]ASI_BLK_P,%d16		! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d2
	fmovd	%d18, %d4
	fmovd	%d20, %d6
	fmovd	%d22, %d8
	fmovd	%d24, %d10
	fmovd	%d26, %d12
	fmovd	%d28, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_AIUS	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_AIUS
	add	%i0, 64, %i0
	fmovd	%d30, %d0
	bgt,pt	%ncc, .co_aln_111_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	stda	%d0, [%i1]ASI_USER
	ba	.co_remain_stuff
	add	%i1, 8, %i1
	! END OF aln_111

.co_aln_110:
! Alignment off by 16 bytes
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	add	%i0, 16, %i0
	sub	%i2, 16, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.co_aln_110_loop:
	ldda	[%i0]ASI_BLK_P,%d16		! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d4
	fmovd	%d18, %d6
	fmovd	%d20, %d8
	fmovd	%d22, %d10
	fmovd	%d24, %d12
	fmovd	%d26, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_AIUS	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_AIUS
	add	%i0, 64, %i0
	fmovd	%d28, %d0
	fmovd	%d30, %d2
	bgt,pt	%ncc, .co_aln_110_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	stda	%d0, [%i1]%asi
	stda	%d2, [%i1+8]%asi
	ba	.co_remain_stuff
	add	%i1, 16, %i1
	! END OF aln_110

.co_aln_101:
! Alignment off by 24 bytes
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	ldd	[%i0+16], %d4
	add	%i0, 24, %i0
	sub	%i2, 24, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.co_aln_101_loop:
	ldda	[%i0]ASI_BLK_P,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d6
	fmovd	%d18, %d8
	fmovd	%d20, %d10
	fmovd	%d22, %d12
	fmovd	%d24, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_AIUS	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_AIUS
	add	%i0, 64, %i0
	fmovd	%d26, %d0
	fmovd	%d28, %d2
	fmovd	%d30, %d4
	bgt,pt	%ncc, .co_aln_101_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	stda	%d0, [%i1]%asi
	stda	%d2, [%i1+8]%asi
	stda	%d4, [%i1+16]%asi
	ba	.co_remain_stuff
	add	%i1, 24, %i1
	! END OF aln_101

.co_aln_100:
! Alignment off by 32 bytes
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	ldd	[%i0+16],%d4
	ldd	[%i0+24],%d6
	add	%i0, 32, %i0
	sub	%i2, 32, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.co_aln_100_loop:
	ldda	[%i0]ASI_BLK_P,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d8
	fmovd	%d18, %d10
	fmovd	%d20, %d12
	fmovd	%d22, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_AIUS	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_AIUS
	add	%i0, 64, %i0
	fmovd	%d24, %d0
	fmovd	%d26, %d2
	fmovd	%d28, %d4
	fmovd	%d30, %d6
	bgt,pt	%ncc, .co_aln_100_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	stda	%d0, [%i1]%asi
	stda	%d2, [%i1+8]%asi
	stda	%d4, [%i1+16]%asi
	stda	%d6, [%i1+24]%asi
	ba	.co_remain_stuff
	add	%i1, 32, %i1
	! END OF aln_100

.co_aln_011:
! Alignment off by 40 bytes
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	ldd	[%i0+16], %d4
	ldd	[%i0+24], %d6
	ldd	[%i0+32], %d8
	add	%i0, 40, %i0
	sub	%i2, 40, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.co_aln_011_loop:
	ldda	[%i0]ASI_BLK_P,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d10
	fmovd	%d18, %d12
	fmovd	%d20, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_AIUS	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_AIUS
	add	%i0, 64, %i0
	fmovd	%d22, %d0
	fmovd	%d24, %d2
	fmovd	%d26, %d4
	fmovd	%d28, %d6
	fmovd	%d30, %d8
	bgt,pt	%ncc, .co_aln_011_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	stda	%d0, [%i1]%asi
	stda	%d2, [%i1+8]%asi
	stda	%d4, [%i1+16]%asi
	stda	%d6, [%i1+24]%asi
	stda	%d8, [%i1+32]%asi
	ba	.co_remain_stuff
	add	%i1, 40, %i1
	! END OF aln_011

.co_aln_010:
! Alignment off by 48 bytes
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	ldd	[%i0+16], %d4
	ldd	[%i0+24], %d6
	ldd	[%i0+32], %d8
	ldd	[%i0+40], %d10
	add	%i0, 48, %i0
	sub	%i2, 48, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.co_aln_010_loop:
	ldda	[%i0]ASI_BLK_P,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d12
	fmovd	%d18, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_AIUS	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_AIUS
	add	%i0, 64, %i0
	fmovd	%d20, %d0
	fmovd	%d22, %d2
	fmovd	%d24, %d4
	fmovd	%d26, %d6
	fmovd	%d28, %d8
	fmovd	%d30, %d10
	bgt,pt	%ncc, .co_aln_010_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	stda	%d0, [%i1]%asi
	stda	%d2, [%i1+8]%asi
	stda	%d4, [%i1+16]%asi
	stda	%d6, [%i1+24]%asi
	stda	%d8, [%i1+32]%asi
	stda	%d10, [%i1+40]%asi
	ba	.co_remain_stuff
	add	%i1, 48, %i1
	! END OF aln_010

.co_aln_001:
! Alignment off by 56 bytes
	ldd	[%i0], %d0
	ldd	[%i0+8], %d2
	ldd	[%i0+16], %d4
	ldd	[%i0+24], %d6
	ldd	[%i0+32], %d8
	ldd	[%i0+40], %d10
	ldd	[%i0+48], %d12
	add	%i0, 56, %i0
	sub	%i2, 56, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.co_aln_001_loop:
	ldda	[%i0]ASI_BLK_P,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_AIUS	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_AIUS
	add	%i0, 64, %i0
	fmovd	%d18, %d0
	fmovd	%d20, %d2
	fmovd	%d22, %d4
	fmovd	%d24, %d6
	fmovd	%d26, %d8
	fmovd	%d28, %d10
	fmovd	%d30, %d12
	bgt,pt	%ncc, .co_aln_001_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	stda	%d0, [%i1]%asi
	stda	%d2, [%i1+8]%asi
	stda	%d4, [%i1+16]%asi
	stda	%d6, [%i1+24]%asi
	stda	%d8, [%i1+32]%asi
	stda	%d10, [%i1+40]%asi
	stda	%d12, [%i1+48]%asi
	ba	.co_remain_stuff
	add	%i1, 56, %i1
	! END OF aln_001

.co_aln_000:
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.co_aln_000_loop:
	ldda	[%i0]ASI_BLK_P,%d0
	subcc	%o3, 64, %o3
	stxa	%g0,[%i0+%i1]ASI_STBI_AIUS	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_AIUS
	add	%i0, 64, %i0
	bgt,pt	%ncc, .co_aln_000_loop
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read
	add	%i1, %i0, %i1

	! END OF aln_000

.co_remain_stuff:
	subcc	%i2, 31, %i2		! adjust length to allow cc test
	ble,pt	%ncc, .co_aln_31
	nop
.co_aln_32:
	ldx	[%i0], %o4		! move 32 bytes
	subcc	%i2, 32, %i2		! decrement length count by 32
	stxa	%o4, [%i1]%asi
	ldx	[%i0+8], %o4
	stxa	%o4, [%i1+8]%asi
	ldx	[%i0+16], %o4
	add	%i0, 32, %i0		! increase src ptr by 32
	stxa	%o4, [%i1+16]%asi
	ldx	[%i0-8], %o4
	add	%i1, 32, %i1		! increase dst ptr by 32
	bgu,pt	%ncc, .co_aln_32	! repeat if at least 32 bytes left
	stxa	%o4, [%i1-8]%asi
.co_aln_31:
	addcc	%i2, 24, %i2		! adjust count to be off by 7
	ble,pt	%ncc, .co_aln_7		! skip if 7 or fewer bytes left
	nop				!
.co_aln_15:
	ldx	[%i0], %o4		! move 8 bytes
	add	%i0, 8, %i0		! increase src ptr by 8
	subcc	%i2, 8, %i2		! decrease count by 8
	add	%i1, 8, %i1		! increase dst ptr by 8
	bgu,pt	%ncc, .co_aln_15
	stxa	%o4, [%i1-8]%asi
.co_aln_7:
	addcc	%i2, 7, %i2		! finish adjustment of remaining count
	bz,pt	%ncc, .co_exit		! exit if finished
	cmp	%i2, 4
	blt,pt	%ncc, .co_unaln3x	! skip if less than 4 bytes left
	nop				!
	ld	[%i0], %o4		! move 4 bytes
	add	%i0, 4, %i0		! increase src ptr by 4
	add	%i1, 4, %i1		! increase dst ptr by 4
	subcc	%i2, 4, %i2		! decrease count by 4
	bnz	.co_unaln3x
	stwa	%o4, [%i1-4]%asi
	ba	.co_exit
	nop

	! destination alignment code
.co_big_d1:
	ldub	[%i0], %o4		! move a byte
	add	%i0, 1, %i0
	stba	%o4, [%i1]ASI_USER
	add	%i1, 1, %i1
	andcc	%i1, 2, %o3
	bz,pt	%ncc, .co_big_d2f
	sub	%i2, 1, %i2
.co_big_d2:
	ldub	[%i0], %o4		! move a half-word (src align unknown)
	ldub	[%i0+1], %o3
	add	%i0, 2, %i0
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o4		! merge
	stha	%o4, [%i1]ASI_USER
	add	%i1, 2, %i1
	andcc	%i1, 4, %o3		! is dest longword aligned
	bz,pt	%ncc, .co_big_d4f
	sub	%i2, 2, %i2
.co_big_d4:				! dest is at least word aligned
	nop
	ldub	[%i0], %o4		! move a word (src align unknown)
	ldub	[%i0+1], %o3
	sll	%o4, 24, %o4		! position
	sll	%o3, 16, %o3		! position
	or	%o4, %o3, %o3		! merge
	ldub	[%i0+2], %o4
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o3		! merge
	ldub	[%i0+3], %o4
	or	%o4, %o3, %o4		! merge
	stwa	%o4,[%i1]ASI_USER	! store four bytes
	add	%i0, 4, %i0		! adjust src by 4
	add	%i1, 4, %i1		! adjust dest by 4
	ba	.co_big_d4f
	sub	%i2, 4, %i2		! adjust count by 4


	! Dst is on 8 byte boundary; src is not;
.co_big_unal8:
	andcc	%i1, 0x3f, %o3		! is dst 64-byte block aligned?
	bz	%ncc, .co_unalnsrc
	sub	%o3, 64, %o3		! %o3 will be multiple of 8
	neg	%o3			! bytes until dest is 64 byte aligned
	sub	%i2, %o3, %i2		! update cnt with bytes to be moved
	! Move bytes according to source alignment
	andcc	%i0, 0x1, %o4
	bnz	%ncc, .co_unalnbyte	! check for byte alignment
	nop
	andcc	%i0, 2, %o4		! check for half word alignment
	bnz	%ncc, .co_unalnhalf
	nop
	! Src is word aligned, move bytes until dest 64 byte aligned
.co_unalnword:
	ld	[%i0], %o4		! load 4 bytes
	stwa	%o4, [%i1]%asi		! and store 4 bytes
	ld	[%i0+4], %o4		! load 4 bytes
	add	%i0, 8, %i0		! increase src ptr by 8
	stwa	%o4, [%i1+4]%asi	! and store 4 bytes
	subcc	%o3, 8, %o3		! decrease count by 8
	bnz	%ncc, .co_unalnword
	add	%i1, 8, %i1		! increase dst ptr by 8
	ba	.co_unalnsrc
	nop

	! Src is half-word aligned, move bytes until dest 64 byte aligned
.co_unalnhalf:
	lduh	[%i0], %o4		! load 2 bytes
	sllx	%o4, 32, %i3		! shift left
	lduw	[%i0+2], %o4
	or	%o4, %i3, %i3
	sllx	%i3, 16, %i3
	lduh	[%i0+6], %o4
	or	%o4, %i3, %i3
	stxa	%i3, [%i1]ASI_USER
	add	%i0, 8, %i0
	subcc	%o3, 8, %o3
	bnz	%ncc, .co_unalnhalf
	add	%i1, 8, %i1
	ba	.co_unalnsrc
	nop

	! Src is Byte aligned, move bytes until dest 64 byte aligned
.co_unalnbyte:
	sub	%i1, %i0, %i1		! share pointer advance
.co_unalnbyte_loop:
	ldub	[%i0], %o4
	sllx	%o4, 56, %i3
	lduh	[%i0+1], %o4
	sllx	%o4, 40, %o4
	or	%o4, %i3, %i3
	lduh	[%i0+3], %o4
	sllx	%o4, 24, %o4
	or	%o4, %i3, %i3
	lduh	[%i0+5], %o4
	sllx	%o4, 8, %o4
	or	%o4, %i3, %i3
	ldub	[%i0+7], %o4
	or	%o4, %i3, %i3
	stxa	%i3, [%i1+%i0]ASI_USER
	subcc	%o3, 8, %o3
	bnz	%ncc, .co_unalnbyte_loop
	add	%i0, 8, %i0
	add	%i1,%i0, %i1		! restore pointer

	! Destination is now block (64 byte aligned), src is not 8 byte aligned
.co_unalnsrc:
	andn	%i2, 0x3f, %i3		! %i3 is multiple of block size
	and	%i2, 0x3f, %i2		! residue bytes in %i2
	add	%i2, 64, %i2		! Insure we don't load beyond
	sub	%i3, 64, %i3		! end of source buffer

	andn	%i0, 0x3f, %o4		! %o4 has block aligned src address
	prefetch [%o4 + (3 * CACHE_LINE)], #one_read
	alignaddr %i0, %g0, %g0		! generate %gsr
	add	%i0, %i3, %i0		! advance %i0 to after blocks
	!
	! Determine source alignment to correct 8 byte offset
	andcc	%i0, 0x20, %o3
	brnz,pn	%o3, .co_unaln_1
	andcc	%i0, 0x10, %o3
	brnz,pn	%o3, .co_unaln_01
	andcc	%i0, 0x08, %o3
	brz,a	%o3, .co_unaln_000
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.co_unaln_001
	nop
.co_unaln_01:
	brnz,a	%o3, .co_unaln_011
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.co_unaln_010
	nop
.co_unaln_1:
	brnz,pn	%o3, .co_unaln_11
	andcc	%i0, 0x08, %o3
	brnz,a	%o3, .co_unaln_101
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.co_unaln_100
	nop
.co_unaln_11:
	brz,pn	%o3, .co_unaln_110
	prefetch [%i0 + (4 * CACHE_LINE)], #one_read

.co_unaln_111:
	ldd	[%o4+56], %d14
.co_unaln_111_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d14, %d16, %d48
	faligndata %d16, %d18, %d50
	faligndata %d18, %d20, %d52
	faligndata %d20, %d22, %d54
	faligndata %d22, %d24, %d56
	faligndata %d24, %d26, %d58
	faligndata %d26, %d28, %d60
	faligndata %d28, %d30, %d62
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_AIUS
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .co_unaln_111_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.co_unaln_done
	nop

.co_unaln_110:
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.co_unaln_110_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d12, %d14, %d48
	faligndata %d14, %d16, %d50
	faligndata %d16, %d18, %d52
	faligndata %d18, %d20, %d54
	faligndata %d20, %d22, %d56
	faligndata %d22, %d24, %d58
	faligndata %d24, %d26, %d60
	faligndata %d26, %d28, %d62
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_AIUS
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .co_unaln_110_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.co_unaln_done
	nop

.co_unaln_101:
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.co_unaln_101_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d10, %d12, %d48
	faligndata %d12, %d14, %d50
	faligndata %d14, %d16, %d52
	faligndata %d16, %d18, %d54
	faligndata %d18, %d20, %d56
	faligndata %d20, %d22, %d58
	faligndata %d22, %d24, %d60
	faligndata %d24, %d26, %d62
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_AIUS
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .co_unaln_101_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.co_unaln_done
	nop

.co_unaln_100:
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.co_unaln_100_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d8, %d10, %d48
	faligndata %d10, %d12, %d50
	faligndata %d12, %d14, %d52
	faligndata %d14, %d16, %d54
	faligndata %d16, %d18, %d56
	faligndata %d18, %d20, %d58
	faligndata %d20, %d22, %d60
	faligndata %d22, %d24, %d62
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_AIUS
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .co_unaln_100_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.co_unaln_done
	nop

.co_unaln_011:
	ldd	[%o4+24], %d6
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.co_unaln_011_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d6, %d8, %d48
	faligndata %d8, %d10, %d50
	faligndata %d10, %d12, %d52
	faligndata %d12, %d14, %d54
	faligndata %d14, %d16, %d56
	faligndata %d16, %d18, %d58
	faligndata %d18, %d20, %d60
	faligndata %d20, %d22, %d62
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_AIUS
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .co_unaln_011_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.co_unaln_done
	nop

.co_unaln_010:
	ldd	[%o4+16], %d4
	ldd	[%o4+24], %d6
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.co_unaln_010_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d4, %d6, %d48
	faligndata %d6, %d8, %d50
	faligndata %d8, %d10, %d52
	faligndata %d10, %d12, %d54
	faligndata %d12, %d14, %d56
	faligndata %d14, %d16, %d58
	faligndata %d16, %d18, %d60
	faligndata %d18, %d20, %d62
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_AIUS
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .co_unaln_010_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.co_unaln_done
	nop

.co_unaln_001:
	ldd	[%o4+8], %d2
	ldd	[%o4+16], %d4
	ldd	[%o4+24], %d6
	ldd	[%o4+32], %d8
	ldd	[%o4+40], %d10
	ldd	[%o4+48], %d12
	ldd	[%o4+56], %d14
.co_unaln_001_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d2, %d4, %d48
	faligndata %d4, %d6, %d50
	faligndata %d6, %d8, %d52
	faligndata %d8, %d10, %d54
	faligndata %d10, %d12, %d56
	faligndata %d12, %d14, %d58
	faligndata %d14, %d16, %d60
	faligndata %d16, %d18, %d62
	fmovd	%d18, %d2
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_AIUS
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .co_unaln_001_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read
	ba	.co_unaln_done
	nop

.co_unaln_000:
	ldda	[%o4]ASI_BLK_P, %d0
.co_unaln_000_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_P, %d16
	faligndata %d0, %d2, %d48
	faligndata %d2, %d4, %d50
	faligndata %d4, %d6, %d52
	faligndata %d6, %d8, %d54
	faligndata %d8, %d10, %d56
	faligndata %d10, %d12, %d58
	faligndata %d12, %d14, %d60
	faligndata %d14, %d16, %d62
	fmovd	%d16, %d0
	fmovd	%d18, %d2
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_AIUS
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .co_unaln_000_loop
	prefetch [%o4 + (4 * CACHE_LINE)], #one_read

.co_unaln_done:
	! Handle trailing bytes, 64 to 127
	! Dest long word aligned, Src not long word aligned
	cmp	%i2, 15
	bleu	%ncc, .co_unaln_short

	andn	%i2, 0x7, %i3		! %i3 is multiple of 8
	and	%i2, 0x7, %i2		! residue bytes in %i2
	add	%i2, 8, %i2
	sub	%i3, 8, %i3		! insure we don't load past end of src
	andn	%i0, 0x7, %o4		! %o4 has long word aligned src address
	add	%i0, %i3, %i0		! advance %i0 to after multiple of 8
	ldd	[%o4], %d0		! fetch partial word
.co_unaln_by8:
	ldd	[%o4+8], %d2
	add	%o4, 8, %o4
	faligndata %d0, %d2, %d16
	subcc	%i3, 8, %i3
	stda	%d16, [%i1]%asi
	fmovd	%d2, %d0
	bgu,pt	%ncc, .co_unaln_by8
	add	%i1, 8, %i1

.co_unaln_short:
	cmp	%i2, 8
	blt,pt	%ncc, .co_unalnfin
	nop
	ldub	[%i0], %o4
	sll	%o4, 24, %o3
	ldub	[%i0+1], %o4
	sll	%o4, 16, %o4
	or	%o4, %o3, %o3
	ldub	[%i0+2], %o4
	sll	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%i0+3], %o4
	or	%o4, %o3, %o3
	stwa	%o3, [%i1]%asi
	ldub	[%i0+4], %o4
	sll	%o4, 24, %o3
	ldub	[%i0+5], %o4
	sll	%o4, 16, %o4
	or	%o4, %o3, %o3
	ldub	[%i0+6], %o4
	sll	%o4, 8, %o4
	or	%o4, %o3, %o3
	ldub	[%i0+7], %o4
	or	%o4, %o3, %o3
	stwa	%o3, [%i1+4]%asi
	add	%i0, 8, %i0
	add	%i1, 8, %i1
	sub	%i2, 8, %i2
.co_unalnfin:
	cmp	%i2, 4
	blt,pt	%ncc, .co_unalnz
	tst	%i2
	ldub	[%i0], %o3		! read byte
	subcc	%i2, 4, %i2		! reduce count by 4
	sll	%o3, 24, %o3		! position
	ldub	[%i0+1], %o4
	sll	%o4, 16, %o4		! position
	or	%o4, %o3, %o3		! merge
	ldub	[%i0+2], %o4
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o3		! merge
	add	%i1, 4, %i1		! advance dst by 4
	ldub	[%i0+3], %o4
	add	%i0, 4, %i0		! advance src by 4
	or	%o4, %o3, %o4		! merge
	bnz,pt	%ncc, .co_unaln3x
	stwa	%o4, [%i1-4]%asi
	ba	.co_exit
	nop
.co_unalnz:
	bz,pt	%ncc, .co_exit
	wr	%l5, %g0, %gsr		! restore %gsr
.co_unaln3x:				! Exactly 1, 2, or 3 bytes remain
	subcc	%i2, 1, %i2		! reduce count for cc test
	ldub	[%i0], %o4		! load one byte
	bz,pt	%ncc, .co_exit
	stba	%o4, [%i1]%asi		! store one byte
	ldub	[%i0+1], %o4		! load second byte
	subcc	%i2, 1, %i2
	bz,pt	%ncc, .co_exit
	stba	%o4, [%i1+1]%asi	! store second byte
	ldub	[%i0+2], %o4		! load third byte
	stba	%o4, [%i1+2]%asi	! store third byte
.co_exit:
	brnz	%g1, .co_fp_restore
	nop
	FZERO
	wr	%g1, %g0, %fprs
	ba,pt	%ncc, .co_ex2
	membar	#Sync
.co_fp_restore:
	BLD_FP_FROMSTACK(%o4)
.co_ex2:
	andn	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT] ! restore old t_lofault
	ret
	restore %g0, 0, %o0

.copyout_err:
	ldn	[THREAD_REG + T_COPYOPS], %o4
	brz	%o4, 2f
	nop
	ldn	[%o4 + CP_COPYOUT], %g2
	jmp	%g2
	nop
2:
	retl
	mov	-1, %o0

#else	/* NIAGARA_IMPL */
.do_copyout:
	!
	! Check the length and bail if zero.
	!
	tst	%o2
	bnz,pt	%ncc, 1f
	nop
	retl
	clr	%o0
1:
	sethi	%hi(copyio_fault), %o4
	or	%o4, %lo(copyio_fault), %o4
	sethi	%hi(copyio_fault_nowindow), %o3
	ldn	[THREAD_REG + T_LOFAULT], SAVED_LOFAULT
	or	%o3, %lo(copyio_fault_nowindow), %o3
	membar	#Sync
	stn	%o3, [THREAD_REG + T_LOFAULT]

	mov	%o0, SAVE_SRC
	mov	%o1, SAVE_DST
	mov	%o2, SAVE_COUNT

	!
	! Check to see if we're more than SMALL_LIMIT (7 bytes).
	! Run in leaf mode, using the %o regs as our input regs.
	!
	subcc	%o2, SMALL_LIMIT, %o3
	bgu,a,pt %ncc, .dco_ns
	or	%o0, %o1, %o3
	!
	! What was previously ".small_copyout"
	! Do full differenced copy.
	!
.dcobcp:
	sub	%g0, %o2, %o3		! negate count
	add	%o0, %o2, %o0		! make %o0 point at the end
	add	%o1, %o2, %o1		! make %o1 point at the end
	ba,pt	%ncc, .dcocl
	ldub	[%o0 + %o3], %o4	! load first byte
	!
	! %o0 and %o2 point at the end and remain pointing at the end
	! of their buffers. We pull things out by adding %o3 (which is
	! the negation of the length) to the buffer end which gives us
	! the curent location in the buffers. By incrementing %o3 we walk
	! through both buffers without having to bump each buffer's
	! pointer. A very fast 4 instruction loop.
	!
	.align 16
.dcocl:
	stba	%o4, [%o1 + %o3]ASI_USER
	inccc	%o3
	bl,a,pt	%ncc, .dcocl
	ldub	[%o0 + %o3], %o4
	!
	! We're done. Go home.
	!
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
	retl
	clr	%o0
	!
	! Try aligned copies from here.
	!
.dco_ns:
	! %o0 = kernel addr (to be copied from)
	! %o1 = user addr (to be copied to)
	! %o2 = length
	! %o3 = %o1 | %o2 (used for alignment checking)
	! %o4 is alternate lo_fault
	! %o5 is original lo_fault
	!
	! See if we're single byte aligned. If we are, check the
	! limit for single byte copies. If we're smaller or equal,
	! bounce to the byte for byte copy loop. Otherwise do it in
	! HW (if enabled).
	!
	btst	1, %o3
	bz,pt	%icc, .dcoh8
	btst	7, %o3
	!
	! Single byte aligned. Do we do it via HW or via
	! byte for byte? Do a quick no memory reference
	! check to pick up small copies.
	!
	sethi	%hi(hw_copy_limit_1), %o3
	!
	! Big enough that we need to check the HW limit for
	! this size copy.
	!
	ld	[%o3 + %lo(hw_copy_limit_1)], %o3
	!
	! Is HW copy on? If not, do everything byte for byte.
	!
	tst	%o3
	bz,pn	%icc, .dcobcp
	subcc	%o3, %o2, %o3
	!
	! If we're less than or equal to the single byte copy limit,
	! bop to the copy loop.
	!
	bge,pt	%ncc, .dcobcp
	nop
	!
	! We're big enough and copy is on. Do it with HW.
	!
	ba,pt	%ncc, .big_copyout
	nop
.dcoh8:
	!
	! 8 byte aligned?
	!
	bnz,a	%ncc, .dcoh4
	btst	3, %o3
	!
	! See if we're in the "small range".
	! If so, go off and do the copy.
	! If not, load the hard limit. %o3 is
	! available for reuse.
	!
	sethi	%hi(hw_copy_limit_8), %o3
	ld	[%o3 + %lo(hw_copy_limit_8)], %o3
	!
	! If it's zero, there's no HW bcopy.
	! Bop off to the aligned copy.
	!
	tst	%o3
	bz,pn	%icc, .dcos8
	subcc	%o3, %o2, %o3
	!
	! We're negative if our size is larger than hw_copy_limit_8.
	!
	bge,pt	%ncc, .dcos8
	nop
	!
	! HW assist is on and we're large enough. Do it.
	!
	ba,pt	%ncc, .big_copyout
	nop
.dcos8:
	!
	! Housekeeping for copy loops. Uses same idea as in the byte for
	! byte copy loop above.
	!
	add	%o0, %o2, %o0
	add	%o1, %o2, %o1
	sub	%g0, %o2, %o3
	ba,pt	%ncc, .dodebc
	srl	%o2, 3, %o2		! Number of 8 byte chunks to copy
	!
	! 4 byte aligned?
	!
.dcoh4:
	bnz,pn	%ncc, .dcoh2
	!
	! See if we're in the "small range".
	! If so, go off an do the copy.
	! If not, load the hard limit. %o3 is
	! available for reuse.
	!
	sethi	%hi(hw_copy_limit_4), %o3
	ld	[%o3 + %lo(hw_copy_limit_4)], %o3
	!
	! If it's zero, there's no HW bcopy.
	! Bop off to the aligned copy.
	!
	tst	%o3
	bz,pn	%icc, .dcos4
	subcc	%o3, %o2, %o3
	!
	! We're negative if our size is larger than hw_copy_limit_4.
	!
	bge,pt	%ncc, .dcos4
	nop
	!
	! HW assist is on and we're large enough. Do it.
	!
	ba,pt	%ncc, .big_copyout
	nop
.dcos4:
	add	%o0, %o2, %o0
	add	%o1, %o2, %o1
	sub	%g0, %o2, %o3
	ba,pt	%ncc, .dodfbc
	srl	%o2, 2, %o2		! Number of 4 byte chunks to copy
	!
	! We must be 2 byte aligned. Off we go.
	! The check for small copies was done in the
	! delay at .dcoh4
	!
.dcoh2:
	ble	%ncc, .dcos2
	sethi	%hi(hw_copy_limit_2), %o3
	ld	[%o3 + %lo(hw_copy_limit_2)], %o3
	tst	%o3
	bz,pn	%icc, .dcos2
	subcc	%o3, %o2, %o3
	bge,pt	%ncc, .dcos2
	nop
	!
	! HW is on and we're big enough. Do it.
	!
	ba,pt	%ncc, .big_copyout
	nop
.dcos2:
	add	%o0, %o2, %o0
	add	%o1, %o2, %o1
	sub	%g0, %o2, %o3
	ba,pt	%ncc, .dodtbc
	srl	%o2, 1, %o2		! Number of 2 byte chunks to copy
.small_copyout:
	!
	! Why are we doing this AGAIN? There are certain conditions in
	! big_copyout that will cause us to forego the HW assisted copies
	! and bounce back to a non-HW assisted copy. This dispatches those
	! copies. Note that we branch around this in the main line code.
	!
	! We make no check for limits or HW enablement here. We've
	! already been told that we're a poster child so just go off
	! and do it.
	!
	or	%o0, %o1, %o3
	btst	1, %o3
	bnz	%icc, .dcobcp		! Most likely
	btst	7, %o3
	bz	%icc, .dcos8
	btst	3, %o3
	bz	%icc, .dcos4
	nop
	ba,pt	%ncc, .dcos2
	nop
	.align 32
.dodebc:
	ldx	[%o0 + %o3], %o4
	deccc	%o2
	stxa	%o4, [%o1 + %o3]ASI_USER
	bg,pt	%ncc, .dodebc
	addcc	%o3, 8, %o3
	!
	! End of copy loop. Check to see if we're done. Most
	! eight byte aligned copies end here.
	!
	bz,pt	%ncc, .dcofh
	nop
	!
	! Something is left - do it byte for byte.
	! 
	ba,pt	%ncc, .dcocl
	ldub	[%o0 + %o3], %o4	! load next byte
	!
	! Four byte copy loop. %o2 is the number of 4 byte chunks to copy.
	!
	.align 32
.dodfbc:
	lduw	[%o0 + %o3], %o4
	deccc	%o2
	sta	%o4, [%o1 + %o3]ASI_USER
	bg,pt	%ncc, .dodfbc
	addcc	%o3, 4, %o3
	!
	! End of copy loop. Check to see if we're done. Most
	! four byte aligned copies end here.
	!
	bz,pt	%ncc, .dcofh
	nop
	!
	! Something is left. Do it byte for byte.
	!
	ba,pt	%ncc, .dcocl
	ldub	[%o0 + %o3], %o4	! load next byte
	!
	! two byte aligned copy loop. %o2 is the number of 2 byte chunks to
	! copy.
	!
	.align 32
.dodtbc:
	lduh	[%o0 + %o3], %o4
	deccc	%o2
	stha	%o4, [%o1 + %o3]ASI_USER
	bg,pt	%ncc, .dodtbc
	addcc	%o3, 2, %o3
	!
	! End of copy loop. Anything left?
	!
	bz,pt	%ncc, .dcofh
	nop
	!
	! Deal with the last byte
	!
	ldub	[%o0 + %o3], %o4
	stba	%o4, [%o1 + %o3]ASI_USER
.dcofh:
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	clr	%o0

.big_copyout:
	! We're going to go off and do a block copy.
	! Switch fault handlers and grab a window. We
	! don't do a membar #Sync since we've done only
	! kernel data to this point.
	stn	%o4, [THREAD_REG + T_LOFAULT]

	! Copy out that reach here are larger than 256 bytes. The
	! hw_copy_limit_1 is set to 256. Never set this limit less
	! 128 bytes.
	save	%sp, -SA(MINFRAME), %sp
.do_block_copyout:

	! Swap src/dst since the code below is memcpy code
	! and memcpy/bcopy have different calling sequences
	mov	%i1, %i5
	mov	%i0, %i1
	mov	%i5, %i0

	! Block (64 bytes) align the destination.
	andcc	%i0, 0x3f, %i3		! is dst block aligned
	bz	%ncc, copyout_blalign	! dst already block aligned
	sub	%i3, 0x40, %i3
	neg	%i3			! bytes till dst 64 bytes aligned
	sub	%i2, %i3, %i2		! update i2 with new count

	! Based on source and destination alignment do
	! either 8 bytes, 4 bytes, 2 bytes or byte copy.

	! Is dst & src 8B aligned
	or	%i0, %i1, %o2
	andcc	%o2, 0x7, %g0
	bz	%ncc, .co_alewdcp
	nop

	! Is dst & src 4B aligned
	andcc	%o2, 0x3, %g0
	bz	%ncc, .co_alwdcp
	nop

	! Is dst & src 2B aligned
	andcc	%o2, 0x1, %g0
	bz	%ncc, .co_alhlfwdcp
	nop

	! 1B aligned
1:	ldub	[%i1], %o2
	stba	%o2, [%i0]ASI_USER
	inc	%i1
	deccc	%i3
	bgu,pt	%ncc, 1b
	inc	%i0

	ba	copyout_blalign
	nop

	! dst & src 4B aligned
.co_alwdcp:
	ld	[%i1], %o2
	sta	%o2, [%i0]ASI_USER
	add	%i1, 0x4, %i1
	subcc	%i3, 0x4, %i3
	bgu,pt	%ncc, .co_alwdcp
	add	%i0, 0x4, %i0

	ba	copyout_blalign
	nop

	! dst & src 2B aligned
.co_alhlfwdcp:
	lduh	[%i1], %o2
	stuha	%o2, [%i0]ASI_USER
	add	%i1, 0x2, %i1
	subcc	%i3, 0x2, %i3
	bgu,pt	%ncc, .co_alhlfwdcp
	add	%i0, 0x2, %i0

	ba	copyout_blalign
	nop

	! dst & src 8B aligned
.co_alewdcp:
	ldx	[%i1], %o2
	stxa	%o2, [%i0]ASI_USER
	add	%i1, 0x8, %i1
	subcc	%i3, 0x8, %i3
	bgu,pt	%ncc, .co_alewdcp
	add	%i0, 0x8, %i0

	! Now Destination is block (64 bytes) aligned
copyout_blalign:
	andn	%i2, 0x3f, %i3		! %i3 count is multiple of block size
	sub	%i2, %i3, %i2		! Residue bytes in %i2

	mov	ASI_BLK_INIT_QUAD_LDD_AIUS, %asi

	andcc	%i1, 0xf, %o2		! is src quadword aligned
	bz,pn	%xcc, .co_blkcpy	! src offset in %o2 (last 4-bits)
	nop
	cmp	%o2, 0x8
	bg	.co_upper_double
	nop
	bl	.co_lower_double
	nop

	! Falls through when source offset is equal to 8 i.e.
	! source is double word aligned.
	! In this case no shift/merge of data is required

	sub	%i1, %o2, %i1		! align the src at 16 bytes.
	andn	%i1, 0x3f, %l0		! %l0 has block aligned source
	prefetch [%l0+0x0], #one_read
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l2
.co_loop0:
	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l4
	prefetch [%l0+0x40], #one_read

	stxa	%l3, [%i0+0x0]%asi
	stxa	%l4, [%i0+0x8]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l2

	stxa	%l5, [%i0+0x10]%asi
	stxa	%l2, [%i0+0x18]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l4

	stxa	%l3, [%i0+0x20]%asi
	stxa	%l4, [%i0+0x28]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l2

	stxa	%l5, [%i0+0x30]%asi
	stxa	%l2, [%i0+0x38]%asi

	add	%l0, 0x40, %l0
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, .co_loop0
	add	%i0, 0x40, %i0
	ba	.co_blkdone
	add	%i1, %o2, %i1		! increment the source by src offset
					! the src offset was stored in %o2

.co_lower_double:

	sub	%i1, %o2, %i1		! align the src at 16 bytes.
	sll	%o2, 3, %o0		! %o0 left shift
	mov	0x40, %o1
	sub	%o1, %o0, %o1		! %o1 right shift = (64 - left shift)
	andn	%i1, 0x3f, %l0		! %l0 has block aligned source
	prefetch [%l0+0x0], #one_read
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l2	! partial data in %l2 and %l3 has
					! complete data
.co_loop1:
	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l4	! %l4 has partial data
							! for this read.
	ALIGN_DATA(%l2, %l3, %l4, %o0, %o1, %l6)	! merge %l2, %l3 and %l4
							! into %l2 and %l3
	prefetch [%l0+0x40], #one_read

	stxa	%l2, [%i0+0x0]%asi
	stxa	%l3, [%i0+0x8]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l2
	ALIGN_DATA(%l4, %l5, %l2, %o0, %o1, %l6)	! merge %l2 with %l5 and
							! %l4 from previous read
							! into %l4 and %l5
	stxa	%l4, [%i0+0x10]%asi
	stxa	%l5, [%i0+0x18]%asi

	! Repeat the same for next 32 bytes.

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l4
	ALIGN_DATA(%l2, %l3, %l4, %o0, %o1, %l6)

	stxa	%l2, [%i0+0x20]%asi
	stxa	%l3, [%i0+0x28]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l2
	ALIGN_DATA(%l4, %l5, %l2, %o0, %o1, %l6)

	stxa	%l4, [%i0+0x30]%asi
	stxa	%l5, [%i0+0x38]%asi

	add	%l0, 0x40, %l0
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, .co_loop1
	add	%i0, 0x40, %i0
	ba	.co_blkdone
	add	%i1, %o2, %i1		! increment the source by src offset
					! the src offset was stored in %o2

.co_upper_double:

	sub	%i1, %o2, %i1		! align the src at 16 bytes.
	sub	%o2, 0x8, %o0
	sll	%o0, 3, %o0		! %o0 left shift
	mov	0x40, %o1
	sub	%o1, %o0, %o1		! %o1 right shift = (64 - left shift)
	andn	%i1, 0x3f, %l0		! %l0 has block aligned source
	prefetch [%l0+0x0], #one_read
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l2	! partial data in %l3
							! for this read and
							! no data in %l2
.co_loop2:
	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l4	! %l4 has complete data
							! and %l5 has partial
	ALIGN_DATA(%l3, %l4, %l5, %o0, %o1, %l6)	! merge %l3, %l4 and %l5
							! into %l3 and %l4
	prefetch [%l0+0x40], #one_read

	stxa	%l3, [%i0+0x0]%asi
	stxa	%l4, [%i0+0x8]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l2
	ALIGN_DATA(%l5, %l2, %l3, %o0, %o1, %l6)	! merge %l2 and %l3 with
							! %l5 from previous read
							! into %l5 and %l2

	stxa	%l5, [%i0+0x10]%asi
	stxa	%l2, [%i0+0x18]%asi

	! Repeat the same for next 32 bytes.

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l4
	ALIGN_DATA(%l3, %l4, %l5, %o0, %o1, %l6)

	stxa	%l3, [%i0+0x20]%asi
	stxa	%l4, [%i0+0x28]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l2
	ALIGN_DATA(%l5, %l2, %l3, %o0, %o1, %l6)

	stxa	%l5, [%i0+0x30]%asi
	stxa	%l2, [%i0+0x38]%asi

	add	%l0, 0x40, %l0
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, .co_loop2
	add	%i0, 0x40, %i0
	ba	.co_blkdone
	add	%i1, %o2, %i1		! increment the source by src offset
					! the src offset was stored in %o2


	! Do fast copy using ASI_BLK_INIT_ST_QUAD_LDD_P
.co_blkcpy:

	andn	%i1, 0x3f, %o0		! %o0 has block aligned source
	prefetch [%o0+0x0], #one_read
1:
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l0
	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l2
	add	%i1, 0x10, %i1

	prefetch [%o0+0x40], #one_read

	stxa	%l0, [%i0+0x0]%asi

	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l4
	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_ST_QUAD_LDD_P, %l6
	add	%i1, 0x10, %i1

	stxa	%l1, [%i0+0x8]%asi
	stxa	%l2, [%i0+0x10]%asi
	stxa	%l3, [%i0+0x18]%asi
	stxa	%l4, [%i0+0x20]%asi
	stxa	%l5, [%i0+0x28]%asi
	stxa	%l6, [%i0+0x30]%asi
	stxa	%l7, [%i0+0x38]%asi

	add	%o0, 0x40, %o0
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, 1b
	add	%i0, 0x40, %i0

.co_blkdone:
	membar	#Sync

	brz,pt	%i2, .copyout_exit
	nop

	! Handle trailing bytes
	cmp	%i2, 0x8
	blu,pt	%ncc, .co_residue
	nop

	! Can we do some 8B ops
	or	%i1, %i0, %o2
	andcc	%o2, 0x7, %g0
	bnz	%ncc, .co_last4
	nop

	! Do 8byte ops as long as possible
.co_last8:
	ldx	[%i1], %o2
	stxa	%o2, [%i0]ASI_USER
	add	%i1, 0x8, %i1
	sub	%i2, 0x8, %i2
	cmp	%i2, 0x8
	bgu,pt	%ncc, .co_last8
	add	%i0, 0x8, %i0

	brz,pt	%i2, .copyout_exit
	nop

	ba	.co_residue
	nop

.co_last4:
	! Can we do 4B ops
	andcc	%o2, 0x3, %g0
	bnz	%ncc, .co_last2
	nop
1:
	ld	[%i1], %o2
	sta	%o2, [%i0]ASI_USER
	add	%i1, 0x4, %i1
	sub	%i2, 0x4, %i2
	cmp	%i2, 0x4
	bgu,pt	%ncc, 1b
	add	%i0, 0x4, %i0

	brz,pt	%i2, .copyout_exit
	nop

	ba	.co_residue
	nop

.co_last2:
	! Can we do 2B ops
	andcc	%o2, 0x1, %g0
	bnz	%ncc, .co_residue
	nop

1:
	lduh	[%i1], %o2
	stuha	%o2, [%i0]ASI_USER
	add	%i1, 0x2, %i1
	sub	%i2, 0x2, %i2
	cmp	%i2, 0x2
	bgu,pt	%ncc, 1b
	add	%i0, 0x2, %i0

	brz,pt	%i2, .copyout_exit
	nop

	! Copy the residue as byte copy
.co_residue:
	ldub	[%i1], %i4
	stba	%i4, [%i0]ASI_USER
	inc	%i1
	deccc	%i2
	bgu,pt	%xcc, .co_residue
	inc	%i0

.copyout_exit:
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	ret
	restore	%g0, 0, %o0

.copyout_err:
	ldn	[THREAD_REG + T_COPYOPS], %o4
	brz	%o4, 2f
	nop
	ldn	[%o4 + CP_COPYOUT], %g2
	jmp	%g2
	nop
2:
	retl
	mov	-1, %o0
#endif	/* NIAGARA_IMPL */
	SET_SIZE(copyout)


	ENTRY(xcopyout)
	sethi	%hi(.xcopyout_err), REAL_LOFAULT
	b	.do_copyout
	or	REAL_LOFAULT, %lo(.xcopyout_err), REAL_LOFAULT
.xcopyout_err:
	ldn	[THREAD_REG + T_COPYOPS], %o4
	brz	%o4, 2f
	nop
	ldn	[%o4 + CP_XCOPYOUT], %g2
	jmp	%g2
	nop
2:
	retl
	mov	%g1, %o0
	SET_SIZE(xcopyout)

	ENTRY(xcopyout_little)
	sethi	%hi(.little_err), %o4
	ldn	[THREAD_REG + T_LOFAULT], %o5
	or	%o4, %lo(.little_err), %o4
	membar	#Sync			! sync error barrier
	stn	%o4, [THREAD_REG + T_LOFAULT]

	subcc	%g0, %o2, %o3
	add	%o0, %o2, %o0
	bz,pn	%ncc, 2f		! check for zero bytes
	sub	%o2, 1, %o4
	add	%o0, %o4, %o0		! start w/last byte
	add	%o1, %o2, %o1
	ldub	[%o0+%o3], %o4

1:	stba	%o4, [%o1+%o3]ASI_AIUSL
	inccc	%o3
	sub	%o0, 2, %o0		! get next byte
	bcc,a,pt %ncc, 1b
	ldub	[%o0+%o3], %o4

2:	membar	#Sync			! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	mov	%g0, %o0		! return (0)
	SET_SIZE(xcopyout_little)

/*
 * Copy user data to kernel space (copyin/xcopyin/xcopyin_little)
 */

	ENTRY(copyin)
	sethi	%hi(.copyin_err), REAL_LOFAULT
	or	REAL_LOFAULT, %lo(.copyin_err), REAL_LOFAULT

#if !defined(NIAGARA_IMPL)
.do_copyin:
	tst	%o2			! check for zero count;  quick exit
	bz,pt	%ncc, .ci_smallqx
	mov	%o0, SAVE_SRC
	mov	%o1, SAVE_DST
	mov	%o2, SAVE_COUNT
	cmp	%o2, FP_COPY		! check for small copy/leaf case
	bgt,pt	%ncc, .ci_copy_more
	ldn	[THREAD_REG + T_LOFAULT], SAVED_LOFAULT
/*
 * Small copy in code
 * 
 */
	sethi	%hi(copyio_fault_nowindow), %o3
	or	%o3, %lo(copyio_fault_nowindow), %o3
	membar	#Sync
	stn	%o3, [THREAD_REG + T_LOFAULT]

	mov	ASI_USER, %asi
	cmp	%o2, SHORTCOPY		! make sure there is enough to align
	ble,pt	%ncc, .ci_smallest
	andcc	%o1, 0x7, %o3		! is dest long word aligned
	bnz,pn	%ncc, .ci_align
	andcc	%o1, 1, %o3		! is dest byte aligned

! Destination is long word aligned
.ci_al_src:
	andcc	%o0, 7, %o3
	brnz,pt	%o3, .ci_src_dst_unal8
	nop
/*
 * Special case for handling when src and dest are both long word aligned
 * and total data to move is less than FP_COPY bytes
 * Also handles finish up for large block moves, so may be less than 32 bytes
 */
.ci_medlong:
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .ci_medl31
	nop
.ci_medl32:
	ldxa	[%o0]%asi, %o4		! move 32 bytes
	subcc	%o2, 32, %o2		! decrement length count by 32
	stx	%o4, [%o1]
	ldxa	[%o0+8]%asi, %o4
	stx	%o4, [%o1+8]
	ldxa	[%o0+16]%asi, %o4
	add	%o0, 32, %o0		! increase src ptr by 32
	stx	%o4, [%o1+16]
	ldxa	[%o0-8]%asi, %o4
	add	%o1, 32, %o1		! increase dst ptr by 32
	bgu,pt	%ncc, .ci_medl32	! repeat if at least 32 bytes left
	stx	%o4, [%o1-8]
.ci_medl31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .ci_medl7		! skip if 7 or fewer bytes left
	nop
.ci_medl8:
	ldxa	[%o0]%asi, %o4		! move 8 bytes
	add	%o0, 8, %o0		! increase src ptr by 8
	subcc	%o2, 8, %o2		! decrease count by 8
	add	%o1, 8, %o1		! increase dst ptr by 8
	bgu,pt	%ncc, .ci_medl8
	stx	%o4, [%o1-8]
.ci_medl7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bnz,pt	%ncc, .ci_small4	! do final bytes if not finished
	nop
.ci_smallx:				! finish up and exit
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
.ci_smallqx:
	retl
	mov	%g0, %o0

.ci_small4:
	cmp	%o2, 4
	blt,pt	%ncc, .ci_small3x	! skip if less than 4 bytes left
	nop				!
	lda	[%o0]%asi, %o4		! move 4 bytes
	add	%o0, 4, %o0		! increase src ptr by 4
	add	%o1, 4, %o1		! increase dst ptr by 4
	subcc	%o2, 4, %o2		! decrease count by 4
	bz	%ncc, .ci_smallx
	stw	%o4, [%o1-4]

.ci_small3x:				! Exactly 1, 2, or 3 bytes remain
	subcc	%o2, 1, %o2		! reduce count for cc test
	lduba	[%o0]%asi, %o4		! load one byte
	bz,pt	%ncc, .ci_smallx
	stb	%o4, [%o1]		! store one byte
	lduba	[%o0+1]%asi, %o4	! load second byte
	subcc	%o2, 1, %o2
	bz,pt	%ncc, .ci_smallx
	stb	%o4, [%o1+1]		! store second byte
	lduba	[%o0+2]%asi, %o4	! load third byte
	ba	.ci_smallx
	stb	%o4, [%o1+2]		! store third byte

.ci_smallest:				! 7 or fewer bytes remain
	cmp	%o2, 4
	blt,pt	%ncc, .ci_small3x
	nop
	lduba	[%o0]%asi, %o4		! read byte
	subcc	%o2, 4, %o2		! reduce count by 4
	stb	%o4, [%o1]		! write byte
	lduba	[%o0+1]%asi, %o4	! repeat for total of 4 bytes
	add	%o0, 4, %o0		! advance src by 4
	stb	%o4, [%o1+1]
	lduba	[%o0-2]%asi, %o4
	add	%o1, 4, %o1		! advance dst by 4
	stb	%o4, [%o1-2]
	lduba	[%o0-1]%asi, %o4
	bnz,pt	%ncc, .ci_small3x
	stb	%o4, [%o1-1]
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
	retl
	mov	%g0, %o0

.ci_align:
	bnz,pt	%ncc, .ci_al_d1
.ci_al_d1f:				! dest is now half word aligned
	andcc	%o1, 2, %o3		! is dest word aligned
	bnz,pt	%ncc, .ci_al_d2
.ci_al_d2f:				! dest is now word aligned
	andcc	%o1, 4, %o3		! is dest longword aligned?
	bz,pt	%ncc, .ci_al_src
	nop
.ci_al_d4:				! dest is word aligned;  src is unknown
	lduba	[%o0]%asi, %o4		! move a word (src align unknown)
	lduba	[%o0+1]%asi, %o3
	sll	%o4, 24, %o4		! position
	sll	%o3, 16, %o3		! position
	or	%o4, %o3, %o3		! merge
	lduba	[%o0+2]%asi, %o4
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o3		! merge
	lduba	[%o0+3]%asi, %o4
	or	%o4, %o3, %o4		! merge
	stw	%o4,[%o1]		! store four bytes
	add	%o0, 4, %o0		! adjust src by 4
	add	%o1, 4, %o1		! adjust dest by 4
	sub	%o2, 4, %o2		! adjust count by 4
	andcc	%o0, 7, %o3		! check for src long word alignment
	brz,pt	%o3, .ci_medlong
.ci_src_dst_unal8:
	! dst is 8-byte aligned, src is not
	! Size is less than FP_COPY
	! Following code is to select for alignment
	andcc	%o0, 0x3, %o3		! test word alignment
	bz,pt	%ncc, .ci_medword
	nop
	andcc	%o0, 0x1, %o3		! test halfword alignment
	bnz,pt	%ncc, .ci_med_byte	! go to byte move if not halfword
	andcc	%o0, 0x2, %o3		! test which byte alignment
	ba	.ci_medhalf
	nop
.ci_al_d1:				! align dest to half word
	lduba	[%o0]%asi, %o4		! move a byte
	add	%o0, 1, %o0
	stb	%o4, [%o1]
	add	%o1, 1, %o1
	andcc	%o1, 2, %o3		! is dest word aligned
	bz,pt	%ncc, .ci_al_d2f
	sub	%o2, 1, %o2
.ci_al_d2:				! align dest to word
	lduba	[%o0]%asi, %o4		! move a half-word (src align unknown)
	lduba	[%o0+1]%asi, %o3
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o4		! merge
	sth	%o4, [%o1]
	add	%o0, 2, %o0
	add	%o1, 2, %o1
	andcc	%o1, 4, %o3		! is dest longword aligned?
	bz,pt	%ncc, .ci_al_src
	sub	%o2, 2, %o2
	ba	.ci_al_d4
	nop
/*
 * Handle all cases where src and dest are aligned on word
 * boundaries. Use unrolled loops for better performance.
 * This option wins over standard large data move when 
 * source and destination is in cache for medium
 * to short data moves.
 */
.ci_medword:
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .ci_medw31
	nop
.ci_medw32:
	lda	[%o0]%asi, %o4		! move a block of 32 bytes
	stw	%o4, [%o1]
	lda	[%o0+4]%asi, %o4
	stw	%o4, [%o1+4]
	lda	[%o0+8]%asi, %o4
	stw	%o4, [%o1+8]
	lda	[%o0+12]%asi, %o4
	stw	%o4, [%o1+12]
	lda	[%o0+16]%asi, %o4
	stw	%o4, [%o1+16]
	lda	[%o0+20]%asi, %o4
	subcc	%o2, 32, %o2		! decrement length count
	stw	%o4, [%o1+20]
	lda	[%o0+24]%asi, %o4
	add	%o0, 32, %o0		! increase src ptr by 32
	stw	%o4, [%o1+24]
	lda	[%o0-4]%asi, %o4
	add	%o1, 32, %o1		! increase dst ptr by 32
	bgu,pt	%ncc, .ci_medw32	! repeat if at least 32 bytes left
	stw	%o4, [%o1-4]
.ci_medw31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .ci_medw7		! skip if 7 or fewer bytes left
	nop				!
.ci_medw15:
	lda	[%o0]%asi, %o4		! move a block of 8 bytes
	subcc	%o2, 8, %o2		! decrement length count
	stw	%o4, [%o1]
	add	%o0, 8, %o0		! increase src ptr by 8
	lda	[%o0-4]%asi, %o4
	add	%o1, 8, %o1		! increase dst ptr by 8
	bgu,pt	%ncc, .ci_medw15
	stw	%o4, [%o1-4]
.ci_medw7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bz,pt	%ncc, .ci_smallx	! exit if finished
	cmp	%o2, 4
	blt,pt	%ncc, .ci_small3x	! skip if less than 4 bytes left
	nop				!
	lda	[%o0]%asi, %o4		! move 4 bytes
	add	%o0, 4, %o0		! increase src ptr by 4
	add	%o1, 4, %o1		! increase dst ptr by 4
	subcc	%o2, 4, %o2		! decrease count by 4
	bnz	.ci_small3x
	stw	%o4, [%o1-4]
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
	retl
	mov	%g0, %o0

.ci_medhalf:
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .ci_medh31
	nop
.ci_medh32:				! load and store block of 32 bytes
	subcc	%o2, 32, %o2		! decrement length count

	lduha	[%o0]%asi, %o4		! move 32 bytes
	lduwa	[%o0+2]%asi, %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduha	[%o0+6]%asi, %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1]

	lduha	[%o0+8]%asi, %o4
	lduwa	[%o0+10]%asi, %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduha	[%o0+14]%asi, %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+8]

	lduha	[%o0+16]%asi, %o4
	lduwa	[%o0+18]%asi, %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduha	[%o0+22]%asi, %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+16]

	add	%o0, 32, %o0		! increase src ptr by 32
	add	%o1, 32, %o1		! increase dst ptr by 32

	lduha	[%o0-8]%asi, %o4
	lduwa	[%o0-6]%asi, %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	lduha	[%o0-2]%asi, %o4
	or	%o3, %o4, %o4
	bgu,pt	%ncc, .ci_medh32	! repeat if at least 32 bytes left
	stx	%o4, [%o1-8]

.ci_medh31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .ci_medh7		! skip if 7 or fewer bytes left
	nop				!
.ci_medh15:
	lduha	[%o0]%asi, %o4		! move 16 bytes
	subcc	%o2, 8, %o2		! decrement length count
	lduwa	[%o0+2]%asi, %o3
	sllx	%o4, 48, %o4
	sllx	%o3, 16, %o3
	or	%o4, %o3, %o3
	add	%o1, 8, %o1		! increase dst ptr by 8
	lduha	[%o0+6]%asi, %o4
	add	%o0, 8, %o0		! increase src ptr by 8
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .ci_medh15
	stx	%o4, [%o1-8]
.ci_medh7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bz,pt	%ncc, .ci_smallx	! exit if finished
	cmp	%o2, 4
	blt,pt	%ncc, .ci_small3x	! skip if less than 4 bytes left
	nop				!
	lduha	[%o0]%asi, %o4
	sll	%o4, 16, %o4
	lduha	[%o0+2]%asi, %o3
	or	%o3, %o4, %o4
	subcc	%o2, 4, %o2
	add	%o0, 4, %o0
	add	%o1, 4, %o1
	bnz	.ci_small3x
	stw	%o4, [%o1-4]
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
	retl
	mov	%g0, %o0

	.align 16
.ci_med_byte:
	bnz,pt	%ncc, .ci_medbh32a	! go to correct byte move
	subcc	%o2, 31, %o2		! adjust length to allow cc test
	ble,pt	%ncc, .ci_medb31
	nop
.ci_medb32:				! Alignment 1 or 5
	subcc	%o2, 32, %o2		! decrement length count

	lduba	[%o0]%asi, %o4		! load and store a block of 32 bytes
	sllx	%o4, 56, %o3
	lduha	[%o0+1]%asi, %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduwa	[%o0+3]%asi, %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0+7]%asi, %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1]

	lduba	[%o0+8]%asi, %o4
	sllx	%o4, 56, %o3
	lduha	[%o0+9]%asi, %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduwa	[%o0+11]%asi, %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0+15]%asi, %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+8]

	lduba	[%o0+16]%asi, %o4
	sllx	%o4, 56, %o3
	lduha	[%o0+17]%asi, %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduwa	[%o0+19]%asi, %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0+23]%asi, %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+16]

	add	%o0, 32, %o0		! increase src ptr by 32
	add	%o1, 32, %o1		! increase dst ptr by 32

	lduba	[%o0-8]%asi, %o4
	sllx	%o4, 56, %o3
	lduha	[%o0-7]%asi, %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduwa	[%o0-5]%asi, %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0-1]%asi, %o4
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .ci_medb32	! repeat if at least 32 bytes left
	stx	%o4, [%o1-8]

.ci_medb31:				! 31 or fewer bytes remaining
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .ci_medb7		! skip if 7 or fewer bytes left
	nop				!
.ci_medb15:

	lduba	[%o0]%asi, %o4		! load and store a block of 8 bytes
	subcc	%o2, 8, %o2		! decrement length count
	sllx	%o4, 56, %o3
	lduha	[%o0+1]%asi, %o4
	sllx	%o4, 40, %o4
	or	%o4, %o3, %o3
	lduwa	[%o0+3]%asi, %o4
	add	%o1, 8, %o1		! increase dst ptr by 16
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0+7]%asi, %o4
	add	%o0, 8, %o0		! increase src ptr by 16
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .ci_medb15
	stx	%o4, [%o1-8]
.ci_medb7:
	addcc	%o2, 7, %o2		! finish adjustment of remaining count
	bz,pt	%ncc, .ci_smallx	! exit if finished
	cmp	%o2, 4
	blt,pt	%ncc, .ci_small3x	! skip if less than 4 bytes left
	nop				!
	lduba	[%o0]%asi, %o4		! move 4 bytes
	sll	%o4, 24, %o3
	lduha	[%o0+1]%asi, %o4
	sll	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0+3]%asi, %o4
	or	%o4, %o3, %o4
	subcc	%o2, 4, %o2
	add	%o0, 4, %o0
	add	%o1, 4, %o1
	bnz	.ci_small3x
	stw	%o4, [%o1-4]
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
	retl
	mov	%g0, %o0

	.align 16
.ci_medbh32a:				! Alignment 3 or 7
	ble,pt	%ncc, .ci_medbh31
	nop
.ci_medbh32:				! Alignment 3 or 7
	subcc	%o2, 32, %o2		! decrement length count

	lduba	[%o0]%asi, %o4		! load and store a block of 32 bytes
	sllx	%o4, 56, %o3
	lduwa	[%o0+1]%asi, %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduha	[%o0+5]%asi, %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0+7]%asi, %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1]

	lduba	[%o0+8]%asi, %o4
	sllx	%o4, 56, %o3
	lduwa	[%o0+9]%asi, %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduha	[%o0+13]%asi, %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0+15]%asi, %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+8]

	lduba	[%o0+16]%asi, %o4
	sllx	%o4, 56, %o3
	lduwa	[%o0+17]%asi, %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduha	[%o0+21]%asi, %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0+23]%asi, %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1+16]

	add	%o0, 32, %o0		! increase src ptr by 32
	add	%o1, 32, %o1		! increase dst ptr by 32

	lduba	[%o0-8]%asi, %o4
	sllx	%o4, 56, %o3
	lduwa	[%o0-7]%asi, %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduha	[%o0-3]%asi, %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0-1]%asi, %o4
	or	%o4, %o3, %o4
	bgu,pt	%ncc, .ci_medbh32	! repeat if at least 32 bytes left
	stx	%o4, [%o1-8]

.ci_medbh31:
	addcc	%o2, 24, %o2		! adjust count to be off by 7
	ble,pt	%ncc, .ci_medb7		! skip if 7 or fewer bytes left
	nop				!
.ci_medbh15:
	lduba	[%o0]%asi, %o4		! load and store a block of 8 bytes
	sllx	%o4, 56, %o3
	lduwa	[%o0+1]%asi, %o4
	sllx	%o4, 24, %o4
	or	%o4, %o3, %o3
	lduha	[%o0+5]%asi, %o4
	sllx	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%o0+7]%asi, %o4
	or	%o4, %o3, %o4
	stx	%o4, [%o1]
	subcc	%o2, 8, %o2		! decrement length count
	add	%o1, 8, %o1		! increase dst ptr by 8
	add	%o0, 8, %o0		! increase src ptr by 8
	bgu,pt	%ncc, .ci_medbh15
	stx	%o4, [%o1-8]
	ba	.ci_medb7
	nop

/*
 * End of small copy in code (no window)
 * 
 */

/*
 * Long copy in code (using register window and fp regs)
 * 
 */

.ci_copy_more:
	sethi	%hi(copyio_fault), %o3
	or	%o3, %lo(copyio_fault), %o3
	membar	#Sync
	stn	%o3, [THREAD_REG + T_LOFAULT]
/*
 * Following code is for large copies. We know there is at
 * least FP_COPY bytes available. FP regs are used, so
 *  we save registers and fp regs before starting
 */
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	or	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT
	rd	%fprs, %g1		! check for unused fp
	! if fprs.fef == 0, set it.
	! Setting it when already set costs more than checking
	andcc	%g1, FPRS_FEF, %g1	! test FEF, fprs.du = fprs.dl = 0
	bz,pt	%ncc, .ci_fp_unused
	mov	ASI_USER, %asi
	BST_FP_TOSTACK(%o3)
	ba	.ci_fp_ready
.ci_fp_unused:
	prefetcha [%i0 + (1 * CACHE_LINE)]%asi, #one_read
	wr	%g0, FPRS_FEF, %fprs	! fprs.fef = 1
.ci_fp_ready:
	rd	%gsr, %l5		! save %gsr value
	andcc	%i1, 1, %o3		! is dest byte aligned
	bnz,pt	%ncc, .ci_big_d1
.ci_big_d1f:				! dest is now half word aligned
	andcc	%i1, 2, %o3
	bnz,pt	%ncc, .ci_big_d2
.ci_big_d2f:				! dest is now word aligned
	andcc	%i1, 4, %o3
	bnz,pt	%ncc, .ci_big_d4
.ci_big_d4f:				! dest is long word aligned
	andcc	%i0, 7, %o3		! is src long word aligned
	brnz,pt	%o3, .ci_big_unal8
	prefetcha [%i0 + (2 * CACHE_LINE)]%asi, #one_read
	! Src and dst are long word aligned
	! align dst to 64 byte boundary
	andcc	%i1, 0x3f, %o3		! %o3 == 0 means dst is 64 byte aligned
	brz,pn	%o3, .ci_al_to_64
	nop
	sub	%o3, 64, %o3		! %o3 has negative bytes to move
	add	%i2, %o3, %i2		! adjust remaining count
	andcc	%o3, 8, %o4		! odd long words to move?
	brz,pt	%o4, .ci_al_to_16
	nop
	add	%o3, 8, %o3
	ldxa	[%i0]%asi, %o4
	add	%i0, 8, %i0		! increment src ptr
	add	%i1, 8, %i1		! increment dst ptr
	stx	%o4, [%i1-8]
! Dest is aligned on 16 bytes, src 8 byte aligned
.ci_al_to_16:
	andcc	%o3, 0x30, %o4		! pair of long words to move?
	brz,pt	%o4, .ci_al_to_64
	nop
.ci_al_mv_16:
	add	%o3, 16, %o3
	ldxa	[%i0]%asi, %o4
	stx	%o4, [%i1]
	add	%i0, 16, %i0		! increment src ptr
	ldxa	[%i0-8]%asi, %o4
	stx	%o4, [%i1+8]
	andcc	%o3, 0x30, %o4
	brnz,pt	%o4, .ci_al_mv_16
	add	%i1, 16, %i1		! increment dst ptr
! Dest is aligned on 64 bytes, src 8 byte aligned
.ci_al_to_64:
	! Determine source alignment
	! to correct 8 byte offset
	andcc	%i0, 32, %o3
	brnz,pn	%o3, .ci_aln_1
	andcc	%i0, 16, %o3
	brnz,pn	%o3, .ci_aln_01
	andcc	%i0, 8, %o3
	brz,pn	%o3, .ci_aln_000
	prefetcha [%i0 + (3 * CACHE_LINE)]%asi, #one_read
	ba	.ci_aln_001
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
.ci_aln_01:
	brnz,pn	%o3, .ci_aln_011
	prefetcha [%i0 + (3 * CACHE_LINE)]%asi, #one_read
	ba	.ci_aln_010
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
.ci_aln_1:
	andcc	%i0, 16, %o3
	brnz,pn	%o3, .ci_aln_11
	andcc	%i0, 8, %o3
	brnz,pn	%o3, .ci_aln_101
	prefetcha [%i0 + (3 * CACHE_LINE)]%asi, #one_read
	ba	.ci_aln_100
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
.ci_aln_11:
	brz,pn	%o3, .ci_aln_110
	prefetcha [%i0 + (3 * CACHE_LINE)]%asi, #one_read

.ci_aln_111:
! Alignment off by 8 bytes
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	ldda	[%i0]%asi, %d0
	add	%i0, 8, %i0
	sub	%i2, 8, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.ci_aln_111_loop:
	ldda	[%i0]ASI_BLK_AIUS,%d16		! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d2
	fmovd	%d18, %d4
	fmovd	%d20, %d6
	fmovd	%d22, %d8
	fmovd	%d24, %d10
	fmovd	%d26, %d12
	fmovd	%d28, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d30, %d0
	bgt,pt	%ncc, .ci_aln_111_loop
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	ba	.ci_remain_stuff
	add	%i1, 8, %i1
	! END OF aln_111

.ci_aln_110:
! Alignment off by 16 bytes
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	ldda	[%i0]%asi, %d0
	ldda	[%i0+8]%asi, %d2
	add	%i0, 16, %i0
	sub	%i2, 16, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.ci_aln_110_loop:
	ldda	[%i0]ASI_BLK_AIUS,%d16		! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d4
	fmovd	%d18, %d6
	fmovd	%d20, %d8
	fmovd	%d22, %d10
	fmovd	%d24, %d12
	fmovd	%d26, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d28, %d0
	fmovd	%d30, %d2
	bgt,pt	%ncc, .ci_aln_110_loop
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	ba	.ci_remain_stuff
	add	%i1, 16, %i1
	! END OF aln_110

.ci_aln_101:
! Alignment off by 24 bytes
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	ldda	[%i0]%asi, %d0
	ldda	[%i0+8]%asi, %d2
	ldda	[%i0+16]%asi, %d4
	add	%i0, 24, %i0
	sub	%i2, 24, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.ci_aln_101_loop:
	ldda	[%i0]ASI_BLK_AIUS,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d6
	fmovd	%d18, %d8
	fmovd	%d20, %d10
	fmovd	%d22, %d12
	fmovd	%d24, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d26, %d0
	fmovd	%d28, %d2
	fmovd	%d30, %d4
	bgt,pt	%ncc, .ci_aln_101_loop
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	std	%d4, [%i1+16]
	ba	.ci_remain_stuff
	add	%i1, 24, %i1
	! END OF aln_101

.ci_aln_100:
! Alignment off by 32 bytes
	ldda	[%i0]%asi, %d0
	ldda	[%i0+8]%asi, %d2
	ldda	[%i0+16]%asi,%d4
	ldda	[%i0+24]%asi,%d6
	add	%i0, 32, %i0
	sub	%i2, 32, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.ci_aln_100_loop:
	ldda	[%i0]ASI_BLK_AIUS,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d8
	fmovd	%d18, %d10
	fmovd	%d20, %d12
	fmovd	%d22, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d24, %d0
	fmovd	%d26, %d2
	fmovd	%d28, %d4
	fmovd	%d30, %d6
	bgt,pt	%ncc, .ci_aln_100_loop
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	std	%d4, [%i1+16]
	std	%d6, [%i1+24]
	ba	.ci_remain_stuff
	add	%i1, 32, %i1
	! END OF aln_100

.ci_aln_011:
! Alignment off by 40 bytes
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	ldda	[%i0]%asi, %d0
	ldda	[%i0+8]%asi, %d2
	ldda	[%i0+16]%asi, %d4
	ldda	[%i0+24]%asi, %d6
	ldda	[%i0+32]%asi, %d8
	add	%i0, 40, %i0
	sub	%i2, 40, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.ci_aln_011_loop:
	ldda	[%i0]ASI_BLK_AIUS,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d10
	fmovd	%d18, %d12
	fmovd	%d20, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d22, %d0
	fmovd	%d24, %d2
	fmovd	%d26, %d4
	fmovd	%d28, %d6
	fmovd	%d30, %d8
	bgt,pt	%ncc, .ci_aln_011_loop
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	std	%d4, [%i1+16]
	std	%d6, [%i1+24]
	std	%d8, [%i1+32]
	ba	.ci_remain_stuff
	add	%i1, 40, %i1
	! END OF aln_011

.ci_aln_010:
! Alignment off by 48 bytes
	ldda	[%i0]%asi, %d0
	ldda	[%i0+8]%asi, %d2
	ldda	[%i0+16]%asi, %d4
	ldda	[%i0+24]%asi, %d6
	ldda	[%i0+32]%asi, %d8
	ldda	[%i0+40]%asi, %d10
	add	%i0, 48, %i0
	sub	%i2, 48, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.ci_aln_010_loop:
	ldda	[%i0]ASI_BLK_AIUS,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d12
	fmovd	%d18, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d20, %d0
	fmovd	%d22, %d2
	fmovd	%d24, %d4
	fmovd	%d26, %d6
	fmovd	%d28, %d8
	fmovd	%d30, %d10
	bgt,pt	%ncc, .ci_aln_010_loop
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	std	%d4, [%i1+16]
	std	%d6, [%i1+24]
	std	%d8, [%i1+32]
	std	%d10, [%i1+40]
	ba	.ci_remain_stuff
	add	%i1, 48, %i1
	! END OF aln_010

.ci_aln_001:
! Alignment off by 56 bytes
	ldda	[%i0]%asi, %d0
	ldda	[%i0+8]%asi, %d2
	ldda	[%i0+16]%asi, %d4
	ldda	[%i0+24]%asi, %d6
	ldda	[%i0+32]%asi, %d8
	ldda	[%i0+40]%asi, %d10
	ldda	[%i0+48]%asi, %d12
	add	%i0, 56, %i0
	sub	%i2, 56, %i2
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.ci_aln_001_loop:
	ldda	[%i0]ASI_BLK_AIUS,%d16	! block load
	subcc	%o3, 64, %o3
	fmovd	%d16, %d14
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	fmovd	%d18, %d0
	fmovd	%d20, %d2
	fmovd	%d22, %d4
	fmovd	%d24, %d6
	fmovd	%d26, %d8
	fmovd	%d28, %d10
	fmovd	%d30, %d12
	bgt,pt	%ncc, .ci_aln_001_loop
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	add	%i1, %i0, %i1

	std	%d0, [%i1]
	std	%d2, [%i1+8]
	std	%d4, [%i1+16]
	std	%d6, [%i1+24]
	std	%d8, [%i1+32]
	std	%d10, [%i1+40]
	std	%d12, [%i1+48]
	ba	.ci_remain_stuff
	add	%i1, 56, %i1
	! END OF aln_001

.ci_aln_000:
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	andn	%i2, 0x7f, %o3		! %o3 is multiple of 2*block size
	and	%i2, 0x7f, %i2		! residue bytes in %i2
	sub	%i1, %i0, %i1
.ci_aln_000_loop:
	ldda	[%i0]ASI_BLK_AIUS,%d0
	subcc	%o3, 64, %o3
	stxa	%g0,[%i0+%i1]ASI_STBI_P	! block initializing store
	stda	%d0,[%i0+%i1]ASI_BLK_P
	add	%i0, 64, %i0
	bgt,pt	%ncc, .ci_aln_000_loop
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read
	add	%i1, %i0, %i1

	! END OF aln_000

.ci_remain_stuff:
	subcc	%i2, 31, %i2		! adjust length to allow cc test
	ble,pt	%ncc, .ci_aln_31
	nop
.ci_aln_32:
	ldxa	[%i0]%asi, %o4		! move 32 bytes
	subcc	%i2, 32, %i2		! decrement length count by 32
	stx	%o4, [%i1]
	ldxa	[%i0+8]%asi, %o4
	stx	%o4, [%i1+8]
	ldxa	[%i0+16]%asi, %o4
	add	%i0, 32, %i0		! increase src ptr by 32
	stx	%o4, [%i1+16]
	ldxa	[%i0-8]%asi, %o4
	add	%i1, 32, %i1		! increase dst ptr by 32
	bgu,pt	%ncc, .ci_aln_32	! repeat if at least 32 bytes left
	stx	%o4, [%i1-8]
.ci_aln_31:
	addcc	%i2, 24, %i2		! adjust count to be off by 7
	ble,pt	%ncc, .ci_aln_7		! skip if 7 or fewer bytes left
	nop				!
.ci_aln_15:
	ldxa	[%i0]%asi, %o4		! move 8 bytes
	add	%i0, 8, %i0		! increase src ptr by 8
	subcc	%i2, 8, %i2		! decrease count by 8
	add	%i1, 8, %i1		! increase dst ptr by 8
	bgu,pt	%ncc, .ci_aln_15
	stx	%o4, [%i1-8]		!
.ci_aln_7:
	addcc	%i2, 7, %i2		! finish adjustment of remaining count
	bz,pt	%ncc, .ci_exit		! exit if finished
	cmp	%i2, 4
	blt,pt	%ncc, .ci_unaln3x	! skip if less than 4 bytes left
	nop				!
	lda	[%i0]%asi, %o4		! move 4 bytes
	add	%i0, 4, %i0		! increase src ptr by 4
	add	%i1, 4, %i1		! increase dst ptr by 4
	subcc	%i2, 4, %i2		! decrease count by 4
	bnz	.ci_unaln3x
	stw	%o4, [%i1-4]
	ba	.ci_exit
	nop

	! destination alignment code
.ci_big_d1:
	lduba	[%i0]%asi, %o4		! move a byte
	add	%i0, 1, %i0
	stb	%o4, [%i1]
	add	%i1, 1, %i1
	andcc	%i1, 2, %o3
	bz,pt	%ncc, .ci_big_d2f
	sub	%i2, 1, %i2
.ci_big_d2:				! dest is now at least half word aligned
	lduba	[%i0]%asi, %o4		! move a half-word (src align unknown)
	lduba	[%i0+1]%asi, %o3
	add	%i0, 2, %i0
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o4		! merge
	sth	%o4, [%i1]
	add	%i1, 2, %i1
	andcc	%i1, 4, %o3
	bz,pt	%ncc, .ci_big_d4f
	sub	%i2, 2, %i2
.ci_big_d4:				! dest is at least word aligned
	nop
	lduba	[%i0]%asi, %o4		! move a word (src align unknown)
	lduba	[%i0+1]%asi, %o3
	sll	%o4, 24, %o4		! position
	sll	%o3, 16, %o3		! position
	or	%o4, %o3, %o3		! merge
	lduba	[%i0+2]%asi, %o4
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o3		! merge
	lduba	[%i0+3]%asi, %o4
	or	%o4, %o3, %o4		! merge
	stw	%o4,[%i1]		! store four bytes
	add	%i0, 4, %i0		! adjust src by 4
	add	%i1, 4, %i1		! adjust dest by 4
	ba	.ci_big_d4f
	sub	%i2, 4, %i2		! adjust count by 4


	! Dst is on 8 byte boundary; src is not;
.ci_big_unal8:
	andcc	%i1, 0x3f, %o3		! is dst 64-byte block aligned?
	bz	%ncc, .ci_unalnsrc
	sub	%o3, 64, %o3		! %o3 will be multiple of 8
	neg	%o3			! bytes until dest is 64 byte aligned
	sub	%i2, %o3, %i2		! update cnt with bytes to be moved
	! Move bytes according to source alignment
	andcc	%i0, 0x1, %o4
	bnz	%ncc, .ci_unalnbyte	! check for byte alignment
	nop
	andcc	%i0, 2, %o4		! check for half word alignment
	bnz	%ncc, .ci_unalnhalf
	nop
	! Src is word aligned, move bytes until dest 64 byte aligned
.ci_unalnword:
	lda	[%i0]%asi, %o4		! load 4 bytes
	stw	%o4, [%i1]		! and store 4 bytes
	lda	[%i0+4]%asi, %o4	! load 4 bytes
	add	%i0, 8, %i0		! increase src ptr by 8
	stw	%o4, [%i1+4]		! and store 4 bytes
	subcc	%o3, 8, %o3		! decrease count by 8
	bnz	%ncc, .ci_unalnword
	add	%i1, 8, %i1		! increase dst ptr by 8
	ba	.ci_unalnsrc
	nop

	! Src is half-word aligned, move bytes until dest 64 byte aligned
.ci_unalnhalf:
	lduha	[%i0]%asi, %o4		! load 2 bytes
	sllx	%o4, 32, %i3		! shift left
	lduwa	[%i0+2]%asi, %o4
	or	%o4, %i3, %i3
	sllx	%i3, 16, %i3
	lduha	[%i0+6]%asi, %o4
	or	%o4, %i3, %i3
	stx	%i3, [%i1]
	add	%i0, 8, %i0
	subcc	%o3, 8, %o3
	bnz	%ncc, .ci_unalnhalf
	add	%i1, 8, %i1
	ba	.ci_unalnsrc
	nop

	! Src is Byte aligned, move bytes until dest 64 byte aligned
.ci_unalnbyte:
	sub	%i1, %i0, %i1		! share pointer advance
.ci_unalnbyte_loop:
	lduba	[%i0]%asi, %o4
	sllx	%o4, 56, %i3
	lduha	[%i0+1]%asi, %o4
	sllx	%o4, 40, %o4
	or	%o4, %i3, %i3
	lduha	[%i0+3]%asi, %o4
	sllx	%o4, 24, %o4
	or	%o4, %i3, %i3
	lduha	[%i0+5]%asi, %o4
	sllx	%o4, 8, %o4
	or	%o4, %i3, %i3
	lduba	[%i0+7]%asi, %o4
	or	%o4, %i3, %i3
	stx	%i3, [%i1+%i0]
	subcc	%o3, 8, %o3
	bnz	%ncc, .ci_unalnbyte_loop
	add	%i0, 8, %i0
	add	%i1,%i0, %i1		! restore pointer

	! Destination is now block (64 byte aligned), src is not 8 byte aligned
.ci_unalnsrc:
	andn	%i2, 0x3f, %i3		! %i3 is multiple of block size
	and	%i2, 0x3f, %i2		! residue bytes in %i2
	add	%i2, 64, %i2		! Insure we don't load beyond
	sub	%i3, 64, %i3		! end of source buffer

	andn	%i0, 0x3f, %o4		! %o4 has block aligned src address
	prefetcha [%o4 + (3 * CACHE_LINE)]%asi, #one_read
	alignaddr %i0, %g0, %g0		! generate %gsr
	add	%i0, %i3, %i0		! advance %i0 to after blocks
	!
	! Determine source alignment to correct 8 byte offset
	andcc	%i0, 0x20, %o3
	brnz,pn	%o3, .ci_unaln_1
	andcc	%i0, 0x10, %o3
	brnz,pn	%o3, .ci_unaln_01
	andcc	%i0, 0x08, %o3
	brz,a	%o3, .ci_unaln_000
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read
	ba	.ci_unaln_001
	nop
.ci_unaln_01:
	brnz,a	%o3, .ci_unaln_011
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read
	ba	.ci_unaln_010
	nop
.ci_unaln_1:
	brnz,pn	%o3, .ci_unaln_11
	andcc	%i0, 0x08, %o3
	brnz,a	%o3, .ci_unaln_101
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read
	ba	.ci_unaln_100
	nop
.ci_unaln_11:
	brz,pn	%o3, .ci_unaln_110
	prefetcha [%i0 + (4 * CACHE_LINE)]%asi, #one_read

.ci_unaln_111:
	ldda	[%o4+56]%asi, %d14
.ci_unaln_111_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_AIUS, %d16
	faligndata %d14, %d16, %d48
	faligndata %d16, %d18, %d50
	faligndata %d18, %d20, %d52
	faligndata %d20, %d22, %d54
	faligndata %d22, %d24, %d56
	faligndata %d24, %d26, %d58
	faligndata %d26, %d28, %d60
	faligndata %d28, %d30, %d62
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .ci_unaln_111_loop
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read
	ba	.ci_unaln_done
	nop

.ci_unaln_110:
	ldda	[%o4+48]%asi, %d12
	ldda	[%o4+56]%asi, %d14
.ci_unaln_110_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_AIUS, %d16
	faligndata %d12, %d14, %d48
	faligndata %d14, %d16, %d50
	faligndata %d16, %d18, %d52
	faligndata %d18, %d20, %d54
	faligndata %d20, %d22, %d56
	faligndata %d22, %d24, %d58
	faligndata %d24, %d26, %d60
	faligndata %d26, %d28, %d62
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .ci_unaln_110_loop
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read
	ba	.ci_unaln_done
	nop

.ci_unaln_101:
	ldda	[%o4+40]%asi, %d10
	ldda	[%o4+48]%asi, %d12
	ldda	[%o4+56]%asi, %d14
.ci_unaln_101_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_AIUS, %d16
	faligndata %d10, %d12, %d48
	faligndata %d12, %d14, %d50
	faligndata %d14, %d16, %d52
	faligndata %d16, %d18, %d54
	faligndata %d18, %d20, %d56
	faligndata %d20, %d22, %d58
	faligndata %d22, %d24, %d60
	faligndata %d24, %d26, %d62
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .ci_unaln_101_loop
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read
	ba	.ci_unaln_done
	nop

.ci_unaln_100:
	ldda	[%o4+32]%asi, %d8
	ldda	[%o4+40]%asi, %d10
	ldda	[%o4+48]%asi, %d12
	ldda	[%o4+56]%asi, %d14
.ci_unaln_100_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_AIUS, %d16
	faligndata %d8, %d10, %d48
	faligndata %d10, %d12, %d50
	faligndata %d12, %d14, %d52
	faligndata %d14, %d16, %d54
	faligndata %d16, %d18, %d56
	faligndata %d18, %d20, %d58
	faligndata %d20, %d22, %d60
	faligndata %d22, %d24, %d62
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .ci_unaln_100_loop
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read
	ba	.ci_unaln_done
	nop

.ci_unaln_011:
	ldda	[%o4+24]%asi, %d6
	ldda	[%o4+32]%asi, %d8
	ldda	[%o4+40]%asi, %d10
	ldda	[%o4+48]%asi, %d12
	ldda	[%o4+56]%asi, %d14
.ci_unaln_011_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_AIUS, %d16
	faligndata %d6, %d8, %d48
	faligndata %d8, %d10, %d50
	faligndata %d10, %d12, %d52
	faligndata %d12, %d14, %d54
	faligndata %d14, %d16, %d56
	faligndata %d16, %d18, %d58
	faligndata %d18, %d20, %d60
	faligndata %d20, %d22, %d62
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .ci_unaln_011_loop
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read
	ba	.ci_unaln_done
	nop

.ci_unaln_010:
	ldda	[%o4+16]%asi, %d4
	ldda	[%o4+24]%asi, %d6
	ldda	[%o4+32]%asi, %d8
	ldda	[%o4+40]%asi, %d10
	ldda	[%o4+48]%asi, %d12
	ldda	[%o4+56]%asi, %d14
.ci_unaln_010_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_AIUS, %d16
	faligndata %d4, %d6, %d48
	faligndata %d6, %d8, %d50
	faligndata %d8, %d10, %d52
	faligndata %d10, %d12, %d54
	faligndata %d12, %d14, %d56
	faligndata %d14, %d16, %d58
	faligndata %d16, %d18, %d60
	faligndata %d18, %d20, %d62
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .ci_unaln_010_loop
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read
	ba	.ci_unaln_done
	nop

.ci_unaln_001:
	ldda	[%o4+8]%asi, %d2
	ldda	[%o4+16]%asi, %d4
	ldda	[%o4+24]%asi, %d6
	ldda	[%o4+32]%asi, %d8
	ldda	[%o4+40]%asi, %d10
	ldda	[%o4+48]%asi, %d12
	ldda	[%o4+56]%asi, %d14
.ci_unaln_001_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_AIUS, %d16
	faligndata %d2, %d4, %d48
	faligndata %d4, %d6, %d50
	faligndata %d6, %d8, %d52
	faligndata %d8, %d10, %d54
	faligndata %d10, %d12, %d56
	faligndata %d12, %d14, %d58
	faligndata %d14, %d16, %d60
	faligndata %d16, %d18, %d62
	fmovd	%d18, %d2
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .ci_unaln_001_loop
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read
	ba	.ci_unaln_done
	nop

.ci_unaln_000:
	ldda	[%o4]ASI_BLK_AIUS, %d0
.ci_unaln_000_loop:
	add	%o4, 64, %o4
	ldda	[%o4]ASI_BLK_AIUS, %d16
	faligndata %d0, %d2, %d48
	faligndata %d2, %d4, %d50
	faligndata %d4, %d6, %d52
	faligndata %d6, %d8, %d54
	faligndata %d8, %d10, %d56
	faligndata %d10, %d12, %d58
	faligndata %d12, %d14, %d60
	faligndata %d14, %d16, %d62
	fmovd	%d16, %d0
	fmovd	%d18, %d2
	fmovd	%d20, %d4
	fmovd	%d22, %d6
	fmovd	%d24, %d8
	fmovd	%d26, %d10
	fmovd	%d28, %d12
	fmovd	%d30, %d14
	stda	%d48, [%i1]ASI_BLK_P
	subcc	%i3, 64, %i3
	add	%i1, 64, %i1
	bgu,pt	%ncc, .ci_unaln_000_loop
	prefetcha [%o4 + (4 * CACHE_LINE)]%asi, #one_read

.ci_unaln_done:
	! Handle trailing bytes, 64 to 127
	! Dest long word aligned, Src not long word aligned
	cmp	%i2, 15
	bleu	%ncc, .ci_unaln_short

	andn	%i2, 0x7, %i3		! %i3 is multiple of 8
	and	%i2, 0x7, %i2		! residue bytes in %i2
	add	%i2, 8, %i2
	sub	%i3, 8, %i3		! insure we don't load past end of src
	andn	%i0, 0x7, %o4		! %o4 has long word aligned src address
	add	%i0, %i3, %i0		! advance %i0 to after multiple of 8
	ldda	[%o4]%asi, %d0		! fetch partial word
.ci_unaln_by8:
	ldda	[%o4+8]%asi, %d2
	add	%o4, 8, %o4
	faligndata %d0, %d2, %d16
	subcc	%i3, 8, %i3
	std	%d16, [%i1]
	fmovd	%d2, %d0
	bgu,pt	%ncc, .ci_unaln_by8
	add	%i1, 8, %i1

.ci_unaln_short:
	cmp	%i2, 8
	blt,pt	%ncc, .ci_unalnfin
	nop
	lduba	[%i0]%asi, %o4
	sll	%o4, 24, %o3
	lduba	[%i0+1]%asi, %o4
	sll	%o4, 16, %o4
	or	%o4, %o3, %o3
	lduba	[%i0+2]%asi, %o4
	sll	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%i0+3]%asi, %o4
	or	%o4, %o3, %o3
	stw	%o3, [%i1]
	lduba	[%i0+4]%asi, %o4
	sll	%o4, 24, %o3
	lduba	[%i0+5]%asi, %o4
	sll	%o4, 16, %o4
	or	%o4, %o3, %o3
	lduba	[%i0+6]%asi, %o4
	sll	%o4, 8, %o4
	or	%o4, %o3, %o3
	lduba	[%i0+7]%asi, %o4
	or	%o4, %o3, %o3
	stw	%o3, [%i1+4]
	add	%i0, 8, %i0
	add	%i1, 8, %i1
	sub	%i2, 8, %i2
.ci_unalnfin:
	cmp	%i2, 4
	blt,pt	%ncc, .ci_unalnz
	tst	%i2
	lduba	[%i0]%asi, %o3		! read byte
	subcc	%i2, 4, %i2		! reduce count by 4
	sll	%o3, 24, %o3		! position
	lduba	[%i0+1]%asi, %o4
	sll	%o4, 16, %o4		! position
	or	%o4, %o3, %o3		! merge
	lduba	[%i0+2]%asi, %o4
	sll	%o4, 8, %o4		! position
	or	%o4, %o3, %o3		! merge
	add	%i1, 4, %i1		! advance dst by 4
	lduba	[%i0+3]%asi, %o4
	add	%i0, 4, %i0		! advance src by 4
	or	%o4, %o3, %o4		! merge
	bnz,pt	%ncc, .ci_unaln3x
	stw	%o4, [%i1-4]
	ba	.ci_exit
	nop
.ci_unalnz:
	bz,pt	%ncc, .ci_exit
	wr	%l5, %g0, %gsr		! restore %gsr
.ci_unaln3x:				! Exactly 1, 2, or 3 bytes remain
	subcc	%i2, 1, %i2		! reduce count for cc test
	lduba	[%i0]%asi, %o4		! load one byte
	bz,pt	%ncc, .ci_exit
	stb	%o4, [%i1]		! store one byte
	lduba	[%i0+1]%asi, %o4	! load second byte
	subcc	%i2, 1, %i2
	bz,pt	%ncc, .ci_exit
	stb	%o4, [%i1+1]		! store second byte
	lduba	[%i0+2]%asi, %o4	! load third byte
	stb	%o4, [%i1+2]		! store third byte
.ci_exit:
	brnz	%g1, .ci_fp_restore
	nop
	FZERO
	wr	%g1, %g0, %fprs
	ba,pt	%ncc, .ci_ex2
	membar	#Sync
.ci_fp_restore:
	BLD_FP_FROMSTACK(%o4)
.ci_ex2:
	andn	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT] ! restore old t_lofault
	ret
	restore %g0, 0, %o0

.copyin_err:
	ldn	[THREAD_REG + T_COPYOPS], %o4
	brz	%o4, 2f
	nop
	ldn	[%o4 + CP_COPYIN], %g2
	jmp	%g2
	nop
2:
	retl
	mov	-1, %o0

#else	/* NIAGARA_IMPL */
.do_copyin:
	!
	! Check the length and bail if zero.
	!
	tst	%o2
	bnz,pt	%ncc, 1f
	nop
	retl
	clr	%o0
1:
	sethi	%hi(copyio_fault), %o4
	or	%o4, %lo(copyio_fault), %o4
	sethi	%hi(copyio_fault_nowindow), %o3
	ldn	[THREAD_REG + T_LOFAULT], SAVED_LOFAULT
	or	%o3, %lo(copyio_fault_nowindow), %o3
	membar	#Sync
	stn	%o3, [THREAD_REG + T_LOFAULT]

	mov	%o0, SAVE_SRC
	mov	%o1, SAVE_DST
	mov	%o2, SAVE_COUNT

	!
	! Check to see if we're more than SMALL_LIMIT.
	!
	subcc	%o2, SMALL_LIMIT, %o3
	bgu,a,pt %ncc, .dci_ns
	or	%o0, %o1, %o3
	!
	! What was previously ".small_copyin"
	!
.dcibcp:
	sub	%g0, %o2, %o3		! setup for copy loop
	add	%o0, %o2, %o0
	add	%o1, %o2, %o1
	ba,pt	%ncc, .dcicl
	lduba	[%o0 + %o3]ASI_USER, %o4
	!
	! %o0 and %o1 point at the end and remain pointing at the end
	! of their buffers. We pull things out by adding %o3 (which is
	! the negation of the length) to the buffer end which gives us
	! the curent location in the buffers. By incrementing %o3 we walk
	! through both buffers without having to bump each buffer's
	! pointer. A very fast 4 instruction loop.
	!
	.align 16
.dcicl:
	stb	%o4, [%o1 + %o3]
	inccc	%o3
	bl,a,pt %ncc, .dcicl
	lduba	[%o0 + %o3]ASI_USER, %o4
	!
	! We're done. Go home.
	!	
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]
	retl
	clr	%o0
	!
	! Try aligned copies from here.
	!
.dci_ns:
	!
	! See if we're single byte aligned. If we are, check the
	! limit for single byte copies. If we're smaller, or equal,
	! bounce to the byte for byte copy loop. Otherwise do it in
	! HW (if enabled).
	!
	btst	1, %o3
	bz,a,pt	%icc, .dcih8
	btst	7, %o3
	!
	! We're single byte aligned.
	!
	sethi	%hi(hw_copy_limit_1), %o3
	ld	[%o3 + %lo(hw_copy_limit_1)], %o3
	!
	! Is HW copy on? If not do everything byte for byte.
	!
	tst	%o3
	bz,pn	%icc, .dcibcp
	subcc	%o3, %o2, %o3
	!
	! Are we bigger than the HW limit? If not
	! go to byte for byte.
	!
	bge,pt	%ncc, .dcibcp
	nop
	!
	! We're big enough and copy is on. Do it with HW.
	!
	ba,pt	%ncc, .big_copyin
	nop
.dcih8:
	!
	! 8 byte aligned?
	!
	bnz,a	%ncc, .dcih4
	btst	3, %o3
	!
	! We're eight byte aligned.
	!
	sethi	%hi(hw_copy_limit_8), %o3
	ld	[%o3 + %lo(hw_copy_limit_8)], %o3
	!
	! Is HW assist on? If not, do it with the aligned copy.
	!
	tst	%o3
	bz,pn	%icc, .dcis8
	subcc	%o3, %o2, %o3
	bge	%ncc, .dcis8
	nop
	ba,pt	%ncc, .big_copyin
	nop
.dcis8:
	!
	! Housekeeping for copy loops. Uses same idea as in the byte for
	! byte copy loop above.
	!
	add	%o0, %o2, %o0
	add	%o1, %o2, %o1
	sub	%g0, %o2, %o3
	ba,pt	%ncc, .didebc
	srl	%o2, 3, %o2		! Number of 8 byte chunks to copy
	!
	! 4 byte aligned?
	!
.dcih4:
	bnz	%ncc, .dcih2
	sethi	%hi(hw_copy_limit_4), %o3
	ld	[%o3 + %lo(hw_copy_limit_4)], %o3
	!
	! Is HW assist on? If not, do it with the aligned copy.
	!
	tst	%o3
	bz,pn	%icc, .dcis4
	subcc	%o3, %o2, %o3
	!
	! We're negative if our size is less than or equal to hw_copy_limit_4.
	!
	bge	%ncc, .dcis4
	nop
	ba,pt	%ncc, .big_copyin
	nop
.dcis4:
	!
	! Housekeeping for copy loops. Uses same idea as in the byte
	! for byte copy loop above.
	!
	add	%o0, %o2, %o0
	add	%o1, %o2, %o1
	sub	%g0, %o2, %o3
	ba,pt	%ncc, .didfbc
	srl	%o2, 2, %o2		! Number of 4 byte chunks to copy
.dcih2:
	!
	! We're two byte aligned. Check for "smallness"
	! done in delay at .dcih4
	!
	bleu,pt	%ncc, .dcis2
	sethi	%hi(hw_copy_limit_2), %o3
	ld	[%o3 + %lo(hw_copy_limit_2)], %o3
	!
	! Is HW assist on? If not, do it with the aligned copy.
	!
	tst	%o3
	bz,pn	%icc, .dcis2
	subcc	%o3, %o2, %o3
	!
	! Are we larger than the HW limit?
	!
	bge	%ncc, .dcis2
	nop
	!
	! HW assist is on and we're large enough to use it.
	!
	ba,pt	%ncc, .big_copyin
	nop
	!
	! Housekeeping for copy loops. Uses same idea as in the byte
	! for byte copy loop above.
	!
.dcis2:
	add	%o0, %o2, %o0
	add	%o1, %o2, %o1
	sub	%g0, %o2, %o3
	ba,pt	%ncc, .didtbc
	srl	%o2, 1, %o2		! Number of 2 byte chunks to copy
	!
.small_copyin:
	!
	! Why are we doing this AGAIN? There are certain conditions in
	! big copyin that will cause us to forgo the HW assisted copys
	! and bounce back to a non-hw assisted copy. This dispatches
	! those copies. Note that we branch around this in the main line
	! code.
	!
	! We make no check for limits or HW enablement here. We've
	! already been told that we're a poster child so just go off
	! and do it.
	!
	or	%o0, %o1, %o3
	btst	1, %o3
	bnz	%icc, .dcibcp		! Most likely
	btst	7, %o3
	bz	%icc, .dcis8
	btst	3, %o3
	bz	%icc, .dcis4
	nop
	ba,pt	%ncc, .dcis2
	nop
	!
	! Eight byte aligned copies. A steal from the original .small_copyin
	! with modifications. %o2 is number of 8 byte chunks to copy. When
	! done, we examine %o3. If this is < 0, we have 1 - 7 bytes more
	! to copy.
	!
	.align 32
.didebc:
	ldxa	[%o0 + %o3]ASI_USER, %o4
	deccc	%o2
	stx	%o4, [%o1 + %o3]
	bg,pt	%ncc, .didebc
	addcc	%o3, 8, %o3
	!
	! End of copy loop. Most 8 byte aligned copies end here.
	!
	bz,pt	%ncc, .dcifh
	nop
	!
	! Something is left. Do it byte for byte.
	!
	ba,pt	%ncc, .dcicl
	lduba	[%o0 + %o3]ASI_USER, %o4
	!
	! 4 byte copy loop. %o2 is number of 4 byte chunks to copy.
	!
	.align 32
.didfbc:
	lduwa	[%o0 + %o3]ASI_USER, %o4
	deccc	%o2
	st	%o4, [%o1 + %o3]
	bg,pt	%ncc, .didfbc
	addcc	%o3, 4, %o3
	!
	! End of copy loop. Most 4 byte aligned copies end here.
	!
	bz,pt	%ncc, .dcifh
	nop
	!
	! Something is left. Do it byte for byte.
	!
	ba,pt	%ncc, .dcicl
	lduba	[%o0 + %o3]ASI_USER, %o4
	!
	! 2 byte aligned copy loop. %o2 is number of 2 byte chunks to
	! copy.
	!
	.align 32
.didtbc:
	lduha	[%o0 + %o3]ASI_USER, %o4
	deccc	%o2
	sth	%o4, [%o1 + %o3]
	bg,pt	%ncc, .didtbc
	addcc	%o3, 2, %o3
	!
	! End of copy loop. Most 2 byte aligned copies end here.
	!
	bz,pt	%ncc, .dcifh
	nop
	!
	! Deal with the last byte
	!
	lduba	[%o0 + %o3]ASI_USER, %o4
	stb	%o4, [%o1 + %o3]
.dcifh:
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT] ! restore old t_lofault
	retl
	clr	%o0

.big_copyin:
	! We're going off to do a block copy.
	! Switch fault hendlers and grab a window. We
	! don't do a membar #Sync since we've done only
	! kernel data to this point.
	stn	%o4, [THREAD_REG + T_LOFAULT]

	! Copy in that reach here are larger than 256 bytes. The
	! hw_copy_limit_1 is set to 256. Never set this limit less
	! 128 bytes.
	save	%sp, -SA(MINFRAME), %sp
.do_blockcopyin:

	! Swap src/dst since the code below is memcpy code
	! and memcpy/bcopy have different calling sequences
	mov	%i1, %i5
	mov	%i0, %i1
	mov	%i5, %i0

	! Block (64 bytes) align the destination.
	andcc	%i0, 0x3f, %i3		! is dst block aligned
	bz	%ncc, copyin_blalign	! dst already block aligned
	sub	%i3, 0x40, %i3
	neg	%i3			! bytes till dst 64 bytes aligned
	sub	%i2, %i3, %i2		! update i2 with new count

	! Based on source and destination alignment do
	! either 8 bytes, 4 bytes, 2 bytes or byte copy.

	! Is dst & src 8B aligned
	or	%i0, %i1, %o2
	andcc	%o2, 0x7, %g0
	bz	%ncc, .ci_alewdcp
	nop

	! Is dst & src 4B aligned
	andcc	%o2, 0x3, %g0
	bz	%ncc, .ci_alwdcp
	nop

	! Is dst & src 2B aligned
	andcc	%o2, 0x1, %g0
	bz	%ncc, .ci_alhlfwdcp
	nop

	! 1B aligned
1:	lduba	[%i1]ASI_USER, %o2
	stb	%o2, [%i0]
	inc	%i1
	deccc	%i3
	bgu,pt	%ncc, 1b
	inc	%i0

	ba	copyin_blalign
	nop

	! dst & src 4B aligned
.ci_alwdcp:
	lda	[%i1]ASI_USER, %o2
	st	%o2, [%i0]
	add	%i1, 0x4, %i1
	subcc	%i3, 0x4, %i3
	bgu,pt	%ncc, .ci_alwdcp
	add	%i0, 0x4, %i0

	ba	copyin_blalign
	nop

	! dst & src 2B aligned
.ci_alhlfwdcp:
	lduha	[%i1]ASI_USER, %o2
	stuh	%o2, [%i0]
	add	%i1, 0x2, %i1
	subcc	%i3, 0x2, %i3
	bgu,pt	%ncc, .ci_alhlfwdcp
	add	%i0, 0x2, %i0

	ba	copyin_blalign
	nop

	! dst & src 8B aligned
.ci_alewdcp:
	ldxa	[%i1]ASI_USER, %o2
	stx	%o2, [%i0]
	add	%i1, 0x8, %i1
	subcc	%i3, 0x8, %i3
	bgu,pt	%ncc, .ci_alewdcp
	add	%i0, 0x8, %i0

copyin_blalign:
	andn	%i2, 0x3f, %i3		! %i3 count is multiple of block size
	sub	%i2, %i3, %i2		! Residue bytes in %i2

	mov	ASI_BLK_INIT_ST_QUAD_LDD_P, %asi

	andcc	%i1, 0xf, %o2		! is src quadword aligned
	bz,pn	%xcc, .ci_blkcpy	! src offset in %o2 (last 4-bits)
	nop
	cmp	%o2, 0x8
	bg	.ci_upper_double
	nop
	bl	.ci_lower_double
	nop

	! Falls through when source offset is equal to 8 i.e.
	! source is double word aligned.
	! In this case no shift/merge of data is required

	sub	%i1, %o2, %i1		! align the src at 16 bytes.
	andn	%i1, 0x3f, %l0		! %l0 has block aligned source
	prefetcha [%l0]ASI_USER, #one_read
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l2
	add	%l0, 0x40, %l0
.ci_loop0:
	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l4

	prefetcha [%l0]ASI_USER, #one_read

	stxa	%l3, [%i0+0x0]%asi
	stxa	%l4, [%i0+0x8]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l2

	stxa	%l5, [%i0+0x10]%asi
	stxa	%l2, [%i0+0x18]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l4

	stxa	%l3, [%i0+0x20]%asi
	stxa	%l4, [%i0+0x28]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l2

	stxa	%l5, [%i0+0x30]%asi
	stxa	%l2, [%i0+0x38]%asi

	add	%l0, 0x40, %l0
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, .ci_loop0
	add	%i0, 0x40, %i0
	ba	.ci_blkdone
	add	%i1, %o2, %i1		! increment the source by src offset
					! the src offset was stored in %o2

.ci_lower_double:

	sub	%i1, %o2, %i1		! align the src at 16 bytes.
	sll	%o2, 3, %o0		! %o0 left shift
	mov	0x40, %o1
	sub	%o1, %o0, %o1		! %o1 right shift = (64 - left shift)
	andn	%i1, 0x3f, %l0		! %l0 has block aligned source
	prefetcha [%l0]ASI_USER, #one_read
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l2	! partial data in %l2
							! and %l3 has complete
							! data
	add	%l0, 0x40, %l0
.ci_loop1:
	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l4	! %l4 has partial data
							! for this read.
	ALIGN_DATA(%l2, %l3, %l4, %o0, %o1, %l6)	! merge %l2, %l3 and %l4
							! into %l2 and %l3

	prefetcha [%l0]ASI_USER, #one_read

	stxa	%l2, [%i0+0x0]%asi
	stxa	%l3, [%i0+0x8]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l2
	ALIGN_DATA(%l4, %l5, %l2, %o0, %o1, %l6)	! merge %l2 with %l5 and
							! %l4 from previous read
							! into %l4 and %l5
	stxa	%l4, [%i0+0x10]%asi
	stxa	%l5, [%i0+0x18]%asi

	! Repeat the same for next 32 bytes.

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l4
	ALIGN_DATA(%l2, %l3, %l4, %o0, %o1, %l6)

	stxa	%l2, [%i0+0x20]%asi
	stxa	%l3, [%i0+0x28]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l2
	ALIGN_DATA(%l4, %l5, %l2, %o0, %o1, %l6)

	stxa	%l4, [%i0+0x30]%asi
	stxa	%l5, [%i0+0x38]%asi

	add	%l0, 0x40, %l0
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, .ci_loop1
	add	%i0, 0x40, %i0
	ba	.ci_blkdone
	add	%i1, %o2, %i1		! increment the source by src offset
					! the src offset was stored in %o2

.ci_upper_double:

	sub	%i1, %o2, %i1		! align the src at 16 bytes.
	sub	%o2, 0x8, %o0
	sll	%o0, 3, %o0		! %o0 left shift
	mov	0x40, %o1
	sub	%o1, %o0, %o1		! %o1 right shift = (64 - left shift)
	andn	%i1, 0x3f, %l0		! %l0 has block aligned source
	prefetcha [%l0]ASI_USER, #one_read
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l2	! partial data in %l3
							! for this read and
							! no data in %l2
	add	%l0, 0x40, %l0
.ci_loop2:
	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l4	! %l4 has complete data
							! and %l5 has partial
	ALIGN_DATA(%l3, %l4, %l5, %o0, %o1, %l6)	! merge %l3, %l4 and %l5
							! into %l3 and %l4
	prefetcha [%l0]ASI_USER, #one_read

	stxa	%l3, [%i0+0x0]%asi
	stxa	%l4, [%i0+0x8]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l2
	ALIGN_DATA(%l5, %l2, %l3, %o0, %o1, %l6)	! merge %l2 and %l3 with
							! %l5 from previous read
							! into %l5 and %l2

	stxa	%l5, [%i0+0x10]%asi
	stxa	%l2, [%i0+0x18]%asi

	! Repeat the same for next 32 bytes.

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l4
	ALIGN_DATA(%l3, %l4, %l5, %o0, %o1, %l6)

	stxa	%l3, [%i0+0x20]%asi
	stxa	%l4, [%i0+0x28]%asi

	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l2
	ALIGN_DATA(%l5, %l2, %l3, %o0, %o1, %l6)

	stxa	%l5, [%i0+0x30]%asi
	stxa	%l2, [%i0+0x38]%asi

	add	%l0, 0x40, %l0
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, .ci_loop2
	add	%i0, 0x40, %i0
	ba	.ci_blkdone
	add	%i1, %o2, %i1		! increment the source by src offset
					! the src offset was stored in %o2


	! Do fast copy using ASI_BLK_INIT_ST_QUAD_LDD_P
.ci_blkcpy:

	andn	%i1, 0x3f, %o0		! %o0 has block aligned source
	prefetcha [%o0]ASI_USER, #one_read
	add	%o0, 0x40, %o0
1:
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l0
	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l2
	add	%i1, 0x10, %i1

	prefetcha [%o0]ASI_USER, #one_read

	stxa	%l0, [%i0+0x0]%asi

	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l4
	add	%i1, 0x10, %i1
	ldda	[%i1]ASI_BLK_INIT_QUAD_LDD_AIUS, %l6
	add	%i1, 0x10, %i1

	stxa	%l1, [%i0+0x8]%asi
	stxa	%l2, [%i0+0x10]%asi
	stxa	%l3, [%i0+0x18]%asi
	stxa	%l4, [%i0+0x20]%asi
	stxa	%l5, [%i0+0x28]%asi
	stxa	%l6, [%i0+0x30]%asi
	stxa	%l7, [%i0+0x38]%asi

	add	%o0, 0x40, %o0
	subcc	%i3, 0x40, %i3
	bgu,pt	%xcc, 1b
	add	%i0, 0x40, %i0

.ci_blkdone:
	membar	#Sync

	brz,pt	%i2, .copyin_exit
	nop

	! Handle trailing bytes
	cmp	%i2, 0x8
	blu,pt	%ncc, .ci_residue
	nop

	! Can we do some 8B ops
	or	%i1, %i0, %o2
	andcc	%o2, 0x7, %g0
	bnz	%ncc, .ci_last4
	nop

	! Do 8byte ops as long as possible
.ci_last8:
	ldxa	[%i1]ASI_USER, %o2
	stx	%o2, [%i0]
	add	%i1, 0x8, %i1
	sub	%i2, 0x8, %i2
	cmp	%i2, 0x8
	bgu,pt	%ncc, .ci_last8
	add	%i0, 0x8, %i0

	brz,pt	%i2, .copyin_exit
	nop

	ba	.ci_residue
	nop

.ci_last4:
	! Can we do 4B ops
	andcc	%o2, 0x3, %g0
	bnz	%ncc, .ci_last2
	nop
1:
	lda	[%i1]ASI_USER, %o2
	st	%o2, [%i0]
	add	%i1, 0x4, %i1
	sub	%i2, 0x4, %i2
	cmp	%i2, 0x4
	bgu,pt	%ncc, 1b
	add	%i0, 0x4, %i0

	brz,pt	%i2, .copyin_exit
	nop

	ba	.ci_residue
	nop

.ci_last2:
	! Can we do 2B ops
	andcc	%o2, 0x1, %g0
	bnz	%ncc, .ci_residue
	nop

1:
	lduha	[%i1]ASI_USER, %o2
	stuh	%o2, [%i0]
	add	%i1, 0x2, %i1
	sub	%i2, 0x2, %i2
	cmp	%i2, 0x2
	bgu,pt	%ncc, 1b
	add	%i0, 0x2, %i0

	brz,pt	%i2, .copyin_exit
	nop

	! Copy the residue as byte copy
.ci_residue:
	lduba	[%i1]ASI_USER, %i4
	stb	%i4, [%i0]
	inc	%i1
	deccc	%i2
	bgu,pt	%xcc, .ci_residue
	inc	%i0

.copyin_exit:
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	ret
	restore	%g0, 0, %o0
.copyin_err:
	ldn	[THREAD_REG + T_COPYOPS], %o4
	brz	%o4, 2f
	nop
	ldn	[%o4 + CP_COPYIN], %g2
	jmp	%g2
	nop
2:
	retl
	mov	-1, %o0
#endif	/* NIAGARA_IMPL */
	SET_SIZE(copyin)

	ENTRY(xcopyin)
	sethi	%hi(.xcopyin_err), REAL_LOFAULT
	b	.do_copyin
	or	REAL_LOFAULT, %lo(.xcopyin_err), REAL_LOFAULT
.xcopyin_err:
	ldn	[THREAD_REG + T_COPYOPS], %o4
	brz	%o4, 2f
	nop
	ldn	[%o4 + CP_XCOPYIN], %g2
	jmp	%g2
	nop
2:
	retl
	mov	%g1, %o0
	SET_SIZE(xcopyin)

	ENTRY(xcopyin_little)
	sethi	%hi(.little_err), %o4
	ldn	[THREAD_REG + T_LOFAULT], %o5
	or	%o4, %lo(.little_err), %o4
	membar	#Sync				! sync error barrier
	stn	%o4, [THREAD_REG + T_LOFAULT]	

	subcc	%g0, %o2, %o3
	add	%o0, %o2, %o0
	bz,pn	%ncc, 2f		! check for zero bytes
	sub	%o2, 1, %o4
	add	%o0, %o4, %o0		! start w/last byte	
	add	%o1, %o2, %o1
	lduba	[%o0+%o3]ASI_AIUSL, %o4

1:	stb	%o4, [%o1+%o3]
	inccc	%o3
	sub	%o0, 2, %o0		! get next byte
	bcc,a,pt %ncc, 1b
	lduba	[%o0+%o3]ASI_AIUSL, %o4

2:	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	mov	%g0, %o0		! return (0)

.little_err:
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	retl
	mov	%g1, %o0
	SET_SIZE(xcopyin_little)


/*
 * Copy a block of storage - must not overlap (from + len <= to).
 * No fault handler installed (to be called under on_fault())
 */

	ENTRY(copyin_noerr)
	sethi	%hi(.copyio_noerr), REAL_LOFAULT
	b	.do_copyin
	or	REAL_LOFAULT, %lo(.copyio_noerr), REAL_LOFAULT
.copyio_noerr:
	jmp	SAVED_LOFAULT
	nop
	SET_SIZE(copyin_noerr)

/*
 * Copy a block of storage - must not overlap (from + len <= to).
 * No fault handler installed (to be called under on_fault())
 */

	ENTRY(copyout_noerr)
	sethi	%hi(.copyio_noerr), REAL_LOFAULT
	b	.do_copyout
	or	REAL_LOFAULT, %lo(.copyio_noerr), REAL_LOFAULT
	SET_SIZE(copyout_noerr)

	.align	4
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

/*
 * hwblkclr - clears block-aligned, block-multiple-sized regions that are
 * longer than 256 bytes in length using Niagara's block stores/quad store.
 * If the criteria for using this routine are not met then it calls bzero
 * and returns 1.  Otherwise 0 is returned indicating success.
 * Caller is responsible for ensuring use_hw_bzero is true and that
 * kpreempt_disable() has been called.
 */
	! %i0 - start address
	! %i1 - length of region (multiple of 64)

	ENTRY(hwblkclr)
	save	%sp, -SA(MINFRAME), %sp

	! Must be block-aligned
	andcc	%i0, 0x3f, %g0
	bnz,pn	%ncc, 1f
	nop

	! ... and must be 256 bytes or more
	cmp	%i1, 0x100
	blu,pn	%ncc, 1f
	nop

	! ... and length must be a multiple of 64
	andcc	%i1, 0x3f, %g0
	bz,pn	%ncc, .pz_doblock
	mov	ASI_BLK_INIT_ST_QUAD_LDD_P, %asi

1:	! punt, call bzero but notify the caller that bzero was used
	mov	%i0, %o0
	call	bzero
	mov	%i1, %o1
	ret
	restore	%g0, 1, %o0	! return (1) - did not use block operations

	! Already verified that there are at least 256 bytes to set
.pz_doblock:
	stxa	%g0, [%i0+0x0]%asi
	stxa	%g0, [%i0+0x40]%asi
	stxa	%g0, [%i0+0x80]%asi
	stxa	%g0, [%i0+0xc0]%asi

	stxa	%g0, [%i0+0x8]%asi
	stxa	%g0, [%i0+0x10]%asi
	stxa	%g0, [%i0+0x18]%asi
	stxa	%g0, [%i0+0x20]%asi
	stxa	%g0, [%i0+0x28]%asi
	stxa	%g0, [%i0+0x30]%asi
	stxa	%g0, [%i0+0x38]%asi

	stxa	%g0, [%i0+0x48]%asi
	stxa	%g0, [%i0+0x50]%asi
	stxa	%g0, [%i0+0x58]%asi
	stxa	%g0, [%i0+0x60]%asi
	stxa	%g0, [%i0+0x68]%asi
	stxa	%g0, [%i0+0x70]%asi
	stxa	%g0, [%i0+0x78]%asi

	stxa	%g0, [%i0+0x88]%asi
	stxa	%g0, [%i0+0x90]%asi
	stxa	%g0, [%i0+0x98]%asi
	stxa	%g0, [%i0+0xa0]%asi
	stxa	%g0, [%i0+0xa8]%asi
	stxa	%g0, [%i0+0xb0]%asi
	stxa	%g0, [%i0+0xb8]%asi

	stxa	%g0, [%i0+0xc8]%asi
	stxa	%g0, [%i0+0xd0]%asi
	stxa	%g0, [%i0+0xd8]%asi
	stxa	%g0, [%i0+0xe0]%asi
	stxa	%g0, [%i0+0xe8]%asi
	stxa	%g0, [%i0+0xf0]%asi
	stxa	%g0, [%i0+0xf8]%asi

	sub	%i1, 0x100, %i1
	cmp	%i1, 0x100
	bgu,pt	%ncc, .pz_doblock
	add	%i0, 0x100, %i0

2:
	! Check if more than 64 bytes to set
	cmp	%i1,0x40
	blu	%ncc, .pz_finish
	nop

3:
	stxa	%g0, [%i0+0x0]%asi
	stxa	%g0, [%i0+0x8]%asi
	stxa	%g0, [%i0+0x10]%asi
	stxa	%g0, [%i0+0x18]%asi
	stxa	%g0, [%i0+0x20]%asi
	stxa	%g0, [%i0+0x28]%asi
	stxa	%g0, [%i0+0x30]%asi
	stxa	%g0, [%i0+0x38]%asi

	subcc	%i1, 0x40, %i1
	bgu,pt	%ncc, 3b
	add	%i0, 0x40, %i0

.pz_finish:
	membar	#Sync
	ret
	restore	%g0, 0, %o0		! return (bzero or not)
	SET_SIZE(hwblkclr)

	/*
	 * Copy 32 bytes of data from src (%o0) to dst (%o1)
	 * using physical addresses.
	 */
	ENTRY_NP(hw_pa_bcopy32)
	rdpr	%pstate, %g1
	andn	%g1, PSTATE_IE, %g2
	wrpr	%g0, %g2, %pstate

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

	membar	#Sync
	retl
	wrpr	%g0, %g1, %pstate
	SET_SIZE(hw_pa_bcopy32)

/*
 * Zero a block of storage.
 *
 * uzero is used by the kernel to zero a block in user address space.
 */

/*
 * Control flow of the bzero/kzero/uzero routine.
 *
 *	For fewer than 7 bytes stores, bytes will be zeroed.
 *
 *	For less than 15 bytes stores, align the address on 4 byte boundary.
 *	Then store as many 4-byte chunks, followed by trailing bytes.
 *
 *	For sizes greater than 15 bytes, align the address on 8 byte boundary.
 *	if (count > 128) {
 *		store as many 8-bytes chunks to block align the address
 *		store using ASI_BLK_INIT_ST_QUAD_LDD_P (bzero/kzero) OR
 *		store using ASI_BLK_INIT_QUAD_LDD_AIUS (uzero)
 *	}
 *	Store as many 8-byte chunks, followed by trailing bytes.
 */

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

/*
 * Zero a block of storage.
 */

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

	sethi	%hi(use_hw_bzero), %o2
	ld	[%o2 + %lo(use_hw_bzero)], %o2
	tst	%o2
	bz	%ncc, .bzero_small
	mov	%o1, %o3

	rd	%asi, %o3
	wr	%g0, ASI_BLK_INIT_ST_QUAD_LDD_P, %asi
	cmp	%o3, ASI_P
	bne,a	%ncc, .algnblk
	wr	%g0, ASI_BLK_INIT_QUAD_LDD_AIUS, %asi

.algnblk:
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
	!
	! Undo asi register setting.
	!
	rd	%asi, %o4
	wr	%g0, ASI_P, %asi
	cmp	%o4, ASI_BLK_INIT_ST_QUAD_LDD_P
	bne,a	%ncc, .bzero_small
	wr	%g0, ASI_USER, %asi

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
