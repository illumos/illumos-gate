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

# ident	"%Z%%M%	%I%	%E% SMI"

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

#if !defined(lint)
#include "assym.h"
#endif	/* lint */


/*
 * Pseudo-code to aid in understanding the control flow of the
 * bcopy/kcopy routine.
 *
 *	! WARNING : <Register usage convention>
 *	! In kcopy() the %o5, holds previous error handler and a flag
 *	! LOFAULT_SET (low bits). The %o5 is null in bcopy().
 *	! The %o5 is not available for any other use.
 *
 * kcopy():
 *	%o5 = curthread->t_lofault;		! save existing handler in %o5
 *	%o5 |= LOFAULT_SET;			! ORed with LOFAULT_SET flag
 *	curthread->t_lofault = .copyerr;
 *	Call bcopy();
 *
 * bcopy():
 * 	if (length < 128)
 * 		goto regular_copy;
 *
 * 	if (!use_hw_bcopy)
 * 		goto regular_copy;
 *
 * 	blockcopy;
 *	restore t_lofault handler if came from kcopy();
 *
 *	regular_copy;
 *	restore t_lofault handler if came from kcopy();
 *
 * In lofault handler:
 *	curthread->t_lofault = (%o5 & ~LOFAULT_SET);	! restore old t_lofault
 *	return (errno)
 *
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
 * BCOPY_FLAG: Set for bcopy calls, cleared for kcopy calls
 * COPY_FLAGS: Both of the above
 *
 * Other flags:
 * KPREEMPT_FLAG: kpreempt needs to be called
 */
#define	FPUSED_FLAG	1
#define	BCOPY_FLAG	2
#define	COPY_FLAGS	(FPUSED_FLAG | BCOPY_FLAG)
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
 *    | 8 bytes to save %fprs               | <--  - SAVED_FPRS_OFFSET
 *    |-------------------------------------|
 *    | 8 bytes to save %gsr                | <--  - SAVED_GSR_OFFSET
 *    ---------------------------------------
 */
#define HWCOPYFRAMESIZE         ((VIS_BLOCKSIZE * (3 + 1)) + (2 * 8))
#define SAVED_FPREGS_OFFSET     (VIS_BLOCKSIZE * 4)
#define SAVED_FPREGS_ADJUST     ((VIS_BLOCKSIZE * 3) + 1)
#define SAVED_FPRS_OFFSET       (SAVED_FPREGS_OFFSET + 8)
#define SAVED_GSR_OFFSET        (SAVED_FPRS_OFFSET + 8)

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

#if !defined(lint)

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
#endif	/* NIAGARA_IMPL */

#endif	/* lint */
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

#if !defined(NIAGARA_IMPL)
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
 * We got here because of a fault during kcopy or bcopy if a fault
 * handler existed when bcopy was called.
 * Errno value is in %g1.
 */
.copyerr:
	sethi	%hi(.copyerr2), %l1
	or	%l1, %lo(.copyerr2), %l1
	membar	#Sync				! sync error barrier
	stn	%l1, [THREAD_REG + T_LOFAULT]	! set t_lofault
	btst	FPUSED_FLAG, %o5
	bz,pt	%xcc, 1f
	and	%o5, BCOPY_FLAG, %l1	! copy flag to %l1

	membar	#Sync				! sync error barrier
	ldx	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2      ! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz,pt	%icc, 4f
	  nop

	! restore fpregs from stack
	BLD_FP_FROMSTACK(%o2)

	ba,pt	%ncc, 2f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO
	wr	%o3, 0, %fprs		! restore fprs

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
	! handler after restting the t_lofault value.
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
	btst	BCOPY_FLAG, %l1
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
#endif	/* lint */


/*
 * Copy a block of storage - must not overlap (from + len <= to).
 */
#if defined(lint)

/* ARGSUSED */
void
bcopy(const void *from, void *to, size_t count)
{}

#else	/* lint */

	ENTRY(bcopy)

#if !defined(NIAGARA_IMPL)
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
	! kcopy and bcopy use the same code path. If BCOPY_FLAG is
	! set and the saved lofault was zero, we won't reset lofault on
	! returning.
	or	%o5, BCOPY_FLAG, %o5
#else	/* NIAGARA_IMPL */
	save	%sp, -SA(MINFRAME), %sp
	clr	%o5			! flag LOFAULT_SET is not set for bcopy
#endif	/* NIAGARA_IMPL */

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
#if !defined(NIAGARA_IMPL)
	ldn	[THREAD_REG + T_LWP], %o3
	brnz,pt	%o3, 1f
	  nop

	! kpreempt_disable();
	ldsb	[THREAD_REG + T_PREEMPT], %o2
	inc	%o2
	stb	%o2, [THREAD_REG + T_PREEMPT]

1:
	rd	%fprs, %o2              ! check for unused fp
	st	%o2, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET] ! save orig %fprs
	btst	FPRS_FEF, %o2
	bz,a,pt	%icc, .do_blockcopy
	wr	%g0, FPRS_FEF, %fprs

	! save in-use fpregs on stack
	BST_FP_TOSTACK(%o2)
#endif	/* NIAGARA_IMPL */
	
.do_blockcopy:

#if !defined(NIAGARA_IMPL)
	rd	%gsr, %o2
	stx	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]      ! save gsr
	or	%o5, FPUSED_FLAG, %o5		! fp regs are in use
#endif	/* NIAGARA_IMPL */

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

#if !defined(NIAGARA_IMPL)
	andn	%i1, 0x3f, %l0		! %l0 has block aligned src address
	prefetch [%l0+0x0], #one_read
	andcc	%i1, 0x3f, %g0		! is src 64B aligned
	bz,pn	%ncc, .blkcpy
	nop

	! handle misaligned source cases
	alignaddr %i1, %g0, %g0		! generate %gsr

	srl	%i1, 0x3, %l1		! src add bits 3, 4, 5 are now least
					! significant in %l1
	andcc	%l1, 0x7, %l2		! mask everything except bits 1, 2, 3
	add	%i1, %i3, %i1

	! switch statement to get to right 8 byte block within
	! 64 byte block
	cmp	 %l2, 0x4
	bgeu,a	 hlf
	cmp	 %l2, 0x6
	cmp	 %l2, 0x2
	bgeu,a	 sqtr
	nop
	cmp	 %l2, 0x1
	be,a	 off15
	nop
	ba	 off7
	nop
sqtr:
	be,a	 off23
	nop
	ba,a	 off31
	nop

hlf:
	bgeu,a	 fqtr
	nop	 
	cmp	 %l2, 0x5
	be,a	 off47
	nop
	ba	 off39
	nop
fqtr:
	be,a	 off55
	nop

	! Falls through when the source offset is greater than 56 
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
7:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_56_63
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 7b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

	! This copy case for source offset between 1 and 7
off7:
	ldda	[%l0]ASI_BLK_P, %d0
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
0:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_1_7
	fsrc1	%d16, %d0
	fsrc1	%d18, %d2
	fsrc1	%d20, %d4
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 0b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

	! This copy case for source offset between 8 and 15
off15:
	ldd	[%l0+0x8], %d2
	ldd	[%l0+0x10], %d4
	ldd	[%l0+0x18], %d6
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
1:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_8_15
	fsrc1	%d18, %d2
	fsrc1	%d20, %d4
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 1b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

	! This copy case for source offset between 16 and 23
off23:
	ldd	[%l0+0x10], %d4
	ldd	[%l0+0x18], %d6
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
2:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_16_23
	fsrc1	%d20, %d4
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 2b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

	! This copy case for source offset between 24 and 31
off31:
	ldd	[%l0+0x18], %d6
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
3:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_24_31
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 3b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

	! This copy case for source offset between 32 and 39
off39:
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
4:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_32_39
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 4b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

	! This copy case for source offset between 40 and 47
off47:
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
5:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_40_47
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 5b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

	! This copy case for source offset between 48 and 55
off55:
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
6:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_48_55
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 6b
	prefetch [%l0+0x80], #one_read
	ba	.blkdone
	membar	#Sync

	! Both source and destination are block aligned.
.blkcpy:
	prefetch [%i1+0x40], #one_read
	prefetch [%i1+0x80], #one_read
8:
	stxa	%g0, [%i0]%asi		! initialize the cache line
	ldda	[%i1]ASI_BLK_P, %d0
	stda	%d0, [%i0]ASI_BLK_P

	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 8b
	prefetch [%i1+0x80], #one_read
	membar	#Sync

.blkdone:
#else	/* NIAGARA_IMPL */
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
#endif	/* NIAGARA_IMPL */

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
#if !defined(NIAGARA_IMPL)
	btst	FPUSED_FLAG, %o5
	bz	%icc, 1f
	  and	%o5,  COPY_FLAGS, %l1	! Store flags in %l1
					! We can't clear the flags from %o5 yet
					! If there's an error, .copyerr will
					! need them

	ldx	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2      ! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz,pt	%icc, 4f
	  nop

	! restore fpregs from stack
	BLD_FP_FROMSTACK(%o2)

	ba,pt	%ncc, 2f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO
	wr	%o3, 0, %fprs		! restore fprs

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

1:
	btst	BCOPY_FLAG, %l1
	bz,pn	%icc, 3f
	andncc	%o5, COPY_FLAGS, %o5

	! Here via bcopy. Check to see if the handler was NULL.
	! If so, just return quietly. Otherwise, reset the
	! handler and go home.
	bnz,pn	%ncc, 3f
	nop

	! Null handler.
	btst	KPREEMPT_FLAG, %l1
	bz,pt	%icc, 2f
	  nop
	call	kpreempt
	  rdpr	%pil, %o0	! pass %pil
2:
	
	ret
	restore	%g0, 0, %o0

	! Here via kcopy or bcopy with a handler.
	! Reset the fault handler.
3:
	membar	#Sync
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault

	! call kpreempt if necessary
	btst	KPREEMPT_FLAG, %l1
	bz,pt	%icc, 4f
	  nop
	call	kpreempt
	  rdpr	%pil, %o0
4:
#else	/* NIAGARA_IMPL */
	membar	#Sync				! sync error barrier
	! Restore t_lofault handler, if came here from kcopy().
	tst	%o5
	bz	%ncc, 1f
	andn	%o5, LOFAULT_SET, %o5
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
1:
#endif	/* NIAGARA_IMPL */
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
#if !defined(NIAGARA_IMPL)
	! FPUSED_FLAG will not have been set in any path leading to
	! this point. No need to deal with it.
	btst	BCOPY_FLAG, %o5
	bz,pn	%icc, 2f
	andncc	%o5, BCOPY_FLAG, %o5
	! Here via bcopy. Check to see if the handler was NULL.
	! If so, just return quietly. Otherwise, reset the
	! handler and go home.
	bnz,pn	%ncc, 2f
	nop
	!
	! Null handler.
	!
	ret
	restore %g0, 0, %o0
	! Here via kcopy or bcopy with a handler.
	! Reset the fault handler.
2:
	membar	#Sync
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
#else	/* NIAGARA_IMPL */
	membar	#Sync				! sync error barrier
	! Restore t_lofault handler, if came here from kcopy().
	tst	%o5
	bz	%ncc, 1f
	andn	%o5, LOFAULT_SET, %o5
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
1:
#endif	/* NIAGARA_IMPL */
	ret
	restore %g0, 0, %o0		! return (0)

/*
 * Common code used to align transfers on word and doubleword
 * boudaries.  Aligns source and destination and returns a count
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
 * use_hw_bcopy.
 */
#ifdef lint
/*ARGSUSED*/
void
hwblkpagecopy(const void *src, void *dst)
{ }
#else /* lint */
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

#if defined(lint)

/*ARGSUSED*/
int
copyout(const void *kaddr, void *uaddr, size_t count)
{ return (0); }

#else	/* lint */

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

	ld	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2
	wr	%o2, 0, %gsr		! restore gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz	%icc, 4f
	  nop

	! restore fpregs from stack
	BLD_FP_FROMSTACK(%o2)

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO				! zero all of the fpregs
	wr	%o3, 0, %fprs		! restore fprs

1:
#else	/* NIAGARA_IMPL */
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
#endif	/* NIAGARA_IMPL */

	restore

	mov	SAVE_SRC, %o0
	mov	SAVE_DST, %o1
	jmp	REAL_LOFAULT
	  mov	SAVE_COUNT, %o2
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
#if !defined(NIAGARA_IMPL)
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp

	rd	%fprs, %o2			! check for unused fp
	st	%o2, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET]	! save %fprs
	btst	FPRS_FEF, %o2
	bz,a,pt	%icc, .do_block_copyout
	wr	%g0, FPRS_FEF, %fprs

	! save in-use fpregs on stack
	BST_FP_TOSTACK(%o2)
#else	/* NIAGARA_IMPL */
	save	%sp, -SA(MINFRAME), %sp
#endif	/* NIAGARA_IMPL */

.do_block_copyout:

#if !defined(NIAGARA_IMPL)
	rd	%gsr, %o2
	stx	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]	! save gsr
	! set the lower bit saved t_lofault to indicate that we need
	! clear %fprs register on the way out
	or	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT
#endif	/* NIAGARA_IMPL */

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

#if !defined(NIAGARA_IMPL)
	andn	%i1, 0x3f, %l0		! %l0 has block aligned src address
	prefetch [%l0+0x0], #one_read
	andcc	%i1, 0x3f, %g0		! is src 64B aligned
	bz,pn	%ncc, .co_blkcpy
	nop

	! handle misaligned source cases
	alignaddr %i1, %g0, %g0		! generate %gsr

	srl	%i1, 0x3, %l1		! src add bits 3, 4, 5 are now least
					! significant in %l1
	andcc	%l1, 0x7, %l2		! mask everything except bits 1, 2, 3
	add	%i1, %i3, %i1

	! switch statement to get to right 8 byte block within
	! 64 byte block
	cmp	 %l2, 0x4
	bgeu,a	 co_hlf
	cmp	 %l2, 0x6
	cmp	 %l2, 0x2
	bgeu,a	 co_sqtr
	nop
	cmp	 %l2, 0x1
	be,a	 co_off15
	nop
	ba	 co_off7
	nop
co_sqtr:
	be,a	 co_off23
	nop
	ba,a	 co_off31
	nop

co_hlf:
	bgeu,a	 co_fqtr
	nop	 
	cmp	 %l2, 0x5
	be,a	 co_off47
	nop
	ba	 co_off39
	nop
co_fqtr:
	be,a	 co_off55
	nop

	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
7:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_56_63
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_AIUS
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 7b
	prefetch [%l0+0x80], #one_read
	ba	.co_blkdone
	membar	#Sync

co_off7:
	ldda	[%l0]ASI_BLK_P, %d0
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
0:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_1_7
	fsrc1	%d16, %d0
	fsrc1	%d18, %d2
	fsrc1	%d20, %d4
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_AIUS
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 0b
	prefetch [%l0+0x80], #one_read
	ba	.co_blkdone
	membar	#Sync

co_off15:
	ldd	[%l0+0x8], %d2
	ldd	[%l0+0x10], %d4
	ldd	[%l0+0x18], %d6
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
1:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_8_15
	fsrc1	%d18, %d2
	fsrc1	%d20, %d4
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_AIUS
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 1b
	prefetch [%l0+0x80], #one_read
	ba	.co_blkdone
	membar	#Sync

co_off23:
	ldd	[%l0+0x10], %d4
	ldd	[%l0+0x18], %d6
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
2:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_16_23
	fsrc1	%d20, %d4
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_AIUS
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 2b
	prefetch [%l0+0x80], #one_read
	ba	.co_blkdone
	membar	#Sync

co_off31:
	ldd	[%l0+0x18], %d6
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
3:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_24_31
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_AIUS
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 3b
	prefetch [%l0+0x80], #one_read
	ba	.co_blkdone
	membar	#Sync

co_off39:
	ldd	[%l0+0x20], %d8
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
4:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_32_39
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_AIUS
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 4b
	prefetch [%l0+0x80], #one_read
	ba	.co_blkdone
	membar	#Sync

co_off47:
	ldd	[%l0+0x28], %d10
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
5:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_40_47
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_AIUS
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 5b
	prefetch [%l0+0x80], #one_read
	ba	.co_blkdone
	membar	#Sync

co_off55:
	ldd	[%l0+0x30], %d12
	ldd	[%l0+0x38], %d14
	prefetch [%l0+0x40], #one_read
	prefetch [%l0+0x80], #one_read
6:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]%asi		! initialize the cache line

	ldda	[%l0]ASI_BLK_P, %d16
	ALIGN_OFF_48_55
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_AIUS
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 6b
	prefetch [%l0+0x80], #one_read
	ba	.co_blkdone
	membar	#Sync

.co_blkcpy:
	prefetch [%i1+0x40], #one_read
	prefetch [%i1+0x80], #one_read
8:
	stxa	%g0, [%i0]%asi		! initialize the cache line
	ldda	[%i1]ASI_BLK_P, %d0
	stda	%d0, [%i0]ASI_BLK_AIUS

	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 8b
	prefetch [%i1+0x80], #one_read
	membar	#Sync

.co_blkdone:
#else	/* NIAGARA_IMPL */
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
#endif	/* NIAGARA_IMPL */

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
#if !defined(NIAGARA_IMPL)
	ld	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2
	wr	%o2, 0, %gsr		! restore gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz	%icc, 4f
	  nop

	! restore fpregs from stack
	BLD_FP_FROMSTACK(%o2)

	ba,pt	%ncc, 2f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO				! zero all of the fpregs
	wr	%o3, 0, %fprs		! restore fprs

2:
	membar	#Sync
	andn	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT
#else	/* NIAGARA_IMPL */
	membar	#Sync
#endif	/* NIAGARA_IMPL */
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
	SET_SIZE(copyout)

#endif	/* lint */


#ifdef	lint

/*ARGSUSED*/
int
xcopyout(const void *kaddr, void *uaddr, size_t count)
{ return (0); }

#else	/* lint */

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

#endif	/* lint */
	
#ifdef	lint

/*ARGSUSED*/
int
xcopyout_little(const void *kaddr, void *uaddr, size_t count)
{ return (0); }

#else	/* lint */

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
	sethi	%hi(.copyin_err), REAL_LOFAULT
	or	REAL_LOFAULT, %lo(.copyin_err), REAL_LOFAULT

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
	stn     SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]   ! restore old t_lofault
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
#if !defined(NIAGARA_IMPL)
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp

	rd	%fprs, %o2			! check for unused fp
	st	%o2, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET]	! save %fprs
	btst	FPRS_FEF, %o2
	bz,a,pt	%icc, .do_blockcopyin
	wr	%g0, FPRS_FEF, %fprs

	! save in-use fpregs on stack
	BST_FP_TOSTACK(%o2)
#else	/* NIAGARA_IMPL */
	save	%sp, -SA(MINFRAME), %sp
#endif	/* NIAGARA_IMPL */

.do_blockcopyin:

#if !defined(NIAGARA_IMPL)
	rd	%gsr, %o2
	stx	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]	! save gsr
	! set the lower bit saved t_lofault to indicate that we need
	! clear %fprs register on the way out
	or	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT
#endif	/* NIAGARA_IMPL */

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

#if !defined(NIAGARA_IMPL)
	mov	ASI_USER, %asi

	andn	%i1, 0x3f, %l0		! %l0 has block aligned src address
	prefetcha [%l0+0x0]%asi, #one_read
	andcc	%i1, 0x3f, %g0		! is src 64B aligned
	bz,pn	%ncc, .ci_blkcpy
	nop

	! handle misaligned source cases
	alignaddr %i1, %g0, %g0		! generate %gsr

	srl	%i1, 0x3, %l1		! src add bits 3, 4, 5 are now least
					! significant in %l1
	andcc	%l1, 0x7, %l2		! mask everything except bits 1, 2, 3
	add	%i1, %i3, %i1

	! switch statement to get to right 8 byte block within
	! 64 byte block
	cmp	 %l2, 0x4
	bgeu,a	 ci_hlf
	cmp	 %l2, 0x6
	cmp	 %l2, 0x2
	bgeu,a	 ci_sqtr
	nop
	cmp	 %l2, 0x1
	be,a	 ci_off15
	nop
	ba	 ci_off7
	nop
ci_sqtr:
	be,a	 ci_off23
	nop
	ba,a	 ci_off31
	nop

ci_hlf:
	bgeu,a	 ci_fqtr
	nop	 
	cmp	 %l2, 0x5
	be,a	 ci_off47
	nop
	ba	 ci_off39
	nop
ci_fqtr:
	be,a	 ci_off55
	nop

	ldda	[%l0+0x38]%asi, %d14
	prefetcha [%l0+0x40]%asi, #one_read
	prefetcha [%l0+0x80]%asi, #one_read
7:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]ASI_BLK_INIT_ST_QUAD_LDD_P ! initialize the cache line

	ldda	[%l0]ASI_BLK_AIUS, %d16
	ALIGN_OFF_56_63
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 7b
	prefetcha [%l0+0x80]%asi, #one_read
	ba	.ci_blkdone
	membar	#Sync

ci_off7:
	ldda	[%l0]ASI_BLK_AIUS, %d0
	prefetcha [%l0+0x40]%asi, #one_read
	prefetcha [%l0+0x80]%asi, #one_read
0:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]ASI_BLK_INIT_ST_QUAD_LDD_P ! initialize the cache line

	ldda	[%l0]ASI_BLK_AIUS, %d16
	ALIGN_OFF_1_7
	fsrc1	%d16, %d0
	fsrc1	%d18, %d2
	fsrc1	%d20, %d4
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 0b
	prefetcha [%l0+0x80]%asi, #one_read
	ba	.ci_blkdone
	membar	#Sync

ci_off15:
	ldda	[%l0+0x8]%asi, %d2
	ldda	[%l0+0x10]%asi, %d4
	ldda	[%l0+0x18]%asi, %d6
	ldda	[%l0+0x20]%asi, %d8
	ldda	[%l0+0x28]%asi, %d10
	ldda	[%l0+0x30]%asi, %d12
	ldda	[%l0+0x38]%asi, %d14
	prefetcha [%l0+0x40]%asi, #one_read
	prefetcha [%l0+0x80]%asi, #one_read
1:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]ASI_BLK_INIT_ST_QUAD_LDD_P ! initialize the cache line

	ldda	[%l0]ASI_BLK_AIUS, %d16
	ALIGN_OFF_8_15
	fsrc1	%d18, %d2
	fsrc1	%d20, %d4
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 1b
	prefetcha [%l0+0x80]%asi, #one_read
	ba	.ci_blkdone
	membar	#Sync

ci_off23:
	ldda	[%l0+0x10]%asi, %d4
	ldda	[%l0+0x18]%asi, %d6
	ldda	[%l0+0x20]%asi, %d8
	ldda	[%l0+0x28]%asi, %d10
	ldda	[%l0+0x30]%asi, %d12
	ldda	[%l0+0x38]%asi, %d14
	prefetcha [%l0+0x40]%asi, #one_read
	prefetcha [%l0+0x80]%asi, #one_read
2:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]ASI_BLK_INIT_ST_QUAD_LDD_P ! initialize the cache line

	ldda	[%l0]ASI_BLK_AIUS, %d16
	ALIGN_OFF_16_23
	fsrc1	%d20, %d4
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 2b
	prefetcha [%l0+0x80]%asi, #one_read
	ba	.ci_blkdone
	membar	#Sync

ci_off31:
	ldda	[%l0+0x18]%asi, %d6
	ldda	[%l0+0x20]%asi, %d8
	ldda	[%l0+0x28]%asi, %d10
	ldda	[%l0+0x30]%asi, %d12
	ldda	[%l0+0x38]%asi, %d14
	prefetcha [%l0+0x40]%asi, #one_read
	prefetcha [%l0+0x80]%asi, #one_read
3:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]ASI_BLK_INIT_ST_QUAD_LDD_P ! initialize the cache line

	ldda	[%l0]ASI_BLK_AIUS, %d16
	ALIGN_OFF_24_31
	fsrc1	%d22, %d6
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 3b
	prefetcha [%l0+0x80]%asi, #one_read
	ba	.ci_blkdone
	membar	#Sync

ci_off39:
	ldda	[%l0+0x20]%asi, %d8
	ldda	[%l0+0x28]%asi, %d10
	ldda	[%l0+0x30]%asi, %d12
	ldda	[%l0+0x38]%asi, %d14
	prefetcha [%l0+0x40]%asi, #one_read
	prefetcha [%l0+0x80]%asi, #one_read
4:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]ASI_BLK_INIT_ST_QUAD_LDD_P ! initialize the cache line

	ldda	[%l0]ASI_BLK_AIUS, %d16
	ALIGN_OFF_32_39
	fsrc1	%d24, %d8
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 4b
	prefetcha [%l0+0x80]%asi, #one_read
	ba	.ci_blkdone
	membar	#Sync

ci_off47:
	ldda	[%l0+0x28]%asi, %d10
	ldda	[%l0+0x30]%asi, %d12
	ldda	[%l0+0x38]%asi, %d14
	prefetcha [%l0+0x40]%asi, #one_read
	prefetcha [%l0+0x80]%asi, #one_read
5:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]ASI_BLK_INIT_ST_QUAD_LDD_P ! initialize the cache line

	ldda	[%l0]ASI_BLK_AIUS, %d16
	ALIGN_OFF_40_47
	fsrc1	%d26, %d10
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 5b
	prefetcha [%l0+0x80]%asi, #one_read
	ba	.ci_blkdone
	membar	#Sync

ci_off55:
	ldda	[%l0+0x30]%asi, %d12
	ldda	[%l0+0x38]%asi, %d14
	prefetcha [%l0+0x40]%asi, #one_read
	prefetcha [%l0+0x80]%asi, #one_read
6:
	add	%l0, 0x40, %l0
	stxa	%g0, [%i0]ASI_BLK_INIT_ST_QUAD_LDD_P ! initialize the cache line

	ldda	[%l0]ASI_BLK_AIUS, %d16
	ALIGN_OFF_48_55
	fsrc1	%d28, %d12
	fsrc1	%d30, %d14

	stda	%d48, [%i0]ASI_BLK_P
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 6b
	prefetcha [%l0+0x80]%asi, #one_read
	ba	.ci_blkdone
	membar	#Sync

.ci_blkcpy:
	prefetcha [%i1+0x40]%asi, #one_read
	prefetcha [%i1+0x80]%asi, #one_read
8:
	stxa	%g0, [%i0]ASI_BLK_INIT_ST_QUAD_LDD_P ! initialize the cache line
	ldda	[%i1]ASI_BLK_AIUS, %d0
	stda	%d0, [%i0]ASI_BLK_P

	add	%i1, 0x40, %i1
	subcc	%i3, 0x40, %i3
	add	%i0, 0x40, %i0
	bgu,pt	%ncc, 8b
	prefetcha [%i1+0x80]%asi, #one_read
	membar	#Sync

.ci_blkdone:
#else	/* NIAGARA_IMPL */
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
#endif	/* NIAGARA_IMPL */

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
#if !defined(NIAGARA_IMPL)
	ld	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2
	wr	%o2, 0, %gsr		! restore gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz	%icc, 4f
	  nop

	! restore fpregs from stack
	BLD_FP_FROMSTACK(%o2)

	ba,pt	%ncc, 2f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO				! zero all of the fpregs
	wr	%o3, 0, %fprs		! restore fprs

2:
	membar	#Sync			! sync error barrier
	andn	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT
#else	/* NIAGARA_IMPL */
	membar	#Sync
#endif	/* NIAGARA_IMPL */
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
	SET_SIZE(copyin)

#endif	/* lint */

#ifdef	lint

/*ARGSUSED*/
int
xcopyin(const void *uaddr, void *kaddr, size_t count)
{ return (0); }

#else	/* lint */

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

#endif	/* lint */

#ifdef	lint

/*ARGSUSED*/
int
xcopyin_little(const void *uaddr, void *kaddr, size_t count)
{ return (0); }

#else	/* lint */

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
	sethi	%hi(.copyio_noerr), REAL_LOFAULT
	b	.do_copyin
	  or	REAL_LOFAULT, %lo(.copyio_noerr), REAL_LOFAULT
.copyio_noerr:
	jmp	SAVED_LOFAULT
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
	sethi	%hi(.copyio_noerr), REAL_LOFAULT
	b	.do_copyout
	  or	REAL_LOFAULT, %lo(.copyio_noerr), REAL_LOFAULT
	SET_SIZE(copyout_noerr)

#endif /* lint */

#if defined(lint)

int use_hw_bcopy = 1;
int use_hw_bzero = 1;
uint_t hw_copy_limit_1 = 0x100;
uint_t hw_copy_limit_2 = 0x200;
uint_t hw_copy_limit_4 = 0x400;
uint_t hw_copy_limit_8 = 0x400;

#else /* !lint */

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
#endif /* !lint */

/*
 * hwblkclr - clears block-aligned, block-multiple-sized regions that are
 * longer than 256 bytes in length using Niagara's block stores/quad store.
 * If the criteria for using this routine are not met then it calls bzero
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
#endif	/* lint */

#ifdef	lint
/* Copy 32 bytes of data from src to dst using physical addresses */
/*ARGSUSED*/
void
hw_pa_bcopy32(uint64_t src, uint64_t dst)
{}
#else	/*!lint */

	/*
	 * Copy 32 bytes of data from src (%o0) to dst (%o1)
	 * using physical addresses.
	 */
	ENTRY_NP(hw_pa_bcopy32)
	rdpr    %pstate, %g1
	andn    %g1, PSTATE_IE, %g2
	wrpr    %g0, %g2, %pstate

	ldxa    [%o0]ASI_MEM, %o2
	add     %o0, 8, %o0
	ldxa    [%o0]ASI_MEM, %o3
	add     %o0, 8, %o0
	ldxa    [%o0]ASI_MEM, %o4
	add     %o0, 8, %o0
	ldxa    [%o0]ASI_MEM, %o5
	stxa    %o2, [%o1]ASI_MEM
	add     %o1, 8, %o1
	stxa    %o3, [%o1]ASI_MEM
	add     %o1, 8, %o1
	stxa    %o4, [%o1]ASI_MEM
	add     %o1, 8, %o1
	stxa    %o5, [%o1]ASI_MEM

	membar	#Sync
	retl
	  wrpr    %g0, %g1, %pstate
	SET_SIZE(hw_pa_bcopy32)
#endif /* lint */

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
#endif	/* lint */
