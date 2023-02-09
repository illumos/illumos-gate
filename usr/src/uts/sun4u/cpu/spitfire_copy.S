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

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/asm_linkage.h>
#include <sys/vtrace.h>
#include <sys/machthread.h>
#include <sys/clock.h>
#include <sys/asi.h>
#include <sys/fsr.h>
#include <sys/privregs.h>

#include "assym.h"


/*
 * Pseudo-code to aid in understanding the control flow of the
 * bcopy routine.
 *
 * On entry to bcopy:
 *
 *	%l6 = curthread->t_lofault;
 *	used_block_copy = FALSE;			! %l6 |= 1
 *	if (%l6 != NULL) {
 *		curthread->t_lofault = .copyerr;
 *		caller_error_handler = TRUE		! %l6 |= 2
 *	}
 *
 * 	if (length < VIS_COPY)
 * 		goto regular_copy;
 *
 * 	if (!use_vis)
 * 		goto_regular_copy;
 *
 * 	if (curthread->t_lwp == NULL) {
 *		! Kernel threads do not have pcb's in which to store
 *		! the floating point state, disallow preemption during
 *		! the copy.
 * 		kpreempt_disable(curthread);
 *	}
 *
 * 	old_fprs = %fprs;
 * 	old_gsr = %gsr;
 * 	if (%fprs.fef) {
 *              ! If we need to save 4 blocks of fpregs then make sure
 *		! the length is still appropriate for that extra overhead.
 * 		if (length < (large_length + (64 * 4))) {
 * 			if (curthread->t_lwp == NULL)
 * 				kpreempt_enable(curthread);
 * 			goto regular_copy;
 * 		}
 * 		%fprs.fef = 1;
 * 		save current fpregs on stack using blockstore
 * 	} else {
 * 		%fprs.fef = 1;
 * 	}
 *
 * 	used_block_copy = 1;				! %l6 |= 1
 * 	do_blockcopy_here;
 *
 * In lofault handler:
 *	curthread->t_lofault = .copyerr2;
 *	Continue on with the normal exit handler
 *
 * On exit:
 *	call_kpreempt = 0;
 * 	if (used_block_copy) {				! %l6 & 1
 * 		%gsr = old_gsr;
 * 		if (old_fprs & FPRS_FEF)
 * 			restore fpregs from stack using blockload
 *		else
 *			zero fpregs
 * 		%fprs = old_fprs;
 * 		if (curthread->t_lwp == NULL) {
 *			kpreempt_enable(curthread);
 *			call_kpreempt = 1;
 *		}
 * 	}
 * 	curthread->t_lofault = (%l6 & ~3);
 *	if (call_kpreempt)
 *		kpreempt(%pil);
 * 	return (0)
 *
 * In second lofault handler (.copyerr2):
 *	We've tried to restore fp state from the stack and failed.  To
 *	prevent from returning with a corrupted fp state, we will panic.
 */

/*
 * Notes on preserving existing fp state:
 *
 * When a copyOP decides to use fp we may have to preserve existing
 * floating point state.  It is not the caller's state that we need to
 * preserve - the rest of the kernel does not use fp and, anyway, fp
 * registers are volatile across a call.  Some examples:
 *
 *	- userland has fp state and is interrupted (device interrupt
 *	  or trap) and within the interrupt/trap handling we use
 *	  bcopy()
 *	- another (higher level) interrupt or trap handler uses bcopy
 *	  while a bcopy from an earlier interrupt is still active
 *	- an asynchronous error trap occurs while fp state exists (in
 *	  userland or in kernel copy) and the tl0 component of the handling
 *	  uses bcopy
 *	- a user process with fp state incurs a copy-on-write fault and
 *	  hwblkpagecopy always uses fp
 *
 * We therefore need a per-call place in which to preserve fp state -
 * using our stack is ideal (and since fp copy cannot be leaf optimized
 * because of calls it makes, this is no hardship).
 *
 * To make sure that floating point state is always saved and restored
 * correctly, the following "big rules" must be followed when the floating
 * point registers will be used:
 *
 * 1. %l6 always holds the caller's lofault handler.  Also in this register,
 *    Bit 1 (FPUSED_FLAG) indicates that the floating point registers are in
 *    use.  Bit 2 (BCOPY_FLAG) indicates that the call was to bcopy.
 *
 * 2. The FPUSED flag indicates that all FP state has been successfully stored
 *    on the stack.  It should not be set until this save has been completed.
 *
 * 3. The FPUSED flag should not be cleared on exit until all FP state has
 *    been restored from the stack.  If an error occurs while restoring
 *    data from the stack, the error handler can check this flag to see if
 *    a restore is necessary.
 *
 * 4. Code run under the new lofault handler must be kept to a minimum.  In
 *    particular, any calls to kpreempt() should not be made until after the
 *    lofault handler has been restored.
 */

/*
 * This shadows sys/machsystm.h which can't be included due to the lack of
 * _ASM guards in include files it references. Change it here, change it there.
 */
#define VIS_COPY_THRESHOLD 900

/*
 * Less then or equal this number of bytes we will always copy byte-for-byte
 */
#define	SMALL_LIMIT	7

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
#define BCOPY_FLAG	2
#define	COPY_FLAGS	(FPUSED_FLAG | BCOPY_FLAG)
#define	KPREEMPT_FLAG	4

/*
 * Size of stack frame in order to accomodate a 64-byte aligned
 * floating-point register save area and 2 32-bit temp locations.
 */
#define	HWCOPYFRAMESIZE	((64 * 5) + (2 * 4))

#define SAVED_FPREGS_OFFSET	(64 * 5)
#define	SAVED_FPRS_OFFSET	(SAVED_FPREGS_OFFSET + 4)
#define	SAVED_GSR_OFFSET	(SAVED_FPRS_OFFSET + 4)

/*
 * Common macros used by the various versions of the block copy
 * routines in this file.
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
	faddd	%f0, %f2, %f32		;\
	fmuld	%f0, %f2, %f34		;\
	faddd	%f0, %f2, %f36		;\
	fmuld	%f0, %f2, %f38		;\
	faddd	%f0, %f2, %f40		;\
	fmuld	%f0, %f2, %f42		;\
	faddd	%f0, %f2, %f44		;\
	fmuld	%f0, %f2, %f46		;\
	faddd	%f0, %f2, %f48		;\
	fmuld	%f0, %f2, %f50		;\
	faddd	%f0, %f2, %f52		;\
	fmuld	%f0, %f2, %f54		;\
	faddd	%f0, %f2, %f56		;\
	fmuld	%f0, %f2, %f58		;\
	faddd	%f0, %f2, %f60		;\
	fmuld	%f0, %f2, %f62


#define	FALIGN_D0			\
	faligndata %d0, %d2, %d48	;\
	faligndata %d2, %d4, %d50	;\
	faligndata %d4, %d6, %d52	;\
	faligndata %d6, %d8, %d54	;\
	faligndata %d8, %d10, %d56	;\
	faligndata %d10, %d12, %d58	;\
	faligndata %d12, %d14, %d60	;\
	faligndata %d14, %d16, %d62

#define	FALIGN_D16			\
	faligndata %d16, %d18, %d48	;\
	faligndata %d18, %d20, %d50	;\
	faligndata %d20, %d22, %d52	;\
	faligndata %d22, %d24, %d54	;\
	faligndata %d24, %d26, %d56	;\
	faligndata %d26, %d28, %d58	;\
	faligndata %d28, %d30, %d60	;\
	faligndata %d30, %d32, %d62

#define	FALIGN_D32			\
	faligndata %d32, %d34, %d48	;\
	faligndata %d34, %d36, %d50	;\
	faligndata %d36, %d38, %d52	;\
	faligndata %d38, %d40, %d54	;\
	faligndata %d40, %d42, %d56	;\
	faligndata %d42, %d44, %d58	;\
	faligndata %d44, %d46, %d60	;\
	faligndata %d46, %d0, %d62

#define	FALIGN_D2			\
	faligndata %d2, %d4, %d48	;\
	faligndata %d4, %d6, %d50	;\
	faligndata %d6, %d8, %d52	;\
	faligndata %d8, %d10, %d54	;\
	faligndata %d10, %d12, %d56	;\
	faligndata %d12, %d14, %d58	;\
	faligndata %d14, %d16, %d60	;\
	faligndata %d16, %d18, %d62

#define	FALIGN_D18			\
	faligndata %d18, %d20, %d48	;\
	faligndata %d20, %d22, %d50	;\
	faligndata %d22, %d24, %d52	;\
	faligndata %d24, %d26, %d54	;\
	faligndata %d26, %d28, %d56	;\
	faligndata %d28, %d30, %d58	;\
	faligndata %d30, %d32, %d60	;\
	faligndata %d32, %d34, %d62

#define	FALIGN_D34			\
	faligndata %d34, %d36, %d48	;\
	faligndata %d36, %d38, %d50	;\
	faligndata %d38, %d40, %d52	;\
	faligndata %d40, %d42, %d54	;\
	faligndata %d42, %d44, %d56	;\
	faligndata %d44, %d46, %d58	;\
	faligndata %d46, %d0, %d60	;\
	faligndata %d0, %d2, %d62

#define	FALIGN_D4			\
	faligndata %d4, %d6, %d48	;\
	faligndata %d6, %d8, %d50	;\
	faligndata %d8, %d10, %d52	;\
	faligndata %d10, %d12, %d54	;\
	faligndata %d12, %d14, %d56	;\
	faligndata %d14, %d16, %d58	;\
	faligndata %d16, %d18, %d60	;\
	faligndata %d18, %d20, %d62

#define	FALIGN_D20			\
	faligndata %d20, %d22, %d48	;\
	faligndata %d22, %d24, %d50	;\
	faligndata %d24, %d26, %d52	;\
	faligndata %d26, %d28, %d54	;\
	faligndata %d28, %d30, %d56	;\
	faligndata %d30, %d32, %d58	;\
	faligndata %d32, %d34, %d60	;\
	faligndata %d34, %d36, %d62

#define	FALIGN_D36			\
	faligndata %d36, %d38, %d48	;\
	faligndata %d38, %d40, %d50	;\
	faligndata %d40, %d42, %d52	;\
	faligndata %d42, %d44, %d54	;\
	faligndata %d44, %d46, %d56	;\
	faligndata %d46, %d0, %d58	;\
	faligndata %d0, %d2, %d60	;\
	faligndata %d2, %d4, %d62

#define	FALIGN_D6			\
	faligndata %d6, %d8, %d48	;\
	faligndata %d8, %d10, %d50	;\
	faligndata %d10, %d12, %d52	;\
	faligndata %d12, %d14, %d54	;\
	faligndata %d14, %d16, %d56	;\
	faligndata %d16, %d18, %d58	;\
	faligndata %d18, %d20, %d60	;\
	faligndata %d20, %d22, %d62

#define	FALIGN_D22			\
	faligndata %d22, %d24, %d48	;\
	faligndata %d24, %d26, %d50	;\
	faligndata %d26, %d28, %d52	;\
	faligndata %d28, %d30, %d54	;\
	faligndata %d30, %d32, %d56	;\
	faligndata %d32, %d34, %d58	;\
	faligndata %d34, %d36, %d60	;\
	faligndata %d36, %d38, %d62

#define	FALIGN_D38			\
	faligndata %d38, %d40, %d48	;\
	faligndata %d40, %d42, %d50	;\
	faligndata %d42, %d44, %d52	;\
	faligndata %d44, %d46, %d54	;\
	faligndata %d46, %d0, %d56	;\
	faligndata %d0, %d2, %d58	;\
	faligndata %d2, %d4, %d60	;\
	faligndata %d4, %d6, %d62

#define	FALIGN_D8			\
	faligndata %d8, %d10, %d48	;\
	faligndata %d10, %d12, %d50	;\
	faligndata %d12, %d14, %d52	;\
	faligndata %d14, %d16, %d54	;\
	faligndata %d16, %d18, %d56	;\
	faligndata %d18, %d20, %d58	;\
	faligndata %d20, %d22, %d60	;\
	faligndata %d22, %d24, %d62

#define	FALIGN_D24			\
	faligndata %d24, %d26, %d48	;\
	faligndata %d26, %d28, %d50	;\
	faligndata %d28, %d30, %d52	;\
	faligndata %d30, %d32, %d54	;\
	faligndata %d32, %d34, %d56	;\
	faligndata %d34, %d36, %d58	;\
	faligndata %d36, %d38, %d60	;\
	faligndata %d38, %d40, %d62

#define	FALIGN_D40			\
	faligndata %d40, %d42, %d48	;\
	faligndata %d42, %d44, %d50	;\
	faligndata %d44, %d46, %d52	;\
	faligndata %d46, %d0, %d54	;\
	faligndata %d0, %d2, %d56	;\
	faligndata %d2, %d4, %d58	;\
	faligndata %d4, %d6, %d60	;\
	faligndata %d6, %d8, %d62

#define	FALIGN_D10			\
	faligndata %d10, %d12, %d48	;\
	faligndata %d12, %d14, %d50	;\
	faligndata %d14, %d16, %d52	;\
	faligndata %d16, %d18, %d54	;\
	faligndata %d18, %d20, %d56	;\
	faligndata %d20, %d22, %d58	;\
	faligndata %d22, %d24, %d60	;\
	faligndata %d24, %d26, %d62

#define	FALIGN_D26			\
	faligndata %d26, %d28, %d48	;\
	faligndata %d28, %d30, %d50	;\
	faligndata %d30, %d32, %d52	;\
	faligndata %d32, %d34, %d54	;\
	faligndata %d34, %d36, %d56	;\
	faligndata %d36, %d38, %d58	;\
	faligndata %d38, %d40, %d60	;\
	faligndata %d40, %d42, %d62

#define	FALIGN_D42			\
	faligndata %d42, %d44, %d48	;\
	faligndata %d44, %d46, %d50	;\
	faligndata %d46, %d0, %d52	;\
	faligndata %d0, %d2, %d54	;\
	faligndata %d2, %d4, %d56	;\
	faligndata %d4, %d6, %d58	;\
	faligndata %d6, %d8, %d60	;\
	faligndata %d8, %d10, %d62

#define	FALIGN_D12			\
	faligndata %d12, %d14, %d48	;\
	faligndata %d14, %d16, %d50	;\
	faligndata %d16, %d18, %d52	;\
	faligndata %d18, %d20, %d54	;\
	faligndata %d20, %d22, %d56	;\
	faligndata %d22, %d24, %d58	;\
	faligndata %d24, %d26, %d60	;\
	faligndata %d26, %d28, %d62

#define	FALIGN_D28			\
	faligndata %d28, %d30, %d48	;\
	faligndata %d30, %d32, %d50	;\
	faligndata %d32, %d34, %d52	;\
	faligndata %d34, %d36, %d54	;\
	faligndata %d36, %d38, %d56	;\
	faligndata %d38, %d40, %d58	;\
	faligndata %d40, %d42, %d60	;\
	faligndata %d42, %d44, %d62

#define	FALIGN_D44			\
	faligndata %d44, %d46, %d48	;\
	faligndata %d46, %d0, %d50	;\
	faligndata %d0, %d2, %d52	;\
	faligndata %d2, %d4, %d54	;\
	faligndata %d4, %d6, %d56	;\
	faligndata %d6, %d8, %d58	;\
	faligndata %d8, %d10, %d60	;\
	faligndata %d10, %d12, %d62

#define	FALIGN_D14			\
	faligndata %d14, %d16, %d48	;\
	faligndata %d16, %d18, %d50	;\
	faligndata %d18, %d20, %d52	;\
	faligndata %d20, %d22, %d54	;\
	faligndata %d22, %d24, %d56	;\
	faligndata %d24, %d26, %d58	;\
	faligndata %d26, %d28, %d60	;\
	faligndata %d28, %d30, %d62

#define	FALIGN_D30			\
	faligndata %d30, %d32, %d48	;\
	faligndata %d32, %d34, %d50	;\
	faligndata %d34, %d36, %d52	;\
	faligndata %d36, %d38, %d54	;\
	faligndata %d38, %d40, %d56	;\
	faligndata %d40, %d42, %d58	;\
	faligndata %d42, %d44, %d60	;\
	faligndata %d44, %d46, %d62

#define	FALIGN_D46			\
	faligndata %d46, %d0, %d48	;\
	faligndata %d0, %d2, %d50	;\
	faligndata %d2, %d4, %d52	;\
	faligndata %d4, %d6, %d54	;\
	faligndata %d6, %d8, %d56	;\
	faligndata %d8, %d10, %d58	;\
	faligndata %d10, %d12, %d60	;\
	faligndata %d12, %d14, %d62


/*
 * Copy a block of storage, returning an error code if `from' or
 * `to' takes a kernel pagefault which cannot be resolved.
 * Returns errno value on pagefault error, 0 if all ok
 */



	.seg	".text"
	.align	4

	ENTRY(kcopy)

	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	set	.copyerr, %l6		! copyerr is lofault value
	ldn	[THREAD_REG + T_LOFAULT], %l7	! save existing handler
	membar	#Sync			! sync error barrier (see copy.s)
	stn	%l6, [THREAD_REG + T_LOFAULT]	! set t_lofault
	!
	! Note that we carefully do *not* flag the setting of
	! t_lofault.
	!
	ba,pt	%ncc, .do_copy		! common code
	  mov	%l7, %l6

/*
 * We got here because of a fault during kcopy or bcopy if a fault
 * handler existed when bcopy was called. 
 * Errno value is in %g1.
 */
.copyerr:
	set	.copyerr2, %l1
	membar	#Sync			! sync error barrier
	stn	%l1, [THREAD_REG + T_LOFAULT]	! set t_lofault
	btst	FPUSED_FLAG, %l6
	bz	%icc, 1f
	  and	%l6, BCOPY_FLAG, %l1	! copy flag to %l1

	membar	#Sync

	ld	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2	! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz	%icc, 4f
	  nop

	! restore fpregs from stack
	membar	#Sync
	add	%fp, STACK_BIAS - 257, %o2
	and	%o2, -64, %o2
	ldda	[%o2]ASI_BLK_P, %d0
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d16
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d32
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d48
	membar	#Sync

	ba,pt	%ncc, 2f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO				! zero all of the fpregs
	wr	%o3, 0, %fprs		! restore fprs

2:	ldn	[THREAD_REG + T_LWP], %o2
	tst	%o2
	bnz,pt	%ncc, 1f
	  nop

	ldsb	[THREAD_REG + T_PREEMPT], %l0
	deccc	%l0
	bnz,pn	%ncc, 1f
	  stb	%l0, [THREAD_REG + T_PREEMPT]

	! Check for a kernel preemption request
	ldn	[THREAD_REG + T_CPU], %l0
	ldub	[%l0 + CPU_KPRUNRUN], %l0
	tst	%l0
	bnz,a,pt	%ncc, 1f	! Need to call kpreempt?
	  or	%l1, KPREEMPT_FLAG, %l1	! If so, set the flag

	!
	! Need to cater for the different expectations of kcopy
	! and bcopy. kcopy will *always* set a t_lofault handler
	! If it fires, we're expected to just return the error code
	! and *not* to invoke any existing error handler. As far as
	! bcopy is concerned, we only set t_lofault if there was an
	! existing lofault handler. In that case we're expected to
	! invoke the previously existing handler after restting the
	! t_lofault value.
	!
1:
	andn	%l6, COPY_FLAGS, %l6	! remove flags from lofault address
	membar	#Sync			! sync error barrier
	stn	%l6, [THREAD_REG + T_LOFAULT]	! restore old t_lofault

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
	!
	! We're here via bcopy. There *must* have been an error handler
	! in place otheerwise we would have died a nasty death already.
	!
	jmp	%l6				! goto real handler
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
	SET_SIZE(kcopy)


/*
 * Copy a block of storage - must not overlap (from + len <= to).
 * Registers: l6 - saved t_lofault
 *
 * Copy a page of memory.
 * Assumes double word alignment and a count >= 256.
 */

	ENTRY(bcopy)

	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	ldn	[THREAD_REG + T_LOFAULT], %l6	! save t_lofault
	tst	%l6
        !
        ! We've already captured whether t_lofault was zero on entry.
        ! We need to mark ourselves as being from bcopy since both
        ! kcopy and bcopy use the same code path. If BCOPY_FLAG is set
        ! and the saved lofault was zero, we won't reset lofault on
        ! returning.
        !
	or	%l6, BCOPY_FLAG, %l6
	bz,pt	%ncc, .do_copy
	sethi	%hi(.copyerr), %o2
	or	%o2, %lo(.copyerr), %o2
	membar	#Sync			! sync error barrier
	stn	%o2, [THREAD_REG + T_LOFAULT]	! install new vector

.do_copy:
	cmp	%i2, 12			! for small counts
	blu	%ncc, .bytecp		! just copy bytes
	  .empty

	cmp	%i2, VIS_COPY_THRESHOLD	! for large counts
	blu,pt	%ncc, .bcb_punt
	  .empty

	!
	! Check to see if VIS acceleration is enabled
	!
	sethi	%hi(use_hw_bcopy), %o2
	ld	[%o2 + %lo(use_hw_bcopy)], %o2
	tst	%o2
	bz,pn	%icc, .bcb_punt
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

	ldn	[THREAD_REG + T_LWP], %o3
	tst	%o3
	bnz,pt	%ncc, 1f
	  nop

	! kpreempt_disable();
	ldsb	[THREAD_REG + T_PREEMPT], %o2
	inc	%o2
	stb	%o2, [THREAD_REG + T_PREEMPT]

1:
	rd	%fprs, %o2		! check for unused fp
	st	%o2, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET] ! save orig %fprs
	btst	FPRS_FEF, %o2
	bz,a	%icc, .do_blockcopy
	  wr	%g0, FPRS_FEF, %fprs

.bcb_fpregs_inuse:
	cmp	%i2, VIS_COPY_THRESHOLD+(64*4) ! for large counts (larger
	bgeu	%ncc, 1f		!  if we have to save the fpregs)
	  nop

	tst	%o3
	bnz,pt	%ncc, .bcb_punt
	  nop

	ldsb	[THREAD_REG + T_PREEMPT], %l0
	deccc	%l0
	bnz,pn	%icc, .bcb_punt
	  stb	%l0, [THREAD_REG + T_PREEMPT]

	! Check for a kernel preemption request
	ldn	[THREAD_REG + T_CPU], %l0
	ldub	[%l0 + CPU_KPRUNRUN], %l0
	tst	%l0
	bz,pt	%icc, .bcb_punt
	  nop

	! Attempt to preempt
	call	kpreempt
	  rdpr	  %pil, %o0		  ! pass %pil

	ba,pt	%ncc, .bcb_punt
	  nop

1:
	wr	%g0, FPRS_FEF, %fprs

	! save in-use fpregs on stack
	membar	#Sync
	add	%fp, STACK_BIAS - 257, %o2
	and	%o2, -64, %o2
	stda	%d0, [%o2]ASI_BLK_P
	add	%o2, 64, %o2
	stda	%d16, [%o2]ASI_BLK_P
	add	%o2, 64, %o2
	stda	%d32, [%o2]ASI_BLK_P
	add	%o2, 64, %o2
	stda	%d48, [%o2]ASI_BLK_P
	membar	#Sync

.do_blockcopy:
	membar	#StoreStore|#StoreLoad|#LoadStore

	rd	%gsr, %o2
	st	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]	! save gsr

	! Set the lower bit in the saved t_lofault to indicate
	! that we need to clear the %fprs register on the way
	! out
	or	%l6, FPUSED_FLAG, %l6

	! Swap src/dst since the code below is memcpy code
	! and memcpy/bcopy have different calling sequences
	mov	%i1, %i5
	mov	%i0, %i1
	mov	%i5, %i0

!!! This code is nearly identical to the version in the sun4u
!!! libc_psr.  Most bugfixes made to that file should be
!!! merged into this routine.

	andcc	%i0, 7, %o3
	bz,pt	%ncc, blkcpy
	sub	%o3, 8, %o3
	neg	%o3
	sub	%i2, %o3, %i2

	! Align Destination on double-word boundary

2:	ldub	[%i1], %o4
	inc	%i1
	inc	%i0
	deccc	%o3
	bgu	%ncc, 2b
	stb	%o4, [%i0 - 1]
blkcpy:	
	andcc	%i0, 63, %i3
	bz,pn	%ncc, blalign		! now block aligned
	sub	%i3, 64, %i3
	neg	%i3			! bytes till block aligned
	sub	%i2, %i3, %i2		! update %i2 with new count

	! Copy %i3 bytes till dst is block (64 byte) aligned. use
	! double word copies.

	alignaddr %i1, %g0, %g1
	ldd	[%g1], %d0
	add	%g1, 8, %g1
6:
	ldd	[%g1], %d2
	add	%g1, 8, %g1
	subcc	%i3, 8, %i3
	faligndata %d0, %d2, %d8
	std	%d8, [%i0]
	add	%i1, 8, %i1
	bz,pn	%ncc, blalign
	add	%i0, 8, %i0
	ldd	[%g1], %d0
	add	%g1, 8, %g1
	subcc	%i3, 8, %i3
	faligndata %d2, %d0, %d8
	std	%d8, [%i0]
	add	%i1, 8, %i1
	bgu,pn	%ncc, 6b
	add	%i0, 8, %i0
 
blalign:
	membar	#StoreLoad
	! %i2 = total length
	! %i3 = blocks	(length - 64) / 64
	! %i4 = doubles remaining  (length - blocks)
	sub	%i2, 64, %i3
	andn	%i3, 63, %i3
	sub	%i2, %i3, %i4
	andn	%i4, 7, %i4
	sub	%i4, 16, %i4
	sub	%i2, %i4, %i2
	sub	%i2, %i3, %i2

	andn	%i1, 0x3f, %l7		! blk aligned address
	alignaddr %i1, %g0, %g0		! gen %gsr

	srl	%i1, 3, %l5		! bits 3,4,5 are now least sig in  %l5
	andcc	%l5, 7, %i5		! mask everything except bits 1,2 3
	add	%i1, %i4, %i1
	add	%i1, %i3, %i1

	ldda	[%l7]ASI_BLK_P, %d0
	add	%l7, 64, %l7
	ldda	[%l7]ASI_BLK_P, %d16
	add	%l7, 64, %l7
	ldda	[%l7]ASI_BLK_P, %d32
	add	%l7, 64, %l7
	sub	%i3, 128, %i3

	! switch statement to get us to the right 8 byte blk within a
	! 64 byte block
	cmp	 %i5, 4
	bgeu,a	 hlf
	cmp	 %i5, 6
	cmp	 %i5, 2
	bgeu,a	 sqtr
	nop
	cmp	 %i5, 1
	be,a	 seg1
	nop
	ba,pt	 %ncc, seg0
	nop
sqtr:
	be,a	 seg2
	nop
	ba,pt	 %ncc, seg3
	nop

hlf:
	bgeu,a	 fqtr
	nop	 
	cmp	 %i5, 5
	be,a	 seg5
	nop
	ba,pt	 %ncc, seg4
	nop
fqtr:
	be,a	 seg6
	nop
	ba,pt	 %ncc, seg7
	nop
	

seg0:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D0
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D16
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D32
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg0

0:
	FALIGN_D16
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D32
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd0
	add	%i0, 64, %i0

1:
	FALIGN_D32
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D0
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd16
	add	%i0, 64, %i0

2:
	FALIGN_D0
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D16
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd32
	add	%i0, 64, %i0

seg1:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D2
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D18
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D34
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg1
0:
	FALIGN_D18
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D34
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd2
	add	%i0, 64, %i0

1:
	FALIGN_D34
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D2
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd18
	add	%i0, 64, %i0

2:
	FALIGN_D2
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D18
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd34
	add	%i0, 64, %i0

seg2:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D4
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D20
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D36
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg2

0:
	FALIGN_D20
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D36
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd4
	add	%i0, 64, %i0

1:
	FALIGN_D36
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D4
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd20
	add	%i0, 64, %i0

2:
	FALIGN_D4
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D20
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd36
	add	%i0, 64, %i0

seg3:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D6
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D22
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D38
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg3

0:
	FALIGN_D22
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D38
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd6
	add	%i0, 64, %i0

1:
	FALIGN_D38
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D6
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd22
	add	%i0, 64, %i0

2:
	FALIGN_D6
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D22
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd38
	add	%i0, 64, %i0

seg4:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D8
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D24
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D40
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg4

0:
	FALIGN_D24
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D40
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd8
	add	%i0, 64, %i0

1:
	FALIGN_D40
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D8
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd24
	add	%i0, 64, %i0

2:
	FALIGN_D8
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D24
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd40
	add	%i0, 64, %i0

seg5:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D10
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D26
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D42
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg5

0:
	FALIGN_D26
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D42
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd10
	add	%i0, 64, %i0

1:
	FALIGN_D42
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D10
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd26
	add	%i0, 64, %i0

2:
	FALIGN_D10
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D26
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd42
	add	%i0, 64, %i0

seg6:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D12
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D28
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D44
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg6

0:
	FALIGN_D28
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D44
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd12
	add	%i0, 64, %i0

1:
	FALIGN_D44
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D12
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd28
	add	%i0, 64, %i0

2:
	FALIGN_D12
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D28
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd44
	add	%i0, 64, %i0

seg7:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D14
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D30
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D46
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, seg7

0:
	FALIGN_D30
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D46
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd14
	add	%i0, 64, %i0

1:
	FALIGN_D46
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D14
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd30
	add	%i0, 64, %i0

2:
	FALIGN_D14
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D30
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, blkd46
	add	%i0, 64, %i0


	!
	! dribble out the last partial block
	!
blkd0:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d0, %d2, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd2:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d2, %d4, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd4:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d4, %d6, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd6:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d6, %d8, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd8:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d8, %d10, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd10:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d10, %d12, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd12:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d12, %d14, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd14:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	fsrc1	%d14, %d0
	ba,a,pt	%ncc, blkleft

blkd16:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d16, %d18, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd18:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d18, %d20, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd20:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d20, %d22, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd22:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d22, %d24, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd24:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d24, %d26, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd26:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d26, %d28, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd28:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d28, %d30, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd30:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	fsrc1	%d30, %d0
	ba,a,pt	%ncc, blkleft
blkd32:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d32, %d34, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd34:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d34, %d36, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd36:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d36, %d38, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd38:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d38, %d40, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd40:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d40, %d42, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd42:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d42, %d44, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd44:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	faligndata %d44, %d46, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
blkd46:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, blkdone
	fsrc1	%d46, %d0

blkleft:
1:
	ldd	[%l7], %d2
	add	%l7, 8, %l7
	subcc	%i4, 8, %i4
	faligndata %d0, %d2, %d8
	std	%d8, [%i0]
	blu,pn	%ncc, blkdone
	add	%i0, 8, %i0
	ldd	[%l7], %d0
	add	%l7, 8, %l7
	subcc	%i4, 8, %i4
	faligndata %d2, %d0, %d8
	std	%d8, [%i0]
	bgeu,pt	%ncc, 1b
	add	%i0, 8, %i0

blkdone:
	tst	%i2
	bz,pt	%ncc, .bcb_exit
	and	%l3, 0x4, %l3		! fprs.du = fprs.dl = 0

7:	ldub	[%i1], %i4
	inc	%i1
	inc	%i0
	deccc	%i2
	bgu,pt	%ncc, 7b
	  stb	  %i4, [%i0 - 1]

.bcb_exit:
	membar	#StoreLoad|#StoreStore
	btst	FPUSED_FLAG, %l6
	bz	%icc, 1f
	  and	%l6, COPY_FLAGS, %l1	! Store flags in %l1
					! We can't clear the flags from %l6 yet.
					! If there's an error, .copyerr will
					! need them

	ld	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2	! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz	%icc, 4f
	  nop

	! restore fpregs from stack
	membar	#Sync
	add	%fp, STACK_BIAS - 257, %o2
	and	%o2, -64, %o2
	ldda	[%o2]ASI_BLK_P, %d0
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d16
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d32
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d48
	membar	#Sync

	ba,pt	%ncc, 2f	
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO				! zero all of the fpregs
	wr	%o3, 0, %fprs		! restore fprs

2:	ldn	[THREAD_REG + T_LWP], %o2
	tst	%o2
	bnz,pt	%ncc, 1f
	  nop

	ldsb	[THREAD_REG + T_PREEMPT], %l0
	deccc	%l0
	bnz,pn	%ncc, 1f
	  stb	%l0, [THREAD_REG + T_PREEMPT]

	! Check for a kernel preemption request
	ldn	[THREAD_REG + T_CPU], %l0
	ldub	[%l0 + CPU_KPRUNRUN], %l0
	tst	%l0
	bnz,a,pt	%ncc, 1f	! Need to call kpreempt?
	  or	%l1, KPREEMPT_FLAG, %l1	! If so, set the flag

1:
	btst	BCOPY_FLAG, %l1
	bz,pn	%icc, 3f
	  andncc	%l6, COPY_FLAGS, %l6

	!
	! Here via bcopy. Check to see if the handler was NULL.
	! If so, just return quietly. Otherwise, reset the
	! handler and go home.
	! 
	bnz,pn	%ncc, 3f
	  nop

	!
	! Null handler.  Check for kpreempt flag, call if necessary,
	! then return.
	!
	btst	KPREEMPT_FLAG, %l1
	bz,pt	%icc, 2f
	  nop
	call	kpreempt
	  rdpr	%pil, %o0	! pass %pil
2:
	ret
	  restore	%g0, 0, %o0

	!
	! Here via kcopy or bcopy with a handler.Reset the
	! fault handler.
	!
3:
	membar	#Sync
	stn	%l6, [THREAD_REG + T_LOFAULT]	! restore old t_lofault

	! call kpreempt if necessary
	btst	KPREEMPT_FLAG, %l1
	bz,pt	%icc, 4f
	  nop
	call	kpreempt
	  rdpr	%pil, %o0
4:
	ret
	  restore	%g0, 0, %o0

.bcb_punt:
	!
	! use aligned transfers where possible
	!
	xor	%i0, %i1, %o4		! xor from and to address
	btst	7, %o4			! if lower three bits zero
	bz	%icc, .aldoubcp		! can align on double boundary
	.empty	! assembler complaints about label

	xor	%i0, %i1, %o4		! xor from and to address
	btst	3, %o4			! if lower two bits zero
	bz	%icc, .alwordcp		! can align on word boundary
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
	bz	%icc, .align_src_only
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
	!
	! FPUSED_FLAG will not have been set in any path leading to
	! this point. No need to deal with it.
	!
.cpdone:
	btst	BCOPY_FLAG, %l6
	bz,pn	%icc, 2f
	andncc	%l6, BCOPY_FLAG, %l6
	!
	! Here via bcopy. Check to see if the handler was NULL.
	! If so, just return quietly. Otherwise, reset the
	! handler and go home.
	!
	bnz,pn	%ncc, 2f
	nop
	!
	! Null handler.
	!
	ret
	restore %g0, 0, %o0
	!
	! Here via kcopy or bcopy with a handler.Reset the
	! fault handler.
	!
2:
  	membar	#Sync
	stn	%l6, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	ret
	restore	%g0, 0, %o0		! return (0)

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
	! get another window w/space for three aligned blocks of saved fpregs
	save	%sp, -SA(MINFRAME + 4*64), %sp

	! %i0 - source address (arg)
	! %i1 - destination address (arg)
	! %i2 - length of region (not arg)
	! %l0 - saved fprs
	! %l1 - pointer to saved fpregs

	rd	%fprs, %l0		! check for unused fp
	btst	FPRS_FEF, %l0
	bz	1f
	membar	#Sync

	! save in-use fpregs on stack
	add	%fp, STACK_BIAS - 193, %l1
	and	%l1, -64, %l1
	stda	%d0, [%l1]ASI_BLK_P
	add	%l1, 64, %l3
	stda	%d16, [%l3]ASI_BLK_P
	add	%l3, 64, %l3
	stda	%d32, [%l3]ASI_BLK_P
	membar	#Sync

1:	wr	%g0, FPRS_FEF, %fprs
	ldda	[%i0]ASI_BLK_P, %d0
	add	%i0, 64, %i0
	set	PAGESIZE - 64, %i2

2:	ldda	[%i0]ASI_BLK_P, %d16
	fsrc1	%d0, %d32
	fsrc1	%d2, %d34
	fsrc1	%d4, %d36
	fsrc1	%d6, %d38
	fsrc1	%d8, %d40
	fsrc1	%d10, %d42
	fsrc1	%d12, %d44
	fsrc1	%d14, %d46
	stda	%d32, [%i1]ASI_BLK_P
	add	%i0, 64, %i0
	subcc	%i2, 64, %i2
	bz,pn	%ncc, 3f
	add	%i1, 64, %i1
	ldda	[%i0]ASI_BLK_P, %d0
	fsrc1	%d16, %d32
	fsrc1	%d18, %d34
	fsrc1	%d20, %d36
	fsrc1	%d22, %d38
	fsrc1	%d24, %d40
	fsrc1	%d26, %d42
	fsrc1	%d28, %d44
	fsrc1	%d30, %d46
	stda	%d32, [%i1]ASI_BLK_P
	add	%i0, 64, %i0
	sub	%i2, 64, %i2
	ba,pt	%ncc, 2b
	add	%i1, 64, %i1

3:	membar	#Sync
	btst	FPRS_FEF, %l0
	bz	4f
	stda	%d16, [%i1]ASI_BLK_P

	! restore fpregs from stack
	membar	#Sync
	ldda	[%l1]ASI_BLK_P, %d0
	add	%l1, 64, %l3
	ldda	[%l3]ASI_BLK_P, %d16
	add	%l3, 64, %l3
	ldda	[%l3]ASI_BLK_P, %d32

4:	wr	%l0, 0, %fprs		! restore fprs
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
 * The only difference between default_copy{in,out} and
 * default_xcopy{in,out} is in the error handling routine they invoke
 * when a memory access error is seen. default_xcopyOP returns the errno
 * while default_copyOP returns -1 (see above). copy{in,out}_noerr set
 * a special flag (by oring the value 2 into the fault handler address)
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
 * the default limits are:
 *
 * single byte aligned - 900 (hw_copy_limit_1)
 * two byte aligned - 1800 (hw_copy_limit_2)
 * four byte aligned - 3600 (hw_copy_limit_4)
 * eight byte aligned - 7200 (hw_copy_limit_8)
 *
 * If the value for a particular limit is zero, the copy will be done
 * via the copy loops rather than VIS.
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
 * --> before we use VIS instructions.
 *
 * If count is less than or equal to SMALL_LIMIT (7) we
 * always do a byte for byte copy.
 *
 * If count is > SMALL_LIMIT, we check the alignment of the input
 * and output pointers. Based on the alignment we check count
 * against a soft limit of VIS_COPY_THRESHOLD (900 on spitfire). If
 * we're larger than VIS_COPY_THRESHOLD, we check against a limit based
 * on detected alignment. If we exceed the alignment value we copy
 * via VIS instructions.
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
 * There is one potential situation in which we start to do a VIS
 * copy but decide to punt and return to the copy loops. There is
 * (in the default configuration) a window of 256 bytes between
 * the single byte aligned copy limit and what VIS treats as its
 * minimum if floating point is in use in the calling app. We need
 * to be prepared to handle this. See the .small_copyOP label for
 * details.
 *
 * Fault handlers are invoked if we reference memory that has no
 * current mapping.  All forms share the same copyio_fault handler.
 * This routine handles fixing up the stack and general housecleaning.
 * Each copy operation has a simple fault handler that is then called
 * to do the work specific to the invidual operation.  The handlers
 * for default_copyOP and copyOP_noerr are found at the end of
 * default_copyout. The handlers for default_xcopyOP are found at the
 * end of xdefault_copyin.
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
	btst	FPUSED_FLAG, SAVED_LOFAULT
	bz	1f
	  andn	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT

	membar	#Sync

	ld	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2
	wr	%o2, 0, %gsr		! restore gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz	4f
	  nop

	! restore fpregs from stack
	membar	#Sync
	add	%fp, STACK_BIAS - 257, %o2
	and	%o2, -64, %o2
	ldda	[%o2]ASI_BLK_P, %d0
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d16
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d32
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d48
	membar	#Sync

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO				! zero all of the fpregs
	wr	%o3, 0, %fprs		! restore fprs

1:

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
	subcc	%o2, VIS_COPY_THRESHOLD, %o3
	bleu,pt	%ncc, .dcobcp
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
	subcc	%o2, VIS_COPY_THRESHOLD, %o3
	bleu,pt	%ncc, .dcos8
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
	subcc	%o2, VIS_COPY_THRESHOLD, %o3
	bleu,pt	%ncc, .dcos4
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
	!
	! Are we using the FP registers?
	!
	rd	%fprs, %o3			! check for unused fp
	btst	FPRS_FEF, %o3
	bnz	%icc, .copyout_fpregs_inuse
	nop
	!
	! We're going to go off and do a block copy.
	! Switch fault hendlers and grab a window. We
	! don't do a membar #Sync since we've done only
	! kernel data to this point.
	!
	stn	%o4, [THREAD_REG + T_LOFAULT]
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	!
	! %o3 is now %i3. Save original %fprs.
	!
	st	%i3, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET]
	ba,pt	%ncc, .do_block_copyout		! Not in use. Go off and do it.
	wr	%g0, FPRS_FEF, %fprs		! clear %fprs
	!
.copyout_fpregs_inuse:
	!
	! We're here if the FP regs are in use. Need to see if the request
	! exceeds our suddenly larger minimum.
	!
	cmp	%i2, VIS_COPY_THRESHOLD+(64*4) ! for large counts (larger
	bl	%ncc, .small_copyout
	  nop
	!
	! We're going to go off and do a block copy.
	! Change to the heavy duty fault handler and grab a window first.
	!
	stn	%o4, [THREAD_REG + T_LOFAULT]
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	st	%i3, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET]
	!
	! save in-use fpregs on stack
	!
	wr	%g0, FPRS_FEF, %fprs
	membar	#Sync
	add	%fp, STACK_BIAS - 257, %o2
	and	%o2, -64, %o2
	stda	%d0, [%o2]ASI_BLK_P
	add	%o2, 64, %o2
	stda	%d16, [%o2]ASI_BLK_P
	add	%o2, 64, %o2
	stda	%d32, [%o2]ASI_BLK_P
	add	%o2, 64, %o2
	stda	%d48, [%o2]ASI_BLK_P
	membar	#Sync

.do_block_copyout:
	membar	#StoreStore|#StoreLoad|#LoadStore

	rd	%gsr, %o2
	st	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]	! save gsr

	! Set the lower bit in the saved t_lofault to indicate
	! that we need to clear the %fprs register on the way
	! out
	or	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT 

	! Swap src/dst since the code below is memcpy code
	! and memcpy/bcopy have different calling sequences
	mov	%i1, %i5
	mov	%i0, %i1
	mov	%i5, %i0

!!! This code is nearly identical to the version in the sun4u
!!! libc_psr.  Most bugfixes made to that file should be
!!! merged into this routine.

	andcc	%i0, 7, %o3
	bz	%ncc, copyout_blkcpy
	sub	%o3, 8, %o3
	neg	%o3
	sub	%i2, %o3, %i2

	! Align Destination on double-word boundary

2:	ldub	[%i1], %o4
	inc	%i1
	stba	%o4, [%i0]ASI_USER
	deccc	%o3
	bgu	%ncc, 2b
	  inc	%i0
copyout_blkcpy:
	andcc	%i0, 63, %i3
	bz,pn	%ncc, copyout_blalign	! now block aligned
	sub	%i3, 64, %i3
	neg	%i3			! bytes till block aligned
	sub	%i2, %i3, %i2		! update %i2 with new count

	! Copy %i3 bytes till dst is block (64 byte) aligned. use
	! double word copies.

	alignaddr %i1, %g0, %g1
	ldd	[%g1], %d0
	add	%g1, 8, %g1
6:
	ldd	[%g1], %d2
	add	%g1, 8, %g1
	subcc	%i3, 8, %i3
	faligndata %d0, %d2, %d8
	stda	 %d8, [%i0]ASI_USER
	add	%i1, 8, %i1
	bz,pn	%ncc, copyout_blalign
	add	%i0, 8, %i0
	ldd	[%g1], %d0
	add	%g1, 8, %g1
	subcc	%i3, 8, %i3
	faligndata %d2, %d0, %d8
	stda	 %d8, [%i0]ASI_USER
	add	%i1, 8, %i1
	bgu,pn	%ncc, 6b
	add	%i0, 8, %i0
 
copyout_blalign:
	membar	#StoreLoad
	! %i2 = total length
	! %i3 = blocks	(length - 64) / 64
	! %i4 = doubles remaining  (length - blocks)
	sub	%i2, 64, %i3
	andn	%i3, 63, %i3
	sub	%i2, %i3, %i4
	andn	%i4, 7, %i4
	sub	%i4, 16, %i4
	sub	%i2, %i4, %i2
	sub	%i2, %i3, %i2

	andn	%i1, 0x3f, %l7		! blk aligned address
	alignaddr %i1, %g0, %g0		! gen %gsr

	srl	%i1, 3, %l5		! bits 3,4,5 are now least sig in  %l5
	andcc	%l5, 7, %i5		! mask everything except bits 1,2 3
	add	%i1, %i4, %i1
	add	%i1, %i3, %i1

	ldda	[%l7]ASI_BLK_P, %d0
	add	%l7, 64, %l7
	ldda	[%l7]ASI_BLK_P, %d16
	add	%l7, 64, %l7
	ldda	[%l7]ASI_BLK_P, %d32
	add	%l7, 64, %l7
	sub	%i3, 128, %i3

	! switch statement to get us to the right 8 byte blk within a
	! 64 byte block

	cmp	 %i5, 4
	bgeu,a	 copyout_hlf
	cmp	 %i5, 6
	cmp	 %i5, 2
	bgeu,a	 copyout_sqtr
	nop
	cmp	 %i5, 1
	be,a	 copyout_seg1
	nop
	ba,pt	 %ncc, copyout_seg0
	nop
copyout_sqtr:
	be,a	 copyout_seg2
	nop
	ba,pt	 %ncc, copyout_seg3
	nop

copyout_hlf:
	bgeu,a	 copyout_fqtr
	nop	 
	cmp	 %i5, 5
	be,a	 copyout_seg5
	nop
	ba,pt	 %ncc, copyout_seg4
	nop
copyout_fqtr:
	be,a	 copyout_seg6
	nop
	ba,pt	 %ncc, copyout_seg7
	nop
	
copyout_seg0:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D0
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D16
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D32
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyout_seg0

0:
	FALIGN_D16
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D32
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd0
	add	%i0, 64, %i0

1:
	FALIGN_D32
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D0
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd16
	add	%i0, 64, %i0

2:
	FALIGN_D0
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D16
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd32
	add	%i0, 64, %i0

copyout_seg1:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D2
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D18
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D34
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyout_seg1
0:
	FALIGN_D18
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D34
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd2
	add	%i0, 64, %i0

1:
	FALIGN_D34
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D2
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd18
	add	%i0, 64, %i0

2:
	FALIGN_D2
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D18
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd34
	add	%i0, 64, %i0

copyout_seg2:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D4
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D20
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D36
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyout_seg2

0:
	FALIGN_D20
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D36
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd4
	add	%i0, 64, %i0

1:
	FALIGN_D36
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D4
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd20
	add	%i0, 64, %i0

2:
	FALIGN_D4
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D20
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd36
	add	%i0, 64, %i0

copyout_seg3:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D6
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D22
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D38
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyout_seg3

0:
	FALIGN_D22
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D38
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd6
	add	%i0, 64, %i0

1:
	FALIGN_D38
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D6
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd22
	add	%i0, 64, %i0

2:
	FALIGN_D6
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D22
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd38
	add	%i0, 64, %i0

copyout_seg4:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D8
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D24
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D40
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyout_seg4

0:
	FALIGN_D24
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D40
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd8
	add	%i0, 64, %i0

1:
	FALIGN_D40
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D8
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd24
	add	%i0, 64, %i0

2:
	FALIGN_D8
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D24
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd40
	add	%i0, 64, %i0

copyout_seg5:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D10
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D26
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D42
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyout_seg5

0:
	FALIGN_D26
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D42
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd10
	add	%i0, 64, %i0

1:
	FALIGN_D42
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D10
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd26
	add	%i0, 64, %i0

2:
	FALIGN_D10
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D26
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd42
	add	%i0, 64, %i0

copyout_seg6:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D12
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D28
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D44
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyout_seg6

0:
	FALIGN_D28
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D44
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd12
	add	%i0, 64, %i0

1:
	FALIGN_D44
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D12
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd28
	add	%i0, 64, %i0

2:
	FALIGN_D12
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D28
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd44
	add	%i0, 64, %i0

copyout_seg7:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D14
	ldda	[%l7]ASI_BLK_P, %d0
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D30
	ldda	[%l7]ASI_BLK_P, %d16
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D46
	ldda	[%l7]ASI_BLK_P, %d32
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyout_seg7

0:
	FALIGN_D30
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D46
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd14
	add	%i0, 64, %i0

1:
	FALIGN_D46
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D14
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd30
	add	%i0, 64, %i0

2:
	FALIGN_D14
	stda	%d48, [%i0]ASI_BLK_AIUS
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D30
	stda	%d48, [%i0]ASI_BLK_AIUS
	ba,pt	%ncc, copyout_blkd46
	add	%i0, 64, %i0


	!
	! dribble out the last partial block
	!
copyout_blkd0:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d0, %d2, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd2:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d2, %d4, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd4:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d4, %d6, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd6:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d6, %d8, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd8:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d8, %d10, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd10:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d10, %d12, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd12:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d12, %d14, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd14:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	fsrc1	%d14, %d0
	ba,a,pt	%ncc, copyout_blkleft

copyout_blkd16:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d16, %d18, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd18:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d18, %d20, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd20:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d20, %d22, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd22:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d22, %d24, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd24:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d24, %d26, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd26:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d26, %d28, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd28:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d28, %d30, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd30:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	fsrc1	%d30, %d0
	ba,a,pt	%ncc, copyout_blkleft
copyout_blkd32:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d32, %d34, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd34:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d34, %d36, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd36:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d36, %d38, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd38:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d38, %d40, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd40:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d40, %d42, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd42:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d42, %d44, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd44:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	faligndata %d44, %d46, %d48
	stda	%d48, [%i0]ASI_USER
	add	%i0, 8, %i0
copyout_blkd46:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyout_blkdone
	fsrc1	%d46, %d0

copyout_blkleft:
1:
	ldd	[%l7], %d2
	add	%l7, 8, %l7
	subcc	%i4, 8, %i4
	faligndata %d0, %d2, %d8
	stda	%d8, [%i0]ASI_USER
	blu,pn	%ncc, copyout_blkdone
	add	%i0, 8, %i0
	ldd	[%l7], %d0
	add	%l7, 8, %l7
	subcc	%i4, 8, %i4
	faligndata %d2, %d0, %d8
	stda	%d8, [%i0]ASI_USER
	bgeu,pt	%ncc, 1b
	add	%i0, 8, %i0

copyout_blkdone:
	tst	%i2
	bz,pt	%ncc, .copyout_exit
	and	%l3, 0x4, %l3		! fprs.du = fprs.dl = 0

7:	ldub	[%i1], %i4
	inc	%i1
	stba	%i4, [%i0]ASI_USER
	inc	%i0
	deccc	%i2
	bgu	%ncc, 7b
	  nop

.copyout_exit:
	membar	#StoreLoad|#StoreStore
	btst	FPUSED_FLAG, SAVED_LOFAULT
	bz	1f
	  nop

	ld	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2
	wr	%o2, 0, %gsr		! restore gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz	4f
	  nop

	! restore fpregs from stack
	membar	#Sync
	add	%fp, STACK_BIAS - 257, %o2
	and	%o2, -64, %o2
	ldda	[%o2]ASI_BLK_P, %d0
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d16
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d32
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d48
	membar	#Sync

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO				! zero all of the fpregs
	wr	%o3, 0, %fprs		! restore fprs

1:
	andn	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT
	membar	#Sync			! sync error barrier
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
	subcc	%o2, VIS_COPY_THRESHOLD, %o3
	bleu,pt	%ncc, .dcibcp
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
	subcc	%o2, VIS_COPY_THRESHOLD, %o3
	bleu,pt	%ncc, .dcis8
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
	subcc	%o2, VIS_COPY_THRESHOLD, %o3
	bleu,pt	%ncc, .dcis4
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
	!
	! Are we using the FP registers?
	!
	rd	%fprs, %o3		! check for unused fp
	btst	FPRS_FEF, %o3
	bnz	%ncc, .copyin_fpregs_inuse
	nop
	!
	! We're going off to do a block copy.
	! Switch fault hendlers and grab a window. We
	! don't do a membar #Sync since we've done only
	! kernel data to this point.
	!
	stn	%o4, [THREAD_REG + T_LOFAULT]
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	!
	! %o3 is %i3 after the save...
	!
	st	%i3, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET]
	ba,pt	%ncc, .do_blockcopyin
	wr	%g0, FPRS_FEF, %fprs
.copyin_fpregs_inuse:
	!
	! We're here if the FP regs are in use. Need to see if the request
	! exceeds our suddenly larger minimum.
	!
	cmp	%i2, VIS_COPY_THRESHOLD+(64*4)
	bl	%ncc, .small_copyin
	nop
	!
	! We're going off and do a block copy.
	! Change to the heavy duty fault handler and grab a window first.
	! New handler is passed in
	!
	stn	%o4, [THREAD_REG + T_LOFAULT]
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	!
	! %o3 is now %i3
	!
	st	%i3, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET]

	! save in-use fpregs on stack
	wr	%g0, FPRS_FEF, %fprs
	membar	#Sync
	add	%fp, STACK_BIAS - 257, %o2
	and	%o2, -64, %o2
	stda	%d0, [%o2]ASI_BLK_P
	add	%o2, 64, %o2
	stda	%d16, [%o2]ASI_BLK_P
	add	%o2, 64, %o2
	stda	%d32, [%o2]ASI_BLK_P
	add	%o2, 64, %o2
	stda	%d48, [%o2]ASI_BLK_P
	membar	#Sync

.do_blockcopyin:
	membar	#StoreStore|#StoreLoad|#LoadStore

	rd	%gsr, %o2
	st	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]	! save gsr

	! Set the lower bit in the saved t_lofault to indicate
	! that we need to clear the %fprs register on the way
	! out
	or	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT

	! Swap src/dst since the code below is memcpy code
	! and memcpy/bcopy have different calling sequences
	mov	%i1, %i5
	mov	%i0, %i1
	mov	%i5, %i0

!!! This code is nearly identical to the version in the sun4u
!!! libc_psr.  Most bugfixes made to that file should be
!!! merged into this routine.

	andcc	%i0, 7, %o3
	bz	copyin_blkcpy
	sub	%o3, 8, %o3
	neg	%o3
	sub	%i2, %o3, %i2

	! Align Destination on double-word boundary

2:	lduba	[%i1]ASI_USER, %o4
	inc	%i1
	inc	%i0
	deccc	%o3
	bgu	%ncc, 2b
	stb	%o4, [%i0-1]
copyin_blkcpy:
	andcc	%i0, 63, %i3
	bz,pn	%ncc, copyin_blalign	! now block aligned
	sub	%i3, 64, %i3
	neg	%i3			! bytes till block aligned
	sub	%i2, %i3, %i2		! update %i2 with new count

	! Copy %i3 bytes till dst is block (64 byte) aligned. use
	! double word copies.

	alignaddr %i1, %g0, %g1
	ldda	[%g1]ASI_USER, %d0
	add	%g1, 8, %g1
6:
	ldda	[%g1]ASI_USER, %d2
	add	%g1, 8, %g1
	subcc	%i3, 8, %i3
	faligndata %d0, %d2, %d8
	std	%d8, [%i0]
	add	%i1, 8, %i1
	bz,pn	%ncc, copyin_blalign
	add	%i0, 8, %i0
	ldda	[%g1]ASI_USER, %d0
	add	%g1, 8, %g1
	subcc	%i3, 8, %i3
	faligndata %d2, %d0, %d8
	std	%d8, [%i0]
	add	%i1, 8, %i1
	bgu,pn	%ncc, 6b
	add	%i0, 8, %i0
 
copyin_blalign:
	membar	#StoreLoad
	! %i2 = total length
	! %i3 = blocks	(length - 64) / 64
	! %i4 = doubles remaining  (length - blocks)
	sub	%i2, 64, %i3
	andn	%i3, 63, %i3
	sub	%i2, %i3, %i4
	andn	%i4, 7, %i4
	sub	%i4, 16, %i4
	sub	%i2, %i4, %i2
	sub	%i2, %i3, %i2

	andn	%i1, 0x3f, %l7		! blk aligned address
	alignaddr %i1, %g0, %g0		! gen %gsr

	srl	%i1, 3, %l5		! bits 3,4,5 are now least sig in  %l5
	andcc	%l5, 7, %i5		! mask everything except bits 1,2 3
	add	%i1, %i4, %i1
	add	%i1, %i3, %i1

	ldda	[%l7]ASI_BLK_AIUS, %d0
	add	%l7, 64, %l7
	ldda	[%l7]ASI_BLK_AIUS, %d16
	add	%l7, 64, %l7
	ldda	[%l7]ASI_BLK_AIUS, %d32
	add	%l7, 64, %l7
	sub	%i3, 128, %i3

	! switch statement to get us to the right 8 byte blk within a
	! 64 byte block

	cmp	 %i5, 4
	bgeu,a	 copyin_hlf
	cmp	 %i5, 6
	cmp	 %i5, 2
	bgeu,a	 copyin_sqtr
	nop
	cmp	 %i5, 1
	be,a	 copyin_seg1
	nop
	ba,pt	 %ncc, copyin_seg0
	nop
copyin_sqtr:
	be,a	 copyin_seg2
	nop
	ba,pt	 %ncc, copyin_seg3
	nop

copyin_hlf:
	bgeu,a	 copyin_fqtr
	nop	 
	cmp	 %i5, 5
	be,a	 copyin_seg5
	nop
	ba,pt	 %ncc, copyin_seg4
	nop
copyin_fqtr:
	be,a	 copyin_seg6
	nop
	ba,pt	 %ncc, copyin_seg7
	nop
	
copyin_seg0:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D0
	ldda	[%l7]ASI_BLK_AIUS, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D16
	ldda	[%l7]ASI_BLK_AIUS, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D32
	ldda	[%l7]ASI_BLK_AIUS, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyin_seg0

0:
	FALIGN_D16
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D32
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd0
	add	%i0, 64, %i0

1:
	FALIGN_D32
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D0
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd16
	add	%i0, 64, %i0

2:
	FALIGN_D0
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D16
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd32
	add	%i0, 64, %i0

copyin_seg1:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D2
	ldda	[%l7]ASI_BLK_AIUS, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D18
	ldda	[%l7]ASI_BLK_AIUS, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D34
	ldda	[%l7]ASI_BLK_AIUS, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyin_seg1
0:
	FALIGN_D18
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D34
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd2
	add	%i0, 64, %i0

1:
	FALIGN_D34
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D2
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd18
	add	%i0, 64, %i0

2:
	FALIGN_D2
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D18
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd34
	add	%i0, 64, %i0
copyin_seg2:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D4
	ldda	[%l7]ASI_BLK_AIUS, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D20
	ldda	[%l7]ASI_BLK_AIUS, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D36
	ldda	[%l7]ASI_BLK_AIUS, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyin_seg2

0:
	FALIGN_D20
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D36
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd4
	add	%i0, 64, %i0

1:
	FALIGN_D36
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D4
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd20
	add	%i0, 64, %i0

2:
	FALIGN_D4
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D20
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd36
	add	%i0, 64, %i0

copyin_seg3:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D6
	ldda	[%l7]ASI_BLK_AIUS, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D22
	ldda	[%l7]ASI_BLK_AIUS, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D38
	ldda	[%l7]ASI_BLK_AIUS, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyin_seg3

0:
	FALIGN_D22
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D38
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd6
	add	%i0, 64, %i0

1:
	FALIGN_D38
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D6
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd22
	add	%i0, 64, %i0

2:
	FALIGN_D6
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D22
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd38
	add	%i0, 64, %i0

copyin_seg4:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D8
	ldda	[%l7]ASI_BLK_AIUS, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D24
	ldda	[%l7]ASI_BLK_AIUS, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D40
	ldda	[%l7]ASI_BLK_AIUS, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyin_seg4

0:
	FALIGN_D24
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D40
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd8
	add	%i0, 64, %i0

1:
	FALIGN_D40
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D8
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd24
	add	%i0, 64, %i0

2:
	FALIGN_D8
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D24
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd40
	add	%i0, 64, %i0

copyin_seg5:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D10
	ldda	[%l7]ASI_BLK_AIUS, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D26
	ldda	[%l7]ASI_BLK_AIUS, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D42
	ldda	[%l7]ASI_BLK_AIUS, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyin_seg5

0:
	FALIGN_D26
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D42
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd10
	add	%i0, 64, %i0

1:
	FALIGN_D42
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D10
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd26
	add	%i0, 64, %i0

2:
	FALIGN_D10
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D26
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd42
	add	%i0, 64, %i0

copyin_seg6:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D12
	ldda	[%l7]ASI_BLK_AIUS, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D28
	ldda	[%l7]ASI_BLK_AIUS, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D44
	ldda	[%l7]ASI_BLK_AIUS, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyin_seg6

0:
	FALIGN_D28
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D44
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd12
	add	%i0, 64, %i0

1:
	FALIGN_D44
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D12
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd28
	add	%i0, 64, %i0

2:
	FALIGN_D12
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D28
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd44
	add	%i0, 64, %i0

copyin_seg7:
	! 1st chunk - %d0 low, %d16 high, %d32 pre, %d48 dst
	FALIGN_D14
	ldda	[%l7]ASI_BLK_AIUS, %d0
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 0f
	add	%i0, 64, %i0
	! 2nd chunk -  %d0 pre, %d16 low, %d32 high, %d48 dst
	FALIGN_D30
	ldda	[%l7]ASI_BLK_AIUS, %d16
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 1f
	add	%i0, 64, %i0
	! 3rd chunk -  %d0 high, %d16 pre, %d32 low, %d48 dst
	FALIGN_D46
	ldda	[%l7]ASI_BLK_AIUS, %d32
	stda	%d48, [%i0]ASI_BLK_P
	add	%l7, 64, %l7
	subcc	%i3, 64, %i3
	bz,pn	%ncc, 2f
	add	%i0, 64, %i0
	ba,a,pt	%ncc, copyin_seg7

0:
	FALIGN_D30
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D46
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd14
	add	%i0, 64, %i0

1:
	FALIGN_D46
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D14
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd30
	add	%i0, 64, %i0

2:
	FALIGN_D14
	stda	%d48, [%i0]ASI_BLK_P
	add	%i0, 64, %i0
	membar	#Sync
	FALIGN_D30
	stda	%d48, [%i0]ASI_BLK_P
	ba,pt	%ncc, copyin_blkd46
	add	%i0, 64, %i0


	!
	! dribble out the last partial block
	!
copyin_blkd0:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d0, %d2, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd2:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d2, %d4, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd4:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d4, %d6, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd6:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d6, %d8, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd8:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d8, %d10, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd10:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d10, %d12, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd12:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d12, %d14, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd14:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	fsrc1	%d14, %d0
	ba,a,pt	%ncc, copyin_blkleft

copyin_blkd16:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d16, %d18, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd18:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d18, %d20, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd20:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d20, %d22, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd22:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d22, %d24, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd24:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d24, %d26, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd26:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d26, %d28, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd28:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d28, %d30, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd30:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	fsrc1	%d30, %d0
	ba,a,pt	%ncc, copyin_blkleft
copyin_blkd32:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d32, %d34, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd34:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d34, %d36, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd36:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d36, %d38, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd38:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d38, %d40, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd40:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d40, %d42, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd42:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d42, %d44, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd44:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	faligndata %d44, %d46, %d48
	std	%d48, [%i0]
	add	%i0, 8, %i0
copyin_blkd46:
	subcc	%i4, 8, %i4
	blu,pn	%ncc, copyin_blkdone
	fsrc1	%d46, %d0

copyin_blkleft:
1:
	ldda	[%l7]ASI_USER, %d2
	add	%l7, 8, %l7
	subcc	%i4, 8, %i4
	faligndata %d0, %d2, %d8
	std	%d8, [%i0]
	blu,pn	%ncc, copyin_blkdone
	add	%i0, 8, %i0
	ldda	[%l7]ASI_USER, %d0
	add	%l7, 8, %l7
	subcc	%i4, 8, %i4
	faligndata %d2, %d0, %d8
	std	%d8, [%i0]
	bgeu,pt	%ncc, 1b
	add	%i0, 8, %i0

copyin_blkdone:
	tst	%i2
	bz,pt	%ncc, .copyin_exit
	and	%l3, 0x4, %l3		! fprs.du = fprs.dl = 0

7:	lduba	[%i1]ASI_USER, %i4
	inc	%i1
	inc	%i0
	deccc	%i2
	bgu	%ncc, 7b
	  stb	  %i4, [%i0 - 1]

.copyin_exit:
	membar	#StoreLoad|#StoreStore
	btst	FPUSED_FLAG, SAVED_LOFAULT
	bz	%icc, 1f
	  nop

	ld	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2	! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz	%icc, 4f
	  nop

	! restore fpregs from stack
	membar	#Sync
	add	%fp, STACK_BIAS - 257, %o2
	and	%o2, -64, %o2
	ldda	[%o2]ASI_BLK_P, %d0
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d16
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d32
	add	%o2, 64, %o2
	ldda	[%o2]ASI_BLK_P, %d48
	membar	#Sync

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO				! zero all of the fpregs
	wr	%o3, 0, %fprs		! restore fprs

1:
	andn	SAVED_LOFAULT, FPUSED_FLAG, SAVED_LOFAULT
	membar	#Sync				! sync error barrier
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
	DGDEF(use_hw_copyio)
	.word	1
	DGDEF(use_hw_bzero)
	.word	1
	DGDEF(hw_copy_limit_1)
	.word	0
	DGDEF(hw_copy_limit_2)
	.word	0
	DGDEF(hw_copy_limit_4)
	.word	0
	DGDEF(hw_copy_limit_8)
	.word	0

	.align	64
	.section ".text"


/*
 * hwblkclr - clears block-aligned, block-multiple-sized regions that are
 * longer than 256 bytes in length using spitfire's block stores.  If
 * the criteria for using this routine are not met then it calls bzero
 * and returns 1.  Otherwise 0 is returned indicating success.
 * Caller is responsible for ensuring use_hw_bzero is true and that
 * kpreempt_disable() has been called.
 */
	! %i0 - start address
	! %i1 - length of region (multiple of 64)
	! %l0 - saved fprs
	! %l1 - pointer to saved %d0 block
	! %l2 - saved curthread->t_lwp

	ENTRY(hwblkclr)
	! get another window w/space for one aligned block of saved fpregs
	save	%sp, -SA(MINFRAME + 2*64), %sp

	! Must be block-aligned
	andcc	%i0, (64-1), %g0
	bnz,pn	%ncc, 1f
	  nop

	! ... and must be 256 bytes or more
	cmp	%i1, 256
	blu,pn	%ncc, 1f
	  nop

	! ... and length must be a multiple of 64
	andcc	%i1, (64-1), %g0
	bz,pn	%ncc, 2f
	  nop

1:	! punt, call bzero but notify the caller that bzero was used
	mov	%i0, %o0
	call	bzero
	  mov	%i1, %o1
	ret
	restore	%g0, 1, %o0	! return (1) - did not use block operations

2:	rd	%fprs, %l0		! check for unused fp
	btst	FPRS_FEF, %l0
	bz	1f
	  nop

	! save in-use fpregs on stack
	membar	#Sync
	add	%fp, STACK_BIAS - 65, %l1
	and	%l1, -64, %l1
	stda	%d0, [%l1]ASI_BLK_P

1:	membar	#StoreStore|#StoreLoad|#LoadStore
	wr	%g0, FPRS_FEF, %fprs
	wr	%g0, ASI_BLK_P, %asi

	! Clear block
	fzero	%d0
	fzero	%d2
	fzero	%d4
	fzero	%d6
	fzero	%d8
	fzero	%d10
	fzero	%d12
	fzero	%d14

	mov	256, %i3
	ba	.pz_doblock
	  nop

.pz_blkstart:	
      ! stda	%d0, [%i0+192]%asi  ! in dly slot of branch that got us here
	stda	%d0, [%i0+128]%asi
	stda	%d0, [%i0+64]%asi
	stda	%d0, [%i0]%asi
.pz_zinst:
	add	%i0, %i3, %i0
	sub	%i1, %i3, %i1
.pz_doblock:
	cmp	%i1, 256
	bgeu,a	%ncc, .pz_blkstart
	  stda	%d0, [%i0+192]%asi

	cmp	%i1, 64
	blu	%ncc, .pz_finish
	
	andn	%i1, (64-1), %i3
	srl	%i3, 4, %i2		! using blocks, 1 instr / 16 words
	set	.pz_zinst, %i4
	sub	%i4, %i2, %i4
	jmp	%i4
	  nop

.pz_finish:
	membar	#Sync
	btst	FPRS_FEF, %l0
	bz,a	.pz_finished
	  wr	%l0, 0, %fprs		! restore fprs

	! restore fpregs from stack
	ldda	[%l1]ASI_BLK_P, %d0
	membar	#Sync
	wr	%l0, 0, %fprs		! restore fprs

.pz_finished:
	ret
	restore	%g0, 0, %o0		! return (bzero or not)
	SET_SIZE(hwblkclr)

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
