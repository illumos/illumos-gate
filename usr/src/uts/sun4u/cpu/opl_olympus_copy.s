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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
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
 * bcopy/copyin/copyout routines.
 *
 * On entry:
 *
 * 	! Determine whether to use the FP register version
 * 	! or the leaf routine version depending on size
 * 	! of copy and flags.  Set up error handling accordingly.
 *	! The transition point depends on whether the src and
 * 	! dst addresses can be aligned to long word, word,
 * 	! half word, or byte boundaries.
 *	!
 *	! WARNING: <Register usage convention>
 *	! For FP version, %l6 holds previous error handling and
 *	! a flag: TRAMP_FLAG (low bits)
 *	! for leaf routine version, %o4 holds those values.
 *	! So either %l6 or %o4 is reserved and not available for
 *	! any other use.
 *
 * 	if (length <= VIS_COPY_THRESHOLD) 	! start with a quick test
 * 		go to small_copy;		! to speed short copies
 *
 * 	! src, dst long word alignable
 * 		if (hw_copy_limit_8 == 0) 	! hw_copy disabled
 * 			go to small_copy;
 *		if (length <= hw_copy_limit_8)
 * 			go to small_copy;
 * 		go to FPBLK_copy;
 * 	}
 * 	if (src,dst not alignable) {
 * 		if (hw_copy_limit_1 == 0) 	! hw_copy disabled
 * 			go to small_copy;
 *		if (length <= hw_copy_limit_1)
 * 			go to small_copy;
 * 		go to FPBLK_copy;
 * 	}
 * 	if (src,dst halfword alignable) {
 * 		if (hw_copy_limit_2 == 0) 	! hw_copy disabled
 * 			go to small_copy;
 *		if (length <= hw_copy_limit_2)
 * 			go to small_copy;
 * 		go to FPBLK_copy;
 * 	}
 * 	if (src,dst word alignable) {
 * 		if (hw_copy_limit_4 == 0) 	! hw_copy disabled
 * 			go to small_copy;
 *		if (length <= hw_copy_limit_4)
 * 			go to small_copy;
 * 		go to FPBLK_copy;
 * 	}
 *
 * small_copy:
 *	Setup_leaf_rtn_error_handler; 		! diffs for each entry point
 *
 *	if (count <= 3)				! fast path for tiny copies
 *		go to sm_left;			! special finish up code
 *	else
 *		if (count > CHKSIZE)		! medium sized copies
 *			go to sm_med		! tuned by alignment
 *		if(src&dst not both word aligned) {
 *	sm_movebytes:
 *			move byte by byte in 4-way unrolled loop
 *			fall into sm_left;
 *	sm_left:
 *			move 0-3 bytes byte at a time as needed.
 *			restore error handler and exit.
 *
 * 		} else {	! src&dst are word aligned
 *			check for at least 8 bytes left,
 *			move word at a time, unrolled by 2
 *			when fewer than 8 bytes left,
 *	sm_half:	move half word at a time while 2 or more bytes left
 *	sm_byte:	move final byte if necessary
 *	sm_exit:
 *			restore error handler and exit.
 *		}
 *
 * ! Medium length cases with at least CHKSIZE bytes available
 * ! method: line up src and dst as best possible, then
 * ! move data in 4-way unrolled loops.
 *
 * sm_med:
 *	if(src&dst unalignable)
 * 		go to sm_movebytes
 *	if(src&dst halfword alignable)
 *		go to sm_movehalf
 *	if(src&dst word alignable)
 *		go to sm_moveword
 * ! fall into long word movement
 *	move bytes until src is word aligned
 *	if not long word aligned, move a word
 *	move long words in 4-way unrolled loop until < 32 bytes left
 *      move long words in 1-way unrolled loop until < 8 bytes left
 *	if zero bytes left, goto sm_exit
 *	if one byte left, go to sm_byte
 *	else go to sm_half
 *
 * sm_moveword:
 *	move bytes until src is word aligned
 *	move words in 4-way unrolled loop until < 16 bytes left
 *      move words in 1-way unrolled loop until < 4 bytes left
 *	if zero bytes left, goto sm_exit
 *	if one byte left, go to sm_byte
 *	else go to sm_half
 *
 * sm_movehalf:
 *	move a byte if needed to align src on halfword
 *	move halfwords in 4-way unrolled loop until < 8 bytes left
 *	if zero bytes left, goto sm_exit
 *	if one byte left, go to sm_byte
 *	else go to sm_half
 *
 *
 * FPBLK_copy:
 * 	%l6 = curthread->t_lofault;
 * 	if (%l6 != NULL) {
 * 		membar #Sync
 * 		curthread->t_lofault = .copyerr;
 * 		caller_error_handler = TRUE             ! %l6 |= 2
 * 	}
 *
 *	! for FPU testing we must not migrate cpus
 * 	if (curthread->t_lwp == NULL) {
 *		! Kernel threads do not have pcb's in which to store
 *		! the floating point state, so disallow preemption during
 *		! the copy.  This also prevents cpu migration.
 * 		kpreempt_disable(curthread);
 *	} else {
 *		thread_nomigrate();
 *	}
 *
 * 	old_fprs = %fprs;
 * 	old_gsr = %gsr;
 * 	if (%fprs.fef) {
 * 		%fprs.fef = 1;
 * 		save current fpregs on stack using blockstore
 * 	} else {
 * 		%fprs.fef = 1;
 * 	}
 *
 *
 * 	do_blockcopy_here;
 *
 * In lofault handler:
 *	curthread->t_lofault = .copyerr2;
 *	Continue on with the normal exit handler
 *
 * On normal exit:
 * 	%gsr = old_gsr;
 * 	if (old_fprs & FPRS_FEF)
 * 		restore fpregs from stack using blockload
 *	else
 *		zero fpregs
 * 	%fprs = old_fprs;
 * 	membar #Sync
 * 	curthread->t_lofault = (%l6 & ~3);
 *	! following test omitted from copyin/copyout as they
 *	! will always have a current thread
 * 	if (curthread->t_lwp == NULL)
 *		kpreempt_enable(curthread);
 *	else
 *		thread_allowmigrate();
 * 	return (0)
 *
 * In second lofault handler (.copyerr2):
 *	We've tried to restore fp state from the stack and failed.  To
 *	prevent from returning with a corrupted fp state, we will panic.
 */

/*
 * Comments about optimization choices
 *
 * The initial optimization decision in this code is to determine
 * whether to use the FP registers for a copy or not.  If we don't
 * use the FP registers, we can execute the copy as a leaf routine,
 * saving a register save and restore.  Also, less elaborate setup
 * is required, allowing short copies to be completed more quickly.
 * For longer copies, especially unaligned ones (where the src and
 * dst do not align to allow simple ldx,stx operation), the FP
 * registers allow much faster copy operations.
 *
 * The estimated extra cost of the FP path will vary depending on
 * src/dst alignment, dst offset from the next 64 byte FPblock store
 * boundary, remaining src data after the last full dst cache line is
 * moved whether the FP registers need to be saved, and some other
 * minor issues.  The average additional overhead is estimated to be
 * 400 clocks.  Since each non-repeated/predicted tst and branch costs
 * around 10 clocks, elaborate calculation would slow down to all
 * longer copies and only benefit a small portion of medium sized
 * copies.  Rather than incur such cost, we chose fixed transition
 * points for each of the alignment choices.
 *
 * For the inner loop, here is a comparison of the per cache line
 * costs for each alignment when src&dst are in cache:
 *
 * byte aligned:  108 clocks slower for non-FPBLK
 * half aligned:   44 clocks slower for non-FPBLK
 * word aligned:   12 clocks slower for non-FPBLK
 * long aligned:    4 clocks >>faster<< for non-FPBLK
 *
 * The long aligned loop runs faster because it does no prefetching.
 * That wins if the data is not in cache or there is too little
 * data to gain much benefit from prefetching.  But when there
 * is more data and that data is not in cache, failing to prefetch
 * can run much slower.  In addition, there is a 2 Kbyte store queue
 * which will cause the non-FPBLK inner loop to slow for larger copies.
 * The exact tradeoff is strongly load and application dependent, with
 * increasing risk of a customer visible performance regression if the
 * non-FPBLK code is used for larger copies. Studies of synthetic in-cache
 * vs out-of-cache copy tests in user space suggest 1024 bytes as a safe
 * upper limit for the non-FPBLK code.  To minimize performance regression
 * risk while still gaining the primary benefits of the improvements to
 * the non-FPBLK code, we set an upper bound of 1024 bytes for the various
 * hw_copy_limit_*.  Later experimental studies using different values
 * of hw_copy_limit_* can be used to make further adjustments if
 * appropriate.
 *
 * hw_copy_limit_1 = src and dst are byte aligned but not halfword aligned
 * hw_copy_limit_2 = src and dst are halfword aligned but not word aligned
 * hw_copy_limit_4 = src and dst are word aligned but not longword aligned
 * hw_copy_limit_8 = src and dst are longword aligned
 *
 * To say that src and dst are word aligned means that after
 * some initial alignment activity of moving 0 to 3 bytes,
 * both the src and dst will be on word boundaries so that
 * word loads and stores may be used.
 *
 * Default values at May,2005 are:
 * hw_copy_limit_1 =  256
 * hw_copy_limit_2 =  512
 * hw_copy_limit_4 = 1024
 * hw_copy_limit_8 = 1024 (or 1536 on some systems)
 *
 *
 * If hw_copy_limit_? is set to zero, then use of FPBLK copy is
 * disabled for that alignment choice.
 * If hw_copy_limit_? is set to a value between 1 and VIS_COPY_THRESHOLD (256)
 * the value of VIS_COPY_THRESHOLD is used.
 * It is not envisioned that hw_copy_limit_? will be changed in the field
 * It is provided to allow for disabling FPBLK copies and to allow
 * easy testing of alternate values on future HW implementations
 * that might have different cache sizes, clock rates or instruction
 * timing rules.
 *
 * Our first test for FPBLK copies vs non-FPBLK copies checks a minimum
 * threshold to speedup all shorter copies (less than 256).  That
 * saves an alignment test, memory reference, and enabling test
 * for all short copies, or an estimated 24 clocks.
 *
 * The order in which these limits are checked does matter since each
 * non-predicted tst and branch costs around 10 clocks.
 * If src and dst are randomly selected addresses,
 * 4 of 8 will not be alignable.
 * 2 of 8 will be half word alignable.
 * 1 of 8 will be word alignable.
 * 1 of 8 will be long word alignable.
 * But, tests on running kernels show that src and dst to copy code
 * are typically not on random alignments.  Structure copies and
 * copies of larger data sizes are often on long word boundaries.
 * So we test the long word alignment case first, then
 * the byte alignment, then halfword, then word alignment.
 *
 * Several times, tests for length are made to split the code
 * into subcases.  These tests often allow later tests to be
 * avoided.  For example, within the non-FPBLK copy, we first
 * check for tiny copies of 3 bytes or less.  That allows us
 * to use a 4-way unrolled loop for the general byte copy case
 * without a test on loop entry.
 * We subdivide the non-FPBLK case further into CHKSIZE bytes and less
 * vs longer cases.  For the really short case, we don't attempt
 * align src and dst.  We try to minimize special case tests in
 * the shortest loops as each test adds a significant percentage
 * to the total time.
 *
 * For the medium sized cases, we allow ourselves to adjust the
 * src and dst alignment and provide special cases for each of
 * the four adjusted alignment cases. The CHKSIZE that was used
 * to decide between short and medium size was chosen to be 39
 * as that allows for the worst case of 7 bytes of alignment
 * shift and 4 times 8 bytes for the first long word unrolling.
 * That knowledge saves an initial test for length on entry into
 * the medium cases.  If the general loop unrolling factor were
 * to be increases, this number would also need to be adjusted.
 *
 * For all cases in the non-FPBLK code where it is known that at
 * least 4 chunks of data are available for movement, the
 * loop is unrolled by four.  This 4-way loop runs in 8 clocks
 * or 2 clocks per data element.
 *
 * Instruction alignment is forced by used of .align 16 directives
 * and nops which are not executed in the code.  This
 * combination of operations shifts the alignment of following
 * loops to insure that loops are aligned so that their instructions
 * fall within the minimum number of 4 instruction fetch groups.
 * If instructions are inserted or removed between the .align
 * instruction and the unrolled loops, then the alignment needs
 * to be readjusted.  Misaligned loops can add a clock per loop
 * iteration to the loop timing.
 *
 * In a few cases, code is duplicated to avoid a branch.  Since
 * a non-predicted tst and branch takes 10 clocks, this savings
 * is judged an appropriate time-space tradeoff.
 *
 * Within the FPBLK-code, the prefetch method in the inner
 * loop needs to be explained as it is not standard.  Two
 * prefetches are issued for each cache line instead of one.
 * The primary one is at the maximum reach of 8 cache lines.
 * Most of the time, that maximum prefetch reach gives the
 * cache line more time to reach the processor for systems with
 * higher processor clocks.  But, sometimes memory interference
 * can cause that prefetch to be dropped.  Putting a second
 * prefetch at a reach of 5 cache lines catches the drops
 * three iterations later and shows a measured improvement
 * in performance over any similar loop with a single prefetch.
 * The prefetches are placed in the loop so they overlap with
 * non-memory instructions, so that there is no extra cost
 * when the data is already in-cache.
 *
 */

/*
 * Notes on preserving existing fp state and on membars.
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
 * When we have finished fp copy (with it's repeated block stores)
 * we must membar #Sync so that our block stores may complete before
 * we either restore the original fp state into the fp registers or
 * return to a caller which may initiate other fp operations that could
 * modify the fp regs we used before the block stores complete.
 *
 * Synchronous faults (eg, unresolvable DMMU miss) that occur while
 * t_lofault is not NULL will not panic but will instead trampoline
 * to the registered lofault handler.  There is no need for any
 * membars for these - eg, our store to t_lofault will always be visible to
 * ourselves and it is our cpu which will take any trap.
 *
 * Asynchronous faults (eg, uncorrectable ECC error from memory) that occur
 * while t_lofault is not NULL will also not panic.  Since we're copying
 * to or from userland the extent of the damage is known - the destination
 * buffer is incomplete.  So trap handlers will trampoline to the lofault
 * handler in this case which should take some form of error action to
 * avoid using the incomplete buffer.  The trap handler also flags the
 * fault so that later return-from-trap handling (for the trap that brought
 * this thread into the kernel in the first place) can notify the process
 * and reboot the system (or restart the service with Greenline/Contracts).
 *
 * Asynchronous faults (eg, uncorrectable ECC error from memory) can
 * result in deferred error traps - the trap is taken sometime after
 * the event and the trap PC may not be the PC of the faulting access.
 * Delivery of such pending traps can be forced by a membar #Sync, acting
 * as an "error barrier" in this role.  To accurately apply the user/kernel
 * separation described in the preceding paragraph we must force delivery
 * of deferred traps affecting kernel state before we install a lofault
 * handler (if we interpose a new lofault handler on an existing one there
 * is no need to repeat this), and we must force delivery of deferred
 * errors affecting the lofault-protected region before we clear t_lofault.
 * Failure to do so results in lost kernel state being interpreted as
 * affecting a copyin/copyout only, or of an error that really only
 * affects copy data being interpreted as losing kernel state.
 *
 * Since the copy operations may preserve and later restore floating
 * point state that does not belong to the caller (see examples above),
 * we must be careful in how we do this in order to prevent corruption
 * of another program.
 *
 * To make sure that floating point state is always saved and restored
 * correctly, the following "big rules" must be followed when the floating
 * point registers will be used:
 *
 * 1. %l6 always holds the caller's lofault handler.  Also in this register,
 *    Bit 1 (FPUSED_FLAG) indicates that the floating point registers are in
 *    use.  Bit 2 (TRAMP_FLAG) indicates that the call was to bcopy, and a
 *    lofault handler was set coming in.
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
 *    particular, any calls to FP_ALLOWMIGRATE, which could result in a call
 *    to kpreempt(), should not be made until after the lofault handler has
 *    been restored.
 */

/*
 * VIS_COPY_THRESHOLD indicates the minimum number of bytes needed
 * to "break even" using FP/VIS-accelerated memory operations.
 * The FPBLK code assumes a minimum number of bytes are available
 * to be moved on entry.  Check that code carefully before
 * reducing VIS_COPY_THRESHOLD below 256.
 */
/*
 * This shadows sys/machsystm.h which can't be included due to the lack of
 * _ASM guards in include files it references. Change it here, change it there.
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
 * Number of outstanding prefetches.
 * first prefetch moves data from L2 to L1 (n_reads)
 * second prefetch moves data from memory to L2 (one_read)
 */
#define	OLYMPUS_C_PREFETCH	24
#define	OLYMPUS_C_2ND_PREFETCH	12

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
 * FZEROQ1Q3: Zero quadrants 1 and 3, ie %f0 - %f15 and %f32 - %f47
 * FZEROQ2Q4: Zero quadrants 2 and 4, ie %f16 - %f31 and %f48 - %f63
 *
 * The instructions below are quicker than repeated fzero instructions
 * since they can dispatch down two fp pipelines.
 */
#define	FZEROQ1Q3			\
	fzero	%f0			;\
	fmovd	%f0, %f2		;\
	fmovd	%f0, %f4		;\
	fmovd	%f0, %f6		;\
	fmovd	%f0, %f8		;\
	fmovd	%f0, %f10		;\
	fmovd	%f0, %f12		;\
	fmovd	%f0, %f14		;\
	fmovd	%f0, %f32		;\
	fmovd	%f0, %f34		;\
	fmovd	%f0, %f36		;\
	fmovd	%f0, %f38		;\
	fmovd	%f0, %f40		;\
	fmovd	%f0, %f42		;\
	fmovd	%f0, %f44		;\
	fmovd	%f0, %f46

#define	FZEROQ2Q4			\
	fzero	%f16			;\
	fmovd	%f0, %f18		;\
	fmovd	%f0, %f20		;\
	fmovd	%f0, %f22		;\
	fmovd	%f0, %f24		;\
	fmovd	%f0, %f26		;\
	fmovd	%f0, %f28		;\
	fmovd	%f0, %f30		;\
	fmovd	%f0, %f48		;\
	fmovd	%f0, %f50		;\
	fmovd	%f0, %f52		;\
	fmovd	%f0, %f54		;\
	fmovd	%f0, %f56		;\
	fmovd	%f0, %f58		;\
	fmovd	%f0, %f60		;\
	fmovd	%f0, %f62

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
 * first quadrant).
 *
 * Similarly: a membar #Sync before restore allows the block stores of
 * the copy operation to complete before we fill the quadrants with their
 * original data, and a membar #Sync after restore lets the block loads
 * of the restore complete before we return to whoever has the fp regs
 * in use.  To avoid repeated membar #Sync we make it the responsibility
 * of the copy code to membar #Sync immediately after copy is complete
 * and before using the BLD_*_FROMSTACK macro.
 */
#define BST_FPQ1Q3_TOSTACK(tmp1)				\
	/* membar #Sync	*/					;\
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, tmp1	;\
	and	tmp1, -VIS_BLOCKSIZE, tmp1 /* block align */	;\
	stda	%f0, [tmp1]ASI_BLK_P				;\
	add	tmp1, VIS_BLOCKSIZE, tmp1			;\
	stda	%f32, [tmp1]ASI_BLK_P				;\
	membar	#Sync

#define	BLD_FPQ1Q3_FROMSTACK(tmp1)				\
	/* membar #Sync - provided at copy completion */	;\
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, tmp1	;\
	and	tmp1, -VIS_BLOCKSIZE, tmp1 /* block align */	;\
	ldda	[tmp1]ASI_BLK_P, %f0				;\
	add	tmp1, VIS_BLOCKSIZE, tmp1			;\
	ldda	[tmp1]ASI_BLK_P, %f32				;\
	membar	#Sync

#define BST_FPQ2Q4_TOSTACK(tmp1)				\
	/* membar #Sync */					;\
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, tmp1	;\
	and	tmp1, -VIS_BLOCKSIZE, tmp1 /* block align */	;\
	stda	%f16, [tmp1]ASI_BLK_P				;\
	add	tmp1, VIS_BLOCKSIZE, tmp1			;\
	stda	%f48, [tmp1]ASI_BLK_P				;\
	membar	#Sync

#define	BLD_FPQ2Q4_FROMSTACK(tmp1)				\
	/* membar #Sync - provided at copy completion */	;\
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, tmp1	;\
	and	tmp1, -VIS_BLOCKSIZE, tmp1 /* block align */	;\
	ldda	[tmp1]ASI_BLK_P, %f16				;\
	add	tmp1, VIS_BLOCKSIZE, tmp1			;\
	ldda	[tmp1]ASI_BLK_P, %f48				;\
	membar	#Sync

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
 * Errno value is in %g1.  bcopy_more uses fp quadrants 1 and 3.
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
	btst	FPRS_FEF, %o3
	bz,pt	%icc, 4f
	  nop

	BLD_FPQ1Q3_FROMSTACK(%o2)

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZEROQ1Q3
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


/*
 * Copy a block of storage - must not overlap (from + len <= to).
 * Registers: l6 - saved t_lofault
 * (for short copies, o4 - saved t_lofault)
 *
 * Copy a page of memory.
 * Assumes double word alignment and a count >= 256.
 */

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
	ba,pt   %ncc, .bc_sm_exit
	  stb	%o3, [%o1 + 2]
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
	ba,pt   %ncc, .bc_sm_exit
	  stb	%o3, [%o1]

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
	ldn     [THREAD_REG + T_LOFAULT], %o3
	brz,pt  %o3, .bc_sm_done
	  nop
	membar	#Sync				! sync error barrier
	andn	%o4, TRAMP_FLAG, %o4
	stn	%o4, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
.bc_sm_done:
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
	prefetch [%o0], #n_reads
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

	rd	%fprs, %o2		! check for unused fp
	st	%o2, [%fp + STACK_BIAS - SAVED_FPRS_OFFSET] ! save orig %fprs
	btst	FPRS_FEF, %o2
	bz,a,pt	%icc, .do_blockcopy
	  wr	%g0, FPRS_FEF, %fprs

	BST_FPQ1Q3_TOSTACK(%o2)

.do_blockcopy:
	rd	%gsr, %o2
	stx	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]	! save gsr
	or	%l6, FPUSED_FLAG, %l6

#define	REALSRC	%i0
#define	DST	%i1
#define	CNT	%i2
#define	SRC	%i3
#define	TMP	%i5

	andcc	DST, VIS_BLOCKSIZE - 1, TMP
	bz,pt	%ncc, 2f
	  neg	TMP
	add	TMP, VIS_BLOCKSIZE, TMP

	! TMP = bytes required to align DST on FP_BLOCK boundary
	! Using SRC as a tmp here
	cmp	TMP, 3
	bleu,pt	%ncc, 1f
	  sub	CNT,TMP,CNT		! adjust main count
	sub	TMP, 3, TMP		! adjust for end of loop test
.bc_blkalign:
	ldub	[REALSRC], SRC		! move 4 bytes per loop iteration
	stb	SRC, [DST]
	subcc	TMP, 4, TMP
	ldub	[REALSRC + 1], SRC
	add	REALSRC, 4, REALSRC
	stb	SRC, [DST + 1]
	ldub	[REALSRC - 2], SRC
	add	DST, 4, DST
	stb	SRC, [DST - 2]
	ldub	[REALSRC - 1], SRC
	bgu,pt	%ncc, .bc_blkalign
	  stb	SRC, [DST - 1]

	addcc	TMP, 3, TMP		! restore count adjustment
	bz,pt	%ncc, 2f		! no bytes left?
	  nop
1:	ldub	[REALSRC], SRC
	inc	REALSRC
	inc	DST
	deccc	TMP
	bgu	%ncc, 1b
	  stb	SRC, [DST - 1]

2:
	membar	#StoreLoad
	andn	REALSRC, 0x7, SRC

	! SRC - 8-byte aligned
	! DST - 64-byte aligned
	ldd	[SRC], %f0
	prefetch [SRC + (1 * VIS_BLOCKSIZE)], #n_reads
	alignaddr REALSRC, %g0, %g0
	ldd	[SRC + 0x08], %f2
	prefetch [SRC + (2 * VIS_BLOCKSIZE)], #n_reads
	faligndata %f0, %f2, %f32
	ldd	[SRC + 0x10], %f4
	prefetch [SRC + (3 * VIS_BLOCKSIZE)], #n_reads
	faligndata %f2, %f4, %f34
	ldd	[SRC + 0x18], %f6
	prefetch [SRC + (4 * VIS_BLOCKSIZE)], #one_read
	faligndata %f4, %f6, %f36
	ldd	[SRC + 0x20], %f8
	prefetch [SRC + (8 * VIS_BLOCKSIZE)], #one_read
	faligndata %f6, %f8, %f38
	ldd	[SRC + 0x28], %f10
	prefetch [SRC + (12 * VIS_BLOCKSIZE)], #one_read
	faligndata %f8, %f10, %f40
	ldd	[SRC + 0x30], %f12
	prefetch [SRC + (16 * VIS_BLOCKSIZE)], #one_read
	faligndata %f10, %f12, %f42
	ldd	[SRC + 0x38], %f14
	ldd	[SRC + VIS_BLOCKSIZE], %f0
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	SRC, VIS_BLOCKSIZE, SRC
	prefetch [SRC + (19 * VIS_BLOCKSIZE)], #one_read
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	ba,pt	%ncc, 1f
	  prefetch [SRC + (23 * VIS_BLOCKSIZE)], #one_read
	.align	32
1:
	ldd	[SRC + 0x08], %f2
	faligndata %f12, %f14, %f44
	ldd	[SRC + 0x10], %f4
	faligndata %f14, %f0, %f46
	stda	%f32, [DST]ASI_BLK_P
	ldd	[SRC + 0x18], %f6
	faligndata %f0, %f2, %f32
	ldd	[SRC + 0x20], %f8
	faligndata %f2, %f4, %f34
	ldd	[SRC + 0x28], %f10
	faligndata %f4, %f6, %f36
	ldd	[SRC + 0x30], %f12
	faligndata %f6, %f8, %f38
	sub	CNT, VIS_BLOCKSIZE, CNT
	ldd	[SRC + 0x38], %f14
	faligndata %f8, %f10, %f40
	add	DST, VIS_BLOCKSIZE, DST
	ldd	[SRC + VIS_BLOCKSIZE], %f0
	faligndata %f10, %f12, %f42
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	prefetch [SRC + (3 * VIS_BLOCKSIZE)], #n_reads
	add	SRC, VIS_BLOCKSIZE, SRC
	prefetch [SRC + ((OLYMPUS_C_PREFETCH) * VIS_BLOCKSIZE)], #one_read
	cmp	CNT, VIS_BLOCKSIZE + 8
	bgu,pt	%ncc, 1b
	  prefetch [SRC + ((OLYMPUS_C_2ND_PREFETCH) * VIS_BLOCKSIZE)], #one_read

	! only if REALSRC & 0x7 is 0
	cmp	CNT, VIS_BLOCKSIZE
	bne	%ncc, 3f
	  andcc	REALSRC, 0x7, %g0
	bz,pt	%ncc, 2f
	  nop
3:
	faligndata %f12, %f14, %f44
	faligndata %f14, %f0, %f46
	stda	%f32, [DST]ASI_BLK_P
	add	DST, VIS_BLOCKSIZE, DST
	ba,pt	%ncc, 3f
	  nop
2:
	ldd	[SRC + 0x08], %f2
	fsrc1	%f12, %f44
	ldd	[SRC + 0x10], %f4
	fsrc1	%f14, %f46
	stda	%f32, [DST]ASI_BLK_P
	ldd	[SRC + 0x18], %f6
	fsrc1	%f0, %f32
	ldd	[SRC + 0x20], %f8
	fsrc1	%f2, %f34
	ldd	[SRC + 0x28], %f10
	fsrc1	%f4, %f36
	ldd	[SRC + 0x30], %f12
	fsrc1	%f6, %f38
	ldd	[SRC + 0x38], %f14
	fsrc1	%f8, %f40
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST
	add	SRC, VIS_BLOCKSIZE, SRC
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	fsrc1	%f10, %f42
	fsrc1	%f12, %f44
	fsrc1	%f14, %f46
	stda	%f32, [DST]ASI_BLK_P
	add	DST, VIS_BLOCKSIZE, DST
	ba,a,pt	%ncc, .bcb_exit
	  nop

3:	tst	CNT
	bz,a,pt	%ncc, .bcb_exit
	  nop

5:	ldub	[REALSRC], TMP
	inc	REALSRC
	inc	DST
	deccc	CNT
	bgu	%ncc, 5b
	  stb	TMP, [DST - 1]
.bcb_exit:
	membar	#Sync

	ldx	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2	! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz,pt	%icc, 4f
	  nop

	BLD_FPQ1Q3_FROMSTACK(%o2)

	ba,pt	%ncc, 2f
	  wr	%o3, 0, %fprs		! restore fprs
4:
	FZEROQ1Q3
	wr	%o3, 0, %fprs		! restore fprs
2:
	membar	#Sync				! sync error barrier
	andn	%l6, MASK_FLAGS, %l6
	stn	%l6, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	FP_ALLOWMIGRATE(5, 6)
	ret
	  restore	%g0, 0, %o0

	SET_SIZE(bcopy_more)

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
 * use_hw_bcopy.  Preventing preemption also prevents cpu migration.
 */
	ENTRY(hwblkpagecopy)
	! get another window w/space for three aligned blocks of saved fpregs
	prefetch [%o0], #n_reads
	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp

	! %i0 - source address (arg)
	! %i1 - destination address (arg)
	! %i2 - length of region (not arg)
	! %l0 - saved fprs
	! %l1 - pointer to saved fpregs

	rd	%fprs, %l0		! check for unused fp
	btst	FPRS_FEF, %l0
	bz,a,pt	%icc, 1f
	  wr	%g0, FPRS_FEF, %fprs

	BST_FPQ1Q3_TOSTACK(%l1)

1:	set	PAGESIZE, CNT
	mov	REALSRC, SRC

	ldd	[SRC], %f0
	prefetch [SRC + (1 * VIS_BLOCKSIZE)], #n_reads
	ldd	[SRC + 0x08], %f2
	prefetch [SRC + (2 * VIS_BLOCKSIZE)], #n_reads
	fmovd	%f0, %f32
	ldd	[SRC + 0x10], %f4
	prefetch [SRC + (3 * VIS_BLOCKSIZE)], #n_reads
	fmovd	%f2, %f34
	ldd	[SRC + 0x18], %f6
	prefetch [SRC + (4 * VIS_BLOCKSIZE)], #one_read
	fmovd	%f4, %f36
	ldd	[SRC + 0x20], %f8
	prefetch [SRC + (8 * VIS_BLOCKSIZE)], #one_read
	fmovd	%f6, %f38
	ldd	[SRC + 0x28], %f10
	prefetch [SRC + (12 * VIS_BLOCKSIZE)], #one_read
	fmovd	%f8, %f40
	ldd	[SRC + 0x30], %f12
	prefetch [SRC + (16 * VIS_BLOCKSIZE)], #one_read
	fmovd	%f10, %f42
	ldd	[SRC + 0x38], %f14
	ldd	[SRC + VIS_BLOCKSIZE], %f0
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	SRC, VIS_BLOCKSIZE, SRC
	prefetch [SRC + (19 * VIS_BLOCKSIZE)], #one_read
	ba,pt	%ncc, 2f
	prefetch [SRC + (23 * VIS_BLOCKSIZE)], #one_read
	.align	32
2:
	ldd	[SRC + 0x08], %f2
	fmovd	%f12, %f44
	ldd	[SRC + 0x10], %f4
	fmovd	%f14, %f46
	stda	%f32, [DST]ASI_BLK_P
	ldd	[SRC + 0x18], %f6
	fmovd	%f0, %f32
	ldd	[SRC + 0x20], %f8
	fmovd	%f2, %f34
	ldd	[SRC + 0x28], %f10
	fmovd	%f4, %f36
	ldd	[SRC + 0x30], %f12
	fmovd	%f6, %f38
	ldd	[SRC + 0x38], %f14
	fmovd	%f8, %f40
	ldd	[SRC + VIS_BLOCKSIZE], %f0
	fmovd	%f10, %f42
	sub	CNT, VIS_BLOCKSIZE, CNT
	prefetch [SRC + (3 * VIS_BLOCKSIZE)], #n_reads
	add	DST, VIS_BLOCKSIZE, DST
	prefetch [SRC + ((OLYMPUS_C_PREFETCH) * VIS_BLOCKSIZE)], #one_read
	add	SRC, VIS_BLOCKSIZE, SRC
	cmp	CNT, VIS_BLOCKSIZE + 8
	bgu,pt	%ncc, 2b
	  prefetch [SRC + ((OLYMPUS_C_2ND_PREFETCH) * VIS_BLOCKSIZE)], #one_read

	! trailing block
	ldd	[SRC + 0x08], %f2
	fsrc1	%f12, %f44
	ldd	[SRC + 0x10], %f4
	fsrc1	%f14, %f46
	stda	%f32, [DST]ASI_BLK_P
	ldd	[SRC + 0x18], %f6
	fsrc1	%f0, %f32
	ldd	[SRC + 0x20], %f8
	fsrc1	%f2, %f34
	ldd	[SRC + 0x28], %f10
	fsrc1	%f4, %f36
	ldd	[SRC + 0x30], %f12
	fsrc1	%f6, %f38
	ldd	[SRC + 0x38], %f14
	fsrc1	%f8, %f40
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST
	add	SRC, VIS_BLOCKSIZE, SRC
	fsrc1	%f10, %f42
	fsrc1	%f12, %f44
	fsrc1	%f14, %f46
	stda	%f32, [DST]ASI_BLK_P

	membar	#Sync

	btst	FPRS_FEF, %l0
	bz,pt	%icc, 2f
	  nop

	BLD_FPQ1Q3_FROMSTACK(%l3)
	ba	3f
	  nop

2:	FZEROQ1Q3

3:	wr	%l0, 0, %fprs		! restore fprs
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
	btst	FPRS_FEF, %o3
	bz,pt	%icc, 4f
	  nop

	BLD_FPQ2Q4_FROMSTACK(%o2)

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs   	! restore fprs

4:
	FZEROQ2Q4
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
	prefetch [%o0], #n_reads
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
	btst	FPRS_FEF, %o2
	bz,a,pt	%icc, .do_blockcopyout
	  wr	%g0, FPRS_FEF, %fprs

	BST_FPQ2Q4_TOSTACK(%o2)

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
	membar	#StoreLoad
	andn	REALSRC, 0x7, SRC

	! SRC - 8-byte aligned
	! DST - 64-byte aligned
	ldd	[SRC], %f16
	prefetch [SRC + (1 * VIS_BLOCKSIZE)], #n_reads
	alignaddr REALSRC, %g0, %g0
	ldd	[SRC + 0x08], %f18
	prefetch [SRC + (2 * VIS_BLOCKSIZE)], #n_reads
	faligndata %f16, %f18, %f48
	ldd	[SRC + 0x10], %f20
	prefetch [SRC + (3 * VIS_BLOCKSIZE)], #n_reads
	faligndata %f18, %f20, %f50
	ldd	[SRC + 0x18], %f22
	prefetch [SRC + (4 * VIS_BLOCKSIZE)], #one_read
	faligndata %f20, %f22, %f52
	ldd	[SRC + 0x20], %f24
	prefetch [SRC + (8 * VIS_BLOCKSIZE)], #one_read
	faligndata %f22, %f24, %f54
	ldd	[SRC + 0x28], %f26
	prefetch [SRC + (12 * VIS_BLOCKSIZE)], #one_read
	faligndata %f24, %f26, %f56
	ldd	[SRC + 0x30], %f28
	prefetch [SRC + (16 * VIS_BLOCKSIZE)], #one_read
	faligndata %f26, %f28, %f58
	ldd	[SRC + 0x38], %f30
	ldd	[SRC + VIS_BLOCKSIZE], %f16
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	SRC, VIS_BLOCKSIZE, SRC
	prefetch [SRC + (19 * VIS_BLOCKSIZE)], #one_read
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	ba,pt	%ncc, 1f
	prefetch [SRC + (23 * VIS_BLOCKSIZE)], #one_read
	.align	32
1:
	ldd	[SRC + 0x08], %f18
	faligndata %f28, %f30, %f60
	ldd	[SRC + 0x10], %f20
	faligndata %f30, %f16, %f62
	stda	%f48, [DST]ASI_BLK_AIUS
	ldd	[SRC + 0x18], %f22
	faligndata %f16, %f18, %f48
	ldd	[SRC + 0x20], %f24
	faligndata %f18, %f20, %f50
	ldd	[SRC + 0x28], %f26
	faligndata %f20, %f22, %f52
	ldd	[SRC + 0x30], %f28
	faligndata %f22, %f24, %f54
	sub	CNT, VIS_BLOCKSIZE, CNT
	ldd	[SRC + 0x38], %f30
	faligndata %f24, %f26, %f56
	add	DST, VIS_BLOCKSIZE, DST
	ldd	[SRC + VIS_BLOCKSIZE], %f16
	faligndata %f26, %f28, %f58
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	prefetch [SRC + (3 * VIS_BLOCKSIZE)], #n_reads
	add	SRC, VIS_BLOCKSIZE, SRC
	prefetch [SRC + ((OLYMPUS_C_PREFETCH) * VIS_BLOCKSIZE)], #one_read
	cmp	CNT, VIS_BLOCKSIZE + 8
	bgu,pt	%ncc, 1b
	  prefetch [SRC + ((OLYMPUS_C_2ND_PREFETCH) * VIS_BLOCKSIZE)], #one_read

	! only if REALSRC & 0x7 is 0
	cmp	CNT, VIS_BLOCKSIZE
	bne	%ncc, 3f
	  andcc	REALSRC, 0x7, %g0
	bz,pt	%ncc, 2f
	  nop
3:
	faligndata %f28, %f30, %f60
	faligndata %f30, %f16, %f62
	stda	%f48, [DST]ASI_BLK_AIUS
	add	DST, VIS_BLOCKSIZE, DST
	ba,pt	%ncc, 3f
	  nop
2:
	ldd	[SRC + 0x08], %f18
	fsrc1	%f28, %f60
	ldd	[SRC + 0x10], %f20
	fsrc1	%f30, %f62
	stda	%f48, [DST]ASI_BLK_AIUS
	ldd	[SRC + 0x18], %f22
	fsrc1	%f16, %f48
	ldd	[SRC + 0x20], %f24
	fsrc1	%f18, %f50
	ldd	[SRC + 0x28], %f26
	fsrc1	%f20, %f52
	ldd	[SRC + 0x30], %f28
	fsrc1	%f22, %f54
	ldd	[SRC + 0x38], %f30
	fsrc1	%f24, %f56
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST
	add	SRC, VIS_BLOCKSIZE, SRC
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	fsrc1	%f26, %f58
	fsrc1	%f28, %f60
	fsrc1	%f30, %f62
	stda	%f48, [DST]ASI_BLK_AIUS
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
	btst	FPRS_FEF, %o3
	bz,pt	%icc, 4f
	  nop

	BLD_FPQ2Q4_FROMSTACK(%o2)

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZEROQ2Q4
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

/*
 * Copy user data to kernel space (copyin/xcopyin/xcopyin_little)
 */

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
	prefetch [%o0], #n_reads
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
	btst	FPRS_FEF, %o2
	bz,a,pt	%icc, .do_blockcopyin
	  wr	%g0, FPRS_FEF, %fprs

	BST_FPQ2Q4_TOSTACK(%o2)

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
	membar	#StoreLoad
	andn	REALSRC, 0x7, SRC

	! SRC - 8-byte aligned
	! DST - 64-byte aligned
	ldda	[SRC]%asi, %f16
	prefetcha [SRC + (1 * VIS_BLOCKSIZE)]%asi, #n_reads
	alignaddr REALSRC, %g0, %g0
	ldda	[SRC + 0x08]%asi, %f18
	prefetcha [SRC + (2 * VIS_BLOCKSIZE)]%asi, #n_reads
	faligndata %f16, %f18, %f48
	ldda	[SRC + 0x10]%asi, %f20
	prefetcha [SRC + (3 * VIS_BLOCKSIZE)]%asi, #n_reads
	faligndata %f18, %f20, %f50
	ldda	[SRC + 0x18]%asi, %f22
	prefetcha [SRC + (4 * VIS_BLOCKSIZE)]%asi, #one_read
	faligndata %f20, %f22, %f52
	ldda	[SRC + 0x20]%asi, %f24
	prefetcha [SRC + (8 * VIS_BLOCKSIZE)]%asi, #one_read
	faligndata %f22, %f24, %f54
	ldda	[SRC + 0x28]%asi, %f26
	prefetcha [SRC + (12 * VIS_BLOCKSIZE)]%asi, #one_read
	faligndata %f24, %f26, %f56
	ldda	[SRC + 0x30]%asi, %f28
	prefetcha [SRC + (16 * VIS_BLOCKSIZE)]%asi, #one_read
	faligndata %f26, %f28, %f58
	ldda	[SRC + 0x38]%asi, %f30
	ldda	[SRC + VIS_BLOCKSIZE]%asi, %f16
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	SRC, VIS_BLOCKSIZE, SRC
	prefetcha [SRC + (19 * VIS_BLOCKSIZE)]%asi, #one_read
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	ba,pt	%ncc, 1f
	prefetcha [SRC + (23 * VIS_BLOCKSIZE)]%asi, #one_read
	.align	32
1:
	ldda	[SRC + 0x08]%asi, %f18
	faligndata %f28, %f30, %f60
	ldda	[SRC + 0x10]%asi, %f20
	faligndata %f30, %f16, %f62
	stda	%f48, [DST]ASI_BLK_P
	ldda	[SRC + 0x18]%asi, %f22
	faligndata %f16, %f18, %f48
	ldda	[SRC + 0x20]%asi, %f24
	faligndata %f18, %f20, %f50
	ldda	[SRC + 0x28]%asi, %f26
	faligndata %f20, %f22, %f52
	ldda	[SRC + 0x30]%asi, %f28
	faligndata %f22, %f24, %f54
	sub	CNT, VIS_BLOCKSIZE, CNT
	ldda	[SRC + 0x38]%asi, %f30
	faligndata %f24, %f26, %f56
	add	DST, VIS_BLOCKSIZE, DST
	ldda	[SRC + VIS_BLOCKSIZE]%asi, %f16
	faligndata %f26, %f28, %f58
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	prefetcha [SRC + (3 * VIS_BLOCKSIZE)]%asi, #n_reads
	add	SRC, VIS_BLOCKSIZE, SRC
	prefetcha [SRC + ((OLYMPUS_C_PREFETCH) * VIS_BLOCKSIZE)]%asi, #one_read
	cmp	CNT, VIS_BLOCKSIZE + 8
	bgu,pt	%ncc, 1b
	  prefetcha [SRC + ((OLYMPUS_C_2ND_PREFETCH) * VIS_BLOCKSIZE)]%asi, #one_read

	! only if REALSRC & 0x7 is 0
	cmp	CNT, VIS_BLOCKSIZE
	bne	%ncc, 3f
	  andcc	REALSRC, 0x7, %g0
	bz,pt	%ncc, 2f
	  nop
3:
	faligndata %f28, %f30, %f60
	faligndata %f30, %f16, %f62
	stda	%f48, [DST]ASI_BLK_P
	add	DST, VIS_BLOCKSIZE, DST
	ba,pt	%ncc, 3f
	  nop
2:
	ldda	[SRC + 0x08]%asi, %f18
	fsrc1	%f28, %f60
	ldda	[SRC + 0x10]%asi, %f20
	fsrc1	%f30, %f62
	stda	%f48, [DST]ASI_BLK_P
	ldda	[SRC + 0x18]%asi, %f22
	fsrc1	%f16, %f48
	ldda	[SRC + 0x20]%asi, %f24
	fsrc1	%f18, %f50
	ldda	[SRC + 0x28]%asi, %f26
	fsrc1	%f20, %f52
	ldda	[SRC + 0x30]%asi, %f28
	fsrc1	%f22, %f54
	ldda	[SRC + 0x38]%asi, %f30
	fsrc1	%f24, %f56
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST
	add	SRC, VIS_BLOCKSIZE, SRC
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	fsrc1	%f26, %f58
	fsrc1	%f28, %f60
	fsrc1	%f30, %f62
	stda	%f48, [DST]ASI_BLK_P
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
	btst	FPRS_FEF, %o3
	bz,pt	%icc, 4f
	  nop

	BLD_FPQ2Q4_FROMSTACK(%o2)

	ba,pt	%ncc, 1f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZEROQ2Q4
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


/*
 * Copy a block of storage - must not overlap (from + len <= to).
 * No fault handler installed (to be called under on_fault())
 */
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

/*
 * Copy a block of storage - must not overlap (from + len <= to).
 * No fault handler installed (to be called under on_fault())
 */

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
	save	%sp, -SA(MINFRAME + 2*VIS_BLOCKSIZE), %sp

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
	ret
	  restore	%g0, 1, %o0 ! return (1) - did not use block operations

2:	rd	%fprs, %l0		! check for unused fp
	btst	FPRS_FEF, %l0
	bz,pt	%icc, 1f
	  nop

	! save in-use fpregs on stack
	membar	#Sync
	add	%fp, STACK_BIAS - 65, %l1
	and	%l1, -VIS_BLOCKSIZE, %l1
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
	ba,pt	%ncc, .pz_doblock
	  nop

.pz_blkstart:
      ! stda	%d0, [%i0 + 192]%asi  ! in dly slot of branch that got us here
	stda	%d0, [%i0 + 128]%asi
	stda	%d0, [%i0 + 64]%asi
	stda	%d0, [%i0]%asi
.pz_zinst:
	add	%i0, %i3, %i0
	sub	%i1, %i3, %i1
.pz_doblock:
	cmp	%i1, 256
	bgeu,a	%ncc, .pz_blkstart
	  stda	%d0, [%i0 + 192]%asi

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
	membar	#Sync

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

	DGDEF(use_hw_bcopy)
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
