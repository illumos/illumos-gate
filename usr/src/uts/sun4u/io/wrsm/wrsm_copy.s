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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"
		
#if !defined(lint)
#include <sys/asm_linkage.h>
#include <sys/asi.h>
#include <sys/machasi.h>
#include <sys/privregs.h>
#include <sys/machthread.h>
#include <sys/fsr.h>
#include <sys/machparam.h>
#include <sys/wrsm_intr.h>
#include <sys/wrsm_intr_impl.h>
#include <wrsm_offsets.h>
#endif /* lint */

#if defined(lint)
#include <sys/types.h>
#else /* lint */
#include "assym.h"
#endif	/* lint */

/*
 * Pseudo-code to aid in understanding the control flow of the
 * wrsm_blkwrite
 *
 * On entry:
 *
 * 	%l6 = curthread->t_lofault;
 * 	if (%l6 != NULL) {
 * 		curthread->t_lofault = .copyerr;
 * 		caller_error_handler = TRUE             ! %l6 |= 1
 * 	}
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
 *              ! If we need to save 3 blocks of fpregs then make sure
 *		! the length is still appropriate for that extra overhead.
 * 		if (length < (large_length + (64 * 3))) {
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
 * 	if (length < HW_THRESHOLD)
 * 		goto slow_copy;
 *
 *
 * 	do blockcopy or slow_copy here;
 *
 *
 * On exit (in lofault handler as well):
 *
 * 	%gsr = old_gsr;
 * 	if (old_fprs & FPRS_FEF)
 * 		restore fpregs from stack using blockload
 *	else
 *		zero fpregs
 * 	%fprs = old_fprs;
 * 	if (curthread->t_lwp == NULL)
 *		kpreempt_enable(curthread);
 * 	curthread->t_lofault = (%l6 & ~1);
 * 	return (0)
 */

/*
 * Number of bytes needed to "break even" using VIS-accelerated
 * memory operations.
 */
#define	HW_THRESHOLD		256

/*
 * Number of outstanding prefetches.  5 seems to be a good number
 * right now.
 */
#define	CHEETAH_PREFETCH	5

/*
 * Size of stack frame in order to accomodate a 64-byte aligned
 * floating-point register save area and 2 64-bit temp locations.
 */
#define	VIS_BLOCKSIZE		64

#define	HWCOPYFRAMESIZE		((VIS_BLOCKSIZE * 4) + (2 * 8))

#define SAVED_FPREGS_OFFSET	(VIS_BLOCKSIZE * 4)
#define SAVED_FPREGS_ADJUST	((VIS_BLOCKSIZE * 3) - 1)
#define	SAVED_FPRS_OFFSET	(SAVED_FPREGS_OFFSET + 8)
#define	SAVED_GSR_OFFSET	(SAVED_FPRS_OFFSET + 8)

/*
 * Common macros used by the various versions of the block copy
 * routines in this file.
 */

/*
 * Zero the parts of the fpreg file that we actually use
 * ( 2 or 3 sets of 8 registers )
 */
#define	FZERO3				\
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
	fmuld	%f0, %f2, %f46

#define	FZERO2				\
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
	fmuld	%f0, %f2, %f30

/*
 * Copy a block of storage, returning an error code if `from' or
 * `to' takes a kernel pagefault which cannot be resolved.
 * Returns errno value on pagefault error, 0 if all ok
 */

#if defined(lint)

/* ARGSUSED */
void
wrsm_blkwrite(void *from, void *to, size_t num_blocks)
{}

#else	/* lint */

	.seg	".text"
	.align	4

	ENTRY(wrsm_blkwrite)

	save	%sp, -SA(MINFRAME + HWCOPYFRAMESIZE), %sp
	ldn	[THREAD_REG + T_LOFAULT], %l6	! save t_lofault
	brz,pt	%l6, .do_copy
	  nop
	set	.copyerr, %o2
	stn	%o2, [THREAD_REG + T_LOFAULT]	! install new vector
	b	.do_copy			! copy code
	  or	%l6, 1, %l6		        ! error should trampoline

/*
 * We got here because of a fault during kcopy.
 * Errno value is in %g1.
 */
.copyerr:
	membar	#Sync

	ldx	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2	! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz	4f
	  nop

	! restore fpregs from stack
	membar	#Sync
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, %o2
	and	%o2, -VIS_BLOCKSIZE, %o2
	ldda	[%o2]ASI_BLK_P, %d0
	add	%o2, VIS_BLOCKSIZE, %o2
	ldda	[%o2]ASI_BLK_P, %d16
	add	%o2, VIS_BLOCKSIZE, %o2
	ldda	[%o2]ASI_BLK_P, %d32
	membar	#Sync

	ba	2f
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO3				! zero all of the fpregs
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
	bz,pt	%ncc, 1f
	  nop

	! Attempt to preempt
	call	kpreempt
	  rdpr	  %pil, %o0		  ! pass %pil

1:
	btst	1, %l6
	andn	%l6, 1, %l6
	bnz,pn	%ncc, 3f
	  stn	%l6, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	ret
	restore	%g1, 0, %o0

3:
	jmp	%l6				! goto real handler
	restore	%g0, 0, %o0			! dispose of copy window

.do_copy:
	sllx    %i2, 6, %i2		! convert blocks to bytes

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
	bz,a	.do_blockcopy
	  wr	%g0, FPRS_FEF, %fprs

.fpregs_inuse:

	wr	%g0, FPRS_FEF, %fprs

	! save in-use fpregs on stack
	membar	#Sync
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, %o2
	and	%o2, -VIS_BLOCKSIZE, %o2
	stda	%d0, [%o2]ASI_BLK_P
	add	%o2, VIS_BLOCKSIZE, %o2
	stda	%d16, [%o2]ASI_BLK_P
	add	%o2, VIS_BLOCKSIZE, %o2
	stda	%d32, [%o2]ASI_BLK_P
	membar	#Sync

.do_blockcopy:
	membar	#StoreStore|#StoreLoad|#LoadStore

	rd	%gsr, %o2
	stx	%o2, [%fp + STACK_BIAS - SAVED_GSR_OFFSET]	! save gsr

#define	REALSRC	%i0
#define	DST	%i1
#define	CNT	%i2
#define	SRC	%i3

	cmp	%i2, HW_THRESHOLD	! for large counts
	blu	%ncc, .slow_copy
	  .empty

2:	membar	#StoreLoad
	alignaddr REALSRC, %g0, SRC

	! SRC - 8-byte aligned
	! DST - 64-byte aligned
	prefetch [SRC], #one_read
	prefetch [SRC + (1 * VIS_BLOCKSIZE)], #one_read
	prefetch [SRC + (2 * VIS_BLOCKSIZE)], #one_read
	prefetch [SRC + (3 * VIS_BLOCKSIZE)], #one_read
	ldd	[SRC], %f0
#if CHEETAH_PREFETCH >= 4
	prefetch [SRC + (4 * VIS_BLOCKSIZE)], #one_read
#endif
	ldd	[SRC + 0x08], %f2
#if CHEETAH_PREFETCH >= 5
	prefetch [SRC + (5 * VIS_BLOCKSIZE)], #one_read
#endif
	ldd	[SRC + 0x10], %f4
#if CHEETAH_PREFETCH >= 6
	prefetch [SRC + (6 * VIS_BLOCKSIZE)], #one_read
#endif
	faligndata %f0, %f2, %f32
	ldd	[SRC + 0x18], %f6
#if CHEETAH_PREFETCH >= 7
	prefetch [SRC + (7 * VIS_BLOCKSIZE)], #one_read
#endif
	faligndata %f2, %f4, %f34
	ldd	[SRC + 0x20], %f8
	faligndata %f4, %f6, %f36
	ldd	[SRC + 0x28], %f10
	faligndata %f6, %f8, %f38
	ldd	[SRC + 0x30], %f12
	faligndata %f8, %f10, %f40
	ldd	[SRC + 0x38], %f14
	faligndata %f10, %f12, %f42
	ldd	[SRC + VIS_BLOCKSIZE], %f0
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	SRC, VIS_BLOCKSIZE, SRC
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	ba,a,pt	%ncc, 1f
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
	ldd	[SRC + 0x38], %f14
	faligndata %f8, %f10, %f40
	ldd	[SRC + VIS_BLOCKSIZE], %f0
	prefetch [SRC + (CHEETAH_PREFETCH * VIS_BLOCKSIZE)], #one_read
	faligndata %f10, %f12, %f42
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	cmp	CNT, VIS_BLOCKSIZE + 8
	bgu,pt	%ncc, 1b
	  add	SRC, VIS_BLOCKSIZE, SRC

	! only if REALSRC & 0x7 is 0
	andcc	REALSRC, 0x7, %g0
	bz	%ncc, 2f
	  nop
3:	
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
	ldd	[SRC + 0x38], %f14
	faligndata %f8, %f10, %f40
	ldd	[SRC + VIS_BLOCKSIZE], %f0
	faligndata %f10, %f12, %f42
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST	
	faligndata %f12, %f14, %f44
	faligndata %f14, %f0, %f46
	stda	%f32, [DST]ASI_BLK_P
	ba	4f
	  add	SRC, VIS_BLOCKSIZE, SRC

2:
	ldd	[SRC + 0x08], %f2
	fsrc1	%f12, %f44
	ldd	[SRC + 0x10], %f4
	fsrc1	%f14, %f46
	stda	%f32, [DST]ASI_BLK_P
	ldd	[SRC + 0x18], %f6
	ldd	[SRC + 0x20], %f8
	ldd	[SRC + 0x28], %f10
	ldd	[SRC + 0x30], %f12
	ldd	[SRC + 0x38], %f14
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	DST, VIS_BLOCKSIZE, DST
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	stda	%f0, [DST]ASI_BLK_P
	ba	4f
	  add	SRC, VIS_BLOCKSIZE, SRC
4:
.copy_exit:
	membar	#StoreLoad|#StoreStore

	andn	%l6, 1, %l6

	ldx	[%fp + STACK_BIAS - SAVED_GSR_OFFSET], %o2	! restore gsr
	wr	%o2, 0, %gsr

	ld	[%fp + STACK_BIAS - SAVED_FPRS_OFFSET], %o3
	btst	FPRS_FEF, %o3
	bz	4f
	  nop

	! restore fpregs from stack
	membar	#Sync
	add	%fp, STACK_BIAS - SAVED_FPREGS_ADJUST, %o2
	and	%o2, -VIS_BLOCKSIZE, %o2
	ldda	[%o2]ASI_BLK_P, %d0
	add	%o2, VIS_BLOCKSIZE, %o2
	ldda	[%o2]ASI_BLK_P, %d16
	add	%o2, VIS_BLOCKSIZE, %o2
	ldda	[%o2]ASI_BLK_P, %d32
	membar	#Sync

	ba	2f	
	  wr	%o3, 0, %fprs		! restore fprs

4:
	FZERO3				! zero all of the fpregs
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
	bz,pt	%ncc, 1f
	  nop

	! Attempt to preempt
	call	kpreempt
	  rdpr	  %pil, %o0		  ! pass %pil

1:
	stn	%l6, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	ret
	restore	%g0, 0, %o0

.slow_copy:

	andcc	REALSRC, 0x7, %g0
	bz	%ncc, 3f
	alignaddr REALSRC, %g0, SRC

1:	brlez,pn	CNT, .copy_exit
	  nop
	ldd	[SRC], %f0
	ldd	[SRC + 0x08], %f2
	ldd	[SRC + 0x10], %f4
	faligndata %f0, %f2, %f32
	ldd	[SRC + 0x18], %f6
	faligndata %f2, %f4, %f34
	ldd	[SRC + 0x20], %f8
	faligndata %f4, %f6, %f36
	ldd	[SRC + 0x28], %f10
	faligndata %f6, %f8, %f38
	ldd	[SRC + 0x30], %f12
	faligndata %f8, %f10, %f40
	ldd	[SRC + 0x38], %f14
	faligndata %f10, %f12, %f42
	ldd	[SRC + VIS_BLOCKSIZE], %f0
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	SRC, VIS_BLOCKSIZE, SRC
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	faligndata %f12, %f14, %f44
	faligndata %f14, %f0, %f46
	stda	%f32, [DST]ASI_BLK_P
	ba	1b
	  add	DST, VIS_BLOCKSIZE, DST

	! SRC - 8-byte aligned
	! DST - 64-byte aligned

3:	brlez,pn	CNT, .copy_exit
	  nop
	ldd	[SRC], %f0
	ldd	[SRC + 0x08], %f2
	ldd	[SRC + 0x10], %f4
	ldd	[SRC + 0x18], %f6
	ldd	[SRC + 0x20], %f8
	ldd	[SRC + 0x28], %f10
	ldd	[SRC + 0x30], %f12
	ldd	[SRC + 0x38], %f14
	sub	CNT, VIS_BLOCKSIZE, CNT
	add	SRC, VIS_BLOCKSIZE, SRC
	add	REALSRC, VIS_BLOCKSIZE, REALSRC
	stda	%f0, [DST]ASI_BLK_P
	ba 3b
	  add	DST, VIS_BLOCKSIZE, DST

	SET_SIZE(wrsm_blkwrite)
#endif	/* lint */


/*
 * wrsm_blkread
 *
 * disable preemption
 * if FPREGS need to be saved, save them
 * check alignment:
 * if (64 alignment) go to loop 3
 * if (8 alinment)   go to loop 2
 * else
 *   if done, go to exit
 *   block load 64 bytes into FPREGS
 *   store 64 bytes on the stack
 *   load 8 bytes into %l0
 *   store byte by byte
 *   repeat
 *
 * loop 2:
 *   if done, go to exit
 *   block load 64 bytes into FPREGS
 *   store the 8 - 8 byte values from FPREGS to mem
 *   repeat
 *
 * loop 3:
 *   if done, go to exit
 *   block load 64 bytes into FPREGS
 *   block store 64 bytes to memory
 *   repeat
 *
 * exit:
 * restore FPREGS or clear them
 * check for preemption requests
 * return
 */

/* we need to save two blocks of 8 registers on the stack + alignment */
#define	READFRAMESIZE		(VIS_BLOCKSIZE * 3)
/* where we put FPREGS */
#define READ_FPREGS_ADJUST	(VIS_BLOCKSIZE - 1)
/* where we put data on stack during byte copy */
#define READ_STACK_ADJUST	((VIS_BLOCKSIZE * 2) - 1)
	
#if defined(lint)
/* ARGSUSED */
void
wrsm_blkread(void *src, void *dst, size_t num_blocks)
{}
#else /* !lint */
!
! Move multiple cache lines of data.
! The source must be 64-byte aligned.
!
! %i0 = src va (64 byte aligned - remote side)
! %i1 = dst va (non alligned - local side)
! %i2 = num_blocks
!
! %l0 = may be used as temporary place holder for data
! %l1 = cache of fpu state
! %l2 = temp address of data on stack
!

	ENTRY(wrsm_blkread)

	save	%sp, -SA(MINFRAME + READFRAMESIZE), %sp

	membar	#Sync

	! kpreempt_disable();
	ldsb	[THREAD_REG + T_PREEMPT], %o2
	inc	%o2
	stb	%o2, [THREAD_REG + T_PREEMPT]

	! check if we need to save the state of the fpu?
	rd	%fprs, %l1
	btst	FPRS_FEF, %l1

	! always enable FPU
	wr	%g0, FPRS_FEF, %fprs

	bz,a	1f
	 nop

	! save in-use fpregs on stack
	membar	#Sync
	add	%fp, STACK_BIAS - READ_FPREGS_ADJUST, %o2
	and	%o2, -64, %o2
	stda	%d0, [%o2]ASI_BLK_P
	membar	#Sync

	! check alignment
1:	andcc	%i1, 63, %g0		! *dst aligned 64 bytes
	bz	%ncc, .loop3

	andcc	%i1, 0x7, %g0		! *dst aligned 8 bytes
	bz	%ncc, .loop2
	 nop

	! we do not have any alignment for destination (loop 1)

	! calculate address for extra space on the stack (below fpregs)
	add	%fp, STACK_BIAS - READ_STACK_ADJUST, %o2
	and	%o2, -64, %o2

	! Perform block move
.loop1:
	brz,pn	%i2, 2f			! while (%i2 > 0) {
	 nop
	ldda	[%i0]ASI_BLK_P, %d0	!   tmp = *src;
	
	! save the data on stack
	membar	#Sync
	stda	%d0, [%o2]ASI_BLK_P
	membar	#Sync
	! read the data into local regs

	add	%o2, 0, %l2		! store the location of data into %l2
	ldx	[%l2], %l0
	stb	%l0, [%i1+7]		! not aligned , store byte at a time
	srlx	%l0, 8, %l0		!   (*dst = tmp;)
	stb	%l0, [%i1+6]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+5]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+4]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+3]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+2]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+1]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1]
	
	add	%l2, 8, %l2		! increment location of data
	ldx	[%l2], %l0
	stb	%l0, [%i1+15]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+14]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+13]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+12]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+11]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+10]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+9]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+8]

	add	%l2, 8, %l2		! increment location of data
	ldx	[%l2], %l0
	stb	%l0, [%i1+23]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+22]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+21]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+20]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+19]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+18]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+17]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+16]

	add	%l2, 8, %l2		! increment location of data
	ldx	[%l2], %l0
	stb	%l0, [%i1+31]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+30]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+29]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+28]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+27]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+26]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+25]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+24]

	add	%l2, 8, %l2		! increment location of data
	ldx	[%l2], %l0
	stb	%l0, [%i1+39]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+38]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+37]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+36]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+35]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+34]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+33]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+32]

	add	%l2, 8, %l2		! increment location of data
	ldx	[%l2], %l0
	stb	%l0, [%i1+47]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+46]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+45]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+44]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+43]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+42]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+41]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+40]

	add	%l2, 8, %l2		! increment location of data
	ldx	[%l2], %l0
	stb	%l0, [%i1+55]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+54]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+53]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+52]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+51]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+50]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+49]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+48]

	add	%l2, 8, %l2		! increment location of data
	ldx	[%l2], %l0
	stb	%l0, [%i1+63]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+62]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+61]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+60]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+59]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+58]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+57]
	srlx	%l0, 8, %l0
	stb	%l0, [%i1+56]

	add	%i0, 64, %i0		!   src++;
	add	%i1, 64, %i1		!   dst++;
	membar	#Sync
	ba	.loop1			!   %i2-- ; 
	  dec	%i2			! }


	! we have 8 byte alignment (loop 2)
.loop2:
	brz,pn	%i2, 2f			! while (%i2 > 0) {
	 nop
	ldda	[%i0]ASI_BLK_P, %f0	!   tmp = *src;

	std	%f0, [%i1]		!   *dst = tmp;
	std	%f2, [%i1 + 0x08]	
	std	%f4, [%i1 + 0x10]	
	std	%f6, [%i1 + 0x18]	
	std	%f8, [%i1 + 0x20]	
	std	%f10, [%i1 + 0x28]	
	std	%f12, [%i1 + 0x30]
	std	%f14, [%i1 + 0x38]
	add	%i0, 64, %i0		!   src++;
	add	%i1, 64, %i1		!   dst++;
	membar	#Sync
	ba	.loop2			!   %i2-- ; 
	  dec	%i2			! }

	! we have 64 byte alignment (loop 3)
.loop3:
	brz,pn	%i2, 2f			! while (%i2 > 0) {
	 nop
	ldda	[%i0]ASI_BLK_P, %f0	!   tmp = *src;

	stda	%d0, [%i1]ASI_BLK_P	!   *dst = tmp;
	add	%i0, 64, %i0		!   src++;
	add	%i1, 64, %i1		!   dst++;
	membar	#Sync 
	ba	.loop3			!   %i2-- ; 
	  dec	%i2			! }
	
2:	! coming out of loop 1, 2 or 3
	! restore fp to the way we got it
	btst	FPRS_FEF, %l1
	bz,a	3f
	  nop

	! restore fpregs from stack
	add	%fp, STACK_BIAS - READ_FPREGS_ADJUST, %o2
	and	%o2, -64, %o2
	ldda	[%o2]ASI_BLK_P, %d0
	membar	#Sync
	ba	4f
	  wr	%g0, %l1, %fprs		! fpu back to the way it was
3:
	FZERO2				! zero all of the fpregs
	wr	%g0, %l1, %fprs		! restore fprs

4:	! kpreempt_enable();
	ldsb	[THREAD_REG + T_PREEMPT], %o2
	deccc	%o2
	stb	%o2, [THREAD_REG + T_PREEMPT]

	! Check for a kernel preemption request
	ldn	[THREAD_REG + T_CPU], %o2
	ldub	[%o2 + CPU_KPRUNRUN], %o2
	tst	%o2
	bz,pt	%icc, 5f
	  nop

	! Attempt to preempt
	call	kpreempt
	  rdpr	  %pil, %o0		  ! pass %pil

5:	ret
	restore
	SET_SIZE(wrsm_blkread)
#endif /* lint */

