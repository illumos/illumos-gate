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

#define	FP_USED 1
#define	LOFAULT_SET 2

/*
 * Error barrier:
 * We use membar sync to establish an error barrier for
 * deferred errors. Membar syncs are added before any update
 * to t_lofault to ensure that deferred errors from earlier
 * accesses will not be reported after the membar. This error
 * isolation is important when we try to recover from async
 * errors which tries to distinguish kernel accesses to user
 * data.
 */

/*
 * Zero a block of storage.
 *
 * uzero is used by the kernel to zero a block in user address space.
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
	! If saved t_lofault has FP_USED set, clear the %fprs register
	!
	btst	FP_USED, %o5
	bz,pt	%ncc, 1f		! skip if not used
	nop
	membar #Sync
	wr	%g0, %g0, %fprs		! clear fprs
	andn	%o5, FP_USED, %o5	! turn off flag bit
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
	cmp	%o1, 15			! check for small counts
	blu,pn	%ncc, .byteclr		! just clear bytes
	nop

	cmp	%o1, 192		! check for large counts
	blu	%ncc, .bzero_small
	nop

	sethi	%hi(use_hw_bzero), %o2
	ld	[%o2 + %lo(use_hw_bzero)], %o2
	tst	%o2
	bz	%icc, .bzero_small
	nop

	rd	%fprs, %o2		! check for unused fp
	btst	FPRS_FEF, %o2
	bnz	%icc, .bzero_small
	nop

	ldn	[THREAD_REG + T_LWP], %o2
	tst	%o2
	bz,pn	%ncc, .bzero_small
	nop

	! Check for block alignment
	btst	(64-1), %o0
	bz	%icc, .bzl_block
	nop

	! Check for double-word alignment
	btst	(8-1), %o0
	bz	%icc, .bzl_dword
	nop

	! Check for word alignment
	btst	(4-1), %o0
	bz	%icc, .bzl_word
	nop

	! Clear bytes until word aligned
.bzl_byte:
	stba	%g0, [%o0]%asi
	add	%o0, 1, %o0
	btst	(4-1), %o0
	bnz	%icc, .bzl_byte
	sub	%o1, 1, %o1

	! Check for dword-aligned
	btst	(8-1), %o0
	bz	%icc, .bzl_dword
	nop
	
	! Clear words until double-word aligned
.bzl_word:
	sta	%g0, [%o0]%asi
	add	%o0, 4, %o0
	btst	(8-1), %o0
	bnz	%icc, .bzl_word
	sub	%o1, 4, %o1

.bzl_dword:
	! Clear dwords until block aligned
	stxa	%g0, [%o0]%asi
	add	%o0, 8, %o0
	btst	(64-1), %o0
	bnz	%icc, .bzl_dword
	sub	%o1, 8, %o1

.bzl_block:
	membar	#StoreStore|#StoreLoad|#LoadStore
	wr	%g0, FPRS_FEF, %fprs

	! Set the lower bit in the saved t_lofault to indicate
	! that we need to clear the %fprs register on the way
	! out
	or	%o5, FP_USED, %o5

	! Clear block
	fzero	%d0
	fzero	%d2
	fzero	%d4
	fzero	%d6
	fzero	%d8
	fzero	%d10
	fzero	%d12
	fzero	%d14
	rd	%asi, %o3
	wr	%g0, ASI_BLK_P, %asi
	cmp	%o3, ASI_P
	bne,a	%icc, 1f
	wr	%g0, ASI_BLK_AIUS, %asi
1:	
	mov	256, %o3
	ba,pt	%ncc, .bzl_doblock
	nop

.bzl_blkstart:	
      ! stda	%d0, [%o0+192]%asi  ! in dly slot of branch that got us here
	stda	%d0, [%o0+128]%asi
	stda	%d0, [%o0+64]%asi
	stda	%d0, [%o0]%asi
.bzl_zinst:
	add	%o0, %o3, %o0
	sub	%o1, %o3, %o1
.bzl_doblock:
	cmp	%o1, 256
	bgeu,a	%ncc, .bzl_blkstart
	stda	%d0, [%o0+192]%asi

	cmp	%o1, 64
	blu	%ncc, .bzl_finish
	
	andn	%o1, (64-1), %o3
	srl	%o3, 4, %o2		! using blocks, 1 instr / 16 words
	set	.bzl_zinst, %o4
	sub	%o4, %o2, %o4
	jmp	%o4
	nop

.bzl_finish:
	membar	#StoreLoad|#StoreStore
	wr	%g0, %g0, %fprs
	andn	%o5, FP_USED, %o5

	rd	%asi, %o4
	wr	%g0, ASI_P, %asi
	cmp	%o4, ASI_BLK_P
	bne,a	%icc, 1f
	wr	%g0, ASI_USER, %asi
1:

.bzlf_dword:
	! double words
	cmp	%o1, 8
	blu	%ncc, .bzlf_word
	nop
	stxa	%g0, [%o0]%asi
	add	%o0, 8, %o0
	sub	%o1, 8, %o1
	ba,pt	%ncc, .bzlf_dword
	nop

.bzlf_word:
	! words
	cmp	%o1, 4
	blu	%ncc, .bzlf_byte
	nop
	sta	%g0, [%o0]%asi
	add	%o0, 4, %o0
	sub	%o1, 4, %o1
	ba,pt	%ncc, .bzlf_word
	nop

1:
	add	%o0, 1, %o0		! increment address
.bzlf_byte:
	subcc	%o1, 1, %o1		! decrement count
	bgeu,a	%ncc, 1b
	stba	%g0, [%o0]%asi		! zero a byte

	!
	! If we used the FP registers, that bit was turned
	! off after we were finished. We're just concerned with
	! whether t_lofault was set when we came in. We end up
	! here from either kzero() or bzero(). kzero() *always*
	! sets a lofault handler. It ors LOFAULT_SET into %o5 
	! to indicate it has done this even if the value of %o5
	! is otherwise zero. bzero() sets a lofault handler *only*
	! if one was previously set. Accordingly we need to examine
	! %o5 and if it is non-zero be sure to clear LOFAULT_SET
	! before resetting the error handler.
	!
	tst	%o5
	bz,pt	%ncc, 1f	
	andn	%o5, LOFAULT_SET, %o5
	membar	#Sync				! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
1:
	retl
	clr	%o0			! return (0)

.bzero_small:

	!
	! Check for word alignment.
	!
	btst	3, %o0
	bz	.bzero_probe
	mov	0x100, %o3		! constant size of main loop
	!
	!
	! clear bytes until word aligned
	!
1:	stba	%g0,[%o0]%asi
	add	%o0, 1, %o0
	btst	3, %o0
	bnz	1b
	sub	%o1, 1, %o1
.bzero_probe:

	!
	! if needed move a word to become double-word aligned.
	!
	btst	7, %o0			! is double aligned?
	bz	%icc, .bzero_nobuf
	nop
	sta	%g0, [%o0]%asi		! clr to double boundry
	sub	%o1, 4, %o1
	ba,pt	%ncc, .bzero_nobuf
	add	%o0, 4, %o0

	!stxa	%g0, [%o0+0xf8]%asi
.bzero_blk:
	stxa	%g0, [%o0+0xf0]%asi
	stxa	%g0, [%o0+0xe8]%asi
	stxa	%g0, [%o0+0xe0]%asi
	stxa	%g0, [%o0+0xd8]%asi
	stxa	%g0, [%o0+0xd0]%asi
	stxa	%g0, [%o0+0xc8]%asi
	stxa	%g0, [%o0+0xc0]%asi
	stxa	%g0, [%o0+0xb8]%asi
	stxa	%g0, [%o0+0xb0]%asi
	stxa	%g0, [%o0+0xa8]%asi
	stxa	%g0, [%o0+0xa0]%asi
	stxa	%g0, [%o0+0x98]%asi
	stxa	%g0, [%o0+0x90]%asi
	stxa	%g0, [%o0+0x88]%asi
	stxa	%g0, [%o0+0x80]%asi
	stxa	%g0, [%o0+0x78]%asi
	stxa	%g0, [%o0+0x70]%asi
	stxa	%g0, [%o0+0x68]%asi
	stxa	%g0, [%o0+0x60]%asi
	stxa	%g0, [%o0+0x58]%asi
	stxa	%g0, [%o0+0x50]%asi
	stxa	%g0, [%o0+0x48]%asi
	stxa	%g0, [%o0+0x40]%asi
	stxa	%g0, [%o0+0x38]%asi
	stxa	%g0, [%o0+0x30]%asi
	stxa	%g0, [%o0+0x28]%asi
	stxa	%g0, [%o0+0x20]%asi
	stxa	%g0, [%o0+0x18]%asi
	stxa	%g0, [%o0+0x10]%asi
	stxa	%g0, [%o0+0x08]%asi
	stxa	%g0, [%o0]%asi
.zinst:
	add	%o0, %o3, %o0		! increment source address
	sub	%o1, %o3, %o1		! decrement count
.bzero_nobuf:
	cmp	%o1, 0x100		! can we do whole chunk?
	bgeu,a	%ncc, .bzero_blk
	stxa	%g0, [%o0+0xf8]%asi	! do first double of chunk

	cmp	%o1, 7			! can we zero any more double words
	bleu	%ncc, .byteclr		! too small go zero bytes

	andn	%o1, 7, %o3		! %o3 bytes left, double-word aligned
	srl	%o3, 1, %o2		! using doubles, need 1 instr / 2 words
	set	.zinst, %o4		! address of clr instructions
	sub	%o4, %o2, %o4		! jmp address relative to instr
	jmp	%o4
	nop
	!
	! do leftover bytes
	!
3:
	add	%o0, 1, %o0		! increment address
.byteclr:
	subcc	%o1, 1, %o1		! decrement count
	bgeu,a	%ncc, 3b
	stba	%g0, [%o0]%asi		! zero a byte

.bzero_finished:
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
