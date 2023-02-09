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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

#include "assym.h"


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
 * Copy a block of storage, returning an error code if `from' or
 * `to' takes a kernel pagefault which cannot be resolved.
 * Returns errno value on pagefault error, 0 if all ok
 */



	.seg	".text"
	.align	4

	ENTRY(kcopy)

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
	membar	#Sync			! sync error barrier
	stn	%o5, [THREAD_REG + T_LOFAULT]	! restore old t_lofault
	ret
	restore	%g1, 0, %o0

	SET_SIZE(kcopy)


/*
 * Copy a block of storage - must not overlap (from + len <= to).
 */

	ENTRY(bcopy)

	save	%sp, -SA(MINFRAME), %sp
	clr	%o5			! flag LOFAULT_SET is not set for bcopy

.do_copy:
        mov     %i1, %g5                ! save dest addr start

        mov     %i2, %l6                ! save size

	cmp	%i2, 12			! for small counts
	blu	%ncc, .bytecp		! just copy bytes
	  .empty

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
        mov     %g5, %o0                ! copy dest address
        call    sync_icache
        mov     %l6, %o1                ! saved size
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
	mov     %i1,    %o0     ! store destination address for flushing

	/*
	 * Copying exactly one page and PAGESIZE is in mutliple of 0x80. 
	 */
1:
	ldx	[%i0+0x0], %l0
	ldx	[%i0+0x8], %l1
	ldx	[%i0+0x10], %l2
	ldx	[%i0+0x18], %l3
	ldx	[%i0+0x20], %l4
	ldx	[%i0+0x28], %l5
	ldx	[%i0+0x30], %l6
	ldx	[%i0+0x38], %l7
	stx	%l0, [%i1+0x0]
	stx	%l1, [%i1+0x8]
	stx	%l2, [%i1+0x10]
	stx	%l3, [%i1+0x18]
	stx	%l4, [%i1+0x20]
	stx	%l5, [%i1+0x28]
	stx	%l6, [%i1+0x30]
	stx	%l7, [%i1+0x38]

	ldx	[%i0+0x40], %l0
	ldx	[%i0+0x48], %l1
	ldx	[%i0+0x50], %l2
	ldx	[%i0+0x58], %l3
	ldx	[%i0+0x60], %l4
	ldx	[%i0+0x68], %l5
	ldx	[%i0+0x70], %l6
	ldx	[%i0+0x78], %l7
	stx	%l0, [%i1+0x40]
	stx	%l1, [%i1+0x48]
	stx	%l2, [%i1+0x50]
	stx	%l3, [%i1+0x58]
	stx	%l4, [%i1+0x60]
	stx	%l5, [%i1+0x68]
	stx	%l6, [%i1+0x70]
	stx	%l7, [%i1+0x78]

	add	%i0, 0x80, %i0
	subcc	%i2, 0x80, %i2
	bgu,pt	%xcc, 1b
	add	%i1, 0x80, %i1

	! %o0 contains the dest. address
	set	PAGESIZE, %o1
	call	sync_icache
	nop

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
 * None of the copyops routines grab a window.
 *
 * Flow:
 *
 * If count == zero return zero.
 *
 * Store the previous lo_fault handler into %g6.
 * Place our secondary lofault handler into %g5.
 * Place the address of our fault handler into %o3.
 *
 * If count is less than or equal to SMALL_LIMIT (7) we
 * always do a byte for byte copy.
 *
 * If count is > SMALL_LIMIT, we check the alignment of the input
 * and output pointers.  We store -count in %o3, we store the number
 * of chunks (8, 4, 2 or 1 byte) operated on in our basic copy loop
 * in %o2. Following this we branch to the appropriate copy loop and
 * copy that many chunks.  Since we've been adding the chunk size
 * to %o3 each time through as well as decrementing %o2, we can tell
 * if any data is is left to be copied by examining %o3. If that is
 * zero, we're done and can go home. If not, we figure out what the
 * largest chunk size left to be copied is and branch to that copy
 * loop unless there's only one byte left. We load that as we're
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
	membar	#Sync
	stn	SAVED_LOFAULT, [THREAD_REG + T_LOFAULT]	! restore old t_lofault

	mov	SAVE_SRC, %o0
	mov	SAVE_DST, %o1
	jmp	REAL_LOFAULT
	  mov	SAVE_COUNT, %o2
	SET_SIZE(copyio_fault)

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
	sethi	%hi(copyio_fault), %o3
	ldn	[THREAD_REG + T_LOFAULT], SAVED_LOFAULT
	or	%o3, %lo(copyio_fault), %o3
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

	ba	.dcobcp
	nop
.dcoh8:
	!
	! 8 byte aligned?
	!
	bnz,a	%ncc, .dcoh4
	btst	3, %o3
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
.dcos2:
	add	%o0, %o2, %o0
	add	%o1, %o2, %o1
	sub	%g0, %o2, %o3
	ba,pt	%ncc, .dodtbc
	srl	%o2, 1, %o2		! Number of 2 byte chunks to copy

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
	sethi	%hi(copyio_fault), %o3
	ldn	[THREAD_REG + T_LOFAULT], SAVED_LOFAULT
	or	%o3, %lo(copyio_fault), %o3
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
	ba	.dcibcp
	nop

.dcih8:
	!
	! 8 byte aligned?
	!
	bnz,a	%ncc, .dcih4
	btst	3, %o3
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
.dcis2:
	add	%o0, %o2, %o0
	add	%o1, %o2, %o1
	sub	%g0, %o2, %o3
	ba,pt	%ncc, .didtbc
	srl	%o2, 1, %o2		! Number of 2 byte chunks to copy

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
	DGDEF(use_hw_bzero)
	.word	1

	.align	64
	.section ".text"


/*
 * hwblkclr - clears block-aligned, block-multiple-sized regions that are
 * longer than 256 bytes in length. For the generic module we will simply
 * call bzero and return 1 to ensure that the pages in cache should be
 * flushed to ensure integrity.
 * Caller is responsible for ensuring use_hw_bzero is true and that
 * kpreempt_disable() has been called.
 */
	! %i0 - start address
	! %i1 - length of region (multiple of 64)

	ENTRY(hwblkclr)
	save	%sp, -SA(MINFRAME), %sp

	! Simply call bzero and notify the caller that bzero was used
	mov	%i0, %o0
	call	bzero
	  mov	%i1, %o1
	ret
	restore	%g0, 1, %o0	! return (1) - did not use block operations

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
