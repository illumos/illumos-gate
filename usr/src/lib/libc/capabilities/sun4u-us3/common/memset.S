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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

	.file	"memset.s"

/*
 * char *memset(sp, c, n)
 *
 * Set an array of n chars starting at sp to the character c.
 * Return sp.
 *
 * Fast assembler language version of the following C-program for memset
 * which represents the `standard' for the C-library.
 *
 *	void *
 *	memset(void *sp1, int c, size_t n)
 *	{
 *	    if (n != 0) {
 *		char *sp = sp1;
 *		do {
 *		    *sp++ = (char)c;
 *		} while (--n != 0);
 *	    }
 *	    return (sp1);
 *	}
 */

#include <sys/asm_linkage.h>
#include <sys/sun4asi.h>

	ANSI_PRAGMA_WEAK(memset,function)

#define	ALIGN8(X)	(((X) + 7) & ~7)
#define BLOCK_SIZE      64

	.section        ".text"
	.align 32

	ENTRY(memset)
	cmp	%o2, 12			! if small counts, just write bytes
	bgeu,pn	%ncc, .wrbig
	mov	%o0, %o5		! copy sp1 before using it

.wrchar:
	deccc   %o2			! byte clearing loop
        inc     %o5
	bgeu,a,pt %ncc, .wrchar
        stb     %o1, [%o5 + -1]         ! we've already incremented the address

        retl
	.empty	! next instruction is safe, %o0 still good

.wrbig:
        andcc	%o5, 7, %o3		! is sp1 aligned on a 8 byte bound
        bz,pt	%ncc, .blkchk		! already double aligned
	and	%o1, 0xff, %o1		! o1 is (char)c
        sub	%o3, 8, %o3		! -(bytes till double aligned)
        add	%o2, %o3, %o2		! update o2 with new count

	! Set -(%o3) bytes till sp1 double aligned
1:	stb	%o1, [%o5]		! there is at least 1 byte to set
	inccc	%o3			! byte clearing loop
        bl,pt	%ncc, 1b
        inc	%o5


	! Now sp1 is double aligned (sp1 is found in %o5)
.blkchk:
	sll     %o1, 8, %o3
        or      %o1, %o3, %o1		! now o1 has 2 bytes of c

        sll     %o1, 16, %o3
        or      %o1, %o3, %o1		! now o1 has 4 bytes of c

	cmp     %o2, 4095		! if large count use Block ld/st

	sllx	%o1, 32, %o3
	or	%o1, %o3, %o1		! now o1 has 8 bytes of c

        bgu,a,pn %ncc, .blkwr		! Do block write for large count
        andcc   %o5, 63, %o3            ! is sp1 block aligned?

	and	%o2, 24, %o3		! o3 is {0, 8, 16, 24}

1:	subcc	%o3, 8, %o3		! double-word loop
	add	%o5, 8, %o5
	bgeu,a,pt %ncc, 1b
	stx	%o1, [%o5 - 8]		! already incremented the address

	andncc	%o2, 31, %o4		! o4 has 32 byte aligned count
	bz,pn	%ncc, 3f		! First instruction of icache line
2:
	subcc	%o4, 32, %o4		! main loop, 32 bytes per iteration
	stx	%o1, [%o5 - 8]
	stx	%o1, [%o5]
	stx	%o1, [%o5 + 8]
	stx	%o1, [%o5 + 16]
	bnz,pt	%ncc, 2b
	add	%o5, 32, %o5

3:
	and	%o2, 7, %o2		! o2 has the remaining bytes (<8)

4:
	deccc   %o2                     ! byte clearing loop
        inc     %o5
        bgeu,a,pt %ncc, 4b
        stb     %o1, [%o5 - 9]		! already incremented the address

	retl
	nop				! %o0 still preserved

.blkwr:
        bz,pn   %ncc, .blalign		! now block aligned
        sub	%o3, 64, %o3		! o3 is -(bytes till block aligned)
	add	%o2, %o3, %o2		! o2 is the remainder

        ! Store -(%o3) bytes till dst is block (64 byte) aligned.
        ! Use double word stores.
	! Recall that dst is already double word aligned
1:
        stx     %o1, [%o5]
	addcc   %o3, 8, %o3
	bl,pt	%ncc, 1b
	add     %o5, 8, %o5

	! sp1 is block aligned
.blalign:
        rd      %fprs, %g1              ! g1 = fprs

	and	%o2, 63, %o3		! calc bytes left after blk store.

	andcc	%g1, 0x4, %g1		! fprs.du = fprs.dl = 0
	bz,a	%ncc, 2f		! Is fprs.fef == 0
        wr      %g0, 0x4, %fprs         ! fprs.fef = 1
2:
	brnz,pn	%o1, 3f			! %o1 is safe to check all 64-bits
	andn	%o2, 63, %o4		! calc size of blocks in bytes
	fzero   %d0
	fzero   %d2
	fzero   %d4
	fzero   %d6
	fmuld   %d0, %d0, %d8
	fzero   %d10
	ba	4f
	fmuld   %d0, %d0, %d12

3:
	! allocate 8 bytes of scratch space on the stack
	add	%sp, -SA(16), %sp
	stx	%o1, [%sp + STACK_BIAS + ALIGN8(MINFRAME)]  ! move %o1 to %d0
	ldd	[%sp + STACK_BIAS + ALIGN8(MINFRAME)], %d0

	fmovd	%d0, %d2
	add	%sp, SA(16), %sp	! deallocate the scratch space
	fmovd	%d0, %d4
	fmovd	%d0, %d6
	fmovd	%d0, %d8
	fmovd	%d0, %d10
	fmovd	%d0, %d12
4:
	fmovd	%d0, %d14

	! 1st quadrant has 64 bytes of c
	! instructions 32-byte aligned here
#ifdef PANTHER_ONLY
	! Panther only code
	prefetch	[%o5 + (3 * BLOCK_SIZE)], 22
	prefetch	[%o5 + (6 * BLOCK_SIZE)], 22
	std	%d0, [%o5]
	std	%d0, [%o5 + 8]
	std	%d0, [%o5 + 16]
	std	%d0, [%o5 + 24]
	std	%d0, [%o5 + 32]
	std	%d0, [%o5 + 40]
	std	%d0, [%o5 + 48]
	std	%d0, [%o5 + 56]
#else
	! Cheetah/Jaguar code
        stda    %d0, [%o5]ASI_BLK_P
#endif
        subcc   %o4, 64, %o4
        bgu,pt	%ncc, 4b
        add     %o5, 64, %o5

	! Set the remaining doubles
	subcc   %o3, 8, %o3		! Can we store any doubles?
	blu,pn  %ncc, 6f
	and	%o2, 7, %o2		! calc bytes left after doubles

5:
	std     %d0, [%o5]		! store the doubles
	subcc   %o3, 8, %o3
	bgeu,pt	%ncc, 5b
        add     %o5, 8, %o5
6:
	! Set the remaining bytes
	brz	%o2, .exit		! safe to check all 64-bits

#if 0
	! Terminate the copy with a partial store. (bug 1200071 does not apply)
	! The data should be at d0
        dec     %o2                     ! needed to get the mask right
	edge8n	%g0, %o2, %o4
	stda	%d0, [%o5]%o4, ASI_PST8_P
#else
7:
	deccc	%o2
	stb	%o1, [%o5]
	bgu,pt	%ncc, 7b
	inc	%o5
#endif

.exit:
        membar  #StoreLoad|#StoreStore
        retl				! %o0 was preserved
        wr	%g1, %g0, %fprs         ! fprs = g1  restore fprs

	SET_SIZE(memset)
