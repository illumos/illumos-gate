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

#define	SAVESIZE	(8 * 1)
#ifdef	__sparcv9
#define	STACK_OFFSET	(STACK_BIAS + 0)
#else
#define	STACK_OFFSET	(STACK_BIAS + 0 + 0)
#endif
#define	scratch_offset	0

#define ASI_CACHE_SPARING_PRIMARY 0xf4
#define	ALIGN8(X)	(((X) + 7) & ~7)
#define	ICACHE_LINE_SIZE	64
#define	FPRS_FEF	0x4
#define	PF_FAR		2048

	.section        ".text"
	.align ICACHE_LINE_SIZE

	/*
	 * Optimizations done:
	 *
	 * No stores in delay slot of branch instructions.
	 * conditional stores where possible
	 * prefetch before doing stxa
	 * Bank interleaved writing.
	 */

	ENTRY(memset)
	add	%sp, -SA(STACK_OFFSET + SAVESIZE), %sp
	mov	%o0, %o5		! copy sp1 before using it
	/*
	 * If 0 bytes to xfer return
	 */
	brnz	%o2, continue
	nop
	retl
	add	%sp, SA(STACK_OFFSET + SAVESIZE), %sp
continue:
	/*
	 * If the count is multiple of 8 and buffer is aligned to 8
	 * we don't have to look at fprs
	 */
	or	%o5, %o2, %o3
	and	%o3, 7, %o3
        brnz	%o3, check_fprs
	mov	4, %g1
	prefetch	[%o5],2
	ba	skip_rd_fprs
	nop
	
check_fprs:
        rd      %fprs, %g1              ! g1 = fprs
skip_rd_fprs:
	prefetch	[%o5],2
	andcc	%g1, 0x4, %g1		! fprs.du = fprs.dl = 0
	bnz	%ncc, 1f		! Is fprs.fef == 1
	nop
        wr      %g0, FPRS_FEF, %fprs	! fprs.fef = 1
1:
	and	%o1, 0xff, %o1		! o1 is (char)c
	sll     %o1, 8, %o3
        or      %o1, %o3, %o1		! now o1 has 2 bytes of c
        sll     %o1, 16, %o3
        or      %o1, %o3, %o1		! now o1 has 4 bytes of c
	sllx	%o1, 32, %o3
	or	%o1, %o3, %o1		! now o1 has 8 bytes of c
	stx	%o1, [%sp + STACK_OFFSET + scratch_offset]
	ldd	[%sp + STACK_OFFSET + scratch_offset], %d0
	cmp	%o2, 8
	bge,pt	%ncc, xfer_8_or_more
	mov	%o0, %o5
	/*
	 * Do a partial store of %o2 bytes
	 */
        andcc	%o5, 7, %o3		! is sp1 aligned on a 8 byte bound
        brz,pt	%o3, aligned_on_8		
        sub	%o5, %o3, %o5		! align the  destination buffer.
	mov	%o3, %o1
	mov	8, %o4
	sub 	%o4, %o3, %o3
	cmp	%o3, %o2
	bg,a,pn	%ncc, 1f
	mov	%o2, %o3	
1:
	! %o3 has the bytes to be written in partial store.
	sub	%o2, %o3, %o2
	dec	%o3
	prefetch	[%o5],2
	edge8n	%g0, %o3, %o4
	srl	%o4, %o1, %o4
	stda	%d0, [%o5]%o4, ASI_PST8_P
	brz	%o2, simple_ret
	add	%o5, 8, %o5
aligned_on_8:
	prefetch	[%o5],2
        dec     %o2                     ! needed to get the mask right
	edge8n	%g0, %o2, %o4
	stda	%d0, [%o5]%o4, ASI_PST8_P
	brnz	%g1, 1f			! was fprs.fef == 1
	nop
        wr	%g1, %g0, %fprs         ! fprs = g1  restore fprs
1:
	retl
	add	%sp, SA(STACK_OFFSET + SAVESIZE), %sp

xfer_8_or_more:
        andcc	%o5, 7, %o3		! is sp1 aligned on a 8 byte bound
        brz,pt	%o3, blkchk		
        sub	%o5, %o3, %o5		! align the  destination buffer.
        sub	%o3, 8, %o3		! -(bytes till double aligned)
        add	%o2, %o3, %o2		! update o2 with new count
	xor	%o3, 0xff, %o3
	and	%o3, 7, %o3
	prefetch	[%o5],2
	edge8ln	%g0, %o3, %o4
	stda	%d0, [%o5]%o4, ASI_PST8_P
	add	%o5, 8, %o5


	! Now sp1 is double aligned (sp1 is found in %o5)
blkchk:
	cmp     %o2, 767		! if large count use Block ld/st
	bg,pt	%ncc,blkwr
	nop

	
	and	%o2, 24, %o3		! o3 is {0, 8, 16, 24}

	brz	%o3, skip_dw_loop
	nop

1:	subcc	%o3, 8, %o3		! double-word loop
	stx	%o1, [%o5]
	bgu,pt %ncc, 1b
	add	%o5, 8, %o5
skip_dw_loop:
	andncc	%o2, 31, %o4		! o4 has 32 byte aligned count
	brz,pn	%o4, 3f
	nop
	ba	loop_32byte
	nop

	.align	ICACHE_LINE_SIZE

loop_32byte:
	subcc	%o4, 32, %o4		! main loop, 32 bytes per iteration
	stx	%o1, [%o5]
	stx	%o1, [%o5 + 8]
	stx	%o1, [%o5 + 16]
	stx	%o1, [%o5 + 24]
	bne,pt  %ncc, loop_32byte
	add	%o5, 32, %o5
3:	
	and	%o2, 7, %o2		! o2 has the remaining bytes (<8)
	brz	%o2, skip_partial_copy
	nop

	! Terminate the copy with a partial store.
	! The data should be at d0
	prefetch	[%o5],2
        dec     %o2                     ! needed to get the mask right
	edge8n	%g0, %o2, %o4
	stda	%d0, [%o5]%o4, ASI_PST8_P

skip_partial_copy:
simple_ret:
	brz,a	%g1, 1f			! was fprs.fef == 0
        wr	%g1, %g0, %fprs         ! fprs = g1  restore fprs
1:
	retl
	add	%sp, SA(STACK_OFFSET + SAVESIZE), %sp

blkwr:
        sub     %o5,1,%o3
        andn    %o3,0x7f,%o4
        add     %o4,128,%o4
        prefetch [%o4],2		!prefetch next 128b
        prefetch [%o4+64],2
        prefetch [%o4+(2*64)],2		!cont from above
        prefetch [%o4+(3*64)],2

        andcc   %o5,0x7f,%o3            !o3=0 , means it is already 128 align
        brz,pn  %o3,alreadyalign128
        sub     %o3,128,%o3

        add     %o2,%o3,%o2
align128:
        stxa    %o1,[%o5]ASI_CACHE_SPARING_PRIMARY
        addcc   %o3,8,%o3
        bl,pt   %ncc,align128
        add     %o5,8,%o5



alreadyalign128:
	andcc	%o5,0x1ff,%o3	!%o3=0 when it is 512 b aligned.
	brnz,pn	%o3, 4f
	mov	%o2,%g5		!g5=count from 512 align
	set	4096, %o4
	subcc	%o2, %o4, %g0
	bge,pn	%ncc, larry_alg
	nop
4:

	sub	%o5,8,%o4	!should be in current 512 chunk
	andn 	%o4,0x1ff,%o3	!%o3=aligned 512b addr
	add 	%o3,0x200,%o3	!%o3=next aligned 512b addr which start larry process
	sub 	%o3,%o5,%o3	!o3=how many byte in the current remaining chunk
	sub	%o2,%o3,%g5	!g5=count from 512 align
	/*
	 * if g5 is < 4096 do start_128 only.
	 */
	set	4096, %o4
	subcc	%g5, %o4, %g0
	bge,pn	%ncc,6f
	nop
	mov	%g0, %g5
	add	%o5, %o2, %o4
	ba	start_128
	nop
6:
	mov	%o3, %o2
	subcc 	%o3,256,%g0	!if it is > 256 bytes , could use the st-interleave alg to wr
	bl,pn	%ncc,storeword	!o.w use storeword to finish the 512 byte alignment.
        !%o1=64 bytes data
        !%o5=next 8 byte addr to write
        !%o2=new count i.e how many bytes to write
        add     %o5,%o2,%o4             !cal the last byte to write %o4
	ba	start_128
	nop

	.align	64
start_128:
	add	%o5, 256, %o3
	prefetch [%o3], 2	!1st 64 byte line of next 256 byte block
	add	%o5, 384, %o3
	prefetch [%o3], 2	!3rd 64 byte line of next 256 byte block
	add	%o5, 320, %o3
	prefetch [%o3], 2	!2nd 64 byte line of next 256 byte block
	add	%o5, 448, %o3
	prefetch [%o3], 2	!4th 64 byte line of next 256 byte block
	mov	%o5, %o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY	!1st 64 byte line
        add     %o5,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY	!3rd 64 byte line
        add     %o5,8,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(2 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128 ,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(3 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(4 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(5 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(6 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(7 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(8 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(9 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(10 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(11 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(12 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(13 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(14 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(15 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,512,%o3  !%o3=final byte of next 256 byte, to check if more 256 byte block ahead
        subcc   %o4,%o3,%g0   !%o4=final byte location;%o3=final byte of next 256 byte block
        bge,pt  %ncc,start_128    !branch taken means next 256 byte block is still within the limit.
        add     %o5,256,%o5

!need to connect the rest of the program
storeword:
        and     %o2,255,%o3
        and     %o3,7,%o2

	! Set the remaining doubles
	subcc   %o3, 8, %o3		! Can we store any doubles?
	bl,pn  %ncc, 6f
	and	%o2, 7, %o2		! calc bytes left after doubles

5:	
	stxa	%o1, [%o5]ASI_CACHE_SPARING_PRIMARY
	subcc   %o3, 8, %o3
	bge,pt	%ncc, 5b
        add     %o5, 8, %o5      
6:
	! Set the remaining bytes
	brz	%o2,  check_larry_alg		! safe to check all 64-bits
	
	! Terminate the copy with a partial store.
	! The data should be at d0
        dec     %o2                     ! needed to get the mask right
	edge8n	%g0, %o2, %o4
	stda	%d0, [%o5]%o4, ASI_PST8_P
check_larry_alg:
	mov	%g5, %o2
	brnz,pn	%o2, larry_alg
	nop
	
.exit:	
	brz,a	%g1, 1f			! was fprs.fef == 0
        wr	%g1, %g0, %fprs         ! fprs = g1  restore fprs
1:
        retl				! %o0 was preserved
	add	%sp, SA(STACK_OFFSET + SAVESIZE), %sp

larry_alg:
	add	%sp, SA(STACK_OFFSET + SAVESIZE), %sp
	save	%sp, -SA(MINFRAME), %sp
	mov	%i0, %o0
	mov	%i1, %o1
	mov	%i2, %o2
	mov	%i3, %o3
	mov	%i5, %o5
!%o5 = next memory addr which is 512 b align
!%g5 = remaining byte from 512 align.
init:
	set     4096,%g6

        prefetch [%o5+0],2
        prefetch [%o5+(64*1)],2
        prefetch [%o5+(64*2)],2
        prefetch [%o5+(64*3)],2
        prefetch [%o5+(64*4)],2
        prefetch [%o5+(64*5)],2
        prefetch [%o5+(64*6)],2
        prefetch [%o5+(64*7)],2
        prefetch [%o5+(64*8)],2
        prefetch [%o5+(64*9)],2
        prefetch [%o5+(64*10)],2
        prefetch [%o5+(64*11)],2
        prefetch [%o5+(64*12)],2
        prefetch [%o5+(64*13)],2
        prefetch [%o5+(64*14)],2
        prefetch [%o5+(64*15)],2
        ba      myloop2
	add     %o5,%g5,%g5
        /* Local register usage:
           %l3   save %o5 at start of inner loop.
           %l5   iteration counter to make buddy loop execute 2 times.
           %l6   iteration counter to make inner loop execute 32 times.
           %l7   address at far ahead of current %o5 for prefetching destination into L2 cache.
	 */

	.align 64
myloop2:
	/* Section 1 */
        set      2,%l5    /* %l5 is the loop count for the buddy loop, for 2 buddy lines.  */
        add      %o5, 0, %l3
buddyloop:
        set      PF_FAR, %l4        /* Prefetch far ahead.             CHANGE FAR PREFETCH HERE.     <<==== */
        add      %o5, %l4, %l7      /* For prefetching far ahead, set %l7 far ahead of %o5           */

        set      2*PF_FAR, %l4      /* Prefetch double far ahead.  SET DOUBLE FAR PREFETCH HERE.     <<==== */
        add      %o5, %l4, %l4      /* %l4 is now double far ahead of the dest address in %o5.       */
        prefetch [%l4+%g0],2        /* Prefetch ahead by 2 pages to get TLB entry in advance.        */

        set      4,%l6             /* %l6 = loop count for the inner loop, for 4 x 8 = 32 lines.     */
        set      0, %l4


/* Each iteration of the inner loop below writes 8 sequential lines.  This loop is iterated 4 times,
   to move a total of 32 lines, all of which have the same value of PA[9], so we increment the base
   address by 1024 bytes in each iteration, which varies PA[10].                                     */
innerloop:
	add	%o5, PF_FAR, %o3
	prefetch [%o3],2
	add	%o3, 64, %o3
	prefetch [%o3],2
	add	%o3, 64, %o3
	prefetch [%o3],2
	add	%o3, 64, %o3
	prefetch [%o3],2
	add	%o3, 64, %o3
	prefetch [%o3],2
	add	%o3, 64, %o3
	prefetch [%o3],2 
	add	%o3, 64, %o3
	prefetch [%o3],2
	add	%o3, 64, %o3
	prefetch [%o3],2

	mov	%o5, %o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY	!1st 64 byte line
        add     %o5,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY	!3rd 64 byte line
        add     %o5,8,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(2 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128 ,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(3 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(4 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(5 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(6 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(7 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(8 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(9 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(10 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(11 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(12 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(13 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(14 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(15 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY

        add     %o5,256,%o5

	mov	%o5, %o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY	!1st 64 byte line
        add     %o5,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY	!3rd 64 byte line
        add     %o5,8,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(2 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128 ,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(3 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(4 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(5 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(6 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(7 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(8 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(9 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(10 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(11 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(12 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(13 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(14 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(15 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY

        subcc   %l6,1,%l6    /* Decrement the inner loop counter.         */

        /* -------- Now increment by 256 + 512 so we don't toggle PA[9] -------- */
        add     %o5, 768, %o5

        bg,pt   %ncc,innerloop
        nop
/* ------------------------ END OF INNER LOOP -------------------------- */

        subcc   %l5,1,%l5
        add     %l3, 512, %o5       /* increment %o5 to first buddy line of dest.   */
        bg,pt   %ncc,buddyloop
	nop
        add     %o5, 3584, %o5      /* Advance both base addresses to 4k above where they started. */
                                        !%o5=next 4096 block.
	add %o5,%g6,%i5
	subcc %g5,%i5,%g0
        bge,pt   %ncc,myloop2
        nop


	/****larryalg_end_here*************/

	sub	%g5,%o5,%o2	!how many byte left
	brz,pn	%o2,complete_write
	mov	%g0,%g5
	add     %o5,%o2,%o4             !cal the last byte to write %o4
	subcc	%o2,256,%g0
	bge,pt	%ncc,memset_128
	mov	%g0,%g5
	
	ba	memset_storeword
	nop


complete_write: 
	brz,a	%g1, 1f			! was fprs.fef == 0
        wr	%g1, %g0, %fprs         ! fprs = g1  restore fprs
1:
        ret				! %o0 was preserved
	restore

	.align	64
memset_128:
	add	%o5, 256, %o3
	prefetch [%o3], 2	!1st 64 byte line of next 256 byte block
	add	%o5, 384, %o3
	prefetch [%o3], 2	!3rd 64 byte line of next 256 byte block
	add	%o5, 320, %o3
	prefetch [%o3], 2	!2nd 64 byte line of next 256 byte block
	add	%o5, 448, %o3
	prefetch [%o3], 2	!4th 64 byte line of next 256 byte block
	mov	%o5, %o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY	!1st 64 byte line
        add     %o5,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY	!3rd 64 byte line
        add     %o5,8,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(2 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128 ,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(3 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(4 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(5 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(6 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(7 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(8 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(9 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(10 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(11 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(12 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(13 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(14 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,(15 * 8),%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
        add     %o5,512,%l4  !%l4=final byte of next 256 byte, to check if more 256 byte block ahead
        add     %o3,128,%o3
        stxa     %o1,[%o3]ASI_CACHE_SPARING_PRIMARY
!this branch condition is not needed if we are handling bytes before 4096b
!because we will only issue once, so %l6 is an invalid data
!the branch is really for handling bytes after 4096b, there could be
!multiple of 256 byte block to work on. 

        subcc   %o4,%l4,%g0   !%o4=final byte location;%l4=final byte of next 256 byte block
        bge,pt  %ncc,memset_128    !branch taken means next 256 byte block is still within the limit.
        add     %o5,256,%o5

!need to connect the rest of the program
memset_storeword:
        and     %o2,255,%o3
        and     %o3,7,%o2

	! Set the remaining doubles
	subcc   %o3, 8, %o3		! Can we store any doubles?
	bl,pn  %ncc, 6f
	and	%o2, 7, %o2		! calc bytes left after doubles

5:	
	stxa	%o1, [%o5]ASI_CACHE_SPARING_PRIMARY
	subcc   %o3, 8, %o3
	bge,pt	%ncc, 5b
        add     %o5, 8, %o5      
6:
	! Set the remaining bytes
	brz	%o2,  complete_write		! safe to check all 64-bits
	
	! Terminate the copy with a partial store.
	! The data should be at d0
        dec     %o2                     ! needed to get the mask right
	edge8n	%g0, %o2, %o4
	stda	%d0, [%o5]%o4, ASI_PST8_P
	
	brz,a	%g1, 1f			! was fprs.fef == 0
        wr	%g1, %g0, %fprs         ! fprs = g1  restore fprs
1:
        ret				! %o0 was preserved
	restore


	SET_SIZE(memset)
