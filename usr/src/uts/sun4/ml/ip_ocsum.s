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
#include <sys/machparam.h>

#include "assym.h"

/*
 * Prefetch considerations
 * 
 * We prefetch one cacheline ahead.  This may not be enough on Serengeti
 * systems - see default_copyout() etc which prefetch 5 lines ahead.
 * On the other hand, we expect most of the source buffers to be
 * recently used enough to be cached.
 *
 * On US-I the prefetches are inoperative.  On US-II they preload the E$;
 * the mainloop unrolling and load-buffer should cover loads from E$.
 * The stores appear to be the slow point on US-II.
 * 
 * On US-IIICu the prefetch preloads the L2$ too, but there is no load
 * buffer so the loads will stall for D$ miss, L2$ hit.  The hardware
 * auto-prefetch is not activated by integer loads.  No solution
 * in sight for this, barring odd games with FP read, write, integer read.
 * 
 * US-IV (Panther) appears similar to US-IIICu, except that a strong
 * variant of prefetch is available which can take TLB traps.  We don't
 * use this.  The h/w prefetch stride can be set to 64, 128 or 192,
 * and they only reach to the L2$ (we don't use these either).
 * L2$ load-to-use latency is 15 cycles (best).
 */


/*
 * ip_ocsum(address, halfword_count, sum)
 * Do a 16 bit one's complement sum of a given number of (16-bit)
 * halfwords. The halfword pointer must not be odd.
 *	%o0 address; %o1 count; %o2 sum accumulator; %o4 temp
 * 	%g2 and %g3 used in main loop
 *
 * (from @(#)ocsum.s 1.3 89/02/24 SMI)
 *
 */

	ENTRY(ip_ocsum)

/*
 * On ttcp transmits, called once per ocsum_copyin but with a small
 * block ( >99.9% ).  Could be the tx hdrs?  How many acks/seg are we rxing?
 * On ttcp receives, called more than once per ocsum_copyout. Rx hdrs
 * and tx acks?
 *
 * To do: telnet and nfs traffic
 *
 * On an NCA'd webserver about 10% of the calls are >64 bytes
 *	about 10% of those start on a 64byte boundary
 *	about 30% are >5*64 bytes.
 * The NCA numbers & proportions don't change with h/w cksum on.
 *
 * Tx hdrs are likely to be already in cache.
 * Rx hdrs depends if already inspected.
 */

	!
	! Entry point for checksum-only.
	! %o0 contains buffer address
	! %o1 contains count of 16bit words
	! %o2 contains sum
	!
	! %o3 temporary
	! %o4 temporary
	! %g1 32bit mask
	! %g4 16bit mask
	! %g5 64bit mask (all 1s)
	!
	not	%g0, %g5	! all 1's
	prefetch [%o0], #n_reads	! first hword, dword, cacheline

	clruw	%g5, %g1	! 32 1's at low end
	srl	%g5, 16, %g4	! 16 1's at low end

	cmp	%o1, 32		! at least a cacheline (64 bytes)?
	bge,pn %icc, ip_ocsum_long	! yes, do the whole works
	andn	%o0, 7, %o5	! delay: base src addr


	cmp	%o1, 4		! < 4 halfwords?
	bl,pn	%icc, .tiny	! < 4 halfwords, just do them
	inc	8, %o5		! delay: next addr (no matter for .tiny)

	/* leading dword with 1-4 hwords: 9 clocks */
	/* Assumes ok to read the entire dword with the leading hwords */

	ldx	[%o5-8], %o3	! NB base addr
	sub	%o5, %o0, %g2	! byte count: 2/4/6/8
	mov	%o5, %o0

	sll	%g2, 2, %g2	! 8/16/24/32 for mask

	sllx	%g5, %g2, %o5

	sllx	%o5, %g2, %o5	! mask: 16/32/48/64 0's at low end

	srl	%g2, 3, %g2	! hw count
	andn	%o3, %o5, %o3	! select hw's from src

	srlx	%o3, 32, %o4	! hi32
	b	9f
	sub	%o1, %g2, %o1	! delay: decr count, 1-4 halfwords

.short_dw:			! max 7 iters of 4 clocks; 1 mispred of 4
	ldx	[%o0], %o3	! tmp64 = *src++ (groups with the branch)

	inc	8, %o0		! (D-cache load-use delay)
	dec	4, %o1		! decrement count, 4 halfwords

	srlx	%o3, 32, %o4	! hi32
9:	and	%o3, %g1, %o3	! lo32

	add	%o4, %o2, %o2	! accumulator
	andncc	%o1, 3, %g0	! more than 3 hwords left?

	bnz,pt %icc, .short_dw
	add	%o3, %o2, %o2	! accumulator

.short_hw:			! trailing dw: 0-3 hwords
	tst	%o1		! 0 seems fairly common...
	bz,a	.short_fold
	srlx	%o2, 32, %o4	! delay: hi32
				! mispredict 4 + 7 clocks for 1-3
	ldx	[%o0], %o3
	sll	%o1, 4, %o1	! bitcount: 16/32/48

	srlx	%g5, %o1, %o5	! mask: 16/32/48  0's at high end

	andn	%o3, %o5, %o3	! select hw's from src

	srlx	%o3, 32, %o4	! hi32
	and	%o3, %g1, %o3	! lo32

	add	%o4, %o2, %o2	! accumulator

	add	%o3, %o2, %o2	! accumulator

	! at this point the 64-bit accumulator
	! has the result that needs to be returned in 16-bits
	srlx	%o2, 32, %o4	! hi32
.short_fold:
	and	%o2, %g1, %o2	! lo32

	add	%o4, %o2, %o2	! 33b

	srlx	%o2, 16, %o3	! hi17
	and	%o2, %g4, %o2	! lo16

	add	%o3, %o2, %o2	! 18b

	srlx	%o2, 16, %o3	! hi2
	and	%o2, %g4, %o2	! lo16

	retl			! return
	add	%o3, %o2, %o0	! 16b result in %o0

.tiny:				! almost never: less than 4 halfwords total.
	tst	%o1
	bz,a	.short_fold

	srlx	%o2, 32, %o4	! delay: hi32

	lduh	[%o0], %o3	! tmp16 = *src++
1:	
	inc	2, %o0
				! stall for D-cache

	add	%o3, %o2, %o2	! accumulator

	deccc	%o1		! decrement count
	bnz,a,pt %icc, 1b
	lduh	[%o0], %o3	! tmp16 = *src++

	! at this point the 64-bit accumulator
	! has the result that needs to be returned in 16-bits
	b	.short_fold
	srlx	%o2, 32, %o4	! hi32

	SET_SIZE(ip_ocsum)	! 64-bit version


	ENTRY(ip_ocsum_long)	! 64-bit, large blocks
	save	%sp, -SA(MINFRAME), %sp	! get another window
	!
	! %i0 contains buffer address
	! %i1 contains count of 16bit words
	! %i2 contains sum
	! %i4 contains the mainloop count
	! %i5 comes in with the buffer address rounded down to the first dword
	!
	! %g1 32bit mask
	! %g4 16bit mask
	! %g5 64bit mask (all 1s)
	! %g6 fetch-ahead offset for Ecache
	!
	! %l0-7,%o0-5,%g2-3 mainloop temporaries
	!
	!
				! 1 clock overhead
	btst	63, %i0		! src 64-byte aligned?
	bz,a,pt	%icc, .mainsection	! aligned blocks are fairly common
	andncc	%i1, 31, %i4	! at least 64 bytes for main loop?


	! Leading dword, with 1-4 hwords: 9 clocks
	! Assumes ok to read the entire dword with the leading bytes
	ldx	[%i5], %l0	! NB base addr
	inc	8, %i5		! next addr

	sub	%i5, %i0, %l2	! byte count: 2/4/6/8
	mov	%i5, %i0

	sll	%l2, 2, %l2	! 8/16/24/32 for mask

	sllx	%g5, %l2, %l4

	sllx	%l4, %l2, %l4	! mask: 16, 32, 48, 64 0's at lsb

	srl	%l2, 3, %l2	! 1/2/3/4 for count
	andn	%l0, %l4, %l0	! select hw's from src

	srlx	%l0, 32, %o0	! hi32
	b	9f
	sub	%i1, %l2, %i1	! decr count, 1-4 halfwords

	! Do dwords until source is 64-byte aligned, 0-6 iterations
	! 4 clocks per + 4 for 1 mispred = 16 clocks avg
.dw:	ldx	[%i0], %l0	! tmp64 = *src++ (groups with the branch below)

	inc	8, %i0		! (Dcache load-use delay)
	dec	4, %i1		! decrement count, 4 halfwords

	srlx	%l0, 32, %o0	! hi32
9:	and	%l0, %g1, %l0	! lo32

	add	%o0, %i2, %i2	! accumulator
	btst	63, %i0		! src 64-byte aligned?

	bnz,pt	%icc, .dw
	add	%l0, %i2, %i2	! accumulator


	! At this point source address is 64 byte aligned
	! and we've dealt with 1-32 halfwords.
	andncc	%i1, 31, %i4	! at least 64 bytes for main loop?
.mainsection:				! total 18n + 21 clocks
	bz,pn	%icc, .postamble
	and	%i1, 31, %i1	! count for postamble

	! preload for main loop - 9 clocks assuming D$ hits at 1 per
	ldx	[%i0+0], %l0
	ldx	[%i0+8], %l1
	ldx	[%i0+16], %l2	! %l0 could be used here if Dcache hit
	ldx	[%i0+24], %l3	!  but US-II prefetch only loads Ecache
	ldx	[%i0+32], %l4	!  check on US-III: could mix preloads & splits?
	ldx	[%i0+40], %l5
	ldx	[%i0+48], %l6
	ldx	[%i0+56], %l7
	inc	64, %i0
	prefetch [%i0], #n_reads

	! main loop. Read 64 bytes at a time - 18 clocks per iteration
5:	!					plus 4 for the exit mispredict
	srlx	%l0, 32, %o0		! hi32 to %o0
	and	%l0, %g1, %l0		! lo32 to %l0

	srlx	%l1, 32, %o1		! hi32 to %o1
	and	%l1, %g1, %l1		! lo32 to %l1

	srlx	%l2, 32, %o2		! hi32 to %o2
	and	%l2, %g1, %l2		! lo32 to %l2

	srlx	%l3, 32, %o3		! hi32 to %o3
	and	%l3, %g1, %l3		! lo32 to %l3

	srlx	%l4, 32, %o4		! hi32 to %o4
	and	%l4, %g1, %l4		! lo32 to %l4

	srlx	%l5, 32, %o5		! hi32 to %o5
	and	%l5, %g1, %l5		! lo32 to %l5

	srlx	%l6, 32, %g2		! hi32 to %g2
	and	%l6, %g1, %l6		! lo32 to %l6

	srlx	%l7, 32, %g3		! hi32 to %g3
	and	%l7, %g1, %l7		! lo32 to %l7
				! splits gave 16 off 32b vals
	deccc	32, %i4		! mv early,avoid mispredicts? nohelp US-II.
	bz,pn	%icc, .looptidy	! count now zero?
	add	%l0, %o0, %o0	! delay

	ldx	[%i0+0], %l0
	add	%l1, %o1, %o1	! adds and loads
	add	%l2, %o2, %o2

	ldx	[%i0+8], %l1
	add	%l3, %o3, %o3
	add	%l4, %o4, %o4

	ldx	[%i0+16], %l2
	add	%l5, %o5, %o5
	add	%l6, %g2, %g2

	ldx	[%i0+24], %l3
	add	%l7, %g3, %g3		! now 8 off 33b vals
	add	%o0, %o1, %o0

	ldx	[%i0+32], %l4
	add	%o2, %o3, %o1
	add	%o4, %o5, %o2

	ldx	[%i0+40], %l5
	add	%g2, %g3, %o3		! now 4 off 34b vals
	add	%o0, %o1, %o0

	ldx	[%i0+48], %l6
	add	%o2, %o3, %o1		! 2 off 35b

	ldx	[%i0+56], %l7
	add	%o0, %o1, %o0		! 36b
	inc	64, %i0		! increment source address

	add	%o0, %i2, %i2	! accumulator
	ba	5b
	prefetch [%i0], #n_reads	! next cacheline
				! end of main loop
.looptidy:	! compute remaining partial sum - 8 clocks
	add	%l1, %o1, %o1
	add	%l2, %o2, %o2

	add	%l3, %o3, %o3
	add	%l4, %o4, %o4

	add	%l5, %o5, %o5
	add	%l6, %g2, %g2

	add	%l7, %g3, %g3		! 8 x 33b
	add	%o0, %o1, %o0

	add	%o2, %o3, %o1
	add	%o4, %o5, %o2

	add	%g2, %g3, %o3		! 4 x 34b
	add	%o0, %o1, %o0

	add	%o2, %o3, %o1		! 2 x 35b
	add	%o0, %i2, %i2	! accumulator

	add	%o1, %i2, %i2	! accumulator


.postamble:
	! postamble hword count is in %i1 (can be zero)
	! while at least 1 dword, do dwords.   Max 7 iterations.
	andncc	%i1, 3, %g0	! more than 3 hwords?
.dotail_dw:
	bz,a,pn	%icc, .dotail_hw
	tst	%i1		! delay: any at all left?
8:	
	ldx	[%i0], %l0	! tmp64 = *src++
	inc	8, %i0
	dec	4, %i1		! decrement count, 4 halfwords

				! stall for D-cache

	srlx	%l0, 32, %o0	! hi32
	and	%l0, %g1, %l0	! lo32

	add	%o0, %i2, %i2	! accumulator

	andncc	%i1, 3, %g0	! more than 3 hwords?
	bnz,pt	%icc, 8b
	add	%l0, %i2, %i2	! accumulator

	! while at least 1 hword, do hwords.   Max 3 iterations.
	tst	%i1
.dotail_hw:
	bz,a	.fold
	srlx	%i2, 32, %o0	! delay: hi32
	lduh	[%i0], %l0	! tmp16 = *src++
1:	
	inc	2, %i0
				! stall for D-cache

	add	%l0, %i2, %i2	! accumulator

	deccc	%i1		! decrement count
	bnz,a,pt %icc, 1b
	lduh	[%i0], %l0	! tmp16 = *src++

	! at this point the 64-bit accumulator
	! has the result that needs to be returned in 16-bits
	srlx	%i2, 32, %o0	! hi32
.fold:
	and	%i2, %g1, %o1	! lo32

	add	%o0, %o1, %o0	! 33b

	srlx	%o0, 16, %o1	! hi17
	and	%o0, %g4, %o0	! lo16

	add	%o1, %o0, %o0	! 18b

	srlx	%o0, 16, %o1	! hi2
	and	%o0, %g4, %o0	! lo16

	add	%o1, %o0, %i0	! 16b result in %i0

	ret			! return
	restore


	SET_SIZE(ip_ocsum_long)	! 64-bit version

