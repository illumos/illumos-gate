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

#if defined(lint)
#include <sys/types.h>
#include <sys/thread.h>
#else	/* lint */
#include "assym.h"
#endif	/* lint */

#include <sys/asi.h>
#include <sys/machasi.h>
#include <sys/asm_linkage.h>
#include <zuluvm_offsets.h>
#include <sys/zulu_hat.h>
#include <sys/zuluvm.h>

/*
 * function to look up ttes in zulu_hat TSB.
 *
 * zulu_hat_tsb_lookup_tl1 is called from the zuluvm dmv interrupt handler
 * so we can only use the global registers.
 *
 * zulu_hat_tsb_lookup_tl0 is called from TL=0 
 */
#ifdef lint

/* ARGSUSED */
uint64_t
zulu_hat_tsb_lookup_tl1(caddr_t vaddr)
{
	return (0);
}

/* ARGSUSED */
uint64_t
zulu_hat_tsb_lookup_tl0(struct zulu_hat *zhat, caddr_t vaddr)
{
	return (0);
}

#else	/* lint */

	/*
	 * %g1 - vaddr | ctx
	 * %g3 - return address
	 * Must preserve %g7 for caller
	 *
	 * returns:
	 * %g1 - pfn and flags
	 * %g2 - zuluvm error code if %g1 is null
	 */
	ENTRY_NP(zulu_hat_tsb_lookup_tl1)
	set	ZULU_CTX_MASK, %g4
	and	%g1, %g4, %g4

	! we're at trap level 1, (TL=1)
	! if the context is already locked by another
	! thread, punt to the TL=0 code
	! it's not safe to spinloop now.

	set	zulu_ctx_tab, %g6
	sllx	%g4, 3, %g5
#ifdef DEBUG
	mov	%g5, %g2	! remember ctx * 8
#endif
	add	%g5, %g6, %g6

	ldx	[%g6], %g4
	andcc	%g4, 1, %g0
	bne,a,pn %icc, ctx_busy
	  mov	ZULUVM_CTX_LOCKED, %g2
	
	! now do a compare and swap and make sure it's still not locked
	or	%g4, 1, %g5
	casxa	[%g6]ASI_N, %g4, %g5
	cmp	%g4, %g5
	bne,a,pn %icc, ctx_busy
	  mov	ZULUVM_CTX_LOCKED, %g2

	brz,a,pn %g4, zulu_hat_tsb_exit
	  mov	%g0, %g1

	! we have the lock now proceed

	! set lsb of g3 to indicate that we need to unlock the context
	! before returning
	ba,pt	%xcc, zulu_hat_tsb_lookup
	  or	%g3, 1, %g3

ctx_busy:
	mov	%g0, %g1
	jmpl	%g3+8, %g0
	nop


	/*
	 * zulu_hat_tsb_lookup_tl0 jumps here
	 *
	 * %g1 vaddr | ctx
	 * %g3 return address | unlock flag (bit zero)
	 * %g4 has the zulu hat ptr (locked)
	 */
zulu_hat_tsb_lookup:
	mov	%g1, %g2
	mov     %g4, %g1
	  
	add	%g1, ZULU_HAT_TSB_SZ, %g5
	lduh	[%g5], %g5		! tsb size
	sub	%g5, 1, %g5

	srlx    %g2, 22,  %g4		! 4m page hash
	and     %g5, %g4, %g4           ! hash index
	sllx    %g4, 4, %g4
	add     %g1, ZULU_HAT_TSB, %g5
	ldx     [%g5], %g5
	add     %g5, %g4, %g4           ! ptr to struct zulu_tte
	ldx     [%g4], %g5              ! get the tag

	set	(0x1ff << 13), %g6
	andn	%g5, %g6, %g5
	andn    %g2, %g6, %g6
	cmp     %g5, %g6
	bne,pn  %xcc, zulu_hat_tsb_try_512k
          nop

	ldx     [%g4 + 8], %g4          ! flags and pfn 
	brgez,pn %g4, zulu_hat_tsb_try_512k ! check if entry is valid
	  nop

	sllx	%g4, 2, %g5
	srlx	%g5, 61, %g5		! tte size
	cmp	%g5, ZULU_TTE4M
	be,pn   %xcc, zulu_hat_tsb_found
	  nop

zulu_hat_tsb_try_512k:
	add     %g1, ZULU_HAT_TSB_SZ, %g5
        lduh    [%g5], %g5              ! tsb size
        sub     %g5, 1, %g5

	srlx    %g2, 19, %g4           ! 4m page hash
        and     %g5, %g4, %g4           ! hash index
        sllx    %g4, 4, %g4
        add     %g1, ZULU_HAT_TSB, %g5
        ldx     [%g5], %g5
        add     %g5, %g4, %g4           ! ptr to struct zulu_tte
        ldx     [%g4], %g5              ! get the tag
	
	set     (0x3f << 13), %g6
        andn    %g5, %g6, %g5
        andn    %g2, %g6, %g6
        cmp     %g5, %g6
        bne,pn  %xcc, zulu_hat_tsb_try_64k
          nop
 
        ldx     [%g4 + 8], %g4          ! flags and pfn
        brgez,pn %g4, zulu_hat_tsb_try_64k ! check if entry is valid
          nop
 
        sllx    %g4, 2, %g5
        srlx    %g5, 61, %g5            ! tte size
        cmp     %g5, ZULU_TTE512K 
        be,pn   %xcc, zulu_hat_tsb_found
          nop

zulu_hat_tsb_try_64k:
	add     %g1, ZULU_HAT_TSB_SZ, %g5
        lduh    [%g5], %g5              ! tsb size
        sub     %g5, 1, %g5
 
        srlx    %g2, 16, %g4           ! 4m page hash
        and     %g5, %g4, %g4           ! hash index
        sllx    %g4, 4, %g4
        add     %g1, ZULU_HAT_TSB, %g5
        ldx     [%g5], %g5
        add     %g5, %g4, %g4           ! ptr to struct zulu_tte
        ldx     [%g4], %g5              ! get the tag

	set     (0x7 << 13), %g6
        andn    %g5, %g6, %g5
        andn    %g2, %g6, %g6
        cmp     %g5, %g6
        bne,pn  %xcc, zulu_hat_tsb_try_8k
          nop
 
        ldx     [%g4 + 8], %g4          ! flags and pfn
        brgez,pn %g4, zulu_hat_tsb_try_8k ! check if entry is valid
          nop
 
        sllx    %g4, 2, %g5
        srlx    %g5, 61, %g5            ! tte size
        cmp     %g5, ZULU_TTE64K
        be,pn   %xcc, zulu_hat_tsb_found
          nop 

zulu_hat_tsb_try_8k:
	add     %g1, ZULU_HAT_TSB_SZ, %g5
	lduh    [%g5], %g5              ! tsb size
	sub     %g5, 1, %g5

	srlx	%g2, 13, %g4		! calc hash
	and	%g5, %g4, %g4		! hash index
	sllx	%g4, 4, %g4
	add	%g1, ZULU_HAT_TSB, %g5
	ldx	[%g5], %g5		! tsb ptr
	add	%g5, %g4, %g4		! ptr to struct tte
	ldx	[%g4], %g5		! get the tag
	cmp	%g5, %g2
	bne,pn	%xcc, zulu_hat_tsb_exit
	  mov	%g0, %g1

	ldx	[%g4 + 8], %g4		! flags and pfn
	brgez,pn %g4, zulu_hat_tsb_exit	! check if entry is valid
	  mov   %g0, %g1

	sllx    %g4, 2, %g5
        srlx    %g5, 61, %g5            ! tte size
	brnz,pn	%g5, zulu_hat_tsb_exit
	  mov   %g0, %g1

zulu_hat_tsb_found:
	! expect the tte size in %g5
	mulx	%g5, 3, %g5
	mov	1, %g1
	sllx	%g1, %g5, %g1
	sub	%g1, 1, %g1
	andn	%g4, %g1, %g4
	srlx	%g2, 13, %g5
	and	%g1, %g5, %g5
	or	%g5, %g4, %g4
	mov   	%g4, %g1

	! now fall through to exit

zulu_hat_tsb_exit:
	! if bit zero of %g3 is set, we're at TL=1 and need to unlock
	! the context here
	andcc	%g3, 1, %g0
	be,pn	%xcc, after_unlock
	  nop

	! clear the context unlock flag
	andn	%g3, 1, %g3

	set     ZULU_CTX_MASK, %g6
	and     %g2, %g6, %g6           ! ctx num

	sllx	%g6, 3, %g6
	set	zulu_ctx_tab, %g5
	add	%g6, %g5, %g5		! %g5 = &zulu_ctx_tab[ctx_num]
	ldx	[%g5], %g6
	andn	%g6, 1, %g6
	stx	%g6, [%g5]

after_unlock:

	! set the status code to ZULUVM_NO_TTE in case we are running at TL=1
	! and no tte was found.
	!
	! note: caller doesn't examine %g2 unless flags and pfn are null
	jmpl    %g3 + 0x8, %g0
	  mov  	ZULUVM_NO_TTE, %g2




	SET_SIZE(zulu_hat_tsb_lookup_tl1)

	/*
	 * %o0 - zulu hat ptr (already locked)
	 * %o1 - vaddr
	 */
	ENTRY_NP(zulu_hat_tsb_lookup_tl0)
	mov	%o0, %g4

	set	zulu_hat_tsb_lookup, %g3

	! note bit zero of g3 is zero which tells zulu_hat_tsb_lookup
	! to not unlock tsb before returning

	jmpl	%g3, %g3
	  mov	%o1, %g1

	retl
	  mov   %g1, %o0
	SET_SIZE(zulu_hat_tsb_lookup_tl0)

#endif	/* lint */
