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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/sun4asi.h>
#include <sys/machasi.h>
#include <sys/asm_linkage.h>
#include <sys/pte.h>
#include <sys/mmu.h>
#include <sys/intreg.h>
#include <sys/zulumod.h>
#include <vm/hat_sfmmu.h>
#include <sys/zulu_hat.h>
#include <zuluvm_offsets.h>

#ifdef lint
void
zuluvm_dmv_tlbmiss_tl1()
{}

#else	/* lint */

	DGDEF(zuluvm_base_pgsize)
        .word   0

	ENTRY_NP(zuluvm_dmv_tlbmiss_tl1)

	! g1 - zuluvm_state_t pointer
	! g2 - IRDR_0
	mov	UIII_IRDR_1, %g3
	ldxa	[%g3]ASI_INTR_RECEIVE, %g5
	stx	%g5, [%g1 + ZULUVM_ASM_TLB_ADDR]
	mov	UIII_IRDR_6, %g3
	ldxa	[%g3]ASI_INTR_RECEIVE, %g5
	stx	%g5, [%g1 + ZULUVM_ASM_TLB_TYPE]

	stxa	%g0, [%g0]ASI_INTR_RECEIVE_STATUS       ! clear the BUSY bit
	membar	#Sync

	mov	%g1, %g7

	! check the fast tlb miss flag
	sethi	%hi(zuluvm_fast_tlb), %g6
	lduw	[%g6 + %lo(zuluvm_fast_tlb)], %g6
	brz,pn	%g6, send_intr1
	  mov	ZULUVM_TTE_DELAY, %g1
#if 1
	add	%g7, ZULUVM_STATE, %g4
	mov	ZULUVM_STATE_IDLE, %g1
	mov	ZULUVM_STATE_TLB_PENDING, %g6
	casa	[%g4]ASI_N, %g1, %g6
	cmp 	%g6, %g1
	be,pt	%icc, 2f
	  nop

	mov	ZULUVM_STATE_CANCELED, %g1
	cmp 	%g6, %g1
	be,pt	%icc, 1f
	  mov	ZULUVM_STATE_STOPPED, %g1
	retry
1:
	st	%g1, [%g4]
#ifdef ZULUVM_STATS
	lduw	[%g7 + ZULUVM_ST_TLBCANCEL], %g3
	add	%g3, 1, %g3
	stuw	%g3, [%g7 + ZULUVM_ST_TLBCANCEL]
#endif
	retry

2:
	ldx	[%g7 + ZULUVM_ASM_TLB_TYPE], %g4
	and	%g4, ZULUVM_DMA_MASK, %g4
#ifdef ZULUVM_STATS
	cmp	%g4, ZULUVM_DMA2
	be,a,pn	%icc, 1f
	  add	%g7, ZULUVM_ST_DTLB2MISS, %g1
	cmp     %g4, ZULUVM_ITLB1
	be,a,pn %icc, 1f
          add   %g7, ZULUVM_ST_ITLB1MISS, %g1
	cmp     %g4, ZULUVM_ITLB2
	be,a,pn %icc, 1f
          add   %g7, ZULUVM_ST_ITLB2MISS, %g1
	add	%g7, ZULUVM_ST_DTLB1MISS, %g1
1:
	lduw	[%g1], %g3
	add	%g3, 1, %g3
	stuw 	%g3, [%g1]
#endif
	/*
	 * lookup the tte in the tsb
	 * %g1 - vaddr[63:13], ctx[12:0]
	 * %g2 - our trap level
	 * %g3 - return address
	 * %g7 - zulu data pointer (needs to be preserved)
	 * return:
	 * %g1 - flags [63..58] and pfn [31..0]
	 * %g2 - status code if %g1 is null
	 * %g7 - zulu data pointer
	 */
	mov	1, %g2
	set	zulu_hat_tsb_lookup_tl1, %g3
	jmpl	%g3, %g3
	  ldx	[%g7 + ZULUVM_ASM_TLB_ADDR], %g1	! vaddr(tag)

	/*
	 * did we find a tte ??
	 * If not, %g2 has the error code
	 */
	brgez,a,pt %g1, send_intr
	mov	%g2, %g1

	set	zulu_tsb_hit, %g6
	ldx	[%g6], %g3
	add	%g3, 1, %g3
	stx	%g3, [%g6]

	/*
	 * get flags and pfn
	 */
	sllx    %g1, 32, %g6
	srlx	%g6, 32, %g6			! %g6 pfn
	srlx    %g1, 59, %g3
	and 	%g3, 0x7, %g2			! %g2 page size
	srlx    %g3, 3, %g4
	and	%g4, 1, %g4			! %g4 write perm
	mov     %g6, %g1 

	/*
	 * check if this is a dtlb2 miss(no itlb, pgsz != 8k)
	 * and if the current dtlb2 pgsz != tte pgsz
	 */
	ldx	[%g7 + ZULUVM_ASM_TLB_TYPE], %g3
	and	%g3, 0x1, %g3
	brnz,pt %g3, 3f				! not 0 => itlb => handles
	  nop

	! check page size, base page size is always handled by dtlb1, so we
	! only need to check against dtlb2
	sethi   %hi(zuluvm_base_pgsize), %g3
        lduw    [%g3 + %lo(zuluvm_base_pgsize)], %g3
	cmp	%g2, %g3
	be,pt	%icc, 2f
	cmp	%g2, ZULU_TTE4M
	be,pt 	%icc, 2f			! TTE4M => dtlb2 => ok!
	  nop

#ifdef ZULUVM_STATS
	lduw	[%g7 + ZULUVM_ST_PAGESIZE], %g3
	add	%g3, 1, %g3
	stuw	%g3, [%g7 + ZULUVM_ST_PAGESIZE]
	add	%g7, ZULUVM_ST_MISS, %g3
	sll	%g2, 2, %g5
	add	%g5, %g3, %g5
	lduw	[%g5], %g3
	add	%g3, 1, %g3
	stuw	%g3, [%g5]
#endif
	! set tte size to ZULUVM_BASE_PGSZ
	sethi   %hi(zuluvm_base_pgsize), %g3
        lduw    [%g3 + %lo(zuluvm_base_pgsize)], %g3
	ba,pt	%icc, 3f
	  mov	%g3, %g2
2:

#ifdef ZULUVM_STATS
	add	%g7, ZULUVM_ST_MISS, %g3
	sll	%g2, 2, %g5
	add	%g3, %g5, %g5
	lduw	[%g5], %g3
	add	%g3, 1, %g3
	stuw	%g3, [%g5]
#endif

	! we maintain data on the last pfns for the last 12 pfns that we
	! processed
3:
        lduw    [%g7 + ZULUVM_PFNCNT], %g5
        add     %g5, 4, %g3
        cmp     %g3, 48
        be,a,pn %icc, 1f
          mov   %g0, %g3
 
1:                           
        stuw    %g3, [%g7 + ZULUVM_PFNCNT]
        sllx    %g5, 3, %g5
        add     %g7, ZULUVM_PFNBUF, %g3
        add     %g3, %g5, %g3
        stx     %g1, [%g3]
        stx     %g2, [%g3 + 8]
        stx     %g4, [%g3 + 16]
	ldx     [%g7 + ZULUVM_ASM_TLB_TYPE], %g5
	stx     %g5, [%g3 + 24]

	ldx	[%g7 + ZULUVM_ASM_TLB_TYPE], %g3
	and	%g3, 0x3, %g3			! tlbtype
	ldx	[%g7 + ZULUVM_ARG], %g6

	! write tte to zulu mmu
	! %g1 pfn
	! %g2 tte size
	! %g3 tlbtype
	! %g4 tte wrperm
	! %g6 zulu device driver arg
	! %g7 devtab pointer

	sllx	%g1, ZULUVM_ZFB_MMU_TLB_D_PA_SHIFT, %g1
	mov	0x1, %g5
	sllx	%g5, 63, %g5			! ZFB_MMU_TLB_D_V_MASK
	or	%g1, %g5, %g1
	or	%g1, ZULUVM_ZFB_MMU_TLB_D_C_MASK, %g1
	sllx	%g2, ZULUVM_ZFB_MMU_TLB_D_SZ_SHIFT, %g2

	brz,pt	%g4, 3f				! write perm ??
	  or	%g2, %g1, %g1

	or	%g1, ZULUVM_ZFB_MMU_TLB_D_W_MASK, %g1
3:
	! at this point %g1 is ready to be written to the corresponding
	! data_in register, let's see which if it was itlb or dtlb...
	and	%g3, ZULUVM_ITLB_FLAG, %g3
						! assumption is that data miss
	brz,pt	%g3, 4f				! is more likely than instr miss
	  ldx	[%g7 + ZULUVM_PAMMU], %g2	! physical addr of zulu mmu regs

	! instruction miss
	mov     ZULUVM_ZFB_MMU_TLB_CR_IMISS_MASK, %g5
        add     %g2, ZULUVM_ITLB_DATA_IN, %g4
	!stxa  %g1, [%g4]ASI_IO
	ba,pt	%xcc, 5f
	  stxa  %g1, [%g4]ASI_IO
	  !ldxa    [%g4]ASI_IO, %g4
4:
	! data miss
	mov     ZULUVM_ZFB_MMU_TLB_CR_DMISS_MASK, %g5
	add     %g2, ZULUVM_DTLB_DATA_IN, %g4
	stxa    %g1, [%g4]ASI_IO
	!ldxa    [%g4]ASI_IO, %g4
5:
	add     %g7, ZULUVM_STATE, %g4
        mov     ZULUVM_STATE_TLB_PENDING, %g6
        mov     ZULUVM_STATE_IDLE, %g1
        casa	[%g4]ASI_N, %g6, %g1
        cmp     %g6, %g1
        bne,a,pn %icc, stopped
          mov	ZULUVM_STATE_STOPPED, %g3

	ldx	[%g7 + ZULUVM_PAMMU], %g2
	add     %g2, ZULUVM_TLB_CONTROL, %g2
	stxa    %g5, [%g2]ASI_IO
	!ldxa	[%g2]ASI_IO, %g3
	retry

send_intr:	
	add     %g7, ZULUVM_STATE, %g4
	mov     ZULUVM_STATE_INTR_QUEUED, %g5
	mov     ZULUVM_STATE_TLB_PENDING, %g3
	casa    [%g4]ASI_N, %g3, %g5
	cmp     %g3, %g5
        be,pt  %icc, deliver_intr
        mov     ZULUVM_STATE_STOPPED, %g3
	ba,pt	%icc, stopped
	  nop
#endif

send_intr1:
	add	%g7, ZULUVM_STATE, %g4
	mov     ZULUVM_STATE_IDLE, %g3
	mov 	ZULUVM_STATE_INTR_QUEUED, %g5
	casa	[%g4]ASI_N, %g3, %g5
        cmp     %g3, %g5
        be,pt  %icc, deliver_intr
        mov	ZULUVM_STATE_STOPPED, %g3
stopped:
	st	%g3, [%g4]
#ifdef ZULUVM_STATS
	lduw	[%g7 + ZULUVM_ST_TLBCANCEL], %g3
	add	%g3, 1, %g3
	stuw	%g3, [%g7 + ZULUVM_ST_TLBCANCEL]
#endif
	retry 

deliver_intr:
	stx     %g1, [%g7 + ZULUVM_ASM_TLB_ERRCODE]     ! set the error field
        stx     %g6, [%g7 + ZULUVM_ASM_TLB_TTE] ! deliver tte in data_0
                                                ! %g6 is invalid if error != SUCCESS
	! setsoftint_tl1(uint64_t inum, uint64_t dummy)
	set     setsoftint_tl1, %g5
        jmp     %g5
        ldx     [%g7 + ZULUVM_INTRNUM], %g1

	SET_SIZE(zuluvm_dmv_tlbmiss_tl1)

#endif	/* lint */

