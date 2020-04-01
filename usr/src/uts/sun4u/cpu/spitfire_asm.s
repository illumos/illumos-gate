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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/mmu.h>
#include <vm/hat_sfmmu.h>
#include <sys/machparam.h>
#include <sys/machcpuvar.h>
#include <sys/machthread.h>
#include <sys/privregs.h>
#include <sys/asm_linkage.h>
#include <sys/machasi.h>
#include <sys/trap.h>
#include <sys/spitregs.h>
#include <sys/xc_impl.h>
#include <sys/intreg.h>
#include <sys/async.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */

/* BEGIN CSTYLED */
#define	DCACHE_FLUSHPAGE(arg1, arg2, tmp1, tmp2, tmp3)			\
	ldxa	[%g0]ASI_LSU, tmp1					;\
	btst	LSU_DC, tmp1		/* is dcache enabled? */	;\
	bz,pn	%icc, 1f						;\
	sethi	%hi(dcache_linesize), tmp1				;\
	ld	[tmp1 + %lo(dcache_linesize)], tmp1			;\
	sethi	%hi(dflush_type), tmp2					;\
	ld	[tmp2 + %lo(dflush_type)], tmp2				;\
	cmp	tmp2, FLUSHPAGE_TYPE					;\
	be,pt	%icc, 2f						;\
	sllx	arg1, SF_DC_VBIT_SHIFT, arg1	/* tag to compare */	;\
	sethi	%hi(dcache_size), tmp3					;\
	ld	[tmp3 + %lo(dcache_size)], tmp3				;\
	cmp	tmp2, FLUSHMATCH_TYPE					;\
	be,pt	%icc, 3f						;\
	nop								;\
	/*								\
	 * flushtype = FLUSHALL_TYPE, flush the whole thing		\
	 * tmp3 = cache size						\
	 * tmp1 = cache line size					\
	 */								\
	sub	tmp3, tmp1, tmp2					;\
4:									\
	stxa	%g0, [tmp2]ASI_DC_TAG					;\
	membar	#Sync							;\
	cmp	%g0, tmp2						;\
	bne,pt	%icc, 4b						;\
	sub	tmp2, tmp1, tmp2					;\
	ba,pt	%icc, 1f						;\
	nop								;\
	/*								\
	 * flushtype = FLUSHPAGE_TYPE					\
	 * arg1 = tag to compare against				\
	 * arg2 = virtual color						\
	 * tmp1 = cache line size					\
	 * tmp2 = tag from cache					\
	 * tmp3 = counter						\
	 */								\
2:									\
	set	MMU_PAGESIZE, tmp3					;\
	sllx	arg2, MMU_PAGESHIFT, arg2  /* color to dcache page */	;\
	sub	tmp3, tmp1, tmp3					;\
4:									\
	ldxa	[arg2 + tmp3]ASI_DC_TAG, tmp2	/* read tag */		;\
	btst	SF_DC_VBIT_MASK, tmp2					;\
	bz,pn	%icc, 5f	  /* branch if no valid sub-blocks */	;\
	andn	tmp2, SF_DC_VBIT_MASK, tmp2	/* clear out v bits */	;\
	cmp	tmp2, arg1						;\
	bne,pn	%icc, 5f			/* br if tag miss */	;\
	nop								;\
	stxa	%g0, [arg2 + tmp3]ASI_DC_TAG				;\
	membar	#Sync							;\
5:									\
	cmp	%g0, tmp3						;\
	bnz,pt	%icc, 4b		/* branch if not done */	;\
	sub	tmp3, tmp1, tmp3					;\
	ba,pt	%icc, 1f						;\
	nop								;\
	/*								\
	 * flushtype = FLUSHMATCH_TYPE					\
	 * arg1 = tag to compare against				\
	 * tmp1 = cache line size					\
	 * tmp3 = cache size						\
	 * arg2 = counter						\
	 * tmp2 = cache tag						\
	 */								\
3:									\
	sub	tmp3, tmp1, arg2					;\
4:									\
	ldxa	[arg2]ASI_DC_TAG, tmp2		/* read tag */		;\
	btst	SF_DC_VBIT_MASK, tmp2					;\
	bz,pn	%icc, 5f		/* br if no valid sub-blocks */	;\
	andn	tmp2, SF_DC_VBIT_MASK, tmp2	/* clear out v bits */	;\
	cmp	tmp2, arg1						;\
	bne,pn	%icc, 5f		/* branch if tag miss */	;\
	nop								;\
	stxa	%g0, [arg2]ASI_DC_TAG					;\
	membar	#Sync							;\
5:									\
	cmp	%g0, arg2						;\
	bne,pt	%icc, 4b		/* branch if not done */	;\
	sub	arg2, tmp1, arg2					;\
1:

/*
 * macro that flushes the entire dcache color
 */
#define	DCACHE_FLUSHCOLOR(arg, tmp1, tmp2)				\
	ldxa	[%g0]ASI_LSU, tmp1;					\
	btst	LSU_DC, tmp1;		/* is dcache enabled? */	\
	bz,pn	%icc, 1f;						\
	sethi	%hi(dcache_linesize), tmp1;				\
	ld	[tmp1 + %lo(dcache_linesize)], tmp1;			\
	set	MMU_PAGESIZE, tmp2;					\
	/*								\
	 * arg = virtual color						\
	 * tmp2 = page size						\
	 * tmp1 = cache line size					\
	 */								\
	sllx	arg, MMU_PAGESHIFT, arg; /* color to dcache page */	\
	sub	tmp2, tmp1, tmp2;					\
2:									\
	stxa	%g0, [arg + tmp2]ASI_DC_TAG;				\
	membar	#Sync;							\
	cmp	%g0, tmp2;						\
	bne,pt	%icc, 2b;						\
	sub	tmp2, tmp1, tmp2;					\
1:

/*
 * macro that flushes the entire dcache
 */
#define	DCACHE_FLUSHALL(size, linesize, tmp)				\
	ldxa	[%g0]ASI_LSU, tmp;					\
	btst	LSU_DC, tmp;		/* is dcache enabled? */	\
	bz,pn	%icc, 1f;						\
									\
	sub	size, linesize, tmp;					\
2:									\
	stxa	%g0, [tmp]ASI_DC_TAG;					\
	membar	#Sync;							\
	cmp	%g0, tmp;						\
	bne,pt	%icc, 2b;						\
	sub	tmp, linesize, tmp;					\
1:

/*
 * macro that flushes the entire icache
 */
#define	ICACHE_FLUSHALL(size, linesize, tmp)				\
	ldxa	[%g0]ASI_LSU, tmp;					\
	btst	LSU_IC, tmp;						\
	bz,pn	%icc, 1f;						\
									\
	sub	size, linesize, tmp;					\
2:									\
	stxa	%g0, [tmp]ASI_IC_TAG;					\
	membar	#Sync;							\
	cmp	%g0, tmp;						\
	bne,pt	%icc, 2b;						\
	sub	tmp, linesize, tmp;					\
1:

#ifdef SF_ERRATA_32
#define SF_WORKAROUND(tmp1, tmp2)                               \
        sethi   %hi(FLUSH_ADDR), tmp2                           ;\
        set     MMU_PCONTEXT, tmp1                              ;\
        stxa    %g0, [tmp1]ASI_DMMU                             ;\
        flush   tmp2                                            ;
#else
#define SF_WORKAROUND(tmp1, tmp2)
#endif /* SF_ERRATA_32 */

/*
 * arg1 = vaddr
 * arg2 = ctxnum
 *      - disable interrupts and clear address mask
 *        to access 64 bit physaddr
 *      - Blow out the TLB, flush user page.
 *        . use secondary context.
 */
#define VTAG_FLUSHUPAGE(lbl, arg1, arg2, tmp1, tmp2, tmp3, tmp4) \
        rdpr    %pstate, tmp1                                   ;\
        andn    tmp1, PSTATE_IE, tmp2				;\
        wrpr    tmp2, 0, %pstate                                ;\
        sethi   %hi(FLUSH_ADDR), tmp2                           ;\
        set     MMU_SCONTEXT, tmp3                              ;\
        ldxa    [tmp3]ASI_DMMU, tmp4                            ;\
        or      DEMAP_SECOND | DEMAP_PAGE_TYPE, arg1, arg1      ;\
        cmp     tmp4, arg2                                      ;\
        be,a,pt %icc, lbl/**/4                                  ;\
          nop                                                   ;\
        stxa    arg2, [tmp3]ASI_DMMU                            ;\
lbl/**/4:                                                       ;\
        stxa    %g0, [arg1]ASI_DTLB_DEMAP                       ;\
        stxa    %g0, [arg1]ASI_ITLB_DEMAP                       ;\
        flush   tmp2                                            ;\
        be,a,pt %icc, lbl/**/5                                  ;\
          nop                                                   ;\
        stxa    tmp4, [tmp3]ASI_DMMU                            ;\
        flush   tmp2                                            ;\
lbl/**/5:                                                       ;\
        wrpr    %g0, tmp1, %pstate

	
/*
 * macro that flushes all the user entries in dtlb
 * arg1 = dtlb entries
 *	- Before first compare:
 *              tmp4 = tte
 *              tmp5 = vaddr
 *              tmp6 = cntxnum
 */
#define DTLB_FLUSH_UNLOCKED_UCTXS(lbl, arg1, tmp1, tmp2, tmp3, \
                                tmp4, tmp5, tmp6) \
lbl/**/0:                                                       ;\
        sllx    arg1, 3, tmp3                                   ;\
        SF_WORKAROUND(tmp1, tmp2)                               ;\
        ldxa    [tmp3]ASI_DTLB_ACCESS, tmp4                     ;\
        srlx    tmp4, 6, tmp4                                   ;\
        andcc   tmp4, 1, %g0                                    ;\
        bnz,pn  %xcc, lbl/**/1                                  ;\
        srlx    tmp4, 57, tmp4                                  ;\
        andcc   tmp4, 1, %g0                                    ;\
        beq,pn  %xcc, lbl/**/1                                  ;\
          nop                                                   ;\
        set     TAGREAD_CTX_MASK, tmp1                          ;\
        ldxa    [tmp3]ASI_DTLB_TAGREAD, tmp2                    ;\
        and     tmp2, tmp1, tmp6                                ;\
        andn    tmp2, tmp1, tmp5                                ;\
	set	KCONTEXT, tmp4					;\
	cmp	tmp6, tmp4					;\
	be	lbl/**/1					;\
	  nop							;\
        VTAG_FLUSHUPAGE(VD/**/lbl, tmp5, tmp6, tmp1, tmp2, tmp3, tmp4) ;\
lbl/**/1:                                                       ;\
        brgz,pt arg1, lbl/**/0                                  ;\
          sub     arg1, 1, arg1


/*
 * macro that flushes all the user entries in itlb	
 * arg1 = itlb entries
 *      - Before first compare:
 *              tmp4 = tte
 *              tmp5 = vaddr
 *              tmp6 = cntxnum
 */
#define ITLB_FLUSH_UNLOCKED_UCTXS(lbl, arg1, tmp1, tmp2, tmp3, \
                                tmp4, tmp5, tmp6) \
lbl/**/0:                                                       ;\
        sllx    arg1, 3, tmp3                                   ;\
        SF_WORKAROUND(tmp1, tmp2)                               ;\
        ldxa    [tmp3]ASI_ITLB_ACCESS, tmp4                     ;\
        srlx    tmp4, 6, tmp4                                   ;\
        andcc   tmp4, 1, %g0                                    ;\
        bnz,pn  %xcc, lbl/**/1                                  ;\
        srlx    tmp4, 57, tmp4                                  ;\
        andcc   tmp4, 1, %g0                                    ;\
        beq,pn  %xcc, lbl/**/1                                  ;\
          nop                                                   ;\
        set     TAGREAD_CTX_MASK, tmp1                          ;\
        ldxa    [tmp3]ASI_ITLB_TAGREAD, tmp2                    ;\
        and     tmp2, tmp1, tmp6                                ;\
        andn    tmp2, tmp1, tmp5                                ;\
	set	KCONTEXT, tmp4					;\
	cmp	tmp6, tmp4					;\
	be	lbl/**/1					;\
	  nop							;\
        VTAG_FLUSHUPAGE(VI/**/lbl, tmp5, tmp6, tmp1, tmp2, tmp3, tmp4) ;\
lbl/**/1:                                                       ;\
        brgz,pt arg1, lbl/**/0                                  ;\
        sub     arg1, 1, arg1


	
/*
 * Macro for getting to offset from 'cpu_private' ptr. The 'cpu_private'
 * ptr is in the machcpu structure.
 * r_or_s:	Register or symbol off offset from 'cpu_private' ptr.
 * scr1:	Scratch, ptr is returned in this register.
 * scr2:	Scratch
 */
#define GET_CPU_PRIVATE_PTR(r_or_s, scr1, scr2, label)		\
	CPU_ADDR(scr1, scr2);						\
	ldn	[scr1 + CPU_PRIVATE], scr1; 				\
	cmp	scr1, 0; 						\
	be	label;							\
	 nop; 								\
	add	scr1, r_or_s, scr1;  					\

#ifdef HUMMINGBIRD
/*
 * UltraSPARC-IIe processor supports both 4-way set associative and
 * direct map E$. For performance reasons, we flush E$ by placing it
 * in direct map mode for data load/store and restore the state after
 * we are done flushing it. Keep interrupts off while flushing in this
 * manner.
 *
 * We flush the entire ecache by starting at one end and loading each
 * successive ecache line for the 2*ecache-size range. We have to repeat
 * the flush operation to guarantee that the entire ecache has been
 * flushed.
 *
 * For flushing a specific physical address, we start at the aliased
 * address and load at set-size stride, wrapping around at 2*ecache-size
 * boundary and skipping the physical address being flushed. It takes
 * 10 loads to guarantee that the physical address has been flushed.
 */

#define	HB_ECACHE_FLUSH_CNT	2
#define	HB_PHYS_FLUSH_CNT	10	/* #loads to flush specific paddr */
#endif /* HUMMINGBIRD */

/* END CSTYLED */

/*
 * Spitfire MMU and Cache operations.
 */

	ENTRY_NP(vtag_flushpage)
	/*
	 * flush page from the tlb
	 *
	 * %o0 = vaddr
	 * %o1 = sfmmup
	 */
	rdpr	%pstate, %o5
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o5, sfdi_label1, %g1)
#endif /* DEBUG */
	/*
	 * disable ints
	 */
	andn	%o5, PSTATE_IE, %o4
	wrpr	%o4, 0, %pstate

	/*
	 * Then, blow out the tlb
	 * Interrupts are disabled to prevent the secondary ctx register
	 * from changing underneath us.
	 */
	sethi   %hi(ksfmmup), %o3
        ldx     [%o3 + %lo(ksfmmup)], %o3
        cmp     %o3, %o1
        bne,pt   %xcc, 1f			! if not kernel as, go to 1
	  sethi	%hi(FLUSH_ADDR), %o3
	/*
	 * For KCONTEXT demaps use primary. type = page implicitly
	 */
	stxa	%g0, [%o0]ASI_DTLB_DEMAP	/* dmmu flush for KCONTEXT */
	stxa	%g0, [%o0]ASI_ITLB_DEMAP	/* immu flush for KCONTEXT */
	flush	%o3
	b	5f
	  nop
1:
	/*
	 * User demap.  We need to set the secondary context properly.
	 * %o0 = vaddr
	 * %o1 = sfmmup
	 * %o3 = FLUSH_ADDR
	 */
	SFMMU_CPU_CNUM(%o1, %g1, %g2)	/* %g1 = sfmmu cnum on this CPU */
	
	set	MMU_SCONTEXT, %o4
	ldxa	[%o4]ASI_DMMU, %o2		/* rd old ctxnum */
	or	DEMAP_SECOND | DEMAP_PAGE_TYPE, %o0, %o0
	cmp	%o2, %g1
	be,pt	%icc, 4f
	  nop
	stxa	%g1, [%o4]ASI_DMMU		/* wr new ctxum */
4:
	stxa	%g0, [%o0]ASI_DTLB_DEMAP
	stxa	%g0, [%o0]ASI_ITLB_DEMAP
	flush	%o3
	be,pt	%icc, 5f
	  nop
	stxa	%o2, [%o4]ASI_DMMU		/* restore old ctxnum */
	flush	%o3
5:
	retl
	  wrpr	%g0, %o5, %pstate		/* enable interrupts */
	SET_SIZE(vtag_flushpage)
	
        .seg    ".text"
.flushallmsg:
        .asciz  "sfmmu_asm: unimplemented flush operation"

        ENTRY_NP(vtag_flushall)
        sethi   %hi(.flushallmsg), %o0
        call    panic
          or    %o0, %lo(.flushallmsg), %o0
        SET_SIZE(vtag_flushall)

	ENTRY_NP(vtag_flushall_uctxs)
	/*
	 * flush entire DTLB/ITLB.
	 */
	CPU_INDEX(%g1, %g2)
	mulx	%g1, CPU_NODE_SIZE, %g1
	set	cpunodes, %g2
	add	%g1, %g2, %g1
	lduh	[%g1 + ITLB_SIZE], %g2		! %g2 = # entries in ITLB
	lduh	[%g1 + DTLB_SIZE], %g1		! %g1 = # entries in DTLB
	sub	%g2, 1, %g2			! %g2 = # entries in ITLB - 1
	sub	%g1, 1, %g1			! %g1 = # entries in DTLB - 1

        !
        ! Flush itlb's
        !
        ITLB_FLUSH_UNLOCKED_UCTXS(I, %g2, %g3, %g4, %o2, %o3, %o4, %o5)

	!
        ! Flush dtlb's
        !
        DTLB_FLUSH_UNLOCKED_UCTXS(D, %g1, %g3, %g4, %o2, %o3, %o4, %o5)

	membar  #Sync
	retl
	  nop
	
	SET_SIZE(vtag_flushall_uctxs)

	ENTRY_NP(vtag_flushpage_tl1)
	/*
	 * x-trap to flush page from tlb and tsb
	 *
	 * %g1 = vaddr, zero-extended on 32-bit kernel
	 * %g2 = sfmmup
	 *
	 * assumes TSBE_TAG = 0
	 */
	srln	%g1, MMU_PAGESHIFT, %g1
	slln	%g1, MMU_PAGESHIFT, %g1			/* g1 = vaddr */
	
	SFMMU_CPU_CNUM(%g2, %g3, %g4)   /* %g3 = sfmmu cnum on this CPU */

	/* We need to set the secondary context properly. */
	set	MMU_SCONTEXT, %g4
	ldxa	[%g4]ASI_DMMU, %g5		/* rd old ctxnum */
	or	DEMAP_SECOND | DEMAP_PAGE_TYPE, %g1, %g1
	stxa	%g3, [%g4]ASI_DMMU		/* wr new ctxum */
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	stxa	%g5, [%g4]ASI_DMMU		/* restore old ctxnum */
	membar #Sync
	retry
	SET_SIZE(vtag_flushpage_tl1)

	ENTRY_NP(vtag_flush_pgcnt_tl1)
	/*
	 * x-trap to flush pgcnt MMU_PAGESIZE pages from tlb
	 *
	 * %g1 = vaddr, zero-extended on 32-bit kernel
	 * %g2 = <sfmmup58 | pgcnt6>
	 *
	 * NOTE: this handler relies on the fact that no
	 *	interrupts or traps can occur during the loop
	 *	issuing the TLB_DEMAP operations. It is assumed
	 *	that interrupts are disabled and this code is
	 *	fetching from the kernel locked text address.
	 *
	 * assumes TSBE_TAG = 0
	 */
	srln	%g1, MMU_PAGESHIFT, %g1
	slln	%g1, MMU_PAGESHIFT, %g1		/* g1 = vaddr */
	or	DEMAP_SECOND | DEMAP_PAGE_TYPE, %g1, %g1
	
	set	SFMMU_PGCNT_MASK, %g4
	and	%g4, %g2, %g3			/* g3 = pgcnt - 1 */
	add	%g3, 1, %g3			/* g3 = pgcnt */

	andn	%g2, SFMMU_PGCNT_MASK, %g2	/* g2 = sfmmup */

	SFMMU_CPU_CNUM(%g2, %g5, %g6)   ! %g5 = sfmmu cnum on this CPU

	/* We need to set the secondary context properly. */
	set	MMU_SCONTEXT, %g4
	ldxa	[%g4]ASI_DMMU, %g6		/* read old ctxnum */
	stxa	%g5, [%g4]ASI_DMMU		/* write new ctxum */

	set	MMU_PAGESIZE, %g2		/* g2 = pgsize */
	sethi	 %hi(FLUSH_ADDR), %g5
1:
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	flush	%g5
	deccc	%g3				/* decr pgcnt */
	bnz,pt	%icc,1b
	  add	%g1, %g2, %g1			/* go to nextpage */

	stxa	%g6, [%g4]ASI_DMMU		/* restore old ctxnum */
	membar #Sync
	retry
	SET_SIZE(vtag_flush_pgcnt_tl1)

	! Not implemented on US1/US2
	ENTRY_NP(vtag_flushall_tl1)
	retry
	SET_SIZE(vtag_flushall_tl1)

/*
 * vac_flushpage(pfnum, color)
 *	Flush 1 8k page of the D-$ with physical page = pfnum
 *	Algorithm:
 *		The spitfire dcache is a 16k direct mapped virtual indexed,
 *		physically tagged cache.  Given the pfnum we read all cache
 *		lines for the corresponding page in the cache (determined by
 *		the color).  Each cache line is compared with
 *		the tag created from the pfnum. If the tags match we flush
 *		the line.
 */
	.seg	".data"
	.align	8
	.global	dflush_type
dflush_type:
	.word	FLUSHPAGE_TYPE
	.seg	".text"

	ENTRY(vac_flushpage)
	/*
	 * flush page from the d$
	 *
	 * %o0 = pfnum, %o1 = color
	 */
	DCACHE_FLUSHPAGE(%o0, %o1, %o2, %o3, %o4)
	retl
	nop
	SET_SIZE(vac_flushpage)

	ENTRY_NP(vac_flushpage_tl1)
	/*
	 * x-trap to flush page from the d$
	 *
	 * %g1 = pfnum, %g2 = color
	 */
	DCACHE_FLUSHPAGE(%g1, %g2, %g3, %g4, %g5)
	retry
	SET_SIZE(vac_flushpage_tl1)

	ENTRY(vac_flushcolor)
	/*
	 * %o0 = vcolor
	 */
	DCACHE_FLUSHCOLOR(%o0, %o1, %o2)
	retl
	  nop
	SET_SIZE(vac_flushcolor)

	ENTRY(vac_flushcolor_tl1)
	/*
	 * %g1 = vcolor
	 */
	DCACHE_FLUSHCOLOR(%g1, %g2, %g3)
	retry
	SET_SIZE(vac_flushcolor_tl1)


	.global _dispatch_status_busy
_dispatch_status_busy:
	.asciz	"ASI_INTR_DISPATCH_STATUS error: busy"
	.align	4

/*
 * Determine whether or not the IDSR is busy.
 * Entry: no arguments
 * Returns: 1 if busy, 0 otherwise
 */
	ENTRY(idsr_busy)
	ldxa	[%g0]ASI_INTR_DISPATCH_STATUS, %g1
	clr	%o0
	btst	IDSR_BUSY, %g1
	bz,a,pt	%xcc, 1f
	mov	1, %o0
1:
	retl
	nop
	SET_SIZE(idsr_busy)
	
/*
 * Setup interrupt dispatch data registers
 * Entry:
 *	%o0 - function or inumber to call
 *	%o1, %o2 - arguments (2 uint64_t's)
 */
	.seg "text"

	ENTRY(init_mondo)
#ifdef DEBUG
	!
	! IDSR should not be busy at the moment
	!
	ldxa	[%g0]ASI_INTR_DISPATCH_STATUS, %g1
	btst	IDSR_BUSY, %g1
	bz,pt	%xcc, 1f
	nop

	sethi	%hi(_dispatch_status_busy), %o0
	call	panic
	or	%o0, %lo(_dispatch_status_busy), %o0
#endif /* DEBUG */

	ALTENTRY(init_mondo_nocheck)
	!
	! interrupt vector dispach data reg 0
	!
1:
	mov	IDDR_0, %g1
	mov	IDDR_1, %g2
	mov	IDDR_2, %g3
	stxa	%o0, [%g1]ASI_INTR_DISPATCH

	!
	! interrupt vector dispach data reg 1
	!
	stxa	%o1, [%g2]ASI_INTR_DISPATCH

	!
	! interrupt vector dispach data reg 2
	!
	stxa	%o2, [%g3]ASI_INTR_DISPATCH

	retl
	membar	#Sync			! allowed to be in the delay slot
	SET_SIZE(init_mondo)

/*
 * Ship mondo to upaid
 */
	ENTRY_NP(shipit)
	sll	%o0, IDCR_PID_SHIFT, %g1	! IDCR<18:14> = upa id
	or	%g1, IDCR_OFFSET, %g1		! IDCR<13:0> = 0x70
	stxa	%g0, [%g1]ASI_INTR_DISPATCH	! interrupt vector dispatch
#if defined(SF_ERRATA_54)
	membar	#Sync				! store must occur before load
	mov	0x20, %g3			! UDBH Control Register Read
	ldxa	[%g3]ASI_SDB_INTR_R, %g0
#endif
	retl
	membar	#Sync
	SET_SIZE(shipit)


/*
 * flush_instr_mem:
 *	Flush a portion of the I-$ starting at vaddr
 * 	%o0 vaddr
 *	%o1 bytes to be flushed
 */

	ENTRY(flush_instr_mem)
	membar	#StoreStore				! Ensure the stores
							! are globally visible
1:
	flush	%o0
	subcc	%o1, ICACHE_FLUSHSZ, %o1		! bytes = bytes-0x20
	bgu,pt	%ncc, 1b
	add	%o0, ICACHE_FLUSHSZ, %o0		! vaddr = vaddr+0x20

	retl
	nop
	SET_SIZE(flush_instr_mem)

/*
 * flush_ecache:
 * Flush the entire e$ using displacement flush by reading through a
 * physically contiguous area. We use mmu bypass asi (ASI_MEM) while
 * reading this physical address range so that data doesn't go to d$.
 * incoming arguments:
 *	%o0 - 64 bit physical address
 *	%o1 - size of address range to read
 *	%o2 - ecache linesize
 */
	ENTRY(flush_ecache)
#ifndef HUMMINGBIRD
	b	2f
	  nop
1:
	ldxa	[%o0 + %o1]ASI_MEM, %g0	! start reading from physaddr + size
2:
	subcc	%o1, %o2, %o1
	bcc,a,pt %ncc, 1b
	  nop

#else /* HUMMINGBIRD */
	/*
	 * UltraSPARC-IIe processor supports both 4-way set associative
	 * and direct map E$. For performance reasons, we flush E$ by
	 * placing it in direct map mode for data load/store and restore
	 * the state after we are done flushing it. It takes 2 iterations
	 * to guarantee that the entire ecache has been flushed.
	 *
	 * Keep the interrupts disabled while flushing E$ in this manner.
	 */
	rdpr	%pstate, %g4		! current pstate (restored later)
	andn	%g4, PSTATE_IE, %g5
	wrpr	%g0, %g5, %pstate	! disable interrupts

	! Place E$ in direct map mode for data access
	or	%g0, 1, %g5
	sllx	%g5, HB_UPA_DMAP_DATA_BIT, %g5
	ldxa	[%g0]ASI_UPA_CONFIG, %g1 ! current UPA config (restored later)
	or	%g1, %g5, %g5
	membar	#Sync
	stxa	%g5, [%g0]ASI_UPA_CONFIG ! enable direct map for data access
	membar	#Sync

	! flush entire ecache HB_ECACHE_FLUSH_CNT times
	mov	HB_ECACHE_FLUSH_CNT-1, %g5
2:
	sub	%o1, %o2, %g3		! start from last entry
1:
	ldxa	[%o0 + %g3]ASI_MEM, %g0	! start reading from physaddr + size
	subcc	%g3, %o2, %g3
	bgeu,a,pt %ncc, 1b
	  nop
	brgz,a,pt %g5, 2b
	  dec	%g5

	membar	#Sync
	stxa	%g1, [%g0]ASI_UPA_CONFIG ! restore UPA config reg
	membar	#Sync
	wrpr	%g0, %g4, %pstate	! restore earlier pstate
#endif /* HUMMINGBIRD */

	retl
	nop
	SET_SIZE(flush_ecache)

/*
 * void kdi_flush_idcache(int dcache_size, int dcache_linesize,
 *			int icache_size, int icache_linesize)
 */
	ENTRY(kdi_flush_idcache)
	DCACHE_FLUSHALL(%o0, %o1, %g1)
	ICACHE_FLUSHALL(%o2, %o3, %g1)
	membar	#Sync
	retl
	nop
	SET_SIZE(kdi_flush_idcache)
	

/*
 * void get_ecache_dtag(uint32_t ecache_idx, uint64_t *data, uint64_t *tag,
 * 			uint64_t *oafsr, uint64_t *acc_afsr)
 *
 * Get ecache data and tag.  The ecache_idx argument is assumed to be aligned
 * on a 64-byte boundary.  The corresponding AFSR value is also read for each
 * 8 byte ecache data obtained. The ecache data is assumed to be a pointer
 * to an array of 16 uint64_t's (e$data & afsr value).  The action to read the
 * data and tag should be atomic to make sense.  We will be executing at PIL15
 * and will disable IE, so nothing can occur between the two reads.  We also
 * assume that the execution of this code does not interfere with what we are
 * reading - not really possible, but we'll live with it for now.
 * We also pass the old AFSR value before clearing it, and caller will take
 * appropriate actions if the important bits are non-zero. 
 *
 * If the caller wishes to track the AFSR in cases where the CP bit is
 * set, an address should be passed in for acc_afsr.  Otherwise, this
 * argument may be null.
 *
 * Register Usage:
 * i0: In: 32-bit e$ index
 * i1: In: addr of e$ data
 * i2: In: addr of e$ tag
 * i3: In: addr of old afsr
 * i4: In: addr of accumulated afsr - may be null
 */
	ENTRY(get_ecache_dtag)
	save	%sp, -SA(MINFRAME), %sp
	or	%g0, 1, %l4
	sllx	%l4, 39, %l4	! set bit 39 for e$ data access
	or	%i0, %l4, %g6	! %g6 = e$ addr for data read
	sllx	%l4, 1, %l4	! set bit 40 for e$ tag access
	or	%i0, %l4, %l4	! %l4 = e$ addr for tag read

	rdpr    %pstate, %i5
	andn    %i5, PSTATE_IE | PSTATE_AM, %i0
	wrpr    %i0, %g0, %pstate       ! clear IE, AM bits

	ldxa    [%g0]ASI_ESTATE_ERR, %g1
	stxa    %g0, [%g0]ASI_ESTATE_ERR        ! disable errors
	membar  #Sync

	ldxa	[%g0]ASI_AFSR, %i0      ! grab the old-afsr before tag read
	stx     %i0, [%i3]		! write back the old-afsr

	ldxa    [%l4]ASI_EC_R, %g0      ! read tag into E$ tag reg
	ldxa    [%g0]ASI_EC_DIAG, %i0   ! read tag from E$ tag reg
	stx     %i0, [%i2]              ! write back tag result

	clr	%i2			! loop count

	brz	%i4, 1f			! acc_afsr == NULL?
	  ldxa	[%g0]ASI_AFSR, %i0      ! grab the old-afsr before clearing
	srlx	%i0, P_AFSR_CP_SHIFT, %l0
	btst	1, %l0
	bz	1f
	  nop
	ldx	[%i4], %g4
	or	%g4, %i0, %g4		! aggregate AFSR in cpu private
	stx	%g4, [%i4]
1:
	stxa    %i0, [%g0]ASI_AFSR	! clear AFSR
	membar  #Sync
	ldxa    [%g6]ASI_EC_R, %i0      ! read the 8byte E$data
	stx     %i0, [%i1]              ! save the E$data
	add     %g6, 8, %g6
	add     %i1, 8, %i1
	ldxa    [%g0]ASI_AFSR, %i0      ! read AFSR for this 16byte read
	srlx	%i0, P_AFSR_CP_SHIFT, %l0
	btst	1, %l0
	bz	2f
	  stx     %i0, [%i1]		! save the AFSR

	brz	%i4, 2f			! acc_afsr == NULL?
	  nop
	ldx	[%i4], %g4
	or	%g4, %i0, %g4		! aggregate AFSR in cpu private
	stx	%g4, [%i4]
2:
	add     %i2, 8, %i2
	cmp     %i2, 64
	bl,a    1b
	  add     %i1, 8, %i1
	stxa    %i0, [%g0]ASI_AFSR              ! clear AFSR
	membar  #Sync
	stxa    %g1, [%g0]ASI_ESTATE_ERR        ! restore error enable
	membar  #Sync
	wrpr    %g0, %i5, %pstate
	ret
	  restore
	SET_SIZE(get_ecache_dtag)

/*
 * The ce_err function handles trap type 0x63 (corrected_ECC_error) at tl=0.
 * Steps: 1. GET AFSR  2. Get AFAR <40:4> 3. Get datapath error status
 *	  4. Clear datapath error bit(s) 5. Clear AFSR error bit
 *	  6. package data in %g2 and %g3 7. call cpu_ce_error vis sys_trap
 * %g2: [ 52:43 UDB lower | 42:33 UDB upper | 32:0 afsr ] - arg #3/arg #1
 * %g3: [ 40:4 afar ] - sys_trap->have_win: arg #4/arg #2
 */
	ENTRY_NP(ce_err)
	ldxa	[%g0]ASI_AFSR, %g3	! save afsr in g3

	!
	! Check for a UE... From Kevin.Normoyle:
	! We try to switch to the trap for the UE, but since that's
	! a hardware pipeline, we might get to the CE trap before we
	! can switch. The UDB and AFSR registers will have both the
	! UE and CE bits set but the UDB syndrome and the AFAR will be
	! for the UE.
	!
	or	%g0, 1, %g1		! put 1 in g1
	sllx	%g1, 21, %g1		! shift left to <21> afsr UE
	andcc	%g1, %g3, %g0		! check for UE in afsr
	bnz	async_err		! handle the UE, not the CE
	  or	%g0, 0x63, %g5		! pass along the CE ttype
	!
	! Disable further CE traps to avoid recursion (stack overflow)
	! and staying above XCALL_PIL for extended periods.
	!
	ldxa	[%g0]ASI_ESTATE_ERR, %g2
	andn	%g2, 0x1, %g2		! clear bit 0 - CEEN
	stxa	%g2, [%g0]ASI_ESTATE_ERR
	membar	#Sync			! required
	!
	! handle the CE
	ldxa	[%g0]ASI_AFAR, %g2	! save afar in g2

	set	P_DER_H, %g4		! put P_DER_H in g4
	ldxa	[%g4]ASI_SDB_INTR_R, %g5 ! read sdb upper half into g5
	or	%g0, 1, %g6		! put 1 in g6
	sllx	%g6, 8, %g6		! shift g6 to <8> sdb CE
	andcc	%g5, %g6, %g1		! check for CE in upper half
	sllx	%g5, 33, %g5		! shift upper bits to <42:33>
	or	%g3, %g5, %g3		! or with afsr bits
	bz,a	1f			! no error, goto 1f
	  nop
	stxa	%g1, [%g4]ASI_SDB_INTR_W ! clear sdb reg error bit
	membar	#Sync			! membar sync required
1:
	set	P_DER_L, %g4		! put P_DER_L in g4
	ldxa	[%g4]ASI_SDB_INTR_R, %g5 ! read sdb lower half into g6
	andcc	%g5, %g6, %g1		! check for CE in lower half
	sllx	%g5, 43, %g5		! shift upper bits to <52:43>
	or	%g3, %g5, %g3		! or with afsr bits
	bz,a	2f			! no error, goto 2f
	  nop
	stxa	%g1, [%g4]ASI_SDB_INTR_W ! clear sdb reg error bit
	membar	#Sync			! membar sync required
2:
	or	%g0, 1, %g4		! put 1 in g4
	sllx	%g4, 20, %g4		! shift left to <20> afsr CE
	stxa	%g4, [%g0]ASI_AFSR	! use g4 to clear afsr CE error
	membar	#Sync			! membar sync required

	set	cpu_ce_error, %g1	! put *cpu_ce_error() in g1
	rdpr	%pil, %g6		! read pil into %g6
	subcc	%g6, PIL_15, %g0
	  movneg	%icc, PIL_14, %g4 ! run at pil 14 unless already at 15
	sethi	%hi(sys_trap), %g5
	jmp	%g5 + %lo(sys_trap)	! goto sys_trap
	  movge	%icc, PIL_15, %g4	! already at pil 15
	SET_SIZE(ce_err)

	ENTRY_NP(ce_err_tl1)
#ifndef	TRAPTRACE
	ldxa	[%g0]ASI_AFSR, %g7
	stxa	%g7, [%g0]ASI_AFSR
	membar	#Sync
	retry
#else
	set	ce_trap_tl1, %g1
	sethi	%hi(dis_err_panic1), %g4
	jmp	%g4 + %lo(dis_err_panic1)
	nop
#endif
	SET_SIZE(ce_err_tl1)

#ifdef	TRAPTRACE
.celevel1msg:
	.asciz	"Softerror with trap tracing at tl1: AFAR 0x%08x.%08x AFSR 0x%08x.%08x";

	ENTRY_NP(ce_trap_tl1)
	! upper 32 bits of AFSR already in o3
	mov	%o4, %o0		! save AFAR upper 32 bits
	mov	%o2, %o4		! lower 32 bits of AFSR
	mov	%o1, %o2		! lower 32 bits of AFAR
	mov	%o0, %o1		! upper 32 bits of AFAR
	set	.celevel1msg, %o0
	call	panic
	nop
	SET_SIZE(ce_trap_tl1)
#endif

/*
 * The async_err function handles trap types 0x0A (instruction_access_error)
 * and 0x32 (data_access_error) at TL = 0 and TL > 0.  When we branch here,
 * %g5 will have the trap type (with 0x200 set if we're at TL > 0).
 *
 * Steps: 1. Get AFSR 2. Get AFAR <40:4> 3. If not UE error skip UDP registers.
 *	  4. Else get and clear datapath error bit(s) 4. Clear AFSR error bits
 *	  6. package data in %g2 and %g3 7. disable all cpu errors, because
 *	  trap is likely to be fatal 8. call cpu_async_error vis sys_trap
 *
 * %g3: [ 63:53 tt | 52:43 UDB_L | 42:33 UDB_U | 32:0 afsr ] - arg #3/arg #1
 * %g2: [ 40:4 afar ] - sys_trap->have_win: arg #4/arg #2
 *
 * async_err is the assembly glue code to get us from the actual trap
 * into the CPU module's C error handler.  Note that we also branch
 * here from ce_err() above.
 */
	ENTRY_NP(async_err)
	stxa	%g0, [%g0]ASI_ESTATE_ERR ! disable ecc and other cpu errors
	membar	#Sync			! membar sync required

	ldxa	[%g0]ASI_AFSR, %g3	! save afsr in g3
	ldxa	[%g0]ASI_AFAR, %g2	! save afar in g2

	sllx	%g5, 53, %g5		! move ttype to <63:53>
	or	%g3, %g5, %g3		! or to afsr in g3

	or	%g0, 1, %g1		! put 1 in g1
	sllx	%g1, 21, %g1		! shift left to <21> afsr UE
	andcc	%g1, %g3, %g0		! check for UE in afsr
	bz,a,pn %icc, 2f		! if !UE skip sdb read/clear
	  nop

	set	P_DER_H, %g4		! put P_DER_H in g4
	ldxa	[%g4]ASI_SDB_INTR_R, %g5 ! read sdb upper half into 56
	or	%g0, 1, %g6		! put 1 in g6
	sllx	%g6, 9, %g6		! shift g6 to <9> sdb UE
	andcc	%g5, %g6, %g1		! check for UE in upper half
	sllx	%g5, 33, %g5		! shift upper bits to <42:33>
	or	%g3, %g5, %g3		! or with afsr bits
	bz,a	1f			! no error, goto 1f
	  nop
	stxa	%g1, [%g4]ASI_SDB_INTR_W ! clear sdb reg UE error bit
	membar	#Sync			! membar sync required
1:
	set	P_DER_L, %g4		! put P_DER_L in g4
	ldxa	[%g4]ASI_SDB_INTR_R, %g5 ! read sdb lower half into g5
	andcc	%g5, %g6, %g1		! check for UE in lower half
	sllx	%g5, 43, %g5		! shift upper bits to <52:43>
	or	%g3, %g5, %g3		! or with afsr bits
	bz,a	2f			! no error, goto 2f
	  nop
	stxa	%g1, [%g4]ASI_SDB_INTR_W ! clear sdb reg UE error bit
	membar	#Sync			! membar sync required
2:
	stxa	%g3, [%g0]ASI_AFSR	! clear all the sticky bits
	membar	#Sync			! membar sync required

	RESET_USER_RTT_REGS(%g4, %g5, async_err_resetskip)
async_err_resetskip:

	set	cpu_async_error, %g1	! put cpu_async_error in g1
	sethi	%hi(sys_trap), %g5
	jmp	%g5 + %lo(sys_trap)	! goto sys_trap
	  or	%g0, PIL_15, %g4	! run at pil 15
	SET_SIZE(async_err)

	ENTRY_NP(dis_err_panic1)
	stxa	%g0, [%g0]ASI_ESTATE_ERR ! disable all error traps
	membar	#Sync
	! save destination routine is in g1
	ldxa	[%g0]ASI_AFAR, %g2	! read afar
	ldxa	[%g0]ASI_AFSR, %g3	! read afsr
	set	P_DER_H, %g4		! put P_DER_H in g4
	ldxa	[%g4]ASI_SDB_INTR_R, %g5 ! read sdb upper half into g5
	sllx	%g5, 33, %g5		! shift upper bits to <42:33>
	or	%g3, %g5, %g3		! or with afsr bits
	set	P_DER_L, %g4		! put P_DER_L in g4
	ldxa	[%g4]ASI_SDB_INTR_R, %g5 ! read sdb lower half into g5
	sllx	%g5, 43, %g5		! shift upper bits to <52:43>
	or	%g3, %g5, %g3		! or with afsr bits

	RESET_USER_RTT_REGS(%g4, %g5, dis_err_panic1_resetskip)
dis_err_panic1_resetskip:

	sethi	%hi(sys_trap), %g5
	jmp	%g5 + %lo(sys_trap)	! goto sys_trap
	  sub	%g0, 1, %g4
	SET_SIZE(dis_err_panic1)

/*
 * The clr_datapath function clears any error bits set in the UDB regs.
 */
	ENTRY(clr_datapath)
	set	P_DER_H, %o4			! put P_DER_H in o4
	ldxa	[%o4]ASI_SDB_INTR_R, %o5	! read sdb upper half into o3
	or	%g0, 0x3, %o2			! put 0x3 in o2
	sllx	%o2, 8, %o2			! shift o2 to <9:8> sdb
	andcc	%o5, %o2, %o1			! check for UE,CE in upper half
	bz,a	1f				! no error, goto 1f
	  nop
	stxa	%o1, [%o4]ASI_SDB_INTR_W	! clear sdb reg UE,CE error bits
	membar	#Sync				! membar sync required
1:
	set	P_DER_L, %o4			! put P_DER_L in o4
	ldxa	[%o4]ASI_SDB_INTR_R, %o5	! read sdb lower half into o5
	andcc	%o5, %o2, %o1			! check for UE,CE in lower half
	bz,a	2f				! no error, goto 2f
	  nop
	stxa	%o1, [%o4]ASI_SDB_INTR_W	! clear sdb reg UE,CE error bits
	membar	#Sync
2:
	retl
	  nop
	SET_SIZE(clr_datapath)

/*
 * The get_udb_errors() function gets the current value of the
 * Datapath Error Registers.
 */
	ENTRY(get_udb_errors)
	set	P_DER_H, %o3
	ldxa	[%o3]ASI_SDB_INTR_R, %o2
	stx	%o2, [%o0]
	set	P_DER_L, %o3
	ldxa	[%o3]ASI_SDB_INTR_R, %o2
	retl
	  stx	%o2, [%o1]
	SET_SIZE(get_udb_errors)

/*
 * The itlb_rd_entry and dtlb_rd_entry functions return the tag portion of the
 * tte, the virtual address, and the ctxnum of the specified tlb entry.  They
 * should only be used in places where you have no choice but to look at the
 * tlb itself.
 *
 * Note: These two routines are required by the Estar "cpr" loadable module.
 */
/*
 * NB - In Spitfire cpus, when reading a tte from the hardware, we
 * need to clear [42-41] because the general definitions in pte.h
 * define the PA to be [42-13] whereas Spitfire really uses [40-13].
 * When cloning these routines for other cpus the "andn" below is not
 * necessary.
 */
	ENTRY_NP(itlb_rd_entry)
	sllx	%o0, 3, %o0
#if defined(SF_ERRATA_32)
	sethi	%hi(FLUSH_ADDR), %g2
	set	MMU_PCONTEXT, %g1
	stxa	%g0, [%g1]ASI_DMMU			! KCONTEXT
	flush	%g2
#endif
	ldxa	[%o0]ASI_ITLB_ACCESS, %g1
	set	TTE_SPITFIRE_PFNHI_CLEAR, %g2		! spitfire only
	sllx	%g2, TTE_SPITFIRE_PFNHI_SHIFT, %g2	! see comment above
	andn	%g1, %g2, %g1				! for details
	stx	%g1, [%o1]
	ldxa	[%o0]ASI_ITLB_TAGREAD, %g2
	set	TAGREAD_CTX_MASK, %o4
	andn	%g2, %o4, %o5
	retl
	  stx	%o5, [%o2]
	SET_SIZE(itlb_rd_entry)

	ENTRY_NP(dtlb_rd_entry)
	sllx	%o0, 3, %o0
#if defined(SF_ERRATA_32)
	sethi	%hi(FLUSH_ADDR), %g2
	set	MMU_PCONTEXT, %g1
	stxa	%g0, [%g1]ASI_DMMU			! KCONTEXT
	flush	%g2
#endif
	ldxa	[%o0]ASI_DTLB_ACCESS, %g1
	set	TTE_SPITFIRE_PFNHI_CLEAR, %g2		! spitfire only
	sllx	%g2, TTE_SPITFIRE_PFNHI_SHIFT, %g2	! see comment above
	andn	%g1, %g2, %g1				! itlb_rd_entry
	stx	%g1, [%o1]
	ldxa	[%o0]ASI_DTLB_TAGREAD, %g2
	set	TAGREAD_CTX_MASK, %o4
	andn	%g2, %o4, %o5
	retl
	  stx	%o5, [%o2]
	SET_SIZE(dtlb_rd_entry)

	ENTRY(set_lsu)
	stxa	%o0, [%g0]ASI_LSU		! store to LSU
	retl
	membar	#Sync
	SET_SIZE(set_lsu)

	ENTRY(get_lsu)
	retl
	ldxa	[%g0]ASI_LSU, %o0		! load LSU
	SET_SIZE(get_lsu)

	/*
	 * Clear the NPT (non-privileged trap) bit in the %tick
	 * registers. In an effort to make the change in the
	 * tick counter as consistent as possible, we disable
	 * all interrupts while we're changing the registers. We also
	 * ensure that the read and write instructions are in the same
	 * line in the instruction cache.
	 */
	ENTRY_NP(cpu_clearticknpt)
	rdpr	%pstate, %g1		/* save processor state */
	andn	%g1, PSTATE_IE, %g3	/* turn off */
	wrpr	%g0, %g3, %pstate	/*   interrupts */
	rdpr	%tick, %g2		/* get tick register */
	brgez,pn %g2, 1f		/* if NPT bit off, we're done */
	mov	1, %g3			/* create mask */
	sllx	%g3, 63, %g3		/*   for NPT bit */
	ba,a,pt	%xcc, 2f
	.align	64			/* Align to I$ boundary */
2:
	rdpr	%tick, %g2		/* get tick register */
	wrpr	%g3, %g2, %tick		/* write tick register, */
					/*   clearing NPT bit   */
#if defined(BB_ERRATA_1)
	rdpr	%tick, %g0		/* read (s)tick (BB_ERRATA_1) */
#endif
1:
	jmp	%g4 + 4
	wrpr	%g0, %g1, %pstate	/* restore processor state */
	SET_SIZE(cpu_clearticknpt)

	/*
	 * get_ecache_tag()
	 * Register Usage:
	 * %o0: In: 32-bit E$ index
	 *      Out: 64-bit E$ tag value
	 * %o1: In: 64-bit AFSR value after clearing sticky bits
	 * %o2: In: address of cpu private afsr storage
	 */
	ENTRY(get_ecache_tag)
	or	%g0, 1, %o4
	sllx	%o4, 40, %o4			! set bit 40 for e$ tag access
	or	%o0, %o4, %o4			! %o4 = e$ addr for tag read
	rdpr	%pstate, %o5
	andn	%o5, PSTATE_IE | PSTATE_AM, %o0
	wrpr	%o0, %g0, %pstate		! clear IE, AM bits

	ldxa	[%g0]ASI_ESTATE_ERR, %g1
	stxa	%g0, [%g0]ASI_ESTATE_ERR	! Turn off Error enable
	membar	#Sync

	ldxa	[%g0]ASI_AFSR, %o0
	srlx	%o0, P_AFSR_CP_SHIFT, %o3
	btst	1, %o3
	bz	1f
	  nop
	ldx	[%o2], %g4
	or	%g4, %o0, %g4			! aggregate AFSR in cpu private
	stx	%g4, [%o2]
1:
	stxa	%o0, [%g0]ASI_AFSR		! clear AFSR
	membar  #Sync

	ldxa	[%o4]ASI_EC_R, %g0
	ldxa	[%g0]ASI_EC_DIAG, %o0		! read tag from e$ tag reg

	ldxa	[%g0]ASI_AFSR, %o3
	srlx	%o3, P_AFSR_CP_SHIFT, %o4
	btst	1, %o4
	bz	2f
	  stx	%o3, [%o1]			! AFSR after sticky clear
	ldx	[%o2], %g4
	or	%g4, %o3, %g4			! aggregate AFSR in cpu private
	stx	%g4, [%o2]
2:
	membar	#Sync

	stxa	%g1, [%g0]ASI_ESTATE_ERR	! Turn error enable back on
	membar	#Sync
	retl
	wrpr	%g0, %o5, %pstate
	SET_SIZE(get_ecache_tag)

	/*
	 * check_ecache_line()
	 * Register Usage:
	 * %o0: In: 32-bit E$ index
	 *      Out: 64-bit accumulated AFSR
	 * %o1: In: address of cpu private afsr storage
	 */
	ENTRY(check_ecache_line)
	or	%g0, 1, %o4
	sllx	%o4, 39, %o4			! set bit 39 for e$ data access
	or	%o0, %o4, %o4		 	! %o4 = e$ addr for data read

	rdpr	%pstate, %o5
	andn	%o5, PSTATE_IE | PSTATE_AM, %o0
	wrpr	%o0, %g0, %pstate		! clear IE, AM bits

	ldxa	[%g0]ASI_ESTATE_ERR, %g1
	stxa	%g0, [%g0]ASI_ESTATE_ERR 	! Turn off Error enable
	membar	#Sync

	ldxa 	[%g0]ASI_AFSR, %o0
	srlx	%o0, P_AFSR_CP_SHIFT, %o2
	btst	1, %o2
	bz	1f
	  clr	%o2				! loop count
	ldx	[%o1], %o3
	or	%o3, %o0, %o3			! aggregate AFSR in cpu private
	stx	%o3, [%o1]
1: 
	stxa    %o0, [%g0]ASI_AFSR              ! clear AFSR
	membar	#Sync

2:
	ldxa	[%o4]ASI_EC_R, %g0		! Read the E$ data 8bytes each
	add	%o2, 1, %o2
	cmp	%o2, 8
	bl,a 	2b
	  add	%o4, 8, %o4

	membar	#Sync
	ldxa	[%g0]ASI_AFSR, %o0		! read accumulated AFSR
	srlx	%o0, P_AFSR_CP_SHIFT, %o2
	btst	1, %o2
	bz	3f
	  nop
	ldx	[%o1], %o3
	or	%o3, %o0, %o3			! aggregate AFSR in cpu private
	stx	%o3, [%o1]
3:
	stxa	%o0, [%g0]ASI_AFSR		! clear AFSR
	membar	#Sync
	stxa	%g1, [%g0]ASI_ESTATE_ERR	! Turn error enable back on
	membar	#Sync
	retl
	wrpr	%g0, %o5, %pstate
	SET_SIZE(check_ecache_line)

	ENTRY(read_and_clear_afsr)
	ldxa	[%g0]ASI_AFSR, %o0
	retl
	  stxa	%o0, [%g0]ASI_AFSR		! clear AFSR
	SET_SIZE(read_and_clear_afsr)

/*
 * scrubphys - Pass in the aligned physical memory address that you want
 * to scrub, along with the ecache size.
 *
 *	1) Displacement flush the E$ line corresponding to %addr.
 *	   The first ldxa guarantees that the %addr is no longer in
 *	   M, O, or E (goes to I or S (if instruction fetch also happens).
 *	2) "Write" the data using a CAS %addr,%g0,%g0.
 *	   The casxa guarantees a transition from I to M or S to M.
 *	3) Displacement flush the E$ line corresponding to %addr.
 *	   The second ldxa pushes the M line out of the ecache, into the
 *	   writeback buffers, on the way to memory.
 *	4) The "membar #Sync" pushes the cache line out of the writeback
 *	   buffers onto the bus, on the way to dram finally.
 *
 * This is a modified version of the algorithm suggested by Gary Lauterbach.
 * In theory the CAS %addr,%g0,%g0 is supposed to mark the addr's cache line
 * as modified, but then we found out that for spitfire, if it misses in the
 * E$ it will probably install as an M, but if it hits in the E$, then it
 * will stay E, if the store doesn't happen. So the first displacement flush
 * should ensure that the CAS will miss in the E$.  Arrgh.
 */

	ENTRY(scrubphys)
	or	%o1, %g0, %o2	! put ecache size in %o2
#ifndef HUMMINGBIRD
	xor	%o0, %o2, %o1	! calculate alias address
	add	%o2, %o2, %o3	! 2 * ecachesize in case
				! addr == ecache_flushaddr
	sub	%o3, 1, %o3	! -1 == mask
	and	%o1, %o3, %o1	! and with xor'd address
	set	ecache_flushaddr, %o3
	ldx	[%o3], %o3

	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, %g0, %pstate	! clear IE, AM bits

	ldxa	[%o1 + %o3]ASI_MEM, %g0 ! load ecache_flushaddr + alias
	casxa	[%o0]ASI_MEM, %g0, %g0
	ldxa	[%o1 + %o3]ASI_MEM, %g0	! load ecache_flushaddr + alias

#else /* HUMMINGBIRD */
	/*
	 * UltraSPARC-IIe processor supports both 4-way set associative
	 * and direct map E$. We need to reconfigure E$ to direct map
	 * mode for data load/store before displacement flush. Also, we
	 * need to flush all 4 sets of the E$ to ensure that the physaddr
	 * has been flushed. Keep the interrupts disabled while flushing
	 * E$ in this manner.
	 *
	 * For flushing a specific physical address, we start at the
	 * aliased address and load at set-size stride, wrapping around
	 * at 2*ecache-size boundary and skipping fault physical address.
	 * It takes 10 loads to guarantee that the physical address has
	 * been flushed.
	 *
	 * Usage:
	 *	%o0	physaddr
	 *	%o5	physaddr - ecache_flushaddr
	 *	%g1	UPA config (restored later)
	 *	%g2	E$ set size
	 *	%g3	E$ flush address range mask (i.e. 2 * E$ -1)
	 *	%g4	#loads to flush phys address
	 *	%g5	temp 
	 */

	sethi	%hi(ecache_associativity), %g5
	ld	[%g5 + %lo(ecache_associativity)], %g5
	udivx	%o2, %g5, %g2	! set size (i.e. ecache_size/#sets)
	xor	%o0, %o2, %o1	! calculate alias address
	add	%o2, %o2, %g3	! 2 * ecachesize in case
				! addr == ecache_flushaddr
	sub	%g3, 1, %g3	! 2 * ecachesize -1 == mask
	and	%o1, %g3, %o1	! and with xor'd address
	sethi	%hi(ecache_flushaddr), %o3
	ldx	[%o3 + %lo(ecache_flushaddr)], %o3

	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, %g0, %pstate	! clear IE, AM bits

	! Place E$ in direct map mode for data access
	or	%g0, 1, %g5
	sllx	%g5, HB_UPA_DMAP_DATA_BIT, %g5
	ldxa	[%g0]ASI_UPA_CONFIG, %g1 ! current UPA config (restored later)
	or	%g1, %g5, %g5
	membar	#Sync
	stxa	%g5, [%g0]ASI_UPA_CONFIG ! enable direct map for data access
	membar	#Sync

	! Displace cache line from each set of E$ starting at the
	! aliased address. at set-size stride, wrapping at 2*ecache_size
	! and skipping load from physaddr. We need 10 loads to flush the
	! physaddr from E$.
	mov	HB_PHYS_FLUSH_CNT-1, %g4 ! #loads to flush phys addr
	sub	%o0, %o3, %o5		! physaddr - ecache_flushaddr
	or	%o1, %g0, %g5		! starting aliased offset
2:
	ldxa	[%g5 + %o3]ASI_MEM, %g0	! load ecache_flushaddr + alias
1:
	add	%g5, %g2, %g5		! calculate offset in next set
	and	%g5, %g3, %g5		! force offset within aliased range
	cmp	%g5, %o5		! skip loads from physaddr
	be,pn %ncc, 1b
	  nop
	brgz,pt	%g4, 2b
	  dec	%g4

	casxa	[%o0]ASI_MEM, %g0, %g0

	! Flush %o0 from ecahe again.
	! Need single displacement flush at offset %o1 this time as
	! the E$ is already in direct map mode.
	ldxa	[%o1 + %o3]ASI_MEM, %g0	! load ecache_flushaddr + alias

	membar	#Sync
	stxa	%g1, [%g0]ASI_UPA_CONFIG ! restore UPA config (DM bits)
	membar	#Sync
#endif /* HUMMINGBIRD */
	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value

	retl
	membar	#Sync			! move the data out of the load buffer
	SET_SIZE(scrubphys)

/*
 * clearphys - Pass in the aligned physical memory address that you want
 * to push out, as a 64 byte block of zeros, from the ecache zero-filled.
 * Since this routine does not bypass the ecache, it is possible that
 * it could generate a UE error while trying to clear the a bad line.
 * This routine clears and restores the error enable flag.
 * TBD - Hummingbird may need similar protection
 */
	ENTRY(clearphys)
	or	%o2, %g0, %o3	! ecache linesize
	or	%o1, %g0, %o2	! ecache size
#ifndef HUMMINGBIRD
	or	%o3, %g0, %o4	! save ecache linesize
	xor	%o0, %o2, %o1	! calculate alias address
	add	%o2, %o2, %o3	! 2 * ecachesize
	sub	%o3, 1, %o3	! -1 == mask
	and	%o1, %o3, %o1	! and with xor'd address
	set	ecache_flushaddr, %o3
	ldx	[%o3], %o3
	or	%o4, %g0, %o2	! saved ecache linesize

	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, %g0, %pstate	! clear IE, AM bits

	ldxa	[%g0]ASI_ESTATE_ERR, %g1
	stxa	%g0, [%g0]ASI_ESTATE_ERR	! disable errors
	membar	#Sync

	! need to put zeros in the cache line before displacing it

	sub	%o2, 8, %o2	! get offset of last double word in ecache line
1:
	stxa	%g0, [%o0 + %o2]ASI_MEM	! put zeros in the ecache line
	sub	%o2, 8, %o2
	brgez,a,pt %o2, 1b
	nop
	ldxa	[%o1 + %o3]ASI_MEM, %g0	! load ecache_flushaddr + alias
	casxa	[%o0]ASI_MEM, %g0, %g0
	ldxa	[%o1 + %o3]ASI_MEM, %g0	! load ecache_flushaddr + alias

	stxa	%g1, [%g0]ASI_ESTATE_ERR	! restore error enable
	membar	#Sync

#else /* HUMMINGBIRD... */
	/*
	 * UltraSPARC-IIe processor supports both 4-way set associative
	 * and direct map E$. We need to reconfigure E$ to direct map
	 * mode for data load/store before displacement flush. Also, we
	 * need to flush all 4 sets of the E$ to ensure that the physaddr
	 * has been flushed. Keep the interrupts disabled while flushing
	 * E$ in this manner.
	 *
	 * For flushing a specific physical address, we start at the
	 * aliased address and load at set-size stride, wrapping around
	 * at 2*ecache-size boundary and skipping fault physical address.
	 * It takes 10 loads to guarantee that the physical address has
	 * been flushed.
	 *
	 * Usage:
	 *	%o0	physaddr
	 *	%o5	physaddr - ecache_flushaddr
	 *	%g1	UPA config (restored later)
	 *	%g2	E$ set size
	 *	%g3	E$ flush address range mask (i.e. 2 * E$ -1)
	 *	%g4	#loads to flush phys address
	 *	%g5	temp 
	 */

	or	%o3, %g0, %o4	! save ecache linesize
	sethi	%hi(ecache_associativity), %g5
	ld	[%g5 + %lo(ecache_associativity)], %g5
	udivx	%o2, %g5, %g2	! set size (i.e. ecache_size/#sets)

	xor	%o0, %o2, %o1	! calculate alias address
	add	%o2, %o2, %g3	! 2 * ecachesize
	sub	%g3, 1, %g3	! 2 * ecachesize -1 == mask
	and	%o1, %g3, %o1	! and with xor'd address
	sethi	%hi(ecache_flushaddr), %o3
	ldx	[%o3 +%lo(ecache_flushaddr)], %o3
	or	%o4, %g0, %o2	! saved ecache linesize

	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, %g0, %pstate	! clear IE, AM bits

	! Place E$ in direct map mode for data access
	or	%g0, 1, %g5
	sllx	%g5, HB_UPA_DMAP_DATA_BIT, %g5
	ldxa	[%g0]ASI_UPA_CONFIG, %g1 ! current UPA config (restored later)
	or	%g1, %g5, %g5
	membar	#Sync
	stxa	%g5, [%g0]ASI_UPA_CONFIG ! enable direct map for data access
	membar	#Sync

	! need to put zeros in the cache line before displacing it

	sub	%o2, 8, %o2	! get offset of last double word in ecache line
1:
	stxa	%g0, [%o0 + %o2]ASI_MEM	! put zeros in the ecache line
	sub	%o2, 8, %o2
	brgez,a,pt %o2, 1b
	nop

	! Displace cache line from each set of E$ starting at the
	! aliased address. at set-size stride, wrapping at 2*ecache_size
	! and skipping load from physaddr. We need 10 loads to flush the
	! physaddr from E$.
	mov	HB_PHYS_FLUSH_CNT-1, %g4 ! #loads to flush phys addr
	sub	%o0, %o3, %o5		! physaddr - ecache_flushaddr
	or	%o1, %g0, %g5		! starting offset
2:
	ldxa	[%g5 + %o3]ASI_MEM, %g0	! load ecache_flushaddr + alias
3:
	add	%g5, %g2, %g5		! calculate offset in next set
	and	%g5, %g3, %g5		! force offset within aliased range
	cmp	%g5, %o5		! skip loads from physaddr
	be,pn %ncc, 3b
	  nop
	brgz,pt	%g4, 2b
	  dec	%g4

	casxa	[%o0]ASI_MEM, %g0, %g0

	! Flush %o0 from ecahe again.
	! Need single displacement flush at offset %o1 this time as
	! the E$ is already in direct map mode.
	ldxa	[%o1 + %o3]ASI_MEM, %g0	! load ecache_flushaddr + alias

	membar	#Sync
	stxa	%g1, [%g0]ASI_UPA_CONFIG ! restore UPA config (DM bits)
	membar	#Sync
#endif /* HUMMINGBIRD... */

	retl
	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value
	SET_SIZE(clearphys)

/*
 * flushecacheline - This is a simpler version of scrubphys
 * which simply does a displacement flush of the line in
 * question. This routine is mainly used in handling async
 * errors where we want to get rid of a bad line in ecache.
 * Note that if the line is modified and it has suffered
 * data corruption - we are guarantee that the hw will write
 * a UE back to mark the page poisoned.
 */
        ENTRY(flushecacheline)
        or      %o1, %g0, %o2   ! put ecache size in %o2
#ifndef HUMMINGBIRD
        xor     %o0, %o2, %o1   ! calculate alias address
        add     %o2, %o2, %o3   ! 2 * ecachesize in case
                                ! addr == ecache_flushaddr
        sub     %o3, 1, %o3     ! -1 == mask
        and     %o1, %o3, %o1   ! and with xor'd address
        set     ecache_flushaddr, %o3
        ldx     [%o3], %o3

        rdpr    %pstate, %o4
        andn    %o4, PSTATE_IE | PSTATE_AM, %o5
        wrpr    %o5, %g0, %pstate       ! clear IE, AM bits

	ldxa	[%g0]ASI_ESTATE_ERR, %g1
	stxa	%g0, [%g0]ASI_ESTATE_ERR	! disable errors
	membar	#Sync

        ldxa    [%o1 + %o3]ASI_MEM, %g0 ! load ecache_flushaddr + alias
	membar	#Sync
	stxa	%g1, [%g0]ASI_ESTATE_ERR	! restore error enable
        membar  #Sync                   
#else /* HUMMINGBIRD */
	/*
	 * UltraSPARC-IIe processor supports both 4-way set associative
	 * and direct map E$. We need to reconfigure E$ to direct map
	 * mode for data load/store before displacement flush. Also, we
	 * need to flush all 4 sets of the E$ to ensure that the physaddr
	 * has been flushed. Keep the interrupts disabled while flushing
	 * E$ in this manner.
	 *
	 * For flushing a specific physical address, we start at the
	 * aliased address and load at set-size stride, wrapping around
	 * at 2*ecache-size boundary and skipping fault physical address.
	 * It takes 10 loads to guarantee that the physical address has
	 * been flushed.
	 *
	 * Usage:
	 *	%o0	physaddr
	 *	%o5	physaddr - ecache_flushaddr
	 *	%g1	error enable register
	 *	%g2	E$ set size
	 *	%g3	E$ flush address range mask (i.e. 2 * E$ -1)
	 *	%g4	UPA config (restored later)
	 *	%g5	temp 
	 */

	sethi	%hi(ecache_associativity), %g5
	ld	[%g5 + %lo(ecache_associativity)], %g5
	udivx	%o2, %g5, %g2	! set size (i.e. ecache_size/#sets)
	xor	%o0, %o2, %o1	! calculate alias address
	add	%o2, %o2, %g3	! 2 * ecachesize in case
				! addr == ecache_flushaddr
	sub	%g3, 1, %g3	! 2 * ecachesize -1 == mask
	and	%o1, %g3, %o1	! and with xor'd address
	sethi	%hi(ecache_flushaddr), %o3
	ldx	[%o3 + %lo(ecache_flushaddr)], %o3

	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, %g0, %pstate	! clear IE, AM bits

	! Place E$ in direct map mode for data access
	or	%g0, 1, %g5
	sllx	%g5, HB_UPA_DMAP_DATA_BIT, %g5
	ldxa	[%g0]ASI_UPA_CONFIG, %g4 ! current UPA config (restored later)
	or	%g4, %g5, %g5
	membar	#Sync
	stxa	%g5, [%g0]ASI_UPA_CONFIG ! enable direct map for data access
	membar	#Sync

	ldxa	[%g0]ASI_ESTATE_ERR, %g1
	stxa	%g0, [%g0]ASI_ESTATE_ERR	! disable errors
	membar	#Sync

	! Displace cache line from each set of E$ starting at the
	! aliased address. at set-size stride, wrapping at 2*ecache_size
	! and skipping load from physaddr. We need 10 loads to flush the
	! physaddr from E$.
	mov	HB_PHYS_FLUSH_CNT-1, %g5 ! #loads to flush physaddr
	sub	%o0, %o3, %o5		! physaddr - ecache_flushaddr
2:
	ldxa	[%o1 + %o3]ASI_MEM, %g0	! load ecache_flushaddr + alias
3:
	add	%o1, %g2, %o1		! calculate offset in next set
	and	%o1, %g3, %o1		! force offset within aliased range
	cmp	%o1, %o5		! skip loads from physaddr
	be,pn %ncc, 3b
	  nop
	brgz,pt	%g5, 2b
	  dec	%g5
	
	membar	#Sync
	stxa	%g1, [%g0]ASI_ESTATE_ERR	! restore error enable
        membar  #Sync                   

	stxa	%g4, [%g0]ASI_UPA_CONFIG ! restore UPA config (DM bits)
	membar	#Sync
#endif /* HUMMINGBIRD */
        retl
        wrpr    %g0, %o4, %pstate       
        SET_SIZE(flushecacheline)

/*
 * ecache_scrubreq_tl1 is the crosstrap handler called at ecache_calls_a_sec Hz
 * from the clock CPU.  It atomically increments the outstanding request
 * counter and, if there was not already an outstanding request,
 * branches to setsoftint_tl1 to enqueue an intr_vec for the given inum.
 */

	! Register usage:
	!
	! Arguments:
	! %g1 - inum
	!
	! Internal:
	! %g2, %g3, %g5 - scratch
	! %g4 - ptr. to spitfire_scrub_misc ec_scrub_outstanding.
	! %g6 - setsoftint_tl1 address

	ENTRY_NP(ecache_scrubreq_tl1)
	set	SFPR_SCRUB_MISC + EC_SCRUB_OUTSTANDING, %g2
	GET_CPU_PRIVATE_PTR(%g2, %g4, %g5, 1f);
	ld	[%g4], %g2		! cpu's ec_scrub_outstanding.
	set	setsoftint_tl1, %g6
	!
	! no need to use atomic instructions for the following
	! increment - we're at tl1
	!
	add	%g2, 0x1, %g3
	brnz,pn	%g2, 1f			! no need to enqueue more intr_vec
	  st	%g3, [%g4]		! delay - store incremented counter
	jmp	%g6			! setsoftint_tl1(%g1) - queue intr_vec
	  nop
	! not reached
1:
	retry
	SET_SIZE(ecache_scrubreq_tl1)

	/*
         * write_ec_tag_parity(), which zero's the ecache tag,
         * marks the state as invalid and writes good parity to the tag.
         * Input %o1= 32 bit E$ index
         */
        ENTRY(write_ec_tag_parity)
        or      %g0, 1, %o4
        sllx    %o4, 39, %o4                    ! set bit 40 for e$ tag access
        or      %o0, %o4, %o4                 ! %o4 = ecache addr for tag write

        rdpr    %pstate, %o5
        andn    %o5, PSTATE_IE | PSTATE_AM, %o1
        wrpr    %o1, %g0, %pstate               ! clear IE, AM bits

        ldxa    [%g0]ASI_ESTATE_ERR, %g1
        stxa    %g0, [%g0]ASI_ESTATE_ERR        ! Turn off Error enable
        membar  #Sync

        ba      1f
         nop
	/*
         * Align on the ecache boundary in order to force
         * ciritical code section onto the same ecache line.
         */
         .align 64

1:
        set     S_EC_PARITY, %o3         	! clear tag, state invalid
        sllx    %o3, S_ECPAR_SHIFT, %o3   	! and with good tag parity
        stxa    %o3, [%g0]ASI_EC_DIAG           ! update with the above info
        stxa    %g0, [%o4]ASI_EC_W
        membar  #Sync

        stxa    %g1, [%g0]ASI_ESTATE_ERR        ! Turn error enable back on
        membar  #Sync
        retl
        wrpr    %g0, %o5, %pstate
        SET_SIZE(write_ec_tag_parity)

	/*
         * write_hb_ec_tag_parity(), which zero's the ecache tag,
         * marks the state as invalid and writes good parity to the tag.
         * Input %o1= 32 bit E$ index
         */
        ENTRY(write_hb_ec_tag_parity)
        or      %g0, 1, %o4
        sllx    %o4, 39, %o4                    ! set bit 40 for e$ tag access
        or      %o0, %o4, %o4               ! %o4 = ecache addr for tag write

        rdpr    %pstate, %o5
        andn    %o5, PSTATE_IE | PSTATE_AM, %o1
        wrpr    %o1, %g0, %pstate               ! clear IE, AM bits

        ldxa    [%g0]ASI_ESTATE_ERR, %g1
        stxa    %g0, [%g0]ASI_ESTATE_ERR        ! Turn off Error enable
        membar  #Sync

        ba      1f
         nop
	/*
         * Align on the ecache boundary in order to force
         * ciritical code section onto the same ecache line.
         */
         .align 64
1: 
#ifdef HUMMINGBIRD
        set     HB_EC_PARITY, %o3         	! clear tag, state invalid
        sllx    %o3, HB_ECPAR_SHIFT, %o3   	! and with good tag parity
#else /* !HUMMINGBIRD */
        set     SB_EC_PARITY, %o3         	! clear tag, state invalid
        sllx    %o3, SB_ECPAR_SHIFT, %o3   	! and with good tag parity
#endif /* !HUMMINGBIRD */

        stxa    %o3, [%g0]ASI_EC_DIAG           ! update with the above info
        stxa    %g0, [%o4]ASI_EC_W
        membar  #Sync

        stxa    %g1, [%g0]ASI_ESTATE_ERR        ! Turn error enable back on
        membar  #Sync
        retl
        wrpr    %g0, %o5, %pstate
        SET_SIZE(write_hb_ec_tag_parity)

#define	VIS_BLOCKSIZE		64

	ENTRY(dtrace_blksuword32)
	save	%sp, -SA(MINFRAME + 4), %sp

	rdpr	%pstate, %l1
	andn	%l1, PSTATE_IE, %l2		! disable interrupts to
	wrpr	%g0, %l2, %pstate		! protect our FPU diddling

	rd	%fprs, %l0
	andcc	%l0, FPRS_FEF, %g0
	bz,a,pt	%xcc, 1f			! if the fpu is disabled
	wr	%g0, FPRS_FEF, %fprs		! ... enable the fpu

	st	%f0, [%fp + STACK_BIAS - 4]	! save %f0 to the stack
1:
	set	0f, %l5
        /*
         * We're about to write a block full or either total garbage
         * (not kernel data, don't worry) or user floating-point data
         * (so it only _looks_ like garbage).
         */
	ld	[%i1], %f0			! modify the block
	membar	#Sync
	stn	%l5, [THREAD_REG + T_LOFAULT]	! set up the lofault handler
	stda	%d0, [%i0]ASI_BLK_COMMIT_S	! store the modified block
	membar	#Sync
	stn	%g0, [THREAD_REG + T_LOFAULT]	! remove the lofault handler

	bz,a,pt	%xcc, 1f
	wr	%g0, %l0, %fprs			! restore %fprs

	ld	[%fp + STACK_BIAS - 4], %f0	! restore %f0
1:

	wrpr	%g0, %l1, %pstate		! restore interrupts

	ret
	restore	%g0, %g0, %o0

0:
	membar	#Sync
	stn	%g0, [THREAD_REG + T_LOFAULT]	! remove the lofault handler

	bz,a,pt	%xcc, 1f
	wr	%g0, %l0, %fprs			! restore %fprs

	ld	[%fp + STACK_BIAS - 4], %f0	! restore %f0
1:

	wrpr	%g0, %l1, %pstate		! restore interrupts

	/*
	 * If tryagain is set (%i2) we tail-call dtrace_blksuword32_err()
	 * which deals with watchpoints. Otherwise, just return -1.
	 */
	brnz,pt	%i2, 1f
	nop
	ret
	restore	%g0, -1, %o0
1:
	call	dtrace_blksuword32_err
	restore

	SET_SIZE(dtrace_blksuword32)

