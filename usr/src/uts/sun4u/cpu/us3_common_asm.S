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
 *
 * Copyright 2020 Joyent, Inc.
 *
 * Assembly code support for Cheetah/Cheetah+ modules
 */

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/mmu.h>
#include <vm/hat_sfmmu.h>
#include <sys/machparam.h>
#include <sys/machcpuvar.h>
#include <sys/machthread.h>
#include <sys/machtrap.h>
#include <sys/privregs.h>
#include <sys/trap.h>
#include <sys/cheetahregs.h>
#include <sys/us3_module.h>
#include <sys/xc_impl.h>
#include <sys/intreg.h>
#include <sys/async.h>
#include <sys/clock.h>
#include <sys/cheetahasm.h>
#include <sys/cmpregs.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */

/* BEGIN CSTYLED */

#define	DCACHE_FLUSHPAGE(arg1, arg2, tmp1, tmp2, tmp3)			\
	ldxa	[%g0]ASI_DCU, tmp1					;\
	btst	DCU_DC, tmp1		/* is dcache enabled? */	;\
	bz,pn	%icc, 1f						;\
	ASM_LD(tmp1, dcache_linesize)					;\
	ASM_LD(tmp2, dflush_type)					;\
	cmp	tmp2, FLUSHPAGE_TYPE					;\
	be,pt	%icc, 2f						;\
	nop								;\
	sllx	arg1, CHEETAH_DC_VBIT_SHIFT, arg1/* tag to compare */	;\
	ASM_LD(tmp3, dcache_size)					;\
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
	 * arg1 = pfn							\
	 * arg2 = virtual color						\
	 * tmp1 = cache line size					\
	 * tmp2 = tag from cache					\
	 * tmp3 = counter						\
	 */								\
2:									\
	set	MMU_PAGESIZE, tmp3					;\
        sllx    arg1, MMU_PAGESHIFT, arg1  /* pfn to 43 bit PA	   */   ;\
	sub	tmp3, tmp1, tmp3					;\
4:									\
	stxa	%g0, [arg1 + tmp3]ASI_DC_INVAL				;\
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
	btst	CHEETAH_DC_VBIT_MASK, tmp2				;\
	bz,pn	%icc, 5f		/* br if no valid sub-blocks */	;\
	andn	tmp2, CHEETAH_DC_VBIT_MASK, tmp2 /* clear out v bits */	;\
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
 * dcache size = 64K, one way 16K
 *
 * In:
 *    arg = virtual color register (not clobbered)
 *    way = way#, can either be a constant or a register (not clobbered)
 *    tmp1, tmp2, tmp3 = scratch registers
 *
 */
#define DCACHE_FLUSHCOLOR(arg, way, tmp1, tmp2, tmp3)			\
	ldxa	[%g0]ASI_DCU, tmp1;					\
	btst	DCU_DC, tmp1;		/* is dcache enabled? */	\
	bz,pn	%icc, 1f;						\
	ASM_LD(tmp1, dcache_linesize)					\
	/*								\
	 * arg = virtual color						\
	 * tmp1 = cache line size					\
	 */								\
	sllx	arg, MMU_PAGESHIFT, tmp2; /* color to dcache page */	\
	mov	way, tmp3;						\
	sllx	tmp3, 14, tmp3;		  /* One way 16K */		\
	or	tmp2, tmp3, tmp3;					\
	set	MMU_PAGESIZE, tmp2;					\
	/*								\
	 * tmp2 = page size						\
	 * tmp3 =  cached page in dcache				\
	 */								\
	sub	tmp2, tmp1, tmp2;					\
2:									\
	stxa	%g0, [tmp3 + tmp2]ASI_DC_TAG;				\
	membar	#Sync;							\
	cmp	%g0, tmp2;						\
	bne,pt	%icc, 2b;						\
	sub	tmp2, tmp1, tmp2;					\
1:

/* END CSTYLED */

/*
 * Cheetah MMU and Cache operations.
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
	PANIC_IF_INTR_DISABLED_PSTR(%o5, u3_di_label0, %g1)
#endif /* DEBUG */
	/*
	 * disable ints
	 */
	andn	%o5, PSTATE_IE, %o4
	wrpr	%o4, 0, %pstate

	/*
	 * Then, blow out the tlb
	 * Interrupts are disabled to prevent the primary ctx register
	 * from changing underneath us.
	 */
	sethi   %hi(ksfmmup), %o3
        ldx     [%o3 + %lo(ksfmmup)], %o3
        cmp     %o3, %o1
        bne,pt   %xcc, 1f			! if not kernel as, go to 1
	  sethi	%hi(FLUSH_ADDR), %o3
	/*
	 * For Kernel demaps use primary. type = page implicitly
	 */
	stxa	%g0, [%o0]ASI_DTLB_DEMAP	/* dmmu flush for KCONTEXT */
	stxa	%g0, [%o0]ASI_ITLB_DEMAP	/* immu flush for KCONTEXT */
	flush	%o3
	retl
	  wrpr	%g0, %o5, %pstate		/* enable interrupts */
1:
	/*
	 * User demap.  We need to set the primary context properly.
	 * Secondary context cannot be used for Cheetah IMMU.
	 * %o0 = vaddr
	 * %o1 = sfmmup
	 * %o3 = FLUSH_ADDR
	 */
	SFMMU_CPU_CNUM(%o1, %g1, %g2)		! %g1 = sfmmu cnum on this CPU

	ldub	[%o1 + SFMMU_CEXT], %o4		! %o4 = sfmmup->sfmmu_cext
	sll	%o4, CTXREG_EXT_SHIFT, %o4
	or	%g1, %o4, %g1			! %g1 = primary pgsz | cnum

	wrpr	%g0, 1, %tl
	set	MMU_PCONTEXT, %o4
	or	DEMAP_PRIMARY | DEMAP_PAGE_TYPE, %o0, %o0
	ldxa	[%o4]ASI_DMMU, %o2		! %o2 = save old ctxnum
	srlx	%o2, CTXREG_NEXT_SHIFT, %o1	! need to preserve nucleus pgsz
	sllx	%o1, CTXREG_NEXT_SHIFT, %o1	! %o1 = nucleus pgsz
	or	%g1, %o1, %g1			! %g1 = nucleus pgsz | primary pgsz | cnum
	stxa	%g1, [%o4]ASI_DMMU		! wr new ctxum

	stxa	%g0, [%o0]ASI_DTLB_DEMAP
	stxa	%g0, [%o0]ASI_ITLB_DEMAP
	stxa	%o2, [%o4]ASI_DMMU		/* restore old ctxnum */
	flush	%o3
	wrpr	%g0, 0, %tl

	retl
	wrpr	%g0, %o5, %pstate		/* enable interrupts */
	SET_SIZE(vtag_flushpage)

	ENTRY_NP2(vtag_flushall, demap_all)
	/*
	 * flush the tlb
	 */
	sethi	%hi(FLUSH_ADDR), %o3
	set	DEMAP_ALL_TYPE, %g1
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	flush	%o3
	retl
	nop
	SET_SIZE(demap_all)
	SET_SIZE(vtag_flushall)


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

	sethi   %hi(ksfmmup), %g3
        ldx     [%g3 + %lo(ksfmmup)], %g3
        cmp     %g3, %g2
        bne,pt	%xcc, 1f                        ! if not kernel as, go to 1
	  slln	%g1, MMU_PAGESHIFT, %g1		/* g1 = vaddr */

	/* We need to demap in the kernel context */
	or	DEMAP_NUCLEUS | DEMAP_PAGE_TYPE, %g1, %g1
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	retry
1:
	/* We need to demap in a user context */
	or	DEMAP_PRIMARY | DEMAP_PAGE_TYPE, %g1, %g1

	SFMMU_CPU_CNUM(%g2, %g6, %g3)	! %g6 = sfmmu cnum on this CPU

	ldub	[%g2 + SFMMU_CEXT], %g4		! %g4 = sfmmup->cext
	sll	%g4, CTXREG_EXT_SHIFT, %g4
	or	%g6, %g4, %g6			! %g6 = pgsz | cnum

	set	MMU_PCONTEXT, %g4
	ldxa	[%g4]ASI_DMMU, %g5		/* rd old ctxnum */
	srlx	%g5, CTXREG_NEXT_SHIFT, %g2	/* %g2 = nucleus pgsz */
	sllx	%g2, CTXREG_NEXT_SHIFT, %g2	/* preserve nucleus pgsz */
	or	%g6, %g2, %g6			/* %g6 = nucleus pgsz | primary pgsz | cnum */
	stxa	%g6, [%g4]ASI_DMMU		/* wr new ctxum */
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	stxa	%g5, [%g4]ASI_DMMU		/* restore old ctxnum */
	retry
	SET_SIZE(vtag_flushpage_tl1)


	ENTRY_NP(vtag_flush_pgcnt_tl1)
	/*
	 * x-trap to flush pgcnt MMU_PAGESIZE pages from tlb
	 *
	 * %g1 = vaddr, zero-extended on 32-bit kernel
	 * %g2 = <sfmmup58|pgcnt6>, (pgcnt - 1) is pass'ed in via pgcnt6 bits.
	 *
	 * NOTE: this handler relies on the fact that no
	 *	interrupts or traps can occur during the loop
	 *	issuing the TLB_DEMAP operations. It is assumed
	 *	that interrupts are disabled and this code is
	 *	fetching from the kernel locked text address.
	 *
	 * assumes TSBE_TAG = 0
	 */
	set	SFMMU_PGCNT_MASK, %g4
	and	%g4, %g2, %g3			/* g3 = pgcnt - 1 */
	add	%g3, 1, %g3			/* g3 = pgcnt */

	andn	%g2, SFMMU_PGCNT_MASK, %g2	/* g2 = sfmmup */
	srln	%g1, MMU_PAGESHIFT, %g1

	sethi   %hi(ksfmmup), %g4
        ldx     [%g4 + %lo(ksfmmup)], %g4
        cmp     %g4, %g2
        bne,pn   %xcc, 1f			/* if not kernel as, go to 1 */
	  slln	%g1, MMU_PAGESHIFT, %g1		/* g1 = vaddr */

	/* We need to demap in the kernel context */
	or	DEMAP_NUCLEUS | DEMAP_PAGE_TYPE, %g1, %g1
	set	MMU_PAGESIZE, %g2		/* g2 = pgsize */
	sethi   %hi(FLUSH_ADDR), %g5
4:
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	flush	%g5				! flush required by immu

	deccc	%g3				/* decr pgcnt */
	bnz,pt	%icc,4b
	  add	%g1, %g2, %g1			/* next page */
	retry
1:
	/*
	 * We need to demap in a user context
	 *
	 * g2 = sfmmup
	 * g3 = pgcnt
	 */
	SFMMU_CPU_CNUM(%g2, %g5, %g6)		! %g5 = sfmmu cnum on this CPU

	or	DEMAP_PRIMARY | DEMAP_PAGE_TYPE, %g1, %g1

	ldub	[%g2 + SFMMU_CEXT], %g4		! %g4 = sfmmup->cext
	sll	%g4, CTXREG_EXT_SHIFT, %g4
	or	%g5, %g4, %g5

	set	MMU_PCONTEXT, %g4
	ldxa	[%g4]ASI_DMMU, %g6		/* rd old ctxnum */
	srlx	%g6, CTXREG_NEXT_SHIFT, %g2	/* %g2 = nucleus pgsz */
	sllx	%g2, CTXREG_NEXT_SHIFT, %g2	/* preserve nucleus pgsz */
	or	%g5, %g2, %g5			/* %g5 = nucleus pgsz | primary pgsz | cnum */
	stxa	%g5, [%g4]ASI_DMMU		/* wr new ctxum */

	set	MMU_PAGESIZE, %g2		/* g2 = pgsize */
	sethi   %hi(FLUSH_ADDR), %g5
3:
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	flush	%g5				! flush required by immu

	deccc	%g3				/* decr pgcnt */
	bnz,pt	%icc,3b
	  add	%g1, %g2, %g1			/* next page */

	stxa	%g6, [%g4]ASI_DMMU		/* restore old ctxnum */
	retry
	SET_SIZE(vtag_flush_pgcnt_tl1)

	ENTRY_NP(vtag_flushall_tl1)
	/*
	 * x-trap to flush tlb
	 */
	set	DEMAP_ALL_TYPE, %g4
	stxa	%g0, [%g4]ASI_DTLB_DEMAP
	stxa	%g0, [%g4]ASI_ITLB_DEMAP
	retry
	SET_SIZE(vtag_flushall_tl1)


/*
 * vac_flushpage(pfnum, color)
 *	Flush 1 8k page of the D-$ with physical page = pfnum
 *	Algorithm:
 *		The cheetah dcache is a 64k psuedo 4 way accaociative cache.
 *		It is virtual indexed, physically tagged cache.
 */
	.seg	".data"
	.align	8
	.global	dflush_type
dflush_type:
	.word	FLUSHPAGE_TYPE

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
	DCACHE_FLUSHCOLOR(%o0, 0, %o1, %o2, %o3)
	DCACHE_FLUSHCOLOR(%o0, 1, %o1, %o2, %o3)
	DCACHE_FLUSHCOLOR(%o0, 2, %o1, %o2, %o3)
	DCACHE_FLUSHCOLOR(%o0, 3, %o1, %o2, %o3)
	retl
	  nop
	SET_SIZE(vac_flushcolor)


	ENTRY(vac_flushcolor_tl1)
	/*
	 * %g1 = vcolor
	 */
	DCACHE_FLUSHCOLOR(%g1, 0, %g2, %g3, %g4)
	DCACHE_FLUSHCOLOR(%g1, 1, %g2, %g3, %g4)
	DCACHE_FLUSHCOLOR(%g1, 2, %g2, %g3, %g4)
	DCACHE_FLUSHCOLOR(%g1, 3, %g2, %g3, %g4)
	retry
	SET_SIZE(vac_flushcolor_tl1)

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

	.global _dispatch_status_busy
_dispatch_status_busy:
	.asciz	"ASI_INTR_DISPATCH_STATUS error: busy"
	.align	4

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
	! interrupt vector dispatch data reg 0
	!
1:
	mov	IDDR_0, %g1
	mov	IDDR_1, %g2
	mov	IDDR_2, %g3
	stxa	%o0, [%g1]ASI_INTR_DISPATCH

	!
	! interrupt vector dispatch data reg 1
	!
	stxa	%o1, [%g2]ASI_INTR_DISPATCH

	!
	! interrupt vector dispatch data reg 2
	!
	stxa	%o2, [%g3]ASI_INTR_DISPATCH

	membar	#Sync
	retl
	nop
	SET_SIZE(init_mondo_nocheck)
	SET_SIZE(init_mondo)


#if !(defined(JALAPENO) || defined(SERRANO))

/*
 * Ship mondo to aid using busy/nack pair bn
 */
	ENTRY_NP(shipit)
	sll	%o0, IDCR_PID_SHIFT, %g1	! IDCR<18:14> = agent id
	sll	%o1, IDCR_BN_SHIFT, %g2		! IDCR<28:24> = b/n pair
	or	%g1, IDCR_OFFSET, %g1		! IDCR<13:0> = 0x70
	or	%g1, %g2, %g1
	stxa	%g0, [%g1]ASI_INTR_DISPATCH	! interrupt vector dispatch
	membar	#Sync
	retl
	nop
	SET_SIZE(shipit)

#endif	/* !(JALAPENO || SERRANO) */


/*
 * flush_instr_mem:
 *	Flush 1 page of the I-$ starting at vaddr
 * 	%o0 vaddr
 *	%o1 bytes to be flushed
 * UltraSPARC-III maintains consistency of the on-chip Instruction Cache with
 * the stores from all processors so that a FLUSH instruction is only needed
 * to ensure pipeline is consistent. This means a single flush is sufficient at
 * the end of a sequence of stores that updates the instruction stream to
 * ensure correct operation.
 */

	ENTRY(flush_instr_mem)
	flush	%o0			! address irrelevant
	retl
	nop
	SET_SIZE(flush_instr_mem)


#if defined(CPU_IMP_ECACHE_ASSOC)

	ENTRY(get_ecache_ctrl)
	GET_CPU_IMPL(%o0)
	cmp	%o0, JAGUAR_IMPL
	!
	! Putting an ASI access in the delay slot may
	! cause it to be accessed, even when annulled.
	!
	bne	1f
	  nop
	ldxa	[%g0]ASI_EC_CFG_TIMING, %o0	! read Jaguar shared E$ ctrl reg
	b	2f
	  nop
1:
	ldxa	[%g0]ASI_EC_CTRL, %o0		! read Ch/Ch+ E$ control reg
2:
	retl
	  nop
	SET_SIZE(get_ecache_ctrl)

#endif	/* CPU_IMP_ECACHE_ASSOC */


#if !(defined(JALAPENO) || defined(SERRANO))

/*
 * flush_ecache:
 *	%o0 - 64 bit physical address
 *	%o1 - ecache size
 *	%o2 - ecache linesize
 */

	ENTRY(flush_ecache)

	/*
	 * For certain CPU implementations, we have to flush the L2 cache
	 * before flushing the ecache.
	 */
	PN_L2_FLUSHALL(%g3, %g4, %g5)

	/*
	 * Flush the entire Ecache using displacement flush.
	 */
	ECACHE_FLUSHALL(%o1, %o2, %o0, %o4)

	retl
	nop
	SET_SIZE(flush_ecache)

#endif	/* !(JALAPENO || SERRANO) */


	ENTRY(flush_dcache)
	ASM_LD(%o0, dcache_size)
	ASM_LD(%o1, dcache_linesize)
	CH_DCACHE_FLUSHALL(%o0, %o1, %o2)
	retl
	nop
	SET_SIZE(flush_dcache)


	ENTRY(flush_icache)
	GET_CPU_PRIVATE_PTR(%g0, %o0, %o2, flush_icache_1);
	ld	[%o0 + CHPR_ICACHE_LINESIZE], %o1
	ba,pt	%icc, 2f
	  ld	[%o0 + CHPR_ICACHE_SIZE], %o0
flush_icache_1:
	ASM_LD(%o0, icache_size)
	ASM_LD(%o1, icache_linesize)
2:
	CH_ICACHE_FLUSHALL(%o0, %o1, %o2, %o4)
	retl
	nop
	SET_SIZE(flush_icache)

	ENTRY(kdi_flush_idcache)
	CH_DCACHE_FLUSHALL(%o0, %o1, %g1)
	CH_ICACHE_FLUSHALL(%o2, %o3, %g1, %g2)
	membar	#Sync
	retl
	nop
	SET_SIZE(kdi_flush_idcache)

	ENTRY(flush_pcache)
	PCACHE_FLUSHALL(%o0, %o1, %o2)
	retl
	nop
	SET_SIZE(flush_pcache)


#if defined(CPU_IMP_L1_CACHE_PARITY)

/*
 * Get dcache data and tag.  The Dcache data is a pointer to a ch_dc_data_t
 * structure (see cheetahregs.h):
 * The Dcache *should* be turned off when this code is executed.
 */
	.align	128
	ENTRY(get_dcache_dtag)
	rdpr	%pstate, %o5
	andn    %o5, PSTATE_IE | PSTATE_AM, %o3
	wrpr	%g0, %o3, %pstate
	b	1f
	  stx	%o0, [%o1 + CH_DC_IDX]

	.align	128
1:
	ldxa	[%o0]ASI_DC_TAG, %o2
	stx	%o2, [%o1 + CH_DC_TAG]
	membar	#Sync
	ldxa	[%o0]ASI_DC_UTAG, %o2
	membar	#Sync
	stx	%o2, [%o1 + CH_DC_UTAG]
	ldxa	[%o0]ASI_DC_SNP_TAG, %o2
	stx	%o2, [%o1 + CH_DC_SNTAG]
	add	%o1, CH_DC_DATA, %o1
	clr	%o3
2:
	membar	#Sync				! required before ASI_DC_DATA
	ldxa	[%o0 + %o3]ASI_DC_DATA, %o2
	membar	#Sync				! required after ASI_DC_DATA
	stx	%o2, [%o1 + %o3]
	cmp	%o3, CH_DC_DATA_REG_SIZE - 8
	blt	2b
	  add	%o3, 8, %o3

	/*
	 * Unlike other CPUs in the family, D$ data parity bits for Panther
	 * do not reside in the microtag. Instead, we have to read them
	 * using the DC_data_parity bit of ASI_DCACHE_DATA. Also, instead
	 * of just having 8 parity bits to protect all 32 bytes of data
	 * per line, we now have 32 bits of parity.
	 */
	GET_CPU_IMPL(%o3)
	cmp	%o3, PANTHER_IMPL
	bne	4f
	  clr	%o3

	/*
	 * move our pointer to the next field where we store parity bits
	 * and add the offset of the last parity byte since we will be
	 * storing all 4 parity bytes within one 64 bit field like this:
	 *
	 * +------+------------+------------+------------+------------+
	 * |  -   | DC_parity  | DC_parity  | DC_parity  | DC_parity  |
	 * |  -   | for word 3 | for word 2 | for word 1 | for word 0 |
	 * +------+------------+------------+------------+------------+
	 *  63:32     31:24        23:16         15:8          7:0
	 */
	add	%o1, CH_DC_PN_DATA_PARITY - CH_DC_DATA + 7, %o1

	/* add the DC_data_parity bit into our working index */
	mov	1, %o2
	sll	%o2, PN_DC_DATA_PARITY_BIT_SHIFT, %o2
	or	%o0, %o2, %o0
3:
	membar	#Sync				! required before ASI_DC_DATA
	ldxa	[%o0 + %o3]ASI_DC_DATA, %o2
	membar	#Sync				! required after ASI_DC_DATA
	stb	%o2, [%o1]
	dec	%o1
	cmp	%o3, CH_DC_DATA_REG_SIZE - 8
	blt	3b
	  add	%o3, 8, %o3
4:
	retl
	  wrpr	%g0, %o5, %pstate
	SET_SIZE(get_dcache_dtag)


/*
 * Get icache data and tag.  The data argument is a pointer to a ch_ic_data_t
 * structure (see cheetahregs.h):
 * The Icache *Must* be turned off when this function is called.
 * This is because diagnostic accesses to the Icache interfere with cache
 * consistency.
 */
	.align	128
	ENTRY(get_icache_dtag)
	rdpr	%pstate, %o5
	andn    %o5, PSTATE_IE | PSTATE_AM, %o3
	wrpr	%g0, %o3, %pstate

	stx	%o0, [%o1 + CH_IC_IDX]
	ldxa	[%o0]ASI_IC_TAG, %o2
	stx	%o2, [%o1 + CH_IC_PATAG]
	add	%o0, CH_ICTAG_UTAG, %o0
	ldxa	[%o0]ASI_IC_TAG, %o2
	add	%o0, (CH_ICTAG_UPPER - CH_ICTAG_UTAG), %o0
	stx	%o2, [%o1 + CH_IC_UTAG]
	ldxa	[%o0]ASI_IC_TAG, %o2
	add	%o0, (CH_ICTAG_LOWER - CH_ICTAG_UPPER), %o0
	stx	%o2, [%o1 + CH_IC_UPPER]
	ldxa	[%o0]ASI_IC_TAG, %o2
	andn	%o0, CH_ICTAG_TMASK, %o0
	stx	%o2, [%o1 + CH_IC_LOWER]
	ldxa	[%o0]ASI_IC_SNP_TAG, %o2
	stx	%o2, [%o1 + CH_IC_SNTAG]
	add	%o1, CH_IC_DATA, %o1
	clr	%o3
2:
	ldxa	[%o0 + %o3]ASI_IC_DATA, %o2
	stx	%o2, [%o1 + %o3]
	cmp	%o3, PN_IC_DATA_REG_SIZE - 8
	blt	2b
	  add	%o3, 8, %o3

	retl
	  wrpr	%g0, %o5, %pstate
	SET_SIZE(get_icache_dtag)

/*
 * Get pcache data and tags.
 * inputs:
 *   pcache_idx	- fully constructed VA for for accessing P$ diagnostic
 *		  registers. Contains PC_way and PC_addr shifted into
 *		  the correct bit positions. See the PRM for more details.
 *   data	- pointer to a ch_pc_data_t
 * structure (see cheetahregs.h):
 */
	.align	128
	ENTRY(get_pcache_dtag)
	rdpr	%pstate, %o5
	andn    %o5, PSTATE_IE | PSTATE_AM, %o3
	wrpr	%g0, %o3, %pstate

	stx	%o0, [%o1 + CH_PC_IDX]
	ldxa	[%o0]ASI_PC_STATUS_DATA, %o2
	stx	%o2, [%o1 + CH_PC_STATUS]
	ldxa	[%o0]ASI_PC_TAG, %o2
	stx	%o2, [%o1 + CH_PC_TAG]
	ldxa	[%o0]ASI_PC_SNP_TAG, %o2
	stx	%o2, [%o1 + CH_PC_SNTAG]
	add	%o1, CH_PC_DATA, %o1
	clr	%o3
2:
	ldxa	[%o0 + %o3]ASI_PC_DATA, %o2
	stx	%o2, [%o1 + %o3]
	cmp	%o3, CH_PC_DATA_REG_SIZE - 8
	blt	2b
	  add	%o3, 8, %o3

	retl
	  wrpr	%g0, %o5, %pstate
	SET_SIZE(get_pcache_dtag)

#endif	/* CPU_IMP_L1_CACHE_PARITY */

/*
 * re-enable the i$, d$, w$, and p$ according to bootup cache state.
 * Turn on WE, HPE, SPE, PE, IC, and DC bits defined as DCU_CACHE.
 *   %o0 - 64 bit constant
 */
	ENTRY(set_dcu)
	stxa	%o0, [%g0]ASI_DCU	! Store to DCU
	flush	%g0	/* flush required after changing the IC bit */
	retl
	nop
	SET_SIZE(set_dcu)


/*
 * Return DCU register.
 */
	ENTRY(get_dcu)
	ldxa	[%g0]ASI_DCU, %o0		/* DCU control register */
	retl
	nop
	SET_SIZE(get_dcu)

/*
 * Cheetah/Cheetah+ level 15 interrupt handler trap table entry.
 *
 * This handler is used to check for softints generated by error trap
 * handlers to report errors.  On Cheetah, this mechanism is used by the
 * Fast ECC at TL>0 error trap handler and, on Cheetah+, by both the Fast
 * ECC at TL>0 error and the I$/D$ parity error at TL>0 trap handlers.
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */

	ENTRY_NP(ch_pil15_interrupt_instr)
	ASM_JMP(%g1, ch_pil15_interrupt)
	SET_SIZE(ch_pil15_interrupt_instr)


	ENTRY_NP(ch_pil15_interrupt)

	/*
	 * Since pil_interrupt is hacked to assume that every level 15
	 * interrupt is generated by the CPU to indicate a performance
	 * counter overflow this gets ugly.  Before calling pil_interrupt
	 * the Error at TL>0 pending status is inspected.  If it is
	 * non-zero, then an error has occurred and it is handled.
	 * Otherwise control is transfered to pil_interrupt.  Note that if
	 * an error is detected pil_interrupt will not be called and
	 * overflow interrupts may be lost causing erroneous performance
	 * measurements.  However, error-recovery will have a detrimental
	 * effect on performance anyway.
	 */
	CPU_INDEX(%g1, %g4)
	set	ch_err_tl1_pending, %g4
	ldub	[%g1 + %g4], %g2
	brz	%g2, 1f
	  nop

	/*
	 * We have a pending TL>0 error, clear the TL>0 pending status.
	 */
	stb	%g0, [%g1 + %g4]

	/*
	 * Clear the softint.
	 */
	mov	1, %g5
	sll	%g5, PIL_15, %g5
	wr	%g5, CLEAR_SOFTINT

	/*
	 * For Cheetah*, call cpu_tl1_error via systrap at PIL 15
	 * to process the Fast ECC/Cache Parity at TL>0 error.  Clear
	 * panic flag (%g2).
	 */
	set	cpu_tl1_error, %g1
	clr	%g2
	ba	sys_trap
	  mov	PIL_15, %g4

1:
	/*
	 * The logout is invalid.
	 *
	 * Call the default interrupt handler.
	 */
	sethi	%hi(pil_interrupt), %g1
	jmp	%g1 + %lo(pil_interrupt)
	  mov	PIL_15, %g4

	SET_SIZE(ch_pil15_interrupt)


/*
 * Error Handling
 *
 * Cheetah provides error checking for all memory access paths between
 * the CPU, External Cache, Cheetah Data Switch and system bus. Error
 * information is logged in the AFSR, (also AFSR_EXT for Panther) and
 * AFAR and one of the following traps is generated (provided that it
 * is enabled in External Cache Error Enable Register) to handle that
 * error:
 * 1. trap 0x70: Precise trap
 *    tt0_fecc for errors at trap level(TL)>=0
 * 2. trap 0x0A and 0x32: Deferred trap
 *    async_err for errors at TL>=0
 * 3. trap 0x63: Disrupting trap
 *    ce_err for errors at TL=0
 *    (Note that trap 0x63 cannot happen at trap level > 0)
 *
 * Trap level one handlers panic the system except for the fast ecc
 * error handler which tries to recover from certain errors.
 */

/*
 * FAST ECC TRAP STRATEGY:
 *
 * Software must handle single and multi bit errors which occur due to data
 * or instruction cache reads from the external cache. A single or multi bit
 * error occuring in one of these situations results in a precise trap.
 *
 * The basic flow of this trap handler is as follows:
 *
 * 1) Record the state and then turn off the Dcache and Icache.  The Dcache
 *    is disabled because bad data could have been installed.  The Icache is
 *    turned off because we want to capture the Icache line related to the
 *    AFAR.
 * 2) Disable trapping on CEEN/NCCEN errors during TL=0 processing.
 * 3) Park sibling core if caches are shared (to avoid race condition while
 *    accessing shared resources such as L3 data staging register during
 *    CPU logout.
 * 4) Read the AFAR and AFSR.
 * 5) If CPU logout structure is not being used, then:
 *    6) Clear all errors from the AFSR.
 *    7) Capture Ecache, Dcache and Icache lines in "CPU log out" structure.
 *    8) Flush Ecache then Flush Dcache and Icache and restore to previous
 *       state.
 *    9) Unpark sibling core if we parked it earlier.
 *    10) call cpu_fast_ecc_error via systrap at PIL 14 unless we're already
 *        running at PIL 15.
 * 6) Otherwise, if CPU logout structure is being used:
 *    7) Incriment the "logout busy count".
 *    8) Flush Ecache then Flush Dcache and Icache and restore to previous
 *       state.
 *    9) Unpark sibling core if we parked it earlier.
 *    10) Issue a retry since the other CPU error logging code will end up
 *       finding this error bit and logging information about it later.
 * 7) Alternatively (to 5 and 6 above), if the cpu_private struct is not
 *    yet initialized such that we can't even check the logout struct, then
 *    we place the clo_flags data into %g2 (sys_trap->have_win arg #1) and
 *    call cpu_fast_ecc_error via systrap. The clo_flags parameter is used
 *    to determine information such as TL, TT, CEEN and NCEEN settings, etc
 *    in the high level trap handler since we don't have access to detailed
 *    logout information in cases where the cpu_private struct is not yet
 *    initialized.
 *
 * We flush the E$ and D$ here on TL=1 code to prevent getting nested
 * Fast ECC traps in the TL=0 code.  If we get a Fast ECC event here in
 * the TL=1 code, we will go to the Fast ECC at TL>0 handler which,
 * since it is uses different code/data from this handler, has a better
 * chance of fixing things up than simply recursing through this code
 * again (this would probably cause an eventual kernel stack overflow).
 * If the Fast ECC at TL>0 handler encounters a Fast ECC error before it
 * can flush the E$ (or the error is a stuck-at bit), we will recurse in
 * the Fast ECC at TL>0 handler and eventually Red Mode.
 *
 * Note that for Cheetah (and only Cheetah), we use alias addresses for
 * flushing rather than ASI accesses (which don't exist on Cheetah).
 * Should we encounter a Fast ECC error within this handler on Cheetah,
 * there's a good chance it's within the ecache_flushaddr buffer (since
 * it's the largest piece of memory we touch in the handler and it is
 * usually kernel text/data).  For that reason the Fast ECC at TL>0
 * handler for Cheetah uses an alternate buffer: ecache_tl1_flushaddr.
 */

/*
 * Cheetah ecc-protected E$ trap (Trap 70) at TL=0
 * tt0_fecc is replaced by fecc_err_instr in cpu_init_trap of the various
 * architecture-specific files.
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */

	ENTRY_NP(fecc_err_instr)
	membar	#Sync			! Cheetah requires membar #Sync

	/*
	 * Save current DCU state.  Turn off the Dcache and Icache.
	 */
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, DCU_DC + DCU_IC, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */

	ASM_JMP(%g4, fast_ecc_err)
	SET_SIZE(fecc_err_instr)


#if !(defined(JALAPENO) || defined(SERRANO))

	.section ".text"
	.align	64
	ENTRY_NP(fast_ecc_err)

	/*
	 * Turn off CEEN and NCEEN.
	 */
	ldxa	[%g0]ASI_ESTATE_ERR, %g3
	andn	%g3, EN_REG_NCEEN + EN_REG_CEEN, %g4
	stxa	%g4, [%g0]ASI_ESTATE_ERR
	membar	#Sync			! membar sync required

	/*
	 * Check to see whether we need to park our sibling core
	 * before recording diagnostic information from caches
	 * which may be shared by both cores.
	 * We use %g1 to store information about whether or not
	 * we had to park the core (%g1 holds our DCUCR value and
	 * we only use bits from that register which are "reserved"
	 * to keep track of core parking) so that we know whether
	 * or not to unpark later. %g5 and %g4 are scratch registers.
	 */
	PARK_SIBLING_CORE(%g1, %g5, %g4)

	/*
	 * Do the CPU log out capture.
	 *   %g3 = "failed?" return value.
	 *   %g2 = Input = AFAR. Output the clo_flags info which is passed
	 *         into this macro via %g4. Output only valid if cpu_private
	 *         struct has not been initialized.
	 *   CHPR_FECCTL0_LOGOUT = cpu logout structure offset input
	 *   %g4 = Trap information stored in the cpu logout flags field
	 *   %g5 = scr1
	 *   %g6 = scr2
	 *   %g3 = scr3
	 *   %g4 = scr4
	 */
	 /* store the CEEN and NCEEN values, TL=0 */
	and	%g3, EN_REG_CEEN + EN_REG_NCEEN, %g4
	set	CHPR_FECCTL0_LOGOUT, %g6
	DO_CPU_LOGOUT(%g3, %g2, %g6, %g4, %g5, %g6, %g3, %g4)

	/*
	 * Flush the Ecache (and L2 cache for Panther) to get the error out
	 * of the Ecache.  If the UCC or UCU is on a dirty line, then the
	 * following flush will turn that into a WDC or WDU, respectively.
	 */
	PN_L2_FLUSHALL(%g4, %g5, %g6)

	CPU_INDEX(%g4, %g5)
	mulx	%g4, CPU_NODE_SIZE, %g4
	set	cpunodes, %g5
	add	%g4, %g5, %g4
	ld	[%g4 + ECACHE_LINESIZE], %g5
	ld	[%g4 + ECACHE_SIZE], %g4

	ASM_LDX(%g6, ecache_flushaddr)
	ECACHE_FLUSHALL(%g4, %g5, %g6, %g7)

	/*
	 * Flush the Dcache.  Since bad data could have been installed in
	 * the Dcache we must flush it before re-enabling it.
	 */
	ASM_LD(%g5, dcache_size)
	ASM_LD(%g6, dcache_linesize)
	CH_DCACHE_FLUSHALL(%g5, %g6, %g7)

	/*
	 * Flush the Icache.  Since we turned off the Icache to capture the
	 * Icache line it is now stale or corrupted and we must flush it
	 * before re-enabling it.
	 */
	GET_CPU_PRIVATE_PTR(%g0, %g5, %g7, fast_ecc_err_5);
	ld	[%g5 + CHPR_ICACHE_LINESIZE], %g6
	ba,pt	%icc, 6f
	  ld	[%g5 + CHPR_ICACHE_SIZE], %g5
fast_ecc_err_5:
	ASM_LD(%g5, icache_size)
	ASM_LD(%g6, icache_linesize)
6:
	CH_ICACHE_FLUSHALL(%g5, %g6, %g7, %g4)

	/*
	 * check to see whether we parked our sibling core at the start
	 * of this handler. If so, we need to unpark it here.
	 * We use DCUCR reserved bits (stored in %g1) to keep track of
	 * whether or not we need to unpark. %g5 and %g4 are scratch registers.
	 */
	UNPARK_SIBLING_CORE(%g1, %g5, %g4)

	/*
	 * Restore the Dcache and Icache to the previous state.
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */

	/*
	 * Make sure our CPU logout operation was successful.
	 */
	cmp	%g3, %g0
	be	8f
	  nop

	/*
	 * If the logout structure had been busy, how many times have
	 * we tried to use it and failed (nesting count)? If we have
	 * already recursed a substantial number of times, then we can
	 * assume things are not going to get better by themselves and
	 * so it would be best to panic.
	 */
	cmp	%g3, CLO_NESTING_MAX
	blt	7f
	  nop

        call ptl1_panic
          mov   PTL1_BAD_ECC, %g1

7:
	/*
	 * Otherwise, if the logout structure was busy but we have not
	 * nested more times than our maximum value, then we simply
	 * issue a retry. Our TL=0 trap handler code will check and
	 * clear the AFSR after it is done logging what is currently
	 * in the logout struct and handle this event at that time.
	 */
	retry
8:
	/*
	 * Call cpu_fast_ecc_error via systrap at PIL 14 unless we're
	 * already at PIL 15.
	 */
	set	cpu_fast_ecc_error, %g1
	rdpr	%pil, %g4
	cmp	%g4, PIL_14
	ba	sys_trap
	  movl	%icc, PIL_14, %g4

	SET_SIZE(fast_ecc_err)

#endif	/* !(JALAPENO || SERRANO) */


/*
 * Cheetah/Cheetah+ Fast ECC at TL>0 trap strategy:
 *
 * The basic flow of this trap handler is as follows:
 *
 * 1) In the "trap 70" trap table code (fecc_err_tl1_instr), generate a
 *    software trap 0 ("ta 0") to buy an extra set of %tpc, etc. which we
 *    will use to save %g1 and %g2.
 * 2) At the software trap 0 at TL>0 trap table code (fecc_err_tl1_cont_instr),
 *    we save %g1+%g2 using %tpc, %tnpc + %tstate and jump to the fast ecc
 *    handler (using the just saved %g1).
 * 3) Turn off the Dcache if it was on and save the state of the Dcache
 *    (whether on or off) in Bit2 (CH_ERR_TSTATE_DC_ON) of %tstate.
 *    NB: we don't turn off the Icache because bad data is not installed nor
 *        will we be doing any diagnostic accesses.
 * 4) compute physical address of the per-cpu/per-tl save area using %g1+%g2
 * 5) Save %g1-%g7 into the per-cpu/per-tl save area (%g1 + %g2 from the
 *    %tpc, %tnpc, %tstate values previously saved).
 * 6) set %tl to %tl - 1.
 * 7) Save the appropriate flags and TPC in the ch_err_tl1_data structure.
 * 8) Save the value of CH_ERR_TSTATE_DC_ON in the ch_err_tl1_tmp field.
 * 9) For Cheetah and Jalapeno, read the AFAR and AFSR and clear.  For
 *    Cheetah+ (and later), read the shadow AFAR and AFSR but don't clear.
 *    Save the values in ch_err_tl1_data.  For Panther, read the shadow
 *    AFSR_EXT and save the value in ch_err_tl1_data.
 * 10) Disable CEEN/NCEEN to prevent any disrupting/deferred errors from
 *    being queued.  We'll report them via the AFSR/AFAR capture in step 13.
 * 11) Flush the Ecache.
 *    NB: the Ecache is flushed assuming the largest possible size with
 *        the smallest possible line size since access to the cpu_nodes may
 *        cause an unrecoverable DTLB miss.
 * 12) Reenable CEEN/NCEEN with the value saved from step 10.
 * 13) For Cheetah and Jalapeno, read the AFAR and AFSR and clear again.
 *    For Cheetah+ (and later), read the primary AFAR and AFSR and now clear.
 *    Save the read AFSR/AFAR values in ch_err_tl1_data.  For Panther,
 *    read and clear the primary AFSR_EXT and save it in ch_err_tl1_data.
 * 14) Flush and re-enable the Dcache if it was on at step 3.
 * 15) Do TRAPTRACE if enabled.
 * 16) Check if a UCU->WDU (or L3_UCU->WDU for Panther) happened, panic if so.
 * 17) Set the event pending flag in ch_err_tl1_pending[CPU]
 * 18) Cause a softint 15.  The pil15_interrupt handler will inspect the
 *    event pending flag and call cpu_tl1_error via systrap if set.
 * 19) Restore the registers from step 5 and issue retry.
 */

/*
 * Cheetah ecc-protected E$ trap (Trap 70) at TL>0
 * tt1_fecc is replaced by fecc_err_tl1_instr in cpu_init_trap of the various
 * architecture-specific files.  This generates a "Software Trap 0" at TL>0,
 * which goes to fecc_err_tl1_cont_instr, and we continue the handling there.
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */

	ENTRY_NP(fecc_err_tl1_instr)
	CH_ERR_TL1_TRAPENTRY(SWTRAP_0);
	SET_SIZE(fecc_err_tl1_instr)

/*
 * Software trap 0 at TL>0.
 * tt1_swtrap0 is replaced by fecc_err_tl1_cont_instr in cpu_init_trap of
 * the various architecture-specific files.  This is used as a continuation
 * of the fast ecc handling where we've bought an extra TL level, so we can
 * use %tpc, %tnpc, %tstate to temporarily save the value of registers %g1
 * and %g2.  Note that %tstate has bits 0-2 and then bits 8-19 as r/w,
 * there's a reserved hole from 3-7.  We only use bits 0-1 and 8-9 (the low
 * order two bits from %g1 and %g2 respectively).
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */

	ENTRY_NP(fecc_err_tl1_cont_instr)
	CH_ERR_TL1_SWTRAPENTRY(fast_ecc_tl1_err)
	SET_SIZE(fecc_err_tl1_cont_instr)


/*
 * The ce_err function handles disrupting trap type 0x63 at TL=0.
 *
 * AFSR errors bits which cause this trap are:
 *	CE, EMC, EDU:ST, EDC, WDU, WDC, CPU, CPC, IVU, IVC
 *
 * NCEEN Bit of Cheetah External Cache Error Enable Register enables
 * the following AFSR disrupting traps: EDU:ST, WDU, CPU, IVU
 *
 * CEEN Bit of Cheetah External Cache Error Enable Register enables
 * the following AFSR disrupting traps: CE, EMC, EDC, WDC, CPC, IVC
 *
 * Cheetah+ also handles (No additional processing required):
 *    DUE, DTO, DBERR	(NCEEN controlled)
 *    THCE		(CEEN and ET_ECC_en controlled)
 *    TUE		(ET_ECC_en controlled)
 *
 * Panther further adds:
 *    IMU, L3_EDU, L3_WDU, L3_CPU		(NCEEN controlled)
 *    IMC, L3_EDC, L3_WDC, L3_CPC, L3_THCE	(CEEN controlled)
 *    TUE_SH, TUE		(NCEEN and L2_tag_ECC_en controlled)
 *    L3_TUE, L3_TUE_SH		(NCEEN and ET_ECC_en controlled)
 *    THCE			(CEEN and L2_tag_ECC_en controlled)
 *    L3_THCE			(CEEN and ET_ECC_en controlled)
 *
 * Steps:
 *	1. Disable hardware corrected disrupting errors only (CEEN)
 *	2. Park sibling core if caches are shared (to avoid race
 *	   condition while accessing shared resources such as L3
 *	   data staging register during CPU logout.
 *	3. If the CPU logout structure is not currently being used:
 *		4. Clear AFSR error bits
 *		5. Capture Ecache, Dcache and Icache lines associated
 *		   with AFAR.
 *		6. Unpark sibling core if we parked it earlier.
 *		7. call cpu_disrupting_error via sys_trap at PIL 14
 *		   unless we're already running at PIL 15.
 *	4. Otherwise, if the CPU logout structure is busy:
 *		5. Incriment "logout busy count" and place into %g3
 *		6. Unpark sibling core if we parked it earlier.
 *		7. Issue a retry since the other CPU error logging
 *		   code will end up finding this error bit and logging
 *		   information about it later.
 *	5. Alternatively (to 3 and 4 above), if the cpu_private struct is
 *         not yet initialized such that we can't even check the logout
 *         struct, then we place the clo_flags data into %g2
 *         (sys_trap->have_win arg #1) and call cpu_disrupting_error via
 *         systrap. The clo_flags parameter is used to determine information
 *         such as TL, TT, CEEN settings, etc in the high level trap
 *         handler since we don't have access to detailed logout information
 *         in cases where the cpu_private struct is not yet initialized.
 *
 * %g3: [ logout busy count ] - arg #2
 * %g2: [ clo_flags if cpu_private unavailable ] - sys_trap->have_win: arg #1
 */

	.align	128
	ENTRY_NP(ce_err)
	membar	#Sync			! Cheetah requires membar #Sync

	/*
	 * Disable trap on hardware corrected errors (CEEN) while at TL=0
	 * to prevent recursion.
	 */
	ldxa	[%g0]ASI_ESTATE_ERR, %g1
	bclr	EN_REG_CEEN, %g1
	stxa	%g1, [%g0]ASI_ESTATE_ERR
	membar	#Sync			! membar sync required

	/*
	 * Save current DCU state.  Turn off Icache to allow capture of
	 * Icache data by DO_CPU_LOGOUT.
	 */
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, DCU_IC, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */

	/*
	 * Check to see whether we need to park our sibling core
	 * before recording diagnostic information from caches
	 * which may be shared by both cores.
	 * We use %g1 to store information about whether or not
	 * we had to park the core (%g1 holds our DCUCR value and
	 * we only use bits from that register which are "reserved"
	 * to keep track of core parking) so that we know whether
	 * or not to unpark later. %g5 and %g4 are scratch registers.
	 */
	PARK_SIBLING_CORE(%g1, %g5, %g4)

	/*
	 * Do the CPU log out capture.
	 *   %g3 = "failed?" return value.
	 *   %g2 = Input = AFAR. Output the clo_flags info which is passed
	 *         into this macro via %g4. Output only valid if cpu_private
	 *         struct has not been initialized.
	 *   CHPR_CECC_LOGOUT = cpu logout structure offset input
	 *   %g4 = Trap information stored in the cpu logout flags field
	 *   %g5 = scr1
	 *   %g6 = scr2
	 *   %g3 = scr3
	 *   %g4 = scr4
	 */
	clr	%g4			! TL=0 bit in afsr
	set	CHPR_CECC_LOGOUT, %g6
	DO_CPU_LOGOUT(%g3, %g2, %g6, %g4, %g5, %g6, %g3, %g4)

	/*
	 * Flush the Icache.  Since we turned off the Icache to capture the
	 * Icache line it is now stale or corrupted and we must flush it
	 * before re-enabling it.
	 */
	GET_CPU_PRIVATE_PTR(%g0, %g5, %g7, ce_err_1);
	ld	[%g5 + CHPR_ICACHE_LINESIZE], %g6
	ba,pt	%icc, 2f
	  ld	[%g5 + CHPR_ICACHE_SIZE], %g5
ce_err_1:
	ASM_LD(%g5, icache_size)
	ASM_LD(%g6, icache_linesize)
2:
	CH_ICACHE_FLUSHALL(%g5, %g6, %g7, %g4)

	/*
	 * check to see whether we parked our sibling core at the start
	 * of this handler. If so, we need to unpark it here.
	 * We use DCUCR reserved bits (stored in %g1) to keep track of
	 * whether or not we need to unpark. %g5 and %g4 are scratch registers.
	 */
	UNPARK_SIBLING_CORE(%g1, %g5, %g4)

	/*
	 * Restore Icache to previous state.
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */

	/*
	 * Make sure our CPU logout operation was successful.
	 */
	cmp	%g3, %g0
	be	4f
	  nop

	/*
	 * If the logout structure had been busy, how many times have
	 * we tried to use it and failed (nesting count)? If we have
	 * already recursed a substantial number of times, then we can
	 * assume things are not going to get better by themselves and
	 * so it would be best to panic.
	 */
	cmp	%g3, CLO_NESTING_MAX
	blt	3f
	  nop

        call ptl1_panic
          mov   PTL1_BAD_ECC, %g1

3:
	/*
	 * Otherwise, if the logout structure was busy but we have not
	 * nested more times than our maximum value, then we simply
	 * issue a retry. Our TL=0 trap handler code will check and
	 * clear the AFSR after it is done logging what is currently
	 * in the logout struct and handle this event at that time.
	 */
	retry
4:
	/*
	 * Call cpu_disrupting_error via systrap at PIL 14 unless we're
	 * already at PIL 15.
	 */
	set	cpu_disrupting_error, %g1
	rdpr	%pil, %g4
	cmp	%g4, PIL_14
	ba	sys_trap
	  movl	%icc, PIL_14, %g4
	SET_SIZE(ce_err)


/*
 * This trap cannot happen at TL>0 which means this routine will never
 * actually be called and so we treat this like a BAD TRAP panic.
 */
	.align	64
	ENTRY_NP(ce_err_tl1)

        call ptl1_panic
          mov   PTL1_BAD_TRAP, %g1

	SET_SIZE(ce_err_tl1)


/*
 * The async_err function handles deferred trap types 0xA
 * (instruction_access_error) and 0x32 (data_access_error) at TL>=0.
 *
 * AFSR errors bits which cause this trap are:
 *	UE, EMU, EDU:BLD, L3_EDU:BLD, TO, BERR
 * On some platforms, EMU may causes cheetah to pull the error pin
 * never giving Solaris a chance to take a trap.
 *
 * NCEEN Bit of Cheetah External Cache Error Enable Register enables
 * the following AFSR deferred traps: UE, EMU, EDU:BLD, TO, BERR
 *
 * Steps:
 *	1. Disable CEEN and NCEEN errors to prevent recursive errors.
 *	2. Turn D$ off per Cheetah PRM P.5 Note 6, turn I$ off to capture
 *         I$ line in DO_CPU_LOGOUT.
 *	3. Park sibling core if caches are shared (to avoid race
 *	   condition while accessing shared resources such as L3
 *	   data staging register during CPU logout.
 *	4. If the CPU logout structure is not currently being used:
 *		5. Clear AFSR error bits
 *		6. Capture Ecache, Dcache and Icache lines associated
 *		   with AFAR.
 *		7. Unpark sibling core if we parked it earlier.
 *		8. call cpu_deferred_error via sys_trap.
 *	5. Otherwise, if the CPU logout structure is busy:
 *		6. Incriment "logout busy count"
 *		7. Unpark sibling core if we parked it earlier.
 *		8) Issue a retry since the other CPU error logging
 *		   code will end up finding this error bit and logging
 *		   information about it later.
 *      6. Alternatively (to 4 and 5 above), if the cpu_private struct is
 *         not yet initialized such that we can't even check the logout
 *         struct, then we place the clo_flags data into %g2
 *         (sys_trap->have_win arg #1) and call cpu_deferred_error via
 *         systrap. The clo_flags parameter is used to determine information
 *         such as TL, TT, CEEN settings, etc in the high level trap handler
 *         since we don't have access to detailed logout information in cases
 *         where the cpu_private struct is not yet initialized.
 *
 * %g2: [ clo_flags if cpu_private unavailable ] - sys_trap->have_win: arg #1
 * %g3: [ logout busy count ] - arg #2
 */

	ENTRY_NP(async_err)
	membar	#Sync			! Cheetah requires membar #Sync

	/*
	 * Disable CEEN and NCEEN.
	 */
	ldxa	[%g0]ASI_ESTATE_ERR, %g3
	andn	%g3, EN_REG_NCEEN + EN_REG_CEEN, %g4
	stxa	%g4, [%g0]ASI_ESTATE_ERR
	membar	#Sync			! membar sync required

	/*
	 * Save current DCU state.
	 * Disable Icache to allow capture of Icache data by DO_CPU_LOGOUT.
	 * Do this regardless of whether this is a Data Access Error or
	 * Instruction Access Error Trap.
	 * Disable Dcache for both Data Access Error and Instruction Access
	 * Error per Cheetah PRM P.5 Note 6.
	 */
	ldxa	[%g0]ASI_DCU, %g1	! save DCU in %g1
	andn	%g1, DCU_IC + DCU_DC, %g4
	stxa	%g4, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */

	/*
	 * Check to see whether we need to park our sibling core
	 * before recording diagnostic information from caches
	 * which may be shared by both cores.
	 * We use %g1 to store information about whether or not
	 * we had to park the core (%g1 holds our DCUCR value and
	 * we only use bits from that register which are "reserved"
	 * to keep track of core parking) so that we know whether
	 * or not to unpark later. %g6 and %g4 are scratch registers.
	 */
	PARK_SIBLING_CORE(%g1, %g6, %g4)

	/*
	 * Do the CPU logout capture.
	 *
	 *   %g3 = "failed?" return value.
	 *   %g2 = Input = AFAR. Output the clo_flags info which is passed
	 *         into this macro via %g4. Output only valid if cpu_private
	 *         struct has not been initialized.
	 *   CHPR_ASYNC_LOGOUT = cpu logout structure offset input
	 *   %g4 = Trap information stored in the cpu logout flags field
	 *   %g5 = scr1
	 *   %g6 = scr2
	 *   %g3 = scr3
	 *   %g4 = scr4
	 */
	andcc	%g5, T_TL1, %g0
	clr	%g6
	movnz	%xcc, 1, %g6			! set %g6 if T_TL1 set
	sllx	%g6, CLO_FLAGS_TL_SHIFT, %g6
	sllx	%g5, CLO_FLAGS_TT_SHIFT, %g4
	set	CLO_FLAGS_TT_MASK, %g2
	and	%g4, %g2, %g4			! ttype
	or	%g6, %g4, %g4			! TT and TL
	and	%g3, EN_REG_CEEN, %g3		! CEEN value
	or	%g3, %g4, %g4			! TT and TL and CEEN
	set	CHPR_ASYNC_LOGOUT, %g6
	DO_CPU_LOGOUT(%g3, %g2, %g6, %g4, %g5, %g6, %g3, %g4)

	/*
	 * If the logout struct was busy, we may need to pass the
	 * TT, TL, and CEEN information to the TL=0 handler via
	 * systrap parameter so save it off here.
	 */
	cmp	%g3, %g0
	be	1f
	  nop
	sllx	%g4, 32, %g4
	or	%g4, %g3, %g3
1:
	/*
	 * Flush the Icache.  Since we turned off the Icache to capture the
	 * Icache line it is now stale or corrupted and we must flush it
	 * before re-enabling it.
	 */
	GET_CPU_PRIVATE_PTR(%g0, %g5, %g7, async_err_1);
	ld	[%g5 + CHPR_ICACHE_LINESIZE], %g6
	ba,pt	%icc, 2f
	  ld	[%g5 + CHPR_ICACHE_SIZE], %g5
async_err_1:
	ASM_LD(%g5, icache_size)
	ASM_LD(%g6, icache_linesize)
2:
	CH_ICACHE_FLUSHALL(%g5, %g6, %g7, %g4)

	/*
	 * XXX - Don't we need to flush the Dcache before turning it back
	 *       on to avoid stale or corrupt data? Was this broken?
	 */
	/*
	 * Flush the Dcache before turning it back on since it may now
	 * contain stale or corrupt data.
	 */
	ASM_LD(%g5, dcache_size)
	ASM_LD(%g6, dcache_linesize)
	CH_DCACHE_FLUSHALL(%g5, %g6, %g7)

	/*
	 * check to see whether we parked our sibling core at the start
	 * of this handler. If so, we need to unpark it here.
	 * We use DCUCR reserved bits (stored in %g1) to keep track of
	 * whether or not we need to unpark. %g5 and %g7 are scratch registers.
	 */
	UNPARK_SIBLING_CORE(%g1, %g5, %g7)

	/*
	 * Restore Icache and Dcache to previous state.
	 */
	stxa	%g1, [%g0]ASI_DCU
	flush	%g0	/* flush required after changing the IC bit */

	/*
	 * Make sure our CPU logout operation was successful.
	 */
	cmp	%g3, %g0
	be	4f
	  nop

	/*
	 * If the logout structure had been busy, how many times have
	 * we tried to use it and failed (nesting count)? If we have
	 * already recursed a substantial number of times, then we can
	 * assume things are not going to get better by themselves and
	 * so it would be best to panic.
	 */
	cmp	%g3, CLO_NESTING_MAX
	blt	3f
	  nop

        call ptl1_panic
          mov   PTL1_BAD_ECC, %g1

3:
	/*
	 * Otherwise, if the logout structure was busy but we have not
	 * nested more times than our maximum value, then we simply
	 * issue a retry. Our TL=0 trap handler code will check and
	 * clear the AFSR after it is done logging what is currently
	 * in the logout struct and handle this event at that time.
	 */
	retry
4:
	RESET_USER_RTT_REGS(%g4, %g5, async_err_resetskip)
async_err_resetskip:
	set	cpu_deferred_error, %g1
	ba	sys_trap
	  mov	PIL_15, %g4		! run at pil 15
	SET_SIZE(async_err)

#if defined(CPU_IMP_L1_CACHE_PARITY)

/*
 * D$ parity error trap (trap 71) at TL=0.
 * tt0_dperr is replaced by dcache_parity_instr in cpu_init_trap of
 * the various architecture-specific files.  This merely sets up the
 * arguments for cpu_parity_error and calls it via sys_trap.
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */
	ENTRY_NP(dcache_parity_instr)
	membar	#Sync			! Cheetah+ requires membar #Sync
	set	cpu_parity_error, %g1
	or	%g0, CH_ERR_DPE, %g2
	rdpr	%tpc, %g3
	sethi	%hi(sys_trap), %g7
	jmp	%g7 + %lo(sys_trap)
	  mov	PIL_15, %g4		! run at pil 15
	SET_SIZE(dcache_parity_instr)


/*
 * D$ parity error trap (trap 71) at TL>0.
 * tt1_dperr is replaced by dcache_parity_tl1_instr in cpu_init_trap of
 * the various architecture-specific files.  This generates a "Software
 * Trap 1" at TL>0, which goes to dcache_parity_tl1_cont_instr, and we
 * continue the handling there.
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */
	ENTRY_NP(dcache_parity_tl1_instr)
	CH_ERR_TL1_TRAPENTRY(SWTRAP_1);
	SET_SIZE(dcache_parity_tl1_instr)


/*
 * Software trap 1 at TL>0.
 * tt1_swtrap1 is replaced by dcache_parity_tl1_cont_instr in cpu_init_trap
 * of the various architecture-specific files.  This is used as a continuation
 * of the dcache parity handling where we've bought an extra TL level, so we
 * can use %tpc, %tnpc, %tstate to temporarily save the value of registers %g1
 * and %g2.  Note that %tstate has bits 0-2 and then bits 8-19 as r/w,
 * there's a reserved hole from 3-7.  We only use bits 0-1 and 8-9 (the low
 * order two bits from %g1 and %g2 respectively).
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */
	ENTRY_NP(dcache_parity_tl1_cont_instr)
	CH_ERR_TL1_SWTRAPENTRY(dcache_parity_tl1_err);
	SET_SIZE(dcache_parity_tl1_cont_instr)

/*
 * D$ parity error at TL>0 handler
 * We get here via trap 71 at TL>0->Software trap 1 at TL>0.  We enter
 * this routine with %g1 and %g2 already saved in %tpc, %tnpc and %tstate.
 */

	ENTRY_NP(dcache_parity_tl1_err)

	/*
	 * This macro saves all the %g registers in the ch_err_tl1_data
	 * structure, updates the ch_err_tl1_flags and saves the %tpc in
	 * ch_err_tl1_tpc.  At the end of this macro, %g1 will point to
	 * the ch_err_tl1_data structure and %g2 will have the original
	 * flags in the ch_err_tl1_data structure.  All %g registers
	 * except for %g1 and %g2 will be available.
	 */
	CH_ERR_TL1_ENTER(CH_ERR_DPE);

#ifdef TRAPTRACE
	/*
	 * Get current trap trace entry physical pointer.
	 */
	CPU_INDEX(%g6, %g5)
	sll	%g6, TRAPTR_SIZE_SHIFT, %g6
	set	trap_trace_ctl, %g5
	add	%g6, %g5, %g6
	ld	[%g6 + TRAPTR_LIMIT], %g5
	tst	%g5
	be	%icc, dpe_tl1_skip_tt
	  nop
	ldx	[%g6 + TRAPTR_PBASE], %g5
	ld	[%g6 + TRAPTR_OFFSET], %g4
	add	%g5, %g4, %g5

	/*
	 * Create trap trace entry.
	 */
	rd	%asi, %g7
	wr	%g0, TRAPTR_ASI, %asi
	rd	STICK, %g4
	stxa	%g4, [%g5 + TRAP_ENT_TICK]%asi
	rdpr	%tl, %g4
	stha	%g4, [%g5 + TRAP_ENT_TL]%asi
	rdpr	%tt, %g4
	stha	%g4, [%g5 + TRAP_ENT_TT]%asi
	rdpr	%tpc, %g4
	stna	%g4, [%g5 + TRAP_ENT_TPC]%asi
	rdpr	%tstate, %g4
	stxa	%g4, [%g5 + TRAP_ENT_TSTATE]%asi
	stna	%sp, [%g5 + TRAP_ENT_SP]%asi
	stna	%g0, [%g5 + TRAP_ENT_TR]%asi
	stna	%g0, [%g5 + TRAP_ENT_F1]%asi
	stna	%g0, [%g5 + TRAP_ENT_F2]%asi
	stna	%g0, [%g5 + TRAP_ENT_F3]%asi
	stna	%g0, [%g5 + TRAP_ENT_F4]%asi
	wr	%g0, %g7, %asi

	/*
	 * Advance trap trace pointer.
	 */
	ld	[%g6 + TRAPTR_OFFSET], %g5
	ld	[%g6 + TRAPTR_LIMIT], %g4
	st	%g5, [%g6 + TRAPTR_LAST_OFFSET]
	add	%g5, TRAP_ENT_SIZE, %g5
	sub	%g4, TRAP_ENT_SIZE, %g4
	cmp	%g5, %g4
	movge	%icc, 0, %g5
	st	%g5, [%g6 + TRAPTR_OFFSET]
dpe_tl1_skip_tt:
#endif	/* TRAPTRACE */

	/*
	 * I$ and D$ are automatically turned off by HW when the CPU hits
	 * a dcache or icache parity error so we will just leave those two
	 * off for now to avoid repeating this trap.
	 * For Panther, however, since we trap on P$ data parity errors
	 * and HW does not automatically disable P$, we need to disable it
	 * here so that we don't encounter any recursive traps when we
	 * issue the retry.
	 */
	ldxa	[%g0]ASI_DCU, %g3
	mov	1, %g4
	sllx	%g4, DCU_PE_SHIFT, %g4
	andn	%g3, %g4, %g3
	stxa	%g3, [%g0]ASI_DCU
	membar	#Sync

	/*
	 * We fall into this macro if we've successfully logged the error in
	 * the ch_err_tl1_data structure and want the PIL15 softint to pick
	 * it up and log it.  %g1 must point to the ch_err_tl1_data structure.
	 * Restores the %g registers and issues retry.
	 */
	CH_ERR_TL1_EXIT;
	SET_SIZE(dcache_parity_tl1_err)

/*
 * I$ parity error trap (trap 72) at TL=0.
 * tt0_iperr is replaced by icache_parity_instr in cpu_init_trap of
 * the various architecture-specific files.  This merely sets up the
 * arguments for cpu_parity_error and calls it via sys_trap.
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */

	ENTRY_NP(icache_parity_instr)
	membar	#Sync			! Cheetah+ requires membar #Sync
	set	cpu_parity_error, %g1
	or	%g0, CH_ERR_IPE, %g2
	rdpr	%tpc, %g3
	sethi	%hi(sys_trap), %g7
	jmp	%g7 + %lo(sys_trap)
	  mov	PIL_15, %g4		! run at pil 15
	SET_SIZE(icache_parity_instr)

/*
 * I$ parity error trap (trap 72) at TL>0.
 * tt1_iperr is replaced by icache_parity_tl1_instr in cpu_init_trap of
 * the various architecture-specific files.  This generates a "Software
 * Trap 2" at TL>0, which goes to icache_parity_tl1_cont_instr, and we
 * continue the handling there.
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */
	ENTRY_NP(icache_parity_tl1_instr)
	CH_ERR_TL1_TRAPENTRY(SWTRAP_2);
	SET_SIZE(icache_parity_tl1_instr)

/*
 * Software trap 2 at TL>0.
 * tt1_swtrap2 is replaced by icache_parity_tl1_cont_instr in cpu_init_trap
 * of the various architecture-specific files.  This is used as a continuation
 * of the icache parity handling where we've bought an extra TL level, so we
 * can use %tpc, %tnpc, %tstate to temporarily save the value of registers %g1
 * and %g2.  Note that %tstate has bits 0-2 and then bits 8-19 as r/w,
 * there's a reserved hole from 3-7.  We only use bits 0-1 and 8-9 (the low
 * order two bits from %g1 and %g2 respectively).
 * NB: Must be 8 instructions or less to fit in trap table and code must
 *     be relocatable.
 */
	ENTRY_NP(icache_parity_tl1_cont_instr)
	CH_ERR_TL1_SWTRAPENTRY(icache_parity_tl1_err);
	SET_SIZE(icache_parity_tl1_cont_instr)


/*
 * I$ parity error at TL>0 handler
 * We get here via trap 72 at TL>0->Software trap 2 at TL>0.  We enter
 * this routine with %g1 and %g2 already saved in %tpc, %tnpc and %tstate.
 */

	ENTRY_NP(icache_parity_tl1_err)

	/*
	 * This macro saves all the %g registers in the ch_err_tl1_data
	 * structure, updates the ch_err_tl1_flags and saves the %tpc in
	 * ch_err_tl1_tpc.  At the end of this macro, %g1 will point to
	 * the ch_err_tl1_data structure and %g2 will have the original
	 * flags in the ch_err_tl1_data structure.  All %g registers
	 * except for %g1 and %g2 will be available.
	 */
	CH_ERR_TL1_ENTER(CH_ERR_IPE);

#ifdef TRAPTRACE
	/*
	 * Get current trap trace entry physical pointer.
	 */
	CPU_INDEX(%g6, %g5)
	sll	%g6, TRAPTR_SIZE_SHIFT, %g6
	set	trap_trace_ctl, %g5
	add	%g6, %g5, %g6
	ld	[%g6 + TRAPTR_LIMIT], %g5
	tst	%g5
	be	%icc, ipe_tl1_skip_tt
	  nop
	ldx	[%g6 + TRAPTR_PBASE], %g5
	ld	[%g6 + TRAPTR_OFFSET], %g4
	add	%g5, %g4, %g5

	/*
	 * Create trap trace entry.
	 */
	rd	%asi, %g7
	wr	%g0, TRAPTR_ASI, %asi
	rd	STICK, %g4
	stxa	%g4, [%g5 + TRAP_ENT_TICK]%asi
	rdpr	%tl, %g4
	stha	%g4, [%g5 + TRAP_ENT_TL]%asi
	rdpr	%tt, %g4
	stha	%g4, [%g5 + TRAP_ENT_TT]%asi
	rdpr	%tpc, %g4
	stna	%g4, [%g5 + TRAP_ENT_TPC]%asi
	rdpr	%tstate, %g4
	stxa	%g4, [%g5 + TRAP_ENT_TSTATE]%asi
	stna	%sp, [%g5 + TRAP_ENT_SP]%asi
	stna	%g0, [%g5 + TRAP_ENT_TR]%asi
	stna	%g0, [%g5 + TRAP_ENT_F1]%asi
	stna	%g0, [%g5 + TRAP_ENT_F2]%asi
	stna	%g0, [%g5 + TRAP_ENT_F3]%asi
	stna	%g0, [%g5 + TRAP_ENT_F4]%asi
	wr	%g0, %g7, %asi

	/*
	 * Advance trap trace pointer.
	 */
	ld	[%g6 + TRAPTR_OFFSET], %g5
	ld	[%g6 + TRAPTR_LIMIT], %g4
	st	%g5, [%g6 + TRAPTR_LAST_OFFSET]
	add	%g5, TRAP_ENT_SIZE, %g5
	sub	%g4, TRAP_ENT_SIZE, %g4
	cmp	%g5, %g4
	movge	%icc, 0, %g5
	st	%g5, [%g6 + TRAPTR_OFFSET]
ipe_tl1_skip_tt:
#endif	/* TRAPTRACE */

	/*
	 * We fall into this macro if we've successfully logged the error in
	 * the ch_err_tl1_data structure and want the PIL15 softint to pick
	 * it up and log it.  %g1 must point to the ch_err_tl1_data structure.
	 * Restores the %g registers and issues retry.
	 */
	CH_ERR_TL1_EXIT;

	SET_SIZE(icache_parity_tl1_err)

#endif	/* CPU_IMP_L1_CACHE_PARITY */


/*
 * The itlb_rd_entry and dtlb_rd_entry functions return the tag portion of the
 * tte, the virtual address, and the ctxnum of the specified tlb entry.  They
 * should only be used in places where you have no choice but to look at the
 * tlb itself.
 *
 * Note: These two routines are required by the Estar "cpr" loadable module.
 */

	ENTRY_NP(itlb_rd_entry)
	sllx	%o0, 3, %o0
	ldxa	[%o0]ASI_ITLB_ACCESS, %g1
	stx	%g1, [%o1]
	ldxa	[%o0]ASI_ITLB_TAGREAD, %g2
	set	TAGREAD_CTX_MASK, %o4
	andn	%g2, %o4, %o5
	retl
	  stx	%o5, [%o2]
	SET_SIZE(itlb_rd_entry)


	ENTRY_NP(dtlb_rd_entry)
	sllx	%o0, 3, %o0
	ldxa	[%o0]ASI_DTLB_ACCESS, %g1
	stx	%g1, [%o1]
	ldxa	[%o0]ASI_DTLB_TAGREAD, %g2
	set	TAGREAD_CTX_MASK, %o4
	andn	%g2, %o4, %o5
	retl
	  stx	%o5, [%o2]
	SET_SIZE(dtlb_rd_entry)


#if !(defined(JALAPENO) || defined(SERRANO))

	ENTRY(get_safari_config)
	ldxa	[%g0]ASI_SAFARI_CONFIG, %o0
	retl
	nop
	SET_SIZE(get_safari_config)


	ENTRY(set_safari_config)
	stxa	%o0, [%g0]ASI_SAFARI_CONFIG
	membar	#Sync
	retl
	nop
	SET_SIZE(set_safari_config)

#endif	/* !(JALAPENO || SERRANO) */


	/*
	 * Clear the NPT (non-privileged trap) bit in the %tick/%stick
	 * registers. In an effort to make the change in the
	 * tick/stick counter as consistent as possible, we disable
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
	.align	8			/* Ensure rd/wr in same i$ line */
2:
	rdpr	%tick, %g2		/* get tick register */
	wrpr	%g3, %g2, %tick		/* write tick register, */
					/*   clearing NPT bit   */
1:
	rd	STICK, %g2		/* get stick register */
	brgez,pn %g2, 3f		/* if NPT bit off, we're done */
	mov	1, %g3			/* create mask */
	sllx	%g3, 63, %g3		/*   for NPT bit */
	ba,a,pt	%xcc, 4f
	.align	8			/* Ensure rd/wr in same i$ line */
4:
	rd	STICK, %g2		/* get stick register */
	wr	%g3, %g2, STICK		/* write stick register, */
					/*   clearing NPT bit   */
3:
	jmp	%g4 + 4
	wrpr	%g0, %g1, %pstate	/* restore processor state */

	SET_SIZE(cpu_clearticknpt)


#if defined(CPU_IMP_L1_CACHE_PARITY)

/*
 * correct_dcache_parity(size_t size, size_t linesize)
 *
 * Correct D$ data parity by zeroing the data and initializing microtag
 * for all indexes and all ways of the D$.
 *
 */
	ENTRY(correct_dcache_parity)
	/*
	 * Register Usage:
	 *
	 * %o0 = input D$ size
	 * %o1 = input D$ line size
	 * %o2 = scratch
	 * %o3 = scratch
	 * %o4 = scratch
	 */

	sub	%o0, %o1, %o0			! init cache line address

	/*
	 * For Panther CPUs, we also need to clear the data parity bits
	 * using DC_data_parity bit of the ASI_DCACHE_DATA register.
	 */
	GET_CPU_IMPL(%o3)
	cmp	%o3, PANTHER_IMPL
	bne	1f
	  clr	%o3				! zero for non-Panther
	mov	1, %o3
	sll	%o3, PN_DC_DATA_PARITY_BIT_SHIFT, %o3

1:
	/*
	 * Set utag = way since it must be unique within an index.
	 */
	srl	%o0, 14, %o2			! get cache way (DC_way)
	membar	#Sync				! required before ASI_DC_UTAG
	stxa	%o2, [%o0]ASI_DC_UTAG		! set D$ utag = cache way
	membar	#Sync				! required after ASI_DC_UTAG

	/*
	 * Zero line of D$ data (and data parity bits for Panther)
	 */
	sub	%o1, 8, %o2
	or	%o0, %o3, %o4			! same address + DC_data_parity
2:
	membar	#Sync				! required before ASI_DC_DATA
	stxa	%g0, [%o0 + %o2]ASI_DC_DATA	! zero 8 bytes of D$ data
	membar	#Sync				! required after ASI_DC_DATA
	/*
	 * We also clear the parity bits if this is a panther. For non-Panther
	 * CPUs, we simply end up clearing the $data register twice.
	 */
	stxa	%g0, [%o4 + %o2]ASI_DC_DATA
	membar	#Sync

	subcc	%o2, 8, %o2
	bge	2b
	nop

	subcc	%o0, %o1, %o0
	bge	1b
	nop

	retl
	  nop
	SET_SIZE(correct_dcache_parity)

#endif	/* CPU_IMP_L1_CACHE_PARITY */


	ENTRY_NP(stick_timestamp)
	rd	STICK, %g1	! read stick reg
	sllx	%g1, 1, %g1
	srlx	%g1, 1, %g1	! clear npt bit

	retl
	stx     %g1, [%o0]	! store the timestamp
	SET_SIZE(stick_timestamp)


	ENTRY_NP(stick_adj)
	rdpr	%pstate, %g1		! save processor state
	andn	%g1, PSTATE_IE, %g3
	ba	1f			! cache align stick adj
	wrpr	%g0, %g3, %pstate	! turn off interrupts

	.align	16
1:	nop

	rd	STICK, %g4		! read stick reg
	add	%g4, %o0, %o1		! adjust stick with skew
	wr	%o1, %g0, STICK		! write stick reg

	retl
	wrpr	%g1, %pstate		! restore processor state
	SET_SIZE(stick_adj)

	ENTRY_NP(kdi_get_stick)
	rd	STICK, %g1
	stx	%g1, [%o0]
	retl
	mov	%g0, %o0
	SET_SIZE(kdi_get_stick)

/*
 * Invalidate the specified line from the D$.
 *
 * Register usage:
 *	%o0 - index for the invalidation, specifies DC_way and DC_addr
 *
 * ASI_DC_TAG, 0x47, is used in the following manner. A 64-bit value is
 * stored to a particular DC_way and DC_addr in ASI_DC_TAG.
 *
 * The format of the stored 64-bit value is:
 *
 *	+----------+--------+----------+
 *	| Reserved | DC_tag | DC_valid |
 *	+----------+--------+----------+
 *       63      31 30     1	      0
 *
 * DC_tag is the 30-bit physical tag of the associated line.
 * DC_valid is the 1-bit valid field for both the physical and snoop tags.
 *
 * The format of the 64-bit DC_way and DC_addr into ASI_DC_TAG is:
 *
 *	+----------+--------+----------+----------+
 *	| Reserved | DC_way | DC_addr  | Reserved |
 *	+----------+--------+----------+----------+
 *       63      16 15    14 13       5 4        0
 *
 * DC_way is a 2-bit index that selects one of the 4 ways.
 * DC_addr is a 9-bit index that selects one of 512 tag/valid fields.
 *
 * Setting the DC_valid bit to zero for the specified DC_way and
 * DC_addr index into the D$ results in an invalidation of a D$ line.
 */
	ENTRY(dcache_inval_line)
	sll	%o0, 5, %o0		! shift index into DC_way and DC_addr
	stxa	%g0, [%o0]ASI_DC_TAG	! zero the DC_valid and DC_tag bits
	membar	#Sync
	retl
	nop
	SET_SIZE(dcache_inval_line)

/*
 * Invalidate the entire I$
 *
 * Register usage:
 *	%o0 - specifies IC_way, IC_addr, IC_tag
 *	%o1 - scratch
 *	%o2 - used to save and restore DCU value
 *	%o3 - scratch
 *	%o5 - used to save and restore PSTATE
 *
 * Due to the behavior of the I$ control logic when accessing ASI_IC_TAG,
 * the I$ should be turned off. Accesses to ASI_IC_TAG may collide and
 * block out snoops and invalidates to the I$, causing I$ consistency
 * to be broken. Before turning on the I$, all I$ lines must be invalidated.
 *
 * ASI_IC_TAG, 0x67, is used in the following manner. A 64-bit value is
 * stored to a particular IC_way, IC_addr, IC_tag in ASI_IC_TAG. The
 * info below describes store (write) use of ASI_IC_TAG. Note that read
 * use of ASI_IC_TAG behaves differently.
 *
 * The format of the stored 64-bit value is:
 *
 *	+----------+--------+---------------+-----------+
 *	| Reserved | Valid  | IC_vpred<7:0> | Undefined |
 *	+----------+--------+---------------+-----------+
 *       63      55    54    53           46 45        0
 *
 * Valid is the 1-bit valid field for both the physical and snoop tags.
 * IC_vpred is the 8-bit LPB bits for 8 instructions starting at
 *	the 32-byte boundary aligned address specified by IC_addr.
 *
 * The format of the 64-bit IC_way, IC_addr, IC_tag into ASI_IC_TAG is:
 *
 *	+----------+--------+---------+--------+---------+
 *	| Reserved | IC_way | IC_addr | IC_tag |Reserved |
 *	+----------+--------+---------+--------+---------+
 *       63      16 15    14 13      5 4      3 2       0
 *
 * IC_way is a 2-bit index that selects one of the 4 ways.
 * IC_addr[13:6] is an 8-bit index that selects one of 256 valid fields.
 * IC_addr[5] is a "don't care" for a store.
 * IC_tag set to 2 specifies that the stored value is to be interpreted
 *	as containing Valid and IC_vpred as described above.
 *
 * Setting the Valid bit to zero for the specified IC_way and
 * IC_addr index into the I$ results in an invalidation of an I$ line.
 */
	ENTRY(icache_inval_all)
	rdpr	%pstate, %o5
	andn	%o5, PSTATE_IE, %o3
	wrpr	%g0, %o3, %pstate	! clear IE bit

	GET_CPU_PRIVATE_PTR(%g0, %o0, %o2, icache_inval_all_1);
	ld	[%o0 + CHPR_ICACHE_LINESIZE], %o1
	ba,pt	%icc, 2f
	  ld	[%o0 + CHPR_ICACHE_SIZE], %o0
icache_inval_all_1:
	ASM_LD(%o0, icache_size)
	ASM_LD(%o1, icache_linesize)
2:
	CH_ICACHE_FLUSHALL(%o0, %o1, %o2, %o4)

	retl
	wrpr	%g0, %o5, %pstate	! restore earlier pstate
	SET_SIZE(icache_inval_all)


/*
 * cache_scrubreq_tl1 is the crosstrap handler called on offlined cpus via a
 * crosstrap.  It atomically increments the outstanding request counter and,
 * if there was not already an outstanding request, branches to setsoftint_tl1
 * to enqueue an intr_vec for the given inum.
 */

	! Register usage:
	!
	! Arguments:
	! %g1 - inum
	! %g2 - index into chsm_outstanding array
	!
	! Internal:
	! %g2, %g3, %g5 - scratch
	! %g4 - ptr. to scrub_misc chsm_outstanding[index].
	! %g6 - setsoftint_tl1 address

	ENTRY_NP(cache_scrubreq_tl1)
	mulx	%g2, CHSM_OUTSTANDING_INCR, %g2
	set	CHPR_SCRUB_MISC + CHSM_OUTSTANDING, %g3
	add	%g2, %g3, %g2
	GET_CPU_PRIVATE_PTR(%g2, %g4, %g5, 1f);
	ld	[%g4], %g2		! cpu's chsm_outstanding[index]
	!
	! no need to use atomic instructions for the following
	! increment - we're at tl1
	!
	add	%g2, 0x1, %g3
	brnz,pn	%g2, 1f			! no need to enqueue more intr_vec
	  st	%g3, [%g4]		! delay - store incremented counter
	ASM_JMP(%g6, setsoftint_tl1)
	! not reached
1:
	retry
	SET_SIZE(cache_scrubreq_tl1)


/*
 * Get the error state for the processor.
 * Note that this must not be used at TL>0
 */
	ENTRY(get_cpu_error_state)
#if defined(CHEETAH_PLUS)
	set	ASI_SHADOW_REG_VA, %o2
	ldxa	[%o2]ASI_AFSR, %o1		! shadow afsr reg
	stx	%o1, [%o0 + CH_CPU_ERRORS_SHADOW_AFSR]
	ldxa	[%o2]ASI_AFAR, %o1		! shadow afar reg
	stx	%o1, [%o0 + CH_CPU_ERRORS_SHADOW_AFAR]
	GET_CPU_IMPL(%o3)	! Only panther has AFSR_EXT registers
	cmp	%o3, PANTHER_IMPL
	bne,a	1f
	  stx	%g0, [%o0 + CH_CPU_ERRORS_AFSR_EXT]	! zero for non-PN
	set	ASI_AFSR_EXT_VA, %o2
	ldxa	[%o2]ASI_AFSR, %o1		! afsr_ext reg
	stx	%o1, [%o0 + CH_CPU_ERRORS_AFSR_EXT]
	set	ASI_SHADOW_AFSR_EXT_VA, %o2
	ldxa	[%o2]ASI_AFSR, %o1		! shadow afsr_ext reg
	stx	%o1, [%o0 + CH_CPU_ERRORS_SHADOW_AFSR_EXT]
	b	2f
	  nop
1:
	stx	%g0, [%o0 + CH_CPU_ERRORS_SHADOW_AFSR_EXT] ! zero for non-PN
2:
#else	/* CHEETAH_PLUS */
	stx	%g0, [%o0 + CH_CPU_ERRORS_SHADOW_AFSR]
	stx	%g0, [%o0 + CH_CPU_ERRORS_SHADOW_AFAR]
	stx	%g0, [%o0 + CH_CPU_ERRORS_AFSR_EXT]
	stx	%g0, [%o0 + CH_CPU_ERRORS_SHADOW_AFSR_EXT]
#endif	/* CHEETAH_PLUS */
#if defined(SERRANO)
	/*
	 * Serrano has an afar2 which captures the address on FRC/FRU errors.
	 * We save this in the afar2 of the register save area.
	 */
	set	ASI_MCU_AFAR2_VA, %o2
	ldxa	[%o2]ASI_MCU_CTRL, %o1
	stx	%o1, [%o0 + CH_CPU_ERRORS_AFAR2]
#endif	/* SERRANO */
	ldxa	[%g0]ASI_AFSR, %o1		! primary afsr reg
	stx	%o1, [%o0 + CH_CPU_ERRORS_AFSR]
	ldxa	[%g0]ASI_AFAR, %o1		! primary afar reg
	retl
	stx	%o1, [%o0 + CH_CPU_ERRORS_AFAR]
	SET_SIZE(get_cpu_error_state)

/*
 * Check a page of memory for errors.
 *
 * Load each 64 byte block from physical memory.
 * Check AFSR after each load to see if an error
 * was caused. If so, log/scrub that error.
 *
 * Used to determine if a page contains
 * CEs when CEEN is disabled.
 */
	ENTRY(cpu_check_block)
	!
	! get a new window with room for the error regs
	!
	save	%sp, -SA(MINFRAME + CH_CPU_ERROR_SIZE), %sp
	srl	%i1, 6, %l4		! clear top bits of psz
					! and divide by 64
	rd	%fprs, %l2		! store FP
	wr	%g0, FPRS_FEF, %fprs	! enable FP
1:
	ldda	[%i0]ASI_BLK_P, %d0	! load a block
	membar	#Sync
	ldxa    [%g0]ASI_AFSR, %l3	! read afsr reg
	brz,a,pt %l3, 2f		! check for error
	nop

	!
	! if error, read the error regs and log it
	!
	call	get_cpu_error_state
	add	%fp, STACK_BIAS - CH_CPU_ERROR_SIZE, %o0

	!
	! cpu_ce_detected(ch_cpu_errors_t *, flag)
	!
	call	cpu_ce_detected		! log the error
	mov	CE_CEEN_TIMEOUT, %o1
2:
	dec	%l4			! next 64-byte block
	brnz,a,pt  %l4, 1b
	add	%i0, 64, %i0		! increment block addr

	wr	%l2, %g0, %fprs		! restore FP
	ret
	restore

	SET_SIZE(cpu_check_block)

/*
 * Perform a cpu logout called from C.  This is used where we did not trap
 * for the error but still want to gather "what we can".  Caller must make
 * sure cpu private area exists and that the indicated logout area is free
 * for use, and that we are unable to migrate cpus.
 */
	ENTRY(cpu_delayed_logout)
	rdpr	%pstate, %o2
	andn	%o2, PSTATE_IE, %o2
	wrpr	%g0, %o2, %pstate		! disable interrupts
	PARK_SIBLING_CORE(%o2, %o3, %o4)	! %o2 has DCU value
	add	%o1, CH_CLO_DATA + CH_CHD_EC_DATA, %o1
	rd	%asi, %g1
	wr	%g0, ASI_P, %asi
	GET_ECACHE_DTAGS(%o0, %o1, %o3, %o4, %o5)
	wr	%g1, %asi
	UNPARK_SIBLING_CORE(%o2, %o3, %o4)	! can use %o2 again
	rdpr	%pstate, %o2
	or	%o2, PSTATE_IE, %o2
	wrpr	%g0, %o2, %pstate
	retl
	  nop
	SET_SIZE(cpu_delayed_logout)

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

#ifdef	CHEETAHPLUS_ERRATUM_25

	/* Claim a chunk of physical address space. */
	ENTRY(claimlines)
1:
	subcc	%o1, %o2, %o1
	add	%o0, %o1, %o3
	bgeu,a,pt	%xcc, 1b
	casxa	[%o3]ASI_MEM, %g0, %g0
	membar  #Sync
	retl
	nop
	SET_SIZE(claimlines)

	/*
	 * CPU feature initialization,
	 * turn BPE off,
	 * get device id.
	 */
	ENTRY(cpu_feature_init)
	save	%sp, -SA(MINFRAME), %sp
	sethi	%hi(cheetah_bpe_off), %o0
	ld	[%o0 + %lo(cheetah_bpe_off)], %o0
	brz	%o0, 1f
	nop
	rd	ASR_DISPATCH_CONTROL, %o0
	andn	%o0, ASR_DISPATCH_CONTROL_BPE, %o0
	wr	%o0, 0, ASR_DISPATCH_CONTROL
1:
	!
	! get the device_id and store the device_id
	! in the appropriate cpunodes structure
	! given the cpus index
	!
	CPU_INDEX(%o0, %o1)
	mulx %o0, CPU_NODE_SIZE, %o0
	set  cpunodes + DEVICE_ID, %o1
	ldxa [%g0] ASI_DEVICE_SERIAL_ID, %o2
	stx  %o2, [%o0 + %o1]
#ifdef	CHEETAHPLUS_ERRATUM_34
	!
	! apply Cheetah+ erratum 34 workaround
	!
	call itlb_erratum34_fixup
	  nop
	call dtlb_erratum34_fixup
	  nop
#endif	/* CHEETAHPLUS_ERRATUM_34 */
	ret
	  restore
	SET_SIZE(cpu_feature_init)

/*
 * Copy a tsb entry atomically, from src to dest.
 * src must be 128 bit aligned.
 */
	ENTRY(copy_tsb_entry)
	ldda	[%o0]ASI_NQUAD_LD, %o2		! %o2 = tag, %o3 = data
	stx	%o2, [%o1]
	stx	%o3, [%o1 + 8 ]
	retl
	nop
	SET_SIZE(copy_tsb_entry)

#endif	/* CHEETAHPLUS_ERRATUM_25 */

#ifdef	CHEETAHPLUS_ERRATUM_34

	!
	! In Cheetah+ erratum 34, under certain conditions an ITLB locked
	! index 0 TTE will erroneously be displaced when a new TTE is
	! loaded via ASI_ITLB_IN.  In order to avoid cheetah+ erratum 34,
	! locked index 0 TTEs must be relocated.
	!
	! NOTE: Care must be taken to avoid an ITLB miss in this routine.
	!
	ENTRY_NP(itlb_erratum34_fixup)
	rdpr	%pstate, %o3
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o3, u3_di_label1, %g1)
#endif /* DEBUG */
	wrpr	%o3, PSTATE_IE, %pstate		! Disable interrupts
	ldxa	[%g0]ASI_ITLB_ACCESS, %o1	! %o1 = entry 0 data
	ldxa	[%g0]ASI_ITLB_TAGREAD, %o2	! %o2 = entry 0 tag

	cmp	%o1, %g0			! Is this entry valid?
	bge	%xcc, 1f
	  andcc	%o1, TTE_LCK_INT, %g0		! Is this entry locked?
	bnz	%icc, 2f
	  nop
1:
	retl					! Nope, outta here...
	  wrpr	%g0, %o3, %pstate		! Enable interrupts
2:
	sethi	%hi(FLUSH_ADDR), %o4
	stxa	%g0, [%o2]ASI_ITLB_DEMAP	! Flush this mapping
	flush	%o4				! Flush required for I-MMU
	!
	! Start search from index 1 up.  This is because the kernel force
	! loads its text page at index 15 in sfmmu_kernel_remap() and we
	! don't want our relocated entry evicted later.
	!
	! NOTE: We assume that we'll be successful in finding an unlocked
	! or invalid entry.  If that isn't the case there are bound to
	! bigger problems.
	!
	set	(1 << 3), %g3
3:
	ldxa	[%g3]ASI_ITLB_ACCESS, %o4	! Load TTE from t16
	!
	! If this entry isn't valid, we'll choose to displace it (regardless
	! of the lock bit).
	!
	cmp	%o4, %g0			! TTE is > 0 iff not valid
	bge	%xcc, 4f			! If invalid, go displace
	  andcc	%o4, TTE_LCK_INT, %g0		! Check for lock bit
	bnz,a	%icc, 3b			! If locked, look at next
	  add	%g3, (1 << 3), %g3		!  entry
4:
	!
	! We found an unlocked or invalid entry; we'll explicitly load
	! the former index 0 entry here.
	!
	sethi	%hi(FLUSH_ADDR), %o4
	set	MMU_TAG_ACCESS, %g4
	stxa	%o2, [%g4]ASI_IMMU
	stxa	%o1, [%g3]ASI_ITLB_ACCESS
	flush	%o4				! Flush required for I-MMU
	retl
	  wrpr	%g0, %o3, %pstate		! Enable interrupts
	SET_SIZE(itlb_erratum34_fixup)

	!
	! In Cheetah+ erratum 34, under certain conditions a DTLB locked
	! index 0 TTE will erroneously be displaced when a new TTE is
	! loaded.  In order to avoid cheetah+ erratum 34, locked index 0
	! TTEs must be relocated.
	!
	ENTRY_NP(dtlb_erratum34_fixup)
	rdpr	%pstate, %o3
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o3, u3_di_label2, %g1)
#endif /* DEBUG */
	wrpr	%o3, PSTATE_IE, %pstate		! Disable interrupts
	ldxa	[%g0]ASI_DTLB_ACCESS, %o1	! %o1 = entry 0 data
	ldxa	[%g0]ASI_DTLB_TAGREAD, %o2	! %o2 = entry 0 tag

	cmp	%o1, %g0			! Is this entry valid?
	bge	%xcc, 1f
	  andcc	%o1, TTE_LCK_INT, %g0		! Is this entry locked?
	bnz	%icc, 2f
	  nop
1:
	retl					! Nope, outta here...
	  wrpr	%g0, %o3, %pstate		! Enable interrupts
2:
	stxa	%g0, [%o2]ASI_DTLB_DEMAP	! Flush this mapping
	membar	#Sync
	!
	! Start search from index 1 up.
	!
	! NOTE: We assume that we'll be successful in finding an unlocked
	! or invalid entry.  If that isn't the case there are bound to
	! bigger problems.
	!
	set	(1 << 3), %g3
3:
	ldxa	[%g3]ASI_DTLB_ACCESS, %o4	! Load TTE from t16
	!
	! If this entry isn't valid, we'll choose to displace it (regardless
	! of the lock bit).
	!
	cmp	%o4, %g0			! TTE is > 0 iff not valid
	bge	%xcc, 4f			! If invalid, go displace
	  andcc	%o4, TTE_LCK_INT, %g0		! Check for lock bit
	bnz,a	%icc, 3b			! If locked, look at next
	  add	%g3, (1 << 3), %g3		!  entry
4:
	!
	! We found an unlocked or invalid entry; we'll explicitly load
	! the former index 0 entry here.
	!
	set	MMU_TAG_ACCESS, %g4
	stxa	%o2, [%g4]ASI_DMMU
	stxa	%o1, [%g3]ASI_DTLB_ACCESS
	membar	#Sync
	retl
	  wrpr	%g0, %o3, %pstate		! Enable interrupts
	SET_SIZE(dtlb_erratum34_fixup)

#endif	/* CHEETAHPLUS_ERRATUM_34 */

