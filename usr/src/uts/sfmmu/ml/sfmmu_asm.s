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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*
 * SFMMU primitives.  These primitives should only be used by sfmmu
 * routines.
 */

#if defined(lint)
#include <sys/types.h>
#else	/* lint */
#include "assym.h"
#endif	/* lint */

#include <sys/asm_linkage.h>
#include <sys/machtrap.h>
#include <sys/machasi.h>
#include <sys/sun4asi.h>
#include <sys/pte.h>
#include <sys/mmu.h>
#include <vm/hat_sfmmu.h>
#include <vm/seg_spt.h>
#include <sys/machparam.h>
#include <sys/privregs.h>
#include <sys/scb.h>
#include <sys/intreg.h>
#include <sys/machthread.h>
#include <sys/intr.h>
#include <sys/clock.h>
#include <sys/trapstat.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>

/*
 * Tracing macro. Adds two instructions if TRAPTRACE is defined.
 */
#define	TT_TRACE(label)		\
	ba	label		;\
	rd	%pc, %g7
#else

#define	TT_TRACE(label)

#endif /* TRAPTRACE */

#ifndef	lint

#if (TTE_SUSPEND_SHIFT > 0)
#define	TTE_SUSPEND_INT_SHIFT(reg)				\
	sllx	reg, TTE_SUSPEND_SHIFT, reg
#else
#define	TTE_SUSPEND_INT_SHIFT(reg)
#endif

#endif /* lint */

#ifndef	lint

/*
 * Assumes TSBE_TAG is 0
 * Assumes TSBE_INTHI is 0
 * Assumes TSBREG.split is 0
 */

#if TSBE_TAG != 0
#error "TSB_UPDATE and TSB_INVALIDATE assume TSBE_TAG = 0"
#endif

#if TSBTAG_INTHI != 0
#error "TSB_UPDATE and TSB_INVALIDATE assume TSBTAG_INTHI = 0"
#endif

/*
 * The following code assumes the tsb is not split.
 *
 * With TSBs no longer shared between processes, it's no longer
 * necessary to hash the context bits into the tsb index to get
 * tsb coloring; the new implementation treats the TSB as a
 * direct-mapped, virtually-addressed cache.
 *
 * In:
 *    vpshift = virtual page shift; e.g. 13 for 8K TTEs (constant or ro)
 *    tsbbase = base address of TSB (clobbered)
 *    tagacc = tag access register (clobbered)
 *    szc = size code of TSB (ro)
 *    tmp = scratch reg
 * Out:
 *    tsbbase = pointer to entry in TSB
 */
#define	GET_TSBE_POINTER(vpshift, tsbbase, tagacc, szc, tmp)		\
	mov	TSB_ENTRIES(0), tmp	/* nentries in TSB size 0 */	;\
	srlx	tagacc, vpshift, tagacc 				;\
	sllx	tmp, szc, tmp		/* tmp = nentries in TSB */	;\
	sub	tmp, 1, tmp		/* mask = nentries - 1 */	;\
	and	tagacc, tmp, tmp	/* tsbent = virtpage & mask */	;\
	sllx	tmp, TSB_ENTRY_SHIFT, tmp	/* entry num --> ptr */	;\
	add	tsbbase, tmp, tsbbase	/* add entry offset to TSB base */

/*
 * When the kpm TSB is used it is assumed that it is direct mapped
 * using (vaddr>>vpshift)%tsbsz as the index.
 *
 * Note that, for now, the kpm TSB and kernel TSB are the same for
 * each mapping size.  However that need not always be the case.  If
 * the trap handlers are updated to search a different TSB for kpm
 * addresses than for kernel addresses then kpm_tsbbase and kpm_tsbsz
 * (and/or kpmsm_tsbbase/kpmsm_tsbsz) may be entirely independent.
 *
 * In:
 *    vpshift = virtual page shift; e.g. 13 for 8K TTEs (constant or ro)
 *    vaddr = virtual address (clobbered)
 *    tsbp, szc, tmp = scratch
 * Out:
 *    tsbp = pointer to entry in TSB
 */
#define	GET_KPM_TSBE_POINTER(vpshift, tsbp, vaddr, szc, tmp)		\
	cmp	vpshift, MMU_PAGESHIFT					;\
	bne,pn	%icc, 1f		/* branch if large case */	;\
	  sethi	%hi(kpmsm_tsbsz), szc					;\
	sethi	%hi(kpmsm_tsbbase), tsbp				;\
	ld	[szc + %lo(kpmsm_tsbsz)], szc				;\
	ldx	[tsbp + %lo(kpmsm_tsbbase)], tsbp			;\
	ba,pt	%icc, 2f						;\
	  nop								;\
1:	sethi	%hi(kpm_tsbsz), szc					;\
	sethi	%hi(kpm_tsbbase), tsbp					;\
	ld	[szc + %lo(kpm_tsbsz)], szc				;\
	ldx	[tsbp + %lo(kpm_tsbbase)], tsbp				;\
2:	GET_TSBE_POINTER(vpshift, tsbp, vaddr, szc, tmp)

/*
 * Lock the TSBE at virtual address tsbep.
 *
 * tsbep = TSBE va (ro)
 * tmp1, tmp2 = scratch registers (clobbered)
 * label = label to jump to if we fail to lock the tsb entry
 * %asi = ASI to use for TSB access
 *
 * NOTE that we flush the TSB using fast VIS instructions that
 * set all 1's in the TSB tag, so TSBTAG_LOCKED|TSBTAG_INVALID must
 * not be treated as a locked entry or we'll get stuck spinning on
 * an entry that isn't locked but really invalid.
 */

#if defined(UTSB_PHYS)

#define	TSB_LOCK_ENTRY(tsbep, tmp1, tmp2, label)			\
	lda	[tsbep]ASI_MEM, tmp1					;\
	sethi	%hi(TSBTAG_LOCKED), tmp2				;\
	cmp	tmp1, tmp2 						;\
	be,a,pn	%icc, label		/* if locked ignore */		;\
	  nop								;\
	casa	[tsbep]ASI_MEM, tmp1, tmp2				;\
	cmp	tmp1, tmp2 						;\
	bne,a,pn %icc, label		/* didn't lock so ignore */	;\
	  nop								;\
	/* tsbe lock acquired */					;\
	membar #StoreStore

#else /* UTSB_PHYS */

#define	TSB_LOCK_ENTRY(tsbep, tmp1, tmp2, label)			\
	lda	[tsbep]%asi, tmp1					;\
	sethi	%hi(TSBTAG_LOCKED), tmp2				;\
	cmp	tmp1, tmp2 						;\
	be,a,pn	%icc, label		/* if locked ignore */		;\
	  nop								;\
	casa	[tsbep]%asi, tmp1, tmp2					;\
	cmp	tmp1, tmp2 						;\
	bne,a,pn %icc, label		/* didn't lock so ignore */	;\
	  nop								;\
	/* tsbe lock acquired */					;\
	membar #StoreStore

#endif /* UTSB_PHYS */

/*
 * Atomically write TSBE at virtual address tsbep.
 *
 * tsbep = TSBE va (ro)
 * tte = TSBE TTE (ro)
 * tagtarget = TSBE tag (ro)
 * %asi = ASI to use for TSB access
 */

#if defined(UTSB_PHYS)

#define	TSB_INSERT_UNLOCK_ENTRY(tsbep, tte, tagtarget, tmp1)		\
	add	tsbep, TSBE_TTE, tmp1					;\
	stxa	tte, [tmp1]ASI_MEM		/* write tte data */	;\
	membar #StoreStore						;\
	add	tsbep, TSBE_TAG, tmp1					;\
	stxa	tagtarget, [tmp1]ASI_MEM	/* write tte tag & unlock */

#else /* UTSB_PHYS */

#define	TSB_INSERT_UNLOCK_ENTRY(tsbep, tte, tagtarget,tmp1)		\
	stxa	tte, [tsbep + TSBE_TTE]%asi	/* write tte data */	;\
	membar #StoreStore						;\
	stxa	tagtarget, [tsbep + TSBE_TAG]%asi /* write tte tag & unlock */

#endif /* UTSB_PHYS */

/*
 * Load an entry into the TSB at TL > 0.
 *
 * tsbep = pointer to the TSBE to load as va (ro)
 * tte = value of the TTE retrieved and loaded (wo)
 * tagtarget = tag target register.  To get TSBE tag to load,
 *   we need to mask off the context and leave only the va (clobbered)
 * ttepa = pointer to the TTE to retrieve/load as pa (ro)
 * tmp1, tmp2 = scratch registers
 * label = label to jump to if we fail to lock the tsb entry
 * %asi = ASI to use for TSB access
 */

#if defined(UTSB_PHYS)

#define	TSB_UPDATE_TL(tsbep, tte, tagtarget, ttepa, tmp1, tmp2, label) \
	TSB_LOCK_ENTRY(tsbep, tmp1, tmp2, label)			;\
	/*								;\
	 * I don't need to update the TSB then check for the valid tte.	;\
	 * TSB invalidate will spin till the entry is unlocked.	Note,	;\
	 * we always invalidate the hash table before we unload the TSB.;\
	 */								;\
	sllx	tagtarget, TTARGET_VA_SHIFT, tagtarget			;\
	ldxa	[ttepa]ASI_MEM, tte					;\
	srlx	tagtarget, TTARGET_VA_SHIFT, tagtarget			;\
	sethi	%hi(TSBTAG_INVALID), tmp2				;\
	add	tsbep, TSBE_TAG, tmp1					;\
	brgez,a,pn tte, label						;\
	 sta	tmp2, [tmp1]ASI_MEM			/* unlock */	;\
	TSB_INSERT_UNLOCK_ENTRY(tsbep, tte, tagtarget, tmp1)		;\
label:

#else /* UTSB_PHYS */

#define	TSB_UPDATE_TL(tsbep, tte, tagtarget, ttepa, tmp1, tmp2, label) \
	TSB_LOCK_ENTRY(tsbep, tmp1, tmp2, label)			;\
	/*								;\
	 * I don't need to update the TSB then check for the valid tte.	;\
	 * TSB invalidate will spin till the entry is unlocked.	Note,	;\
	 * we always invalidate the hash table before we unload the TSB.;\
	 */								;\
	sllx	tagtarget, TTARGET_VA_SHIFT, tagtarget			;\
	ldxa	[ttepa]ASI_MEM, tte					;\
	srlx	tagtarget, TTARGET_VA_SHIFT, tagtarget			;\
	sethi	%hi(TSBTAG_INVALID), tmp2				;\
	brgez,a,pn tte, label						;\
	 sta	tmp2, [tsbep + TSBE_TAG]%asi		/* unlock */	;\
	TSB_INSERT_UNLOCK_ENTRY(tsbep, tte, tagtarget, tmp1)		;\
label:

#endif /* UTSB_PHYS */

/*
 * Load a 32M/256M Panther TSB entry into the TSB at TL > 0,
 *   for ITLB synthesis.
 *
 * tsbep = pointer to the TSBE to load as va (ro)
 * tte = 4M pfn offset (in), value of the TTE retrieved and loaded (out)
 *   with exec_perm turned off and exec_synth turned on
 * tagtarget = tag target register.  To get TSBE tag to load,
 *   we need to mask off the context and leave only the va (clobbered)
 * ttepa = pointer to the TTE to retrieve/load as pa (ro)
 * tmp1, tmp2 = scratch registers
 * label = label to use for branch (text)
 * %asi = ASI to use for TSB access
 */

#define	TSB_UPDATE_TL_PN(tsbep, tte, tagtarget, ttepa, tmp1, tmp2, label) \
	TSB_LOCK_ENTRY(tsbep, tmp1, tmp2, label)			;\
	/*								;\
	 * I don't need to update the TSB then check for the valid tte.	;\
	 * TSB invalidate will spin till the entry is unlocked.	Note,	;\
	 * we always invalidate the hash table before we unload the TSB.;\
	 * Or in 4M pfn offset to TTE and set the exec_perm bit to 0	;\
	 * and exec_synth bit to 1.					;\
	 */								;\
	sllx	tagtarget, TTARGET_VA_SHIFT, tagtarget			;\
	mov	tte, tmp1						;\
	ldxa	[ttepa]ASI_MEM, tte					;\
	srlx	tagtarget, TTARGET_VA_SHIFT, tagtarget			;\
	sethi	%hi(TSBTAG_INVALID), tmp2				;\
	brgez,a,pn tte, label						;\
	 sta	tmp2, [tsbep + TSBE_TAG]%asi		/* unlock */	;\
	or	tte, tmp1, tte						;\
	andn	tte, TTE_EXECPRM_INT, tte				;\
	or	tte, TTE_E_SYNTH_INT, tte				;\
	TSB_INSERT_UNLOCK_ENTRY(tsbep, tte, tagtarget, tmp1)		;\
label:

/*
 * Build a 4M pfn offset for a Panther 32M/256M page, for ITLB synthesis.
 *
 * tte = value of the TTE, used to get tte_size bits (ro)
 * tagaccess = tag access register, used to get 4M pfn bits (ro)
 * pfn = 4M pfn bits shifted to offset for tte (out)
 * tmp1 = scratch register
 * label = label to use for branch (text)
 */

#define	GET_4M_PFN_OFF(tte, tagaccess, pfn, tmp, label)			\
	/*								;\
	 * Get 4M bits from tagaccess for 32M, 256M pagesizes.		;\
	 * Return them, shifted, in pfn.				;\
	 */								;\
	srlx	tagaccess, MMU_PAGESHIFT4M, tagaccess			;\
	srlx	tte, TTE_SZ_SHFT, tmp		/* isolate the */	;\
	andcc	tmp, TTE_SZ_BITS, %g0		/* tte_size bits */	;\
	bz,a,pt %icc, label/**/f		/* if 0, is */		;\
	  and	tagaccess, 0x7, tagaccess	/* 32M page size */	;\
	and	tagaccess, 0x3f, tagaccess /* else 256M page size */	;\
label:									;\
	sllx	tagaccess, MMU_PAGESHIFT4M, pfn

/*
 * Add 4M TTE size code to a tte for a Panther 32M/256M page,
 * for ITLB synthesis.
 *
 * tte = value of the TTE, used to get tte_size bits (rw)
 * tmp1 = scratch register
 */

#define	SET_TTE4M_PN(tte, tmp)						\
	/*								;\
	 * Set 4M pagesize tte bits. 					;\
	 */								;\
	set	TTE4M, tmp						;\
	sllx	tmp, TTE_SZ_SHFT, tmp					;\
	or	tte, tmp, tte

/*
 * Load an entry into the TSB at TL=0.
 *
 * tsbep = pointer to the TSBE to load as va (ro)
 * tteva = pointer to the TTE to load as va (ro)
 * tagtarget = TSBE tag to load (which contains no context), synthesized
 * to match va of MMU tag target register only (ro)
 * tmp1, tmp2 = scratch registers (clobbered)
 * label = label to use for branches (text)
 * %asi = ASI to use for TSB access
 */

#if defined(UTSB_PHYS)

#define	TSB_UPDATE(tsbep, tteva, tagtarget, tmp1, tmp2, label)		\
	/* can't rd tteva after locking tsb because it can tlb miss */	;\
	ldx	[tteva], tteva			/* load tte */		;\
	TSB_LOCK_ENTRY(tsbep, tmp1, tmp2, label)			;\
	sethi	%hi(TSBTAG_INVALID), tmp2				;\
	add	tsbep, TSBE_TAG, tmp1					;\
	brgez,a,pn tteva, label						;\
	 sta	tmp2, [tmp1]ASI_MEM			/* unlock */	;\
	TSB_INSERT_UNLOCK_ENTRY(tsbep, tteva, tagtarget, tmp1)		;\
label:

#else /* UTSB_PHYS */

#define	TSB_UPDATE(tsbep, tteva, tagtarget, tmp1, tmp2, label)		\
	/* can't rd tteva after locking tsb because it can tlb miss */	;\
	ldx	[tteva], tteva			/* load tte */		;\
	TSB_LOCK_ENTRY(tsbep, tmp1, tmp2, label)			;\
	sethi	%hi(TSBTAG_INVALID), tmp2				;\
	brgez,a,pn tteva, label						;\
	 sta	tmp2, [tsbep + TSBE_TAG]%asi		/* unlock */	;\
	TSB_INSERT_UNLOCK_ENTRY(tsbep, tteva, tagtarget, tmp1)		;\
label:

#endif /* UTSB_PHYS */

/*
 * Invalidate a TSB entry in the TSB.
 *
 * NOTE: TSBE_TAG is assumed to be zero.  There is a compile time check
 *	 about this earlier to ensure this is true.  Thus when we are
 *	 directly referencing tsbep below, we are referencing the tte_tag
 *	 field of the TSBE.  If this  offset ever changes, the code below
 *	 will need to be modified.
 *
 * tsbep = pointer to TSBE as va (ro)
 * tag = invalidation is done if this matches the TSBE tag (ro)
 * tmp1 - tmp3 = scratch registers (clobbered)
 * label = label name to use for branches (text)
 * %asi = ASI to use for TSB access
 */

#if defined(UTSB_PHYS)

#define	TSB_INVALIDATE(tsbep, tag, tmp1, tmp2, tmp3, label)		\
	lda	[tsbep]ASI_MEM, tmp1	/* tmp1 = tsbe tag */		;\
	sethi	%hi(TSBTAG_LOCKED), tmp2				;\
label/**/1:								;\
	cmp	tmp1, tmp2		/* see if tsbe is locked, if */	;\
	be,a,pn	%icc, label/**/1	/* so, loop until unlocked */	;\
	  lda	[tsbep]ASI_MEM, tmp1	/* reloading value each time */	;\
	ldxa	[tsbep]ASI_MEM, tmp3	/* tmp3 = tsbe tag */		;\
	cmp	tag, tmp3		/* compare tags */		;\
	bne,pt	%xcc, label/**/2	/* if different, do nothing */	;\
	  sethi	%hi(TSBTAG_INVALID), tmp3				;\
	casa	[tsbep]ASI_MEM, tmp1, tmp3 /* try to set tag invalid */	;\
	cmp	tmp1, tmp3		/* if not successful */		;\
	bne,a,pn %icc, label/**/1	/* start over from the top */	;\
	  lda	[tsbep]ASI_MEM, tmp1	/* reloading tsbe tag */	;\
label/**/2:

#else /* UTSB_PHYS */

#define	TSB_INVALIDATE(tsbep, tag, tmp1, tmp2, tmp3, label)		\
	lda	[tsbep]%asi, tmp1	/* tmp1 = tsbe tag */		;\
	sethi	%hi(TSBTAG_LOCKED), tmp2				;\
label/**/1:								;\
	cmp	tmp1, tmp2		/* see if tsbe is locked, if */	;\
	be,a,pn	%icc, label/**/1	/* so, loop until unlocked */	;\
	  lda	[tsbep]%asi, tmp1	/* reloading value each time */	;\
	ldxa	[tsbep]%asi, tmp3	/* tmp3 = tsbe tag */		;\
	cmp	tag, tmp3		/* compare tags */		;\
	bne,pt	%xcc, label/**/2	/* if different, do nothing */	;\
	  sethi	%hi(TSBTAG_INVALID), tmp3				;\
	casa	[tsbep]%asi, tmp1, tmp3	/* try to set tag invalid */	;\
	cmp	tmp1, tmp3		/* if not successful */		;\
	bne,a,pn %icc, label/**/1	/* start over from the top */	;\
	  lda	[tsbep]%asi, tmp1	/* reloading tsbe tag */	;\
label/**/2:

#endif /* UTSB_PHYS */

#if TSB_SOFTSZ_MASK < TSB_SZ_MASK
#error	- TSB_SOFTSZ_MASK too small
#endif


/*
 * An implementation of setx which will be hot patched at run time.
 * since it is being hot patched, there is no value passed in.
 * Thus, essentially we are implementing
 *	setx value, tmp, dest
 * where value is RUNTIME_PATCH (aka 0) in this case.
 */
#define	RUNTIME_PATCH_SETX(dest, tmp)					\
	sethi	%hh(RUNTIME_PATCH), tmp					;\
	sethi	%lm(RUNTIME_PATCH), dest				;\
	or	tmp, %hm(RUNTIME_PATCH), tmp				;\
	or	dest, %lo(RUNTIME_PATCH), dest				;\
	sllx	tmp, 32, tmp						;\
	nop				/* for perf reasons */		;\
	or	tmp, dest, dest		/* contents of patched value */

#endif /* lint */


#if defined (lint)

/*
 * sfmmu related subroutines
 */
uint_t
sfmmu_disable_intrs()
{ return(0); }

/* ARGSUSED */
void
sfmmu_enable_intrs(uint_t pstate_save)
{}

/* ARGSUSED */
int
sfmmu_alloc_ctx(sfmmu_t *sfmmup, int allocflag, struct cpu *cp, int shflag)
{ return(0); }

/*
 * Use cas, if tte has changed underneath us then reread and try again.
 * In the case of a retry, it will update sttep with the new original.
 */
/* ARGSUSED */
int
sfmmu_modifytte(tte_t *sttep, tte_t *stmodttep, tte_t *dttep)
{ return(0); }

/*
 * Use cas, if tte has changed underneath us then return 1, else return 0
 */
/* ARGSUSED */
int
sfmmu_modifytte_try(tte_t *sttep, tte_t *stmodttep, tte_t *dttep)
{ return(0); }

/* ARGSUSED */
void
sfmmu_copytte(tte_t *sttep, tte_t *dttep)
{}

/*ARGSUSED*/
struct tsbe *
sfmmu_get_tsbe(uint64_t tsbeptr, caddr_t vaddr, int vpshift, int tsb_szc)
{ return(0); }

/*ARGSUSED*/
uint64_t
sfmmu_make_tsbtag(caddr_t va)
{ return(0); }

#else	/* lint */

	.seg	".data"
	.global	sfmmu_panic1
sfmmu_panic1:
	.asciz	"sfmmu_asm: interrupts already disabled"

	.global	sfmmu_panic3
sfmmu_panic3:
	.asciz	"sfmmu_asm: sfmmu_vatopfn called for user"

	.global	sfmmu_panic4
sfmmu_panic4:
	.asciz	"sfmmu_asm: 4M tsb pointer mis-match"

	.global	sfmmu_panic5
sfmmu_panic5:
	.asciz	"sfmmu_asm: no unlocked TTEs in TLB 0"

	.global	sfmmu_panic6
sfmmu_panic6:
	.asciz	"sfmmu_asm: interrupts not disabled"

	.global	sfmmu_panic7
sfmmu_panic7:
	.asciz	"sfmmu_asm: kernel as"

	.global	sfmmu_panic8
sfmmu_panic8:
	.asciz	"sfmmu_asm: gnum is zero"

	.global	sfmmu_panic9
sfmmu_panic9:
	.asciz	"sfmmu_asm: cnum is greater than MAX_SFMMU_CTX_VAL"

	.global	sfmmu_panic10
sfmmu_panic10:
	.asciz	"sfmmu_asm: valid SCD with no 3rd scd TSB"

	.global	sfmmu_panic11
sfmmu_panic11:
	.asciz	"sfmmu_asm: ktsb_phys must not be 0 on a sun4v platform"

        ENTRY(sfmmu_disable_intrs)
        rdpr    %pstate, %o0
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o0, sfmmu_di_l0, %g1)
#endif /* DEBUG */
        retl
          wrpr   %o0, PSTATE_IE, %pstate
        SET_SIZE(sfmmu_disable_intrs)

	ENTRY(sfmmu_enable_intrs)
        retl
          wrpr    %g0, %o0, %pstate
        SET_SIZE(sfmmu_enable_intrs)

/*
 * This routine is called both by resume() and sfmmu_get_ctx() to
 * allocate a new context for the process on a MMU.
 * if allocflag == 1, then alloc ctx when HAT mmu cnum == INVALID .
 * if allocflag == 0, then do not alloc ctx if HAT mmu cnum == INVALID, which
 * is the case when sfmmu_alloc_ctx is called from resume().
 *
 * The caller must disable interrupts before entering this routine.
 * To reduce ctx switch overhead, the code contains both 'fast path' and
 * 'slow path' code. The fast path code covers the common case where only
 * a quick check is needed and the real ctx allocation is not required.
 * It can be done without holding the per-process (PP) lock.
 * The 'slow path' code must be protected by the PP Lock and performs ctx
 * allocation.
 * Hardware context register and HAT mmu cnum are updated accordingly.
 *
 * %o0 - sfmmup
 * %o1 - allocflag
 * %o2 - CPU
 * %o3 - sfmmu private/shared flag
 *
 * ret - 0: no ctx is allocated
 *       1: a ctx is allocated
 */
        ENTRY_NP(sfmmu_alloc_ctx)

#ifdef DEBUG
	sethi   %hi(ksfmmup), %g1
	ldx     [%g1 + %lo(ksfmmup)], %g1
	cmp     %g1, %o0
	bne,pt   %xcc, 0f
	  nop

	sethi   %hi(panicstr), %g1		! if kernel as, panic
        ldx     [%g1 + %lo(panicstr)], %g1
        tst     %g1
        bnz,pn  %icc, 7f
          nop

	sethi	%hi(sfmmu_panic7), %o0
	call	panic
	  or	%o0, %lo(sfmmu_panic7), %o0

7:
	retl
	  mov	%g0, %o0			! %o0 = ret = 0

0:
	PANIC_IF_INTR_ENABLED_PSTR(sfmmu_ei_l1, %g1)
#endif /* DEBUG */

	mov	%o3, %g1			! save sfmmu pri/sh flag in %g1

	! load global mmu_ctxp info
	ldx	[%o2 + CPU_MMU_CTXP], %o3		! %o3 = mmu_ctx_t ptr

#ifdef sun4v
	/* During suspend on sun4v, context domains can be temporary removed */
	brz,a,pn       %o3, 0f
	  nop
#endif

        lduw	[%o2 + CPU_MMU_IDX], %g2		! %g2 = mmu index

	! load global mmu_ctxp gnum
	ldx	[%o3 + MMU_CTX_GNUM], %o4		! %o4 = mmu_ctxp->gnum

#ifdef DEBUG
	cmp	%o4, %g0		! mmu_ctxp->gnum should never be 0
	bne,pt	%xcc, 3f
	  nop

	sethi   %hi(panicstr), %g1	! test if panicstr is already set
        ldx     [%g1 + %lo(panicstr)], %g1
        tst     %g1
        bnz,pn  %icc, 1f
          nop

	sethi	%hi(sfmmu_panic8), %o0
	call	panic
	  or	%o0, %lo(sfmmu_panic8), %o0
1:
	retl
	  mov	%g0, %o0			! %o0 = ret = 0
3:
#endif

	! load HAT sfmmu_ctxs[mmuid] gnum, cnum

	sllx	%g2, SFMMU_MMU_CTX_SHIFT, %g2
	add	%o0, %g2, %g2		! %g2 = &sfmmu_ctxs[mmuid] - SFMMU_CTXS

	/*
	 * %g5 = sfmmu gnum returned
	 * %g6 = sfmmu cnum returned
	 * %g2 = &sfmmu_ctxs[mmuid] - SFMMU_CTXS
	 * %g4 = scratch
	 *
	 * Fast path code, do a quick check.
	 */
	SFMMU_MMUID_GNUM_CNUM(%g2, %g5, %g6, %g4)

	cmp	%g6, INVALID_CONTEXT		! hat cnum == INVALID ??
	bne,pt	%icc, 1f			! valid hat cnum, check gnum
	  nop

	! cnum == INVALID, check allocflag
	mov	%g0, %g4	! %g4 = ret = 0
	brz,pt  %o1, 8f		! allocflag == 0, skip ctx allocation, bail
	  mov	%g6, %o1

	! (invalid HAT cnum) && (allocflag == 1)
	ba,pt	%icc, 2f
	  nop
#ifdef sun4v
0:
	set	INVALID_CONTEXT, %o1
	membar	#LoadStore|#StoreStore
	ba,pt	%icc, 8f
	  mov   %g0, %g4                ! %g4 = ret = 0
#endif
1:
	! valid HAT cnum, check gnum
	cmp	%g5, %o4
	mov	1, %g4				!%g4 = ret = 1
	be,a,pt	%icc, 8f			! gnum unchanged, go to done
	  mov	%g6, %o1

2:
	/*
	 * Grab per process (PP) sfmmu_ctx_lock spinlock,
	 * followed by the 'slow path' code.
	 */
	ldstub	[%o0 + SFMMU_CTX_LOCK], %g3	! %g3 = per process (PP) lock
3:
	brz	%g3, 5f
	  nop
4:
	brnz,a,pt       %g3, 4b				! spin if lock is 1
	  ldub	[%o0 + SFMMU_CTX_LOCK], %g3
	ba	%xcc, 3b				! retry the lock
	  ldstub	[%o0 + SFMMU_CTX_LOCK], %g3    ! %g3 = PP lock

5:
	membar  #LoadLoad
	/*
	 * %g5 = sfmmu gnum returned
	 * %g6 = sfmmu cnum returned
	 * %g2 = &sfmmu_ctxs[mmuid] - SFMMU_CTXS
	 * %g4 = scratch
	 */
	SFMMU_MMUID_GNUM_CNUM(%g2, %g5, %g6, %g4)

	cmp	%g6, INVALID_CONTEXT		! hat cnum == INVALID ??
	bne,pt	%icc, 1f			! valid hat cnum, check gnum
	  nop

	! cnum == INVALID, check allocflag
	mov	%g0, %g4	! %g4 = ret = 0
	brz,pt	%o1, 2f		! allocflag == 0, called from resume, set hw
	  mov	%g6, %o1

	! (invalid HAT cnum) && (allocflag == 1)
	ba,pt	%icc, 6f
	  nop
1:
	! valid HAT cnum, check gnum
	cmp	%g5, %o4
	mov	1, %g4				! %g4 = ret  = 1
	be,a,pt	%icc, 2f			! gnum unchanged, go to done
	  mov	%g6, %o1

	ba,pt	%icc, 6f
	  nop
2:
	membar  #LoadStore|#StoreStore
	ba,pt %icc, 8f
	  clrb  [%o0 + SFMMU_CTX_LOCK]
6:
	/*
	 * We get here if we do not have a valid context, or
	 * the HAT gnum does not match global gnum. We hold
	 * sfmmu_ctx_lock spinlock. Allocate that context.
	 *
	 * %o3 = mmu_ctxp
	 */
	add	%o3, MMU_CTX_CNUM, %g3
	ld	[%o3 + MMU_CTX_NCTXS], %g4

	/*
         * %g2 = &sfmmu_ctx_t[mmuid] - SFMMU_CTXS;
         * %g3 = mmu cnum address
	 * %g4 = mmu nctxs
	 *
	 * %o0 = sfmmup
	 * %o1 = mmu current cnum value (used as new cnum)
	 * %o4 = mmu gnum
	 *
	 * %o5 = scratch
	 */
	ld	[%g3], %o1
0:
	cmp	%o1, %g4
	bl,a,pt %icc, 1f
	  add	%o1, 1, %o5		! %o5 = mmu_ctxp->cnum + 1

	/*
	 * cnum reachs max, bail, so wrap around can be performed later.
	 */
	set	INVALID_CONTEXT, %o1
	mov	%g0, %g4		! %g4 = ret = 0

	membar  #LoadStore|#StoreStore
	ba,pt	%icc, 8f
	  clrb	[%o0 + SFMMU_CTX_LOCK]
1:
	! %g3 = addr of mmu_ctxp->cnum
	! %o5 = mmu_ctxp->cnum + 1
	cas	[%g3], %o1, %o5
	cmp	%o1, %o5
	bne,a,pn %xcc, 0b	! cas failed
	  ld	[%g3], %o1

#ifdef DEBUG
        set	MAX_SFMMU_CTX_VAL, %o5
	cmp	%o1, %o5
	ble,pt %icc, 2f
	  nop

	sethi	%hi(sfmmu_panic9), %o0
	call	panic
	  or	%o0, %lo(sfmmu_panic9), %o0
2:
#endif
	! update hat gnum and cnum
	sllx	%o4, SFMMU_MMU_GNUM_RSHIFT, %o4
	or	%o4, %o1, %o4
	stx	%o4, [%g2 + SFMMU_CTXS]

	membar  #LoadStore|#StoreStore
	clrb	[%o0 + SFMMU_CTX_LOCK]

	mov	1, %g4			! %g4 = ret = 1
8:
	/*
	 * program the secondary context register
	 *
	 * %o1 = cnum
	 * %g1 = sfmmu private/shared flag (0:private,  1:shared)
	 */

	/*
	 * When we come here and context is invalid, we want to set both
	 * private and shared ctx regs to INVALID. In order to
	 * do so, we set the sfmmu priv/shared flag to 'private' regardless
	 * so that private ctx reg will be set to invalid.
	 * Note that on sun4v values written to private context register are
	 * automatically written to corresponding shared context register as
	 * well. On sun4u SET_SECCTX() will invalidate shared context register
	 * when it sets a private secondary context register.
	 */

	cmp	%o1, INVALID_CONTEXT
	be,a,pn	%icc, 9f
	  clr	%g1
9:

#ifdef	sun4u
	ldub	[%o0 + SFMMU_CEXT], %o2
	sll	%o2, CTXREG_EXT_SHIFT, %o2
	or	%o1, %o2, %o1
#endif /* sun4u */

	SET_SECCTX(%o1, %g1, %o4, %o5, alloc_ctx_lbl1)

        retl
          mov   %g4, %o0                        ! %o0 = ret

	SET_SIZE(sfmmu_alloc_ctx)

	ENTRY_NP(sfmmu_modifytte)
	ldx	[%o2], %g3			/* current */
	ldx	[%o0], %g1			/* original */
2:
	ldx	[%o1], %g2			/* modified */
	cmp	%g2, %g3			/* is modified = current? */
	be,a,pt	%xcc,1f				/* yes, don't write */
	stx	%g3, [%o0]			/* update new original */
	casx	[%o2], %g1, %g2
	cmp	%g1, %g2
	be,pt	%xcc, 1f			/* cas succeeded - return */
	  nop
	ldx	[%o2], %g3			/* new current */
	stx	%g3, [%o0]			/* save as new original */
	ba,pt	%xcc, 2b
	  mov	%g3, %g1
1:	retl
	membar	#StoreLoad
	SET_SIZE(sfmmu_modifytte)

	ENTRY_NP(sfmmu_modifytte_try)
	ldx	[%o1], %g2			/* modified */
	ldx	[%o2], %g3			/* current */
	ldx	[%o0], %g1			/* original */
	cmp	%g3, %g2			/* is modified = current? */
	be,a,pn %xcc,1f				/* yes, don't write */
	mov	0, %o1				/* as if cas failed. */

	casx	[%o2], %g1, %g2
	membar	#StoreLoad
	cmp	%g1, %g2
	movne	%xcc, -1, %o1			/* cas failed. */
	move	%xcc, 1, %o1			/* cas succeeded. */
1:
	stx	%g2, [%o0]			/* report "current" value */
	retl
	mov	%o1, %o0
	SET_SIZE(sfmmu_modifytte_try)

	ENTRY_NP(sfmmu_copytte)
	ldx	[%o0], %g1
	retl
	stx	%g1, [%o1]
	SET_SIZE(sfmmu_copytte)


	/*
	 * Calculate a TSB entry pointer for the given TSB, va, pagesize.
	 * %o0 = TSB base address (in), pointer to TSB entry (out)
	 * %o1 = vaddr (in)
	 * %o2 = vpshift (in)
	 * %o3 = tsb size code (in)
	 * %o4 = scratch register
	 */
	ENTRY_NP(sfmmu_get_tsbe)
	GET_TSBE_POINTER(%o2, %o0, %o1, %o3, %o4)
	retl
	nop
	SET_SIZE(sfmmu_get_tsbe)

	/*
	 * Return a TSB tag for the given va.
	 * %o0 = va (in/clobbered)
	 * %o0 = va shifted to be in tsb tag format (with no context) (out)
	 */
	ENTRY_NP(sfmmu_make_tsbtag)
	retl
	srln	%o0, TTARGET_VA_SHIFT, %o0
	SET_SIZE(sfmmu_make_tsbtag)

#endif /* lint */

/*
 * Other sfmmu primitives
 */


#if defined (lint)
void
sfmmu_patch_ktsb(void)
{
}

void
sfmmu_kpm_patch_tlbm(void)
{
}

void
sfmmu_kpm_patch_tsbm(void)
{
}

void
sfmmu_patch_shctx(void)
{
}

/* ARGSUSED */
void
sfmmu_load_tsbe(struct tsbe *tsbep, uint64_t vaddr, tte_t *ttep, int phys)
{
}

/* ARGSUSED */
void
sfmmu_unload_tsbe(struct tsbe *tsbep, uint64_t vaddr, int phys)
{
}

/* ARGSUSED */
void
sfmmu_kpm_load_tsb(caddr_t addr, tte_t *ttep, int vpshift)
{
}

/* ARGSUSED */
void
sfmmu_kpm_unload_tsb(caddr_t addr, int vpshift)
{
}

#else /* lint */

#define	I_SIZE		4

	ENTRY_NP(sfmmu_fix_ktlb_traptable)
	/*
	 * %o0 = start of patch area
	 * %o1 = size code of TSB to patch
	 * %o3 = scratch
	 */
	/* fix sll */
	ld	[%o0], %o3			/* get sll */
	sub	%o3, %o1, %o3			/* decrease shift by tsb szc */
	st	%o3, [%o0]			/* write sll */
	flush	%o0
	/* fix srl */
	add	%o0, I_SIZE, %o0		/* goto next instr. */
	ld	[%o0], %o3			/* get srl */
	sub	%o3, %o1, %o3			/* decrease shift by tsb szc */
	st	%o3, [%o0]			/* write srl */
	retl
	flush	%o0
	SET_SIZE(sfmmu_fix_ktlb_traptable)

	ENTRY_NP(sfmmu_fixup_ktsbbase)
	/*
	 * %o0 = start of patch area
	 * %o5 = kernel virtual or physical tsb base address
	 * %o2, %o3 are used as scratch registers.
	 */
	/* fixup sethi instruction */
	ld	[%o0], %o3
	srl	%o5, 10, %o2			! offset is bits 32:10
	or	%o3, %o2, %o3			! set imm22
	st	%o3, [%o0]
	/* fixup offset of lduw/ldx */
	add	%o0, I_SIZE, %o0		! next instr
	ld	[%o0], %o3
	and	%o5, 0x3ff, %o2			! set imm13 to bits 9:0
	or	%o3, %o2, %o3
	st	%o3, [%o0]
	retl
	flush	%o0
	SET_SIZE(sfmmu_fixup_ktsbbase)

	ENTRY_NP(sfmmu_fixup_setx)
	/*
	 * %o0 = start of patch area
	 * %o4 = 64 bit value to patch
	 * %o2, %o3 are used as scratch registers.
	 *
	 * Note: Assuming that all parts of the instructions which need to be
	 *	 patched correspond to RUNTIME_PATCH (aka 0)
	 *
	 * Note the implementation of setx which is being patched is as follows:
	 *
	 * sethi   %hh(RUNTIME_PATCH), tmp
	 * sethi   %lm(RUNTIME_PATCH), dest
	 * or      tmp, %hm(RUNTIME_PATCH), tmp
	 * or      dest, %lo(RUNTIME_PATCH), dest
	 * sllx    tmp, 32, tmp
	 * nop
	 * or      tmp, dest, dest
	 *
	 * which differs from the implementation in the
	 * "SPARC Architecture Manual"
	 */
	/* fixup sethi instruction */
	ld	[%o0], %o3
	srlx	%o4, 42, %o2			! bits [63:42]
	or	%o3, %o2, %o3			! set imm22
	st	%o3, [%o0]
	/* fixup sethi instruction */
	add	%o0, I_SIZE, %o0		! next instr
	ld	[%o0], %o3
	sllx	%o4, 32, %o2			! clear upper bits
	srlx	%o2, 42, %o2			! bits [31:10]
	or	%o3, %o2, %o3			! set imm22
	st	%o3, [%o0]
	/* fixup or instruction */
	add	%o0, I_SIZE, %o0		! next instr
	ld	[%o0], %o3
	srlx	%o4, 32, %o2			! bits [63:32]
	and	%o2, 0x3ff, %o2			! bits [41:32]
	or	%o3, %o2, %o3			! set imm
	st	%o3, [%o0]
	/* fixup or instruction */
	add	%o0, I_SIZE, %o0		! next instr
	ld	[%o0], %o3
	and	%o4, 0x3ff, %o2			! bits [9:0]
	or	%o3, %o2, %o3			! set imm
	st	%o3, [%o0]
	retl
	flush	%o0
	SET_SIZE(sfmmu_fixup_setx)

	ENTRY_NP(sfmmu_fixup_or)
	/*
	 * %o0 = start of patch area
	 * %o4 = 32 bit value to patch
	 * %o2, %o3 are used as scratch registers.
	 * Note: Assuming that all parts of the instructions which need to be
	 *	 patched correspond to RUNTIME_PATCH (aka 0)
	 */
	ld	[%o0], %o3
	and	%o4, 0x3ff, %o2			! bits [9:0]
	or	%o3, %o2, %o3			! set imm
	st	%o3, [%o0]
	retl
	flush	%o0
	SET_SIZE(sfmmu_fixup_or)

	ENTRY_NP(sfmmu_fixup_shiftx)
	/*
	 * %o0 = start of patch area
	 * %o4 = signed int immediate value to add to sllx/srlx imm field
	 * %o2, %o3 are used as scratch registers.
	 *
	 * sllx/srlx store the 6 bit immediate value in the lowest order bits
	 * so we do a simple add.  The caller must be careful to prevent
	 * overflow, which could easily occur if the initial value is nonzero!
	 */
	ld	[%o0], %o3			! %o3 = instruction to patch
	and	%o3, 0x3f, %o2			! %o2 = existing imm value
	add	%o2, %o4, %o2			! %o2 = new imm value
	andn	%o3, 0x3f, %o3			! clear old imm value
	and	%o2, 0x3f, %o2			! truncate new imm value
	or	%o3, %o2, %o3			! set new imm value
	st	%o3, [%o0]			! store updated instruction
	retl
	flush	%o0
	SET_SIZE(sfmmu_fixup_shiftx)

	ENTRY_NP(sfmmu_fixup_mmu_asi)
	/*
	 * Patch imm_asi of all ldda instructions in the MMU
	 * trap handlers.  We search MMU_PATCH_INSTR instructions
	 * starting from the itlb miss handler (trap 0x64).
	 * %o0 = address of tt[0,1]_itlbmiss
	 * %o1 = imm_asi to setup, shifted by appropriate offset.
	 * %o3 = number of instructions to search
	 * %o4 = reserved by caller: called from leaf routine
	 */
1:	ldsw	[%o0], %o2			! load instruction to %o2
	brgez,pt %o2, 2f
	  srl	%o2, 30, %o5
	btst	1, %o5				! test bit 30; skip if not set
	bz,pt	%icc, 2f
	  sllx	%o2, 39, %o5			! bit 24 -> bit 63
	srlx	%o5, 58, %o5			! isolate op3 part of opcode
	xor	%o5, 0x13, %o5			! 01 0011 binary == ldda
	brnz,pt	%o5, 2f				! skip if not a match
	  or	%o2, %o1, %o2			! or in imm_asi
	st	%o2, [%o0]			! write patched instruction
2:	dec	%o3
	brnz,a,pt %o3, 1b			! loop until we're done
	  add	%o0, I_SIZE, %o0
	retl
	flush	%o0
	SET_SIZE(sfmmu_fixup_mmu_asi)

	/*
	 * Patch immediate ASI used to access the TSB in the
	 * trap table.
	 * inputs: %o0 = value of ktsb_phys
	 */
	ENTRY_NP(sfmmu_patch_mmu_asi)
	mov	%o7, %o4			! save return pc in %o4
	mov	ASI_QUAD_LDD_PHYS, %o3		! set QUAD_LDD_PHYS by default

#ifdef sun4v

	/*
	 * Check ktsb_phys. It must be non-zero for sun4v, panic if not.
	 */

	brnz,pt %o0, do_patch
	nop

	sethi	%hi(sfmmu_panic11), %o0
	call	panic
	  or	%o0, %lo(sfmmu_panic11), %o0
do_patch:

#else /* sun4v */
	/*
	 * Some non-sun4v platforms deploy virtual ktsb (ktsb_phys==0).
	 * Note that ASI_NQUAD_LD is not defined/used for sun4v
	 */
	movrz	%o0, ASI_NQUAD_LD, %o3

#endif /* sun4v */

	sll	%o3, 5, %o1			! imm_asi offset
	mov	6, %o3				! number of instructions
	sethi	%hi(dktsb), %o0			! to search
	call	sfmmu_fixup_mmu_asi		! patch kdtlb miss
	  or	%o0, %lo(dktsb), %o0
	mov	6, %o3				! number of instructions
	sethi	%hi(dktsb4m), %o0		! to search
	call	sfmmu_fixup_mmu_asi		! patch kdtlb4m miss
	  or	%o0, %lo(dktsb4m), %o0
	mov	6, %o3				! number of instructions
	sethi	%hi(iktsb), %o0			! to search
	call	sfmmu_fixup_mmu_asi		! patch kitlb miss
	  or	%o0, %lo(iktsb), %o0
	mov	6, %o3				! number of instructions
	sethi	%hi(iktsb4m), %o0		! to search
	call	sfmmu_fixup_mmu_asi		! patch kitlb4m miss
	  or	%o0, %lo(iktsb4m), %o0
	mov	%o4, %o7			! retore return pc -- leaf
	retl
	nop
	SET_SIZE(sfmmu_patch_mmu_asi)


	ENTRY_NP(sfmmu_patch_ktsb)
	/*
	 * We need to fix iktsb, dktsb, et. al.
	 */
	save	%sp, -SA(MINFRAME), %sp
	set	ktsb_phys, %o1
	ld	[%o1], %o4
	set	ktsb_base, %o5
	set	ktsb4m_base, %l1
	brz,pt	%o4, 1f
	  nop
	set	ktsb_pbase, %o5
	set	ktsb4m_pbase, %l1
1:
	sethi	%hi(ktsb_szcode), %o1
	ld	[%o1 + %lo(ktsb_szcode)], %o1	/* %o1 = ktsb size code */

	sethi	%hi(iktsb), %o0
	call	sfmmu_fix_ktlb_traptable
	  or	%o0, %lo(iktsb), %o0

	sethi	%hi(dktsb), %o0
	call	sfmmu_fix_ktlb_traptable
	  or	%o0, %lo(dktsb), %o0

	sethi	%hi(ktsb4m_szcode), %o1
	ld	[%o1 + %lo(ktsb4m_szcode)], %o1	/* %o1 = ktsb4m size code */

	sethi	%hi(iktsb4m), %o0
	call	sfmmu_fix_ktlb_traptable
	  or	%o0, %lo(iktsb4m), %o0

	sethi	%hi(dktsb4m), %o0
	call	sfmmu_fix_ktlb_traptable
	  or	%o0, %lo(dktsb4m), %o0

#ifndef sun4v
	mov	ASI_N, %o2
	movrnz	%o4, ASI_MEM, %o2	! setup kernel 32bit ASI to patch
	mov	%o2, %o4		! sfmmu_fixup_or needs this in %o4
	sethi	%hi(tsb_kernel_patch_asi), %o0
	call	sfmmu_fixup_or
	  or	%o0, %lo(tsb_kernel_patch_asi), %o0
#endif /* !sun4v */

	ldx 	[%o5], %o4		! load ktsb base addr (VA or PA)

	sethi	%hi(dktsbbase), %o0
	call	sfmmu_fixup_setx	! patch value of ktsb base addr
	  or	%o0, %lo(dktsbbase), %o0

	sethi	%hi(iktsbbase), %o0
	call	sfmmu_fixup_setx	! patch value of ktsb base addr
	  or	%o0, %lo(iktsbbase), %o0

	sethi	%hi(sfmmu_kprot_patch_ktsb_base), %o0
	call	sfmmu_fixup_setx	! patch value of ktsb base addr
	  or	%o0, %lo(sfmmu_kprot_patch_ktsb_base), %o0

#ifdef sun4v
	sethi	%hi(sfmmu_dslow_patch_ktsb_base), %o0
	call	sfmmu_fixup_setx	! patch value of ktsb base addr
	  or	%o0, %lo(sfmmu_dslow_patch_ktsb_base), %o0
#endif /* sun4v */

	ldx 	[%l1], %o4		! load ktsb4m base addr (VA or PA)

	sethi	%hi(dktsb4mbase), %o0
	call	sfmmu_fixup_setx	! patch value of ktsb4m base addr
	  or	%o0, %lo(dktsb4mbase), %o0

	sethi	%hi(iktsb4mbase), %o0
	call	sfmmu_fixup_setx	! patch value of ktsb4m base addr
	  or	%o0, %lo(iktsb4mbase), %o0

	sethi	%hi(sfmmu_kprot_patch_ktsb4m_base), %o0
	call	sfmmu_fixup_setx	! patch value of ktsb4m base addr
	  or	%o0, %lo(sfmmu_kprot_patch_ktsb4m_base), %o0

#ifdef sun4v
	sethi	%hi(sfmmu_dslow_patch_ktsb4m_base), %o0
	call	sfmmu_fixup_setx	! patch value of ktsb4m base addr
	  or	%o0, %lo(sfmmu_dslow_patch_ktsb4m_base), %o0
#endif /* sun4v */

	set	ktsb_szcode, %o4
	ld	[%o4], %o4
	sethi	%hi(sfmmu_kprot_patch_ktsb_szcode), %o0
	call	sfmmu_fixup_or		! patch value of ktsb_szcode
	  or	%o0, %lo(sfmmu_kprot_patch_ktsb_szcode), %o0

#ifdef sun4v
	sethi	%hi(sfmmu_dslow_patch_ktsb_szcode), %o0
	call	sfmmu_fixup_or		! patch value of ktsb_szcode
	  or	%o0, %lo(sfmmu_dslow_patch_ktsb_szcode), %o0
#endif /* sun4v */

	set	ktsb4m_szcode, %o4
	ld	[%o4], %o4
	sethi	%hi(sfmmu_kprot_patch_ktsb4m_szcode), %o0
	call	sfmmu_fixup_or		! patch value of ktsb4m_szcode
	  or	%o0, %lo(sfmmu_kprot_patch_ktsb4m_szcode), %o0

#ifdef sun4v
	sethi	%hi(sfmmu_dslow_patch_ktsb4m_szcode), %o0
	call	sfmmu_fixup_or		! patch value of ktsb4m_szcode
	  or	%o0, %lo(sfmmu_dslow_patch_ktsb4m_szcode), %o0
#endif /* sun4v */

	ret
	restore
	SET_SIZE(sfmmu_patch_ktsb)

	ENTRY_NP(sfmmu_kpm_patch_tlbm)
	/*
	 * Fixup trap handlers in common segkpm case.  This is reserved
	 * for future use should kpm TSB be changed to be other than the
	 * kernel TSB.
	 */
	retl
	nop
	SET_SIZE(sfmmu_kpm_patch_tlbm)

	ENTRY_NP(sfmmu_kpm_patch_tsbm)
	/*
	 * nop the branch to sfmmu_kpm_dtsb_miss_small
	 * in the case where we are using large pages for
	 * seg_kpm (and hence must probe the second TSB for
	 * seg_kpm VAs)
	 */
	set	dktsb4m_kpmcheck_small, %o0
	MAKE_NOP_INSTR(%o1)
	st	%o1, [%o0]
	flush	%o0
	retl
	nop
	SET_SIZE(sfmmu_kpm_patch_tsbm)

	ENTRY_NP(sfmmu_patch_utsb)
#ifdef UTSB_PHYS
	retl
	nop
#else /* UTSB_PHYS */
	/*
	 * We need to hot patch utsb_vabase and utsb4m_vabase
	 */
	save	%sp, -SA(MINFRAME), %sp

	/* patch value of utsb_vabase */
	set	utsb_vabase, %o1
	ldx	[%o1], %o4
	sethi	%hi(sfmmu_uprot_get_1st_tsbe_ptr), %o0
	call	sfmmu_fixup_setx
	  or	%o0, %lo(sfmmu_uprot_get_1st_tsbe_ptr), %o0
	sethi	%hi(sfmmu_uitlb_get_1st_tsbe_ptr), %o0
	call	sfmmu_fixup_setx
	  or	%o0, %lo(sfmmu_uitlb_get_1st_tsbe_ptr), %o0
	sethi	%hi(sfmmu_udtlb_get_1st_tsbe_ptr), %o0
	call	sfmmu_fixup_setx
	  or	%o0, %lo(sfmmu_udtlb_get_1st_tsbe_ptr), %o0

	/* patch value of utsb4m_vabase */
	set	utsb4m_vabase, %o1
	ldx	[%o1], %o4
	sethi	%hi(sfmmu_uprot_get_2nd_tsb_base), %o0
	call	sfmmu_fixup_setx
	  or	%o0, %lo(sfmmu_uprot_get_2nd_tsb_base), %o0
	sethi	%hi(sfmmu_uitlb_get_2nd_tsb_base), %o0
	call	sfmmu_fixup_setx
	  or	%o0, %lo(sfmmu_uitlb_get_2nd_tsb_base), %o0
	sethi	%hi(sfmmu_udtlb_get_2nd_tsb_base), %o0
	call	sfmmu_fixup_setx
	  or	%o0, %lo(sfmmu_udtlb_get_2nd_tsb_base), %o0

	/*
	 * Patch TSB base register masks and shifts if needed.
	 * By default the TSB base register contents are set up for 4M slab.
	 * If we're using a smaller slab size and reserved VA range we need
	 * to patch up those values here.
	 */
	set	tsb_slab_shift, %o1
	set	MMU_PAGESHIFT4M, %o4
	lduw	[%o1], %o3
	subcc	%o4, %o3, %o4
	bz,pt	%icc, 1f
	  /* delay slot safe */

	/* patch reserved VA range size if needed. */
	sethi	%hi(sfmmu_tsb_1st_resv_offset), %o0
	call	sfmmu_fixup_shiftx
	  or	%o0, %lo(sfmmu_tsb_1st_resv_offset), %o0
	call	sfmmu_fixup_shiftx
	  add	%o0, I_SIZE, %o0
	sethi	%hi(sfmmu_tsb_2nd_resv_offset), %o0
	call	sfmmu_fixup_shiftx
	  or	%o0, %lo(sfmmu_tsb_2nd_resv_offset), %o0
	call	sfmmu_fixup_shiftx
	  add	%o0, I_SIZE, %o0
1:
	/* patch TSBREG_VAMASK used to set up TSB base register */
	set	tsb_slab_mask, %o1
	ldx	[%o1], %o4
	sethi	%hi(sfmmu_tsb_1st_tsbreg_vamask), %o0
	call	sfmmu_fixup_or
	  or	%o0, %lo(sfmmu_tsb_1st_tsbreg_vamask), %o0
	sethi	%hi(sfmmu_tsb_2nd_tsbreg_vamask), %o0
	call	sfmmu_fixup_or
	  or	%o0, %lo(sfmmu_tsb_2nd_tsbreg_vamask), %o0

	ret
	restore
#endif /* UTSB_PHYS */
	SET_SIZE(sfmmu_patch_utsb)

	ENTRY_NP(sfmmu_patch_shctx)
#ifdef sun4u
	retl
	  nop
#else /* sun4u */
	set	sfmmu_shctx_cpu_mondo_patch, %o0
	MAKE_JMP_INSTR(5, %o1, %o2)	! jmp       %g5
	st	%o1, [%o0]
	flush	%o0
	MAKE_NOP_INSTR(%o1)
	add	%o0, I_SIZE, %o0	! next instr
	st	%o1, [%o0]
	flush	%o0

	set	sfmmu_shctx_user_rtt_patch, %o0
	st      %o1, [%o0]		! nop 1st instruction
	flush	%o0
	add     %o0, I_SIZE, %o0
	st      %o1, [%o0]		! nop 2nd instruction
	flush	%o0
	add     %o0, I_SIZE, %o0
	st      %o1, [%o0]		! nop 3rd instruction
	flush	%o0
	add     %o0, I_SIZE, %o0
	st      %o1, [%o0]		! nop 4th instruction
	flush	%o0
	add     %o0, I_SIZE, %o0
	st      %o1, [%o0]		! nop 5th instruction
	flush	%o0
	add     %o0, I_SIZE, %o0
	st      %o1, [%o0]		! nop 6th instruction
	retl
	flush	%o0
#endif /* sun4u */
	SET_SIZE(sfmmu_patch_shctx)

	/*
	 * Routine that loads an entry into a tsb using virtual addresses.
	 * Locking is required since all cpus can use the same TSB.
	 * Note that it is no longer required to have a valid context
	 * when calling this function.
	 */
	ENTRY_NP(sfmmu_load_tsbe)
	/*
	 * %o0 = pointer to tsbe to load
	 * %o1 = tsb tag
	 * %o2 = virtual pointer to TTE
	 * %o3 = 1 if physical address in %o0 else 0
	 */
	rdpr	%pstate, %o5
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o5, sfmmu_di_l2, %g1)
#endif /* DEBUG */

	wrpr	%o5, PSTATE_IE, %pstate		/* disable interrupts */

	SETUP_TSB_ASI(%o3, %g3)
	TSB_UPDATE(%o0, %o2, %o1, %g1, %g2, locked_tsb_l8)

	wrpr	%g0, %o5, %pstate		/* enable interrupts */

	retl
	membar	#StoreStore|#StoreLoad
	SET_SIZE(sfmmu_load_tsbe)

	/*
	 * Flush TSB of a given entry if the tag matches.
	 */
	ENTRY(sfmmu_unload_tsbe)
	/*
	 * %o0 = pointer to tsbe to be flushed
	 * %o1 = tag to match
	 * %o2 = 1 if physical address in %o0 else 0
	 */
	SETUP_TSB_ASI(%o2, %g1)
	TSB_INVALIDATE(%o0, %o1, %g1, %o2, %o3, unload_tsbe)
	retl
	membar	#StoreStore|#StoreLoad
	SET_SIZE(sfmmu_unload_tsbe)

	/*
	 * Routine that loads a TTE into the kpm TSB from C code.
	 * Locking is required since kpm TSB is shared among all CPUs.
	 */
	ENTRY_NP(sfmmu_kpm_load_tsb)
	/*
	 * %o0 = vaddr
	 * %o1 = ttep
	 * %o2 = virtpg to TSB index shift (e.g. TTE pagesize shift)
	 */
	rdpr	%pstate, %o5			! %o5 = saved pstate
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o5, sfmmu_di_l3, %g1)
#endif /* DEBUG */
	wrpr	%o5, PSTATE_IE, %pstate		! disable interrupts

#ifndef sun4v
	sethi	%hi(ktsb_phys), %o4
	mov	ASI_N, %o3
	ld	[%o4 + %lo(ktsb_phys)], %o4
	movrnz	%o4, ASI_MEM, %o3
	mov	%o3, %asi
#endif /* !sun4v */
	mov	%o0, %g1			! %g1 = vaddr

	/* GET_KPM_TSBE_POINTER(vpshift, tsbp, vaddr (clobbers), tmp1, tmp2) */
	GET_KPM_TSBE_POINTER(%o2, %g2, %g1, %o3, %o4)
	/* %g2 = tsbep, %g1 clobbered */

	srlx	%o0, TTARGET_VA_SHIFT, %g1;	! %g1 = tag target
	/* TSB_UPDATE(tsbep, tteva, tagtarget, tmp1, tmp2, label) */
	TSB_UPDATE(%g2, %o1, %g1, %o3, %o4, locked_tsb_l9)

	wrpr	%g0, %o5, %pstate		! enable interrupts
	retl
	  membar #StoreStore|#StoreLoad
	SET_SIZE(sfmmu_kpm_load_tsb)

	/*
	 * Routine that shoots down a TTE in the kpm TSB or in the
	 * kernel TSB depending on virtpg. Locking is required since
	 * kpm/kernel TSB is shared among all CPUs.
	 */
	ENTRY_NP(sfmmu_kpm_unload_tsb)
	/*
	 * %o0 = vaddr
	 * %o1 = virtpg to TSB index shift (e.g. TTE page shift)
	 */
#ifndef sun4v
	sethi	%hi(ktsb_phys), %o4
	mov	ASI_N, %o3
	ld	[%o4 + %lo(ktsb_phys)], %o4
	movrnz	%o4, ASI_MEM, %o3
	mov	%o3, %asi
#endif /* !sun4v */
	mov	%o0, %g1			! %g1 = vaddr

	/* GET_KPM_TSBE_POINTER(vpshift, tsbp, vaddr (clobbers), tmp1, tmp2) */
	GET_KPM_TSBE_POINTER(%o1, %g2, %g1, %o3, %o4)
	/* %g2 = tsbep, %g1 clobbered */

	srlx	%o0, TTARGET_VA_SHIFT, %g1;	! %g1 = tag target
	/* TSB_INVALIDATE(tsbep, tag, tmp1, tmp2, tmp3, label) */
	TSB_INVALIDATE(%g2, %g1, %o3, %o4, %o1, kpm_tsbinval)

	retl
	  membar	#StoreStore|#StoreLoad
	SET_SIZE(sfmmu_kpm_unload_tsb)

#endif /* lint */


#if defined (lint)

/*ARGSUSED*/
pfn_t
sfmmu_ttetopfn(tte_t *tte, caddr_t vaddr)
{ return(0); }

#else /* lint */

	ENTRY_NP(sfmmu_ttetopfn)
	ldx	[%o0], %g1			/* read tte */
	TTETOPFN(%g1, %o1, sfmmu_ttetopfn_l1, %g2, %g3, %g4)
	/*
	 * g1 = pfn
	 */
	retl
	mov	%g1, %o0
	SET_SIZE(sfmmu_ttetopfn)

#endif /* !lint */

/*
 * These macros are used to update global sfmmu hme hash statistics
 * in perf critical paths. It is only enabled in debug kernels or
 * if SFMMU_STAT_GATHER is defined
 */
#if defined(DEBUG) || defined(SFMMU_STAT_GATHER)
#define	HAT_HSEARCH_DBSTAT(hatid, tsbarea, tmp1, tmp2)			\
	ldn	[tsbarea + TSBMISS_KHATID], tmp1			;\
	mov	HATSTAT_KHASH_SEARCH, tmp2				;\
	cmp	tmp1, hatid						;\
	movne	%ncc, HATSTAT_UHASH_SEARCH, tmp2			;\
	set	sfmmu_global_stat, tmp1					;\
	add	tmp1, tmp2, tmp1					;\
	ld	[tmp1], tmp2						;\
	inc	tmp2							;\
	st	tmp2, [tmp1]

#define	HAT_HLINK_DBSTAT(hatid, tsbarea, tmp1, tmp2)			\
	ldn	[tsbarea + TSBMISS_KHATID], tmp1			;\
	mov	HATSTAT_KHASH_LINKS, tmp2				;\
	cmp	tmp1, hatid						;\
	movne	%ncc, HATSTAT_UHASH_LINKS, tmp2				;\
	set	sfmmu_global_stat, tmp1					;\
	add	tmp1, tmp2, tmp1					;\
	ld	[tmp1], tmp2						;\
	inc	tmp2							;\
	st	tmp2, [tmp1]


#else /* DEBUG || SFMMU_STAT_GATHER */

#define	HAT_HSEARCH_DBSTAT(hatid, tsbarea, tmp1, tmp2)

#define	HAT_HLINK_DBSTAT(hatid, tsbarea, tmp1, tmp2)

#endif  /* DEBUG || SFMMU_STAT_GATHER */

/*
 * This macro is used to update global sfmmu kstas in non
 * perf critical areas so they are enabled all the time
 */
#define	HAT_GLOBAL_STAT(statname, tmp1, tmp2)				\
	sethi	%hi(sfmmu_global_stat), tmp1				;\
	add	tmp1, statname, tmp1					;\
	ld	[tmp1 + %lo(sfmmu_global_stat)], tmp2			;\
	inc	tmp2							;\
	st	tmp2, [tmp1 + %lo(sfmmu_global_stat)]

/*
 * These macros are used to update per cpu stats in non perf
 * critical areas so they are enabled all the time
 */
#define	HAT_PERCPU_STAT32(tsbarea, stat, tmp1)				\
	ld	[tsbarea + stat], tmp1					;\
	inc	tmp1							;\
	st	tmp1, [tsbarea + stat]

/*
 * These macros are used to update per cpu stats in non perf
 * critical areas so they are enabled all the time
 */
#define	HAT_PERCPU_STAT16(tsbarea, stat, tmp1)				\
	lduh	[tsbarea + stat], tmp1					;\
	inc	tmp1							;\
	stuh	tmp1, [tsbarea + stat]

#if defined(KPM_TLBMISS_STATS_GATHER)
	/*
	 * Count kpm dtlb misses separately to allow a different
	 * evaluation of hme and kpm tlbmisses. kpm tsb hits can
	 * be calculated by (kpm_dtlb_misses - kpm_tsb_misses).
	 */
#define	KPM_TLBMISS_STAT_INCR(tagacc, val, tsbma, tmp1, label)		\
	brgez	tagacc, label	/* KPM VA? */				;\
	nop								;\
	CPU_INDEX(tmp1, tsbma)						;\
	sethi	%hi(kpmtsbm_area), tsbma				;\
	sllx	tmp1, KPMTSBM_SHIFT, tmp1				;\
	or	tsbma, %lo(kpmtsbm_area), tsbma				;\
	add	tsbma, tmp1, tsbma		/* kpmtsbm area */	;\
	/* VA range check */						;\
	ldx	[tsbma + KPMTSBM_VBASE], val				;\
	cmp	tagacc, val						;\
	blu,pn	%xcc, label						;\
	  ldx	[tsbma + KPMTSBM_VEND], tmp1				;\
	cmp	tagacc, tmp1						;\
	bgeu,pn	%xcc, label						;\
	  lduw	[tsbma + KPMTSBM_DTLBMISS], val				;\
	inc	val							;\
	st	val, [tsbma + KPMTSBM_DTLBMISS]				;\
label:
#else
#define	KPM_TLBMISS_STAT_INCR(tagacc, val, tsbma, tmp1, label)
#endif	/* KPM_TLBMISS_STATS_GATHER */

#if defined (lint)
/*
 * The following routines are jumped to from the mmu trap handlers to do
 * the setting up to call systrap.  They are separate routines instead of
 * being part of the handlers because the handlers would exceed 32
 * instructions and since this is part of the slow path the jump
 * cost is irrelevant.
 */
void
sfmmu_pagefault(void)
{
}

void
sfmmu_mmu_trap(void)
{
}

void
sfmmu_window_trap(void)
{
}

void
sfmmu_kpm_exception(void)
{
}

#else /* lint */

#ifdef	PTL1_PANIC_DEBUG
	.seg	".data"
	.global	test_ptl1_panic
test_ptl1_panic:
	.word	0
	.align	8

	.seg	".text"
	.align	4
#endif	/* PTL1_PANIC_DEBUG */


	ENTRY_NP(sfmmu_pagefault)
	SET_GL_REG(1)
	USE_ALTERNATE_GLOBALS(%g5)
	GET_MMU_BOTH_TAGACC(%g5 /*dtag*/, %g2 /*itag*/, %g6, %g4)
	rdpr	%tt, %g6
	cmp	%g6, FAST_IMMU_MISS_TT
	be,a,pn	%icc, 1f
	  mov	T_INSTR_MMU_MISS, %g3
	cmp	%g6, T_INSTR_MMU_MISS
	be,a,pn	%icc, 1f
	  mov	T_INSTR_MMU_MISS, %g3
	mov	%g5, %g2
	mov	T_DATA_PROT, %g3		/* arg2 = traptype */
	cmp	%g6, FAST_DMMU_MISS_TT
	move	%icc, T_DATA_MMU_MISS, %g3	/* arg2 = traptype */
	cmp	%g6, T_DATA_MMU_MISS
	move	%icc, T_DATA_MMU_MISS, %g3	/* arg2 = traptype */

#ifdef  PTL1_PANIC_DEBUG
	/* check if we want to test the tl1 panic */
	sethi	%hi(test_ptl1_panic), %g4
	ld	[%g4 + %lo(test_ptl1_panic)], %g1
	st	%g0, [%g4 + %lo(test_ptl1_panic)]
	cmp	%g1, %g0
	bne,a,pn %icc, ptl1_panic
	  or	%g0, PTL1_BAD_DEBUG, %g1
#endif	/* PTL1_PANIC_DEBUG */
1:
	HAT_GLOBAL_STAT(HATSTAT_PAGEFAULT, %g6, %g4)
	/*
	 * g2 = tag access reg
	 * g3.l = type
	 * g3.h = 0
	 */
	sethi	%hi(trap), %g1
	or	%g1, %lo(trap), %g1
2:
	ba,pt	%xcc, sys_trap
	  mov	-1, %g4
	SET_SIZE(sfmmu_pagefault)

	ENTRY_NP(sfmmu_mmu_trap)
	SET_GL_REG(1)
	USE_ALTERNATE_GLOBALS(%g5)
	GET_MMU_BOTH_TAGACC(%g5 /*dtag*/, %g2 /*itag*/, %g4, %g6)
	rdpr	%tt, %g6
	cmp	%g6, FAST_IMMU_MISS_TT
	be,a,pn	%icc, 1f
	  mov	T_INSTR_MMU_MISS, %g3
	cmp	%g6, T_INSTR_MMU_MISS
	be,a,pn	%icc, 1f
	  mov	T_INSTR_MMU_MISS, %g3
	mov	%g5, %g2
	mov	T_DATA_PROT, %g3		/* arg2 = traptype */
	cmp	%g6, FAST_DMMU_MISS_TT
	move	%icc, T_DATA_MMU_MISS, %g3	/* arg2 = traptype */
	cmp	%g6, T_DATA_MMU_MISS
	move	%icc, T_DATA_MMU_MISS, %g3	/* arg2 = traptype */
1:
	/*
	 * g2 = tag access reg
	 * g3 = type
	 */
	sethi	%hi(sfmmu_tsbmiss_exception), %g1
	or	%g1, %lo(sfmmu_tsbmiss_exception), %g1
	ba,pt	%xcc, sys_trap
	  mov	-1, %g4
	/*NOTREACHED*/
	SET_SIZE(sfmmu_mmu_trap)

	ENTRY_NP(sfmmu_suspend_tl)
	SET_GL_REG(1)
	USE_ALTERNATE_GLOBALS(%g5)
	GET_MMU_BOTH_TAGACC(%g5 /*dtag*/, %g2 /*itag*/, %g4, %g3)
	rdpr	%tt, %g6
	cmp	%g6, FAST_IMMU_MISS_TT
	be,a,pn	%icc, 1f
	  mov	T_INSTR_MMU_MISS, %g3
	mov	%g5, %g2
	cmp	%g6, FAST_DMMU_MISS_TT
	move	%icc, T_DATA_MMU_MISS, %g3
	movne	%icc, T_DATA_PROT, %g3
1:
	sethi	%hi(sfmmu_tsbmiss_suspended), %g1
	or	%g1, %lo(sfmmu_tsbmiss_suspended), %g1
	/* g1 = TL0 handler, g2 = tagacc, g3 = trap type */
	ba,pt	%xcc, sys_trap
	  mov	PIL_15, %g4
	/*NOTREACHED*/
	SET_SIZE(sfmmu_suspend_tl)

	/*
	 * No %g registers in use at this point.
	 */
	ENTRY_NP(sfmmu_window_trap)
	rdpr	%tpc, %g1
#ifdef sun4v
#ifdef DEBUG
	/* We assume previous %gl was 1 */
	rdpr	%tstate, %g4
	srlx	%g4, TSTATE_GL_SHIFT, %g4
	and	%g4, TSTATE_GL_MASK, %g4
	cmp	%g4, 1
	bne,a,pn %icc, ptl1_panic
	  mov	PTL1_BAD_WTRAP, %g1
#endif /* DEBUG */
	/* user miss at tl>1. better be the window handler or user_rtt */
	/* in user_rtt? */
	set	rtt_fill_start, %g4
	cmp	%g1, %g4
	blu,pn %xcc, 6f
	 .empty
	set	rtt_fill_end, %g4
	cmp	%g1, %g4
	bgeu,pn %xcc, 6f
	 nop
	set	fault_rtt_fn1, %g1
	wrpr	%g0, %g1, %tnpc
	ba,a	7f
6:
	! must save this trap level before descending trap stack
	! no need to save %tnpc, either overwritten or discarded
	! already got it: rdpr	%tpc, %g1
	rdpr	%tstate, %g6
	rdpr	%tt, %g7
	! trap level saved, go get underlying trap type
	rdpr	%tl, %g5
	sub	%g5, 1, %g3
	wrpr	%g3, %tl
	rdpr	%tt, %g2
	wrpr	%g5, %tl
	! restore saved trap level
	wrpr	%g1, %tpc
	wrpr	%g6, %tstate
	wrpr	%g7, %tt
#else /* sun4v */
	/* user miss at tl>1. better be the window handler */
	rdpr	%tl, %g5
	sub	%g5, 1, %g3
	wrpr	%g3, %tl
	rdpr	%tt, %g2
	wrpr	%g5, %tl
#endif /* sun4v */
	and	%g2, WTRAP_TTMASK, %g4
	cmp	%g4, WTRAP_TYPE
	bne,pn	%xcc, 1f
	 nop
	/* tpc should be in the trap table */
	set	trap_table, %g4
	cmp	%g1, %g4
	blt,pn %xcc, 1f
	 .empty
	set	etrap_table, %g4
	cmp	%g1, %g4
	bge,pn %xcc, 1f
	 .empty
	andn	%g1, WTRAP_ALIGN, %g1	/* 128 byte aligned */
	add	%g1, WTRAP_FAULTOFF, %g1
	wrpr	%g0, %g1, %tnpc
7:
	/*
	 * some wbuf handlers will call systrap to resolve the fault
	 * we pass the trap type so they figure out the correct parameters.
	 * g5 = trap type, g6 = tag access reg
	 */

	/*
	 * only use g5, g6, g7 registers after we have switched to alternate
	 * globals.
	 */
	SET_GL_REG(1)
	USE_ALTERNATE_GLOBALS(%g5)
	GET_MMU_D_TAGACC(%g6 /*dtag*/, %g5 /*scratch*/)
	rdpr	%tt, %g7
	cmp	%g7, FAST_IMMU_MISS_TT
	be,a,pn	%icc, ptl1_panic
	  mov	PTL1_BAD_WTRAP, %g1
	cmp	%g7, T_INSTR_MMU_MISS
	be,a,pn	%icc, ptl1_panic
	  mov	PTL1_BAD_WTRAP, %g1
	mov	T_DATA_PROT, %g5
	cmp	%g7, FAST_DMMU_MISS_TT
	move	%icc, T_DATA_MMU_MISS, %g5
	cmp	%g7, T_DATA_MMU_MISS
	move	%icc, T_DATA_MMU_MISS, %g5
	! XXXQ AGS re-check out this one
	done
1:
	CPU_PADDR(%g1, %g4)
	add	%g1, CPU_TL1_HDLR, %g1
	lda	[%g1]ASI_MEM, %g4
	brnz,a,pt %g4, sfmmu_mmu_trap
	  sta	%g0, [%g1]ASI_MEM
	ba,pt	%icc, ptl1_panic
	  mov	PTL1_BAD_TRAP, %g1
	SET_SIZE(sfmmu_window_trap)

	ENTRY_NP(sfmmu_kpm_exception)
	/*
	 * We have accessed an unmapped segkpm address or a legal segkpm
	 * address which is involved in a VAC alias conflict prevention.
	 * Before we go to trap(), check to see if CPU_DTRACE_NOFAULT is
	 * set. If it is, we will instead note that a fault has occurred
	 * by setting CPU_DTRACE_BADADDR and issue a "done" (instead of
	 * a "retry"). This will step over the faulting instruction.
	 * Note that this means that a legal segkpm address involved in
	 * a VAC alias conflict prevention (a rare case to begin with)
	 * cannot be used in DTrace.
	 */
	CPU_INDEX(%g1, %g2)
	set	cpu_core, %g2
	sllx	%g1, CPU_CORE_SHIFT, %g1
	add	%g1, %g2, %g1
	lduh	[%g1 + CPUC_DTRACE_FLAGS], %g2
	andcc	%g2, CPU_DTRACE_NOFAULT, %g0
	bz	0f
	or	%g2, CPU_DTRACE_BADADDR, %g2
	stuh	%g2, [%g1 + CPUC_DTRACE_FLAGS]
	GET_MMU_D_ADDR(%g3, /*scratch*/ %g4)
	stx	%g3, [%g1 + CPUC_DTRACE_ILLVAL]
	done
0:
	TSTAT_CHECK_TL1(1f, %g1, %g2)
1:
	SET_GL_REG(1)
	USE_ALTERNATE_GLOBALS(%g5)
	GET_MMU_D_TAGACC(%g2 /* tagacc */, %g4 /*scratch*/)
	mov	T_DATA_MMU_MISS, %g3	/* arg2 = traptype */
	/*
	 * g2=tagacc g3.l=type g3.h=0
	 */
	sethi	%hi(trap), %g1
	or	%g1, %lo(trap), %g1
	ba,pt	%xcc, sys_trap
	mov	-1, %g4
	SET_SIZE(sfmmu_kpm_exception)

#endif /* lint */

#if defined (lint)

void
sfmmu_tsb_miss(void)
{
}

void
sfmmu_kpm_dtsb_miss(void)
{
}

void
sfmmu_kpm_dtsb_miss_small(void)
{
}

#else /* lint */

#if (IMAP_SEG != 0)
#error - ism_map->ism_seg offset is not zero
#endif

/*
 * Copies ism mapping for this ctx in param "ism" if this is a ISM
 * tlb miss and branches to label "ismhit". If this is not an ISM
 * process or an ISM tlb miss it falls thru.
 *
 * Checks to see if the vaddr passed in via tagacc is in an ISM segment for
 * this process.
 * If so, it will branch to label "ismhit".  If not, it will fall through.
 *
 * Also hat_unshare() will set the context for this process to INVALID_CONTEXT
 * so that any other threads of this process will not try and walk the ism
 * maps while they are being changed.
 *
 * NOTE: We will never have any holes in our ISM maps. sfmmu_share/unshare
 *       will make sure of that. This means we can terminate our search on
 *       the first zero mapping we find.
 *
 * Parameters:
 * tagacc	= (pseudo-)tag access register (vaddr + ctx) (in)
 * tsbmiss	= address of tsb miss area (in)
 * ismseg	= contents of ism_seg for this ism map (out)
 * ismhat	= physical address of imap_ismhat for this ism map (out)
 * tmp1		= scratch reg (CLOBBERED)
 * tmp2		= scratch reg (CLOBBERED)
 * tmp3		= scratch reg (CLOBBERED)
 * label:    temporary labels
 * ismhit:   label where to jump to if an ism dtlb miss
 * exitlabel:label where to jump if hat is busy due to hat_unshare.
 */
#define ISM_CHECK(tagacc, tsbmiss, ismseg, ismhat, tmp1, tmp2, tmp3 \
	label, ismhit)							\
	ldx	[tsbmiss + TSBMISS_ISMBLKPA], tmp1 /* tmp1 = &ismblk */	;\
	brlz,pt  tmp1, label/**/3		/* exit if -1 */	;\
	  add	tmp1, IBLK_MAPS, ismhat	/* ismhat = &ismblk.map[0] */	;\
label/**/1:								;\
	ldxa	[ismhat]ASI_MEM, ismseg	/* ismblk.map[0].ism_seg */	;\
	mov	tmp1, tmp3	/* update current ismblkpa head */	;\
label/**/2:								;\
	brz,pt  ismseg, label/**/3		/* no mapping */	;\
	  add	ismhat, IMAP_VB_SHIFT, tmp1 /* tmp1 = vb_shift addr */	;\
	lduba	[tmp1]ASI_MEM, tmp1 		/* tmp1 = vb shift*/	;\
	srlx	ismseg, tmp1, tmp2		/* tmp2 = vbase */	;\
	srlx	tagacc, tmp1, tmp1		/* tmp1 =  va seg*/	;\
	sub	tmp1, tmp2, tmp2		/* tmp2 = va - vbase */	;\
	add	ismhat, IMAP_SZ_MASK, tmp1 /* tmp1 = sz_mask addr */	;\
	lda	[tmp1]ASI_MEM, tmp1		/* tmp1 = sz_mask */	;\
	and	ismseg, tmp1, tmp1		/* tmp1 = size */	;\
	cmp	tmp2, tmp1		 	/* check va <= offset*/	;\
	blu,a,pt  %xcc, ismhit			/* ism hit */		;\
	  add	ismhat, IMAP_ISMHAT, ismhat 	/* ismhat = &ism_sfmmu*/ ;\
									;\
	add	ismhat, ISM_MAP_SZ, ismhat /* ismhat += sizeof(map) */ 	;\
	add	tmp3, (IBLK_MAPS + ISM_MAP_SLOTS * ISM_MAP_SZ), tmp1	;\
	cmp	ismhat, tmp1						;\
	bl,pt	%xcc, label/**/2		/* keep looking  */	;\
	  ldxa	[ismhat]ASI_MEM, ismseg	/* ismseg = map[ismhat] */	;\
									;\
	add	tmp3, IBLK_NEXTPA, tmp1					;\
	ldxa	[tmp1]ASI_MEM, tmp1		/* check blk->nextpa */	;\
	brgez,pt tmp1, label/**/1		/* continue if not -1*/	;\
	  add	tmp1, IBLK_MAPS, ismhat	/* ismhat = &ismblk.map[0]*/	;\
label/**/3:

/*
 * Returns the hme hash bucket (hmebp) given the vaddr, and the hatid
 * It also returns the virtual pg for vaddr (ie. vaddr << hmeshift)
 * Parameters:
 * tagacc = reg containing virtual address
 * hatid = reg containing sfmmu pointer
 * hmeshift = constant/register to shift vaddr to obtain vapg
 * hmebp = register where bucket pointer will be stored
 * vapg = register where virtual page will be stored
 * tmp1, tmp2 = tmp registers
 */


#define	HMEHASH_FUNC_ASM(tagacc, hatid, tsbarea, hmeshift, hmebp,	\
	vapg, label, tmp1, tmp2)					\
	sllx	tagacc, TAGACC_CTX_LSHIFT, tmp1				;\
	brnz,a,pt tmp1, label/**/1					;\
	  ld    [tsbarea + TSBMISS_UHASHSZ], hmebp			;\
	ld	[tsbarea + TSBMISS_KHASHSZ], hmebp			;\
	ba,pt	%xcc, label/**/2					;\
	  ldx	[tsbarea + TSBMISS_KHASHSTART], tmp1			;\
label/**/1:								;\
	ldx	[tsbarea + TSBMISS_UHASHSTART], tmp1			;\
label/**/2:								;\
	srlx	tagacc, hmeshift, vapg					;\
	xor	vapg, hatid, tmp2	/* hatid ^ (vaddr >> shift) */	;\
	and	tmp2, hmebp, hmebp	/* index into hme_hash */	;\
	mulx	hmebp, HMEBUCK_SIZE, hmebp				;\
	add	hmebp, tmp1, hmebp

/*
 * hashtag includes bspage + hashno (64 bits).
 */

#define	MAKE_HASHTAG(vapg, hatid, hmeshift, hashno, hblktag)		\
	sllx	vapg, hmeshift, vapg					;\
	mov	hashno, hblktag						;\
	sllx	hblktag, HTAG_REHASH_SHIFT, hblktag			;\
	or	vapg, hblktag, hblktag

/*
 * Function to traverse hmeblk hash link list and find corresponding match.
 * The search is done using physical pointers. It returns the physical address
 * pointer to the hmeblk that matches with the tag provided.
 * Parameters:
 * hmebp	= register that points to hme hash bucket, also used as
 *		  tmp reg (clobbered)
 * hmeblktag	= register with hmeblk tag match
 * hatid	= register with hatid
 * hmeblkpa	= register where physical ptr will be stored
 * tmp1		= tmp reg
 * label: temporary label
 */

#define	HMEHASH_SEARCH(hmebp, hmeblktag, hatid, hmeblkpa, tsbarea, 	\
	tmp1, label)							\
	add     hmebp, HMEBUCK_NEXTPA, hmeblkpa				;\
	ldxa    [hmeblkpa]ASI_MEM, hmeblkpa				;\
	HAT_HSEARCH_DBSTAT(hatid, tsbarea, hmebp, tmp1)			;\
label/**/1:								;\
	cmp	hmeblkpa, HMEBLK_ENDPA					;\
	be,pn   %xcc, label/**/2					;\
	HAT_HLINK_DBSTAT(hatid, tsbarea, hmebp, tmp1)			;\
	add	hmeblkpa, HMEBLK_TAG, hmebp				;\
	ldxa	[hmebp]ASI_MEM, tmp1	 /* read 1st part of tag */	;\
	add	hmebp, CLONGSIZE, hmebp					;\
	ldxa	[hmebp]ASI_MEM, hmebp 	/* read 2nd part of tag */	;\
	xor	tmp1, hmeblktag, tmp1					;\
	xor	hmebp, hatid, hmebp					;\
	or	hmebp, tmp1, hmebp					;\
	brz,pn	hmebp, label/**/2	/* branch on hit */		;\
	  add	hmeblkpa, HMEBLK_NEXTPA, hmebp				;\
	ba,pt	%xcc, label/**/1					;\
	  ldxa	[hmebp]ASI_MEM, hmeblkpa	/* hmeblk ptr pa */	;\
label/**/2:

/*
 * Function to traverse hmeblk hash link list and find corresponding match.
 * The search is done using physical pointers. It returns the physical address
 * pointer to the hmeblk that matches with the tag
 * provided.
 * Parameters:
 * hmeblktag	= register with hmeblk tag match (rid field is 0)
 * hatid	= register with hatid (pointer to SRD)
 * hmeblkpa	= register where physical ptr will be stored
 * tmp1		= tmp reg
 * tmp2		= tmp reg
 * label: temporary label
 */

#define	HMEHASH_SEARCH_SHME(hmeblktag, hatid, hmeblkpa, tsbarea,	\
	tmp1, tmp2, label)			 			\
label/**/1:								;\
	cmp	hmeblkpa, HMEBLK_ENDPA					;\
	be,pn   %xcc, label/**/4					;\
	HAT_HLINK_DBSTAT(hatid, tsbarea, tmp1, tmp2)			;\
	add	hmeblkpa, HMEBLK_TAG, tmp2				;\
	ldxa	[tmp2]ASI_MEM, tmp1	 /* read 1st part of tag */	;\
	add	tmp2, CLONGSIZE, tmp2					;\
	ldxa	[tmp2]ASI_MEM, tmp2 	/* read 2nd part of tag */	;\
	xor	tmp1, hmeblktag, tmp1					;\
	xor	tmp2, hatid, tmp2					;\
	brz,pn	tmp2, label/**/3	/* branch on hit */		;\
	  add	hmeblkpa, HMEBLK_NEXTPA, tmp2				;\
label/**/2:								;\
	ba,pt	%xcc, label/**/1					;\
	  ldxa	[tmp2]ASI_MEM, hmeblkpa	/* hmeblk ptr pa */		;\
label/**/3:								;\
	cmp	tmp1, SFMMU_MAX_HME_REGIONS				;\
	bgeu,pt	%xcc, label/**/2					;\
	  add	hmeblkpa, HMEBLK_NEXTPA, tmp2				;\
	and	tmp1, BT_ULMASK, tmp2					;\
	srlx	tmp1, BT_ULSHIFT, tmp1					;\
	sllx	tmp1, CLONGSHIFT, tmp1					;\
	add	tsbarea, tmp1, tmp1					;\
	ldx	[tmp1 + TSBMISS_SHMERMAP], tmp1				;\
	srlx	tmp1, tmp2, tmp1					;\
	btst	0x1, tmp1						;\
	bz,pn	%xcc, label/**/2					;\
	  add	hmeblkpa, HMEBLK_NEXTPA, tmp2				;\
label/**/4:

#if ((1 << SFHME_SHIFT) != SFHME_SIZE)
#error HMEBLK_TO_HMENT assumes sf_hment is power of 2 in size
#endif

/*
 * HMEBLK_TO_HMENT is a macro that given an hmeblk and a vaddr returns
 * the offset for the corresponding hment.
 * Parameters:
 * In:
 *	vaddr = register with virtual address
 *	hmeblkpa = physical pointer to hme_blk
 * Out:
 *	hmentoff = register where hment offset will be stored
 *	hmemisc = hblk_misc
 * Scratch:
 *	tmp1
 */
#define	HMEBLK_TO_HMENT(vaddr, hmeblkpa, hmentoff, hmemisc, tmp1, label1)\
	add	hmeblkpa, HMEBLK_MISC, hmentoff				;\
	lda	[hmentoff]ASI_MEM, hmemisc 				;\
	andcc	hmemisc, HBLK_SZMASK, %g0				;\
	bnz,a,pn  %icc, label1		/* if sz != TTE8K branch */	;\
	  or	%g0, HMEBLK_HME1, hmentoff				;\
	srl	vaddr, MMU_PAGESHIFT, tmp1				;\
	and	tmp1, NHMENTS - 1, tmp1		/* tmp1 = index */	;\
	sllx	tmp1, SFHME_SHIFT, tmp1					;\
	add	tmp1, HMEBLK_HME1, hmentoff				;\
label1:

/*
 * GET_TTE is a macro that returns a TTE given a tag and hatid.
 *
 * tagacc	= (pseudo-)tag access register (in)
 * hatid	= sfmmu pointer for TSB miss (in)
 * tte		= tte for TLB miss if found, otherwise clobbered (out)
 * hmeblkpa	= PA of hment if found, otherwise clobbered (out)
 * tsbarea	= pointer to the tsbmiss area for this cpu. (in)
 * hmemisc	= hblk_misc if TTE is found (out), otherwise clobbered
 * hmeshift	= constant/register to shift VA to obtain the virtual pfn
 *		  for this page size.
 * hashno	= constant/register hash number
 * tmp		= temp value - clobbered
 * label	= temporary label for branching within macro.
 * foundlabel	= label to jump to when tte is found.
 * suspendlabel= label to jump to when tte is suspended.
 * exitlabel	= label to jump to when tte is not found.
 *
 */
#define GET_TTE(tagacc, hatid, tte, hmeblkpa, tsbarea, hmemisc, hmeshift, \
		 hashno, tmp, label, foundlabel, suspendlabel, exitlabel) \
									;\
	stn	tagacc, [tsbarea + (TSBMISS_SCRATCH + TSB_TAGACC)]	;\
	stn	hatid, [tsbarea + (TSBMISS_SCRATCH + TSBMISS_HATID)]	;\
	HMEHASH_FUNC_ASM(tagacc, hatid, tsbarea, hmeshift, tte,		\
		hmeblkpa, label/**/5, hmemisc, tmp)			;\
									;\
	/*								;\
	 * tagacc = tagacc						;\
	 * hatid = hatid						;\
	 * tsbarea = tsbarea						;\
	 * tte   = hmebp (hme bucket pointer)				;\
	 * hmeblkpa  = vapg  (virtual page)				;\
	 * hmemisc, tmp = scratch					;\
	 */								;\
	MAKE_HASHTAG(hmeblkpa, hatid, hmeshift, hashno, hmemisc)	;\
	or	hmemisc, SFMMU_INVALID_SHMERID, hmemisc			;\
									;\
	/*								;\
	 * tagacc = tagacc						;\
	 * hatid = hatid						;\
	 * tte   = hmebp						;\
	 * hmeblkpa  = CLOBBERED					;\
	 * hmemisc  = htag_bspage+hashno+invalid_rid			;\
	 * tmp  = scratch						;\
	 */								;\
	stn	tte, [tsbarea + (TSBMISS_SCRATCH + TSBMISS_HMEBP)]	;\
	HMEHASH_SEARCH(tte, hmemisc, hatid, hmeblkpa, 	 		\
		tsbarea, tagacc, label/**/1)				;\
	/*								;\
	 * tagacc = CLOBBERED						;\
	 * tte = CLOBBERED						;\
	 * hmeblkpa = hmeblkpa						;\
	 * tmp = scratch						;\
	 */								;\
	cmp	hmeblkpa, HMEBLK_ENDPA					;\
	bne,pn   %xcc, label/**/4       /* branch if hmeblk found */    ;\
	  ldn	[tsbarea + (TSBMISS_SCRATCH + TSB_TAGACC)], tagacc	;\
	ba,pt	%xcc, exitlabel		/* exit if hblk not found */	;\
	  nop								;\
label/**/4:								;\
	/*								;\
	 * We have found the hmeblk containing the hment.		;\
	 * Now we calculate the corresponding tte.			;\
	 *								;\
	 * tagacc = tagacc						;\
	 * hatid = hatid						;\
	 * tte   = clobbered						;\
	 * hmeblkpa  = hmeblkpa						;\
	 * hmemisc  = hblktag						;\
	 * tmp = scratch						;\
	 */								;\
	HMEBLK_TO_HMENT(tagacc, hmeblkpa, hatid, hmemisc, tte,		\
		label/**/2)						;\
									;\
	/*								;\
	 * tagacc = tagacc						;\
	 * hatid = hmentoff						;\
	 * tte   = clobbered						;\
	 * hmeblkpa  = hmeblkpa						;\
	 * hmemisc  = hblk_misc						;\
	 * tmp = scratch						;\
	 */								;\
									;\
	add	hatid, SFHME_TTE, hatid					;\
	add	hmeblkpa, hatid, hmeblkpa				;\
	ldxa	[hmeblkpa]ASI_MEM, tte	/* MMU_READTTE through pa */	;\
	ldn	[tsbarea + (TSBMISS_SCRATCH + TSBMISS_HMEBP)], hatid 	;\
	set	TTE_SUSPEND, hatid					;\
	TTE_SUSPEND_INT_SHIFT(hatid)					;\
	btst	tte, hatid						;\
	bz,pt	%xcc, foundlabel					;\
	ldn	[tsbarea + (TSBMISS_SCRATCH + TSBMISS_HATID)], hatid	;\
									;\
	/*								;\
	 * Mapping is suspended, so goto suspend label.			;\
	 */								;\
	ba,pt	%xcc, suspendlabel					;\
	  nop

/*
 * GET_SHME_TTE is similar to GET_TTE() except it searches
 * shared hmeblks via HMEHASH_SEARCH_SHME() macro.
 * If valid tte is found, hmemisc = shctx flag, i.e., shme is
 * either 0 (not part of scd) or 1 (part of scd).
 */
#define GET_SHME_TTE(tagacc, hatid, tte, hmeblkpa, tsbarea, hmemisc, 	\
		hmeshift, hashno, tmp, label, foundlabel,		\
		suspendlabel, exitlabel)				\
									;\
	stn	tagacc, [tsbarea + (TSBMISS_SCRATCH + TSB_TAGACC)]	;\
	stn	hatid, [tsbarea + (TSBMISS_SCRATCH + TSBMISS_HATID)]	;\
	HMEHASH_FUNC_ASM(tagacc, hatid, tsbarea, hmeshift, tte,		\
		hmeblkpa, label/**/5, hmemisc, tmp)			;\
									;\
	/*								;\
	 * tagacc = tagacc						;\
	 * hatid = hatid						;\
	 * tsbarea = tsbarea						;\
	 * tte   = hmebp (hme bucket pointer)				;\
	 * hmeblkpa  = vapg  (virtual page)				;\
	 * hmemisc, tmp = scratch					;\
	 */								;\
	MAKE_HASHTAG(hmeblkpa, hatid, hmeshift, hashno, hmemisc)	;\
									;\
	/*								;\
	 * tagacc = tagacc						;\
	 * hatid = hatid						;\
	 * tsbarea = tsbarea						;\
	 * tte   = hmebp						;\
	 * hmemisc  = htag_bspage + hashno + 0 (for rid)		;\
	 * hmeblkpa  = CLOBBERED					;\
	 * tmp = scratch						;\
	 */								;\
	stn	tte, [tsbarea + (TSBMISS_SCRATCH + TSBMISS_HMEBP)]	;\
									;\
	add     tte, HMEBUCK_NEXTPA, hmeblkpa				;\
	ldxa    [hmeblkpa]ASI_MEM, hmeblkpa				;\
	HAT_HSEARCH_DBSTAT(hatid, tsbarea, tagacc, tte)			;\
									;\
label/**/8:								;\
	HMEHASH_SEARCH_SHME(hmemisc, hatid, hmeblkpa,			\
		tsbarea, tagacc, tte, label/**/1)			;\
	/*								;\
	 * tagacc = CLOBBERED						;\
	 * tte = CLOBBERED						;\
	 * hmeblkpa = hmeblkpa						;\
	 * tmp = scratch						;\
	 */								;\
	cmp	hmeblkpa, HMEBLK_ENDPA					;\
	bne,pn   %xcc, label/**/4       /* branch if hmeblk found */    ;\
	  ldn	[tsbarea + (TSBMISS_SCRATCH + TSB_TAGACC)], tagacc	;\
	ba,pt	%xcc, exitlabel		/* exit if hblk not found */	;\
	  nop								;\
label/**/4:								;\
	/*								;\
	 * We have found the hmeblk containing the hment.		;\
	 * Now we calculate the corresponding tte.			;\
	 *								;\
	 * tagacc = tagacc						;\
	 * hatid = hatid						;\
	 * tte   = clobbered						;\
	 * hmeblkpa  = hmeblkpa						;\
	 * hmemisc  = hblktag						;\
	 * tsbarea = tsbmiss area					;\
	 * tmp = scratch						;\
	 */								;\
	HMEBLK_TO_HMENT(tagacc, hmeblkpa, hatid, hmemisc, tte,		\
		label/**/2)						;\
									;\
	/*								;\
	 * tagacc = tagacc						;\
	 * hatid = hmentoff						;\
	 * tte = clobbered						;\
	 * hmeblkpa  = hmeblkpa						;\
	 * hmemisc  = hblk_misc						;\
	 * tsbarea = tsbmiss area					;\
	 * tmp = scratch						;\
	 */								;\
									;\
	add	hatid, SFHME_TTE, hatid					;\
	add	hmeblkpa, hatid, hmeblkpa				;\
	ldxa	[hmeblkpa]ASI_MEM, tte	/* MMU_READTTE through pa */	;\
	brlz,pt tte, label/**/6						;\
	  nop								;\
	btst	HBLK_SZMASK, hmemisc					;\
	bnz,a,pt %icc, label/**/7					;\
	  ldn	[tsbarea + (TSBMISS_SCRATCH + TSBMISS_HMEBP)], hatid 	;\
									;\
	/*								;\
 	 * We found an invalid 8K tte in shme.				;\
	 * it may not belong to shme's region since			;\
	 * region size/alignment granularity is 8K but different	;\
	 * regions don't share hmeblks. Continue the search.		;\
	 */								;\
	sub	hmeblkpa, hatid, hmeblkpa				;\
	ldn	[tsbarea + (TSBMISS_SCRATCH + TSBMISS_HATID)], hatid	;\
	srlx	tagacc, hmeshift, tte					;\
	add	hmeblkpa, HMEBLK_NEXTPA, hmeblkpa			;\
	ldxa	[hmeblkpa]ASI_MEM, hmeblkpa				;\
	MAKE_HASHTAG(tte, hatid, hmeshift, hashno, hmemisc)		;\
	ba,a,pt	%xcc, label/**/8					;\
label/**/6:								;\
	GET_SCDSHMERMAP(tsbarea, hmeblkpa, hatid, hmemisc)		;\
	ldn	[tsbarea + (TSBMISS_SCRATCH + TSBMISS_HMEBP)], hatid 	;\
label/**/7:								;\
	set	TTE_SUSPEND, hatid					;\
	TTE_SUSPEND_INT_SHIFT(hatid)					;\
	btst	tte, hatid						;\
	bz,pt	%xcc, foundlabel					;\
	ldn	[tsbarea + (TSBMISS_SCRATCH + TSBMISS_HATID)], hatid	;\
									;\
	/*								;\
	 * Mapping is suspended, so goto suspend label.			;\
	 */								;\
	ba,pt	%xcc, suspendlabel					;\
	  nop

	/*
	 * KERNEL PROTECTION HANDLER
	 *
	 * g1 = tsb8k pointer register (clobbered)
	 * g2 = tag access register (ro)
	 * g3 - g7 = scratch registers
	 *
	 * Note: This function is patched at runtime for performance reasons.
	 * 	 Any changes here require sfmmu_patch_ktsb fixed.
	 */
	ENTRY_NP(sfmmu_kprot_trap)
	mov	%g2, %g7		! TSB pointer macro clobbers tagacc
sfmmu_kprot_patch_ktsb_base:
	RUNTIME_PATCH_SETX(%g1, %g6)
	/* %g1 = contents of ktsb_base or ktsb_pbase */
sfmmu_kprot_patch_ktsb_szcode:
	or	%g0, RUNTIME_PATCH, %g3	! ktsb_szcode (hot patched)

	GET_TSBE_POINTER(MMU_PAGESHIFT, %g1, %g7, %g3, %g5)
	! %g1 = First TSB entry pointer, as TSB miss handler expects

	mov	%g2, %g7		! TSB pointer macro clobbers tagacc
sfmmu_kprot_patch_ktsb4m_base:
	RUNTIME_PATCH_SETX(%g3, %g6)
	/* %g3 = contents of ktsb4m_base or ktsb4m_pbase */
sfmmu_kprot_patch_ktsb4m_szcode:
	or	%g0, RUNTIME_PATCH, %g6	! ktsb4m_szcode (hot patched)

	GET_TSBE_POINTER(MMU_PAGESHIFT4M, %g3, %g7, %g6, %g5)
	! %g3 = 4M tsb entry pointer, as TSB miss handler expects

        CPU_TSBMISS_AREA(%g6, %g7)
        HAT_PERCPU_STAT16(%g6, TSBMISS_KPROTS, %g7)
	ba,pt	%xcc, sfmmu_tsb_miss_tt
	  nop

	/*
	 * USER PROTECTION HANDLER
	 *
	 * g1 = tsb8k pointer register (ro)
	 * g2 = tag access register (ro)
	 * g3 = faulting context (clobbered, currently not used)
	 * g4 - g7 = scratch registers
	 */
	ALTENTRY(sfmmu_uprot_trap)
#ifdef sun4v
	GET_1ST_TSBE_PTR(%g2, %g1, %g4, %g5)
	/* %g1 = first TSB entry ptr now, %g2 preserved */

	GET_UTSBREG(SCRATCHPAD_UTSBREG2, %g3)	/* get 2nd utsbreg */
	brlz,pt %g3, 9f				/* check for 2nd TSB */
	  nop

	GET_2ND_TSBE_PTR(%g2, %g3, %g4, %g5)
	/* %g3 = second TSB entry ptr now, %g2 preserved */

#else /* sun4v */
#ifdef UTSB_PHYS
	/* g1 = first TSB entry ptr */
	GET_UTSBREG(SCRATCHPAD_UTSBREG2, %g3)
	brlz,pt %g3, 9f			/* check for 2nd TSB */
	  nop

	GET_2ND_TSBE_PTR(%g2, %g3, %g4, %g5)
	/* %g3 = second TSB entry ptr now, %g2 preserved */
#else /* UTSB_PHYS */
	brgez,pt %g1, 9f		/* check for 2nd TSB */
	  mov	-1, %g3			/* set second tsbe ptr to -1 */

	mov	%g2, %g7
	GET_2ND_TSBE_PTR(%g7, %g1, %g3, %g4, %g5, sfmmu_uprot)
	/* %g3 = second TSB entry ptr now, %g7 clobbered */
	mov	%g1, %g7
	GET_1ST_TSBE_PTR(%g7, %g1, %g5, sfmmu_uprot)
#endif /* UTSB_PHYS */
#endif /* sun4v */
9:
	CPU_TSBMISS_AREA(%g6, %g7)
	HAT_PERCPU_STAT16(%g6, TSBMISS_UPROTS, %g7)
	ba,pt	%xcc, sfmmu_tsb_miss_tt		/* branch TSB miss handler */
	  nop

	/*
	 * Kernel 8K page iTLB miss.  We also get here if we took a
	 * fast instruction access mmu miss trap while running in
	 * invalid context.
	 *
	 * %g1 = 8K TSB pointer register (not used, clobbered)
	 * %g2 = tag access register (used)
	 * %g3 = faulting context id (used)
	 * %g7 = TSB tag to match (used)
	 */
	.align	64
	ALTENTRY(sfmmu_kitlb_miss)
	brnz,pn %g3, tsb_tl0_noctxt
	  nop

	/* kernel miss */
	/* get kernel tsb pointer */
	/* we patch the next set of instructions at run time */
	/* NOTE: any changes here require sfmmu_patch_ktsb fixed */
iktsbbase:
	RUNTIME_PATCH_SETX(%g4, %g5)
	/* %g4 = contents of ktsb_base or ktsb_pbase */

iktsb:	sllx	%g2, 64-(TAGACC_SHIFT + TSB_START_SIZE + RUNTIME_PATCH), %g1
	srlx	%g1, 64-(TSB_START_SIZE + TSB_ENTRY_SHIFT + RUNTIME_PATCH), %g1
	or	%g4, %g1, %g1			! form tsb ptr
	ldda	[%g1]RUNTIME_PATCH, %g4		! %g4 = tag, %g5 = data
	cmp	%g4, %g7
	bne,pn	%xcc, iktsb4mbase		! check 4m ktsb
	  srlx    %g2, MMU_PAGESHIFT4M, %g3	! use 4m virt-page as TSB index

	andcc %g5, TTE_EXECPRM_INT, %g0		! check exec bit
	bz,pn	%icc, exec_fault
	  nop
	TT_TRACE(trace_tsbhit)			! 2 instr traptrace
	ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)
	retry

iktsb4mbase:
        RUNTIME_PATCH_SETX(%g4, %g6)
        /* %g4 = contents of ktsb4m_base or ktsb4m_pbase */
iktsb4m:
	sllx    %g3, 64-(TSB_START_SIZE + RUNTIME_PATCH), %g3
        srlx    %g3, 64-(TSB_START_SIZE + TSB_ENTRY_SHIFT + RUNTIME_PATCH), %g3
	add	%g4, %g3, %g3			! %g3 = 4m tsbe ptr
	ldda	[%g3]RUNTIME_PATCH, %g4		! %g4 = tag, %g5 = data
	cmp	%g4, %g7
	bne,pn	%xcc, sfmmu_tsb_miss_tt		! branch on miss
	  andcc %g5, TTE_EXECPRM_INT, %g0		! check exec bit
	bz,pn	%icc, exec_fault
	  nop
	TT_TRACE(trace_tsbhit)			! 2 instr traptrace
	ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)
	retry

	/*
	 * Kernel dTLB miss.  We also get here if we took a fast data
	 * access mmu miss trap while running in invalid context.
	 *
	 * Note: for now we store kpm TTEs in the kernel TSB as usual.
	 *	We select the TSB miss handler to branch to depending on
	 *	the virtual address of the access.  In the future it may
	 *	be desirable to separate kpm TTEs into their own TSB,
	 *	in which case all that needs to be done is to set
	 *	kpm_tsbbase/kpm_tsbsz to point to the new TSB and branch
	 *	early in the miss if we detect a kpm VA to a new handler.
	 *
	 * %g1 = 8K TSB pointer register (not used, clobbered)
	 * %g2 = tag access register (used)
	 * %g3 = faulting context id (used)
	 */
	.align	64
	ALTENTRY(sfmmu_kdtlb_miss)
	brnz,pn	%g3, tsb_tl0_noctxt		/* invalid context? */
	  nop

	/* Gather some stats for kpm misses in the TLB. */
	/* KPM_TLBMISS_STAT_INCR(tagacc, val, tsbma, tmp1, label) */
	KPM_TLBMISS_STAT_INCR(%g2, %g4, %g5, %g6, kpmtlbm_stat_out)

	/*
	 * Get first TSB offset and look for 8K/64K/512K mapping
	 * using the 8K virtual page as the index.
	 *
	 * We patch the next set of instructions at run time;
	 * any changes here require sfmmu_patch_ktsb changes too.
	 */
dktsbbase:
	RUNTIME_PATCH_SETX(%g7, %g6)
	/* %g7 = contents of ktsb_base or ktsb_pbase */

dktsb:	sllx	%g2, 64-(TAGACC_SHIFT + TSB_START_SIZE + RUNTIME_PATCH), %g1
	srlx	%g1, 64-(TSB_START_SIZE + TSB_ENTRY_SHIFT + RUNTIME_PATCH), %g1

	/*
	 * At this point %g1 is our index into the TSB.
	 * We just masked off enough bits of the VA depending
	 * on our TSB size code.
	 */
	ldda	[%g7 + %g1]RUNTIME_PATCH, %g4	! %g4 = tag, %g5 = data
	srlx	%g2, TAG_VALO_SHIFT, %g6	! make tag to compare
	cmp	%g6, %g4			! compare tag
	bne,pn	%xcc, dktsb4m_kpmcheck_small
	  add	%g7, %g1, %g1			/* form tsb ptr */
	TT_TRACE(trace_tsbhit)
	DTLB_STUFF(%g5, %g1, %g2, %g3, %g4)
	/* trapstat expects tte in %g5 */
	retry

	/*
	 * If kpm is using large pages, the following instruction needs
	 * to be patched to a nop at boot time (by sfmmu_kpm_patch_tsbm)
	 * so that we will probe the 4M TSB regardless of the VA.  In
	 * the case kpm is using small pages, we know no large kernel
	 * mappings are located above 0x80000000.00000000 so we skip the
	 * probe as an optimization.
	 */
dktsb4m_kpmcheck_small:
	brlz,pn %g2, sfmmu_kpm_dtsb_miss_small
	  /* delay slot safe, below */

	/*
	 * Get second TSB offset and look for 4M mapping
	 * using 4M virtual page as the TSB index.
	 *
	 * Here:
	 * %g1 = 8K TSB pointer.  Don't squash it.
	 * %g2 = tag access register (we still need it)
	 */
	srlx	%g2, MMU_PAGESHIFT4M, %g3

	/*
	 * We patch the next set of instructions at run time;
	 * any changes here require sfmmu_patch_ktsb changes too.
	 */
dktsb4mbase:
	RUNTIME_PATCH_SETX(%g7, %g6)
	/* %g7 = contents of ktsb4m_base or ktsb4m_pbase */
dktsb4m:
	sllx	%g3, 64-(TSB_START_SIZE + RUNTIME_PATCH), %g3
	srlx	%g3, 64-(TSB_START_SIZE + TSB_ENTRY_SHIFT + RUNTIME_PATCH), %g3

	/*
	 * At this point %g3 is our index into the TSB.
	 * We just masked off enough bits of the VA depending
	 * on our TSB size code.
	 */
	ldda	[%g7 + %g3]RUNTIME_PATCH, %g4	! %g4 = tag, %g5 = data
	srlx	%g2, TAG_VALO_SHIFT, %g6	! make tag to compare
	cmp	%g6, %g4			! compare tag

dktsb4m_tsbmiss:
	bne,pn	%xcc, dktsb4m_kpmcheck
	  add	%g7, %g3, %g3			! %g3 = kernel second TSB ptr
	TT_TRACE(trace_tsbhit)
	/* we don't check TTE size here since we assume 4M TSB is separate */
	DTLB_STUFF(%g5, %g1, %g2, %g3, %g4)
	/* trapstat expects tte in %g5 */
	retry

	/*
	 * So, we failed to find a valid TTE to match the faulting
	 * address in either TSB.  There are a few cases that could land
	 * us here:
	 *
	 * 1) This is a kernel VA below 0x80000000.00000000.  We branch
	 *    to sfmmu_tsb_miss_tt to handle the miss.
	 * 2) We missed on a kpm VA, and we didn't find the mapping in the
	 *    4M TSB.  Let segkpm handle it.
	 *
	 * Note that we shouldn't land here in the case of a kpm VA when
	 * kpm_smallpages is active -- we handled that case earlier at
	 * dktsb4m_kpmcheck_small.
	 *
	 * At this point:
	 *  g1 = 8K-indexed primary TSB pointer
	 *  g2 = tag access register
	 *  g3 = 4M-indexed secondary TSB pointer
	 */
dktsb4m_kpmcheck:
	cmp	%g2, %g0
	bl,pn	%xcc, sfmmu_kpm_dtsb_miss
	  nop
	ba,a,pt	%icc, sfmmu_tsb_miss_tt
	  nop

#ifdef sun4v
	/*
	 * User instruction miss w/ single TSB.
	 * The first probe covers 8K, 64K, and 512K page sizes,
	 * because 64K and 512K mappings are replicated off 8K
	 * pointer.
	 *
	 * g1 = tsb8k pointer register
	 * g2 = tag access register
	 * g3 - g6 = scratch registers
	 * g7 = TSB tag to match
	 */
	.align	64
	ALTENTRY(sfmmu_uitlb_fastpath)

	PROBE_1ST_ITSB(%g1, %g7, uitlb_fast_8k_probefail)
	/* g4 - g5 = clobbered by PROBE_1ST_ITSB */
	ba,pn	%xcc, sfmmu_tsb_miss_tt
	  mov	-1, %g3

	/*
	 * User data miss w/ single TSB.
	 * The first probe covers 8K, 64K, and 512K page sizes,
	 * because 64K and 512K mappings are replicated off 8K
	 * pointer.
	 *
	 * g1 = tsb8k pointer register
	 * g2 = tag access register
	 * g3 - g6 = scratch registers
	 * g7 = TSB tag to match
	 */
	.align 64
	ALTENTRY(sfmmu_udtlb_fastpath)

	PROBE_1ST_DTSB(%g1, %g7, udtlb_fast_8k_probefail)
	/* g4 - g5 = clobbered by PROBE_1ST_DTSB */
	ba,pn	%xcc, sfmmu_tsb_miss_tt
	  mov	-1, %g3

	/*
	 * User instruction miss w/ multiple TSBs (sun4v).
	 * The first probe covers 8K, 64K, and 512K page sizes,
	 * because 64K and 512K mappings are replicated off 8K
	 * pointer.  Second probe covers 4M page size only.
	 *
	 * Just like sfmmu_udtlb_slowpath, except:
	 *   o Uses ASI_ITLB_IN
	 *   o checks for execute permission
	 *   o No ISM prediction.
	 *
	 * g1 = tsb8k pointer register
	 * g2 = tag access register
	 * g3 - g6 = scratch registers
	 * g7 = TSB tag to match
	 */
	.align	64
	ALTENTRY(sfmmu_uitlb_slowpath)

	GET_1ST_TSBE_PTR(%g2, %g1, %g4, %g5)
	PROBE_1ST_ITSB(%g1, %g7, uitlb_8k_probefail)
	/* g4 - g5 = clobbered here */

	GET_2ND_TSBE_PTR(%g2, %g3, %g4, %g5)
	/* g1 = first TSB pointer, g3 = second TSB pointer */
	srlx	%g2, TAG_VALO_SHIFT, %g7
	PROBE_2ND_ITSB(%g3, %g7)
	/* NOT REACHED */

#else /* sun4v */

	/*
	 * User instruction miss w/ multiple TSBs (sun4u).
	 * The first probe covers 8K, 64K, and 512K page sizes,
	 * because 64K and 512K mappings are replicated off 8K
	 * pointer.  Probe of 1st TSB has already been done prior to entry
	 * into this routine. For the UTSB_PHYS case we probe up to 3
	 * valid other TSBs in the following order:
	 * 1) shared TSB for 4M-256M pages
	 * 2) private TSB for 4M-256M pages
	 * 3) shared TSB for 8K-512K pages
	 *
	 * For the non UTSB_PHYS case we probe the 2nd TSB here that backs
	 * 4M-256M pages.
	 *
	 * Just like sfmmu_udtlb_slowpath, except:
	 *   o Uses ASI_ITLB_IN
	 *   o checks for execute permission
	 *   o No ISM prediction.
	 *
	 * g1 = tsb8k pointer register
	 * g2 = tag access register
	 * g4 - g6 = scratch registers
	 * g7 = TSB tag to match
	 */
	.align	64
	ALTENTRY(sfmmu_uitlb_slowpath)

#ifdef UTSB_PHYS

       GET_UTSBREG(SCRATCHPAD_UTSBREG4, %g6)
        brlz,pt %g6, 1f
          nop
        GET_4TH_TSBE_PTR(%g2, %g6, %g4, %g5)
        PROBE_4TH_ITSB(%g6, %g7, uitlb_4m_scd_probefail)
1:
        GET_UTSBREG(SCRATCHPAD_UTSBREG2, %g3)
        brlz,pt %g3, 2f
          nop
        GET_2ND_TSBE_PTR(%g2, %g3, %g4, %g5)
        PROBE_2ND_ITSB(%g3, %g7, uitlb_4m_probefail)
2:
        GET_UTSBREG(SCRATCHPAD_UTSBREG3, %g6)
        brlz,pt %g6, sfmmu_tsb_miss_tt
          nop
        GET_3RD_TSBE_PTR(%g2, %g6, %g4, %g5)
        PROBE_3RD_ITSB(%g6, %g7, uitlb_8K_scd_probefail)
        ba,pn   %xcc, sfmmu_tsb_miss_tt
          nop

#else /* UTSB_PHYS */
	mov	%g1, %g3	/* save tsb8k reg in %g3 */
	GET_1ST_TSBE_PTR(%g3, %g1, %g5, sfmmu_uitlb)
	PROBE_1ST_ITSB(%g1, %g7, uitlb_8k_probefail)
	mov	%g2, %g6	/* GET_2ND_TSBE_PTR clobbers tagacc */
	mov	%g3, %g7	/* copy tsb8k reg in %g7 */
	GET_2ND_TSBE_PTR(%g6, %g7, %g3, %g4, %g5, sfmmu_uitlb)
       /* g1 = first TSB pointer, g3 = second TSB pointer */
        srlx    %g2, TAG_VALO_SHIFT, %g7
        PROBE_2ND_ITSB(%g3, %g7, isynth)
	ba,pn	%xcc, sfmmu_tsb_miss_tt
	  nop

#endif /* UTSB_PHYS */
#endif /* sun4v */

#if defined(sun4u) && defined(UTSB_PHYS)

        /*
	 * We come here for ism predict DTLB_MISS case or if
	 * if probe in first TSB failed.
         */

        .align 64
        ALTENTRY(sfmmu_udtlb_slowpath_noismpred)

	/*
         * g1 = tsb8k pointer register
         * g2 = tag access register
         * g4 - %g6 = scratch registers
         * g7 = TSB tag to match
	 */

	/*
	 * ISM non-predict probe order
         * probe 1ST_TSB (8K index)
         * probe 2ND_TSB (4M index)
         * probe 4TH_TSB (4M index)
         * probe 3RD_TSB (8K index)
	 *
	 * We already probed first TSB in DTLB_MISS handler.
	 */

        /*
         * Private 2ND TSB 4M-256 pages
         */
	GET_UTSBREG(SCRATCHPAD_UTSBREG2, %g3)
	brlz,pt %g3, 1f
	  nop
        GET_2ND_TSBE_PTR(%g2, %g3, %g4, %g5)
        PROBE_2ND_DTSB(%g3, %g7, udtlb_4m_probefail)

	/*
	 * Shared Context 4TH TSB 4M-256 pages
	 */
1:
	GET_UTSBREG(SCRATCHPAD_UTSBREG4, %g6)
	brlz,pt %g6, 2f
	  nop
        GET_4TH_TSBE_PTR(%g2, %g6, %g4, %g5)
        PROBE_4TH_DTSB(%g6, %g7, udtlb_4m_shctx_probefail)

        /*
         * Shared Context 3RD TSB 8K-512K pages
         */
2:
	GET_UTSBREG(SCRATCHPAD_UTSBREG3, %g6)
	brlz,pt %g6, sfmmu_tsb_miss_tt
	  nop
        GET_3RD_TSBE_PTR(%g2, %g6, %g4, %g5)
        PROBE_3RD_DTSB(%g6, %g7, udtlb_8k_shctx_probefail)
	ba,pn	%xcc, sfmmu_tsb_miss_tt
	  nop

	.align 64
        ALTENTRY(sfmmu_udtlb_slowpath_ismpred)

	/*
         * g1 = tsb8k pointer register
         * g2 = tag access register
         * g4 - g6 = scratch registers
         * g7 = TSB tag to match
	 */

	/*
	 * ISM predict probe order
	 * probe 4TH_TSB (4M index)
	 * probe 2ND_TSB (4M index)
	 * probe 1ST_TSB (8K index)
	 * probe 3RD_TSB (8K index)

	/*
	 * Shared Context 4TH TSB 4M-256 pages
	 */
	GET_UTSBREG(SCRATCHPAD_UTSBREG4, %g6)
	brlz,pt %g6, 4f
	  nop
        GET_4TH_TSBE_PTR(%g2, %g6, %g4, %g5)
        PROBE_4TH_DTSB(%g6, %g7, udtlb_4m_shctx_probefail2)

        /*
         * Private 2ND TSB 4M-256 pages
         */
4:
	GET_UTSBREG(SCRATCHPAD_UTSBREG2, %g3)
	brlz,pt %g3, 5f
	  nop
        GET_2ND_TSBE_PTR(%g2, %g3, %g4, %g5)
        PROBE_2ND_DTSB(%g3, %g7, udtlb_4m_probefail2)

5:
        PROBE_1ST_DTSB(%g1, %g7, udtlb_8k_first_probefail2)

        /*
         * Shared Context 3RD TSB 8K-512K pages
         */
	GET_UTSBREG(SCRATCHPAD_UTSBREG3, %g6)
	brlz,pt %g6, 6f
	  nop
        GET_3RD_TSBE_PTR(%g2, %g6, %g4, %g5)
        PROBE_3RD_DTSB(%g6, %g7, udtlb_8k_shctx_probefail2)
6:
	ba,pn	%xcc, sfmmu_tsb_miss_tt /* ISM Predict and ISM non-predict path */
	  nop

#else /* sun4u && UTSB_PHYS */

       .align 64
        ALTENTRY(sfmmu_udtlb_slowpath)

	srax	%g2, PREDISM_BASESHIFT, %g6	/* g6 > 0 : ISM predicted */
	brgz,pn %g6, udtlb_miss_probesecond	/* check for ISM */
	  mov	%g1, %g3

udtlb_miss_probefirst:
	/*
	 * g1 = 8K TSB pointer register
	 * g2 = tag access register
	 * g3 = (potentially) second TSB entry ptr
	 * g6 = ism pred.
	 * g7 = vpg_4m
	 */
#ifdef sun4v
	GET_1ST_TSBE_PTR(%g2, %g1, %g4, %g5)
	PROBE_1ST_DTSB(%g1, %g7, udtlb_first_probefail)

	/*
	 * Here:
	 *   g1 = first TSB pointer
	 *   g2 = tag access reg
	 *   g3 = second TSB ptr IFF ISM pred. (else don't care)
	 */
	brgz,pn	%g6, sfmmu_tsb_miss_tt
	  nop
#else /* sun4v */
	mov	%g1, %g4
	GET_1ST_TSBE_PTR(%g4, %g1, %g5, sfmmu_udtlb)
	PROBE_1ST_DTSB(%g1, %g7, udtlb_first_probefail)

	/*
	 * Here:
	 *   g1 = first TSB pointer
	 *   g2 = tag access reg
	 *   g3 = second TSB ptr IFF ISM pred. (else don't care)
	 */
	brgz,pn	%g6, sfmmu_tsb_miss_tt
	  nop
	ldxa	[%g0]ASI_DMMU_TSB_8K, %g3
	/* fall through in 8K->4M probe order */
#endif /* sun4v */

udtlb_miss_probesecond:
	/*
	 * Look in the second TSB for the TTE
	 * g1 = First TSB entry ptr if !ISM pred, TSB8K ptr reg if ISM pred.
	 * g2 = tag access reg
	 * g3 = 8K TSB pointer register
	 * g6 = ism pred.
	 * g7 = vpg_4m
	 */
#ifdef sun4v
	/* GET_2ND_TSBE_PTR(tagacc, tsbe_ptr, tmp1, tmp2) */
	GET_2ND_TSBE_PTR(%g2, %g3, %g4, %g5)
	/* %g2 is okay, no need to reload, %g3 = second tsbe ptr */
#else /* sun4v */
	mov	%g3, %g7
	GET_2ND_TSBE_PTR(%g2, %g7, %g3, %g4, %g5, sfmmu_udtlb)
	/* %g2 clobbered, %g3 =second tsbe ptr */
	mov	MMU_TAG_ACCESS, %g2
	ldxa	[%g2]ASI_DMMU, %g2
#endif /* sun4v */

	srlx	%g2, TAG_VALO_SHIFT, %g7
	PROBE_2ND_DTSB(%g3, %g7, udtlb_4m_probefail)
	/* g4 - g5 = clobbered here; %g7 still vpg_4m at this point */
	brgz,pn	%g6, udtlb_miss_probefirst
	  nop

	/* fall through to sfmmu_tsb_miss_tt */
#endif /* sun4u && UTSB_PHYS */


	ALTENTRY(sfmmu_tsb_miss_tt)
	TT_TRACE(trace_tsbmiss)
	/*
	 * We get here if there is a TSB miss OR a write protect trap.
	 *
	 * g1 = First TSB entry pointer
	 * g2 = tag access register
	 * g3 = 4M TSB entry pointer; -1 if no 2nd TSB
	 * g4 - g7 = scratch registers
	 */

	ALTENTRY(sfmmu_tsb_miss)

	/*
	 * If trapstat is running, we need to shift the %tpc and %tnpc to
	 * point to trapstat's TSB miss return code (note that trapstat
	 * itself will patch the correct offset to add).
	 */
	rdpr	%tl, %g7
	cmp	%g7, 1
	ble,pt	%xcc, 0f
	  sethi	%hi(KERNELBASE), %g6
	rdpr	%tpc, %g7
	or	%g6, %lo(KERNELBASE), %g6
	cmp	%g7, %g6
	bgeu,pt	%xcc, 0f
	/* delay slot safe */

	ALTENTRY(tsbmiss_trapstat_patch_point)
	add	%g7, RUNTIME_PATCH, %g7	/* must match TSTAT_TSBMISS_INSTR */
	wrpr	%g7, %tpc
	add	%g7, 4, %g7
	wrpr	%g7, %tnpc
0:
	CPU_TSBMISS_AREA(%g6, %g7)
	stn	%g1, [%g6 + TSBMISS_TSBPTR]	/* save 1ST tsb pointer */
	stn	%g3, [%g6 + TSBMISS_TSBPTR4M]	/* save 2ND tsb pointer */

	sllx	%g2, TAGACC_CTX_LSHIFT, %g3
	brz,a,pn %g3, 1f			/* skip ahead if kernel */
	  ldn	[%g6 + TSBMISS_KHATID], %g7
	srlx	%g3, TAGACC_CTX_LSHIFT, %g3	/* g3 = ctxnum */
	ldn	[%g6 + TSBMISS_UHATID], %g7     /* g7 = hatid */

	HAT_PERCPU_STAT32(%g6, TSBMISS_UTSBMISS, %g5)

	cmp	%g3, INVALID_CONTEXT
	be,pn	%icc, tsb_tl0_noctxt		/* no ctx miss exception */
	  stn	%g7, [%g6 + (TSBMISS_SCRATCH + TSBMISS_HATID)]

#if defined(sun4v) || defined(UTSB_PHYS)
        ldub    [%g6 + TSBMISS_URTTEFLAGS], %g7	/* clear ctx1 flag set from */
        andn    %g7, HAT_CHKCTX1_FLAG, %g7	/* the previous tsb miss    */
        stub    %g7, [%g6 + TSBMISS_URTTEFLAGS]
#endif /* sun4v || UTSB_PHYS */

	ISM_CHECK(%g2, %g6, %g3, %g4, %g5, %g7, %g1, tsb_l1, tsb_ism)
	/*
	 * The miss wasn't in an ISM segment.
	 *
	 * %g1 %g3, %g4, %g5, %g7 all clobbered
	 * %g2 = (pseudo) tag access
	 */

	ba,pt	%icc, 2f
	  ldn	[%g6 + (TSBMISS_SCRATCH + TSBMISS_HATID)], %g7

1:
	HAT_PERCPU_STAT32(%g6, TSBMISS_KTSBMISS, %g5)
	/*
	 * 8K and 64K hash.
	 */
2:

	GET_TTE(%g2, %g7, %g3, %g4, %g6, %g1,
		MMU_PAGESHIFT64K, TTE64K, %g5, tsb_l8K, tsb_checktte,
		sfmmu_suspend_tl, tsb_512K)
	/* NOT REACHED */

tsb_512K:
	sllx	%g2, TAGACC_CTX_LSHIFT, %g5
	brz,pn	%g5, 3f
	  ldub	[%g6 + TSBMISS_UTTEFLAGS], %g4
	and	%g4, HAT_512K_FLAG, %g5

	/*
	 * Note that there is a small window here where we may have
	 * a 512k page in the hash list but have not set the HAT_512K_FLAG
	 * flag yet, so we will skip searching the 512k hash list.
	 * In this case we will end up in pagefault which will find
	 * the mapping and return.  So, in this instance we will end up
	 * spending a bit more time resolving this TSB miss, but it can
	 * only happen once per process and even then, the chances of that
	 * are very small, so it's not worth the extra overhead it would
	 * take to close this window.
	 */
	brz,pn	%g5, tsb_4M
	  nop
3:
	/*
	 * 512K hash
	 */

	GET_TTE(%g2, %g7, %g3, %g4, %g6, %g1,
		MMU_PAGESHIFT512K, TTE512K, %g5, tsb_l512K, tsb_checktte,
		sfmmu_suspend_tl, tsb_4M)
	/* NOT REACHED */

tsb_4M:
	sllx	%g2, TAGACC_CTX_LSHIFT, %g5
	brz,pn	%g5, 4f
	  ldub	[%g6 + TSBMISS_UTTEFLAGS], %g4
	and	%g4, HAT_4M_FLAG, %g5
	brz,pn	%g5, tsb_32M
	  nop
4:
	/*
	 * 4M hash
	 */

	GET_TTE(%g2, %g7, %g3, %g4, %g6, %g1,
		MMU_PAGESHIFT4M, TTE4M, %g5, tsb_l4M, tsb_checktte,
		sfmmu_suspend_tl, tsb_32M)
	/* NOT REACHED */

tsb_32M:
	sllx	%g2, TAGACC_CTX_LSHIFT, %g5
#ifdef	sun4v
        brz,pn	%g5, 6f
#else
	brz,pn  %g5, tsb_pagefault
#endif
	  ldub	[%g6 + TSBMISS_UTTEFLAGS], %g4
	and	%g4, HAT_32M_FLAG, %g5
	brz,pn	%g5, tsb_256M
	  nop
5:
	/*
	 * 32M hash
	 */

	GET_TTE(%g2, %g7, %g3, %g4, %g6, %g1,
		MMU_PAGESHIFT32M, TTE32M, %g5, tsb_l32M, tsb_checktte,
		sfmmu_suspend_tl, tsb_256M)
	/* NOT REACHED */

#if defined(sun4u) && !defined(UTSB_PHYS)
#define tsb_shme        tsb_pagefault
#endif
tsb_256M:
	ldub	[%g6 + TSBMISS_UTTEFLAGS], %g4
	and	%g4, HAT_256M_FLAG, %g5
	brz,pn	%g5, tsb_shme
	  nop
6:
	/*
	 * 256M hash
	 */

	GET_TTE(%g2, %g7, %g3, %g4, %g6, %g1,
	    MMU_PAGESHIFT256M, TTE256M, %g5, tsb_l256M, tsb_checktte,
	    sfmmu_suspend_tl, tsb_shme)
	/* NOT REACHED */

tsb_checktte:
	/*
	 * g1 = hblk_misc
	 * g2 = tagacc
	 * g3 = tte
	 * g4 = tte pa
	 * g6 = tsbmiss area
	 * g7 = hatid
	 */
	brlz,a,pt %g3, tsb_validtte
	  rdpr	%tt, %g7

#if defined(sun4u) && !defined(UTSB_PHYS)
#undef tsb_shme
	ba      tsb_pagefault
	  nop
#else /* sun4u && !UTSB_PHYS */

tsb_shme:
	/*
	 * g2 = tagacc
	 * g6 = tsbmiss area
	 */
	sllx	%g2, TAGACC_CTX_LSHIFT, %g5
	brz,pn	%g5, tsb_pagefault
	  nop
	ldx	[%g6 + TSBMISS_SHARED_UHATID], %g7	/* g7 = srdp */
	brz,pn	%g7, tsb_pagefault
	  nop

	GET_SHME_TTE(%g2, %g7, %g3, %g4, %g6, %g1,
		MMU_PAGESHIFT64K, TTE64K, %g5, tsb_shme_l8K, tsb_shme_checktte,
		sfmmu_suspend_tl, tsb_shme_512K)
	/* NOT REACHED */

tsb_shme_512K:
	ldub	[%g6 + TSBMISS_URTTEFLAGS], %g4
	and	%g4, HAT_512K_FLAG, %g5
	brz,pn	%g5, tsb_shme_4M
	  nop

	/*
	 * 512K hash
	 */

	GET_SHME_TTE(%g2, %g7, %g3, %g4, %g6, %g1,
		MMU_PAGESHIFT512K, TTE512K, %g5, tsb_shme_l512K, tsb_shme_checktte,
		sfmmu_suspend_tl, tsb_shme_4M)
	/* NOT REACHED */

tsb_shme_4M:
	ldub	[%g6 + TSBMISS_URTTEFLAGS], %g4
	and	%g4, HAT_4M_FLAG, %g5
	brz,pn	%g5, tsb_shme_32M
	  nop
4:
	/*
	 * 4M hash
	 */
	GET_SHME_TTE(%g2, %g7, %g3, %g4, %g6, %g1,
		MMU_PAGESHIFT4M, TTE4M, %g5, tsb_shme_l4M, tsb_shme_checktte,
		sfmmu_suspend_tl, tsb_shme_32M)
	/* NOT REACHED */

tsb_shme_32M:
	ldub	[%g6 + TSBMISS_URTTEFLAGS], %g4
	and	%g4, HAT_32M_FLAG, %g5
	brz,pn	%g5, tsb_shme_256M
	  nop

	/*
	 * 32M hash
	 */

	GET_SHME_TTE(%g2, %g7, %g3, %g4, %g6, %g1,
		MMU_PAGESHIFT32M, TTE32M, %g5, tsb_shme_l32M, tsb_shme_checktte,
		sfmmu_suspend_tl, tsb_shme_256M)
	/* NOT REACHED */

tsb_shme_256M:
	ldub	[%g6 + TSBMISS_URTTEFLAGS], %g4
	and	%g4, HAT_256M_FLAG, %g5
	brz,pn	%g5, tsb_pagefault
	  nop

	/*
	 * 256M hash
	 */

	GET_SHME_TTE(%g2, %g7, %g3, %g4, %g6, %g1,
	    MMU_PAGESHIFT256M, TTE256M, %g5, tsb_shme_l256M, tsb_shme_checktte,
	    sfmmu_suspend_tl, tsb_pagefault)
	/* NOT REACHED */

tsb_shme_checktte:

	brgez,pn %g3, tsb_pagefault
	  rdpr	%tt, %g7
	/*
	 * g1 = ctx1 flag
	 * g3 = tte
	 * g4 = tte pa
	 * g6 = tsbmiss area
	 * g7 = tt
	 */

	brz,pt  %g1, tsb_validtte
	  nop
	ldub    [%g6 + TSBMISS_URTTEFLAGS], %g1
	  or	%g1, HAT_CHKCTX1_FLAG, %g1
	stub    %g1, [%g6 + TSBMISS_URTTEFLAGS]

	SAVE_CTX1(%g7, %g2, %g1, tsb_shmel)
#endif /* sun4u && !UTSB_PHYS */

tsb_validtte:
	/*
	 * g3 = tte
	 * g4 = tte pa
	 * g6 = tsbmiss area
	 * g7 = tt
	 */

	/*
	 * Set ref/mod bits if this is a prot trap.  Usually, it isn't.
	 */
	cmp	%g7, FAST_PROT_TT
	bne,pt	%icc, 4f
	  nop

	TTE_SET_REFMOD_ML(%g3, %g4, %g6, %g7, %g5, tsb_lset_refmod,
	    tsb_protfault)

	GET_MMU_D_TTARGET(%g2, %g7)		/* %g2 = ttarget */
#ifdef sun4v
	MMU_FAULT_STATUS_AREA(%g7)
	ldx	[%g7 + MMFSA_D_ADDR], %g5	/* load fault addr for later */
#else /* sun4v */
	mov     MMU_TAG_ACCESS, %g5
	ldxa    [%g5]ASI_DMMU, %g5
#endif /* sun4v */
	ba,pt	%xcc, tsb_update_tl1
	  nop
4:
	/*
	 * If ITLB miss check exec bit.
	 * If not set treat as invalid TTE.
	 */
	cmp     %g7, T_INSTR_MMU_MISS
	be,pn	%icc, 5f
	  andcc   %g3, TTE_EXECPRM_INT, %g0	/* check execute bit is set */
	cmp     %g7, FAST_IMMU_MISS_TT
	bne,pt %icc, 3f
	  andcc   %g3, TTE_EXECPRM_INT, %g0	/* check execute bit is set */
5:
	bz,pn %icc, tsb_protfault
	  nop

3:
	/*
	 * Set reference bit if not already set
	 */
	TTE_SET_REF_ML(%g3, %g4, %g6, %g7, %g5, tsb_lset_ref)

	/*
	 * Now, load into TSB/TLB.  At this point:
	 * g3 = tte
	 * g4 = patte
	 * g6 = tsbmiss area
	 */
	rdpr	%tt, %g7
#ifdef sun4v
	MMU_FAULT_STATUS_AREA(%g2)
	cmp	%g7, T_INSTR_MMU_MISS
	be,a,pt	%icc, 9f
	  nop
	cmp	%g7, FAST_IMMU_MISS_TT
	be,a,pt	%icc, 9f
	  nop
	add	%g2, MMFSA_D_, %g2
9:
	ldx	[%g2 + MMFSA_CTX_], %g7
	sllx	%g7, TTARGET_CTX_SHIFT, %g7
	ldx	[%g2 + MMFSA_ADDR_], %g2
	mov	%g2, %g5		! load the fault addr for later use
	srlx	%g2, TTARGET_VA_SHIFT, %g2
	or	%g2, %g7, %g2
#else /* sun4v */
	mov     MMU_TAG_ACCESS, %g5
	cmp     %g7, FAST_IMMU_MISS_TT
	be,a,pt %icc, 9f
	   ldxa  [%g0]ASI_IMMU, %g2
	ldxa    [%g0]ASI_DMMU, %g2
	ba,pt   %icc, tsb_update_tl1
	   ldxa  [%g5]ASI_DMMU, %g5
9:
	ldxa    [%g5]ASI_IMMU, %g5
#endif /* sun4v */

tsb_update_tl1:
	srlx	%g2, TTARGET_CTX_SHIFT, %g7
	brz,pn	%g7, tsb_kernel
#ifdef sun4v
	  and	%g3, TTE_SZ_BITS, %g7	! assumes TTE_SZ_SHFT is 0
#else  /* sun4v */
	  srlx	%g3, TTE_SZ_SHFT, %g7
#endif /* sun4v */

tsb_user:
#ifdef sun4v
	cmp	%g7, TTE4M
	bge,pn	%icc, tsb_user4m
	  nop
#else /* sun4v */
	cmp	%g7, TTESZ_VALID | TTE4M
	be,pn	%icc, tsb_user4m
	  srlx	%g3, TTE_SZ2_SHFT, %g7
	andcc	%g7, TTE_SZ2_BITS, %g7		! check 32/256MB
#ifdef ITLB_32M_256M_SUPPORT
	bnz,pn	%icc, tsb_user4m
	  nop
#else /* ITLB_32M_256M_SUPPORT */
	bnz,a,pn %icc, tsb_user_pn_synth
	 nop
#endif /* ITLB_32M_256M_SUPPORT */
#endif /* sun4v */

tsb_user8k:
#if defined(sun4v) || defined(UTSB_PHYS)
	ldub	[%g6 + TSBMISS_URTTEFLAGS], %g7
	and	%g7, HAT_CHKCTX1_FLAG, %g1
	brz,a,pn %g1, 1f
	  ldn	[%g6 + TSBMISS_TSBPTR], %g1		! g1 = 1ST TSB ptr
	GET_UTSBREG_SHCTX(%g6, TSBMISS_TSBSCDPTR, %g1)
	brlz,a,pn %g1, ptl1_panic			! if no shared 3RD tsb
	  mov PTL1_NO_SCDTSB8K, %g1			! panic
        GET_3RD_TSBE_PTR(%g5, %g1, %g6, %g7)
1:
#else /* defined(sun4v) || defined(UTSB_PHYS) */
	ldn   [%g6 + TSBMISS_TSBPTR], %g1             ! g1 = 1ST TSB ptr
#endif /* defined(sun4v) || defined(UTSB_PHYS) */

#ifndef UTSB_PHYS
	mov	ASI_N, %g7	! user TSBs accessed by VA
	mov	%g7, %asi
#endif /* !UTSB_PHYS */

	TSB_UPDATE_TL(%g1, %g3, %g2, %g4, %g7, %g6, locked_tsb_l3)

	rdpr    %tt, %g5
#ifdef sun4v
	cmp	%g5, T_INSTR_MMU_MISS
	be,a,pn	%xcc, 9f
	  mov	%g3, %g5
#endif /* sun4v */
	cmp	%g5, FAST_IMMU_MISS_TT
	be,pn	%xcc, 9f
	  mov	%g3, %g5

	DTLB_STUFF(%g5, %g1, %g2, %g3, %g4)
	! trapstat wants TTE in %g5
	retry
9:
	ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)
	! trapstat wants TTE in %g5
	retry

tsb_user4m:
#if defined(sun4v) || defined(UTSB_PHYS)
	ldub	[%g6 + TSBMISS_URTTEFLAGS], %g7
	and	%g7, HAT_CHKCTX1_FLAG, %g1
	brz,a,pn %g1, 4f
	  ldn	[%g6 + TSBMISS_TSBPTR4M], %g1		! g1 = 2ND TSB ptr
	GET_UTSBREG_SHCTX(%g6, TSBMISS_TSBSCDPTR4M, %g1)! g1 = 4TH TSB ptr
	brlz,a,pn %g1, 5f				! if no shared 4TH TSB
	  nop
        GET_4TH_TSBE_PTR(%g5, %g1, %g6, %g7)

#else /* defined(sun4v) || defined(UTSB_PHYS) */
	ldn   [%g6 + TSBMISS_TSBPTR4M], %g1             ! g1 = 2ND TSB ptr
#endif /* defined(sun4v) || defined(UTSB_PHYS) */
4:
	brlz,pn %g1, 5f	/* Check to see if we have 2nd TSB programmed */
	  nop

#ifndef UTSB_PHYS
	mov	ASI_N, %g7	! user TSBs accessed by VA
	mov	%g7, %asi
#endif /* UTSB_PHYS */

        TSB_UPDATE_TL(%g1, %g3, %g2, %g4, %g7, %g6, locked_tsb_l4)

5:
	rdpr    %tt, %g5
#ifdef sun4v
        cmp     %g5, T_INSTR_MMU_MISS
        be,a,pn %xcc, 9f
          mov   %g3, %g5
#endif /* sun4v */
        cmp     %g5, FAST_IMMU_MISS_TT
        be,pn   %xcc, 9f
        mov     %g3, %g5

        DTLB_STUFF(%g5, %g1, %g2, %g3, %g4)
        ! trapstat wants TTE in %g5
        retry
9:
        ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)
        ! trapstat wants TTE in %g5
        retry

#if !defined(sun4v) && !defined(ITLB_32M_256M_SUPPORT)
	/*
	 * Panther ITLB synthesis.
	 * The Panther 32M and 256M ITLB code simulates these two large page
	 * sizes with 4M pages, to provide support for programs, for example
	 * Java, that may copy instructions into a 32M or 256M data page and
	 * then execute them. The code below generates the 4M pfn bits and
	 * saves them in the modified 32M/256M ttes in the TSB. If the tte is
	 * stored in the DTLB to map a 32M/256M page, the 4M pfn offset bits
	 * are ignored by the hardware.
	 *
	 * Now, load into TSB/TLB.  At this point:
	 * g2 = tagtarget
	 * g3 = tte
	 * g4 = patte
	 * g5 = tt
	 * g6 = tsbmiss area
	 */
tsb_user_pn_synth:
	rdpr %tt, %g5
	cmp    %g5, FAST_IMMU_MISS_TT
	be,pt	%xcc, tsb_user_itlb_synth	/* ITLB miss */
	  andcc %g3, TTE_EXECPRM_INT, %g0	/* is execprm bit set */
	bz,pn %icc, 4b				/* if not, been here before */
	  ldn	[%g6 + TSBMISS_TSBPTR4M], %g1	/* g1 = tsbp */
	brlz,a,pn %g1, 5f			/* no 2nd tsb */
	  mov	%g3, %g5

	mov	MMU_TAG_ACCESS, %g7
	ldxa	[%g7]ASI_DMMU, %g6		/* get tag access va */
	GET_4M_PFN_OFF(%g3, %g6, %g5, %g7, 1)	/* make 4M pfn offset */

	mov	ASI_N, %g7	/* user TSBs always accessed by VA */
	mov	%g7, %asi
	TSB_UPDATE_TL_PN(%g1, %g5, %g2, %g4, %g7, %g3, locked_tsb_l5) /* update TSB */
5:
        DTLB_STUFF(%g5, %g1, %g2, %g3, %g4)
        retry

tsb_user_itlb_synth:
	ldn	[%g6 + TSBMISS_TSBPTR4M], %g1		/* g1 =  2ND TSB */

	mov	MMU_TAG_ACCESS, %g7
	ldxa	[%g7]ASI_IMMU, %g6		/* get tag access va */
	GET_4M_PFN_OFF(%g3, %g6, %g5, %g7, 2)	/* make 4M pfn offset */
	brlz,a,pn %g1, 7f	/* Check to see if we have 2nd TSB programmed */
	  or	%g5, %g3, %g5			/* add 4M bits to TTE */

	mov	ASI_N, %g7	/* user TSBs always accessed by VA */
	mov	%g7, %asi
	TSB_UPDATE_TL_PN(%g1, %g5, %g2, %g4, %g7, %g3, locked_tsb_l6) /* update TSB */
7:
	SET_TTE4M_PN(%g5, %g7)			/* add TTE4M pagesize to TTE */
        ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)
        retry
#endif /* sun4v && ITLB_32M_256M_SUPPORT */

tsb_kernel:
	rdpr	%tt, %g5
#ifdef sun4v
	cmp	%g7, TTE4M
	bge,pn	%icc, 5f
#else
	cmp	%g7, TTESZ_VALID | TTE4M	! no 32M or 256M support
	be,pn	%icc, 5f
#endif /* sun4v */
	  nop
	ldn	[%g6 + TSBMISS_TSBPTR], %g1	! g1 = 8K TSB ptr
	ba,pt	%xcc, 6f
	  nop
5:
	ldn	[%g6 + TSBMISS_TSBPTR4M], %g1	! g1 = 4M TSB ptr
	brlz,pn	%g1, 3f		/* skip programming if 4M TSB ptr is -1 */
	  nop
6:
#ifndef sun4v
tsb_kernel_patch_asi:
	or	%g0, RUNTIME_PATCH, %g6
	mov	%g6, %asi	! XXX avoid writing to %asi !!
#endif
	TSB_UPDATE_TL(%g1, %g3, %g2, %g4, %g7, %g6, locked_tsb_l7)
3:
#ifdef sun4v
	cmp	%g5, T_INSTR_MMU_MISS
	be,a,pn	%icc, 1f
	  mov	%g3, %g5			! trapstat wants TTE in %g5
#endif /* sun4v */
	cmp	%g5, FAST_IMMU_MISS_TT
	be,pn	%icc, 1f
	  mov	%g3, %g5			! trapstat wants TTE in %g5
	DTLB_STUFF(%g5, %g1, %g2, %g3, %g4)
	! trapstat wants TTE in %g5
	retry
1:
	ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)
	! trapstat wants TTE in %g5
	retry

tsb_ism:
	/*
	 * This is an ISM [i|d]tlb miss.  We optimize for largest
	 * page size down to smallest.
	 *
	 * g2 = vaddr + ctx(or ctxtype (sun4v)) aka (pseudo-)tag access
	 *	register
	 * g3 = ismmap->ism_seg
	 * g4 = physical address of ismmap->ism_sfmmu
	 * g6 = tsbmiss area
	 */
	ldna	[%g4]ASI_MEM, %g7		/* g7 = ism hatid */
	brz,a,pn %g7, ptl1_panic		/* if zero jmp ahead */
	  mov	PTL1_BAD_ISM, %g1
						/* g5 = pa of imap_vb_shift */
	sub	%g4, (IMAP_ISMHAT - IMAP_VB_SHIFT), %g5
	lduba	[%g5]ASI_MEM, %g4		/* g4 = imap_vb_shift */
	srlx	%g3, %g4, %g3			/* clr size field */
	set	TAGACC_CTX_MASK, %g1		/* mask off ctx number */
	sllx    %g3, %g4, %g3                   /* g3 = ism vbase */
	and     %g2, %g1, %g4                   /* g4 = ctx number */
	andn    %g2, %g1, %g1                   /* g1 = tlb miss vaddr */
	sub     %g1, %g3, %g2                   /* g2 = offset in ISM seg */
	or      %g2, %g4, %g2                   /* g2 = (pseudo-)tagacc */
	sub     %g5, (IMAP_VB_SHIFT - IMAP_HATFLAGS), %g5
	lduha   [%g5]ASI_MEM, %g4               /* g5 = pa of imap_hatflags */
#if defined(sun4v) || defined(UTSB_PHYS)
	and     %g4, HAT_CTX1_FLAG, %g5         /* g5 = imap_hatflags */
	brz,pt %g5, tsb_chk4M_ism
	  nop
	ldub    [%g6 + TSBMISS_URTTEFLAGS], %g5
	or      %g5, HAT_CHKCTX1_FLAG, %g5
	stub    %g5, [%g6 + TSBMISS_URTTEFLAGS]
	rdpr    %tt, %g5
	SAVE_CTX1(%g5, %g3, %g1, tsb_shctxl)
#endif /* defined(sun4v) || defined(UTSB_PHYS) */

	/*
	 * ISM pages are always locked down.
	 * If we can't find the tte then pagefault
	 * and let the spt segment driver resolve it.
	 *
	 * g2 = tagacc w/ISM vaddr (offset in ISM seg)
	 * g4 = imap_hatflags
	 * g6 = tsb miss area
	 * g7 = ISM hatid
	 */

tsb_chk4M_ism:
	and	%g4, HAT_4M_FLAG, %g5		/* g4 = imap_hatflags */
	brnz,pt	%g5, tsb_ism_4M			/* branch if 4M pages */
	  nop

tsb_ism_32M:
	and	%g4, HAT_32M_FLAG, %g5		/* check default 32M next */
	brz,pn	%g5, tsb_ism_256M
	  nop

	/*
	 * 32M hash.
	 */

	GET_TTE(%g2, %g7, %g3, %g4, %g6, %g1, MMU_PAGESHIFT32M,
	    TTE32M, %g5, tsb_ism_l32M, tsb_ism_32M_found, sfmmu_suspend_tl,
	    tsb_ism_4M)
	/* NOT REACHED */

tsb_ism_32M_found:
	brlz,a,pt %g3, tsb_validtte
	  rdpr	%tt, %g7
	ba,pt	%xcc, tsb_ism_4M
	  nop

tsb_ism_256M:
	and	%g4, HAT_256M_FLAG, %g5		/* 256M is last resort */
	brz,a,pn %g5, ptl1_panic
	  mov	PTL1_BAD_ISM, %g1

	/*
	 * 256M hash.
	 */
	GET_TTE(%g2, %g7, %g3, %g4, %g6, %g1, MMU_PAGESHIFT256M,
	    TTE256M, %g5, tsb_ism_l256M, tsb_ism_256M_found, sfmmu_suspend_tl,
	    tsb_ism_4M)

tsb_ism_256M_found:
	brlz,a,pt %g3, tsb_validtte
	  rdpr	%tt, %g7

tsb_ism_4M:
	/*
	 * 4M hash.
	 */
	GET_TTE(%g2, %g7, %g3, %g4, %g6, %g1, MMU_PAGESHIFT4M,
	    TTE4M, %g5, tsb_ism_l4M, tsb_ism_4M_found, sfmmu_suspend_tl,
	    tsb_ism_8K)
	/* NOT REACHED */

tsb_ism_4M_found:
	brlz,a,pt %g3, tsb_validtte
	  rdpr	%tt, %g7

tsb_ism_8K:
	/*
	 * 8K and 64K hash.
	 */

	GET_TTE(%g2, %g7, %g3, %g4, %g6, %g1, MMU_PAGESHIFT64K,
	    TTE64K, %g5, tsb_ism_l8K, tsb_ism_8K_found, sfmmu_suspend_tl,
	    tsb_pagefault)
	/* NOT REACHED */

tsb_ism_8K_found:
	brlz,a,pt %g3, tsb_validtte
	  rdpr	%tt, %g7

tsb_pagefault:
	rdpr	%tt, %g7
	cmp	%g7, FAST_PROT_TT
	be,a,pn	%icc, tsb_protfault
	  wrpr	%g0, FAST_DMMU_MISS_TT, %tt

tsb_protfault:
	/*
	 * we get here if we couldn't find a valid tte in the hash.
	 *
	 * If user and we are at tl>1 we go to window handling code.
	 *
	 * If kernel and the fault is on the same page as our stack
	 * pointer, then we know the stack is bad and the trap handler
	 * will fail, so we call ptl1_panic with PTL1_BAD_STACK.
	 *
	 * If this is a kernel trap and tl>1, panic.
	 *
	 * Otherwise we call pagefault.
	 */
	cmp	%g7, FAST_IMMU_MISS_TT
#ifdef sun4v
	MMU_FAULT_STATUS_AREA(%g4)
	ldx	[%g4 + MMFSA_I_CTX], %g5
	ldx	[%g4 + MMFSA_D_CTX], %g4
	move	%icc, %g5, %g4
	cmp	%g7, T_INSTR_MMU_MISS
	move	%icc, %g5, %g4
#else
	mov	MMU_TAG_ACCESS, %g4
	ldxa	[%g4]ASI_DMMU, %g2
	ldxa	[%g4]ASI_IMMU, %g5
	move	%icc, %g5, %g2
	cmp	%g7, T_INSTR_MMU_MISS
	move	%icc, %g5, %g2
	sllx	%g2, TAGACC_CTX_LSHIFT, %g4
#endif /* sun4v */
	brnz,pn	%g4, 3f				/* skip if not kernel */
	  rdpr	%tl, %g5

	add	%sp, STACK_BIAS, %g3
	srlx	%g3, MMU_PAGESHIFT, %g3
	srlx	%g2, MMU_PAGESHIFT, %g4
	cmp	%g3, %g4
	be,a,pn	%icc, ptl1_panic		/* panic if bad %sp */
	  mov	PTL1_BAD_STACK, %g1

	cmp	%g5, 1
	ble,pt	%icc, 2f
	  nop
	TSTAT_CHECK_TL1(2f, %g1, %g2)
	rdpr	%tt, %g2
	cmp	%g2, FAST_PROT_TT
	mov	PTL1_BAD_KPROT_FAULT, %g1
	movne	%icc, PTL1_BAD_KMISS, %g1
	ba,pt	%icc, ptl1_panic
	  nop

2:
	/*
	 * We are taking a pagefault in the kernel on a kernel address.  If
	 * CPU_DTRACE_NOFAULT is set in the cpuc_dtrace_flags, we don't actually
	 * want to call sfmmu_pagefault -- we will instead note that a fault
	 * has occurred by setting CPU_DTRACE_BADADDR and issue a "done"
	 * (instead of a "retry").  This will step over the faulting
	 * instruction.
	 */
	CPU_INDEX(%g1, %g2)
	set	cpu_core, %g2
	sllx	%g1, CPU_CORE_SHIFT, %g1
	add	%g1, %g2, %g1
	lduh	[%g1 + CPUC_DTRACE_FLAGS], %g2
	andcc	%g2, CPU_DTRACE_NOFAULT, %g0
	bz	sfmmu_pagefault
	or	%g2, CPU_DTRACE_BADADDR, %g2
	stuh	%g2, [%g1 + CPUC_DTRACE_FLAGS]
	GET_MMU_D_ADDR(%g3, %g4)
	stx	%g3, [%g1 + CPUC_DTRACE_ILLVAL]
	done

3:
	cmp	%g5, 1
	ble,pt	%icc, 4f
	  nop
	TSTAT_CHECK_TL1(4f, %g1, %g2)
	ba,pt	%icc, sfmmu_window_trap
	  nop

4:
	/*
	 * We are taking a pagefault on a non-kernel address.  If we are in
	 * the kernel (e.g., due to a copyin()), we will check cpuc_dtrace_flags
	 * and (if CPU_DTRACE_NOFAULT is set) will proceed as outlined above.
	 */
	CPU_INDEX(%g1, %g2)
	set	cpu_core, %g2
	sllx	%g1, CPU_CORE_SHIFT, %g1
	add	%g1, %g2, %g1
	lduh	[%g1 + CPUC_DTRACE_FLAGS], %g2
	andcc	%g2, CPU_DTRACE_NOFAULT, %g0
	bz	sfmmu_mmu_trap
	or	%g2, CPU_DTRACE_BADADDR, %g2
	stuh	%g2, [%g1 + CPUC_DTRACE_FLAGS]
	GET_MMU_D_ADDR(%g3, %g4)
	stx	%g3, [%g1 + CPUC_DTRACE_ILLVAL]

	/*
	 * Be sure that we're actually taking this miss from the kernel --
	 * otherwise we have managed to return to user-level with
	 * CPU_DTRACE_NOFAULT set in cpuc_dtrace_flags.
	 */
	rdpr	%tstate, %g2
	btst	TSTATE_PRIV, %g2
	bz,a	ptl1_panic
	  mov	PTL1_BAD_DTRACE_FLAGS, %g1
	done

	ALTENTRY(tsb_tl0_noctxt)
	/*
	 * If we have no context, check to see if CPU_DTRACE_NOFAULT is set;
	 * if it is, indicated that we have faulted and issue a done.
	 */
	CPU_INDEX(%g5, %g6)
	set	cpu_core, %g6
	sllx	%g5, CPU_CORE_SHIFT, %g5
	add	%g5, %g6, %g5
	lduh	[%g5 + CPUC_DTRACE_FLAGS], %g6
	andcc	%g6, CPU_DTRACE_NOFAULT, %g0
	bz	1f
	or	%g6, CPU_DTRACE_BADADDR, %g6
	stuh	%g6, [%g5 + CPUC_DTRACE_FLAGS]
	GET_MMU_D_ADDR(%g3, %g4)
	stx	%g3, [%g5 + CPUC_DTRACE_ILLVAL]

	/*
	 * Be sure that we're actually taking this miss from the kernel --
	 * otherwise we have managed to return to user-level with
	 * CPU_DTRACE_NOFAULT set in cpuc_dtrace_flags.
	 */
	rdpr	%tstate, %g5
	btst	TSTATE_PRIV, %g5
	bz,a	ptl1_panic
	  mov	PTL1_BAD_DTRACE_FLAGS, %g1
	TSTAT_CHECK_TL1(2f, %g1, %g2);
2:
	done

1:
	rdpr	%tt, %g5
	cmp	%g5, FAST_IMMU_MISS_TT
#ifdef sun4v
	MMU_FAULT_STATUS_AREA(%g2)
	be,a,pt	%icc, 2f
	  ldx	[%g2 + MMFSA_I_CTX], %g3
	cmp	%g5, T_INSTR_MMU_MISS
	be,a,pt	%icc, 2f
	  ldx	[%g2 + MMFSA_I_CTX], %g3
	ldx	[%g2 + MMFSA_D_CTX], %g3
2:
#else
	mov	MMU_TAG_ACCESS, %g2
	be,a,pt	%icc, 2f
	  ldxa	[%g2]ASI_IMMU, %g3
	ldxa	[%g2]ASI_DMMU, %g3
2:	sllx	%g3, TAGACC_CTX_LSHIFT, %g3
#endif /* sun4v */
	brz,a,pn %g3, ptl1_panic		! panic if called for kernel
	  mov	PTL1_BAD_CTX_STEAL, %g1		! since kernel ctx was stolen
	rdpr	%tl, %g5
	cmp	%g5, 1
	ble,pt	%icc, sfmmu_mmu_trap
	  nop
	TSTAT_CHECK_TL1(sfmmu_mmu_trap, %g1, %g2)
	ba,pt	%icc, sfmmu_window_trap
	  nop
	SET_SIZE(sfmmu_tsb_miss)
#endif  /* lint */

#if defined (lint)
/*
 * This routine will look for a user or kernel vaddr in the hash
 * structure.  It returns a valid pfn or PFN_INVALID.  It doesn't
 * grab any locks.  It should only be used by other sfmmu routines.
 */
/* ARGSUSED */
pfn_t
sfmmu_vatopfn(caddr_t vaddr, sfmmu_t *sfmmup, tte_t *ttep)
{
	return(0);
}

/* ARGSUSED */
pfn_t
sfmmu_kvaszc2pfn(caddr_t vaddr, int hashno)
{
	return(0);
}

#else /* lint */

	ENTRY_NP(sfmmu_vatopfn)
 	/*
 	 * disable interrupts
 	 */
 	rdpr	%pstate, %o3
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o3, sfmmu_di_l5, %g1)
#endif
	/*
	 * disable interrupts to protect the TSBMISS area
	 */
	andn    %o3, PSTATE_IE, %o5
	wrpr    %o5, 0, %pstate

	/*
	 * o0 = vaddr
	 * o1 = sfmmup
	 * o2 = ttep
	 */
	CPU_TSBMISS_AREA(%g1, %o5)
	ldn	[%g1 + TSBMISS_KHATID], %o4
	cmp	%o4, %o1
	bne,pn	%ncc, vatopfn_nokernel
	  mov	TTE64K, %g5			/* g5 = rehash # */
	mov %g1,%o5				/* o5 = tsbmiss_area */
	/*
	 * o0 = vaddr
	 * o1 & o4 = hatid
	 * o2 = ttep
	 * o5 = tsbmiss area
	 */
	mov	HBLK_RANGE_SHIFT, %g6
1:

	/*
	 * o0 = vaddr
	 * o1 = sfmmup
	 * o2 = ttep
	 * o3 = old %pstate
	 * o4 = hatid
	 * o5 = tsbmiss
	 * g5 = rehash #
	 * g6 = hmeshift
	 *
	 * The first arg to GET_TTE is actually tagaccess register
	 * not just vaddr. Since this call is for kernel we need to clear
	 * any lower vaddr bits that would be interpreted as ctx bits.
	 */
	set     TAGACC_CTX_MASK, %g1
	andn    %o0, %g1, %o0
	GET_TTE(%o0, %o4, %g1, %g2, %o5, %g4, %g6, %g5, %g3,
		vatopfn_l1, kvtop_hblk_found, tsb_suspend, kvtop_nohblk)

kvtop_hblk_found:
	/*
	 * o0 = vaddr
	 * o1 = sfmmup
	 * o2 = ttep
	 * g1 = tte
	 * g2 = tte pa
	 * g3 = scratch
	 * o2 = tsbmiss area
	 * o1 = hat id
	 */
	brgez,a,pn %g1, 6f			/* if tte invalid goto tl0 */
	  mov	-1, %o0				/* output = -1 (PFN_INVALID) */
	stx %g1,[%o2]				/* put tte into *ttep */
	TTETOPFN(%g1, %o0, vatopfn_l2, %g2, %g3, %g4)
	/*
	 * o0 = vaddr
	 * o1 = sfmmup
	 * o2 = ttep
	 * g1 = pfn
	 */
	ba,pt	%xcc, 6f
	  mov	%g1, %o0

kvtop_nohblk:
	/*
	 * we get here if we couldn't find valid hblk in hash.  We rehash
	 * if neccesary.
	 */
	ldn	[%o5 + (TSBMISS_SCRATCH + TSB_TAGACC)], %o0
#ifdef sun4v
	cmp	%g5, MAX_HASHCNT
#else
	cmp	%g5, DEFAULT_MAX_HASHCNT	/* no 32/256M kernel pages */
#endif /* sun4v */
	be,a,pn	%icc, 6f
	  mov	-1, %o0				/* output = -1 (PFN_INVALID) */
	mov	%o1, %o4			/* restore hatid */
#ifdef sun4v
        add	%g5, 2, %g5
	cmp	%g5, 3
	move	%icc, MMU_PAGESHIFT4M, %g6
	ba,pt	%icc, 1b
	movne	%icc, MMU_PAGESHIFT256M, %g6
#else
        inc	%g5
	cmp	%g5, 2
	move	%icc, MMU_PAGESHIFT512K, %g6
	ba,pt	%icc, 1b
	movne	%icc, MMU_PAGESHIFT4M, %g6
#endif /* sun4v */
6:
	retl
 	  wrpr	%g0, %o3, %pstate		/* re-enable interrupts */

tsb_suspend:
	/*
	 * o0 = vaddr
	 * o1 = sfmmup
	 * o2 = ttep
	 * g1 = tte
	 * g2 = tte pa
	 * g3 = tte va
	 * o2 = tsbmiss area  use o5 instead of o2 for tsbmiss
	 */
	stx %g1,[%o2]				/* put tte into *ttep */
	brgez,a,pn %g1, 8f			/* if tte invalid goto 8: */
	  sub	%g0, 1, %o0			/* output = PFN_INVALID */
	sub	%g0, 2, %o0			/* output = PFN_SUSPENDED */
8:
	retl
	 wrpr	%g0, %o3, %pstate		/* enable interrupts */

vatopfn_nokernel:
	/*
	 * This routine does NOT support user addresses
	 * There is a routine in C that supports this.
	 * The only reason why we don't have the C routine
	 * support kernel addresses as well is because
	 * we do va_to_pa while holding the hashlock.
	 */
 	wrpr	%g0, %o3, %pstate		/* re-enable interrupts */
	save	%sp, -SA(MINFRAME), %sp
	sethi	%hi(sfmmu_panic3), %o0
	call	panic
	 or	%o0, %lo(sfmmu_panic3), %o0

	SET_SIZE(sfmmu_vatopfn)

	/*
	 * %o0 = vaddr
	 * %o1 = hashno (aka szc)
	 *
	 *
	 * This routine is similar to sfmmu_vatopfn() but will only look for
	 * a kernel vaddr in the hash structure for the specified rehash value.
	 * It's just an optimization for the case when pagesize for a given
	 * va range is already known (e.g. large page heap) and we don't want
	 * to start the search with rehash value 1 as sfmmu_vatopfn() does.
	 *
	 * Returns valid pfn or PFN_INVALID if
	 * tte for specified rehash # is not found, invalid or suspended.
	 */
	ENTRY_NP(sfmmu_kvaszc2pfn)
 	/*
 	 * disable interrupts
 	 */
 	rdpr	%pstate, %o3
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o3, sfmmu_di_l6, %g1)
#endif
	/*
	 * disable interrupts to protect the TSBMISS area
	 */
	andn    %o3, PSTATE_IE, %o5
	wrpr    %o5, 0, %pstate

	CPU_TSBMISS_AREA(%g1, %o5)
	ldn	[%g1 + TSBMISS_KHATID], %o4
	sll	%o1, 1, %g6
	add	%g6, %o1, %g6
	add	%g6, MMU_PAGESHIFT, %g6
	/*
	 * %o0 = vaddr
	 * %o1 = hashno
	 * %o3 = old %pstate
	 * %o4 = ksfmmup
	 * %g1 = tsbmiss area
	 * %g6 = hmeshift
	 */

	/*
	 * The first arg to GET_TTE is actually tagaccess register
	 * not just vaddr. Since this call is for kernel we need to clear
	 * any lower vaddr bits that would be interpreted as ctx bits.
	 */
	srlx	%o0, MMU_PAGESHIFT, %o0
	sllx	%o0, MMU_PAGESHIFT, %o0
	GET_TTE(%o0, %o4, %g3, %g4, %g1, %o5, %g6, %o1, %g5,
		kvaszc2pfn_l1, kvaszc2pfn_hblk_found, kvaszc2pfn_nohblk,
		kvaszc2pfn_nohblk)

kvaszc2pfn_hblk_found:
	/*
	 * %g3 = tte
	 * %o0 = vaddr
	 */
	brgez,a,pn %g3, 1f			/* check if tte is invalid */
	  mov	-1, %o0				/* output = -1 (PFN_INVALID) */
	TTETOPFN(%g3, %o0, kvaszc2pfn_l2, %g2, %g4, %g5)
	/*
	 * g3 = pfn
	 */
	ba,pt	%xcc, 1f
	  mov	%g3, %o0

kvaszc2pfn_nohblk:
	mov	-1, %o0

1:
	retl
 	  wrpr	%g0, %o3, %pstate		/* re-enable interrupts */

	SET_SIZE(sfmmu_kvaszc2pfn)

#endif /* lint */



#if !defined(lint)

/*
 * kpm lock used between trap level tsbmiss handler and kpm C level.
 */
#define KPMLOCK_ENTER(kpmlckp, tmp1, label1, asi)			\
	mov     0xff, tmp1						;\
label1:									;\
	casa    [kpmlckp]asi, %g0, tmp1					;\
	brnz,pn tmp1, label1						;\
	mov     0xff, tmp1						;\
	membar  #LoadLoad

#define KPMLOCK_EXIT(kpmlckp, asi)					\
	membar  #LoadStore|#StoreStore					;\
	sta     %g0, [kpmlckp]asi

/*
 * Lookup a memseg for a given pfn and if found, return the physical
 * address of the corresponding struct memseg in mseg, otherwise
 * return MSEG_NULLPTR_PA. The kpmtsbm pointer must be provided in
 * tsbmp, %asi is assumed to be ASI_MEM.
 * This lookup is done by strictly traversing only the physical memseg
 * linkage. The more generic approach, to check the virtual linkage
 * before using the physical (used e.g. with hmehash buckets), cannot
 * be used here. Memory DR operations can run in parallel to this
 * lookup w/o any locks and updates of the physical and virtual linkage
 * cannot be done atomically wrt. to each other. Because physical
 * address zero can be valid physical address, MSEG_NULLPTR_PA acts
 * as "physical NULL" pointer.
 */
#define	PAGE_NUM2MEMSEG_NOLOCK_PA(pfn, mseg, tsbmp, tmp1, tmp2, tmp3, label) \
	sethi	%hi(mhash_per_slot), tmp3 /* no tsbmp use due to DR */	;\
	ldx	[tmp3 + %lo(mhash_per_slot)], mseg			;\
	udivx	pfn, mseg, mseg						;\
	ldx	[tsbmp + KPMTSBM_MSEGPHASHPA], tmp1			;\
	and	mseg, SFMMU_N_MEM_SLOTS - 1, mseg			;\
	sllx	mseg, SFMMU_MEM_HASH_ENTRY_SHIFT, mseg			;\
	add	tmp1, mseg, tmp1					;\
	ldxa	[tmp1]%asi, mseg					;\
	cmp	mseg, MSEG_NULLPTR_PA					;\
	be,pn	%xcc, label/**/1		/* if not found */	;\
	  nop								;\
	ldxa	[mseg + MEMSEG_PAGES_BASE]%asi, tmp1			;\
	cmp	pfn, tmp1			/* pfn - pages_base */	;\
	blu,pn	%xcc, label/**/1					;\
	  ldxa	[mseg + MEMSEG_PAGES_END]%asi, tmp2			;\
	cmp	pfn, tmp2			/* pfn - pages_end */	;\
	bgeu,pn	%xcc, label/**/1					;\
	  sub	pfn, tmp1, tmp1			/* pfn - pages_base */	;\
	mulx	tmp1, PAGE_SIZE, tmp1					;\
	ldxa	[mseg + MEMSEG_PAGESPA]%asi, tmp2	/* pages */	;\
	add	tmp2, tmp1, tmp1			/* pp */	;\
	lduwa	[tmp1 + PAGE_PAGENUM]%asi, tmp2				;\
	cmp	tmp2, pfn						;\
	be,pt	%xcc, label/**/_ok			/* found */	;\
label/**/1:								;\
	/* brute force lookup */					;\
	sethi	%hi(memsegspa), tmp3 /* no tsbmp use due to DR */	;\
	ldx	[tmp3 + %lo(memsegspa)], mseg				;\
label/**/2:								;\
	cmp	mseg, MSEG_NULLPTR_PA					;\
	be,pn	%xcc, label/**/_ok		/* if not found */	;\
	  nop								;\
	ldxa	[mseg + MEMSEG_PAGES_BASE]%asi, tmp1			;\
	cmp	pfn, tmp1			/* pfn - pages_base */	;\
	blu,a,pt %xcc, label/**/2					;\
	  ldxa	[mseg + MEMSEG_NEXTPA]%asi, mseg			;\
	ldxa	[mseg + MEMSEG_PAGES_END]%asi, tmp2			;\
	cmp	pfn, tmp2			/* pfn - pages_end */	;\
	bgeu,a,pt %xcc, label/**/2					;\
	  ldxa	[mseg + MEMSEG_NEXTPA]%asi, mseg			;\
label/**/_ok:

	/*
	 * kpm tsb miss handler large pages
	 * g1 = 8K kpm TSB entry pointer
	 * g2 = tag access register
	 * g3 = 4M kpm TSB entry pointer
	 */
	ALTENTRY(sfmmu_kpm_dtsb_miss)
	TT_TRACE(trace_tsbmiss)

	CPU_INDEX(%g7, %g6)
	sethi	%hi(kpmtsbm_area), %g6
	sllx	%g7, KPMTSBM_SHIFT, %g7
	or	%g6, %lo(kpmtsbm_area), %g6
	add	%g6, %g7, %g6			/* g6 = kpmtsbm ptr */

	/* check enable flag */
	ldub	[%g6 + KPMTSBM_FLAGS], %g4
	and	%g4, KPMTSBM_ENABLE_FLAG, %g5
	brz,pn	%g5, sfmmu_tsb_miss		/* if kpm not enabled */
	  nop

	/* VA range check */
	ldx	[%g6 + KPMTSBM_VBASE], %g7
	cmp	%g2, %g7
	blu,pn	%xcc, sfmmu_tsb_miss
	  ldx	[%g6 + KPMTSBM_VEND], %g5
	cmp	%g2, %g5
	bgeu,pn	%xcc, sfmmu_tsb_miss
	  stx	%g3, [%g6 + KPMTSBM_TSBPTR]

	/*
	 * check TL tsbmiss handling flag
	 * bump tsbmiss counter
	 */
	lduw	[%g6 + KPMTSBM_TSBMISS], %g5
#ifdef	DEBUG
	and	%g4, KPMTSBM_TLTSBM_FLAG, %g3
	inc	%g5
	brz,pn	%g3, sfmmu_kpm_exception
	  st	%g5, [%g6 + KPMTSBM_TSBMISS]
#else
	inc	%g5
	st	%g5, [%g6 + KPMTSBM_TSBMISS]
#endif
	/*
	 * At this point:
	 *  g1 = 8K kpm TSB pointer (not used)
	 *  g2 = tag access register
	 *  g3 = clobbered
	 *  g6 = per-CPU kpm tsbmiss area
	 *  g7 = kpm_vbase
	 */

	/* vaddr2pfn */
	ldub	[%g6 + KPMTSBM_SZSHIFT], %g3
	sub	%g2, %g7, %g4			/* paddr = vaddr-kpm_vbase */
	srax    %g4, %g3, %g2			/* which alias range (r) */
	brnz,pn	%g2, sfmmu_kpm_exception	/* if (r != 0) goto C handler */
	  srlx	%g4, MMU_PAGESHIFT, %g2		/* %g2 = pfn */

	/*
	 * Setup %asi
	 * mseg_pa = page_numtomemseg_nolock(pfn)
	 * if (mseg_pa == NULL) sfmmu_kpm_exception
	 * g2=pfn
	 */
	mov	ASI_MEM, %asi
	PAGE_NUM2MEMSEG_NOLOCK_PA(%g2, %g3, %g6, %g4, %g5, %g7, kpmtsbmp2m)
	cmp	%g3, MSEG_NULLPTR_PA
	be,pn	%xcc, sfmmu_kpm_exception	/* if mseg not found */
	  nop

	/*
	 * inx = ptokpmp((kpmptop((ptopkpmp(pfn))) - mseg_pa->kpm_pbase));
	 * g2=pfn g3=mseg_pa
	 */
	ldub	[%g6 + KPMTSBM_KPMP2PSHFT], %g5
	ldxa	[%g3 + MEMSEG_KPM_PBASE]%asi, %g7
	srlx	%g2, %g5, %g4
	sllx	%g4, %g5, %g4
	sub	%g4, %g7, %g4
	srlx	%g4, %g5, %g4

	/*
	 * Validate inx value
	 * g2=pfn g3=mseg_pa g4=inx
	 */
#ifdef	DEBUG
	ldxa	[%g3 + MEMSEG_KPM_NKPMPGS]%asi, %g5
	cmp	%g4, %g5			/* inx - nkpmpgs */
	bgeu,pn	%xcc, sfmmu_kpm_exception	/* if out of range */
	  ld	[%g6 + KPMTSBM_KPMPTABLESZ], %g7
#else
	ld	[%g6 + KPMTSBM_KPMPTABLESZ], %g7
#endif
	/*
	 * kp = &mseg_pa->kpm_pages[inx]
	 */
	sllx	%g4, KPMPAGE_SHIFT, %g4		/* kpm_pages offset */
	ldxa	[%g3 + MEMSEG_KPM_PAGES]%asi, %g5 /* kpm_pages */
	add	%g5, %g4, %g5			/* kp */

	/*
	 * KPMP_HASH(kp)
	 * g2=pfn g3=mseg_pa g4=offset g5=kp g7=kpmp_table_sz
	 */
	ldub	[%g6 + KPMTSBM_KPMPSHIFT], %g1	/* kpmp_shift */
	sub	%g7, 1, %g7			/* mask */
	srlx	%g5, %g1, %g1			/* x = ksp >> kpmp_shift */
	add	%g5, %g1, %g5			/* y = ksp + x */
	and 	%g5, %g7, %g5			/* hashinx = y & mask */

	/*
	 * Calculate physical kpm_page pointer
	 * g2=pfn g3=mseg_pa g4=offset g5=hashinx
	 */
	ldxa	[%g3 + MEMSEG_KPM_PAGESPA]%asi, %g1 /* kpm_pagespa */
	add	%g1, %g4, %g1			/* kp_pa */

	/*
	 * Calculate physical hash lock address
	 * g1=kp_refcntc_pa g2=pfn g5=hashinx
	 */
	ldx	[%g6 + KPMTSBM_KPMPTABLEPA], %g4 /* kpmp_tablepa */
	sllx	%g5, KPMHLK_SHIFT, %g5
	add	%g4, %g5, %g3
	add	%g3, KPMHLK_LOCK, %g3		/* hlck_pa */

	/*
	 * Assemble tte
	 * g1=kp_pa g2=pfn g3=hlck_pa
	 */
#ifdef sun4v
	sethi	%hi(TTE_VALID_INT), %g5		/* upper part */
	sllx	%g5, 32, %g5
	mov	(TTE_CP_INT|TTE_CV_INT|TTE_PRIV_INT|TTE_HWWR_INT), %g4
	or	%g4, TTE4M, %g4
	or	%g5, %g4, %g5
#else
	sethi	%hi(TTE_VALID_INT), %g4
	mov	TTE4M, %g5
	sllx	%g5, TTE_SZ_SHFT_INT, %g5
	or	%g5, %g4, %g5			/* upper part */
	sllx	%g5, 32, %g5
	mov	(TTE_CP_INT|TTE_CV_INT|TTE_PRIV_INT|TTE_HWWR_INT), %g4
	or	%g5, %g4, %g5
#endif
	sllx	%g2, MMU_PAGESHIFT, %g4
	or	%g5, %g4, %g5			/* tte */
	ldx	[%g6 + KPMTSBM_TSBPTR], %g4
	GET_MMU_D_TTARGET(%g2, %g7)		/* %g2 = ttarget */

	/*
	 * tsb dropin
	 * g1=kp_pa g2=ttarget g3=hlck_pa g4=kpmtsbp4m g5=tte g6=kpmtsbm_area
	 */

	/* KPMLOCK_ENTER(kpmlckp, tmp1, label1, asi) */
	KPMLOCK_ENTER(%g3, %g7, kpmtsbmhdlr1, ASI_MEM)

	/* use C-handler if there's no go for dropin */
	ldsha	[%g1 + KPMPAGE_REFCNTC]%asi, %g7 /* kp_refcntc */
	cmp	%g7, -1
	bne,pn	%xcc, 5f	/* use C-handler if there's no go for dropin */
	  nop

#ifdef	DEBUG
	/* double check refcnt */
	ldsha	[%g1 + KPMPAGE_REFCNT]%asi, %g7
	brz,pn	%g7, 5f			/* let C-handler deal with this */
	  nop
#endif

#ifndef sun4v
	ldub	[%g6 + KPMTSBM_FLAGS], %g7
	mov	ASI_N, %g1
	andcc	%g7, KPMTSBM_TSBPHYS_FLAG, %g0
	movnz	%icc, ASI_MEM, %g1
	mov	%g1, %asi
#endif

	/*
	 * TSB_LOCK_ENTRY(tsbp, tmp1, tmp2, label) (needs %asi set)
	 * If we fail to lock the TSB entry then just load the tte into the
	 * TLB.
	 */
	TSB_LOCK_ENTRY(%g4, %g1, %g7, locked_tsb_l1)

	/* TSB_INSERT_UNLOCK_ENTRY(tsbp, tte, tagtarget, tmp) */
	TSB_INSERT_UNLOCK_ENTRY(%g4, %g5, %g2, %g7)
locked_tsb_l1:
	DTLB_STUFF(%g5, %g1, %g2, %g4, %g6)

	/* KPMLOCK_EXIT(kpmlckp, asi) */
	KPMLOCK_EXIT(%g3, ASI_MEM)

	/*
	 * If trapstat is running, we need to shift the %tpc and %tnpc to
	 * point to trapstat's TSB miss return code (note that trapstat
	 * itself will patch the correct offset to add).
	 * Note: TTE is expected in %g5 (allows per pagesize reporting).
	 */
	rdpr	%tl, %g7
	cmp	%g7, 1
	ble	%icc, 0f
	sethi	%hi(KERNELBASE), %g6
	rdpr	%tpc, %g7
	or	%g6, %lo(KERNELBASE), %g6
	cmp	%g7, %g6
	bgeu	%xcc, 0f
	ALTENTRY(tsbmiss_trapstat_patch_point_kpm)
	add	%g7, RUNTIME_PATCH, %g7	/* must match TSTAT_TSBMISS_INSTR */
	wrpr	%g7, %tpc
	add	%g7, 4, %g7
	wrpr	%g7, %tnpc
0:
	retry
5:
	/* g3=hlck_pa */
	KPMLOCK_EXIT(%g3, ASI_MEM)
	ba,pt	%icc, sfmmu_kpm_exception
	  nop
	SET_SIZE(sfmmu_kpm_dtsb_miss)

	/*
	 * kpm tsbmiss handler for smallpages
	 * g1 = 8K kpm TSB pointer
	 * g2 = tag access register
	 * g3 = 4M kpm TSB pointer
	 */
	ALTENTRY(sfmmu_kpm_dtsb_miss_small)
	TT_TRACE(trace_tsbmiss)
	CPU_INDEX(%g7, %g6)
	sethi	%hi(kpmtsbm_area), %g6
	sllx	%g7, KPMTSBM_SHIFT, %g7
	or	%g6, %lo(kpmtsbm_area), %g6
	add	%g6, %g7, %g6			/* g6 = kpmtsbm ptr */

	/* check enable flag */
	ldub	[%g6 + KPMTSBM_FLAGS], %g4
	and	%g4, KPMTSBM_ENABLE_FLAG, %g5
	brz,pn	%g5, sfmmu_tsb_miss		/* if kpm not enabled */
	  nop

	/*
	 * VA range check
	 * On fail: goto sfmmu_tsb_miss
	 */
	ldx	[%g6 + KPMTSBM_VBASE], %g7
	cmp	%g2, %g7
	blu,pn	%xcc, sfmmu_tsb_miss
	  ldx	[%g6 + KPMTSBM_VEND], %g5
	cmp	%g2, %g5
	bgeu,pn	%xcc, sfmmu_tsb_miss
	  stx	%g1, [%g6 + KPMTSBM_TSBPTR]	/* save 8K kpm TSB pointer */

	/*
	 * check TL tsbmiss handling flag
	 * bump tsbmiss counter
	 */
	lduw	[%g6 + KPMTSBM_TSBMISS], %g5
#ifdef	DEBUG
	and	%g4, KPMTSBM_TLTSBM_FLAG, %g1
	inc	%g5
	brz,pn	%g1, sfmmu_kpm_exception
	  st	%g5, [%g6 + KPMTSBM_TSBMISS]
#else
	inc	%g5
	st	%g5, [%g6 + KPMTSBM_TSBMISS]
#endif
	/*
	 * At this point:
	 *  g1 = clobbered
	 *  g2 = tag access register
	 *  g3 = 4M kpm TSB pointer (not used)
	 *  g6 = per-CPU kpm tsbmiss area
	 *  g7 = kpm_vbase
	 */

	/*
	 * Assembly implementation of SFMMU_KPM_VTOP(vaddr, paddr)
	 * which is defined in mach_kpm.h. Any changes in that macro
	 * should also be ported back to this assembly code.
	 */
	ldub	[%g6 + KPMTSBM_SZSHIFT], %g3	/* g3 = kpm_size_shift */
	sub	%g2, %g7, %g4			/* paddr = vaddr-kpm_vbase */
	srax    %g4, %g3, %g7			/* which alias range (r) */
	brz,pt	%g7, 2f
	  sethi   %hi(vac_colors_mask), %g5
	ld	[%g5 + %lo(vac_colors_mask)], %g5

	srlx	%g2, MMU_PAGESHIFT, %g1		/* vaddr >> MMU_PAGESHIFT */
	and	%g1, %g5, %g1			/* g1 = v */
	sllx	%g7, %g3, %g5			/* g5 = r << kpm_size_shift */
	cmp	%g7, %g1			/* if (r > v) */
	bleu,pn %xcc, 1f
	  sub   %g4, %g5, %g4			/* paddr -= r << kpm_size_shift */
	sub	%g7, %g1, %g5			/* g5 = r - v */
	sllx	%g5, MMU_PAGESHIFT, %g7		/* (r-v) << MMU_PAGESHIFT */
	add	%g4, %g7, %g4			/* paddr += (r-v)<<MMU_PAGESHIFT */
	ba	2f
	  nop
1:
	sllx	%g7, MMU_PAGESHIFT, %g5		/* else */
	sub	%g4, %g5, %g4			/* paddr -= r << MMU_PAGESHIFT */

	/*
	 * paddr2pfn
	 *  g1 = vcolor (not used)
	 *  g2 = tag access register
	 *  g3 = clobbered
	 *  g4 = paddr
	 *  g5 = clobbered
	 *  g6 = per-CPU kpm tsbmiss area
	 *  g7 = clobbered
	 */
2:
	srlx	%g4, MMU_PAGESHIFT, %g2		/* g2 = pfn */

	/*
	 * Setup %asi
	 * mseg_pa = page_numtomemseg_nolock_pa(pfn)
	 * if (mseg not found) sfmmu_kpm_exception
	 * g2=pfn g6=per-CPU kpm tsbmiss area
	 * g4 g5 g7 for scratch use.
	 */
	mov	ASI_MEM, %asi
	PAGE_NUM2MEMSEG_NOLOCK_PA(%g2, %g3, %g6, %g4, %g5, %g7, kpmtsbmsp2m)
	cmp	%g3, MSEG_NULLPTR_PA
	be,pn	%xcc, sfmmu_kpm_exception	/* if mseg not found */
	  nop

	/*
	 * inx = pfn - mseg_pa->kpm_pbase
	 * g2=pfn  g3=mseg_pa  g6=per-CPU kpm tsbmiss area
	 */
	ldxa	[%g3 + MEMSEG_KPM_PBASE]%asi, %g7
	sub	%g2, %g7, %g4

#ifdef	DEBUG
	/*
	 * Validate inx value
	 * g2=pfn g3=mseg_pa g4=inx g6=per-CPU tsbmiss area
	 */
	ldxa	[%g3 + MEMSEG_KPM_NKPMPGS]%asi, %g5
	cmp	%g4, %g5			/* inx - nkpmpgs */
	bgeu,pn	%xcc, sfmmu_kpm_exception	/* if out of range */
	  ld	[%g6 + KPMTSBM_KPMPTABLESZ], %g7
#else
	ld	[%g6 + KPMTSBM_KPMPTABLESZ], %g7
#endif
	/* ksp = &mseg_pa->kpm_spages[inx] */
	ldxa	[%g3 + MEMSEG_KPM_SPAGES]%asi, %g5
	add	%g5, %g4, %g5			/* ksp */

	/*
	 * KPMP_SHASH(kp)
	 * g2=pfn g3=mseg_pa g4=inx g5=ksp
	 * g6=per-CPU kpm tsbmiss area  g7=kpmp_stable_sz
	 */
	ldub	[%g6 + KPMTSBM_KPMPSHIFT], %g1	/* kpmp_shift */
	sub	%g7, 1, %g7			/* mask */
	sllx	%g5, %g1, %g1			/* x = ksp << kpmp_shift */
	add	%g5, %g1, %g5			/* y = ksp + x */
	and 	%g5, %g7, %g5			/* hashinx = y & mask */

	/*
	 * Calculate physical kpm_spage pointer
	 * g2=pfn g3=mseg_pa g4=offset g5=hashinx
	 * g6=per-CPU kpm tsbmiss area
	 */
	ldxa	[%g3 + MEMSEG_KPM_PAGESPA]%asi, %g1 /* kpm_spagespa */
	add	%g1, %g4, %g1			/* ksp_pa */

	/*
	 * Calculate physical hash lock address.
	 * Note: Changes in kpm_shlk_t must be reflected here.
	 * g1=ksp_pa g2=pfn g5=hashinx
	 * g6=per-CPU kpm tsbmiss area
	 */
	ldx	[%g6 + KPMTSBM_KPMPTABLEPA], %g4 /* kpmp_stablepa */
	sllx	%g5, KPMSHLK_SHIFT, %g5
	add	%g4, %g5, %g3			/* hlck_pa */

	/*
	 * Assemble non-cacheable tte initially
	 * g1=ksp_pa g2=pfn g3=hlck_pa
	 * g6=per-CPU kpm tsbmiss area
	 */
	sethi	%hi(TTE_VALID_INT), %g5		/* upper part */
	sllx	%g5, 32, %g5
	mov	(TTE_CP_INT|TTE_PRIV_INT|TTE_HWWR_INT), %g4
	or	%g5, %g4, %g5
	sllx	%g2, MMU_PAGESHIFT, %g4
	or	%g5, %g4, %g5			/* tte */
	ldx	[%g6 + KPMTSBM_TSBPTR], %g4
	GET_MMU_D_TTARGET(%g2, %g7)		/* %g2 = ttarget */

	/*
	 * tsb dropin
	 * g1=ksp_pa g2=ttarget g3=hlck_pa g4=ktsbp g5=tte (non-cacheable)
	 * g6=per-CPU kpm tsbmiss area  g7=scratch register
	 */

	/* KPMLOCK_ENTER(kpmlckp, tmp1, label1, asi) */
	KPMLOCK_ENTER(%g3, %g7, kpmtsbsmlock, ASI_MEM)

	/* use C-handler if there's no go for dropin */
	ldsba	[%g1 + KPMSPAGE_MAPPED]%asi, %g7	/* kp_mapped */
	andcc	%g7, KPM_MAPPED_GO, %g0			/* go or no go ? */
	bz,pt	%icc, 5f				/* no go */
	  nop
	and	%g7, KPM_MAPPED_MASK, %g7		/* go */
	cmp	%g7, KPM_MAPPEDS			/* cacheable ? */
	be,a,pn	%xcc, 3f
	  or	%g5, TTE_CV_INT, %g5			/* cacheable */
3:
#ifndef sun4v
	ldub	[%g6 + KPMTSBM_FLAGS], %g7
	mov	ASI_N, %g1
	andcc	%g7, KPMTSBM_TSBPHYS_FLAG, %g0
	movnz	%icc, ASI_MEM, %g1
	mov	%g1, %asi
#endif

	/*
	 * TSB_LOCK_ENTRY(tsbp, tmp1, tmp2, label) (needs %asi set)
	 * If we fail to lock the TSB entry then just load the tte into the
	 * TLB.
	 */
	TSB_LOCK_ENTRY(%g4, %g1, %g7, locked_tsb_l2)

	/* TSB_INSERT_UNLOCK_ENTRY(tsbp, tte, tagtarget, tmp) */
	TSB_INSERT_UNLOCK_ENTRY(%g4, %g5, %g2, %g7)
locked_tsb_l2:
	DTLB_STUFF(%g5, %g2, %g4, %g5, %g6)

	/* KPMLOCK_EXIT(kpmlckp, asi) */
	KPMLOCK_EXIT(%g3, ASI_MEM)

	/*
	 * If trapstat is running, we need to shift the %tpc and %tnpc to
	 * point to trapstat's TSB miss return code (note that trapstat
	 * itself will patch the correct offset to add).
	 * Note: TTE is expected in %g5 (allows per pagesize reporting).
	 */
	rdpr	%tl, %g7
	cmp	%g7, 1
	ble	%icc, 0f
	sethi	%hi(KERNELBASE), %g6
	rdpr	%tpc, %g7
	or	%g6, %lo(KERNELBASE), %g6
	cmp	%g7, %g6
	bgeu	%xcc, 0f
	ALTENTRY(tsbmiss_trapstat_patch_point_kpm_small)
	add	%g7, RUNTIME_PATCH, %g7	/* must match TSTAT_TSBMISS_INSTR */
	wrpr	%g7, %tpc
	add	%g7, 4, %g7
	wrpr	%g7, %tnpc
0:
	retry
5:
	/* g3=hlck_pa */
	KPMLOCK_EXIT(%g3, ASI_MEM)
	ba,pt	%icc, sfmmu_kpm_exception
	  nop
	SET_SIZE(sfmmu_kpm_dtsb_miss_small)

#if (1<< KPMTSBM_SHIFT) != KPMTSBM_SIZE
#error - KPMTSBM_SHIFT does not correspond to size of kpmtsbm struct
#endif

#endif /* lint */

#ifdef	lint
/*
 * Enable/disable tsbmiss handling at trap level for a kpm (large) page.
 * Called from C-level, sets/clears "go" indication for trap level handler.
 * khl_lock is a low level spin lock to protect the kp_tsbmtl field.
 * Assumed that &kp->kp_refcntc is checked for zero or -1 at C-level.
 * Assumes khl_mutex is held when called from C-level.
 */
/* ARGSUSED */
void
sfmmu_kpm_tsbmtl(short *kp_refcntc, uint_t *khl_lock, int cmd)
{
}

/*
 * kpm_smallpages: stores val to byte at address mapped within
 * low level lock brackets. The old value is returned.
 * Called from C-level.
 */
/* ARGSUSED */
int
sfmmu_kpm_stsbmtl(uchar_t *mapped, uint_t *kshl_lock, int val)
{
	return (0);
}

#else /* lint */

	.seg	".data"
sfmmu_kpm_tsbmtl_panic:
	.ascii	"sfmmu_kpm_tsbmtl: interrupts disabled"
	.byte	0
sfmmu_kpm_stsbmtl_panic:
	.ascii	"sfmmu_kpm_stsbmtl: interrupts disabled"
	.byte	0
	.align	4
	.seg	".text"

	ENTRY_NP(sfmmu_kpm_tsbmtl)
	rdpr	%pstate, %o3
	/*
	 * %o0 = &kp_refcntc
	 * %o1 = &khl_lock
	 * %o2 = 0/1 (off/on)
	 * %o3 = pstate save
	 */
#ifdef DEBUG
	andcc	%o3, PSTATE_IE, %g0		/* if interrupts already */
	bnz,pt %icc, 1f				/* disabled, panic	 */
	  nop
	save	%sp, -SA(MINFRAME), %sp
	sethi	%hi(sfmmu_kpm_tsbmtl_panic), %o0
	call	panic
	 or	%o0, %lo(sfmmu_kpm_tsbmtl_panic), %o0
	ret
	restore
1:
#endif /* DEBUG */
	wrpr	%o3, PSTATE_IE, %pstate		/* disable interrupts */

	KPMLOCK_ENTER(%o1, %o4, kpmtsbmtl1, ASI_N)
	mov	-1, %o5
	brz,a	%o2, 2f
	  mov	0, %o5
2:
	sth	%o5, [%o0]
	KPMLOCK_EXIT(%o1, ASI_N)

	retl
	  wrpr	%g0, %o3, %pstate		/* enable interrupts */
	SET_SIZE(sfmmu_kpm_tsbmtl)

	ENTRY_NP(sfmmu_kpm_stsbmtl)
	rdpr	%pstate, %o3
	/*
	 * %o0 = &mapped
	 * %o1 = &kshl_lock
	 * %o2 = val
	 * %o3 = pstate save
	 */
#ifdef DEBUG
	andcc	%o3, PSTATE_IE, %g0		/* if interrupts already */
	bnz,pt %icc, 1f				/* disabled, panic	 */
	  nop
	save	%sp, -SA(MINFRAME), %sp
	sethi	%hi(sfmmu_kpm_stsbmtl_panic), %o0
	call	panic
	  or	%o0, %lo(sfmmu_kpm_stsbmtl_panic), %o0
	ret
	restore
1:
#endif /* DEBUG */
	wrpr	%o3, PSTATE_IE, %pstate		/* disable interrupts */

	KPMLOCK_ENTER(%o1, %o4, kpmstsbmtl1, ASI_N)
	ldsb	[%o0], %o5
	stb	%o2, [%o0]
	KPMLOCK_EXIT(%o1, ASI_N)

	and	%o5, KPM_MAPPED_MASK, %o0	/* return old val */
	retl
	  wrpr	%g0, %o3, %pstate		/* enable interrupts */
	SET_SIZE(sfmmu_kpm_stsbmtl)

#endif /* lint */

#ifndef lint
#ifdef sun4v
	/*
	 * User/kernel data miss w// multiple TSBs
	 * The first probe covers 8K, 64K, and 512K page sizes,
	 * because 64K and 512K mappings are replicated off 8K
	 * pointer.  Second probe covers 4M page size only.
	 *
	 * MMU fault area contains miss address and context.
	 */
	ALTENTRY(sfmmu_slow_dmmu_miss)
	GET_MMU_D_PTAGACC_CTXTYPE(%g2, %g3)	! %g2 = ptagacc, %g3 = ctx type

slow_miss_common:
	/*
	 *  %g2 = tagacc register (needed for sfmmu_tsb_miss_tt)
	 *  %g3 = ctx (cannot be INVALID_CONTEXT)
	 */
	brnz,pt	%g3, 8f			! check for user context
	  nop

	/*
	 * Kernel miss
	 * Get 8K and 4M TSB pointers in %g1 and %g3 and
	 * branch to sfmmu_tsb_miss_tt to handle it.
	 */
	mov	%g2, %g7		! TSB pointer macro clobbers tagacc
sfmmu_dslow_patch_ktsb_base:
	RUNTIME_PATCH_SETX(%g1, %g6)	! %g1 = contents of ktsb_pbase
sfmmu_dslow_patch_ktsb_szcode:
	or	%g0, RUNTIME_PATCH, %g3	! ktsb_szcode (hot patched)

	GET_TSBE_POINTER(MMU_PAGESHIFT, %g1, %g7, %g3, %g5)
	! %g1 = First TSB entry pointer, as TSB miss handler expects

	mov	%g2, %g7		! TSB pointer macro clobbers tagacc
sfmmu_dslow_patch_ktsb4m_base:
	RUNTIME_PATCH_SETX(%g3, %g6)	! %g3 = contents of ktsb4m_pbase
sfmmu_dslow_patch_ktsb4m_szcode:
	or	%g0, RUNTIME_PATCH, %g6	! ktsb4m_szcode (hot patched)

	GET_TSBE_POINTER(MMU_PAGESHIFT4M, %g3, %g7, %g6, %g5)
	! %g3 = 4M tsb entry pointer, as TSB miss handler expects
	ba,a,pt	%xcc, sfmmu_tsb_miss_tt
	.empty

8:
	/*
	 * User miss
	 * Get first TSB pointer in %g1
	 * Get second TSB pointer (or NULL if no second TSB) in %g3
	 * Branch to sfmmu_tsb_miss_tt to handle it
	 */
	GET_1ST_TSBE_PTR(%g2, %g1, %g4, %g5)
	/* %g1 = first TSB entry ptr now, %g2 preserved */

	GET_UTSBREG(SCRATCHPAD_UTSBREG2, %g3)	/* get 2nd utsbreg */
	brlz,pt %g3, sfmmu_tsb_miss_tt		/* done if no 2nd TSB */
	  nop

	GET_2ND_TSBE_PTR(%g2, %g3, %g4, %g5)
	/* %g3 = second TSB entry ptr now, %g2 preserved */
9:
	ba,a,pt	%xcc, sfmmu_tsb_miss_tt
	.empty
	SET_SIZE(sfmmu_slow_dmmu_miss)


	/*
	 * User/kernel instruction miss w/ multiple TSBs
	 * The first probe covers 8K, 64K, and 512K page sizes,
	 * because 64K and 512K mappings are replicated off 8K
	 * pointer.  Second probe covers 4M page size only.
	 *
	 * MMU fault area contains miss address and context.
	 */
	ALTENTRY(sfmmu_slow_immu_miss)
	GET_MMU_I_PTAGACC_CTXTYPE(%g2, %g3)
	ba,a,pt	%xcc, slow_miss_common
	SET_SIZE(sfmmu_slow_immu_miss)

#endif /* sun4v */
#endif	/* lint */

#ifndef lint

/*
 * Per-CPU tsbmiss areas to avoid cache misses in TSB miss handlers.
 */
	.seg	".data"
	.align	64
	.global tsbmiss_area
tsbmiss_area:
	.skip	(TSBMISS_SIZE * NCPU)

	.align	64
	.global kpmtsbm_area
kpmtsbm_area:
	.skip	(KPMTSBM_SIZE * NCPU)
#endif	/* lint */
