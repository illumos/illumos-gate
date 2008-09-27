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

/*
 * VM - Hardware Address Translation management.
 *
 * This file describes the contents of the sun reference mmu (sfmmu)
 * specific hat data structures and the sfmmu specific hat procedures.
 * The machine independent interface is described in <vm/hat.h>.
 */

#ifndef _VM_MACH_SFMMU_H
#define	_VM_MACH_SFMMU_H

#include <sys/x_call.h>
#include <sys/hypervisor_api.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Define UTSB_PHYS if user TSB is always accessed via physical address.
 * On sun4v platform, user TSB is accessed via physical address.
 */
#define	UTSB_PHYS	1

/*
 * Hypervisor TSB info
 */
#define	NHV_TSB_INFO	4

#ifndef _ASM

struct hv_tsb_block {
	uint64_t	hv_tsb_info_pa;	/* hypervisor TSB info PA */
	uint64_t	hv_tsb_info_cnt; /* hypervisor TSB info count */
	hv_tsb_info_t	hv_tsb_info[NHV_TSB_INFO]; /* hypervisor TSB info */
};

#endif /* _ASM */

#ifdef _ASM

/*
 * This macro is used to set private/shared secondary context register in
 * sfmmu_alloc_ctx().
 * Input:
 * cnum     = cnum
 * is_shctx = sfmmu private/shared flag (0: private, 1: shared)
 * tmp2 is only used in the sun4u version of this macro
 */
#define	SET_SECCTX(cnum, is_shctx, tmp1, tmp2, label)			\
	mov	MMU_SCONTEXT, tmp1;					\
	movrnz	is_shctx, MMU_SCONTEXT1, tmp1;				\
	stxa    cnum, [tmp1]ASI_MMU_CTX;  /* set 2nd ctx reg. */	\
	membar  #Sync;							\

/*
 * This macro is used in the MMU code to check if TL should be lowered from
 * 2 to 1 to pop trapstat's state.  See the block comment in trapstat.c
 * for details.
 */

#define	TSTAT_CHECK_TL1(label, scr1, scr2)			\
	rdpr	%tpc, scr1;					\
	sethi	%hi(KERNELBASE), scr2;				\
	or	scr2, %lo(KERNELBASE), scr2; 			\
	cmp	scr1, scr2; 					\
	bgeu	%xcc, 9f;					\
	nop;							\
	wrpr	%g0, 1, %gl;					\
	ba	label;						\
	wrpr	%g0, 1, %tl;					\
9:

/*
 * The following macros allow us to share majority of the
 * SFMMU code between sun4u and sun4v platforms.
 */

#define	SETUP_TSB_ASI(qlp, tmp)

#define	SETUP_UTSB_ATOMIC_ASI(tmp1, tmp2)

/*
 * Macro to swtich to alternate global register on sun4u platforms
 * (not applicable to sun4v platforms)
 */
#define	USE_ALTERNATE_GLOBALS(scr)

/*
 * Macro to set %gl register value on sun4v platforms
 * (not applicable to sun4u platforms)
 */
#define	SET_GL_REG(val)						\
	wrpr	%g0, val, %gl

/*
 * Get pseudo-tagacc value and context from the MMU fault area.  Pseudo-tagacc
 * is the faulting virtual address OR'd with 0 for KCONTEXT, INVALID_CONTEXT
 * (1) for invalid context, and USER_CONTEXT (2) for user context.
 *
 * In:
 *   tagacc, ctxtype = scratch registers
 * Out:
 *   tagacc = MMU data tag access register value
 *   ctx = context type (KCONTEXT, INVALID_CONTEXT or USER_CONTEXT)
 */
#define	GET_MMU_D_PTAGACC_CTXTYPE(ptagacc, ctxtype)			\
	MMU_FAULT_STATUS_AREA(ctxtype);					\
	ldx	[ctxtype + MMFSA_D_ADDR], ptagacc;			\
	ldx	[ctxtype + MMFSA_D_CTX], ctxtype;			\
	srlx	ptagacc, MMU_PAGESHIFT, ptagacc; /* align to page boundary */ \
	cmp	ctxtype, USER_CONTEXT_TYPE;				\
	sllx	ptagacc, MMU_PAGESHIFT, ptagacc;			\
	movgu	%icc, USER_CONTEXT_TYPE, ctxtype;			\
	or	ptagacc, ctxtype, ptagacc

/*
 * Synthesize/get data tag access register value from the MMU fault area
 *
 * In:
 *   tagacc, scr1 = scratch registers
 * Out:
 *   tagacc = MMU data tag access register value
 */
#define	GET_MMU_D_TAGACC(tagacc, scr1)				\
	GET_MMU_D_PTAGACC_CTXTYPE(tagacc, scr1)

/*
 * Synthesize/get data tag target register value from the MMU fault area
 *
 * In:
 *   ttarget, scr1 = scratch registers
 * Out:
 *   ttarget = MMU data tag target register value
 */
#define	GET_MMU_D_TTARGET(ttarget, scr1)			\
	MMU_FAULT_STATUS_AREA(ttarget);				\
	ldx	[ttarget + MMFSA_D_CTX], scr1;			\
	sllx	scr1, TTARGET_CTX_SHIFT, scr1;			\
	ldx	[ttarget + MMFSA_D_ADDR], ttarget;		\
	srlx	ttarget, TTARGET_VA_SHIFT, ttarget;		\
	or	ttarget, scr1, ttarget

/*
 * Synthesize/get data/instruction psuedo tag access register values
 * from the MMU fault area (context is 0 for kernel, 1 for invalid, 2 for user)
 *
 * In:
 *   dtagacc, itagacc, scr1, scr2 = scratch registers
 * Out:
 *   dtagacc = MMU data tag access register value w/psuedo-context
 *   itagacc = MMU instruction tag access register value w/pseudo-context
 */
#define	GET_MMU_BOTH_TAGACC(dtagacc, itagacc, scr1, scr2)	\
	MMU_FAULT_STATUS_AREA(scr1);				\
	ldx	[scr1 + MMFSA_D_ADDR], scr2;			\
	ldx	[scr1 + MMFSA_D_CTX], dtagacc;			\
	srlx	scr2, MMU_PAGESHIFT, scr2;	/* align to page boundary */ \
	cmp	dtagacc, USER_CONTEXT_TYPE;			\
	sllx	scr2, MMU_PAGESHIFT, scr2;			\
	movgu	%icc, USER_CONTEXT_TYPE, dtagacc;		\
	or	scr2, dtagacc, dtagacc;				\
	ldx	[scr1 + MMFSA_I_ADDR], scr2;			\
	ldx	[scr1 + MMFSA_I_CTX], itagacc;			\
	srlx	scr2, MMU_PAGESHIFT, scr2;	/* align to page boundry */ \
	cmp	itagacc, USER_CONTEXT_TYPE;			\
	sllx	scr2, MMU_PAGESHIFT, scr2;			\
	movgu	%icc, USER_CONTEXT_TYPE, itagacc;		\
	or	scr2, itagacc, itagacc

/*
 * Synthesize/get MMU data fault address from the MMU fault area
 *
 * In:
 *   daddr, scr1 = scratch registers
 * Out:
 *   daddr = MMU data fault address
 */
#define	GET_MMU_D_ADDR(daddr, scr1)				\
	MMU_FAULT_STATUS_AREA(scr1);				\
	ldx	[scr1 + MMFSA_D_ADDR], daddr

/*
 * Get pseudo-tagacc value and context from the MMU fault area.  Pseudo-tagacc
 * is the faulting virtual address OR'd with 0 for KCONTEXT, INVALID_CONTEXT
 * (1) for invalid context, and USER_CONTEXT (2) for user context.
 *
 * In:
 *   tagacc, ctxtype = scratch registers
 * Out:
 *   tagacc = MMU instruction tag access register value
 *   ctxtype = context type (KCONTEXT, INVALID_CONTEXT or USER_CONTEXT)
 */
#define	GET_MMU_I_PTAGACC_CTXTYPE(ptagacc, ctxtype)			\
	MMU_FAULT_STATUS_AREA(ctxtype);					\
	ldx	[ctxtype + MMFSA_I_ADDR], ptagacc;			\
	ldx	[ctxtype + MMFSA_I_CTX], ctxtype;			\
	srlx	ptagacc, MMU_PAGESHIFT, ptagacc; /* align to page boundary */ \
	cmp	ctxtype, USER_CONTEXT_TYPE;				\
	sllx	ptagacc, MMU_PAGESHIFT, ptagacc;			\
	movgu	%icc, USER_CONTEXT_TYPE, ctxtype;			\
	or	ptagacc, ctxtype, ptagacc

/*
 * Load ITLB entry
 *
 * In:
 *   tte = reg containing tte
 *   scr1, scr2, scr3, scr4 = scratch registers
 */
#define	ITLB_STUFF(tte, scr1, scr2, scr3, scr4)		\
	mov	%o0, scr1;				\
	mov	%o1, scr2;				\
	mov	%o2, scr3;				\
	mov	%o3, scr4;				\
	MMU_FAULT_STATUS_AREA(%o2);			\
	ldx	[%o2 + MMFSA_I_ADDR], %o0;		\
	ldx	[%o2 + MMFSA_I_CTX], %o1;		\
	mov	tte, %o2;				\
	mov	MAP_ITLB, %o3;				\
	ta	MMU_MAP_ADDR;				\
	/* BEGIN CSTYLED */				\
	brnz,a,pn %o0, ptl1_panic;			\
	  mov	PTL1_BAD_HCALL, %g1;			\
	/* END CSTYLED */				\
	mov	scr1, %o0;				\
	mov	scr2, %o1;				\
	mov	scr3, %o2;				\
	mov	scr4, %o3

/*
 * Load DTLB entry
 *
 * In:
 *   tte = reg containing tte
 *   scr1, scr2, scr3, scr4 = scratch registers
 */
#define	DTLB_STUFF(tte, scr1, scr2, scr3, scr4)		\
	mov	%o0, scr1;				\
	mov	%o1, scr2;				\
	mov	%o2, scr3;				\
	mov	%o3, scr4;				\
	MMU_FAULT_STATUS_AREA(%o2);			\
	ldx	[%o2 + MMFSA_D_ADDR], %o0;		\
	ldx	[%o2 + MMFSA_D_CTX], %o1;		\
	mov	tte, %o2;				\
	mov	MAP_DTLB, %o3;				\
	ta	MMU_MAP_ADDR;				\
	/* BEGIN CSTYLED */				\
	brnz,a,pn %o0, ptl1_panic;			\
	  mov	PTL1_BAD_HCALL, %g1;			\
	/* END CSTYLED */				\
	mov	scr1, %o0;				\
	mov	scr2, %o1;				\
	mov	scr3, %o2;				\
	mov	scr4, %o3

/*
 * Returns PFN given the TTE and vaddr
 *
 * In:
 *   tte = reg containing tte
 *   vaddr = reg containing vaddr
 *   scr1, scr2, scr3 = scratch registers
 * Out:
 *   tte = PFN value
 */
#define	TTETOPFN(tte, vaddr, label, scr1, scr2, scr3)			\
	and	tte, TTE_SZ_BITS, scr1;		/* scr1 = ttesz */	\
	sllx	tte, TTE_PA_LSHIFT, tte;				\
	sllx	scr1, 1, scr2;						\
	add	scr2, scr1, scr2;		/* mulx 3 */		\
	add	scr2, MMU_PAGESHIFT + TTE_PA_LSHIFT, scr3;		\
	/* CSTYLED */							\
	brz,pt	scr2, label/**/1;					\
	srlx	tte, scr3, tte;						\
	sllx	tte, scr2, tte;						\
	set	1, scr1;						\
	add	scr2, MMU_PAGESHIFT, scr3;				\
	sllx	scr1, scr3, scr1;					\
	sub	scr1, 1, scr1;	/* scr1=TTE_PAGE_OFFSET(ttesz) */	\
	and	vaddr, scr1, scr2;					\
	srln	scr2, MMU_PAGESHIFT, scr2;				\
	or	tte, scr2, tte;						\
	/* CSTYLED */							\
label/**/1:

/*
 * Support for non-coherent I$.
 *
 * In sun4v we use tte bit 3 as a software flag indicating whether
 * execute permission is given. IMMU miss traps cause the real execute
 * permission to be set. sfmmu_ttesync() will see if execute permission
 * has been set, and then set P_EXEC in page_t. This causes I-cache
 * flush when the page is freed.
 *
 * However, the hypervisor reserves bit 3 as part of a 4-bit page size.
 * We allow this flag to be set in hme TTE, but never in TSB or TLB.
 */
#define	TTE_CLR_SOFTEXEC_ML(tte)	bclr TTE_SOFTEXEC_INT, tte
#define	TTE_CHK_SOFTEXEC_ML(tte)	andcc tte, TTE_SOFTEXEC_INT, %g0

/*
 * TTE_SET_EXEC_ML is a macro that updates the exec bit if it is
 * not already set. Will also set reference bit at the same time.
 *
 * Caller must check EXECPRM. Do not call if it is already set in the tte.
 *
 * Parameters:
 * tte      = reg containing tte
 * ttepa    = physical pointer to tte
 * tmp1     = tmp reg
 * label    = temporary label
 */

#define	TTE_SET_EXEC_ML(tte, ttepa, tmp1, label)			\
	/* BEGIN CSTYLED */						\
	/* update execprm bit */					\
label/**/1:								\
	or	tte, (TTE_EXECPRM_INT | TTE_REF_INT), tmp1;		\
	casxa	[ttepa]ASI_MEM, tte, tmp1; 	/* update bits */	\
	cmp	tte, tmp1;						\
	bne,a,pn %xcc, label/**/1;					\
	  mov	tmp1, tte;						\
	or	tte, (TTE_EXECPRM_INT | TTE_REF_INT), tte;		\
	/* END CSTYLED */


/*
 * TTE_SET_REF_ML is a macro that updates the reference bit if it is
 * not already set.
 *
 * Parameters:
 * tte      = reg containing tte
 * ttepa    = physical pointer to tte
 * tteva    = virtual ptr to tte
 * tsbarea  = tsb miss area
 * tmp1     = tmp reg
 * label    = temporary label
 */

#define	TTE_SET_REF_ML(tte, ttepa, tteva, tsbarea, tmp1, label)		\
	/* BEGIN CSTYLED */						\
	/* check reference bit */					\
	btst	TTE_REF_INT, tte;					\
	bnz,pt	%xcc, label/**/2;	/* if ref bit set-skip ahead */	\
	nop;								\
	/* update reference bit */					\
label/**/1:								\
	or	tte, TTE_REF_INT, tmp1;					\
	casxa	[ttepa]ASI_MEM, tte, tmp1; 	/* update ref bit */	\
	cmp	tte, tmp1;						\
	bne,a,pn %xcc, label/**/1;					\
	ldxa	[ttepa]ASI_MEM, tte;	/* MMU_READTTE through pa */	\
	or	tte, TTE_REF_INT, tte;					\
label/**/2:								\
	/* END CSTYLED */


/*
 * TTE_SET_REFMOD_ML is a macro that updates the reference and modify bits
 * if not already set.
 *
 * Parameters:
 * tte      = reg containing tte
 * ttepa    = physical pointer to tte
 * tteva    = virtual ptr to tte
 * tsbarea  = tsb miss area
 * tmp1     = tmp reg
 * label    = temporary label
 * exitlabel = label where to jump to if write perm bit not set.
 */

#define	TTE_SET_REFMOD_ML(tte, ttepa, tteva, tsbarea, tmp1, label,	\
	exitlabel)							\
	/* BEGIN CSTYLED */						\
	/* check reference bit */					\
	btst	TTE_WRPRM_INT, tte;					\
	bz,pn	%xcc, exitlabel;	/* exit if wr_perm no set */	\
	  btst	TTE_HWWR_INT, tte;					\
	bnz,pn	%xcc, label/**/2;	/* nothing to do */		\
	  nop;								\
	/* update reference bit */					\
label/**/1:								\
	or	tte, TTE_HWWR_INT | TTE_REF_INT, tmp1;			\
	casxa	[ttepa]ASI_MEM, tte, tmp1; /* update ref/mod bit */	\
	cmp	tte, tmp1;						\
	bne,a,pn %xcc, label/**/1;					\
	  ldxa	[ttepa]ASI_MEM, tte;	/* MMU_READTTE through pa */	\
	or	tte, TTE_HWWR_INT | TTE_REF_INT, tte;			\
label/**/2:								\
	/* END CSTYLED */
/*
 * Get TSB base register from the scratchpad for
 * shared contexts
 *
 * In:
 *   tsbmiss = pointer to tsbmiss area
 *   tsbmissoffset = offset to right tsb pointer
 *   tsbreg = scratch
 * Out:
 *   tsbreg = tsbreg from the specified scratchpad register
 */
#define	GET_UTSBREG_SHCTX(tsbmiss, tsbmissoffset, tsbreg)		\
	ldx	[tsbmiss + tsbmissoffset], tsbreg


/*
 * Get the location of the TSB entry in the first TSB to probe
 *
 * In:
 *   tagacc = tag access register (not clobbered)
 *   tsbe, tmp1, tmp2 = scratch registers
 * Out:
 *   tsbe = pointer to the tsbe in the 1st TSB
 */

#define	GET_1ST_TSBE_PTR(tagacc, tsbe, tmp1, tmp2)			\
	/* BEGIN CSTYLED */						\
	mov	SCRATCHPAD_UTSBREG1, tmp1				;\
	ldxa	[tmp1]ASI_SCRATCHPAD, tsbe	/* get tsbreg */	;\
	and	tsbe, TSB_SOFTSZ_MASK, tmp2	/* tmp2=szc */		;\
	andn	tsbe, TSB_SOFTSZ_MASK, tsbe	/* tsbbase */		;\
	mov	TSB_ENTRIES(0), tmp1	/* nentries in TSB size 0 */	;\
	sllx	tmp1, tmp2, tmp1	/* tmp1 = nentries in TSB */	;\
	sub	tmp1, 1, tmp1		/* mask = nentries - 1 */	;\
	srlx	tagacc, MMU_PAGESHIFT, tmp2 				;\
	and	tmp2, tmp1, tmp1	/* tsbent = virtpage & mask */	;\
	sllx	tmp1, TSB_ENTRY_SHIFT, tmp1	/* entry num --> ptr */	;\
	add	tsbe, tmp1, tsbe	/* add entry offset to TSB base */ ;\
	/* END CSTYLED */


/*
 * Will probe the first TSB, and if it finds a match, will insert it
 * into the TLB and retry.
 *
 * tsbe_ptr = precomputed first TSB entry pointer (in, ro)
 * vpg_4m = 4M virtual page number for tag matching  (in, ro)
 * label = where to branch to if this is a miss (text)
 * %asi = atomic ASI to use for the TSB access
 *
 * For trapstat, we have to explicily use these registers.
 * g4 = location tag will be retrieved into from TSB (out)
 * g5 = location data(tte) will be retrieved into from TSB (out)
 */
#define	PROBE_1ST_DTSB(tsbe_ptr, vpg_4m, label)	/* g4/g5 clobbered */	\
	/* BEGIN CSTYLED */						\
	ldda	[tsbe_ptr]ASI_QUAD_LDD_PHYS, %g4 /* g4 = tag, g5 = data */ ;\
	cmp	%g4, vpg_4m		/* compare tag w/ TSB */	;\
	bne,pn	%xcc, label/**/1	/* branch if !match */		;\
	  nop								;\
	brgez,pn %g5, label/**/1					;\
	  nop								;\
	TT_TRACE(trace_tsbhit)						;\
	DTLB_STUFF(%g5, %g1, %g2, %g3, %g4)				;\
	/* trapstat expects tte in %g5 */				;\
	retry				/* retry faulted instruction */	;\
label/**/1:								\
	/* END CSTYLED */


/*
 * Same as above, only if the TTE doesn't have the execute
 * bit set, will branch to exec_fault directly.
 */
#define	PROBE_1ST_ITSB(tsbe_ptr, vpg_4m, label)				\
	/* BEGIN CSTYLED */						\
	ldda	[tsbe_ptr]ASI_QUAD_LDD_PHYS, %g4 /* g4 = tag, g5 = data */ ;\
	cmp	%g4, vpg_4m		/* compare tag w/ TSB */	;\
	bne,pn	%xcc, label/**/1	/* branch if !match */		;\
	  nop								;\
	brgez,pn %g5, label/**/1					;\
	  nop								;\
	andcc	%g5, TTE_EXECPRM_INT, %g0  /* check execute bit */	;\
	bz,pn	%icc, exec_fault					;\
	  nop								;\
	TT_TRACE(trace_tsbhit)						;\
	ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)				;\
	retry				/* retry faulted instruction */	;\
label/**/1:								\
	/* END CSTYLED */

/*
 * vpg_4m = 4M virtual page number for tag matching (in)
 * tsbe_ptr = precomputed second TSB entry pointer (in)
 * label = label to use to make branch targets unique (text)
 *
 * For trapstat, we have to explicity use these registers.
 * g4 = tag portion of TSBE (out)
 * g5 = data portion of TSBE (out)
 */
#define	PROBE_2ND_DTSB(tsbe_ptr, vpg_4m, label)				\
	/* BEGIN CSTYLED */						\
	ldda	[tsbe_ptr]ASI_QUAD_LDD_PHYS, %g4  /* g4 = tag, g5 = data */ ;\
	/* since we are looking at 2nd tsb, if it's valid, it must be 4M */ ;\
	cmp	%g4, vpg_4m						;\
	bne,pn	%xcc, label/**/1					;\
	  nop								;\
	brgez,pn %g5, label/**/1					;\
	  nop								;\
	mov	tsbe_ptr, %g1		/* trace_tsbhit wants ptr in %g1 */ ;\
	TT_TRACE(trace_tsbhit)						;\
	DTLB_STUFF(%g5, %g1, %g2, %g3, %g4)				;\
	/* trapstat expects tte in %g5 */				;\
	retry				/* retry faulted instruction */	;\
label/**/1:								\
	/* END CSTYLED */


/*
 * Same as above, with the following additions:
 * If the TTE found is not executable, branch directly
 * to exec_fault.  If a TSB miss, branch to TSB miss handler.
 */
#define	PROBE_2ND_ITSB(tsbe_ptr, vpg_4m)				\
	/* BEGIN CSTYLED */						\
	ldda	[tsbe_ptr]ASI_QUAD_LDD_PHYS, %g4 /* g4 = tag, g5 = data */ ;\
	cmp	%g4, vpg_4m		/* compare tag w/ TSB */	;\
	bne,pn	%xcc, sfmmu_tsb_miss_tt	/* branch if !match */		;\
	  nop								;\
	brgez,pn %g5, sfmmu_tsb_miss_tt					;\
	  nop								;\
	andcc	%g5, TTE_EXECPRM_INT, %g0  /* check execute bit */	;\
	bz,pn	%icc, exec_fault					;\
	  mov	tsbe_ptr, %g1		/* trap trace wants ptr in %g1 */ ;\
	TT_TRACE(trace_tsbhit)						;\
	ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)				;\
	retry				/* retry faulted instruction */	\
	/* END CSTYLED */

/*
 * 1. Get ctx1. The traptype is supplied by caller.
 * 2. If iTSB miss, store in MMFSA_I_CTX
 * 3. if dTSB miss, store in MMFSA_D_CTX
 * 4. Thus the [D|I]TLB_STUFF will work as expected.
 */
#define	SAVE_CTX1(traptype, ctx1, tmp, label)				\
	/* BEGIN CSTYLED */						\
	mov	MMU_SCONTEXT1, tmp					;\
	ldxa	[tmp]ASI_MMU_CTX, ctx1					;\
	MMU_FAULT_STATUS_AREA(tmp)					;\
	cmp     traptype, FAST_IMMU_MISS_TT				;\
	be,a,pn %icc, label						;\
	  stx	ctx1, [tmp + MMFSA_I_CTX] 				;\
	cmp     traptype, T_INSTR_MMU_MISS				;\
	be,a,pn %icc, label						;\
	  stx	ctx1, [tmp + MMFSA_I_CTX]				;\
	stx	ctx1, [tmp + MMFSA_D_CTX]				;\
label:
	/* END CSTYLED */

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_MACH_SFMMU_H */
