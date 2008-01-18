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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/x_call.h>
#include <sys/cheetahregs.h>
#include <sys/spitregs.h>
#include <sys/opl_olympus_regs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * On sun4u platforms, user TSBs are accessed via virtual address by default.
 * Platforms that support ASI_SCRATCHPAD registers can define UTSB_PHYS in the
 * platform Makefile to access user TSBs via physical address but must also
 * designate one ASI_SCRATCHPAD register to hold the second user TSB.  To
 * designate the user TSB scratchpad register, platforms must provide a
 * definition for SCRATCHPAD_UTSBREG below.
 *
 * Platforms that use UTSB_PHYS do not allocate 2 locked TLB entries to access
 * the user TSBs.
 */
#if defined(UTSB_PHYS)

#if defined(_OPL)
#define	SCRATCHPAD_UTSBREG	OPL_SCRATCHPAD_UTSBREG4
#else
#error "Compiling UTSB_PHYS but no SCRATCHPAD_UTSBREG specified"
#endif

#endif /* UTSB_PHYS */


#ifdef _ASM

/*
 * This macro is used to set private secondary context register in
 * sfmmu_alloc_ctx().
 * Input:
 * cnum : cnum
 * arg2 : unused
 */
#define	SET_SECCTX(cnum, arg2, tmp1, tmp2)			\
	mov	MMU_SCONTEXT, tmp1;				\
	sethi	%hi(FLUSH_ADDR), tmp2;				\
	stxa	cnum, [tmp1]ASI_MMU_CTX;			\
	flush	tmp2

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
	ba	label;						\
	wrpr	%g0, 1, %tl;					\
9:


/*
 * The following macros allow us to share majority of the
 * SFMMU code between sun4u and sun4v platforms.
 */

#define	SETUP_TSB_ASI(qlp, tmp)					\
	movrz	qlp, ASI_N, tmp;				\
	movrnz	qlp, ASI_MEM, tmp;				\
	mov	tmp, %asi

/*
 * Macro to swtich to alternate global register on sun4u platforms
 * (not applicable to sun4v platforms)
 */
#define	USE_ALTERNATE_GLOBALS(scr)				\
	rdpr	%pstate, scr;					\
	wrpr	scr, PSTATE_MG | PSTATE_AG, %pstate

/*
 * Macro to set %gl register value on sun4v platforms
 * (not applicable to sun4u platforms)
 */
#define	SET_GL_REG(val)

/*
 * Get MMU data tag access register value
 *
 * In:
 *   tagacc, scr1 = scratch registers
 * Out:
 *   tagacc = MMU data tag access register value
 */
#define	GET_MMU_D_TAGACC(tagacc, scr1)				\
	mov	MMU_TAG_ACCESS, scr1;				\
	ldxa	[scr1]ASI_DMMU, tagacc

/*
 * Get MMU data tag target register
 *
 * In:
 *   ttarget, scr1 = scratch registers
 * Out:
 *   ttarget = MMU data tag target register value
 */
#define	GET_MMU_D_TTARGET(ttarget, scr1)			\
	ldxa	[%g0]ASI_DMMU, ttarget

/*
 * Get MMU data/instruction tag access register values
 *
 * In:
 *   dtagacc, itagacc, scr1, scr2 = scratch registers
 * Out:
 *   dtagacc = MMU data tag access register value
 *   itagacc = MMU instruction tag access register value
 */
#define	GET_MMU_BOTH_TAGACC(dtagacc, itagacc, scr1, scr2)	\
	mov	MMU_TAG_ACCESS, scr1;				\
	ldxa	[scr1]ASI_DMMU, dtagacc;			\
	ldxa	[scr1]ASI_IMMU, itagacc

/*
 * Get MMU data fault address from the tag access register
 *
 * In:
 *   daddr, scr1 = scratch registers
 * Out:
 *   daddr = MMU data fault address
 */
#define	GET_MMU_D_ADDR(daddr, scr1)				\
	mov	MMU_TAG_ACCESS, scr1;				\
	ldxa	[scr1]ASI_DMMU, daddr;				\
	set	TAGACC_CTX_MASK, scr1;				\
	andn	daddr, scr1, daddr


/*
 * Load ITLB entry
 *
 * In:
 *   tte = reg containing tte
 *   scr1, scr2, scr3, scr4 = scratch registers (not used)
 */
#define	ITLB_STUFF(tte, scr1, scr2, scr3, scr4)			\
	stxa	tte, [%g0]ASI_ITLB_IN

/*
 * Load DTLB entry
 *
 * In:
 *   tte = reg containing tte
 *   scr1, scr2, scr3, scr4 = scratch register (not used)
 */
#define	DTLB_STUFF(tte, scr1, scr2, scr3, scr4)			\
	stxa	tte, [%g0]ASI_DTLB_IN


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
	srlx	tte, TTE_SZ_SHFT, scr1;					\
	and	scr1, TTE_SZ_BITS, scr1;	/* scr1 = tte_size */	\
	srlx	tte, TTE_SZ2_SHFT, scr3;				\
	and	scr3, TTE_SZ2_BITS, scr3;	/* scr3 = tte_size2 */	\
	or	scr1, scr3, scr1;					\
	sllx	scr1, 1, scr2;						\
	add	scr2, scr1, scr2;		/* mulx 3 */		\
	sllx	tte, TTE_PA_LSHIFT, tte;				\
	add	scr2, MMU_PAGESHIFT + TTE_PA_LSHIFT, scr3;		\
	/* BEGIN CSTYLED */						\
	brz,pt	scr2, label/**/1;					\
	  srlx	tte, scr3, tte;						\
	/* END CSTYLED */						\
	sllx	tte, scr2, tte;						\
	set	1, scr1;						\
	add	scr2, MMU_PAGESHIFT, scr3;				\
	sllx	scr1, scr3, scr1;					\
	sub	scr1, 1, scr1;		/* g2=TTE_PAGE_OFFSET(ttesz) */	\
	and	vaddr, scr1, scr2;					\
	srln	scr2, MMU_PAGESHIFT, scr2;				\
	or	tte, scr2, tte;						\
	/* CSTYLED */							\
label/**/1:


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
	andcc	tte, TTE_REF_INT, %g0;					\
	bnz,pt	%xcc, label/**/4;	/* if ref bit set-skip ahead */	\
	  nop;								\
	GET_CPU_IMPL(tmp1);						\
	cmp	tmp1, SPITFIRE_IMPL;					\
	blt	%icc, label/**/2;	/* skip flush if FJ-OPL cpus */	\
	cmp	tmp1, CHEETAH_IMPL;					\
	bl,a	%icc, label/**/1;					\
	/* update reference bit */					\
	lduh	[tsbarea + TSBMISS_DMASK], tmp1;			\
	stxa	%g0, [ttepa]ASI_DC_INVAL; /* flush line from dcache */	\
	membar	#Sync;							\
	ba	label/**/2;						\
label/**/1:								\
	and	tteva, tmp1, tmp1;					\
	stxa	%g0, [tmp1]ASI_DC_TAG; /* flush line from dcache */	\
	membar	#Sync;							\
label/**/2:								\
	or	tte, TTE_REF_INT, tmp1;					\
	casxa	[ttepa]ASI_MEM, tte, tmp1; 	/* update ref bit */	\
	cmp	tte, tmp1;						\
	bne,a,pn %xcc, label/**/2;					\
	ldxa	[ttepa]ASI_MEM, tte;	/* MMU_READTTE through pa */	\
	or	tte, TTE_REF_INT, tte;					\
label/**/4:								\
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
	andcc	tte, TTE_WRPRM_INT, %g0;				\
	bz,pn	%xcc, exitlabel;	/* exit if wr_perm not set */	\
	  nop;								\
	andcc	tte, TTE_HWWR_INT, %g0;					\
	bnz,pn	%xcc, label/**/4;	/* nothing to do */		\
	  nop;								\
	GET_CPU_IMPL(tmp1);						\
	cmp	tmp1, SPITFIRE_IMPL;					\
	blt	%icc, label/**/2;	/* skip flush if FJ-OPL cpus */	\
	cmp	tmp1, CHEETAH_IMPL;					\
	bl,a	%icc, label/**/1;					\
	/* update reference bit */					\
	lduh	[tsbarea + TSBMISS_DMASK], tmp1;			\
	stxa    %g0, [ttepa]ASI_DC_INVAL; /* flush line from dcache */ 	\
	membar	#Sync;							\
	ba	label/**/2;						\
label/**/1:								\
	and	tteva, tmp1, tmp1;					\
	stxa	%g0, [tmp1]ASI_DC_TAG; /* flush line from dcache */	\
	membar	#Sync;							\
label/**/2:								\
	or	tte, TTE_HWWR_INT | TTE_REF_INT, tmp1;			\
	casxa	[ttepa]ASI_MEM, tte, tmp1; /* update ref/mod bit */	\
	cmp	tte, tmp1;						\
	bne,a,pn %xcc, label/**/2;					\
	  ldxa	[ttepa]ASI_MEM, tte;	/* MMU_READTTE through pa */	\
	or	tte, TTE_HWWR_INT | TTE_REF_INT, tte;			\
label/**/4:								\
	/* END CSTYLED */


#ifndef UTSB_PHYS

/*
 * Synthesize TSB base register contents for a process with
 * a single TSB.
 *
 * We patch the virtual address mask in at runtime since the
 * number of significant virtual address bits in the TSB VA
 * can vary depending upon the TSB slab size being used on the
 * machine.
 *
 * In:
 *   tsbinfo = TSB info pointer (ro)
 *   vabase = value of utsb_vabase (ro)
 * Out:
 *   tsbreg = value to program into TSB base register
 */

#define	MAKE_TSBREG(tsbreg, tsbinfo, vabase, tmp1, tmp2, label)		\
	/* BEGIN CSTYLED */						\
	ldx	[tsbinfo + TSBINFO_VADDR], tmp1;			\
	.global	label/**/_tsbreg_vamask					;\
label/**/_tsbreg_vamask:						\
	or	%g0, RUNTIME_PATCH, tsbreg;				\
	lduh	[tsbinfo + TSBINFO_SZCODE], tmp2;			\
	sllx	tsbreg, TSBREG_VAMASK_SHIFT, tsbreg;			\
	or	vabase, tmp2, tmp2;					\
	and	tmp1, tsbreg, tsbreg;					\
	or	tsbreg, tmp2, tsbreg;					\
	/* END CSTYLED */


/*
 * Synthesize TSB base register contents for a process with
 * two TSBs.  See hat_sfmmu.h for the layout of the TSB base
 * register in this case.
 *
 * In:
 *   tsb1 = pointer to first TSB info (ro)
 *   tsb2 = pointer to second TSB info (ro)
 * Out:
 *   tsbreg = value to program into TSB base register
 */
#define	MAKE_TSBREG_SECTSB(tsbreg, tsb1, tsb2, tmp1, tmp2, tmp3, label)	\
	/* BEGIN CSTYLED */						\
	set	TSBREG_MSB_CONST, tmp3					;\
	sllx	tmp3, TSBREG_MSB_SHIFT, tsbreg				;\
	.global	label/**/_tsbreg_vamask					;\
label/**/_tsbreg_vamask:						;\
	or	%g0, RUNTIME_PATCH, tmp3				;\
	sll	tmp3, TSBREG_VAMASK_SHIFT, tmp3				;\
	ldx	[tsb1 + TSBINFO_VADDR], tmp1				;\
	ldx	[tsb2 + TSBINFO_VADDR], tmp2				;\
	and	tmp1, tmp3, tmp1					;\
	and	tmp2, tmp3, tmp2					;\
	sllx	tmp2, TSBREG_SECTSB_MKSHIFT, tmp2			;\
	or	tmp1, tmp2, tmp3					;\
	or	tsbreg, tmp3, tsbreg					;\
	lduh	[tsb1 + TSBINFO_SZCODE], tmp1				;\
	lduh	[tsb2 + TSBINFO_SZCODE], tmp2				;\
	and	tmp1, TSB_SOFTSZ_MASK, tmp1				;\
	and	tmp2, TSB_SOFTSZ_MASK, tmp2				;\
	sllx	tmp2, TSBREG_SECSZ_SHIFT, tmp2				;\
	or	tmp1, tmp2, tmp3					;\
	or	tsbreg, tmp3, tsbreg					;\
	/* END CSTYLED */


/*
 * Load the locked TSB TLB entry.
 *
 * In:
 *   tsbinfo = tsb_info pointer as va (ro)
 *   tteidx = shifted index into TLB to load the locked entry (ro)
 *   va = virtual address at which to load the locked TSB entry (ro)
 * Out:
 * Scratch:
 *   tmp
 */
#define	LOAD_TSBTTE(tsbinfo, tteidx, va, tmp)				\
	mov	MMU_TAG_ACCESS, tmp;					\
	stxa	va, [tmp]ASI_DMMU;		/* set tag access */	\
	membar	#Sync;							\
	ldx	[tsbinfo + TSBINFO_TTE], tmp;	/* fetch locked tte */	\
	stxa	tmp, [tteidx]ASI_DTLB_ACCESS;	/* load locked tte */	\
	membar	#Sync


/*
 * In the current implementation, TSBs usually come from physically
 * contiguous chunks of memory up to 4MB in size, but 8K TSBs may be
 * allocated from 8K chunks of memory under certain conditions.  To
 * prevent aliasing in the virtual address cache when the TSB slab is
 * 8K in size we must align the reserved (TL>0) TSB virtual address to
 * have the same low-order bits as the kernel (TL=0) TSB virtual address,
 * and map 8K TSBs with an 8K TTE.  In cases where the TSB reserved VA
 * range is smaller than the assumed 4M we will patch the shift at
 * runtime; otherwise we leave it alone (which is why RUNTIME_PATCH
 * constant doesn't appear below).
 *
 * In:
 *   tsbinfo (ro)
 *   resva: reserved VA base for this TSB
 * Out:
 *   resva: corrected VA for this TSB
 */
#define	RESV_OFFSET(tsbinfo, resva, tmp1, label)			\
	/* BEGIN CSTYLED */						\
	lduh	[tsbinfo + TSBINFO_SZCODE], tmp1			;\
	brgz,pn	tmp1, label/**/9	 				;\
	  nop								;\
	ldx	[tsbinfo + TSBINFO_VADDR], tmp1				;\
	.global	label/**/_resv_offset					;\
label/**/_resv_offset:							;\
	sllx	tmp1, (64 - MMU_PAGESHIFT4M), tmp1			;\
	srlx	tmp1, (64 - MMU_PAGESHIFT4M), tmp1			;\
	or	tmp1, resva, resva					;\
label/**/9:								\
	/* END CSTYLED */

/*
 * Determine the pointer of the entry in the first TSB to probe given
 * the 8K TSB pointer register contents.
 *
 * In:
 *   tsbp8k = 8K TSB pointer register (ro)
 *   tmp = scratch register
 *   label = label for hot patching of utsb_vabase
 *
 * Out: tsbe_ptr = TSB entry address
 *
 * Note: This function is patched at runtime for performance reasons.
 *	 Any changes here require sfmmu_patch_utsb fixed.
 */

#define	GET_1ST_TSBE_PTR(tsbp8k, tsbe_ptr, tmp, label)			\
	/* BEGIN CSTYLED */						\
label/**/_get_1st_tsbe_ptr:						;\
	RUNTIME_PATCH_SETX(tsbe_ptr, tmp)				;\
	/* tsbeptr = contents of utsb_vabase */				;\
	/* clear upper bits leaving just bits 21:0 of TSB ptr. */	;\
	sllx	tsbp8k, TSBREG_FIRTSB_SHIFT, tmp			;\
	/* finish clear */						;\
	srlx	tmp, TSBREG_FIRTSB_SHIFT, tmp				;\
	/* or-in bits 41:22 of the VA to form the real pointer. */	;\
	or	tsbe_ptr, tmp, tsbe_ptr					\
	/* END CSTYLED */

/*
 * Determine the base address of the second TSB given the 8K TSB
 * pointer register contents.
 *
 * In:
 *   tsbp8k = 8K TSB pointer register (ro)
 *   tmp = scratch register
 *   label = label for hot patching of utsb_vabase
 *
 * Out:
 *   tsbbase = TSB base address
 *
 * Note: This function is patched at runtime for performance reasons.
 *	 Any changes here require sfmmu_patch_utsb fixed.
 */

#define	GET_2ND_TSB_BASE(tsbp8k, tsbbase, tmp, label)			\
	/* BEGIN CSTYLED */						\
label/**/_get_2nd_tsb_base:						;\
	RUNTIME_PATCH_SETX(tsbbase, tmp)				;\
	/* tsbbase = contents of utsb4m_vabase */			;\
	/* clear upper bits leaving just bits 21:xx of TSB addr. */	;\
	sllx	tsbp8k, TSBREG_SECTSB_LSHIFT, tmp			;\
	/* clear lower bits leaving just 21:13 in 8:0 */		;\
	srlx	tmp, (TSBREG_SECTSB_RSHIFT + MMU_PAGESHIFT), tmp	;\
	/* adjust TSB offset to bits 21:13 */				;\
	sllx	tmp, MMU_PAGESHIFT, tmp					;\
	or	tsbbase, tmp, tsbbase					;\
	/* END CSTYLED */

/*
 * Determine the size code of the second TSB given the 8K TSB
 * pointer register contents.
 *
 * In:
 *   tsbp8k = 8K TSB pointer register (ro)
 * Out:
 *   size = TSB size code
 */

#define	GET_2ND_TSB_SIZE(tsbp8k, size)					\
	srlx	tsbp8k, TSBREG_SECSZ_SHIFT, size;			\
	and	size, TSB_SOFTSZ_MASK, size

/*
 * Get the location in the 2nd TSB of the tsbe for this fault.
 * Assumes that the second TSB only contains 4M mappings.
 *
 * In:
 *   tagacc = tag access register (clobbered)
 *   tsbp8k = contents of TSB8K pointer register (ro)
 *   tmp1, tmp2 = scratch registers
 *   label = label at which to patch in reserved TSB 4M VA range
 * Out:
 *   tsbe_ptr = pointer to the tsbe in the 2nd TSB
 */
#define	GET_2ND_TSBE_PTR(tagacc, tsbp8k, tsbe_ptr, tmp1, tmp2, label)	\
	GET_2ND_TSB_BASE(tsbp8k, tsbe_ptr, tmp2, label);		\
	/* tsbe_ptr = TSB base address, tmp2 = junk */			\
	GET_2ND_TSB_SIZE(tsbp8k, tmp1);					\
	/* tmp1 = TSB size code */					\
	GET_TSBE_POINTER(MMU_PAGESHIFT4M, tsbe_ptr, tagacc, tmp1, tmp2)

#endif /* UTSB_PHYS */


#ifdef UTSB_PHYS

/*
 * Synthesize a TSB base register contents for a process.
 *
 * In:
 *   tsbinfo = TSB info pointer (ro)
 *   tsbreg, tmp1 = scratch registers
 * Out:
 *   tsbreg = value to program into TSB base register
 */

#define	MAKE_UTSBREG_PHYS(tsbinfo, tsbreg, tmp1)			\
	ldx	[tsbinfo + TSBINFO_PADDR], tsbreg;		\
	lduh	[tsbinfo + TSBINFO_SZCODE], tmp1;		\
	and	tmp1, TSB_SOFTSZ_MASK, tmp1;			\
	or	tsbreg, tmp1, tsbreg;				\

/*
 * Load TSB base register into a dedicated scratchpad register.
 * This register contains utsb_pabase in bits 63:13, and TSB size
 * code in bits 2:0.
 *
 * In:
 *   tsbreg = value to load (ro)
 *   regnum = constant or register
 *   tmp1 = scratch register
 * Out:
 *   Specified scratchpad register updated
 *
 * Note: If this is enabled on Panther, a membar #Sync is required
 *	 following an ASI store to the scratchpad registers.
 */

#define	SET_UTSBREG(regnum, tsbreg, tmp1)				\
	mov	regnum, tmp1;						\
	stxa	tsbreg, [tmp1]ASI_SCRATCHPAD;	/* save tsbreg */	\

/*
 * Get TSB base register from the scratchpad
 *
 * In:
 *   regnum = constant or register
 *   tsbreg = scratch
 * Out:
 *   tsbreg = tsbreg from the specified scratchpad register
 */

#define	GET_UTSBREG(regnum, tsbreg)					\
	mov	regnum, tsbreg;						\
	ldxa	[tsbreg]ASI_SCRATCHPAD, tsbreg

/*
 * Determine the pointer of the entry in the first TSB to probe given
 * the 8K TSB pointer register contents.
 *
 * In:
 *   tagacc = tag access register
 *   tsbe_ptr = 8K TSB pointer register
 *   tmp = scratch registers
 *
 * Out: tsbe_ptr = TSB entry address
 *
 * Note: This macro is a nop since the 8K TSB pointer register
 *	 is the entry pointer and does not need to be decoded.
 *	 It is defined to allow for code sharing with sun4v.
 */

#define	GET_1ST_TSBE_PTR(tagacc, tsbe_ptr, tmp1, tmp2)

/*
 * Get the location in the 2nd TSB of the tsbe for this fault.
 * Assumes that the second TSB only contains 4M mappings.
 *
 * In:
 *   tagacc = tag access register (not clobbered)
 *   tsbe = 2nd TSB base register
 *   tmp1, tmp2 = scratch registers
 * Out:
 *   tsbe = pointer to the tsbe in the 2nd TSB
 */

#define	GET_2ND_TSBE_PTR(tagacc, tsbe, tmp1, tmp2)			\
	and	tsbe, TSB_SOFTSZ_MASK, tmp2;	/* tmp2=szc */		\
	andn	tsbe, TSB_SOFTSZ_MASK, tsbe;	/* tsbbase */		\
	mov	TSB_ENTRIES(0), tmp1;	/* nentries in TSB size 0 */	\
	sllx	tmp1, tmp2, tmp1;	/* tmp1 = nentries in TSB */	\
	sub	tmp1, 1, tmp1;		/* mask = nentries - 1 */	\
	srlx	tagacc, MMU_PAGESHIFT4M, tmp2; 				\
	and	tmp2, tmp1, tmp1;	/* tsbent = virtpage & mask */	\
	sllx	tmp1, TSB_ENTRY_SHIFT, tmp1;	/* entry num --> ptr */	\
	add	tsbe, tmp1, tsbe	/* add entry offset to TSB base */

/*
 * Read the 2nd TSB base register.  This is not done in GET_2ND_TSBE_PTR as
 * an optimization since the TLB miss trap handler entries have potentially
 * already loaded the 2nd TSB base reg when we invoke GET_2ND_TSBE_PTR.
 *
 * Out:
 *   tsbreg = contents of the 2nd TSB base register
 */
#define	GET_2ND_TSBREG(tsbreg)						\
	GET_UTSBREG(SCRATCHPAD_UTSBREG, tsbreg);

/*
 * Load the 2nd TSB base into a dedicated scratchpad register which
 * is used as a pseudo TSB base register.
 *
 * In:
 *   tsbreg = value to load (ro)
 *   regnum = constant or register
 *   tmp1 = scratch register
 * Out:
 *   Specified scratchpad register updated
 */
#define	LOAD_2ND_TSBREG(tsbreg, tmp1)					\
	SET_UTSBREG(SCRATCHPAD_UTSBREG, tsbreg, tmp1);

#endif /* UTSB_PHYS */


/*
 * Load TSB base register.  In the single TSB case this register
 * contains utsb_vabase, bits 21:13 of tsbinfo->tsb_va, and the
 * TSB size code in bits 2:0.  See hat_sfmmu.h for the layout in
 * the case where we have multiple TSBs per process.
 *
 * In:
 *   tsbreg = value to load (ro)
 */
#define	LOAD_TSBREG(tsbreg, tmp1, tmp2)					\
	mov	MMU_TSB, tmp1;						\
	sethi	%hi(FLUSH_ADDR), tmp2;					\
	stxa	tsbreg, [tmp1]ASI_DMMU;		/* dtsb reg */		\
	stxa	tsbreg, [tmp1]ASI_IMMU;		/* itsb reg */		\
	flush	tmp2

#ifdef UTSB_PHYS
#define	UTSB_PROBE_ASI	ASI_QUAD_LDD_PHYS
#else
#define	UTSB_PROBE_ASI	ASI_NQUAD_LD
#endif

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
	ldda	[tsbe_ptr]UTSB_PROBE_ASI, %g4 /* g4 = tag, g5 = data */	;\
	cmp	%g4, vpg_4m		/* compare tag w/ TSB */	;\
	bne,pn	%xcc, label/**/1	/* branch if !match */		;\
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
	ldda	[tsbe_ptr]UTSB_PROBE_ASI, %g4 /* g4 = tag, g5 = data */	;\
	cmp	%g4, vpg_4m		/* compare tag w/ TSB */	;\
	bne,pn	%xcc, label/**/1	/* branch if !match */		;\
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
	ldda	[tsbe_ptr]UTSB_PROBE_ASI, %g4 /* g4 = tag, g5 = data */	;\
	/* since we are looking at 2nd tsb, if it's valid, it must be 4M */ ;\
	cmp	%g4, vpg_4m						;\
	bne,pn	%xcc, label/**/1					;\
	  nop								;\
	mov	tsbe_ptr, %g1		/* trace_tsbhit wants ptr in %g1 */ ;\
	TT_TRACE(trace_tsbhit)						;\
	DTLB_STUFF(%g5, %g1, %g2, %g3, %g4)				;\
	/* trapstat expects tte in %g5 */				;\
	retry				/* retry faulted instruction */	;\
label/**/1:								\
	/* END CSTYLED */

/*
 * Macro to get SCD shared hme map on sun4v platforms
 * (not applicable to sun4u platforms)
 */
#define	GET_SCDSHMERMAP(tsbarea, hmeblkpa, hatid, hmemisc)

#ifndef TRAPTRACE
/*
 * Same as above, with the following additions:
 * If the TTE found is not executable, branch directly
 * to exec_fault after checking for ITLB synthesis.
 * If a TSB miss, branch to TSB miss handler.
 */
#define	PROBE_2ND_ITSB(tsbe_ptr, vpg_4m, label)				\
	/* BEGIN CSTYLED */						\
	ldda	[tsbe_ptr]UTSB_PROBE_ASI, %g4 /* g4 = tag, g5 = data */	;\
	cmp	%g4, vpg_4m		/* compare tag w/ TSB */	;\
	bne,pn	%xcc, sfmmu_tsb_miss_tt	/* branch if !match */		;\
	  or	%g0, TTE4M, %g6						;\
	andcc	%g5, TTE_EXECPRM_INT, %g0  /* check execute bit */	;\
	bz,a,pn	%icc, label/**/1					;\
	  sllx	%g6, TTE_SZ_SHFT, %g6					;\
	ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)				;\
	retry				/* retry faulted instruction */ ;\
label/**/1:								;\
	andcc %g5, TTE_E_SYNTH_INT, %g0					;\
	bz,pn	%icc, exec_fault					;\
	  or	%g5, %g6, %g5						;\
	ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)				;\
	retry				/* retry faulted instruction */	\
	/* END CSTYLED */
#else /* TRAPTRACE */
/*
 * Same as above, with the TT_TRACE and mov tsbe_ptr, %g1 additions.
 */
#define	PROBE_2ND_ITSB(tsbe_ptr, vpg_4m, label)				\
	/* BEGIN CSTYLED */						\
	ldda	[tsbe_ptr]UTSB_PROBE_ASI, %g4 /* g4 = tag, g5 = data */	;\
	cmp	%g4, vpg_4m		/* compare tag w/ TSB */	;\
	bne,pn	%xcc, sfmmu_tsb_miss_tt	/* branch if !match */		;\
	  or	%g0, TTE4M, %g6						;\
	andcc	%g5, TTE_EXECPRM_INT, %g0  /* check execute bit */	;\
	bz,a,pn	%icc, label/**/1					;\
	  sllx	%g6, TTE_SZ_SHFT, %g6					;\
	mov	tsbe_ptr, %g1		/* trap trace wants ptr in %g1 */ ;\
	TT_TRACE(trace_tsbhit)						;\
	ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)				;\
	retry				/* retry faulted instruction */ ;\
label/**/1:								;\
	andcc %g5, TTE_E_SYNTH_INT, %g0				;\
	bz,pn	%icc, exec_fault					;\
	  mov	tsbe_ptr, %g1		/* trap trace wants ptr in %g1 */ ;\
	or	%g5, %g6, %g5						;\
	TT_TRACE(trace_tsbhit)						;\
	ITLB_STUFF(%g5, %g1, %g2, %g3, %g4)				;\
	retry				/* retry faulted instruction */	\
	/* END CSTYLED */

#endif /* TRAPTRACE */
#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_MACH_SFMMU_H */
