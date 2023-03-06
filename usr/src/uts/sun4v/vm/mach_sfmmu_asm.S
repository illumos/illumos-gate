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

/*
 * SFMMU primitives.  These primitives should only be used by sfmmu
 * routines.
 */

#include "assym.h"

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
#include <sys/clock.h>
#include <sys/trapstat.h>

/*
 * sfmmu related subroutines
 */

/*
 * Invalidate either the context of a specific victim or any process
 * currently running on this CPU. 
 *
 * %g1 = sfmmup whose ctx is being stolen (victim)
 *	 when called from sfmmu_wrap_around, %g1 == INVALID_CONTEXT.
 * Note %g1 is the only input argument used by this xcall handler.
 */

	ENTRY(sfmmu_raise_tsb_exception)
	!
	! if (victim == INVALID_CONTEXT) {
	!	if (sec-ctx > INVALID_CONTEXT)
	!		write INVALID_CONTEXT to sec-ctx
	!	if (pri-ctx > INVALID_CONTEXT) 
	!		write INVALID_CONTEXT to pri-ctx
	!
	! } else if (current CPU tsbmiss->usfmmup != victim sfmmup) {
	!	return
	! } else {
	!	if (sec-ctx > INVALID_CONTEXT)
	!		write INVALID_CONTEXT to sec-ctx
	!	
	!	if (pri-ctx > INVALID_CONTEXT)
	!		write INVALID_CONTEXT to pri-ctx
	! }
	!

	sethi   %hi(ksfmmup), %g3
	ldx	[%g3 + %lo(ksfmmup)], %g3
	cmp	%g1, %g3
	be,a,pn %xcc, ptl1_panic	/* can't invalidate kernel ctx */
	  mov	PTL1_BAD_RAISE_TSBEXCP, %g1

	set	INVALID_CONTEXT, %g2
	
	cmp	%g1, INVALID_CONTEXT
	bne,pt	%xcc, 1f			/* called from wrap_around? */
	  mov	MMU_SCONTEXT, %g3

	ldxa	[%g3]ASI_MMU_CTX, %g5		/* %g5 = sec-ctx */
	cmp	%g5, INVALID_CONTEXT		/* kernel  or invalid ctx ? */
	ble,pn	%xcc, 0f			/* yes, no need to change */
	  mov	MMU_PCONTEXT, %g7
	
	stxa	%g2, [%g3]ASI_MMU_CTX		/* set invalid ctx */
	membar	#Sync

0:	
	ldxa	[%g7]ASI_MMU_CTX, %g5		/* %g5 = pri-ctx */
	cmp	%g5, INVALID_CONTEXT		/* kernel or invalid ctx? */
	ble,pn	%xcc, 6f			/* yes, no need to change */
	  nop

	stxa	%g2, [%g7]ASI_MMU_CTX		/* set pri-ctx to invalid  */
	membar	#Sync

6:	/* flushall tlb */
	mov	%o0, %g3
	mov	%o1, %g4
	mov	%o2, %g6 
	mov	%o5, %g7

        mov     %g0, %o0        ! XXX no cpu list yet
        mov     %g0, %o1        ! XXX no cpu list yet
        mov     MAP_ITLB | MAP_DTLB, %o2
        mov     MMU_DEMAP_ALL, %o5
        ta      FAST_TRAP
        brz,pt  %o0, 5f
          nop
     	ba ptl1_panic		/* bad HV call */
	  mov	PTL1_BAD_RAISE_TSBEXCP, %g1
5:	
	mov	%g3, %o0
	mov	%g4, %o1
	mov	%g6, %o2
	mov	%g7, %o5
	
	ba	3f
	  nop
1:
	/*
	 * %g1 = sfmmup
	 * %g2 = INVALID_CONTEXT
	 * %g3 = MMU_SCONTEXT
	 */
	CPU_TSBMISS_AREA(%g5, %g6)		/* load cpu tsbmiss area */
	ldx	[%g5 + TSBMISS_UHATID], %g5     /* load usfmmup */

	cmp	%g5, %g1			/* is it the victim? */
	bne,pt	%xcc, 2f			/* is our sec-ctx a victim? */
	  nop

	ldxa    [%g3]ASI_MMU_CTX, %g5           /* %g5 = sec-ctx */
	cmp     %g5, INVALID_CONTEXT            /* kernel  or invalid ctx ? */
	ble,pn  %xcc, 0f                        /* yes, no need to change */
	  mov	MMU_PCONTEXT, %g7

	stxa	%g2, [%g3]ASI_MMU_CTX		/* set sec-ctx to invalid */
	membar	#Sync

0:
	ldxa	[%g7]ASI_MMU_CTX, %g4		/* %g4 = pri-ctx */
	cmp	%g4, INVALID_CONTEXT		/* is pri-ctx the victim? */
	ble 	%icc, 3f			/* no need to change pri-ctx */
	  nop
	stxa	%g2, [%g7]ASI_MMU_CTX		/* set pri-ctx to invalid  */
	membar	#Sync

3:
	/* TSB program must be cleared - walkers do not check a context. */
	mov	%o0, %g3
	mov	%o1, %g4
	mov	%o5, %g7
	clr	%o0
	clr	%o1
	mov	MMU_TSB_CTXNON0, %o5
	ta	FAST_TRAP
	brnz,a,pn %o0, ptl1_panic
	  mov	PTL1_BAD_HCALL, %g1
	mov	%g3, %o0
	mov	%g4, %o1
	mov	%g7, %o5
2:
	retry
	SET_SIZE(sfmmu_raise_tsb_exception)

	ENTRY_NP(sfmmu_getctx_pri)
	set	MMU_PCONTEXT, %o0
	retl
	ldxa	[%o0]ASI_MMU_CTX, %o0
	SET_SIZE(sfmmu_getctx_pri)

	ENTRY_NP(sfmmu_getctx_sec)
	set	MMU_SCONTEXT, %o0
	retl
	ldxa	[%o0]ASI_MMU_CTX, %o0
	SET_SIZE(sfmmu_getctx_sec)

	/*
	 * Set the secondary context register for this process.
	 * %o0 = context number
	 */
	ENTRY_NP(sfmmu_setctx_sec)
	/*
	 * From resume we call sfmmu_setctx_sec with interrupts disabled.
	 * But we can also get called from C with interrupts enabled. So,
	 * we need to check first.
	 */

	/* If interrupts are not disabled, then disable them */
	rdpr	%pstate, %g1
	btst	PSTATE_IE, %g1
	bnz,a,pt %icc, 1f
	wrpr	%g1, PSTATE_IE, %pstate		/* disable interrupts */
1:
	mov	MMU_SCONTEXT, %o1
	stxa	%o0, [%o1]ASI_MMU_CTX		/* set 2nd context reg. */
	membar	#Sync
        /*
         * if the routine is entered with intr enabled, then enable intr now.
         * otherwise, keep intr disabled, return without enabing intr.
         * %g1 - old intr state
         */
        btst    PSTATE_IE, %g1
        bnz,a,pt %icc, 2f
        wrpr    %g0, %g1, %pstate               /* enable interrupts */
2:      retl
        nop
        SET_SIZE(sfmmu_setctx_sec)

	/*
	 * set ktsb_phys to 1 if the processor supports ASI_QUAD_LDD_PHYS.
	 * returns the detection value in %o0.
	 */
	ENTRY_NP(sfmmu_setup_4lp)
	set	ktsb_phys, %o2
	mov	1, %o1
	st	%o1, [%o2]
	retl
	mov	%o1, %o0
	SET_SIZE(sfmmu_setup_4lp)

	/*
	 * Called to load MMU registers and tsbmiss area
	 * for the active process.  This function should
	 * only be called from TL=0.
	 *
	 * %o0 - hat pointer
	 */
	ENTRY_NP(sfmmu_load_mmustate)

#ifdef DEBUG
	PANIC_IF_INTR_ENABLED_PSTR(msfmmu_ei_l1, %g1)
#endif /* DEBUG */

	sethi	%hi(ksfmmup), %o3
	ldx	[%o3 + %lo(ksfmmup)], %o3
	cmp	%o3, %o0
	be,pn	%xcc, 7f			! if kernel as, do nothing
	  nop
	
	set     MMU_SCONTEXT, %o3
        ldxa    [%o3]ASI_MMU_CTX, %o5
	
	cmp	%o5, INVALID_CONTEXT		! ctx is invalid?
	bne,pt	%icc, 1f
	  nop

	CPU_TSBMISS_AREA(%o2, %o3)		! %o2 = tsbmiss area
	stx	%o0, [%o2 + TSBMISS_UHATID]
	stx	%g0, [%o2 +  TSBMISS_SHARED_UHATID]
#ifdef DEBUG
	/* check if hypervisor/hardware should handle user TSB */
	sethi	%hi(hv_use_non0_tsb), %o2
	ld	[%o2 + %lo(hv_use_non0_tsb)], %o2
	brz,pn	%o2, 0f
	  nop
#endif /* DEBUG */
	clr	%o0				! ntsb = 0 for invalid ctx
	clr	%o1				! HV_TSB_INFO_PA = 0 if inv ctx
	mov	MMU_TSB_CTXNON0, %o5
	ta	FAST_TRAP			! set TSB info for user process
	brnz,a,pn %o0, panic_bad_hcall
	  mov	MMU_TSB_CTXNON0, %o1
0:
	retl
	  nop
1:		
	/*
	 * We need to set up the TSB base register, tsbmiss
	 * area, and pass the TSB information into the hypervisor
	 */
	ldx	[%o0 + SFMMU_TSB], %o1		! %o1 = first tsbinfo
	ldx	[%o1 + TSBINFO_NEXTPTR], %g2	! %g2 = second tsbinfo

	/* create/set first UTSBREG */
	MAKE_UTSBREG(%o1, %o2, %o3)		! %o2 = user tsbreg
	SET_UTSBREG(SCRATCHPAD_UTSBREG1, %o2, %o3)

	brz,pt	%g2, 2f
	  mov	-1, %o2				! use -1 if no second TSB

	/* make 2nd UTSBREG */
	MAKE_UTSBREG(%g2, %o2, %o3)		! %o2 = user tsbreg
2:
	SET_UTSBREG(SCRATCHPAD_UTSBREG2, %o2, %o3)

        /* make 3rd and 4th TSB */
	CPU_TSBMISS_AREA(%o4, %o3)		! %o4 = tsbmiss area

	ldx	[%o0 + SFMMU_SCDP], %g2		! %g2 = sfmmu_scd
	brz,pt	%g2, 3f
	  mov	-1, %o2				! use -1 if no third TSB

	ldx	[%g2 + SCD_SFMMUP], %g3		! %g3 = scdp->scd_sfmmup
	ldx	[%g3 + SFMMU_TSB], %o1		! %o1 = first scd tsbinfo
	brz,pn %o1, 9f
	  nop					! panic if no third TSB

	/* make 3rd UTSBREG */
	MAKE_UTSBREG(%o1, %o2, %o3)		! %o2 = user tsbreg
3:
	SET_UTSBREG_SHCTX(%o4, TSBMISS_TSBSCDPTR, %o2)

	brz,pt	%g2, 4f
	  mov	-1, %o2				! use -1 if no 3rd or 4th TSB

	brz,pt	%o1, 4f
	  mov	-1, %o2				! use -1 if no 3rd or 4th TSB
	ldx	[%o1 + TSBINFO_NEXTPTR], %g2	! %g2 = second scd tsbinfo
	brz,pt	%g2, 4f
	  mov	-1, %o2				! use -1 if no 4th TSB

	/* make 4th UTSBREG */
	MAKE_UTSBREG(%g2, %o2, %o3)		! %o2 = user tsbreg
4:
	SET_UTSBREG_SHCTX(%o4, TSBMISS_TSBSCDPTR4M, %o2)

#ifdef DEBUG
	/* check if hypervisor/hardware should handle user TSB */
	sethi	%hi(hv_use_non0_tsb), %o2
	ld	[%o2 + %lo(hv_use_non0_tsb)], %o2
	brz,pn	%o2, 6f
	  nop
#endif /* DEBUG */
	CPU_ADDR(%o2, %o4)	! load CPU struct addr to %o2 using %o4
	ldub    [%o2 + CPU_TSTAT_FLAGS], %o1	! load cpu_tstat_flag to %o1

	mov	%o0, %o3			! preserve %o0
	btst	TSTAT_TLB_STATS, %o1
	bnz,a,pn %icc, 5f			! ntsb = 0 if TLB stats enabled
	  clr	%o0
	
	ldx	[%o3 + SFMMU_HVBLOCK + HV_TSB_INFO_CNT], %o0
5:
	ldx	[%o3 + SFMMU_HVBLOCK + HV_TSB_INFO_PA], %o1	
	mov	MMU_TSB_CTXNON0, %o5
	ta	FAST_TRAP			! set TSB info for user process
	brnz,a,pn %o0, panic_bad_hcall
	mov	MMU_TSB_CTXNON0, %o1
	mov	%o3, %o0			! restore %o0
6:
	ldx	[%o0 + SFMMU_ISMBLKPA], %o1	! copy members of sfmmu
	CPU_TSBMISS_AREA(%o2, %o3)		! %o2 = tsbmiss area
	stx	%o1, [%o2 + TSBMISS_ISMBLKPA]	! sfmmu_tsb_miss into the
	ldub	[%o0 + SFMMU_TTEFLAGS], %o3	! per-CPU tsbmiss area.
	ldub	[%o0 + SFMMU_RTTEFLAGS], %o4
	ldx	[%o0 + SFMMU_SRDP], %o1
	stx	%o0, [%o2 + TSBMISS_UHATID]
	stub	%o3, [%o2 + TSBMISS_UTTEFLAGS]
	stub	%o4,  [%o2 + TSBMISS_URTTEFLAGS]
	stx	%o1, [%o2 +  TSBMISS_SHARED_UHATID]
	brz,pn	%o1, 7f				! check for sfmmu_srdp
	  add	%o0, SFMMU_HMERMAP, %o1
	add	%o2, TSBMISS_SHMERMAP, %o2
	mov	SFMMU_HMERGNMAP_WORDS, %o3
						! set tsbmiss shmermap
	SET_REGION_MAP(%o1, %o2, %o3, %o4, load_shme_mmustate)

	ldx	[%o0 + SFMMU_SCDP], %o4		! %o4 = sfmmu_scd
	CPU_TSBMISS_AREA(%o2, %o3)		! %o2 = tsbmiss area
	mov	SFMMU_HMERGNMAP_WORDS, %o3
	brnz,pt	%o4, 8f				! check for sfmmu_scdp else
	  add	%o2, TSBMISS_SCDSHMERMAP, %o2	! zero tsbmiss scd_shmermap
	ZERO_REGION_MAP(%o2, %o3, zero_scd_mmustate)
7:
	retl
	nop
8:						! set tsbmiss scd_shmermap
	add	%o4, SCD_HMERMAP, %o1
	SET_REGION_MAP(%o1, %o2, %o3, %o4, load_scd_mmustate)
	retl
	  nop
9:
	sethi   %hi(panicstr), %g1		! panic if no 3rd TSB  
        ldx     [%g1 + %lo(panicstr)], %g1                             
        tst     %g1
	                                                   
        bnz,pn  %xcc, 7b                                            
          nop                                                            
                                                                        
        sethi   %hi(sfmmu_panic10), %o0                                 
        call    panic                                                 
          or      %o0, %lo(sfmmu_panic10), %o0                         

	SET_SIZE(sfmmu_load_mmustate)
	
	ENTRY(prefetch_tsbe_read)
	retl
	nop
	SET_SIZE(prefetch_tsbe_read)

	ENTRY(prefetch_tsbe_write)
	retl
	nop
	SET_SIZE(prefetch_tsbe_write)
