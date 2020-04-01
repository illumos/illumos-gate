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
 * %g1 = sfmmup whose ctx is being invalidated
 *	 when called from sfmmu_wrap_around, %g1 == INVALID_CONTEXT
 * Note %g1 is the only input argument used by this xcall handler.
 */
	ENTRY(sfmmu_raise_tsb_exception)
	!
	! if (victim == INVALID_CONTEXT ||
	!     current CPU tsbmiss->usfmmup == victim sfmmup) {
	!       if (shctx_on) {
	!               shctx = INVALID;
	!       }
	!	if (sec-ctx > INVALID_CONTEXT) {
	!		write INVALID_CONTEXT to sec-ctx
	!	}
	!	if (pri-ctx > INVALID_CONTEXT) {
	!		write INVALID_CONTEXT to pri-ctx
	!	}
	! }

	sethi   %hi(ksfmmup), %g3
        ldx     [%g3 + %lo(ksfmmup)], %g3
	cmp	%g1, %g3
	be,a,pn %xcc, ptl1_panic		/* can't invalidate kernel ctx */
	  mov	PTL1_BAD_RAISE_TSBEXCP, %g1

	set	INVALID_CONTEXT, %g2
	cmp	%g1, INVALID_CONTEXT
	be,pn	%xcc, 0f			/* called from wrap_around? */
	  mov	MMU_SCONTEXT, %g3

	CPU_TSBMISS_AREA(%g5, %g6)		/* load cpu tsbmiss area */
	ldx	[%g5 + TSBMISS_UHATID], %g5     /* load usfmmup */
	cmp	%g5, %g1			/* hat toBe-invalid running? */
	bne,pt	%xcc, 3f
	  nop

0:
	sethi   %hi(shctx_on), %g5
        ld      [%g5 + %lo(shctx_on)], %g5
        brz     %g5, 1f
          mov     MMU_SHARED_CONTEXT, %g5
        sethi   %hi(FLUSH_ADDR), %g4
        stxa    %g0, [%g5]ASI_MMU_CTX
        flush   %g4

1:
	ldxa	[%g3]ASI_MMU_CTX, %g5		/* %g5 = pgsz | sec-ctx */
	set     CTXREG_CTX_MASK, %g4
	and	%g5, %g4, %g5			/* %g5 = sec-ctx */
	cmp	%g5, INVALID_CONTEXT		/* kernel ctx or invald ctx? */
	ble,pn	%xcc, 2f			/* yes, no need to change */
	  mov   MMU_PCONTEXT, %g7

	stxa	%g2, [%g3]ASI_MMU_CTX		/* set invalid ctx */
	membar	#Sync
	
2:
	ldxa	[%g7]ASI_MMU_CTX, %g3		/* get pgz | pri-ctx */
	and     %g3, %g4, %g5			/* %g5 = pri-ctx */
	cmp	%g5, INVALID_CONTEXT		/* kernel ctx or invald ctx? */
	ble,pn	%xcc, 3f			/* yes, no need to change */
	  srlx	%g3, CTXREG_NEXT_SHIFT, %g3	/* %g3 = nucleus pgsz */
	sllx	%g3, CTXREG_NEXT_SHIFT, %g3	/* need to preserve nucleus pgsz */
	or	%g3, %g2, %g2			/* %g2 = nucleus pgsz | INVALID_CONTEXT */
	
	stxa	%g2, [%g7]ASI_MMU_CTX		/* set pri-ctx to invalid */
3:
	retry
	SET_SIZE(sfmmu_raise_tsb_exception)
	


	/*
	 * %o0 = virtual address
	 * %o1 = address of TTE to be loaded
	 */
	ENTRY_NP(sfmmu_itlb_ld_kva)
	rdpr	%pstate, %o3
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o3, msfmmu_di_l1, %g1)
#endif /* DEBUG */
	wrpr	%o3, PSTATE_IE, %pstate		! Disable interrupts
	srln	%o0, MMU_PAGESHIFT, %o0
	slln	%o0, MMU_PAGESHIFT, %o0		! Clear page offset

	ldx	[%o1], %g1
	set	MMU_TAG_ACCESS, %o5
#ifdef	CHEETAHPLUS_ERRATUM_34
	!
	! If this is Cheetah or derivative and the specified TTE is locked
	! and hence to be loaded into the T16, fully-associative TLB, we
	! must avoid Cheetah+ erratum 34.  In Cheetah+ erratum 34, under
	! certain conditions an ITLB locked index 0 TTE will erroneously be
	! displaced when a new TTE is loaded via ASI_ITLB_IN.  To avoid
	! this erratum, we scan the T16 top down for an unlocked TTE and
	! explicitly load the specified TTE into that index.
	!
	GET_CPU_IMPL(%g2)
	cmp	%g2, CHEETAH_IMPL
	bl,pn	%icc, 0f
	  nop

	andcc	%g1, TTE_LCK_INT, %g0
	bz	%icc, 0f			! Lock bit is not set;
						!   load normally.
	  or	%g0, (15 << 3), %g3		! Start searching from the
						!   top down.

1:
	ldxa	[%g3]ASI_ITLB_ACCESS, %g4	! Load TTE from t16

	!
	! If this entry isn't valid, we'll choose to displace it (regardless
	! of the lock bit).
	!
	cmp	%g4, %g0
	bge	%xcc, 2f			! TTE is > 0 iff not valid
	  andcc	%g4, TTE_LCK_INT, %g0		! Check for lock bit
	bz	%icc, 2f			! If unlocked, go displace
	  nop
	sub	%g3, (1 << 3), %g3
	brgz	%g3, 1b				! Still more TLB entries
	  nop					! to search

	sethi   %hi(sfmmu_panic5), %o0          ! We searched all entries and
	call    panic                           ! found no unlocked TTE so
	  or    %o0, %lo(sfmmu_panic5), %o0     ! give up.


2:
	!
	! We have found an unlocked or non-valid entry; we'll explicitly load
	! our locked entry here.
	!
	sethi	%hi(FLUSH_ADDR), %o1		! Flush addr doesn't matter
	stxa	%o0, [%o5]ASI_IMMU
	stxa	%g1, [%g3]ASI_ITLB_ACCESS
	flush	%o1				! Flush required for I-MMU
	ba	3f				! Delay slot of ba is empty
	  nop					!   per Erratum 64

0:
#endif	/* CHEETAHPLUS_ERRATUM_34 */
	sethi	%hi(FLUSH_ADDR), %o1		! Flush addr doesn't matter
	stxa	%o0, [%o5]ASI_IMMU
	stxa	%g1, [%g0]ASI_ITLB_IN
	flush	%o1				! Flush required for I-MMU
3:
	retl
	  wrpr	%g0, %o3, %pstate		! Enable interrupts
	SET_SIZE(sfmmu_itlb_ld_kva)

	/*
	 * Load an entry into the DTLB.
	 *
	 * Special handling is required for locked entries since there
	 * are some TLB slots that are reserved for the kernel but not
	 * always held locked.  We want to avoid loading locked TTEs
	 * into those slots since they could be displaced.
	 *
	 * %o0 = virtual address
	 * %o1 = address of TTE to be loaded
	 */
	ENTRY_NP(sfmmu_dtlb_ld_kva)
	rdpr	%pstate, %o3
#ifdef DEBUG
	PANIC_IF_INTR_DISABLED_PSTR(%o3, msfmmu_di_l2, %g1)
#endif /* DEBUG */
	wrpr	%o3, PSTATE_IE, %pstate		! disable interrupts
	srln	%o0, MMU_PAGESHIFT, %o0
	slln	%o0, MMU_PAGESHIFT, %o0		! clear page offset

	ldx	[%o1], %g1

	set	MMU_TAG_ACCESS, %o5
	
	set	cpu_impl_dual_pgsz, %o2
	ld	[%o2], %o2
	brz	%o2, 1f
	  nop

	sethi	%hi(ksfmmup), %o2
	ldx	[%o2 + %lo(ksfmmup)], %o2
	ldub    [%o2 + SFMMU_CEXT], %o2
        sll     %o2, TAGACCEXT_SHIFT, %o2

	set	MMU_TAG_ACCESS_EXT, %o4		! can go into T8 if unlocked
	stxa	%o2,[%o4]ASI_DMMU
	membar	#Sync
1:
	andcc	%g1, TTE_LCK_INT, %g0		! Locked entries require
	bnz,pn	%icc, 2f			! special handling
	  sethi	%hi(dtlb_resv_ttenum), %g3
	stxa	%o0,[%o5]ASI_DMMU		! Load unlocked TTE
	stxa	%g1,[%g0]ASI_DTLB_IN		! via DTLB_IN
	membar	#Sync
	retl
	  wrpr	%g0, %o3, %pstate		! enable interrupts
2:
#ifdef	CHEETAHPLUS_ERRATUM_34
	GET_CPU_IMPL(%g2)
#endif
	ld	[%g3 + %lo(dtlb_resv_ttenum)], %g3
	sll	%g3, 3, %g3			! First reserved idx in TLB 0
	sub	%g3, (1 << 3), %g3		! Decrement idx
	! Erratum 15 workaround due to ld [%g3 + %lo(dtlb_resv_ttenum)], %g3
	ldxa	[%g3]ASI_DTLB_ACCESS, %g4	! Load TTE from TLB 0
3:
	ldxa	[%g3]ASI_DTLB_ACCESS, %g4	! Load TTE from TLB 0
	!
	! If this entry isn't valid, we'll choose to displace it (regardless
	! of the lock bit).
	!
	brgez,pn %g4, 4f			! TTE is > 0 iff not valid
	  nop
	andcc	%g4, TTE_LCK_INT, %g0		! Check for lock bit
	bz,pn	%icc, 4f			! If unlocked, go displace
	  nop
	sub	%g3, (1 << 3), %g3		! Decrement idx
#ifdef	CHEETAHPLUS_ERRATUM_34
	!
	! If this is a Cheetah or derivative, we must work around Erratum 34
	! for the DTLB.  Erratum 34 states that under certain conditions, 
	! a locked entry 0 TTE may be improperly displaced.  To avoid this,
	! we do not place a locked TTE in entry 0.
	!
	brgz	%g3, 3b
	  nop
	cmp	%g2, CHEETAH_IMPL
	bge,pt	%icc, 5f
	  nop
	brz	%g3, 3b
	 nop
#else	/* CHEETAHPLUS_ERRATUM_34 */
	brgez	%g3, 3b
	  nop
#endif	/* CHEETAHPLUS_ERRATUM_34 */
5:
	sethi	%hi(sfmmu_panic5), %o0		! We searched all entries and
	call	panic				! found no unlocked TTE so
	  or	%o0, %lo(sfmmu_panic5), %o0	! give up.
4:
	stxa	%o0,[%o5]ASI_DMMU		! Setup tag access
#ifdef	OLYMPUS_SHARED_FTLB
	stxa	%g1,[%g0]ASI_DTLB_IN
#else
	stxa	%g1,[%g3]ASI_DTLB_ACCESS	! Displace entry at idx
#endif
	membar	#Sync
	retl
	  wrpr	%g0, %o3, %pstate		! enable interrupts
	SET_SIZE(sfmmu_dtlb_ld_kva)

	ENTRY_NP(sfmmu_getctx_pri)
	set	MMU_PCONTEXT, %o0
	retl
	  ldxa	[%o0]ASI_MMU_CTX, %o0
	SET_SIZE(sfmmu_getctx_pri)

	ENTRY_NP(sfmmu_getctx_sec)
	set	MMU_SCONTEXT, %o0
	set	CTXREG_CTX_MASK, %o1
	ldxa	[%o0]ASI_MMU_CTX, %o0
	retl
	  and	%o0, %o1, %o0
	SET_SIZE(sfmmu_getctx_sec)

	/*
	 * Set the secondary context register for this process.
	 * %o0 = page_size | context number for this process.
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

	sethi	%hi(FLUSH_ADDR), %o4
	stxa	%o0, [%o1]ASI_MMU_CTX		/* set 2nd context reg. */
	flush	%o4
        sethi   %hi(shctx_on), %g3
        ld      [%g3 + %lo(shctx_on)], %g3
	brz     %g3, 2f
	  nop
	set	CTXREG_CTX_MASK, %o4
	and	%o0,%o4,%o1
	cmp	%o1, INVALID_CONTEXT
	bne,pn %icc, 2f
   	  mov     MMU_SHARED_CONTEXT, %o1
        sethi   %hi(FLUSH_ADDR), %o4
        stxa    %g0, [%o1]ASI_MMU_CTX           /* set 2nd context reg. */
        flush   %o4

	/*
	 * if the routine was entered with intr enabled, then enable intr now.
	 * otherwise, keep intr disabled, return without enabing intr.
	 * %g1 - old intr state
	 */
2:	btst	PSTATE_IE, %g1
	bnz,a,pt %icc, 3f
	  wrpr	%g0, %g1, %pstate		/* enable interrupts */
3:	retl
	  nop
	SET_SIZE(sfmmu_setctx_sec)

	/*
	 * set ktsb_phys to 1 if the processor supports ASI_QUAD_LDD_PHYS.
	 * returns the detection value in %o0.
	 *
	 * Currently ASI_QUAD_LDD_PHYS is supported in processors as follows
	 *  - cheetah+ and later (greater or equal to CHEETAH_PLUS_IMPL)
	 *  - FJ OPL Olympus-C and later  (less than SPITFIRE_IMPL)
	 *
	 */
	ENTRY_NP(sfmmu_setup_4lp)
	GET_CPU_IMPL(%o0);
	cmp	%o0, CHEETAH_PLUS_IMPL
	bge,pt	%icc, 4f
	  mov	1, %o1
	cmp	%o0, SPITFIRE_IMPL
	bge,a,pn %icc, 3f
	  clr	%o1
4:
	set	ktsb_phys, %o2
	st	%o1, [%o2]
3:	retl
	mov	%o1, %o0
	SET_SIZE(sfmmu_setup_4lp)


	/*
	 * Called to load MMU registers and tsbmiss area
	 * for the active process.  This function should
	 * only be called from TL=0.
	 *
	 * %o0 - hat pointer
	 *
	 */
	ENTRY_NP(sfmmu_load_mmustate)

#ifdef DEBUG
        PANIC_IF_INTR_ENABLED_PSTR(msfmmu_ei_l3, %g1)
#endif /* DEBUG */

        sethi   %hi(ksfmmup), %o3
        ldx     [%o3 + %lo(ksfmmup)], %o3
        cmp     %o3, %o0
        be,pn   %xcc, 8f			! if kernel as, do nothing
          nop      
        /*
         * We need to set up the TSB base register, tsbmiss
         * area, and load locked TTE(s) for the TSB.
         */
        ldx     [%o0 + SFMMU_TSB], %o1          ! %o1 = first tsbinfo
        ldx     [%o1 + TSBINFO_NEXTPTR], %g2    ! %g2 = second tsbinfo

#ifdef UTSB_PHYS
        /*
         * UTSB_PHYS accesses user TSBs via physical addresses.  The first
         * TSB is in the MMU I/D TSB Base registers.  The 2nd, 3rd and 
	 * 4th TSBs use designated ASI_SCRATCHPAD regs as pseudo TSB base regs.
	 */
	 
        /* create/set first UTSBREG actually loaded into MMU_TSB  */
        MAKE_UTSBREG(%o1, %o2, %o3)             ! %o2 = first utsbreg
 	LOAD_TSBREG(%o2, %o3, %o4)              ! write TSB base register

        brz,a,pt  %g2, 2f
          mov   -1, %o2                         ! use -1 if no second TSB

        MAKE_UTSBREG(%g2, %o2, %o3)             ! %o2 = second utsbreg
2:
        SET_UTSBREG(SCRATCHPAD_UTSBREG2, %o2, %o3)

	/* make 3rd and 4th TSB */
	CPU_TSBMISS_AREA(%o4, %o3) 		! %o4 = tsbmiss area

        ldx     [%o0 + SFMMU_SCDP], %g2         ! %g2 = sfmmu_scd
        brz,pt  %g2, 3f
          mov   -1, %o2                         ! use -1 if no third TSB

        ldx     [%g2 + SCD_SFMMUP], %g3         ! %g3 = scdp->scd_sfmmup
        ldx     [%g3 + SFMMU_TSB], %o1          ! %o1 = first scd tsbinfo
        brz,pn %o1, 5f
          nop                                   ! panic if no third TSB

	/* make 3rd UTSBREG */
        MAKE_UTSBREG(%o1, %o2, %o3)             ! %o2 = third utsbreg
3:
        SET_UTSBREG(SCRATCHPAD_UTSBREG3, %o2, %o3)
	stn	%o2, [%o4 + TSBMISS_TSBSCDPTR]

        brz,pt  %g2, 4f
          mov   -1, %o2                         ! use -1 if no 3rd or 4th TSB

        ldx     [%o1 + TSBINFO_NEXTPTR], %g2    ! %g2 = second scd tsbinfo
        brz,pt  %g2, 4f
          mov   -1, %o2                         ! use -1 if no 4th TSB

	/* make 4th UTSBREG */
        MAKE_UTSBREG(%g2, %o2, %o3)             ! %o2 = fourth utsbreg
4:
        SET_UTSBREG(SCRATCHPAD_UTSBREG4, %o2, %o3)
	stn	%o2, [%o4 + TSBMISS_TSBSCDPTR4M]
	ba,pt	%icc, 6f
	  mov	%o4, %o2			! %o2 = tsbmiss area
5:
        sethi   %hi(panicstr), %g1              ! panic if no 3rd TSB
        ldx     [%g1 + %lo(panicstr)], %g1
        tst     %g1

        bnz,pn  %xcc, 8f
          nop    

        sethi   %hi(sfmmu_panic10), %o0
        call    panic
          or     %o0, %lo(sfmmu_panic10), %o0
	  
#else /* UTSBREG_PHYS */

        brz,pt  %g2, 4f	
          nop
        /*
         * We have a second TSB for this process, so we need to
         * encode data for both the first and second TSB in our single
         * TSB base register.  See hat_sfmmu.h for details on what bits
         * correspond to which TSB.
         * We also need to load a locked TTE into the TLB for the second TSB
         * in this case.
         */
        MAKE_TSBREG_SECTSB(%o2, %o1, %g2, %o3, %o4, %g3, sfmmu_tsb_2nd)
        ! %o2 = tsbreg
        sethi   %hi(utsb4m_dtlb_ttenum), %o3
        sethi   %hi(utsb4m_vabase), %o4
        ld      [%o3 + %lo(utsb4m_dtlb_ttenum)], %o3
        ldx     [%o4 + %lo(utsb4m_vabase)], %o4 ! %o4 = TLB tag for sec TSB
        sll     %o3, DTACC_SHIFT, %o3           ! %o3 = sec TSB TLB index
        RESV_OFFSET(%g2, %o4, %g3, sfmmu_tsb_2nd)       ! or-in bits of TSB VA
        LOAD_TSBTTE(%g2, %o3, %o4, %g3)         ! load sec TSB locked TTE
        sethi   %hi(utsb_vabase), %g3
        ldx     [%g3 + %lo(utsb_vabase)], %g3   ! %g3 = TLB tag for first TSB
        ba,pt   %xcc, 5f
          nop

4:      sethi   %hi(utsb_vabase), %g3
        ldx     [%g3 + %lo(utsb_vabase)], %g3   ! %g3 = TLB tag for first TSB
        MAKE_TSBREG(%o2, %o1, %g3, %o3, %o4, sfmmu_tsb_1st)     ! %o2 = tsbreg

5:      LOAD_TSBREG(%o2, %o3, %o4)              ! write TSB base register

        /*
         * Load the TTE for the first TSB at the appropriate location in
         * the TLB
         */
        sethi   %hi(utsb_dtlb_ttenum), %o2
        ld      [%o2 + %lo(utsb_dtlb_ttenum)], %o2
        sll     %o2, DTACC_SHIFT, %o2           ! %o1 = first TSB TLB index
        RESV_OFFSET(%o1, %g3, %o3, sfmmu_tsb_1st)       ! or-in bits of TSB VA
        LOAD_TSBTTE(%o1, %o2, %g3, %o4)         ! load first TSB locked TTE
	CPU_TSBMISS_AREA(%o2, %o3)
#endif /* UTSB_PHYS */
6:
	ldx     [%o0 + SFMMU_ISMBLKPA], %o1     ! copy members of sfmmu
	              				! we need to access from
        stx     %o1, [%o2 + TSBMISS_ISMBLKPA]   ! sfmmu_tsb_miss into the
        ldub    [%o0 + SFMMU_TTEFLAGS], %o3     ! per-CPU tsbmiss area.
        stx     %o0, [%o2 + TSBMISS_UHATID]
        stub    %o3, [%o2 + TSBMISS_UTTEFLAGS]
#ifdef UTSB_PHYS
        ldx     [%o0 + SFMMU_SRDP], %o1
        ldub    [%o0 + SFMMU_RTTEFLAGS], %o4
        stub    %o4,  [%o2 + TSBMISS_URTTEFLAGS]
        stx     %o1, [%o2 +  TSBMISS_SHARED_UHATID]
        brz,pn  %o1, 8f				! check for sfmmu_srdp
          add   %o0, SFMMU_HMERMAP, %o1
        add     %o2, TSBMISS_SHMERMAP, %o2
        mov     SFMMU_HMERGNMAP_WORDS, %o3
                                                ! set tsbmiss shmermap
        SET_REGION_MAP(%o1, %o2, %o3, %o4, load_shme_mmustate)

	ldx     [%o0 + SFMMU_SCDP], %o4         ! %o4 = sfmmu_scd
        CPU_TSBMISS_AREA(%o2, %o3)              ! %o2 = tsbmiss area
        mov     SFMMU_HMERGNMAP_WORDS, %o3
        brnz,pt %o4, 7f                       ! check for sfmmu_scdp else
          add   %o2, TSBMISS_SCDSHMERMAP, %o2 ! zero tsbmiss scd_shmermap
        ZERO_REGION_MAP(%o2, %o3, zero_scd_mmustate)
	ba 8f
	  nop
7:
        add     %o4, SCD_HMERMAP, %o1
        SET_REGION_MAP(%o1, %o2, %o3, %o4, load_scd_mmustate)
#endif /* UTSB_PHYS */

8:
	retl
          nop
        SET_SIZE(sfmmu_load_mmustate)

/*
 * Invalidate all of the entries within the TSB, by setting the inv bit
 * in the tte_tag field of each tsbe.
 *
 * We take advantage of the fact that the TSBs are page aligned and a
 * multiple of PAGESIZE to use ASI_BLK_INIT_xxx ASI.
 *
 * See TSB_LOCK_ENTRY and the miss handlers for how this works in practice
 * (in short, we set all bits in the upper word of the tag, and we give the
 * invalid bit precedence over other tag bits in both places).
 */

#define	VIS_BLOCKSIZE	64

	ENTRY(sfmmu_inv_tsb_fast)

	! Get space for aligned block of saved fp regs.
	save	%sp, -SA(MINFRAME + 2*VIS_BLOCKSIZE), %sp

	! kpreempt_disable();
	ldsb	[THREAD_REG + T_PREEMPT], %l3
	inc	%l3
	stb	%l3, [THREAD_REG + T_PREEMPT]

	! See if fpu was in use.  If it was, we need to save off the
	! floating point registers to the stack.
	rd	%fprs, %l0			! %l0 = cached copy of fprs
	btst	FPRS_FEF, %l0
	bz,pt	%icc, 4f
	  nop

	! save in-use fpregs on stack
	membar	#Sync				! make sure tranx to fp regs
						! have completed
	add	%fp, STACK_BIAS - 65, %l1	! get stack frame for fp regs
	and	%l1, -VIS_BLOCKSIZE, %l1	! block align frame
	stda	%d0, [%l1]ASI_BLK_P		! %l1 = addr of saved fp regs

	! enable fp
4:	membar	#StoreStore|#StoreLoad|#LoadStore
	wr	%g0, FPRS_FEF, %fprs
	wr	%g0, ASI_BLK_P, %asi

	! load up FP registers with invalid TSB tag.
	fone	%d0			! ones in tag
	fzero	%d2			! zeros in TTE
	fone	%d4			! ones in tag
	fzero	%d6			! zeros in TTE
	fone	%d8			! ones in tag
	fzero	%d10			! zeros in TTE
	fone	%d12			! ones in tag
	fzero	%d14			! zeros in TTE
	ba,pt	%xcc, .sfmmu_inv_doblock
	  mov	(4*VIS_BLOCKSIZE), %i4	! we do 4 stda's each loop below

.sfmmu_inv_blkstart:
      ! stda	%d0, [%i0+192]%asi  ! in dly slot of branch that got us here
	stda	%d0, [%i0+128]%asi
	stda	%d0, [%i0+64]%asi
	stda	%d0, [%i0]%asi

	add	%i0, %i4, %i0
	sub	%i1, %i4, %i1

.sfmmu_inv_doblock:
	cmp	%i1, (4*VIS_BLOCKSIZE)	! check for completion
	bgeu,a	%icc, .sfmmu_inv_blkstart
	  stda	%d0, [%i0+192]%asi

.sfmmu_inv_finish:
	membar	#Sync
	btst	FPRS_FEF, %l0		! saved from above
	bz,a	.sfmmu_inv_finished
	  wr	%l0, 0, %fprs		! restore fprs

	! restore fpregs from stack
	ldda    [%l1]ASI_BLK_P, %d0
	membar	#Sync
	wr	%l0, 0, %fprs		! restore fprs

.sfmmu_inv_finished:
	! kpreempt_enable();
	ldsb	[THREAD_REG + T_PREEMPT], %l3
	dec	%l3
	stb	%l3, [THREAD_REG + T_PREEMPT]
	ret
	  restore
	SET_SIZE(sfmmu_inv_tsb_fast)

/*
 * Prefetch "struct tsbe" while walking TSBs.
 * prefetch 7 cache lines ahead of where we are at now.
 * #n_reads is being used since #one_read only applies to
 * floating point reads, and we are not doing floating point
 * reads.  However, this has the negative side effect of polluting
 * the ecache.
 * The 448 comes from (7 * 64) which is how far ahead of our current
 * address, we want to prefetch.
 */
	ENTRY(prefetch_tsbe_read)
	retl
	  prefetch	[%o0+448], #n_reads
	SET_SIZE(prefetch_tsbe_read)

/* Prefetch the tsbe that we are about to write */
	ENTRY(prefetch_tsbe_write)
	retl
	  prefetch	[%o0], #n_writes
	SET_SIZE(prefetch_tsbe_write)

