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

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/machcpuvar.h>
#include <sys/mmu.h>
#include <sys/intreg.h>
#include <sys/dmv.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */


vec_uiii_irdr_tab:
        .byte   UIII_IRDR_0, UIII_IRDR_1, UIII_IRDR_2, UIII_IRDR_3
        .byte   UIII_IRDR_4, UIII_IRDR_5, UIII_IRDR_6, UIII_IRDR_7

/*
 * (TT 0x60, TL>0) Interrupt Vector Handler
 *	Globals are the Interrupt Globals.
 */
	ENTRY_NP(vec_interrupt)
	!
	! Load the interrupt receive data register 0.
	! It could be a fast trap handler address (pc > KERNELBASE) at TL>0
	! or an interrupt number.
	!
	mov	IRDR_0, %g2
	ldxa	[%g2]ASI_INTR_RECEIVE, %g5	! %g5 = PC or Interrupt Number

	! If the high bit of IRDR_0 is set, then this is a
	! data bearing mondo vector.
	brlz,pt %g5, dmv_vector
	.empty


vec_interrupt_resume:	
	set	KERNELBASE, %g4
	cmp	%g5, %g4
	bl,a,pt	%xcc, 0f			! an interrupt number found
	  nop
	!
	! intercept OBP xcalls and set PCONTEXT=0
	!
	set	_end, %g4		! _end is highest kernel address
	cmp	%g5, %g4
	bl,a,pt	%xcc, 7f
	  nop

#ifndef _OPL
	mov	MMU_PCONTEXT, %g1
	ldxa	[%g1]ASI_DMMU, %g1
	srlx	%g1, CTXREG_NEXT_SHIFT, %g3
	brz,pt	%g3, 7f			! nucleus pgsz is 0, no problem
	  sllx	%g3, CTXREG_NEXT_SHIFT, %g3
	set	CTXREG_CTX_MASK, %g4	! check Pcontext
	btst	%g4, %g1
	bz,a,pt	%xcc, 6f
	  clr	%g3			! kernel:  PCONTEXT=0
	xor	%g3, %g1, %g3		! user:	clr N_pgsz0/1 bits
6:
	set	DEMAP_ALL_TYPE, %g1
	stxa	%g0, [%g1]ASI_DTLB_DEMAP
	stxa	%g0, [%g1]ASI_ITLB_DEMAP
	mov	MMU_PCONTEXT, %g1
	stxa	%g3, [%g1]ASI_DMMU
        membar  #Sync
	sethi	%hi(FLUSH_ADDR), %g1
	flush	%g1			! flush required by immu
#endif /* _OPL */

7:
	!
	!  Cross-trap request case
	!
	! Load interrupt receive data registers 1 and 2 to fetch
	! the arguments for the fast trap handler.
	!
	! Register usage:
	!	g5: TL>0 handler
	!	g1: arg1
	!	g2: arg2
	!	g3: arg3
	!	g4: arg4
	!
	mov	IRDR_1, %g2
	ldxa	[%g2]ASI_INTR_RECEIVE, %g1
	mov	IRDR_2, %g2
	ldxa	[%g2]ASI_INTR_RECEIVE, %g2
#ifdef TRAPTRACE
	TRACE_PTR(%g4, %g6)
	GET_TRACE_TICK(%g6, %g3)
	stxa	%g6, [%g4 + TRAP_ENT_TICK]%asi
	rdpr	%tl, %g6
	stha	%g6, [%g4 + TRAP_ENT_TL]%asi
	rdpr	%tt, %g6
	stha	%g6, [%g4 + TRAP_ENT_TT]%asi
	rdpr	%tpc, %g6
	stna	%g6, [%g4 + TRAP_ENT_TPC]%asi
	rdpr	%tstate, %g6
	stxa	%g6, [%g4 + TRAP_ENT_TSTATE]%asi
	stna	%sp, [%g4 + TRAP_ENT_SP]%asi
	stna	%g5, [%g4 + TRAP_ENT_TR]%asi	! pc of the TL>0 handler
	stxa	%g1, [%g4 + TRAP_ENT_F1]%asi
	stxa	%g2, [%g4 + TRAP_ENT_F3]%asi
	stxa	%g0, [%g4 + TRAP_ENT_F2]%asi
	stxa	%g0, [%g4 + TRAP_ENT_F4]%asi
	TRACE_NEXT(%g4, %g6, %g3)
#endif /* TRAPTRACE */
	stxa	%g0, [%g0]ASI_INTR_RECEIVE_STATUS	! clear the BUSY bit
	membar	#Sync
#ifdef SF_ERRATA_51
	ba,pt	%icc, 1f
	nop
	.align 32
1:	jmp	%g5				! call the fast trap handler
	nop
#else
	jmp	%g5
	nop
#endif /* SF_ERRATA_51 */
	/* Never Reached */

0:
	! We have an interrupt number.
        !
	! Register usage:
	!	%g5 - inum
	!	%g1 - temp
	!
        ! We don't bother to verify that the received inum is valid (it should
        ! be < MAXIVNUM) since setvecint_tl1 will do that for us.
        !
	! clear BUSY bit
	!
	stxa	%g0, [%g0]ASI_INTR_RECEIVE_STATUS
	membar	#Sync

	! setvecint_tl1 will do all the work, and finish with a retry
	!
	ba,pt	%xcc, setvecint_tl1
	mov	%g5, %g1		! setvecint_tl1 expects inum in %g1

	/* Never Reached */
	SET_SIZE(vec_interrupt)


!	
!   See usr/src/uts/sun4u/sys/dmv.h for the Databearing Mondo Vector
!	 interrupt format
!
! Inputs:
!	g1: value of ASI_INTR_RECEIVE_STATUS
!	g5: word 0 of the interrupt data
! Register use:
!	g2: dmv inum
!	g3: scratch
!	g4: pointer to dmv_dispatch_table
!	g6: handler pointer from dispatch table


	DGDEF(dmv_spurious_cnt)
	.word	0

	ENTRY_NP(dmv_vector)
	srlx	%g5, DMV_INUM_SHIFT, %g2
	set	DMV_INUM_MASK, %g3
	and	%g2, %g3, %g2		   ! %g2 = inum

	set	dmv_totalints, %g3
	ld	[%g3], %g3
	cmp	%g2, %g3
	bge,pn	%xcc, 2f		   ! inum >= dmv_totalints
	nop
	
	set	dmv_dispatch_table, %g3
	ldn	[%g3], %g4
	brz,pn	%g4, 2f
	sll	%g2, DMV_DISP_SHIFT, %g3   ! %g3 = inum*sizeof(struct dmv_disp)
		
	add	%g4, %g3, %g4		! %g4 = &dmv_dispatch_table[inum]
#if (DMV_FUNC != 0) || (DMV_ARG != 8)
#error "DMV_FUNC or DMV_SIZE has changed"
#endif
	ldda	[%g4]ASI_NQUAD_LD, %g2  ! %g2=handler %g3=argument
	mov	%g3, %g1
	brz,pn  %g2, 2f	
	nop
	
	! we have a handler, so call it
	! On entry to the handler, the %g registers are set as follows:
	!
	!	%g1	The argument (arg) passed to dmv_add_intr().
	!	%g2	Word 0 of the incoming mondo vector.
	!
	jmp	%g2
	mov	%g5, %g2
		
	! No handler was listed in the table, so just record it
	! as an error condition and continue.  There is a race
	! window here updating the counter, but that's ok since
	! just knowing that spurious interrupts happened is enough,
	! we probably won't need to know exactly how many.
2:
	set	dmv_spurious_cnt, %g1
	ld	[%g1], %g2
	inc	%g2
	ba,pt	%xcc,3f
	st	%g2, [%g1]
	
	!	When the handler's processing (which should be as quick as
	!	possible) is complete, the handler must exit by jumping to
	!	the label dmv_finish_intr.  The contents of %g1 at this time
	!	determine whether a software interrupt will be issued, as
	!	follows:
	!
	!		If %g1 is less than zero, no interrupt will be queued.
	!		Otherwise, %g1 will be used as the interrupt number
	!		to simulate; this means that the behavior of the
	!		interrupt system will be exactly that which would have
	!		occurred if the first word of the incoming interrupt
	!		vector had contained the contents of %g1.

	ENTRY_NP(dmv_finish_intr)
	brlz,pn %g1,3f
	nop
	!	generate an interrupt based on the contents of %g1
	ba,pt	%xcc,vec_interrupt_resume
	mov	%g1, %g5
	!	We are done
3:	
	stxa	%g0, [%g0]ASI_INTR_RECEIVE_STATUS ! clear the busy bit
	retry
	SET_SIZE(dmv_vector)

	DGDEF(vec_spurious_cnt)
	.word	0

	ENTRY_NP(vec_intr_spurious)
	sethi	%hi(vec_spurious_cnt), %g2
	ld	[%g2 + %lo(vec_spurious_cnt)], %g2
#ifdef TRAPTRACE
	TRACE_PTR(%g4, %g6)
	GET_TRACE_TICK(%g6, %g3)
	stxa	%g6, [%g4 + TRAP_ENT_TICK]%asi
	rdpr	%tl, %g6
	stha	%g6, [%g4 + TRAP_ENT_TL]%asi
	rdpr	%tt, %g6
	or	%g6, TT_SPURIOUS_INT, %g6
	stha	%g6, [%g4 + TRAP_ENT_TT]%asi
	rdpr	%tpc, %g6
	stna	%g6, [%g4 + TRAP_ENT_TPC]%asi
	rdpr	%tstate, %g6
	stxa	%g6, [%g4 + TRAP_ENT_TSTATE]%asi
	stna	%sp, [%g4 + TRAP_ENT_SP]%asi
	stna	%g1, [%g4 + TRAP_ENT_TR]%asi	! irsr
	stna	%g2, [%g4 + TRAP_ENT_F1]%asi
	ldxa	[%g0]ASI_INTR_RECEIVE_STATUS, %g5
	stxa	%g5, [%g4 + TRAP_ENT_F2]%asi
	stxa	%g0, [%g4 + TRAP_ENT_F4]%asi
	TRACE_NEXT(%g4, %g6, %g3)
#endif /* TRAPTRACE */
	cmp	%g2, 16
	bl,a,pt	%xcc, 1f
	inc	%g2
	!
	! prepare for sys_trap()
	!	%g1 - sys_tl1_panic
	!	%g2 - panic message
	!	%g4 - current pil
	!
#ifdef CLEAR_INTR_BUSYBIT_ON_SPURIOUS
	/*
	 * Certain processors (OPL) need to explicitly
	 * clear the intr busy bit even though it is
	 * not visibly set (spurious intrs)
	 */
	stxa	%g0, [%g0]ASI_INTR_RECEIVE_STATUS	! clear the BUSY bit
	membar  #Sync
#endif /* CLEAR_INTR_BUSYBIT_ON_SPURIOUS */
	sub	%g0, 1, %g4
	set	_not_ready, %g2
	sethi	%hi(sys_tl1_panic), %g1
	ba,pt	%xcc, sys_trap
	or	%g1, %lo(sys_tl1_panic), %g1
	!
1:	sethi	%hi(vec_spurious_cnt), %g1
	st	%g2, [%g1 + %lo(vec_spurious_cnt)]
	retry
	SET_SIZE(vec_intr_spurious)

_not_ready:	.asciz	"Interrupt Vector Receive Register not READY"

