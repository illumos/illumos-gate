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
#include <sys/intreg.h>
#include <sys/cmn_err.h>
#include <sys/ftrace.h>
#include <sys/machasi.h>
#include <sys/scb.h>
#include <sys/error.h>
#include <sys/mmu.h>
#include <vm/hat_sfmmu.h>
#define	INTR_REPORT_SIZE	64

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */


/*
 * (TT 0x7c, TL>0) CPU Mondo Queue Handler
 *	Globals are the Interrupt Globals.
 */
	ENTRY_NP(cpu_mondo)
	!
	!	Register Usage:-
	!	%g5	PC for fasttrap TL>0 handler
	!	%g1	arg 1	
	!	%g2	arg 2	
	!	%g3	queue base VA 
	!	%g4 	queue size mask	
	!	%g6	head ptr
	!	%g7	tail ptr	
	mov	CPU_MONDO_Q_HD, %g3	
	ldxa	[%g3]ASI_QUEUE, %g6	! %g6 = head ptr 
	mov	CPU_MONDO_Q_TL, %g4	
	ldxa	[%g4]ASI_QUEUE, %g7	! %g7 = tail ptr 
	cmp	%g6, %g7
	be,pn	%xcc, 3f		! head == tail
	nop
	
	CPU_ADDR(%g1,%g2)
	add	%g1, CPU_MCPU, %g2
	ldx	[%g2 + MCPU_CPU_Q_BASE], %g3	! %g3 = queue base PA
	ldx	[%g2 + MCPU_CPU_Q_SIZE], %g4	! queue size
	sub	%g4, 1, %g4		! %g4 = queue size mask	

	! Load interrupt receive data registers 1 and 2 to fetch
	! the arguments for the fast trap handler.
	!
	! XXX - Since the data words in the interrupt report are not defined yet 
	! we assume that the consective words contain valid data and preserve
	! sun4u's xcall mondo arguments. 
	! Register usage:
	!	%g5	PC for fasttrap TL>0 handler
	!	%g1	arg 1	
	!	%g2	arg 2	

	ldxa	[%g3 + %g6]ASI_MEM, %g5	! get PC from q base + head
	add	%g6, 0x8, %g6		! inc head
	ldxa	[%g3 + %g6]ASI_MEM, %g1 ! read data word 1
	add	%g6, 0x8, %g6		! inc head
	ldxa	[%g3 + %g6]ASI_MEM, %g2	! read data word 2
	add	%g6, (INTR_REPORT_SIZE - 16) , %g6 ! inc head to next record	
	and	%g6, %g4, %g6 		! and size mask for wrap around	
	mov	CPU_MONDO_Q_HD, %g3	
	stxa	%g6, [%g3]ASI_QUEUE	! store head pointer 
	membar	#Sync

#ifdef TRAPTRACE
	TRACE_PTR(%g4, %g6)
	GET_TRACE_TICK(%g6, %g3)
	stxa	%g6, [%g4 + TRAP_ENT_TICK]%asi
	TRACE_SAVE_TL_GL_REGS(%g4, %g6)
	rdpr	%tt, %g6
	stha	%g6, [%g4 + TRAP_ENT_TT]%asi
	rdpr	%tpc, %g6
	stna	%g6, [%g4 + TRAP_ENT_TPC]%asi
	rdpr	%tstate, %g6
	stxa	%g6, [%g4 + TRAP_ENT_TSTATE]%asi
	stna	%sp, [%g4 + TRAP_ENT_SP]%asi
	stna	%g5, [%g4 + TRAP_ENT_TR]%asi	! pc of the TL>0 handler
	stna	%g1, [%g4 + TRAP_ENT_F1]%asi	! arg1
	stna	%g2, [%g4 + TRAP_ENT_F3]%asi	! arg2
	mov	CPU_MONDO_Q_HD, %g6
	ldxa	[%g6]ASI_QUEUE, %g6		! new head offset
	stna	%g6, [%g4 + TRAP_ENT_F2]%asi
	stna	%g7, [%g4 + TRAP_ENT_F4]%asi	! tail offset
	TRACE_NEXT(%g4, %g6, %g3)
#endif /* TRAPTRACE */

	/*
	 * For now catch invalid PC being passed via cpu_mondo queue
	 */
	set	KERNELBASE, %g4
	cmp	%g5, %g4
	bl,pn	%xcc, 2f		! branch if bad %pc
	  nop
	

	/*
	 * If this platform supports shared contexts and we are jumping
	 * to OBP code, then we need to invalidate both contexts to prevent OBP
	 * from corrupting the shared context registers.
	 *
	 * If shared contexts are not supported then the next two instructions
	 * will be patched with:
	 *
	 * jmp       %g5
	 * nop
	 *
	 */
	.global sfmmu_shctx_cpu_mondo_patch
sfmmu_shctx_cpu_mondo_patch:
	set	OFW_START_ADDR, %g4	! Check if this a call into OBP?
	cmp	%g5, %g4
	bl,pt %xcc, 1f
	  nop
	set	OFW_END_ADDR, %g4	
	cmp	%g5, %g4
	bg,pn %xcc, 1f		
	  nop
	mov	MMU_PCONTEXT, %g3
	ldxa	[%g3]ASI_MMU_CTX, %g4
	cmp	%g4, INVALID_CONTEXT	! Check if we are in kernel mode
	ble,pn %xcc, 1f			! or the primary context is invalid
	  nop
	set	INVALID_CONTEXT, %g4	! Invalidate contexts - compatability
	stxa    %g4, [%g3]ASI_MMU_CTX	! mode ensures shared contexts are also
	mov     MMU_SCONTEXT, %g3	! invalidated.
	stxa    %g4, [%g3]ASI_MMU_CTX
	membar  #Sync
	mov	%o0, %g3		! save output regs
	mov	%o1, %g4
	mov	%o5, %g6
	clr	%o0			! Invalidate tsbs, set ntsb = 0
	clr	%o1			! and HV_TSB_INFO_PA = 0
	mov	MMU_TSB_CTXNON0, %o5
	ta	FAST_TRAP		! set TSB info for user process
	brnz,a,pn %o0, ptl1_panic
	  mov	PTL1_BAD_HCALL, %g1
	mov	%g3, %o0		! restore output regs
	mov	%g4, %o1
	mov	%g6, %o5
1:
	jmp	%g5			! jump to traphandler
	nop
2:
	! invalid trap handler, discard it for now
	set	cpu_mondo_inval, %g4
	ldx	[%g4], %g5
	inc	%g5
	stx	%g5, [%g4]
3:
	retry
	/* Never Reached */
	SET_SIZE(cpu_mondo)


/*
 * (TT 0x7d, TL>0) Dev Mondo Queue Handler
 *	Globals are the Interrupt Globals.
 * We only process one interrupt at a time causing us to keep
 * taking this trap till the queue is empty.
 * We really should drain the whole queue for better performance
 * but this will do for now.
 */
	ENTRY_NP(dev_mondo)
	!
	!	Register Usage:-
	!	%g5	PC for fasttrap TL>0 handler
	!	%g1	arg 1	
	!	%g2	arg 2	
	!	%g3	queue base PA 
	!	%g4 	queue size mask	
	!	%g6	head ptr
	!	%g7	tail ptr	
	mov	DEV_MONDO_Q_HD, %g3	
	ldxa	[%g3]ASI_QUEUE, %g6	! %g6 = head ptr 
	mov	DEV_MONDO_Q_TL, %g4	
	ldxa	[%g4]ASI_QUEUE, %g7	! %g7 = tail ptr 
	cmp	%g6, %g7
	be,pn	%xcc, 0f		! head == tail
	nop

	CPU_ADDR(%g1,%g2)
	add	%g1, CPU_MCPU, %g2
	ldx	[%g2 + MCPU_DEV_Q_BASE], %g3	! %g3 = queue base PA

	! Register usage:
	!	%g5 - inum
	!	%g1 - cpu struct pointer used below in TRAPTRACE 
	!
	ldxa	[%g3 + %g6]ASI_MEM, %g5	! get inum from q base + head

	!
	! We verify that inum is valid ( < MAXVNUM). If it is greater
	! than MAXVNUM, we let setvecint_tl1 take care of it.
	!
	set	MAXIVNUM, %g4
	cmp	%g5, %g4
	bgeu,a,pn	%xcc, 1f
	ldx	[%g2 + MCPU_DEV_Q_SIZE], %g4	! queue size - delay slot

	!
	!	Copy 64-byte payload to the *iv_payload if it is not NULL
	!
	set	intr_vec_table, %g1		! %g1 = intr_vec_table
	sll	%g5, CPTRSHIFT, %g7		! %g7 = offset to inum entry
						!       in the intr_vec_table
	add	%g1, %g7, %g7			! %g7 = &intr_vec_table[inum]
	ldn	[%g7], %g1			! %g1 = ptr to intr_vec_t (iv)

	!
	! Verify the pointer to first intr_vec_t for a given inum and
	! it should not be NULL. If this pointer is NULL, then it is a
	! spurious interrupt. In this case, just call setvecint_tl1 and
	! it will handle this spurious interrupt.
	!
	brz,a,pn	%g1, 1f			! if %g1 is NULL
	ldx	[%g2 + MCPU_DEV_Q_SIZE], %g4	! queue size - delay slot

	ldx	[%g1 + IV_PAYLOAD_BUF], %g1	! %g1 = iv->iv_payload_buf
	brz,a,pt	%g1, 1f			! if it is NULL
	ldx	[%g2 + MCPU_DEV_Q_SIZE], %g4	! queue size - delay slot

	!
	!	Now move 64 byte payload from mondo queue to buf	
	!
	mov	%g6, %g7			! %g7 = head ptr 
	ldxa	[%g3 + %g7]ASI_MEM, %g4
	stx	%g4, [%g1 + 0]			! byte 0 - 7
	add	%g7, 8, %g7
	ldxa	[%g3 + %g7]ASI_MEM, %g4
	stx	%g4, [%g1 + 8]			! byte 8 - 15
	add	%g7, 8, %g7
	ldxa	[%g3 + %g7]ASI_MEM, %g4
	stx	%g4, [%g1 + 16]			! byte 16 - 23
	add	%g7, 8, %g7
	ldxa	[%g3 + %g7]ASI_MEM, %g4
	stx	%g4, [%g1 + 24]			! byte 24 - 31
	add	%g7, 8, %g7
	ldxa	[%g3 + %g7]ASI_MEM, %g4
	stx	%g4, [%g1 + 32]			! byte 32 - 39
	add	%g7, 8, %g7
	ldxa	[%g3 + %g7]ASI_MEM, %g4
	stx	%g4, [%g1 + 40]			! byte 40 - 47
	add	%g7, 8, %g7
	ldxa	[%g3 + %g7]ASI_MEM, %g4
	stx	%g4, [%g1 + 48]			! byte 48 - 55
	add	%g7, 8, %g7
	ldxa	[%g3 + %g7]ASI_MEM, %g4
	stx	%g4, [%g1 + 56]			! byte 56 - 63
	ldx	[%g2 + MCPU_DEV_Q_SIZE], %g4	! queue size

1:	sub	%g4, 1, %g4		! %g4 = queue size mask	
	add	%g6, INTR_REPORT_SIZE , %g6 ! inc head to next record	
	and	%g6, %g4, %g6 		! and mask for wrap around	
	mov	DEV_MONDO_Q_HD, %g3	
	stxa	%g6, [%g3]ASI_QUEUE	! increment head offset 
	membar	#Sync

#ifdef TRAPTRACE
	TRACE_PTR(%g4, %g6)
	GET_TRACE_TICK(%g6, %g3)
	stxa	%g6, [%g4 + TRAP_ENT_TICK]%asi
	TRACE_SAVE_TL_GL_REGS(%g4, %g6)
	rdpr	%tt, %g6
	stha	%g6, [%g4 + TRAP_ENT_TT]%asi
	rdpr	%tpc, %g6
	stna	%g6, [%g4 + TRAP_ENT_TPC]%asi
	rdpr	%tstate, %g6
	stxa	%g6, [%g4 + TRAP_ENT_TSTATE]%asi
	! move head to sp
	ldx	[%g2 + MCPU_DEV_Q_BASE], %g6
	stna	%g6, [%g4 + TRAP_ENT_SP]%asi	! Device Queue Base PA
	stna	%g5, [%g4 + TRAP_ENT_TR]%asi	! Inum 
	mov	DEV_MONDO_Q_HD, %g6	
	ldxa	[%g6]ASI_QUEUE, %g6		! New head offset 
	stna	%g6, [%g4 + TRAP_ENT_F1]%asi
	ldx	[%g2 + MCPU_DEV_Q_SIZE], %g6
	stna	%g6, [%g4 + TRAP_ENT_F2]%asi	! Q Size	
	stna	%g7, [%g4 + TRAP_ENT_F3]%asi	! tail offset
	stna	%g0, [%g4 + TRAP_ENT_F4]%asi
	TRACE_NEXT(%g4, %g6, %g3)
#endif /* TRAPTRACE */

	!
	! setvecint_tl1 will do all the work, and finish with a retry
	!
	ba,pt	%xcc, setvecint_tl1
	mov	%g5, %g1		! setvecint_tl1 expects inum in %g1

0:	retry 

	/* Never Reached */
	SET_SIZE(dev_mondo)

	.seg	".data"
	.global	cpu_mondo_inval
	.align	8
cpu_mondo_inval:
	.skip	8

	.seg	".text"


/*
 * (TT 0x7e, TL>0) Resumeable Error Queue Handler
 *	We keep a shadow copy of the queue in kernel buf.
 *	Read the resumable queue head and tail offset
 *	If there are entries on the queue, move them to
 *	the kernel buf, which is next to the resumable
 *	queue in the memory. Call C routine to process.
 */
	ENTRY_NP(resumable_error)
	mov	CPU_RQ_HD, %g4
	ldxa	[%g4]ASI_QUEUE, %g2		! %g2 = Q head offset 
	mov	CPU_RQ_TL, %g4
	ldxa	[%g4]ASI_QUEUE, %g3		! %g3 = Q tail offset
	mov	%g2, %g6			! save head in %g2

	cmp	%g6, %g3
	be,pn	%xcc, 0f			! head == tail
	nop

	CPU_ADDR(%g1, %g4)			! %g1 = cpu struct addr

2:	set	CPU_RQ_BASE_OFF, %g4
	ldx	[%g1 + %g4], %g4		! %g4 = queue base PA
	add	%g6, %g4, %g4			! %g4 = PA of ER in Q		
	set	CPU_RQ_SIZE, %g7
	add	%g4, %g7, %g7			! %g7=PA of ER in kernel buf

	ldxa	[%g7]ASI_MEM, %g5		! %g5=first 8 byte of ER buf
	cmp	0, %g5
	bne,pn	%xcc, 1f			! first 8 byte is not 0
	nop

	/* Now we can move 64 bytes from queue to buf */
	set	0, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 0 - 7	
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 8 - 15
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 16 - 23
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 24 - 31
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 32 - 39
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 40 - 47
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 48 - 55
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 56 - 63

	set	CPU_RQ_SIZE, %g5		! %g5 = queue size
	sub	%g5, 1, %g5			! %g5 = queu size mask

	add	%g6, Q_ENTRY_SIZE, %g6		! increment q head to next
	and	%g6, %g5, %g6			! size mask for warp around
	cmp	%g6, %g3			! head == tail ??

	bne,pn	%xcc, 2b			! still have more to process
	nop

	/*
	 * head equals to tail now, we can update the queue head 
	 * and call sys_trap
	 */
	mov	CPU_RQ_HD, %g4
	stxa	%g6, [%g4]ASI_QUEUE		! update head offset
	membar	#Sync
	
	/*
	 * Call sys_trap at PIL 14 unless we're already at PIL 15. %g2.l is
	 * head offset(arg2) and %g3 is tail
	 * offset(arg3).
	 */
	set	process_resumable_error, %g1
	rdpr	%pil, %g4
	cmp	%g4, PIL_14
	ba	sys_trap
	  movl	%icc, PIL_14, %g4

	/*
	 * We are here because the C routine is not able to process
	 * errors in time. So the first 8 bytes of ER in buf has not
	 * been cleared. We update head to tail and call sys_trap to
	 * print out an error message
	 */
	
1:	mov	CPU_RQ_HD, %g4
	stxa	%g3, [%g4]ASI_QUEUE		! set head equal to tail
	membar	#Sync

	/*
	 * Set %g2 to %g6, which is current head offset. %g2 
	 * is arg2 of the C routine. %g3 is the tail offset,
	 * which is arg3 of the C routine.
	 * Call rq_overflow at PIL 14 unless we're already at PIL 15.
	 */
	mov	%g6, %g2
	set	rq_overflow, %g1
	rdpr	%pil, %g4
	cmp	%g4, PIL_14
	ba	sys_trap
	  movl	%icc, PIL_14, %g4

0:	retry

	/*NOTREACHED*/
	SET_SIZE(resumable_error)

/*
 * (TT 0x7f, TL>0) Non-resumeable Error Queue Handler
 *	We keep a shadow copy of the queue in kernel buf.
 *	Read non-resumable queue head and tail offset
 *	If there are entries on the queue, move them to
 *	the kernel buf, which is next to the non-resumable
 *	queue in the memory. Call C routine to process.
 */
	ENTRY_NP(nonresumable_error)
	mov	CPU_NRQ_HD, %g4
	ldxa	[%g4]ASI_QUEUE, %g2		! %g2 = Q head offset 
	mov	CPU_NRQ_TL, %g4
	ldxa	[%g4]ASI_QUEUE, %g3		! %g3 = Q tail offset

	cmp	%g2, %g3
	be,pn	%xcc, 0f			! head == tail
	nop

	/* force %gl to 1 as sys_trap requires */
	wrpr	%g0, 1, %gl
	mov	CPU_NRQ_HD, %g4
	ldxa	[%g4]ASI_QUEUE, %g2		! %g2 = Q head offset 
	mov	CPU_NRQ_TL, %g4
	ldxa	[%g4]ASI_QUEUE, %g3		! %g3 = Q tail offset
	mov	%g2, %g6			! save head in %g2

	CPU_PADDR(%g1, %g4)			! %g1 = cpu struct paddr

2:	set	CPU_NRQ_BASE_OFF, %g4
	ldxa	[%g1 + %g4]ASI_MEM, %g4		! %g4 = queue base PA
	add	%g6, %g4, %g4			! %g4 = PA of ER in Q		
	set	CPU_NRQ_SIZE, %g7
	add	%g4, %g7, %g7			! %g7 = PA of ER in kernel buf

	ldxa	[%g7]ASI_MEM, %g5		! %g5 = first 8 byte of ER buf
	cmp	0, %g5
	bne,pn	%xcc, 1f			! first 8 byte is not 0
	nop

	/* Now we can move 64 bytes from queue to buf */
	set	0, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 0 - 7	
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 8 - 15
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 16 - 23
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 24 - 31
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 32 - 39
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 40 - 47
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 48 - 55
	add	%g5, 8, %g5
	ldxa	[%g4 + %g5]ASI_MEM, %g1
	stxa	%g1, [%g7 + %g5]ASI_MEM		! byte 56 - 63

	set	CPU_NRQ_SIZE, %g5		! %g5 = queue size
	sub	%g5, 1, %g5			! %g5 = queu size mask

	add	%g6, Q_ENTRY_SIZE, %g6		! increment q head to next
	and	%g6, %g5, %g6			! size mask for warp around
	cmp	%g6, %g3			! head == tail ??

	bne,pn	%xcc, 2b			! still have more to process
	nop

	/*
	 * head equals to tail now, we can update the queue head 
	 * and call sys_trap
	 */
	mov	CPU_NRQ_HD, %g4
	stxa	%g6, [%g4]ASI_QUEUE		! update head offset
	membar	#Sync

	/*
	 * Call sys_trap. %g2 is TL(arg2), %g3 is head and tail
	 * offset(arg3).
	 * %g3 looks like following:
	 *	+--------------------+--------------------+
	 *	|   tail offset      |    head offset     |
	 *	+--------------------+--------------------+
	 *	63                 32 31                 0
	 *
	 * Run at PIL 14 unless we're already at PIL 15.
	 */
	sllx	%g3, 32, %g3			! %g3.h = tail offset
	or	%g3, %g2, %g3			! %g3.l = head offset
	rdpr	%tl, %g2			! %g2 = current tl

	/*
	 * Now check if the first error that sent us here was caused
	 * in user's SPILL/FILL trap. If it was, we call sys_trap to
	 * kill the user process. Several considerations:
	 * - If multiple nonresumable errors happen, we only check the
	 *   first one. Nonresumable errors cause system either panic
	 *   or kill the user process. So the system has already
	 *   panic'ed or killed user process after processing the first
	 *   error. Therefore, no need to check if other error packet
	 *   for this type of error.
	 * - Errors happen in user's SPILL/FILL trap will bring us at
	 *   TL = 2.
	 * - We need to lower TL to 1 to get the trap type and tstate.
	 *   We don't go back to TL = 2 so no need to save states.
	 */
	cmp	%g2, 2	
	bne,pt	%xcc, 3f			! if tl != 2
	nop
	/* Check to see if the trap pc is in a window spill/fill handling */
	rdpr	%tpc, %g4
	/* tpc should be in the trap table */
	set	trap_table, %g5
	cmp	%g4, %g5
	blu,pt	%xcc, 3f
	nop
	set	etrap_table, %g5
	cmp	%g4, %g5
	bgeu,pt	%xcc, 3f
	nop	
	/* Set tl to 1 in order to read tt[1] and tstate[1] */
	wrpr	%g0, 1, %tl
	rdpr	%tt, %g4			! %g4 = tt[1]
	/* Check if tt[1] is a window trap */
	and	%g4, WTRAP_TTMASK, %g4
	cmp	%g4, WTRAP_TYPE
	bne,pt	%xcc, 3f
	nop
	rdpr	%tstate, %g5			! %g5 = tstate[1]
	btst	TSTATE_PRIV, %g5
	bnz	%xcc, 3f			! Is it from user code?
	nop
	/*
	 * Now we know the error happened in user's SPILL/FILL trap.
	 * Turn on the user spill/fill flag in %g2
	 */
	mov	1, %g4
	sllx	%g4, ERRH_U_SPILL_FILL_SHIFT, %g4
	or	%g2, %g4, %g2			! turn on flag in %g2
	
3:	sub	%g2, 1, %g2			! %g2.l = previous tl

	set	process_nonresumable_error, %g1
	rdpr	%pil, %g4
	cmp	%g4, PIL_14
	ba	sys_trap
	  movl	%icc, PIL_14, %g4

	/*
	 * We are here because the C routine is not able to process
	 * errors in time. So the first 8 bytes of ER in buf has not
	 * been cleared. We call sys_trap to panic.
	 * Run at PIL 14 unless we're already at PIL 15.
	 */
1:	set	nrq_overflow, %g1
	rdpr	%pil, %g4
	cmp	%g4, PIL_14
	ba	sys_trap
	  movl	%icc, PIL_14, %g4

0:	retry

	/*NOTREACHED*/
	SET_SIZE(nonresumable_error)
