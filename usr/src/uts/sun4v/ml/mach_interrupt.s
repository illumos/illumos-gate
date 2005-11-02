/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(lint)
#include <sys/types.h>
#include <sys/thread.h>
#else	/* lint */
#include "assym.h"
#endif	/* lint */

#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/machcpuvar.h>
#include <sys/intreg.h>
#include <sys/cmn_err.h>
#include <sys/ftrace.h>
#include <sys/machasi.h>
#include <sys/error.h>
#define	INTR_REPORT_SIZE	64

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */

#if defined(lint)

void
cpu_mondo(void)
{}

#else	/* lint */


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
	be,pn	%xcc, 0f		! head == tail
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
	GET_TRACE_TICK(%g6)
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
	bl,a,pn	%xcc, 1f		! branch if bad %pc
	nop

	jmp	%g5			! jump to traphandler
	nop
1:
	! invalid trap handler, discard it for now
	set	cpu_mondo_inval, %g4
	ldx	[%g4], %g5
	inc	%g5
	stx	%g5, [%g4]
0:
	retry
	/* Never Reached */
	SET_SIZE(cpu_mondo)

#endif /* lint */

#if defined(lint)

void
dev_mondo(void)
{}

#else	/* lint */


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
	! than MAXVNUM, we let setsoftint_tl1 take care of it.
	!
	set	MAXIVNUM, %g4
	cmp	%g5, %g4
	bgeu,a,pn	%xcc, 1f
	ldx	[%g2 + MCPU_DEV_Q_SIZE], %g4	! queue size - delay slot

	!
	!	Copy 64-byte payload to the *iv_payload if it is not NULL
	!
	set	intr_vector, %g1
	sll	%g5, INTR_VECTOR_SHIFT, %g7
	add	%g1, %g7, %g1			! %g1 = &intr_vector[inum]
	ldx	[%g1 + IV_PAYLOAD_BUF], %g1	! %g1 = iv_payload_buf
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
	GET_TRACE_TICK(%g6)
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
#ifdef __sparcv9
	ldx	[%g2 + MCPU_DEV_Q_SIZE], %g6
	stna	%g6, [%g4 + TRAP_ENT_F2]%asi	! Q Size	
	stna	%g7, [%g4 + TRAP_ENT_F3]%asi	! tail offset
	stna	%g0, [%g4 + TRAP_ENT_F4]%asi
#endif
	TRACE_NEXT(%g4, %g6, %g3)
#endif /* TRAPTRACE */

	!
	! setsoftint_tl1 will do all the work, and finish with a retry
	!
	ba,pt	%xcc, setsoftint_tl1
	mov	%g5, %g1		! setsoftint_tl1 expects inum in %g1

0:	retry 

	/* Never Reached */
	SET_SIZE(dev_mondo)
#endif /* lint */

#if defined(lint)
uint64_t cpu_mondo_inval;
#else /* lint */
	.seg	".data"
	.global	cpu_mondo_inval
	.align	8
cpu_mondo_inval:
	.skip	8

	.seg	".text"
#endif	/* lint */


#if defined(lint)

void
resumable_error(void)
{}

#else	/* lint */

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
#endif /* lint */

#if defined(lint)

void
nonresumable_error(void)
{}

#else	/* lint */

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
	sub	%g2, 1, %g2			! %g2 = previous tl, arg2

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
#endif /* lint */
