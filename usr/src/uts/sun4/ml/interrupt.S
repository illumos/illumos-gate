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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include "assym.h"

#include <sys/cmn_err.h>
#include <sys/ftrace.h>
#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/machcpuvar.h>
#include <sys/intreg.h>
#include <sys/ivintr.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */


/*
 * (TT 0x40..0x4F, TL>0) Interrupt Level N Handler (N == 1..15)
 * 	Register passed from LEVEL_INTERRUPT(level)
 *	%g4 - interrupt request level
 */
	ENTRY_NP(pil_interrupt)
	!
	! Register usage
	!	%g1 - cpu
	!	%g2 - pointer to intr_vec_t (iv)
	!	%g4 - pil
	!	%g3, %g5, %g6, %g7 - temps
	!
	! Grab the first or list head intr_vec_t off the intr_head[pil]
	! and panic immediately if list head is NULL. Otherwise, update
	! intr_head[pil] to next intr_vec_t on the list and clear softint
	! %clear_softint, if next intr_vec_t is NULL.
	!
	CPU_ADDR(%g1, %g5)		! %g1 = cpu
	!
	ALTENTRY(pil_interrupt_common)
	sll	%g4, CPTRSHIFT, %g5	! %g5 = offset to the pil entry
	add	%g1, INTR_HEAD, %g6	! %g6 = &cpu->m_cpu.intr_head
	add	%g6, %g5, %g6		! %g6 = &cpu->m_cpu.intr_head[pil]
	ldn	[%g6], %g2		! %g2 = cpu->m_cpu.intr_head[pil]
	brnz,pt	%g2, 0f			! check list head (iv) is NULL
	nop
	ba	ptl1_panic		! panic, list head (iv) is NULL
	mov	PTL1_BAD_INTR_VEC, %g1
0:
	lduh	[%g2 + IV_FLAGS], %g7	! %g7 = iv->iv_flags
	and	%g7, IV_SOFTINT_MT, %g3 ! %g3 = iv->iv_flags & IV_SOFTINT_MT
	brz,pt	%g3, 1f			! check for multi target softint
	add	%g2, IV_PIL_NEXT, %g7	! g7% = &iv->iv_pil_next
	ld	[%g1 + CPU_ID], %g3	! for multi target softint, use cpuid
	sll	%g3, CPTRSHIFT, %g3	! convert cpuid to offset address
	add	%g7, %g3, %g7		! %g5 = &iv->iv_xpil_next[cpuid]
1:
	ldn	[%g7], %g3		! %g3 = next intr_vec_t
	brnz,pn	%g3, 2f			! branch if next intr_vec_t non NULL
	stn	%g3, [%g6]		! update cpu->m_cpu.intr_head[pil]
	add	%g1, INTR_TAIL, %g6	! %g6 =  &cpu->m_cpu.intr_tail
	stn	%g0, [%g5 + %g6]	! clear cpu->m_cpu.intr_tail[pil]
	mov	1, %g5			! %g5 = 1
	sll	%g5, %g4, %g5		! %g5 = 1 << pil
	wr	%g5, CLEAR_SOFTINT	! clear interrupt on this pil
2:
#ifdef TRAPTRACE
	TRACE_PTR(%g5, %g6)
	TRACE_SAVE_TL_GL_REGS(%g5, %g6)
	rdpr	%tt, %g6
	stha	%g6, [%g5 + TRAP_ENT_TT]%asi	! trap_type = %tt
	rdpr	%tpc, %g6
	stna	%g6, [%g5 + TRAP_ENT_TPC]%asi	! trap_pc = %tpc
	rdpr	%tstate, %g6
	stxa	%g6, [%g5 + TRAP_ENT_TSTATE]%asi ! trap_tstate = %tstate
	stna	%sp, [%g5 + TRAP_ENT_SP]%asi	! trap_sp = %sp
	stna	%g2, [%g5 + TRAP_ENT_TR]%asi	! trap_tr = first intr_vec
	stna	%g3, [%g5 + TRAP_ENT_F1]%asi	! trap_f1 = next intr_vec
	GET_TRACE_TICK(%g6, %g3)
	stxa	%g6, [%g5 + TRAP_ENT_TICK]%asi	! trap_tick = %tick
	sll	%g4, CPTRSHIFT, %g3
	add	%g1, INTR_HEAD, %g6
	ldn	[%g6 + %g3], %g6		! %g6=cpu->m_cpu.intr_head[pil]
	stna	%g6, [%g5 + TRAP_ENT_F2]%asi	! trap_f2 = intr_head[pil]
	add	%g1, INTR_TAIL, %g6
	ldn	[%g6 + %g3], %g6		! %g6=cpu->m_cpu.intr_tail[pil]
	stna	%g6, [%g5 + TRAP_ENT_F3]%asi	! trap_f3 = intr_tail[pil]
	stna	%g4, [%g5 + TRAP_ENT_F4]%asi	! trap_f4 = pil
	TRACE_NEXT(%g5, %g6, %g3)
#endif /* TRAPTRACE */
	!
	! clear the iv_pending flag for this interrupt request
	!
	lduh	[%g2 + IV_FLAGS], %g3		! %g3 = iv->iv_flags
	andn	%g3, IV_SOFTINT_PEND, %g3	! %g3 = !(iv->iv_flags & PEND)
	sth	%g3, [%g2 + IV_FLAGS]		! clear IV_SOFTINT_PEND flag
	stn	%g0, [%g7]			! clear iv->iv_pil_next or
						!       iv->iv_pil_xnext

	!
	! Prepare for sys_trap()
	!
	! Registers passed to sys_trap()
	!	%g1 - interrupt handler at TL==0
	!	%g2 - pointer to current intr_vec_t (iv),
	!	      job queue for intr_thread or current_thread
	!	%g3 - pil
	!	%g4 - initial pil for handler
	!
	! figure which handler to run and which %pil it starts at
	! intr_thread starts at DISP_LEVEL to prevent preemption
	! current_thread starts at PIL_MAX to protect cpu_intr_actv
	!
	mov	%g4, %g3		! %g3 = %g4, pil
	cmp	%g4, LOCK_LEVEL
	bg,a,pt	%xcc, 3f		! branch if pil > LOCK_LEVEL
	mov	PIL_MAX, %g4		! %g4 = PIL_MAX (15)
	sethi	%hi(intr_thread), %g1	! %g1 = intr_thread
	mov	DISP_LEVEL, %g4		! %g4 = DISP_LEVEL (11)
	ba,pt	%xcc, sys_trap
	or	%g1, %lo(intr_thread), %g1
3:
	sethi	%hi(current_thread), %g1 ! %g1 = current_thread
	ba,pt	%xcc, sys_trap
	or	%g1, %lo(current_thread), %g1
	SET_SIZE(pil_interrupt_common)
	SET_SIZE(pil_interrupt)


_spurious:
	.asciz	"!interrupt 0x%x at level %d not serviced"

/*
 * SERVE_INTR_PRE is called once, just before the first invocation
 * of SERVE_INTR.
 *
 * Registers on entry:
 *
 * iv_p, cpu, regs: may be out-registers
 * ls1, ls2: local scratch registers
 * os1, os2, os3: scratch registers, may be out
 */

#define SERVE_INTR_PRE(iv_p, cpu, ls1, ls2, os1, os2, os3, regs)	\
	mov	iv_p, ls1;						\
	mov	iv_p, ls2;						\
	SERVE_INTR_TRACE(iv_p, os1, os2, os3, regs);

/*
 * SERVE_INTR is called immediately after either SERVE_INTR_PRE or
 * SERVE_INTR_NEXT, without intervening code. No register values
 * may be modified.
 *
 * After calling SERVE_INTR, the caller must check if os3 is set. If
 * so, there is another interrupt to process. The caller must call
 * SERVE_INTR_NEXT, immediately followed by SERVE_INTR.
 *
 * Before calling SERVE_INTR_NEXT, the caller may perform accounting
 * and other actions which need to occur after invocation of an interrupt
 * handler. However, the values of ls1 and os3 *must* be preserved and
 * passed unmodified into SERVE_INTR_NEXT.
 *
 * Registers on return from SERVE_INTR:
 *
 * ls1 - the pil just processed
 * ls2 - the pointer to intr_vec_t (iv) just processed
 * os3 - if set, another interrupt needs to be processed
 * cpu, ls1, os3 - must be preserved if os3 is set
 */

#define	SERVE_INTR(os5, cpu, ls1, ls2, os1, os2, os3, os4)		\
	ldn	[ls1 + IV_HANDLER], os2;				\
	ldn	[ls1 + IV_ARG1], %o0;					\
	ldn	[ls1 + IV_ARG2], %o1;					\
	call	os2;							\
	lduh	[ls1 + IV_PIL], ls1;					\
	brnz,pt	%o0, 2f;						\
	mov	CE_WARN, %o0;						\
	set	_spurious, %o1;						\
	mov	ls2, %o2;						\
	call	cmn_err;						\
	rdpr	%pil, %o3;						\
2:	ldn	[THREAD_REG + T_CPU], cpu;				\
	sll	ls1, 3, os1;						\
	add	os1, CPU_STATS_SYS_INTR - 8, os2;			\
	ldx	[cpu + os2], os3;					\
	inc	os3;							\
	stx	os3, [cpu + os2];					\
	sll	ls1, CPTRSHIFT, os2;					\
	add	cpu,  INTR_HEAD, os1;					\
	add	os1, os2, os1;						\
	ldn	[os1], os3;

/*
 * Registers on entry:
 *
 * cpu			- cpu pointer (clobbered, set to cpu upon completion)
 * ls1, os3		- preserved from prior call to SERVE_INTR
 * ls2			- local scratch reg (not preserved)
 * os1, os2, os4, os5	- scratch reg, can be out (not preserved)
 */
#define SERVE_INTR_NEXT(os5, cpu, ls1, ls2, os1, os2, os3, os4)		\
	sll	ls1, CPTRSHIFT, os4;					\
	add	cpu, INTR_HEAD, os1;					\
	rdpr	%pstate, ls2;						\
	wrpr	ls2, PSTATE_IE, %pstate;				\
	lduh	[os3 + IV_FLAGS], os2;					\
	and	os2, IV_SOFTINT_MT, os2;				\
	brz,pt	os2, 4f;						\
	add	os3, IV_PIL_NEXT, os2;					\
	ld	[cpu + CPU_ID], os5;					\
	sll	os5, CPTRSHIFT, os5;					\
	add	os2, os5, os2;						\
4:	ldn	[os2], os5;						\
	brnz,pn	os5, 5f;						\
	stn	os5, [os1 + os4];					\
	add	cpu, INTR_TAIL, os1;					\
	stn	%g0, [os1 + os4];					\
	mov	1, os1;							\
	sll	os1, ls1, os1;						\
	wr	os1, CLEAR_SOFTINT;					\
5:	lduh	[os3 + IV_FLAGS], ls1;                                  \
	andn	ls1, IV_SOFTINT_PEND, ls1;				\
	sth	ls1, [os3 + IV_FLAGS];				        \
	stn	%g0, [os2];						\
	wrpr	%g0, ls2, %pstate;					\
	mov	os3, ls1;						\
	mov	os3, ls2;						\
	SERVE_INTR_TRACE2(os5, os1, os2, os3, os4);

#ifdef TRAPTRACE
/*
 * inum - not modified, _spurious depends on it.
 */
#define	SERVE_INTR_TRACE(inum, os1, os2, os3, os4)			\
	rdpr	%pstate, os3;						\
	andn	os3, PSTATE_IE | PSTATE_AM, os2;			\
	wrpr	%g0, os2, %pstate;					\
	TRACE_PTR(os1, os2); 						\
	ldn	[os4 + PC_OFF], os2;					\
	stna	os2, [os1 + TRAP_ENT_TPC]%asi;				\
	ldx	[os4 + TSTATE_OFF], os2;				\
	stxa	os2, [os1 + TRAP_ENT_TSTATE]%asi;			\
	mov	os3, os4;						\
	GET_TRACE_TICK(os2, os3);					\
	stxa	os2, [os1 + TRAP_ENT_TICK]%asi;				\
	TRACE_SAVE_TL_GL_REGS(os1, os2);				\
	set	TT_SERVE_INTR, os2;					\
	rdpr	%pil, os3;						\
	or	os2, os3, os2;						\
	stha	os2, [os1 + TRAP_ENT_TT]%asi;				\
	stna	%sp, [os1 + TRAP_ENT_SP]%asi;				\
	stna	inum, [os1 + TRAP_ENT_TR]%asi;				\
	stna	%g0, [os1 + TRAP_ENT_F1]%asi;				\
	stna	%g0, [os1 + TRAP_ENT_F2]%asi;				\
	stna	%g0, [os1 + TRAP_ENT_F3]%asi;				\
	stna	%g0, [os1 + TRAP_ENT_F4]%asi;				\
	TRACE_NEXT(os1, os2, os3);					\
	wrpr	%g0, os4, %pstate
#else	/* TRAPTRACE */
#define SERVE_INTR_TRACE(inum, os1, os2, os3, os4)
#endif	/* TRAPTRACE */

#ifdef TRAPTRACE
/*
 * inum - not modified, _spurious depends on it.
 */
#define	SERVE_INTR_TRACE2(inum, os1, os2, os3, os4)			\
	rdpr	%pstate, os3;						\
	andn	os3, PSTATE_IE | PSTATE_AM, os2;			\
	wrpr	%g0, os2, %pstate;					\
	TRACE_PTR(os1, os2); 						\
	stna	%g0, [os1 + TRAP_ENT_TPC]%asi;				\
	stxa	%g0, [os1 + TRAP_ENT_TSTATE]%asi;			\
	mov	os3, os4;						\
	GET_TRACE_TICK(os2, os3);					\
	stxa	os2, [os1 + TRAP_ENT_TICK]%asi;				\
	TRACE_SAVE_TL_GL_REGS(os1, os2);				\
	set	TT_SERVE_INTR, os2;					\
	rdpr	%pil, os3;						\
	or	os2, os3, os2;						\
	stha	os2, [os1 + TRAP_ENT_TT]%asi;				\
	stna	%sp, [os1 + TRAP_ENT_SP]%asi;				\
	stna	inum, [os1 + TRAP_ENT_TR]%asi;				\
	stna	%g0, [os1 + TRAP_ENT_F1]%asi;				\
	stna	%g0, [os1 + TRAP_ENT_F2]%asi;				\
	stna	%g0, [os1 + TRAP_ENT_F3]%asi;				\
	stna	%g0, [os1 + TRAP_ENT_F4]%asi;				\
	TRACE_NEXT(os1, os2, os3);					\
	wrpr	%g0, os4, %pstate
#else	/* TRAPTRACE */
#define SERVE_INTR_TRACE2(inum, os1, os2, os3, os4)
#endif	/* TRAPTRACE */

#define	INTRCNT_LIMIT 16

/*
 * Handle an interrupt in a new thread.
 *	Entry:
 *		%o0       = pointer to regs structure
 *		%o1       = pointer to current intr_vec_t (iv) to be processed
 *		%o2       = pil
 *		%sp       = on current thread's kernel stack
 *		%o7       = return linkage to trap code
 *		%g7       = current thread
 *		%pstate   = normal globals, interrupts enabled,
 *		            privileged, fp disabled
 *		%pil      = DISP_LEVEL
 *
 *	Register Usage
 *		%l0       = return linkage
 *		%l1       = pil
 *		%l2 - %l3 = scratch
 *		%l4 - %l7 = reserved for sys_trap
 *		%o2       = cpu
 *		%o3       = intr thread
 *		%o0       = scratch
 *		%o4 - %o5 = scratch
 */
	ENTRY_NP(intr_thread)
	mov	%o7, %l0
	mov	%o2, %l1
	!
	! See if we are interrupting another interrupt thread.
	!
	lduh	[THREAD_REG + T_FLAGS], %o3
	andcc	%o3, T_INTR_THREAD, %g0
	bz,pt	%xcc, 1f
	ldn	[THREAD_REG + T_CPU], %o2	! delay - load CPU pointer

	! We have interrupted an interrupt thread. Take a timestamp,
	! compute its interval, and update its cumulative counter.
	add	THREAD_REG, T_INTR_START, %o5
0:
	ldx	[%o5], %o3
	brz,pn	%o3, 1f
	! We came in on top of an interrupt thread that had no timestamp.
	! This could happen if, for instance, an interrupt thread which had
	! previously blocked is being set up to run again in resume(), but
	! resume() hasn't yet stored a timestamp for it. Or, it could be in
	! swtch() after its slice has been accounted for.
	! Only account for the time slice if the starting timestamp is non-zero.
	RD_CLOCK_TICK(%o4,%l2,%l3,__LINE__)
	sub	%o4, %o3, %o4			! o4 has interval

	! A high-level interrupt in current_thread() interrupting here
	! will account for the interrupted thread's time slice, but
	! only if t_intr_start is non-zero. Since this code is going to account
	! for the time slice, we want to "atomically" load the thread's
	! starting timestamp, calculate the interval with %tick, and zero
	! its starting timestamp.
	! To do this, we do a casx on the t_intr_start field, and store 0 to it.
	! If it has changed since we loaded it above, we need to re-compute the
	! interval, since a changed t_intr_start implies current_thread placed
	! a new, later timestamp there after running a high-level interrupt,
	! and the %tick val in %o4 had become stale.
	mov	%g0, %l2
	casx	[%o5], %o3, %l2

	! If %l2 == %o3, our casx was successful. If not, the starting timestamp
	! changed between loading it (after label 0b) and computing the
	! interval above.
	cmp	%l2, %o3
	bne,pn	%xcc, 0b

	! Check for Energy Star mode
	lduh	[%o2 + CPU_DIVISOR], %l2	! delay -- %l2 = clock divisor
	cmp	%l2, 1
	bg,a,pn	%xcc, 2f
	mulx	%o4, %l2, %o4	! multiply interval by clock divisor iff > 1
2:
	! We now know that a valid interval for the interrupted interrupt
	! thread is in %o4. Update its cumulative counter.
	ldub	[THREAD_REG + T_PIL], %l3	! load PIL
	sllx	%l3, 4, %l3		! convert PIL index to byte offset
	add	%l3, CPU_MCPU, %l3	! CPU_INTRSTAT is too big for use
	add	%l3, MCPU_INTRSTAT, %l3	! as const, add offsets separately
	ldx	[%o2 + %l3], %o5	! old counter in o5
	add	%o5, %o4, %o5		! new counter in o5
	stx	%o5, [%o2 + %l3]	! store new counter

	! Also update intracct[]
	lduh	[%o2 + CPU_MSTATE], %l3
	sllx	%l3, 3, %l3
	add	%l3, CPU_INTRACCT, %l3
	add	%l3, %o2, %l3
0:
	ldx	[%l3], %o5
	add	%o5, %o4, %o3
	casx	[%l3], %o5, %o3
	cmp	%o5, %o3
	bne,pn	%xcc, 0b
	nop

1:
	!
	! Get set to run interrupt thread.
	! There should always be an interrupt thread since we allocate one
	! for each level on the CPU.
	!
	! Note that the code in kcpc_overflow_intr -relies- on the ordering
	! of events here -- in particular that t->t_lwp of the interrupt thread
	! is set to the pinned thread *before* curthread is changed.
	!
	ldn	[%o2 + CPU_INTR_THREAD], %o3	! interrupt thread pool
	ldn	[%o3 + T_LINK], %o4		! unlink thread from CPU's list
	stn	%o4, [%o2 + CPU_INTR_THREAD]
	!
	! Set bit for this level in CPU's active interrupt bitmask.
	!
	ld	[%o2 + CPU_INTR_ACTV], %o5
	mov	1, %o4
	sll	%o4, %l1, %o4
#ifdef DEBUG
	!
	! ASSERT(!(CPU->cpu_intr_actv & (1 << PIL)))
	!
	andcc	%o5, %o4, %g0
	bz,pt	%xcc, 0f
	nop
	! Do not call panic if a panic is already in progress.
	sethi	%hi(panic_quiesce), %l2
	ld	[%l2 + %lo(panic_quiesce)], %l2
	brnz,pn	%l2, 0f
	nop
	sethi	%hi(intr_thread_actv_bit_set), %o0
	call	panic
	or	%o0, %lo(intr_thread_actv_bit_set), %o0
0:
#endif /* DEBUG */
	or	%o5, %o4, %o5
	st	%o5, [%o2 + CPU_INTR_ACTV]
	!
	! Consider the new thread part of the same LWP so that
	! window overflow code can find the PCB.
	!
	ldn	[THREAD_REG + T_LWP], %o4
	stn	%o4, [%o3 + T_LWP]
	!
	! Threads on the interrupt thread free list could have state already
	! set to TS_ONPROC, but it helps in debugging if they're TS_FREE
	! Could eliminate the next two instructions with a little work.
	!
	mov	TS_ONPROC, %o4
	st	%o4, [%o3 + T_STATE]
	!
	! Push interrupted thread onto list from new thread.
	! Set the new thread as the current one.
	! Set interrupted thread's T_SP because if it is the idle thread,
	! resume may use that stack between threads.
	!
	stn	%o7, [THREAD_REG + T_PC]	! mark pc for resume
	stn	%sp, [THREAD_REG + T_SP]	! mark stack for resume
	stn	THREAD_REG, [%o3 + T_INTR]	! push old thread
	stn	%o3, [%o2 + CPU_THREAD]		! set new thread
	mov	%o3, THREAD_REG			! set global curthread register
	ldn	[%o3 + T_STACK], %o4		! interrupt stack pointer
	sub	%o4, STACK_BIAS, %sp
	!
	! Initialize thread priority level from intr_pri
	!
	sethi	%hi(intr_pri), %o4
	ldsh	[%o4 + %lo(intr_pri)], %o4	! grab base interrupt priority
	add	%l1, %o4, %o4		! convert level to dispatch priority
	sth	%o4, [THREAD_REG + T_PRI]
	stub	%l1, [THREAD_REG + T_PIL]	! save pil for intr_passivate

	! Store starting timestamp in thread structure.
	add	THREAD_REG, T_INTR_START, %o3
1:
	ldx	[%o3], %o5
	RD_CLOCK_TICK(%o4,%l2,%l3,__LINE__)
	casx	[%o3], %o5, %o4
	cmp	%o4, %o5
	! If a high-level interrupt occurred while we were attempting to store
	! the timestamp, try again.
	bne,pn	%xcc, 1b
	nop

	wrpr	%g0, %l1, %pil			! lower %pil to new level
	!
	! Fast event tracing.
	!
	ld	[%o2 + CPU_FTRACE_STATE], %o4	! %o2 = curthread->t_cpu
	btst	FTRACE_ENABLED, %o4
	be,pt	%icc, 1f			! skip if ftrace disabled
	  mov	%l1, %o5
	!
	! Tracing is enabled - write the trace entry.
	!
	save	%sp, -SA(MINFRAME), %sp
	set	ftrace_intr_thread_format_str, %o0
	mov	%i0, %o1
	mov	%i1, %o2
	mov	%i5, %o3
	call	ftrace_3
	ldn	[%i0 + PC_OFF], %o4
	restore
1:
	!
	! call the handler
	!
	SERVE_INTR_PRE(%o1, %o2, %l1, %l3, %o4, %o5, %o3, %o0)
	!
	! %o0 and %o1 are now available as scratch registers.
	!
0:
	SERVE_INTR(%o1, %o2, %l1, %l3, %o4, %o5, %o3, %o0)
	!
	! If %o3 is set, we must call serve_intr_next, and both %l1 and %o3
	! must be preserved. %l1 holds our pil, %l3 holds our inum.
	!
	! Note: %l1 is the pil level we're processing, but we may have a
	! higher effective pil because a higher-level interrupt may have
	! blocked.
	!
	wrpr	%g0, DISP_LEVEL, %pil
	!
	! Take timestamp, compute interval, update cumulative counter.
	!
	add	THREAD_REG, T_INTR_START, %o5
1:
	ldx	[%o5], %o0
#ifdef DEBUG
	brnz	%o0, 9f
	nop
	! Do not call panic if a panic is already in progress.
	sethi	%hi(panic_quiesce), %o1
	ld	[%o1 + %lo(panic_quiesce)], %o1
	brnz,pn	%o1, 9f
	nop
	sethi	%hi(intr_thread_t_intr_start_zero), %o0
	call	panic
	or	%o0, %lo(intr_thread_t_intr_start_zero), %o0
9:
#endif /* DEBUG */
	RD_CLOCK_TICK(%o1,%l2,%l3,__LINE__)
	sub	%o1, %o0, %l2			! l2 has interval
	!
	! The general outline of what the code here does is:
	! 1. load t_intr_start, %tick, and calculate the delta
	! 2. replace t_intr_start with %tick (if %o3 is set) or 0.
	!
	! The problem is that a high-level interrupt could arrive at any time.
	! It will account for (%tick - t_intr_start) for us when it starts,
	! unless we have set t_intr_start to zero, and then set t_intr_start
	! to a new %tick when it finishes. To account for this, our first step
	! is to load t_intr_start and the last is to use casx to store the new
	! t_intr_start. This guarantees atomicity in reading t_intr_start,
	! reading %tick, and updating t_intr_start.
	!
	movrz	%o3, %g0, %o1
	casx	[%o5], %o0, %o1
	cmp	%o0, %o1
	bne,pn	%xcc, 1b
	!
	! Check for Energy Star mode
	!
	lduh	[%o2 + CPU_DIVISOR], %o0	! delay -- %o0 = clock divisor
	cmp	%o0, 1
	bg,a,pn	%xcc, 2f
	mulx	%l2, %o0, %l2	! multiply interval by clock divisor iff > 1
2:
	!
	! Update cpu_intrstat. If o3 is set then we will be processing another
	! interrupt. Above we have set t_intr_start to %tick, not 0. This
	! means a high-level interrupt can arrive and update the same stats
	! we're updating. Need to use casx.
	!
	sllx	%l1, 4, %o1			! delay - PIL as byte offset
	add	%o1, CPU_MCPU, %o1		! CPU_INTRSTAT const too big
	add	%o1, MCPU_INTRSTAT, %o1		! add parts separately
	add	%o1, %o2, %o1
1:
	ldx	[%o1], %o5			! old counter in o5
	add	%o5, %l2, %o0			! new counter in o0
 	stx	%o0, [%o1 + 8]			! store into intrstat[pil][1]
	casx	[%o1], %o5, %o0			! and into intrstat[pil][0]
	cmp	%o5, %o0
	bne,pn	%xcc, 1b
	nop

	! Also update intracct[]
	lduh	[%o2 + CPU_MSTATE], %o1
	sllx	%o1, 3, %o1
	add	%o1, CPU_INTRACCT, %o1
	add	%o1, %o2, %o1
1:
	ldx	[%o1], %o5
	add	%o5, %l2, %o0
	casx	[%o1], %o5, %o0
	cmp	%o5, %o0
	bne,pn	%xcc, 1b
	nop

	!
	! Don't keep a pinned process pinned indefinitely. Bump cpu_intrcnt
	! for each interrupt handler we invoke. If we hit INTRCNT_LIMIT, then
	! we've crossed the threshold and we should unpin the pinned threads
	! by preempt()ing ourselves, which will bubble up the t_intr chain
	! until hitting the non-interrupt thread, which will then in turn
	! preempt itself allowing the interrupt processing to resume. Finally,
	! the scheduler takes over and picks the next thread to run.
	!
	! If our CPU is quiesced, we cannot preempt because the idle thread
	! won't ever re-enter the scheduler, and the interrupt will be forever
	! blocked.
	!
	! If t_intr is NULL, we're not pinning anyone, so we use a simpler
	! algorithm. Just check for cpu_kprunrun, and if set then preempt.
	! This insures we enter the scheduler if a higher-priority thread
	! has become runnable.
	!
	lduh	[%o2 + CPU_FLAGS], %o5		! don't preempt if quiesced
	andcc	%o5, CPU_QUIESCED, %g0
	bnz,pn	%xcc, 1f

	ldn     [THREAD_REG + T_INTR], %o5      ! pinning anything?
	brz,pn  %o5, 3f				! if not, don't inc intrcnt

	ldub	[%o2 + CPU_INTRCNT], %o5	! delay - %o5 = cpu_intrcnt
	inc	%o5
	cmp	%o5, INTRCNT_LIMIT		! have we hit the limit?
	bl,a,pt	%xcc, 1f			! no preempt if < INTRCNT_LIMIT
	stub	%o5, [%o2 + CPU_INTRCNT]	! delay annul - inc CPU_INTRCNT
	bg,pn	%xcc, 2f			! don't inc stats again
	!
	! We've reached the limit. Set cpu_intrcnt and cpu_kprunrun, and do
	! CPU_STATS_ADDQ(cp, sys, intrunpin, 1). Then call preempt.
	!
	mov	1, %o4				! delay
	stub	%o4, [%o2 + CPU_KPRUNRUN]
	ldx	[%o2 + CPU_STATS_SYS_INTRUNPIN], %o4
	inc	%o4
	stx	%o4, [%o2 + CPU_STATS_SYS_INTRUNPIN]
	ba	2f
	stub	%o5, [%o2 + CPU_INTRCNT]	! delay
3:
	! Code for t_intr == NULL
	ldub	[%o2 + CPU_KPRUNRUN], %o5
	brz,pt	%o5, 1f				! don't preempt unless kprunrun
2:
	! Time to call preempt
	mov	%o2, %l3			! delay - save %o2
	call	preempt
	mov	%o3, %l2			! delay - save %o3.
	mov	%l3, %o2			! restore %o2
	mov	%l2, %o3			! restore %o3
	wrpr	%g0, DISP_LEVEL, %pil		! up from cpu_base_spl
1:
	!
	! Do we need to call serve_intr_next and do this again?
	!
	brz,a,pt %o3, 0f
	ld	[%o2 + CPU_INTR_ACTV], %o5	! delay annulled
	!
	! Restore %pil before calling serve_intr() again. We must check
	! CPU_BASE_SPL and set %pil to max(our-pil, CPU_BASE_SPL)
	!
	ld	[%o2 + CPU_BASE_SPL], %o4
	cmp	%o4, %l1
	movl	%xcc, %l1, %o4
	wrpr	%g0, %o4, %pil
	SERVE_INTR_NEXT(%o1, %o2, %l1, %l3, %o4, %o5, %o3, %o0)
	ba	0b				! compute new stats
	nop
0:
	!
	! Clear bit for this level in CPU's interrupt active bitmask.
	!
	mov	1, %o4
	sll	%o4, %l1, %o4
#ifdef DEBUG
	!
	! ASSERT(CPU->cpu_intr_actv & (1 << PIL))
	!
	andcc	%o4, %o5, %g0
	bnz,pt	%xcc, 0f
	nop
	! Do not call panic if a panic is already in progress.
	sethi	%hi(panic_quiesce), %l2
	ld	[%l2 + %lo(panic_quiesce)], %l2
	brnz,pn	%l2, 0f
	nop
	sethi	%hi(intr_thread_actv_bit_not_set), %o0
	call	panic
	or	%o0, %lo(intr_thread_actv_bit_not_set), %o0
0:
#endif /* DEBUG */
	andn	%o5, %o4, %o5
	st	%o5, [%o2 + CPU_INTR_ACTV]
	!
	! If there is still an interrupted thread underneath this one,
	! then the interrupt was never blocked and the return is fairly
	! simple.  Otherwise jump to intr_thread_exit.
	!
	ldn	[THREAD_REG + T_INTR], %o4	! pinned thread
	brz,pn	%o4, intr_thread_exit		! branch if none
	nop
	!
	! link the thread back onto the interrupt thread pool
	!
	ldn	[%o2 + CPU_INTR_THREAD], %o3
	stn	%o3, [THREAD_REG + T_LINK]
	stn	THREAD_REG, [%o2 + CPU_INTR_THREAD]
	!
	! set the thread state to free so kernel debuggers don't see it
	!
	mov	TS_FREE, %o5
	st	%o5, [THREAD_REG + T_STATE]
	!
	! Switch back to the interrupted thread and return
	!
	stn	%o4, [%o2 + CPU_THREAD]
	membar	#StoreLoad			! sync with mutex_exit()
	mov	%o4, THREAD_REG

	! If we pinned an interrupt thread, store its starting timestamp.
	lduh	[THREAD_REG + T_FLAGS], %o5
	andcc	%o5, T_INTR_THREAD, %g0
	bz,pt	%xcc, 1f
	ldn	[THREAD_REG + T_SP], %sp	! delay - restore %sp

	add	THREAD_REG, T_INTR_START, %o3	! o3 has &curthread->t_intr_star
0:
	ldx	[%o3], %o4			! o4 = t_intr_start before
	RD_CLOCK_TICK(%o5,%l2,%l3,__LINE__)
	casx	[%o3], %o4, %o5			! put o5 in ts if o4 == ts after
	cmp	%o4, %o5
	! If a high-level interrupt occurred while we were attempting to store
	! the timestamp, try again.
	bne,pn	%xcc, 0b
	ldn	[THREAD_REG + T_SP], %sp	! delay - restore %sp
1:
	! If the thread being restarted isn't pinning anyone, and no interrupts
	! are pending, zero out cpu_intrcnt
	ldn	[THREAD_REG + T_INTR], %o4
	brnz,pn	%o4, 2f
	rd	SOFTINT, %o4			! delay
	set	SOFTINT_MASK, %o5
	andcc	%o4, %o5, %g0
	bz,a,pt	%xcc, 2f
	stub	%g0, [%o2 + CPU_INTRCNT]	! delay annul
2:
	jmp	%l0 + 8
	nop
	SET_SIZE(intr_thread)
	/* Not Reached */

	!
	! An interrupt returned on what was once (and still might be)
	! an interrupt thread stack, but the interrupted process is no longer
	! there.  This means the interrupt must have blocked.
	!
	! There is no longer a thread under this one, so put this thread back
	! on the CPU's free list and resume the idle thread which will dispatch
	! the next thread to run.
	!
	! All traps below DISP_LEVEL are disabled here, but the mondo interrupt
	! is enabled.
	!
	ENTRY_NP(intr_thread_exit)
#ifdef TRAPTRACE
	rdpr	%pstate, %l2
	andn	%l2, PSTATE_IE | PSTATE_AM, %o4
	wrpr	%g0, %o4, %pstate			! cpu to known state
	TRACE_PTR(%o4, %o5)
	GET_TRACE_TICK(%o5, %o0)
	stxa	%o5, [%o4 + TRAP_ENT_TICK]%asi
	TRACE_SAVE_TL_GL_REGS(%o4, %o5)
	set	TT_INTR_EXIT, %o5
	stha	%o5, [%o4 + TRAP_ENT_TT]%asi
	stna	%g0, [%o4 + TRAP_ENT_TPC]%asi
	stxa	%g0, [%o4 + TRAP_ENT_TSTATE]%asi
	stna	%sp, [%o4 + TRAP_ENT_SP]%asi
	stna	THREAD_REG, [%o4 + TRAP_ENT_TR]%asi
	ld	[%o2 + CPU_BASE_SPL], %o5
	stna	%o5, [%o4 + TRAP_ENT_F1]%asi
	stna	%g0, [%o4 + TRAP_ENT_F2]%asi
	stna	%g0, [%o4 + TRAP_ENT_F3]%asi
	stna	%g0, [%o4 + TRAP_ENT_F4]%asi
	TRACE_NEXT(%o4, %o5, %o0)
	wrpr	%g0, %l2, %pstate
#endif /* TRAPTRACE */
	! cpu_stats.sys.intrblk++
        ldx	[%o2 + CPU_STATS_SYS_INTRBLK], %o4
        inc     %o4
        stx	%o4, [%o2 + CPU_STATS_SYS_INTRBLK]
	!
	! Put thread back on the interrupt thread list.
	!

	!
	! Set the CPU's base SPL level.
	!
#ifdef DEBUG
	!
	! ASSERT(!(CPU->cpu_intr_actv & (1 << PIL)))
	!
	ld	[%o2 + CPU_INTR_ACTV], %o5
	mov	1, %o4
	sll	%o4, %l1, %o4
	and	%o5, %o4, %o4
	brz,pt	%o4, 0f
	nop
	! Do not call panic if a panic is already in progress.
	sethi	%hi(panic_quiesce), %l2
	ld	[%l2 + %lo(panic_quiesce)], %l2
	brnz,pn	%l2, 0f
	nop
	sethi	%hi(intr_thread_exit_actv_bit_set), %o0
	call	panic
	or	%o0, %lo(intr_thread_exit_actv_bit_set), %o0
0:
#endif /* DEBUG */
	call	_intr_set_spl			! set CPU's base SPL level
	ld	[%o2 + CPU_INTR_ACTV], %o5	! delay - load active mask
	!
	! set the thread state to free so kernel debuggers don't see it
	!
	mov	TS_FREE, %o4
	st	%o4, [THREAD_REG + T_STATE]
	!
	! Put thread on either the interrupt pool or the free pool and
	! call swtch() to resume another thread.
	!
	ldn	[%o2 + CPU_INTR_THREAD], %o5	! get list pointer
	stn	%o5, [THREAD_REG + T_LINK]
	call	swtch				! switch to best thread
	stn	THREAD_REG, [%o2 + CPU_INTR_THREAD] ! delay - put thread on list
	ba,a,pt	%xcc, .				! swtch() shouldn't return
	SET_SIZE(intr_thread_exit)

	.global ftrace_intr_thread_format_str
ftrace_intr_thread_format_str:
	.asciz	"intr_thread(): regs=0x%lx, int=0x%lx, pil=0x%lx"
#ifdef DEBUG
intr_thread_actv_bit_set:
	.asciz	"intr_thread():	cpu_intr_actv bit already set for PIL"
intr_thread_actv_bit_not_set:
	.asciz	"intr_thread():	cpu_intr_actv bit not set for PIL"
intr_thread_exit_actv_bit_set:
	.asciz	"intr_thread_exit(): cpu_intr_actv bit erroneously set for PIL"
intr_thread_t_intr_start_zero:
	.asciz	"intr_thread():	t_intr_start zero upon handler return"
#endif /* DEBUG */

/*
 * Handle an interrupt in the current thread
 *	Entry:
 *		%o0       = pointer to regs structure
 *		%o1       = pointer to current intr_vec_t (iv) to be processed
 *		%o2       = pil
 *		%sp       = on current thread's kernel stack
 *		%o7       = return linkage to trap code
 *		%g7       = current thread
 *		%pstate   = normal globals, interrupts enabled,
 *		            privileged, fp disabled
 *		%pil      = PIL_MAX
 *
 *	Register Usage
 *		%l0       = return linkage
 *		%l1       = old stack
 *		%l2 - %l3 = scratch
 *		%l4 - %l7 = reserved for sys_trap
 *		%o3       = cpu
 *		%o0       = scratch
 *		%o4 - %o5 = scratch
 */
	ENTRY_NP(current_thread)

	mov	%o7, %l0
	ldn	[THREAD_REG + T_CPU], %o3

	ldn	[THREAD_REG + T_ONFAULT], %l2
	brz,pt	%l2, no_onfault		! branch if no onfault label set
	nop
	stn	%g0, [THREAD_REG + T_ONFAULT]! clear onfault label
	ldn	[THREAD_REG + T_LOFAULT], %l3
	stn	%g0, [THREAD_REG + T_LOFAULT]! clear lofault data

	sub	%o2, LOCK_LEVEL + 1, %o5
	sll	%o5, CPTRSHIFT, %o5
	add	%o5, CPU_OFD, %o4	! %o4 has on_fault data offset
	stn	%l2, [%o3 + %o4]	! save onfault label for pil %o2
	add	%o5, CPU_LFD, %o4	! %o4 has lofault data offset
	stn	%l3, [%o3 + %o4]	! save lofault data for pil %o2

no_onfault:
	ldn	[THREAD_REG + T_ONTRAP], %l2
	brz,pt	%l2, 6f			! branch if no on_trap protection
	nop
	stn	%g0, [THREAD_REG + T_ONTRAP]! clear on_trap protection
	sub	%o2, LOCK_LEVEL + 1, %o5
	sll	%o5, CPTRSHIFT, %o5
	add	%o5, CPU_OTD, %o4	! %o4 has on_trap data offset
	stn	%l2, [%o3 + %o4]	! save on_trap label for pil %o2

	!
	! Set bit for this level in CPU's active interrupt bitmask.
	!
6:	ld	[%o3 + CPU_INTR_ACTV], %o5	! o5 has cpu_intr_actv b4 chng
	mov	1, %o4
	sll	%o4, %o2, %o4			! construct mask for level
#ifdef DEBUG
	!
	! ASSERT(!(CPU->cpu_intr_actv & (1 << PIL)))
	!
	andcc	%o5, %o4, %g0
	bz,pt	%xcc, 0f
	nop
	! Do not call panic if a panic is already in progress.
	sethi	%hi(panic_quiesce), %l2
	ld	[%l2 + %lo(panic_quiesce)], %l2
	brnz,pn	%l2, 0f
	nop
	sethi	%hi(current_thread_actv_bit_set), %o0
	call	panic
	or	%o0, %lo(current_thread_actv_bit_set), %o0
0:
#endif /* DEBUG */
	or	%o5, %o4, %o4
	!
	! See if we are interrupting another high-level interrupt.
	!
	srl	%o5, LOCK_LEVEL + 1, %o5	! only look at high-level bits
	brz,pt	%o5, 1f
	st	%o4, [%o3 + CPU_INTR_ACTV]	! delay - store active mask
	!
	! We have interrupted another high-level interrupt. Find its PIL,
	! compute the interval it ran for, and update its cumulative counter.
	!
	! Register usage:

	! o2 = PIL of this interrupt
	! o5 = high PIL bits of INTR_ACTV (not including this PIL)
	! l1 = bitmask used to find other active high-level PIL
	! o4 = index of bit set in l1
	! Use cpu_intr_actv to find the cpu_pil_high_start[] offset for the
	! interrupted high-level interrupt.
	! Create mask for cpu_intr_actv. Begin by looking for bits set
	! at one level below the current PIL. Since %o5 contains the active
	! mask already shifted right by (LOCK_LEVEL + 1), we start by looking
	! at bit (current_pil - (LOCK_LEVEL + 2)).
	sub	%o2, LOCK_LEVEL + 2, %o4
	mov	1, %l1
	sll	%l1, %o4, %l1
2:
#ifdef DEBUG
	! ASSERT(%l1 != 0) (we didn't shift the bit off the right edge)
	brnz,pt	%l1, 9f
	nop

	! Don't panic if a panic is already in progress.
	sethi	%hi(panic_quiesce), %l3
	ld	[%l3 + %lo(panic_quiesce)], %l3
	brnz,pn	%l3, 9f
	nop
	sethi	%hi(current_thread_nested_PIL_not_found), %o0
	call	panic
	or	%o0, %lo(current_thread_nested_PIL_not_found), %o0
9:
#endif /* DEBUG */
	andcc	%l1, %o5, %g0		! test mask against high-level bits of
	bnz	%xcc, 3f		! cpu_intr_actv
	nop
	srl	%l1, 1, %l1		! No match. Try next lower PIL.
	ba,pt	%xcc, 2b
	sub	%o4, 1, %o4		! delay - decrement PIL
3:
	sll	%o4, 3, %o4			! index to byte offset
	add	%o4, CPU_MCPU, %l1	! CPU_PIL_HIGH_START is too large
	add	%l1, MCPU_PIL_HIGH_START, %l1
	ldx	[%o3 + %l1], %l3		! load starting timestamp
#ifdef DEBUG
	brnz,pt	%l3, 9f
	nop
	! Don't panic if a panic is already in progress.
	sethi	%hi(panic_quiesce), %l1
	ld	[%l1 + %lo(panic_quiesce)], %l1
	brnz,pn	%l1, 9f
	nop
	srl	%o4, 3, %o1			! Find interrupted PIL for panic
	add	%o1, LOCK_LEVEL + 1, %o1
	sethi	%hi(current_thread_nested_pil_zero), %o0
	call	panic
	or	%o0, %lo(current_thread_nested_pil_zero), %o0
9:
#endif /* DEBUG */
	RD_CLOCK_TICK_NO_SUSPEND_CHECK(%l1, %l2)
	sub	%l1, %l3, %l3			! interval in %l3
	!
	! Check for Energy Star mode
	!
	lduh	[%o3 + CPU_DIVISOR], %l1	! %l1 = clock divisor
	cmp	%l1, 1
	bg,a,pn	%xcc, 2f
	mulx	%l3, %l1, %l3	! multiply interval by clock divisor iff > 1
2:
	!
	! We need to find the CPU offset of the cumulative counter. We start
	! with %o4, which has (PIL - (LOCK_LEVEL + 1)) * 8. We need PIL * 16,
	! so we shift left 1, then add (LOCK_LEVEL + 1) * 16, which is
	! CPU_INTRSTAT_LOW_PIL_OFFSET.
	!
	sll	%o4, 1, %o4
	add	%o4, CPU_MCPU, %o4		! CPU_INTRSTAT const too large
	add	%o4, MCPU_INTRSTAT, %o4		! add parts separately
	add	%o4, CPU_INTRSTAT_LOW_PIL_OFFSET, %o4
	ldx	[%o3 + %o4], %l1		! old counter in l1
	add	%l1, %l3, %l1			! new counter in l1
	stx	%l1, [%o3 + %o4]		! store new counter

	! Also update intracct[]
	lduh	[%o3 + CPU_MSTATE], %o4
	sllx	%o4, 3, %o4
	add	%o4, CPU_INTRACCT, %o4
	ldx	[%o3 + %o4], %l1
	add	%l1, %l3, %l1
	! Another high-level interrupt is active below this one, so
	! there is no need to check for an interrupt thread. That will be
	! done by the lowest priority high-level interrupt active.
	ba,pt	%xcc, 5f
	stx	%l1, [%o3 + %o4]		! delay - store new counter
1:
	! If we haven't interrupted another high-level interrupt, we may be
	! interrupting a low level interrupt thread. If so, compute its interval
	! and update its cumulative counter.
	lduh	[THREAD_REG + T_FLAGS], %o4
	andcc	%o4, T_INTR_THREAD, %g0
	bz,pt	%xcc, 4f
	nop

	! We have interrupted an interrupt thread. Take timestamp, compute
	! interval, update cumulative counter.

	! Check t_intr_start. If it is zero, either intr_thread() or
	! current_thread() (at a lower PIL, of course) already did
	! the accounting for the underlying interrupt thread.
	ldx	[THREAD_REG + T_INTR_START], %o5
	brz,pn	%o5, 4f
	nop

	stx	%g0, [THREAD_REG + T_INTR_START]
	RD_CLOCK_TICK_NO_SUSPEND_CHECK(%o4, %l2)
	sub	%o4, %o5, %o5			! o5 has the interval

	! Check for Energy Star mode
	lduh	[%o3 + CPU_DIVISOR], %o4	! %o4 = clock divisor
	cmp	%o4, 1
	bg,a,pn	%xcc, 2f
	mulx	%o5, %o4, %o5	! multiply interval by clock divisor iff > 1
2:
	ldub	[THREAD_REG + T_PIL], %o4
	sllx	%o4, 4, %o4			! PIL index to byte offset
	add	%o4, CPU_MCPU, %o4		! CPU_INTRSTAT const too large
	add	%o4, MCPU_INTRSTAT, %o4		! add parts separately
	ldx	[%o3 + %o4], %l2		! old counter in l2
	add	%l2, %o5, %l2			! new counter in l2
	stx	%l2, [%o3 + %o4]		! store new counter

	! Also update intracct[]
	lduh	[%o3 + CPU_MSTATE], %o4
	sllx	%o4, 3, %o4
	add	%o4, CPU_INTRACCT, %o4
	ldx	[%o3 + %o4], %l2
	add	%l2, %o5, %l2
	stx	%l2, [%o3 + %o4]
4:
	!
	! Handle high-level interrupts on separate interrupt stack.
	! No other high-level interrupts are active, so switch to int stack.
	!
	mov	%sp, %l1
	ldn	[%o3 + CPU_INTR_STACK], %l3
	sub	%l3, STACK_BIAS, %sp

5:
#ifdef DEBUG
	!
	! ASSERT(%o2 > LOCK_LEVEL)
	!
	cmp	%o2, LOCK_LEVEL
	bg,pt	%xcc, 3f
	nop
	mov	CE_PANIC, %o0
	sethi	%hi(current_thread_wrong_pil), %o1
	call	cmn_err				! %o2 has the %pil already
	or	%o1, %lo(current_thread_wrong_pil), %o1
#endif
3:
	! Store starting timestamp for this PIL in CPU structure at
	! cpu.cpu_m.pil_high_start[PIL - (LOCK_LEVEL + 1)]
        sub     %o2, LOCK_LEVEL + 1, %o4	! convert PIL to array index
	sllx    %o4, 3, %o4			! index to byte offset
	add	%o4, CPU_MCPU, %o4	! CPU_PIL_HIGH_START is too large
	add	%o4, MCPU_PIL_HIGH_START, %o4
	RD_CLOCK_TICK_NO_SUSPEND_CHECK(%o5, %l2)
        stx     %o5, [%o3 + %o4]

	wrpr	%g0, %o2, %pil			! enable interrupts

	!
	! call the handler
	!
	SERVE_INTR_PRE(%o1, %o3, %l2, %l3, %o4, %o5, %o2, %o0)
1:
	SERVE_INTR(%o1, %o3, %l2, %l3, %o4, %o5, %o2, %o0)

	brz,a,pt %o2, 0f			! if %o2, more intrs await
	rdpr	%pil, %o2			! delay annulled
	SERVE_INTR_NEXT(%o1, %o3, %l2, %l3, %o4, %o5, %o2, %o0)
	ba	1b
	nop
0:
	wrpr	%g0, PIL_MAX, %pil		! disable interrupts (1-15)

	cmp	%o2, PIL_15
	bne,pt	%xcc, 3f
	nop

	sethi	%hi(cpc_level15_inum), %o1
	ldx	[%o1 + %lo(cpc_level15_inum)], %o1 ! arg for intr_enqueue_req
	brz	%o1, 3f
	nop

	rdpr 	%pstate, %g5
	andn	%g5, PSTATE_IE, %g1
	wrpr	%g0, %g1, %pstate		! Disable vec interrupts

	call	intr_enqueue_req		! preserves %g5
	mov	PIL_15, %o0

	! clear perfcntr overflow
	mov	1, %o0
	sllx	%o0, PIL_15, %o0
	wr	%o0, CLEAR_SOFTINT

	wrpr	%g0, %g5, %pstate		! Enable vec interrupts

3:
	cmp	%o2, PIL_14
	be	tick_rtt			!  cpu-specific tick processing
	nop
	.global	current_thread_complete
current_thread_complete:
	!
	! Register usage:
	!
	! %l1 = stack pointer
	! %l2 = CPU_INTR_ACTV >> (LOCK_LEVEL + 1)
	! %o2 = PIL
	! %o3 = CPU pointer
	! %o4, %o5, %l3, %l4, %l5 = scratch
	!
	ldn	[THREAD_REG + T_CPU], %o3
	!
	! Clear bit for this level in CPU's interrupt active bitmask.
	!
	ld	[%o3 + CPU_INTR_ACTV], %l2
	mov	1, %o5
	sll	%o5, %o2, %o5
#ifdef DEBUG
	!
	! ASSERT(CPU->cpu_intr_actv & (1 << PIL))
	!
	andcc	%l2, %o5, %g0
	bnz,pt	%xcc, 0f
	nop
	! Do not call panic if a panic is already in progress.
	sethi	%hi(panic_quiesce), %l2
	ld	[%l2 + %lo(panic_quiesce)], %l2
	brnz,pn	%l2, 0f
	nop
	sethi	%hi(current_thread_actv_bit_not_set), %o0
	call	panic
	or	%o0, %lo(current_thread_actv_bit_not_set), %o0
0:
#endif /* DEBUG */
	andn	%l2, %o5, %l2
	st	%l2, [%o3 + CPU_INTR_ACTV]

	! Take timestamp, compute interval, update cumulative counter.
        sub     %o2, LOCK_LEVEL + 1, %o4	! PIL to array index
	sllx    %o4, 3, %o4			! index to byte offset
	add	%o4, CPU_MCPU, %o4	! CPU_PIL_HIGH_START is too large
	add	%o4, MCPU_PIL_HIGH_START, %o4
	RD_CLOCK_TICK_NO_SUSPEND_CHECK(%o5, %o0)
	ldx     [%o3 + %o4], %o0
#ifdef DEBUG
	! ASSERT(cpu.cpu_m.pil_high_start[pil - (LOCK_LEVEL + 1)] != 0)
	brnz,pt	%o0, 9f
	nop
	! Don't panic if a panic is already in progress.
	sethi	%hi(panic_quiesce), %l2
	ld	[%l2 + %lo(panic_quiesce)], %l2
	brnz,pn	%l2, 9f
	nop
	sethi	%hi(current_thread_timestamp_zero), %o0
	call	panic
	or	%o0, %lo(current_thread_timestamp_zero), %o0
9:
#endif /* DEBUG */
	stx	%g0, [%o3 + %o4]
	sub	%o5, %o0, %o5			! interval in o5

	! Check for Energy Star mode
	lduh	[%o3 + CPU_DIVISOR], %o4	! %o4 = clock divisor
	cmp	%o4, 1
	bg,a,pn	%xcc, 2f
	mulx	%o5, %o4, %o5	! multiply interval by clock divisor iff > 1
2:
	sllx	%o2, 4, %o4			! PIL index to byte offset
	add	%o4, CPU_MCPU, %o4		! CPU_INTRSTAT too large
	add	%o4, MCPU_INTRSTAT, %o4		! add parts separately
	ldx	[%o3 + %o4], %o0		! old counter in o0
	add	%o0, %o5, %o0			! new counter in o0
	stx	%o0, [%o3 + %o4]		! store new counter

	! Also update intracct[]
	lduh	[%o3 + CPU_MSTATE], %o4
	sllx	%o4, 3, %o4
	add	%o4, CPU_INTRACCT, %o4
	ldx	[%o3 + %o4], %o0
	add	%o0, %o5, %o0
	stx	%o0, [%o3 + %o4]

	!
	! get back on current thread's stack
	!
	srl	%l2, LOCK_LEVEL + 1, %l2
	tst	%l2				! any more high-level ints?
	movz	%xcc, %l1, %sp
	!
	! Current register usage:
	! o2 = PIL
	! o3 = CPU pointer
	! l0 = return address
	! l2 = intr_actv shifted right
	!
	bz,pt	%xcc, 3f			! if l2 was zero, no more ints
	nop
	!
	! We found another high-level interrupt active below the one that just
	! returned. Store a starting timestamp for it in the CPU structure.
	!
	! Use cpu_intr_actv to find the cpu_pil_high_start[] offset for the
	! interrupted high-level interrupt.
	! Create mask for cpu_intr_actv. Begin by looking for bits set
	! at one level below the current PIL. Since %l2 contains the active
	! mask already shifted right by (LOCK_LEVEL + 1), we start by looking
	! at bit (current_pil - (LOCK_LEVEL + 2)).
	! %l1 = mask, %o5 = index of bit set in mask
	!
	mov	1, %l1
	sub	%o2, LOCK_LEVEL + 2, %o5
	sll	%l1, %o5, %l1			! l1 = mask for level
1:
#ifdef DEBUG
	! ASSERT(%l1 != 0) (we didn't shift the bit off the right edge)
	brnz,pt	%l1, 9f
	nop
	sethi	%hi(current_thread_nested_PIL_not_found), %o0
	call	panic
	or	%o0, %lo(current_thread_nested_PIL_not_found), %o0
9:
#endif /* DEBUG */
	andcc	%l1, %l2, %g0		! test mask against high-level bits of
	bnz	%xcc, 2f		! cpu_intr_actv
	nop
	srl	%l1, 1, %l1		! No match. Try next lower PIL.
	ba,pt	%xcc, 1b
	sub	%o5, 1, %o5		! delay - decrement PIL
2:
	sll	%o5, 3, %o5		! convert array index to byte offset
	add	%o5, CPU_MCPU, %o5	! CPU_PIL_HIGH_START is too large
	add	%o5, MCPU_PIL_HIGH_START, %o5
	RD_CLOCK_TICK_NO_SUSPEND_CHECK(%o4, %l2)
	! Another high-level interrupt is active below this one, so
	! there is no need to check for an interrupt thread. That will be
	! done by the lowest priority high-level interrupt active.
	ba,pt	%xcc, 7f
	stx	%o4, [%o3 + %o5]	! delay - store timestamp
3:
	! If we haven't interrupted another high-level interrupt, we may have
	! interrupted a low level interrupt thread. If so, store a starting
	! timestamp in its thread structure.
	lduh	[THREAD_REG + T_FLAGS], %o4
	andcc	%o4, T_INTR_THREAD, %g0
	bz,pt	%xcc, 7f
	nop

	RD_CLOCK_TICK_NO_SUSPEND_CHECK(%o4, %l2)
	stx	%o4, [THREAD_REG + T_INTR_START]

7:
	sub	%o2, LOCK_LEVEL + 1, %o4
	sll	%o4, CPTRSHIFT, %o5

	! Check on_trap saved area and restore as needed
	add	%o5, CPU_OTD, %o4
	ldn	[%o3 + %o4], %l2
	brz,pt %l2, no_ontrp_restore
	nop
	stn	%l2, [THREAD_REG + T_ONTRAP] ! restore
	stn	%g0, [%o3 + %o4]	! clear

no_ontrp_restore:
	! Check on_fault saved area and restore as needed
	add	%o5, CPU_OFD, %o4
	ldn	[%o3 + %o4], %l2
	brz,pt %l2, 8f
	nop
	stn	%l2, [THREAD_REG + T_ONFAULT] ! restore
	stn	%g0, [%o3 + %o4]	! clear
	add	%o5, CPU_LFD, %o4
	ldn	[%o3 + %o4], %l2
	stn	%l2, [THREAD_REG + T_LOFAULT] ! restore
	stn	%g0, [%o3 + %o4]	! clear


8:
	! Enable interrupts and return
	jmp	%l0 + 8
	wrpr	%g0, %o2, %pil			! enable interrupts
	SET_SIZE(current_thread)


#ifdef DEBUG
current_thread_wrong_pil:
	.asciz	"current_thread: unexpected pil level: %d"
current_thread_actv_bit_set:
	.asciz	"current_thread(): cpu_intr_actv bit already set for PIL"
current_thread_actv_bit_not_set:
	.asciz	"current_thread(): cpu_intr_actv bit not set for PIL"
current_thread_nested_pil_zero:
	.asciz	"current_thread(): timestamp zero for nested PIL %d"
current_thread_timestamp_zero:
	.asciz	"current_thread(): timestamp zero upon handler return"
current_thread_nested_PIL_not_found:
	.asciz	"current_thread: couldn't find nested high-level PIL"
#endif /* DEBUG */

/*
 * Return a thread's interrupt level.
 * Since this isn't saved anywhere but in %l4 on interrupt entry, we
 * must dig it out of the save area.
 *
 * Caller 'swears' that this really is an interrupt thread.
 *
 * int
 * intr_level(t)
 *	kthread_id_t	t;
 */

	ENTRY_NP(intr_level)
	retl
	ldub	[%o0 + T_PIL], %o0		! return saved pil
	SET_SIZE(intr_level)

	ENTRY_NP(disable_pil_intr)
	rdpr	%pil, %o0
	retl
	wrpr	%g0, PIL_MAX, %pil		! disable interrupts (1-15)
	SET_SIZE(disable_pil_intr)

	ENTRY_NP(enable_pil_intr)
	retl
	wrpr	%o0, %pil
	SET_SIZE(enable_pil_intr)

	ENTRY_NP(disable_vec_intr)
	rdpr	%pstate, %o0
	andn	%o0, PSTATE_IE, %g1
	retl
	wrpr	%g0, %g1, %pstate		! disable interrupt
	SET_SIZE(disable_vec_intr)

	ENTRY_NP(enable_vec_intr)
	retl
	wrpr	%g0, %o0, %pstate
	SET_SIZE(enable_vec_intr)

	ENTRY_NP(cbe_level14)
	save    %sp, -SA(MINFRAME), %sp ! get a new window
	!
	! Make sure that this is from TICK_COMPARE; if not just return
	!
	rd	SOFTINT, %l1
	set	(TICK_INT_MASK | STICK_INT_MASK), %o2
	andcc	%l1, %o2, %g0
	bz,pn	%icc, 2f
	nop

	CPU_ADDR(%o1, %o2)
	call	cyclic_fire
	mov	%o1, %o0
2:
	ret
	restore	%g0, 1, %o0
	SET_SIZE(cbe_level14)


	ENTRY_NP(kdi_setsoftint)
	save	%sp, -SA(MINFRAME), %sp	! get a new window
	rdpr	%pstate, %l5
	andn	%l5, PSTATE_IE, %l1
	wrpr	%l1, %pstate		! disable interrupt
	!
	! We have a pointer to an interrupt vector data structure.
	! Put the request on the cpu's softint priority list and
	! set %set_softint.
	!
	! Register usage
	! 	%i0 - pointer to intr_vec_t (iv)
	!	%l2 - requested pil
	!	%l4 - cpu
	!	%l5 - pstate
	!	%l1, %l3, %l6 - temps
	!
	! check if a softint is pending for this softint,
	! if one is pending, don't bother queuing another.
	!
	lduh	[%i0 + IV_FLAGS], %l1	! %l1 = iv->iv_flags
	and	%l1, IV_SOFTINT_PEND, %l6 ! %l6 = iv->iv_flags & IV_SOFTINT_PEND
	brnz,pn	%l6, 4f			! branch if softint is already pending
	or	%l1, IV_SOFTINT_PEND, %l2
	sth	%l2, [%i0 + IV_FLAGS]	! Set IV_SOFTINT_PEND flag

	CPU_ADDR(%l4, %l2)		! %l4 = cpu
	lduh	[%i0 + IV_PIL], %l2	! %l2 = iv->iv_pil

	!
	! Insert intr_vec_t (iv) to appropriate cpu's softint priority list
	!
	sll	%l2, CPTRSHIFT, %l0	! %l0 = offset to pil entry
	add	%l4, INTR_TAIL, %l6	! %l6 = &cpu->m_cpu.intr_tail
	ldn	[%l6 + %l0], %l1	! %l1 = cpu->m_cpu.intr_tail[pil]
					!       current tail (ct)
	brz,pt	%l1, 2f			! branch if current tail is NULL
	stn	%i0, [%l6 + %l0]	! make intr_vec_t (iv) as new tail
	!
	! there's pending intr_vec_t already
	!
	lduh	[%l1 + IV_FLAGS], %l6	! %l6 = ct->iv_flags
	and	%l6, IV_SOFTINT_MT, %l6	! %l6 = ct->iv_flags & IV_SOFTINT_MT
	brz,pt	%l6, 1f			! check for Multi target softint flag
	add	%l1, IV_PIL_NEXT, %l3	! %l3 = &ct->iv_pil_next
	ld	[%l4 + CPU_ID], %l6	! for multi target softint, use cpuid
	sll	%l6, CPTRSHIFT, %l6	! calculate offset address from cpuid
	add	%l3, %l6, %l3		! %l3 =  &ct->iv_xpil_next[cpuid]
1:
	!
	! update old tail
	!
	ba,pt	%xcc, 3f
	stn	%i0, [%l3]		! [%l3] = iv, set pil_next field
2:
	!
	! no pending intr_vec_t; make intr_vec_t as new head
	!
	add	%l4, INTR_HEAD, %l6	! %l6 = &cpu->m_cpu.intr_head[pil]
	stn	%i0, [%l6 + %l0]	! cpu->m_cpu.intr_head[pil] = iv
3:
	!
	! Write %set_softint with (1<<pil) to cause a "pil" level trap
	!
	mov	1, %l1			! %l1 = 1
	sll	%l1, %l2, %l1		! %l1 = 1 << pil
	wr	%l1, SET_SOFTINT	! trigger required pil softint
4:
	wrpr	%g0, %l5, %pstate	! %pstate = saved %pstate (in %l5)
	ret
	restore
	SET_SIZE(kdi_setsoftint)

	!
	! Register usage
	!	Arguments:
	! 	%g1 - Pointer to intr_vec_t (iv)
	!
	!	Internal:
	!	%g2 - pil
	!	%g4 - cpu
	!	%g3,%g5-g7 - temps
	!
	ENTRY_NP(setsoftint_tl1)
	!
	! We have a pointer to an interrupt vector data structure.
	! Put the request on the cpu's softint priority list and
	! set %set_softint.
	!
	CPU_ADDR(%g4, %g2)		! %g4 = cpu
	lduh	[%g1 + IV_PIL], %g2	! %g2 = iv->iv_pil

	!
	! Insert intr_vec_t (iv) to appropriate cpu's softint priority list
	!
	sll	%g2, CPTRSHIFT, %g7	! %g7 = offset to pil entry
	add	%g4, INTR_TAIL, %g6	! %g6 = &cpu->m_cpu.intr_tail
	ldn	[%g6 + %g7], %g5	! %g5 = cpu->m_cpu.intr_tail[pil]
					!       current tail (ct)
	brz,pt	%g5, 1f			! branch if current tail is NULL
	stn	%g1, [%g6 + %g7]	! make intr_rec_t (iv) as new tail
	!
	! there's pending intr_vec_t already
	!
	lduh	[%g5 + IV_FLAGS], %g6	! %g6 = ct->iv_flags
	and	%g6, IV_SOFTINT_MT, %g6	! %g6 = ct->iv_flags & IV_SOFTINT_MT
	brz,pt	%g6, 0f			! check for Multi target softint flag
	add	%g5, IV_PIL_NEXT, %g3	! %g3 = &ct->iv_pil_next
	ld	[%g4 + CPU_ID], %g6	! for multi target softint, use cpuid
	sll	%g6, CPTRSHIFT, %g6	! calculate offset address from cpuid
	add	%g3, %g6, %g3		! %g3 = &ct->iv_xpil_next[cpuid]
0:
	!
	! update old tail
	!
	ba,pt	%xcc, 2f
	stn	%g1, [%g3]		! [%g3] = iv, set pil_next field
1:
	!
	! no pending intr_vec_t; make intr_vec_t as new head
	!
	add	%g4, INTR_HEAD, %g6	! %g6 = &cpu->m_cpu.intr_head[pil]
	stn	%g1, [%g6 + %g7]	! cpu->m_cpu.intr_head[pil] = iv
2:
#ifdef TRAPTRACE
	TRACE_PTR(%g5, %g6)
	GET_TRACE_TICK(%g6, %g3)
	stxa	%g6, [%g5 + TRAP_ENT_TICK]%asi	! trap_tick = %tick
	TRACE_SAVE_TL_GL_REGS(%g5, %g6)
	rdpr	%tt, %g6
	stha	%g6, [%g5 + TRAP_ENT_TT]%asi	! trap_type = %tt
	rdpr	%tpc, %g6
	stna	%g6, [%g5 + TRAP_ENT_TPC]%asi	! trap_pc = %tpc
	rdpr	%tstate, %g6
	stxa	%g6, [%g5 + TRAP_ENT_TSTATE]%asi ! trap_tstate = %tstate
	stna	%sp, [%g5 + TRAP_ENT_SP]%asi	! trap_sp = %sp
	stna	%g1, [%g5 + TRAP_ENT_TR]%asi	! trap_tr = iv
	ldn	[%g1 + IV_PIL_NEXT], %g6	!
	stna	%g6, [%g5 + TRAP_ENT_F1]%asi	! trap_f1 = iv->iv_pil_next
	add	%g4, INTR_HEAD, %g6
	ldn	[%g6 + %g7], %g6		! %g6=cpu->m_cpu.intr_head[pil]
	stna	%g6, [%g5 + TRAP_ENT_F2]%asi	! trap_f2 = intr_head[pil]
	add	%g4, INTR_TAIL, %g6
	ldn	[%g6 + %g7], %g6		! %g6=cpu->m_cpu.intr_tail[pil]
	stna	%g6, [%g5 + TRAP_ENT_F3]%asi	! trap_f3 = intr_tail[pil]
	stna	%g2, [%g5 + TRAP_ENT_F4]%asi	! trap_f4 = pil
	TRACE_NEXT(%g5, %g6, %g3)
#endif /* TRAPTRACE */
	!
	! Write %set_softint with (1<<pil) to cause a "pil" level trap
	!
	mov	1, %g5			! %g5 = 1
	sll	%g5, %g2, %g5		! %g5 = 1 << pil
	wr	%g5, SET_SOFTINT	! trigger required pil softint
	retry
	SET_SIZE(setsoftint_tl1)

	!
	! Register usage
	!	Arguments:
	! 	%g1 - inumber
	!
	!	Internal:
	! 	%g1 - softint pil mask
	!	%g2 - pil of intr_vec_t
	!	%g3 - pointer to current intr_vec_t (iv)
	!	%g4 - cpu
	!	%g5, %g6,%g7 - temps
	!
	ENTRY_NP(setvecint_tl1)
	!
	! Verify the inumber received (should be inum < MAXIVNUM).
	!
	set	MAXIVNUM, %g2
	cmp	%g1, %g2
	bgeu,pn	%xcc, .no_ivintr
	clr	%g2			! expected in .no_ivintr

	!
	! Fetch data from intr_vec_table according to the inum.
	!
	! We have an interrupt number. Fetch the interrupt vector requests
	! from the interrupt vector table for a given interrupt number and
	! insert them into cpu's softint priority lists and set %set_softint.
	!
	set	intr_vec_table, %g5	! %g5 = intr_vec_table
	sll	%g1, CPTRSHIFT, %g6	! %g6 = offset to inum entry in table
	add	%g5, %g6, %g5		! %g5 = &intr_vec_table[inum]
	ldn	[%g5], %g3		! %g3 = pointer to first entry of
					!       intr_vec_t list

	! Verify the first intr_vec_t pointer for a given inum and it should
	! not be NULL. This used to be guarded by DEBUG but broken drivers can
	! cause spurious tick interrupts when the softint register is programmed
	! with 1 << 0 at the end of this routine. Now we always check for a
	! valid intr_vec_t pointer.
	brz,pn	%g3, .no_ivintr
	nop

	!
	! Traverse the intr_vec_t link list, put each item on to corresponding
	! CPU softint priority queue, and compose the final softint pil mask.
	!
	! At this point:
	!	%g3 = intr_vec_table[inum]
	!
	CPU_ADDR(%g4, %g2)		! %g4 = cpu
	mov	%g0, %g1		! %g1 = 0, initialize pil mask to 0
0:
	!
	! Insert next intr_vec_t (iv) to appropriate cpu's softint priority list
	!
	! At this point:
	!	%g1 = softint pil mask
	!	%g3 = pointer to next intr_vec_t (iv)
	!	%g4 = cpu
	!
	lduh	[%g3 + IV_PIL], %g2	! %g2 = iv->iv_pil
	sll	%g2, CPTRSHIFT, %g7	! %g7 = offset to pil entry
	add	%g4, INTR_TAIL, %g6	! %g6 = &cpu->m_cpu.intr_tail
	ldn	[%g6 + %g7], %g5	! %g5 = cpu->m_cpu.intr_tail[pil]
					! 	current tail (ct)
	brz,pt	%g5, 2f			! branch if current tail is NULL
	stn	%g3, [%g6 + %g7]	! make intr_vec_t (iv) as new tail
					! cpu->m_cpu.intr_tail[pil] = iv
	!
	! there's pending intr_vec_t already
	!
	lduh	[%g5 + IV_FLAGS], %g6	! %g6 = ct->iv_flags
	and	%g6, IV_SOFTINT_MT, %g6	! %g6 = ct->iv_flags & IV_SOFTINT_MT
	brz,pt	%g6, 1f			! check for Multi target softint flag
	add	%g5, IV_PIL_NEXT, %g5	! %g5 = &ct->iv_pil_next
	ld	[%g4 + CPU_ID], %g6	! for multi target softint, use cpuid
	sll	%g6, CPTRSHIFT, %g6	! calculate offset address from cpuid
	add	%g5, %g6, %g5		! %g5 = &ct->iv_xpil_next[cpuid]
1:
	!
	! update old tail
	!
	ba,pt	%xcc, 3f
	stn	%g3, [%g5]		! [%g5] = iv, set pil_next field
2:
	!
	! no pending intr_vec_t; make intr_vec_t as new head
	!
	add	%g4, INTR_HEAD, %g6	!  %g6 = &cpu->m_cpu.intr_head[pil]
	stn	%g3, [%g6 + %g7]	!  cpu->m_cpu.intr_head[pil] = iv
3:
#ifdef TRAPTRACE
	TRACE_PTR(%g5, %g6)
	TRACE_SAVE_TL_GL_REGS(%g5, %g6)
	rdpr	%tt, %g6
	stha	%g6, [%g5 + TRAP_ENT_TT]%asi	! trap_type = %tt`
	rdpr	%tpc, %g6
	stna	%g6, [%g5 + TRAP_ENT_TPC]%asi	! trap_pc = %tpc
	rdpr	%tstate, %g6
	stxa	%g6, [%g5 + TRAP_ENT_TSTATE]%asi ! trap_tstate = %tstate
	stna	%sp, [%g5 + TRAP_ENT_SP]%asi	! trap_sp = %sp
	stna	%g3, [%g5 + TRAP_ENT_TR]%asi	! trap_tr = iv
	stna	%g1, [%g5 + TRAP_ENT_F1]%asi	! trap_f1 = pil mask
	add	%g4, INTR_HEAD, %g6
	ldn	[%g6 + %g7], %g6		! %g6=cpu->m_cpu.intr_head[pil]
	stna	%g6, [%g5 + TRAP_ENT_F2]%asi	! trap_f2 = intr_head[pil]
	add	%g4, INTR_TAIL, %g6
	ldn	[%g6 + %g7], %g6		! %g6=cpu->m_cpu.intr_tail[pil]
	stna	%g6, [%g5 + TRAP_ENT_F3]%asi	! trap_f3 = intr_tail[pil]
	stna	%g2, [%g5 + TRAP_ENT_F4]%asi	! trap_f4 = pil
	GET_TRACE_TICK(%g6, %g7)
	stxa	%g6, [%g5 + TRAP_ENT_TICK]%asi	! trap_tick = %tick
	TRACE_NEXT(%g5, %g6, %g7)
#endif /* TRAPTRACE */
	mov	1, %g6			! %g6 = 1
	sll	%g6, %g2, %g6		! %g6 = 1 << pil
	or	%g1, %g6, %g1		! %g1 |= (1 << pil), pil mask
	ldn	[%g3 + IV_VEC_NEXT], %g3 ! %g3 = pointer to next intr_vec_t (iv)
	brnz,pn	%g3, 0b			! iv->iv_vec_next is non NULL, goto 0b
	nop
	wr	%g1, SET_SOFTINT	! triggered one or more pil softints
	retry

.no_ivintr:
	! no_ivintr: arguments: rp, inum (%g1), pil (%g2 == 0)
	mov	%g2, %g3
	mov	%g1, %g2
	set	no_ivintr, %g1
	ba,pt	%xcc, sys_trap
	mov	PIL_15, %g4
	SET_SIZE(setvecint_tl1)

	ENTRY_NP(wr_clr_softint)
	retl
	wr	%o0, CLEAR_SOFTINT
	SET_SIZE(wr_clr_softint)

/*
 * intr_enqueue_req
 *
 * %o0 - pil
 * %o1 - pointer to intr_vec_t (iv)
 * %o5 - preserved
 * %g5 - preserved
 */
	ENTRY_NP(intr_enqueue_req)
	!
	CPU_ADDR(%g4, %g1)		! %g4 = cpu

	!
	! Insert intr_vec_t (iv) to appropriate cpu's softint priority list
	!
	sll	%o0, CPTRSHIFT, %o0	! %o0 = offset to pil entry
	add	%g4, INTR_TAIL, %g6	! %g6 = &cpu->m_cpu.intr_tail
	ldn	[%o0 + %g6], %g1	! %g1 = cpu->m_cpu.intr_tail[pil]
					!       current tail (ct)
	brz,pt	%g1, 2f			! branch if current tail is NULL
	stn	%o1, [%g6 + %o0]	! make intr_vec_t (iv) as new tail

	!
	! there's pending intr_vec_t already
	!
	lduh	[%g1 + IV_FLAGS], %g6	! %g6 = ct->iv_flags
	and	%g6, IV_SOFTINT_MT, %g6	! %g6 = ct->iv_flags & IV_SOFTINT_MT
	brz,pt	%g6, 1f			! check for Multi target softint flag
	add	%g1, IV_PIL_NEXT, %g3	! %g3 = &ct->iv_pil_next
	ld	[%g4 + CPU_ID], %g6	! for multi target softint, use cpuid
	sll	%g6, CPTRSHIFT, %g6	! calculate offset address from cpuid
	add	%g3, %g6, %g3		! %g3 = &ct->iv_xpil_next[cpuid]
1:
	!
	! update old tail
	!
	ba,pt	%xcc, 3f
	stn	%o1, [%g3]		! {%g5] = iv, set pil_next field
2:
	!
	! no intr_vec_t's queued so make intr_vec_t as new head
	!
	add	%g4, INTR_HEAD, %g6	! %g6 = &cpu->m_cpu.intr_head[pil]
	stn	%o1, [%g6 + %o0]	! cpu->m_cpu.intr_head[pil] = iv
3:
	retl
	nop
	SET_SIZE(intr_enqueue_req)

/*
 * Set CPU's base SPL level, based on which interrupt levels are active.
 * 	Called at spl7 or above.
 */

	ENTRY_NP(set_base_spl)
	ldn	[THREAD_REG + T_CPU], %o2	! load CPU pointer
	ld	[%o2 + CPU_INTR_ACTV], %o5	! load active interrupts mask

/*
 * WARNING: non-standard callinq sequence; do not call from C
 *	%o2 = pointer to CPU
 *	%o5 = updated CPU_INTR_ACTV
 */
_intr_set_spl:					! intr_thread_exit enters here
	!
	! Determine highest interrupt level active.  Several could be blocked
	! at higher levels than this one, so must convert flags to a PIL
	! Normally nothing will be blocked, so test this first.
	!
	brz,pt	%o5, 1f				! nothing active
	sra	%o5, 11, %o3			! delay - set %o3 to bits 15-11
	set	_intr_flag_table, %o1
	tst	%o3				! see if any of the bits set
	ldub	[%o1 + %o3], %o3		! load bit number
	bnz,a,pn %xcc, 1f			! yes, add 10 and we're done
	add	%o3, 11-1, %o3			! delay - add bit number - 1

	sra	%o5, 6, %o3			! test bits 10-6
	tst	%o3
	ldub	[%o1 + %o3], %o3
	bnz,a,pn %xcc, 1f
	add	%o3, 6-1, %o3

	sra	%o5, 1, %o3			! test bits 5-1
	ldub	[%o1 + %o3], %o3

	!
	! highest interrupt level number active is in %l6
	!
1:
	retl
	st	%o3, [%o2 + CPU_BASE_SPL]	! delay - store base priority
	SET_SIZE(set_base_spl)

/*
 * Table that finds the most significant bit set in a five bit field.
 * Each entry is the high-order bit number + 1 of it's index in the table.
 * This read-only data is in the text segment.
 */
_intr_flag_table:
	.byte	0, 1, 2, 2,	3, 3, 3, 3,	4, 4, 4, 4,	4, 4, 4, 4
	.byte	5, 5, 5, 5,	5, 5, 5, 5,	5, 5, 5, 5,	5, 5, 5, 5
	.align	4

/*
 * int
 * intr_passivate(from, to)
 *	kthread_id_t	from;		interrupt thread
 *	kthread_id_t	to;		interrupted thread
 */

	ENTRY_NP(intr_passivate)
	save	%sp, -SA(MINFRAME), %sp	! get a new window

	flushw				! force register windows to stack
	!
	! restore registers from the base of the stack of the interrupt thread.
	!
	ldn	[%i0 + T_STACK], %i2	! get stack save area pointer
	ldn	[%i2 + (0*GREGSIZE)], %l0	! load locals
	ldn	[%i2 + (1*GREGSIZE)], %l1
	ldn	[%i2 + (2*GREGSIZE)], %l2
	ldn	[%i2 + (3*GREGSIZE)], %l3
	ldn	[%i2 + (4*GREGSIZE)], %l4
	ldn	[%i2 + (5*GREGSIZE)], %l5
	ldn	[%i2 + (6*GREGSIZE)], %l6
	ldn	[%i2 + (7*GREGSIZE)], %l7
	ldn	[%i2 + (8*GREGSIZE)], %o0	! put ins from stack in outs
	ldn	[%i2 + (9*GREGSIZE)], %o1
	ldn	[%i2 + (10*GREGSIZE)], %o2
	ldn	[%i2 + (11*GREGSIZE)], %o3
	ldn	[%i2 + (12*GREGSIZE)], %o4
	ldn	[%i2 + (13*GREGSIZE)], %o5
	ldn	[%i2 + (14*GREGSIZE)], %i4
					! copy stack/pointer without using %sp
	ldn	[%i2 + (15*GREGSIZE)], %i5
	!
	! put registers into the save area at the top of the interrupted
	! thread's stack, pointed to by %l7 in the save area just loaded.
	!
	ldn	[%i1 + T_SP], %i3	! get stack save area pointer
	stn	%l0, [%i3 + STACK_BIAS + (0*GREGSIZE)]	! save locals
	stn	%l1, [%i3 + STACK_BIAS + (1*GREGSIZE)]
	stn	%l2, [%i3 + STACK_BIAS + (2*GREGSIZE)]
	stn	%l3, [%i3 + STACK_BIAS + (3*GREGSIZE)]
	stn	%l4, [%i3 + STACK_BIAS + (4*GREGSIZE)]
	stn	%l5, [%i3 + STACK_BIAS + (5*GREGSIZE)]
	stn	%l6, [%i3 + STACK_BIAS + (6*GREGSIZE)]
	stn	%l7, [%i3 + STACK_BIAS + (7*GREGSIZE)]
	stn	%o0, [%i3 + STACK_BIAS + (8*GREGSIZE)]	! save ins using outs
	stn	%o1, [%i3 + STACK_BIAS + (9*GREGSIZE)]
	stn	%o2, [%i3 + STACK_BIAS + (10*GREGSIZE)]
	stn	%o3, [%i3 + STACK_BIAS + (11*GREGSIZE)]
	stn	%o4, [%i3 + STACK_BIAS + (12*GREGSIZE)]
	stn	%o5, [%i3 + STACK_BIAS + (13*GREGSIZE)]
	stn	%i4, [%i3 + STACK_BIAS + (14*GREGSIZE)]
						! fp, %i7 copied using %i4
	stn	%i5, [%i3 + STACK_BIAS + (15*GREGSIZE)]
	stn	%g0, [%i2 + ((8+6)*GREGSIZE)]
						! clear fp in save area

	! load saved pil for return
	ldub	[%i0 + T_PIL], %i0
	ret
	restore
	SET_SIZE(intr_passivate)

/*
 * intr_get_time() is a resource for interrupt handlers to determine how
 * much time has been spent handling the current interrupt. Such a function
 * is needed because higher level interrupts can arrive during the
 * processing of an interrupt, thus making direct comparisons of %tick by
 * the handler inaccurate. intr_get_time() only returns time spent in the
 * current interrupt handler.
 *
 * The caller must be calling from an interrupt handler running at a pil
 * below or at lock level. Timings are not provided for high-level
 * interrupts.
 *
 * The first time intr_get_time() is called while handling an interrupt,
 * it returns the time since the interrupt handler was invoked. Subsequent
 * calls will return the time since the prior call to intr_get_time(). Time
 * is returned as ticks, adjusted for any clock divisor due to power
 * management. Use tick2ns() to convert ticks to nsec. Warning: ticks may
 * not be the same across CPUs.
 *
 * Theory Of Intrstat[][]:
 *
 * uint64_t intrstat[pil][0..1] is an array indexed by pil level, with two
 * uint64_ts per pil.
 *
 * intrstat[pil][0] is a cumulative count of the number of ticks spent
 * handling all interrupts at the specified pil on this CPU. It is
 * exported via kstats to the user.
 *
 * intrstat[pil][1] is always a count of ticks less than or equal to the
 * value in [0]. The difference between [1] and [0] is the value returned
 * by a call to intr_get_time(). At the start of interrupt processing,
 * [0] and [1] will be equal (or nearly so). As the interrupt consumes
 * time, [0] will increase, but [1] will remain the same. A call to
 * intr_get_time() will return the difference, then update [1] to be the
 * same as [0]. Future calls will return the time since the last call.
 * Finally, when the interrupt completes, [1] is updated to the same as [0].
 *
 * Implementation:
 *
 * intr_get_time() works much like a higher level interrupt arriving. It
 * "checkpoints" the timing information by incrementing intrstat[pil][0]
 * to include elapsed running time, and by setting t_intr_start to %tick.
 * It then sets the return value to intrstat[pil][0] - intrstat[pil][1],
 * and updates intrstat[pil][1] to be the same as the new value of
 * intrstat[pil][0].
 *
 * In the normal handling of interrupts, after an interrupt handler returns
 * and the code in intr_thread() updates intrstat[pil][0], it then sets
 * intrstat[pil][1] to the new value of intrstat[pil][0]. When [0] == [1],
 * the timings are reset, i.e. intr_get_time() will return [0] - [1] which
 * is 0.
 *
 * Whenever interrupts arrive on a CPU which is handling a lower pil
 * interrupt, they update the lower pil's [0] to show time spent in the
 * handler that they've interrupted. This results in a growing discrepancy
 * between [0] and [1], which is returned the next time intr_get_time() is
 * called. Time spent in the higher-pil interrupt will not be returned in
 * the next intr_get_time() call from the original interrupt, because
 * the higher-pil interrupt's time is accumulated in intrstat[higherpil][].
 */
	ENTRY_NP(intr_get_time)
#ifdef DEBUG
	!
	! Lots of asserts, but just check panic_quiesce first.
	! Don't bother with lots of tests if we're just ignoring them.
	!
	sethi	%hi(panic_quiesce), %o0
	ld	[%o0 + %lo(panic_quiesce)], %o0
	brnz,pn	%o0, 2f
	nop
	!
	! ASSERT(%pil <= LOCK_LEVEL)
	!
	rdpr	%pil, %o1
	cmp	%o1, LOCK_LEVEL
	ble,pt	%xcc, 0f
	sethi	%hi(intr_get_time_high_pil), %o0	! delay
	call	panic
	or	%o0, %lo(intr_get_time_high_pil), %o0
0:
	!
	! ASSERT((t_flags & T_INTR_THREAD) != 0 && t_pil > 0)
	!
	lduh	[THREAD_REG + T_FLAGS], %o2
	andcc	%o2, T_INTR_THREAD, %g0
	bz,pn	%xcc, 1f
	ldub	[THREAD_REG + T_PIL], %o1		! delay
	brnz,pt	%o1, 0f
1:
	sethi	%hi(intr_get_time_not_intr), %o0
	call	panic
	or	%o0, %lo(intr_get_time_not_intr), %o0
0:
	!
	! ASSERT(t_intr_start != 0)
	!
	ldx	[THREAD_REG + T_INTR_START], %o1
	brnz,pt	%o1, 2f
	sethi	%hi(intr_get_time_no_start_time), %o0	! delay
	call	panic
	or	%o0, %lo(intr_get_time_no_start_time), %o0
2:
#endif /* DEBUG */
	!
	! %o0 = elapsed time and return value
	! %o1 = pil
	! %o2 = scratch
	! %o3 = scratch
	! %o4 = scratch
	! %o5 = cpu
	!
	wrpr	%g0, PIL_MAX, %pil	! make this easy -- block normal intrs
	ldn	[THREAD_REG + T_CPU], %o5
	ldub	[THREAD_REG + T_PIL], %o1
	ldx	[THREAD_REG + T_INTR_START], %o3 ! %o3 = t_intr_start
	!
	! Calculate elapsed time since t_intr_start. Update t_intr_start,
	! get delta, and multiply by cpu_divisor if necessary.
	!
	RD_CLOCK_TICK_NO_SUSPEND_CHECK(%o2, %o0)
	stx	%o2, [THREAD_REG + T_INTR_START]
	sub	%o2, %o3, %o0

	lduh	[%o5 + CPU_DIVISOR], %o4
	cmp	%o4, 1
	bg,a,pn	%xcc, 1f
	mulx	%o0, %o4, %o0	! multiply interval by clock divisor iff > 1
1:
	! Update intracct[]
	lduh	[%o5 + CPU_MSTATE], %o4
	sllx	%o4, 3, %o4
	add	%o4, CPU_INTRACCT, %o4
	ldx	[%o5 + %o4], %o2
	add	%o2, %o0, %o2
	stx	%o2, [%o5 + %o4]

	!
	! Increment cpu_m.intrstat[pil][0]. Calculate elapsed time since
	! cpu_m.intrstat[pil][1], which is either when the interrupt was
	! first entered, or the last time intr_get_time() was invoked. Then
	! update cpu_m.intrstat[pil][1] to match [0].
	!
	sllx	%o1, 4, %o3
	add	%o3, CPU_MCPU, %o3
	add	%o3, MCPU_INTRSTAT, %o3
	add	%o3, %o5, %o3		! %o3 = cpu_m.intrstat[pil][0]
	ldx	[%o3], %o2
	add	%o2, %o0, %o2		! %o2 = new value for intrstat
	stx	%o2, [%o3]
	ldx	[%o3 + 8], %o4		! %o4 = cpu_m.intrstat[pil][1]
	sub	%o2, %o4, %o0		! %o0 is elapsed time since %o4
	stx	%o2, [%o3 + 8]		! make [1] match [0], resetting time

	ld	[%o5 + CPU_BASE_SPL], %o2	! restore %pil to the greater
	cmp	%o2, %o1			! of either our pil %o1 or
	movl	%xcc, %o1, %o2			! cpu_base_spl.
	retl
	wrpr	%g0, %o2, %pil
	SET_SIZE(intr_get_time)

#ifdef DEBUG
intr_get_time_high_pil:
	.asciz	"intr_get_time(): %pil > LOCK_LEVEL"
intr_get_time_not_intr:
	.asciz	"intr_get_time(): not called from an interrupt thread"
intr_get_time_no_start_time:
	.asciz	"intr_get_time(): t_intr_start == 0"
#endif /* DEBUG */
