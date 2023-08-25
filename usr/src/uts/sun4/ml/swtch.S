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
 * Copyright (c) 1993, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Process switching routines.
 */

#include "assym.h"

#include <sys/param.h>
#include <sys/asm_linkage.h>
#include <sys/mmu.h>
#include <sys/pcb.h>
#include <sys/machthread.h>
#include <sys/machclock.h>
#include <sys/privregs.h>
#include <sys/vtrace.h>
#include <vm/hat_sfmmu.h>

/*
 * resume(kthread_id_t)
 *
 * a thread can only run on one processor at a time. there
 * exists a window on MPs where the current thread on one
 * processor is capable of being dispatched by another processor.
 * some overlap between outgoing and incoming threads can happen
 * when they are the same thread. in this case where the threads
 * are the same, resume() on one processor will spin on the incoming
 * thread until resume() on the other processor has finished with
 * the outgoing thread.
 *
 * The MMU context changes when the resuming thread resides in a different
 * process.  Kernel threads are known by resume to reside in process 0.
 * The MMU context, therefore, only changes when resuming a thread in
 * a process different from curproc.
 *
 * resume_from_intr() is called when the thread being resumed was not
 * passivated by resume (e.g. was interrupted).  This means that the
 * resume lock is already held and that a restore context is not needed.
 * Also, the MMU context is not changed on the resume in this case.
 *
 * resume_from_zombie() is the same as resume except the calling thread
 * is a zombie and must be put on the deathrow list after the CPU is
 * off the stack.
 */

	ENTRY(resume)
	save	%sp, -SA(MINFRAME), %sp		! save ins and locals

	call	__dtrace_probe___sched_off__cpu	! DTrace probe
	mov	%i0, %o0			! arg for DTrace probe

	membar	#Sync				! flush writebuffers
	flushw					! flushes all but this window

	stn	%i7, [THREAD_REG + T_PC]	! save return address
	stn	%fp, [THREAD_REG + T_SP]	! save sp

	!
	! Save GSR (Graphics Status Register).
	!
	! Read fprs, call fp_save if FPRS_FEF set.
	! This handles floating-point state saving.
	! The fprs could be turned on by hw bcopy software,
	! *or* by fp_disabled. Handle it either way.
	!
	ldn	[THREAD_REG + T_LWP], %o4	! get lwp pointer
	rd	%fprs, %g4			! read fprs
	brnz,pt	%o4, 0f				! if user thread skip
	  ldn	[THREAD_REG + T_CPU], %i1	! get CPU pointer

	!
	! kernel thread
	!
	! we save fprs at the beginning the stack so we know
	! where to check at resume time
	ldn	[THREAD_REG + T_STACK], %i2
	ldn	[THREAD_REG + T_CTX], %g3	! get ctx pointer
	andcc	%g4, FPRS_FEF, %g0		! is FPRS_FEF set
	bz,pt	%icc, 1f			! nope, skip
	  st	%g4, [%i2 + SA(MINFRAME) + FPU_FPRS]	! save fprs

	! save kernel fp state in stack
	add	%i2, SA(MINFRAME), %o0		! o0 = kfpu_t ptr
	rd	%gsr, %g5
	call	fp_save
	stx	%g5, [%o0 + FPU_GSR]		! store GSR
	ba,a,pt	%icc, 1f
	  nop

0:
	! user thread
	! o4 = lwp ptr
	! g4 = fprs
	! i1 = CPU ptr
	ldn	[%o4 + LWP_FPU], %o0		! fp pointer
	stn	%fp, [THREAD_REG + T_SP]	! save sp
	andcc	%g4, FPRS_FEF, %g0		! is FPRS_FEF set
	st	%g4, [%o0 + FPU_FPRS]		! store FPRS
#if defined(DEBUG) || defined(NEED_FPU_EXISTS)
	sethi	%hi(fpu_exists), %g5
	ld	[%g5 + %lo(fpu_exists)], %g5
	brz,pn	%g5, 1f
	  ldn	[THREAD_REG + T_CTX], %g3	! get ctx pointer
#endif
	bz,pt	%icc, 1f			! most apps don't use fp
	  ldn	[THREAD_REG + T_CTX], %g3	! get ctx pointer
	ldn	[%o4 + LWP_FPU], %o0		! fp pointer
	rd	%gsr, %g5
	call	fp_save				! doesn't touch globals
	stx	%g5, [%o0 + FPU_GSR]		! store GSR
1:
	!
	! Perform context switch callback if set.
	! This handles coprocessor state saving.
	! i1 = cpu ptr
	! g3 = ctx pointer
	!
	wr	%g0, %g0, %fprs			! disable fpu and clear fprs
	brz,pt	%g3, 2f				! skip call when zero
	ldn	[%i0 + T_PROCP], %i3		! delay slot - get proc pointer
	call	savectx
	mov	THREAD_REG, %o0			! delay - arg = thread pointer
2:
	ldn	[THREAD_REG + T_PROCP], %i2	! load old curproc - for mmu

	!
	! Temporarily switch to idle thread's stack
	!
	ldn	[%i1 + CPU_IDLE_THREAD], %o0	! idle thread pointer
	ldn	[%o0 + T_SP], %o1		! get onto idle thread stack
	sub	%o1, SA(MINFRAME), %sp		! save room for ins and locals
	clr	%fp

	!
	! Set the idle thread as the current thread
	!
	mov	THREAD_REG, %l3			! save %g7 (current thread)
	mov	%o0, THREAD_REG			! set %g7 to idle
	stn	%o0, [%i1 + CPU_THREAD]		! set CPU's thread to idle

	!
	! Clear and unlock previous thread's t_lock
	! to allow it to be dispatched by another processor.
	!
	clrb	[%l3 + T_LOCK]			! clear tp->t_lock

	!
	! IMPORTANT: Registers at this point must be:
	!	%i0 = new thread
	!	%i1 = cpu pointer
	!	%i2 = old proc pointer
	!	%i3 = new proc pointer
	!
	! Here we are in the idle thread, have dropped the old thread.
	!
	ALTENTRY(_resume_from_idle)

	! SET_KCONTEXTREG(reg0, reg1, reg2, reg3, reg4, label1, label2, label3)
	SET_KCONTEXTREG(%o0, %g1, %g2, %g3, %o3, l1, l2, l3)

	cmp 	%i2, %i3		! resuming the same process?
	be,pt	%xcc, 5f		! yes.
	  nop

	ldx	[%i3 + P_AS], %o0	! load p->p_as
	ldx	[%o0 + A_HAT], %i5	! %i5 = new proc hat

	!
	! update cpusran field
	!
	ld	[%i1 + CPU_ID], %o4
	add	%i5, SFMMU_CPUSRAN, %o5
	CPU_INDEXTOSET(%o5, %o4, %g1)
	ldx	[%o5], %o2		! %o2 = cpusran field
	mov	1, %g2
	sllx	%g2, %o4, %o4		! %o4 = bit for this cpu
	andcc	%o4, %o2, %g0
	bnz,pn	%xcc, 0f		! bit already set, go to 0
	  nop
3:
	or	%o2, %o4, %o1		! or in this cpu's bit mask
	casx	[%o5], %o2, %o1
	cmp	%o2, %o1
	bne,a,pn %xcc, 3b
	  ldx	[%o5], %o2		! o2 = cpusran field
	membar	#LoadLoad|#StoreLoad

0:
	!
	! disable interrupts
	!
	! if resume from user to kernel thread
	!	call sfmmu_setctx_sec
	! if resume from kernel (or a different user) thread to user thread
	!	call sfmmu_alloc_ctx
	! sfmmu_load_mmustate
	!
	! enable interrupts
	!
	! %i5 = new proc hat
	!

	sethi	%hi(ksfmmup), %o2
        ldx	[%o2 + %lo(ksfmmup)], %o2

	rdpr	%pstate, %i4
        cmp	%i5, %o2		! new proc hat == ksfmmup ?
	bne,pt	%xcc, 3f		! new proc is not kernel as, go to 3
	  wrpr	%i4, PSTATE_IE, %pstate

	SET_KAS_CTXSEC_ARGS(%i5, %o0, %o1)

	! new proc is kernel as

	call	sfmmu_setctx_sec		! switch to kernel context
	  or	%o0, %o1, %o0

	ba,a,pt	%icc, 4f

	!
	! Switch to user address space.
	!
3:
	mov	%i5, %o0			! %o0 = sfmmup
	mov	%i1, %o2			! %o2 = CPU
	set	SFMMU_PRIVATE, %o3		! %o3 = sfmmu private flag
	call	sfmmu_alloc_ctx
	  mov	%g0, %o1			! %o1 = allocate flag = 0

	brz,a,pt %o0, 4f			! %o0 == 0, no private alloc'ed
          nop

        ldn     [%i5 + SFMMU_SCDP], %o0         ! using shared contexts?
        brz,a,pt %o0, 4f
          nop

	ldn   [%o0 + SCD_SFMMUP], %o0		! %o0 = scdp->scd_sfmmup
	mov	%i1, %o2			! %o2 = CPU
	set	SFMMU_SHARED, %o3		! %o3 = sfmmu shared flag
	call	sfmmu_alloc_ctx
	  mov	1, %o1				! %o1 = allocate flag = 1

4:
	call	sfmmu_load_mmustate		! program MMU registers
	  mov	%i5, %o0

	wrpr    %g0, %i4, %pstate               ! enable interrupts

5:
	!
	! spin until dispatched thread's mutex has
	! been unlocked. this mutex is unlocked when
	! it becomes safe for the thread to run.
	!
	ldstub	[%i0 + T_LOCK], %o0	! lock curthread's t_lock
6:
	brnz,pn	%o0, 7f			! lock failed
	  ldx	[%i0 + T_PC], %i7	! delay - restore resuming thread's pc

	!
	! Fix CPU structure to indicate new running thread.
	! Set pointer in new thread to the CPU structure.
	! XXX - Move migration statistic out of here
	!
        ldx	[%i0 + T_CPU], %g2	! last CPU to run the new thread
        cmp     %g2, %i1		! test for migration
        be,pt	%xcc, 4f		! no migration
          ldn	[%i0 + T_LWP], %o1	! delay - get associated lwp (if any)
        ldx	[%i1 + CPU_STATS_SYS_CPUMIGRATE], %g2
        inc     %g2
        stx	%g2, [%i1 + CPU_STATS_SYS_CPUMIGRATE]
	stx	%i1, [%i0 + T_CPU]	! set new thread's CPU pointer
4:
	stx	%i0, [%i1 + CPU_THREAD]	! set CPU's thread pointer
	membar	#StoreLoad		! synchronize with mutex_exit()
	mov	%i0, THREAD_REG		! update global thread register
	stx	%o1, [%i1 + CPU_LWP]	! set CPU's lwp ptr
	brz,a,pn %o1, 1f		! if no lwp, branch and clr mpcb
	  stx	%g0, [%i1 + CPU_MPCB]
	!
	! user thread
	! o1 = lwp
	! i0 = new thread
	!
	ldx	[%i0 + T_STACK], %o0
	stx	%o0, [%i1 + CPU_MPCB]	! set CPU's mpcb pointer
#ifdef CPU_MPCB_PA
	ldx	[%o0 + MPCB_PA], %o0
	stx	%o0, [%i1 + CPU_MPCB_PA]
#endif
	! Switch to new thread's stack
	ldx	[%i0 + T_SP], %o0	! restore resuming thread's sp
	sub	%o0, SA(MINFRAME), %sp	! in case of intr or trap before restore
	mov	%o0, %fp
	!
	! Restore resuming thread's GSR reg and floating-point regs
	! Note that the ld to the gsr register ensures that the loading of
	! the floating point saved state has completed without necessity
	! of a membar #Sync.
	!
#if defined(DEBUG) || defined(NEED_FPU_EXISTS)
	sethi	%hi(fpu_exists), %g3
	ld	[%g3 + %lo(fpu_exists)], %g3
	brz,pn	%g3, 2f
	  ldx	[%i0 + T_CTX], %i5	! should resumed thread restorectx?
#endif
	ldx	[%o1 + LWP_FPU], %o0		! fp pointer
	ld	[%o0 + FPU_FPRS], %g5		! get fpu_fprs
	andcc	%g5, FPRS_FEF, %g0		! is FPRS_FEF set?
	bz,a,pt	%icc, 9f			! no, skip fp_restore
	  wr	%g0, FPRS_FEF, %fprs		! enable fprs so fp_zero works

	ldx	[THREAD_REG + T_CPU], %o4	! cpu pointer
	call	fp_restore
	  wr	%g5, %g0, %fprs			! enable fpu and restore fprs

	ldx	[%o0 + FPU_GSR], %g5		! load saved GSR data
	wr	%g5, %g0, %gsr			! restore %gsr data
	ba,pt	%icc,2f
	  ldx	[%i0 + T_CTX], %i5	! should resumed thread restorectx?

9:
	!
	! Zero resuming thread's fp registers, for *all* non-fp program
	! Remove all possibility of using the fp regs as a "covert channel".
	!
	call	fp_zero
	  wr	%g0, %g0, %gsr
	ldx	[%i0 + T_CTX], %i5	! should resumed thread restorectx?
	ba,pt	%icc, 2f
	  wr	%g0, %g0, %fprs			! disable fprs

1:
#ifdef CPU_MPCB_PA
	mov	-1, %o1
	stx	%o1, [%i1 + CPU_MPCB_PA]
#endif
	!
	! kernel thread
	! i0 = new thread
	!
	! Switch to new thread's stack
	!
	ldx	[%i0 + T_SP], %o0	! restore resuming thread's sp
	sub	%o0, SA(MINFRAME), %sp	! in case of intr or trap before restore
	mov	%o0, %fp
	!
	! Restore resuming thread's GSR reg and floating-point regs
	! Note that the ld to the gsr register ensures that the loading of
	! the floating point saved state has completed without necessity
	! of a membar #Sync.
	!
	ldx	[%i0 + T_STACK], %o0
	ld	[%o0 + SA(MINFRAME) + FPU_FPRS], %g5	! load fprs
	ldx	[%i0 + T_CTX], %i5		! should thread restorectx?
	andcc	%g5, FPRS_FEF, %g0		! did we save fp in stack?
	bz,a,pt	%icc, 2f
	  wr	%g0, %g0, %fprs			! clr fprs

	wr	%g5, %g0, %fprs			! enable fpu and restore fprs
	call	fp_restore
	add	%o0, SA(MINFRAME), %o0		! o0 = kpu_t ptr
	ldx	[%o0 + FPU_GSR], %g5		! load saved GSR data
	wr	%g5, %g0, %gsr			! restore %gsr data

2:
	!
	! Restore resuming thread's context
	! i5 = ctx ptr
	!
	brz,a,pt %i5, 8f		! skip restorectx() when zero
	  ld	[%i1 + CPU_BASE_SPL], %o0
	call	restorectx		! thread can not sleep on temp stack
	  mov	THREAD_REG, %o0		! delay slot - arg = thread pointer
	!
	! Set priority as low as possible, blocking all interrupt threads
	! that may be active.
	!
	ld	[%i1 + CPU_BASE_SPL], %o0
8:
	wrpr	%o0, 0, %pil
	wrpr	%g0, WSTATE_KERN, %wstate
	!
	! If we are resuming an interrupt thread, store a starting timestamp
	! in the thread structure.
	!
	lduh	[THREAD_REG + T_FLAGS], %o0
	andcc	%o0, T_INTR_THREAD, %g0
	bnz,pn	%xcc, 0f
	  nop
5:
	call	__dtrace_probe___sched_on__cpu	! DTrace probe
	nop

	ret				! resume curthread
	restore
0:
	add	THREAD_REG, T_INTR_START, %o2
1:
	ldx	[%o2], %o1
	RD_CLOCK_TICK(%o0,%o3,%g5,__LINE__)
	casx	[%o2], %o1, %o0
	cmp	%o0, %o1
	be,pt	%xcc, 5b
	  nop
	! If an interrupt occurred while we were attempting to store
	! the timestamp, try again.
	ba,pt	%xcc, 1b
	  nop

	!
	! lock failed - spin with regular load to avoid cache-thrashing.
	!
7:
	brnz,a,pt %o0, 7b		! spin while locked
	  ldub	[%i0 + T_LOCK], %o0
	ba	%xcc, 6b
	  ldstub  [%i0 + T_LOCK], %o0	! delay - lock curthread's mutex
	SET_SIZE(_resume_from_idle)
	SET_SIZE(resume)

	ENTRY(resume_from_zombie)
	save	%sp, -SA(MINFRAME), %sp		! save ins and locals

	call	__dtrace_probe___sched_off__cpu	! DTrace probe
	mov	%i0, %o0			! arg for DTrace probe

	ldn	[THREAD_REG + T_CPU], %i1	! cpu pointer

	flushw					! flushes all but this window
	ldn	[THREAD_REG + T_PROCP], %i2	! old procp for mmu ctx

	!
	! Temporarily switch to the idle thread's stack so that
	! the zombie thread's stack can be reclaimed by the reaper.
	!
	ldn	[%i1 + CPU_IDLE_THREAD], %o2	! idle thread pointer
	ldn	[%o2 + T_SP], %o1		! get onto idle thread stack
	sub	%o1, SA(MINFRAME), %sp		! save room for ins and locals
	clr	%fp
	!
	! Set the idle thread as the current thread.
	! Put the zombie on death-row.
	!
	mov	THREAD_REG, %o0			! save %g7 = curthread for arg
	mov	%o2, THREAD_REG			! set %g7 to idle
	stn	%g0, [%i1 + CPU_MPCB]		! clear mpcb
#ifdef CPU_MPCB_PA
	mov	-1, %o1
	stx	%o1, [%i1 + CPU_MPCB_PA]
#endif
	call	reapq_add			! reapq_add(old_thread);
	stn	%o2, [%i1 + CPU_THREAD]		! delay - CPU's thread = idle

	!
	! resume_from_idle args:
	!	%i0 = new thread
	!	%i1 = cpu
	!	%i2 = old proc
	!	%i3 = new proc
	!
	b	_resume_from_idle		! finish job of resume
	ldn	[%i0 + T_PROCP], %i3		! new process
	SET_SIZE(resume_from_zombie)

	ENTRY(resume_from_intr)
	save	%sp, -SA(MINFRAME), %sp		! save ins and locals

	!
	! We read in the fprs and call fp_save if FPRS_FEF is set
	! to save the floating-point state if fprs has been
	! modified by operations such as hw bcopy or fp_disabled.
	! This is to resolve an issue where an interrupting thread
	! doesn't retain their floating-point registers when
	! switching out of the interrupt context.
	!
	rd	%fprs, %g4
	ldn	[THREAD_REG + T_STACK], %i2
	andcc	%g4, FPRS_FEF, %g0		! is FPRS_FEF set
	bz,pt	%icc, 4f
	  st	%g4, [%i2 + SA(MINFRAME) + FPU_FPRS]	! save fprs

	! save kernel fp state in stack
	add	%i2, SA(MINFRAME), %o0		! %o0 = kfpu_t ptr
	rd	%gsr, %g5
	call fp_save
	stx	%g5, [%o0 + FPU_GSR]		! store GSR

4:

	flushw					! flushes all but this window
	stn	%fp, [THREAD_REG + T_SP]	! delay - save sp
	stn	%i7, [THREAD_REG + T_PC]	! save return address

	ldn	[%i0 + T_PC], %i7		! restore resuming thread's pc
	ldn	[THREAD_REG + T_CPU], %i1	! cpu pointer

	!
	! Fix CPU structure to indicate new running thread.
	! The pinned thread we're resuming already has the CPU pointer set.
	!
	mov	THREAD_REG, %l3		! save old thread
	stn	%i0, [%i1 + CPU_THREAD]	! set CPU's thread pointer
	membar	#StoreLoad		! synchronize with mutex_exit()
	mov	%i0, THREAD_REG		! update global thread register

	!
	! Switch to new thread's stack
	!
	ldn	[THREAD_REG + T_SP], %o0	! restore resuming thread's sp
	sub	%o0, SA(MINFRAME), %sp ! in case of intr or trap before restore
	mov	%o0, %fp
	clrb	[%l3 + T_LOCK]		! clear intr thread's tp->t_lock

	!
	! If we are resuming an interrupt thread, store a timestamp in the
	! thread structure.
	!
	lduh	[THREAD_REG + T_FLAGS], %o0
	andcc	%o0, T_INTR_THREAD, %g0
	bnz,pn	%xcc, 0f
	!
	! We're resuming a non-interrupt thread.
	! Clear CPU_INTRCNT and check if cpu_kprunrun set?
	!
	ldub	[%i1 + CPU_KPRUNRUN], %o5	! delay
	brnz,pn	%o5, 3f				! call kpreempt(KPREEMPT_SYNC);
	stub	%g0, [%i1 + CPU_INTRCNT]
1:
	ret				! resume curthread
	restore
0:
	!
	! We're an interrupt thread. Update t_intr_start and cpu_intrcnt
	!
	add	THREAD_REG, T_INTR_START, %o2
2:
	ldx	[%o2], %o1
	RD_CLOCK_TICK(%o0,%o3,%l1,__LINE__)
	casx	[%o2], %o1, %o0
	cmp	%o0, %o1
	bne,pn	%xcc, 2b
	ldn	[THREAD_REG + T_INTR], %l1	! delay
	! Reset cpu_intrcnt if we aren't pinning anyone
	brz,a,pt %l1, 2f
	stub	%g0, [%i1 + CPU_INTRCNT]
2:
	ba,pt	%xcc, 1b
	nop
3:
	!
	! We're a non-interrupt thread and cpu_kprunrun is set. call kpreempt.
	!
	call	kpreempt
	mov	KPREEMPT_SYNC, %o0
	ba,pt	%xcc, 1b
	nop
	SET_SIZE(resume_from_intr)


/*
 * thread_start()
 *
 * the current register window was crafted by thread_run() to contain
 * an address of a procedure (in register %i7), and its args in registers
 * %i0 through %i5. a stack trace of this thread will show the procedure
 * that thread_start() invoked at the bottom of the stack. an exit routine
 * is stored in %l0 and called when started thread returns from its called
 * procedure.
 */

	ENTRY(thread_start)
	mov	%i0, %o0
	jmpl 	%i7, %o7	! call thread_run()'s start() procedure.
	mov	%i1, %o1

	call	thread_exit	! destroy thread if it returns.
	nop
	unimp 0
	SET_SIZE(thread_start)
