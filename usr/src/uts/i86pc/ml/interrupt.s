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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved					*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation		*/
/*	  All Rights Reserved					*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/psw.h>
#include <sys/x86_archext.h>

#if defined(__lint)

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/systm.h>

#else   /* __lint */

#include <sys/segments.h>
#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/traptrace.h>
#include <sys/clock.h>
#include <sys/panic.h>
#include "assym.h"

_ftrace_intr_thread_fmt:
	.string	"intr_thread(): regs=0x%lx, int=0x%x, pil=0x%x"

#endif	/* lint */

#if defined(__i386)

#if defined(__lint)

void
patch_tsc(void)
{}

#else	/* __lint */

/*
 * To cope with processors that do not implement the rdtsc instruction,
 * we patch the kernel to use rdtsc if that feature is detected on the CPU.
 * On an unpatched kernel, all locations requiring rdtsc are nop's.
 *
 * This function patches the nop's to rdtsc.
 */
	ENTRY_NP(patch_tsc)
	movw	_rdtsc_insn, %cx
	movw	%cx, _tsc_patch1
	movw	%cx, _tsc_patch2
	movw	%cx, _tsc_patch3
	movw	%cx, _tsc_patch4
	movw	%cx, _tsc_patch5
	movw	%cx, _tsc_patch6
	movw	%cx, _tsc_patch7
	movw	%cx, _tsc_patch8
	movw	%cx, _tsc_patch9
	movw	%cx, _tsc_patch10
	movw	%cx, _tsc_patch11
	movw	%cx, _tsc_patch12
	movw	%cx, _tsc_patch13
	movw	%cx, _tsc_patch14
	movw	%cx, _tsc_patch15
	movw	%cx, _tsc_patch16
	movw	%cx, _tsc_patch17
	ret
_rdtsc_insn:
	rdtsc
	SET_SIZE(patch_tsc)

#endif	/* __lint */

#endif	/* __i386 */


#if defined(__lint)

void
_interrupt(void)
{}

#else	/* __lint */

#if defined(__amd64)

	/*
	 * Common register usage:
	 *
	 * %rbx		cpu pointer
	 * %r12		trap trace pointer -and- stash of
	 *		vec across intr_thread dispatch.
	 * %r13d	ipl of isr
	 * %r14d	old ipl (ipl level we entered on)
	 * %r15		interrupted thread stack pointer
	 */
	ENTRY_NP2(cmnint, _interrupt)

	INTR_PUSH

	/*
	 * At the end of TRACE_PTR %r12 points to the current TRAPTRACE entry
	 */
	TRACE_PTR(%r12, %rax, %eax, %rdx, $TT_INTERRUPT)
						/* Uses labels 8 and 9 */
	TRACE_REGS(%r12, %rsp, %rax, %rbx)	/* Uses label 9 */
	TRACE_STAMP(%r12)		/* Clobbers %eax, %edx, uses 9 */

	DISABLE_INTR_FLAGS		/* (and set kernel flag values) */

	movq	%rsp, %rbp

	TRACE_STACK(%r12)

	LOADCPU(%rbx)				/* &cpu */
	leaq	REGOFF_TRAPNO(%rbp), %rsi	/* &vector */
	movl	CPU_PRI(%rbx), %r14d		/* old ipl */
	movl	CPU_SOFTINFO(%rbx), %edx

#ifdef TRAPTRACE
	movl	$255, TTR_IPL(%r12)
	movl	%r14d, %edi
	movb	%dil, TTR_PRI(%r12)
	movl	CPU_BASE_SPL(%rbx), %edi
	movb	%dil, TTR_SPL(%r12)
	movb	$255, TTR_VECTOR(%r12)
#endif

	/*
	 * Check to see if the trap number is T_SOFTINT; if it is,
	 * jump straight to dosoftint now.
	 */
	cmpq	$T_SOFTINT, (%rsi)
	je	dosoftint

	/*
	 * Raise the interrupt priority level, returns newpil.
	 * (The vector address is in %rsi so setlvl can update it.)
	 */
	movl	%r14d, %edi			/* old ipl */
						/* &vector */
	call	*setlvl(%rip)
	
#ifdef TRAPTRACE
	movb	%al, TTR_IPL(%r12)
#endif
	/*
	 * check for spurious interrupt
	 */
	cmpl	$-1, %eax
	je	_sys_rtt

#ifdef TRAPTRACE
	movl	%r14d, %edx
	movb	%dl, TTR_PRI(%r12)
	movl	CPU_BASE_SPL(%rbx), %edx
	movb	%dl, TTR_SPL(%r12)
#endif
	movl	%eax, CPU_PRI(%rbx)		/* update ipl */

#ifdef TRAPTRACE
	movl	REGOFF_TRAPNO(%rbp), %edx
	movb	%dl, TTR_VECTOR(%r12)
#endif
	movl	%eax, %r13d			/* ipl of isr */

	/*
	 * At this point we can take one of two paths.
	 * If the new level is at or below lock level, we will
	 * run this interrupt in a separate thread.
	 */
	cmpl	$LOCK_LEVEL, %eax
	jbe	intr_thread

	movq	%rbx, %rdi		/* &cpu */
	movl	%r13d, %esi		/* ipl */
	movl	%r14d, %edx		/* old ipl */
	movq	%rbp, %rcx		/* &regs */
	call	hilevel_intr_prolog
	orl	%eax, %eax		/* zero if need to switch stack */
	jnz	1f

	/*
	 * Save the thread stack and get on the cpu's interrupt stack
	 */
	movq	%rsp, %r15
	movq	CPU_INTR_STACK(%rbx), %rsp
1:

	sti

	/*
	 * Walk the list of handlers for this vector, calling
	 * them as we go until no more interrupts are claimed.
	 */
	movl	REGOFF_TRAPNO(%rbp), %edi
	call	av_dispatch_autovect

	cli

	movq	%rbx, %rdi			/* &cpu */
	movl	%r13d, %esi			/* ipl */
	movl	%r14d, %edx			/* oldipl */
	movl	REGOFF_TRAPNO(%rbp), %ecx	/* vec */	
	call	hilevel_intr_epilog
	orl	%eax, %eax		/* zero if need to switch stack */
	jnz	2f
	movq	%r15, %rsp
2:	/*
	 * Check for, and execute, softints before we iret.
	 *
	 * (dosoftint expects oldipl in %r14d (which is where it is)
	 * the cpu pointer in %rbx (which is where it is) and the
	 * softinfo in %edx (which is where we'll put it right now))
	 */
	movl	CPU_SOFTINFO(%rbx), %edx
	orl	%edx, %edx
	jz	_sys_rtt
	jmp	dosoftint
	/*NOTREACHED*/

	SET_SIZE(cmnint)
	SET_SIZE(_interrupt)

/*
 * Handle an interrupt in a new thread
 *
 * As we branch here, interrupts are still masked,
 * %rbx still contains the cpu pointer,
 * %r14d contains the old ipl that we came in on, and
 * %eax contains the new ipl that we got from the setlvl routine
 */

	ENTRY_NP(intr_thread)

	movq	%rbx, %rdi	/* &cpu */
	movq	%rbp, %rsi	/* &regs = stack pointer for _sys_rtt */
	movl	REGOFF_TRAPNO(%rbp), %r12d	/* stash the vec */
	movl	%eax, %edx	/* new pil from setlvlx() */
	call	intr_thread_prolog
	movq	%rsp, %r15
	movq	%rax, %rsp	/* t_stk from interrupt thread */
	movq	%rsp, %rbp

	sti

	testl	$FTRACE_ENABLED, CPU_FTRACE_STATE(%rbx)
	jz	1f
	/*
	 * ftracing support. do we need this on x86?
	 */
	leaq	_ftrace_intr_thread_fmt(%rip), %rdi
	movq	%rbp, %rsi			/* &regs */
	movl	%r12d, %edx			/* vec */
	movq	CPU_THREAD(%rbx), %r11		/* (the interrupt thread) */
	movzbl	T_PIL(%r11), %ecx		/* newipl */
	call	ftrace_3_notick
1:
	movl	%r12d, %edi			/* vec */
	call	av_dispatch_autovect

	cli

	movq	%rbx, %rdi			/* &cpu */
	movl	%r12d, %esi			/* vec */
	movl	%r14d, %edx			/* oldpil */
	call	intr_thread_epilog
	/*
	 * If we return from here (we might not if the interrupted thread
	 * has exited or blocked, in which case we'll have quietly swtch()ed
	 * away) then we need to switch back to our old %rsp
	 */
	movq	%r15, %rsp
	movq	%rsp, %rbp
	/*
	 * Check for, and execute, softints before we iret.
	 *
	 * (dosoftint expects oldpil in %r14d, the cpu pointer in %rbx and
	 * the mcpu_softinfo.st_pending field in %edx.
	 */
	movl	CPU_SOFTINFO(%rbx), %edx
	orl	%edx, %edx
	jz	_sys_rtt
	/*FALLTHROUGH*/

/*
 * Process soft interrupts.
 * Interrupts are masked, and we have a minimal frame on the stack.
 * %edx should contain the mcpu_softinfo.st_pending field
 */

	ALTENTRY(dosoftint)

	movq	%rbx, %rdi	/* &cpu */
	movq	%rbp, %rsi	/* &regs = stack pointer for _sys_rtt */
				/* cpu->cpu_m.mcpu_softinfo.st_pending */
	movl	%r14d, %ecx	/* oldipl */
	call	dosoftint_prolog
	/*
	 * dosoftint_prolog() usually returns a stack pointer for the
	 * interrupt thread that we must switch to.  However, if the
	 * returned stack pointer is NULL, then the software interrupt was
	 * too low in priority to run now; we'll catch it another time.
	 */
	orq	%rax, %rax
	jz	_sys_rtt
	movq	%rsp, %r15
	movq	%rax, %rsp	/* t_stk from interrupt thread */
	movq	%rsp, %rbp

	sti

	/*
	 * Enabling interrupts (above) could raise the current ipl
	 * and base spl.  But, we continue processing the current soft
	 * interrupt and we will check the base spl next time around
	 * so that blocked interrupt threads get a chance to run.
	 */
	movq	CPU_THREAD(%rbx), %r11	/* now an interrupt thread */
	movzbl	T_PIL(%r11), %edi
	call	av_dispatch_softvect

	cli

	movq	%rbx, %rdi		/* &cpu */
	movl	%r14d, %esi		/* oldpil */
	call	dosoftint_epilog
	movq	%r15, %rsp		/* back on old stack pointer */
	movq	%rsp, %rbp
	movl	CPU_SOFTINFO(%rbx), %edx
	orl	%edx, %edx
	jz	_sys_rtt
	jmp	dosoftint

	SET_SIZE(dosoftint)
	SET_SIZE(intr_thread)

#elif defined(__i386)

/*
 * One day, this should just invoke the C routines that know how to
 * do all the interrupt bookkeeping.  In the meantime, try
 * and make the assembler a little more comprehensible.
 */

#define	INC64(basereg, offset)			\
	addl	$1, offset(basereg);		\
	adcl	$0, offset + 4(basereg)

#define	TSC_CLR(basereg, offset)		\
	movl	$0, offset(basereg);		\
	movl	$0, offset + 4(basereg)

/*
 * The following macros assume the time value is in %edx:%eax
 * e.g. from a rdtsc instruction.
 */
#define	TSC_STORE(reg, offset)		\
	movl	%eax, offset(reg);	\
	movl	%edx, offset + 4(reg)

#define	TSC_LOAD(reg, offset)	\
	movl	offset(reg), %eax;	\
	movl	offset + 4(reg), %edx

#define	TSC_ADD_TO(reg, offset)		\
	addl	%eax, offset(reg);	\
	adcl	%edx, offset + 4(reg)

#define	TSC_SUB_FROM(reg, offset)	\
	subl	offset(reg), %eax;	\
	sbbl	offset + 4(reg), %edx	/* interval in edx:eax */

/*
 * basereg   - pointer to cpu struct
 * pilreg    - pil or converted pil (pil - (LOCK_LEVEL + 1))
 *
 * Returns (base + pil * 8) in pilreg
 */
#define	PILBASE(basereg, pilreg)	\
	lea	(basereg, pilreg, 8), pilreg

/*
 * Returns (base + (pil - (LOCK_LEVEL + 1)) * 8) in pilreg
 */
#define	HIGHPILBASE(basereg, pilreg)		\
	subl	$LOCK_LEVEL + 1, pilreg;	\
	PILBASE(basereg, pilreg)

/*
 * Returns (base + pil * 16) in pilreg
 */
#define	PILBASE_INTRSTAT(basereg, pilreg)	\
	shl	$4, pilreg;			\
	addl	basereg, pilreg;

/*
 * Returns (cpu + cpu_mstate * 8) in tgt
 */
#define	INTRACCTBASE(cpureg, tgtreg)		\
	movzwl	CPU_MSTATE(cpureg), tgtreg;	\
	lea	(cpureg, tgtreg, 8), tgtreg

/*
 * cpu_stats.sys.intr[PIL]++
 */
#define	INC_CPU_STATS_INTR(pilreg, tmpreg, tmpreg_32, basereg)	\
	movl	pilreg, tmpreg_32;				\
	PILBASE(basereg, tmpreg);				\
	INC64(tmpreg, _CONST(CPU_STATS_SYS_INTR - 8))

/*
 * Unlink thread from CPU's list
 */
#define	UNLINK_INTR_THREAD(cpureg, ithread, tmpreg)	\
	mov	CPU_INTR_THREAD(cpureg), ithread;	\
	mov	T_LINK(ithread), tmpreg;		\
	mov	tmpreg, CPU_INTR_THREAD(cpureg)

/*
 * Link a thread into CPU's list
 */
#define	LINK_INTR_THREAD(cpureg, ithread, tmpreg)	\
	mov	CPU_INTR_THREAD(cpureg), tmpreg;	\
	mov	tmpreg, T_LINK(ithread);		\
	mov	ithread, CPU_INTR_THREAD(cpureg)

#if defined(DEBUG)

/*
 * Do not call panic, if panic is already in progress.
 */
#define	__PANIC(msg, label)		\
	cmpl	$0, panic_quiesce;		\
	jne	label;				\
	pushl	$msg;				\
	call	panic

#define	__CMP64_JNE(basereg, offset, label)	\
	cmpl	$0, offset(basereg);		\
	jne	label;				\
	cmpl	$0, offset + 4(basereg);	\
	jne	label

/*
 * ASSERT(!(CPU->cpu_intr_actv & (1 << PIL)))
 */
#define	ASSERT_NOT_CPU_INTR_ACTV(pilreg, basereg, msg)	\
	btl	pilreg, CPU_INTR_ACTV(basereg);		\
	jnc	4f;					\
	__PANIC(msg, 4f);				\
4:

/*
 * ASSERT(CPU->cpu_intr_actv & (1 << PIL))
 */
#define	ASSERT_CPU_INTR_ACTV(pilreg, basereg, msg)	\
	btl	pilreg, CPU_INTR_ACTV(basereg);		\
	jc	5f;					\
	__PANIC(msg, 5f);				\
5:

/*
 * ASSERT(CPU->cpu_pil_high_start != 0)
 */
#define	ASSERT_CPU_PIL_HIGH_START_NZ(basereg)			\
	__CMP64_JNE(basereg, CPU_PIL_HIGH_START, 6f);		\
	__PANIC(_interrupt_timestamp_zero, 6f);		\
6:

/*
 * ASSERT(t->t_intr_start != 0)
 */
#define	ASSERT_T_INTR_START_NZ(basereg)				\
	__CMP64_JNE(basereg, T_INTR_START, 7f);			\
	__PANIC(_intr_thread_t_intr_start_zero, 7f);	\
7:

_interrupt_actv_bit_set:
	.string	"_interrupt(): cpu_intr_actv bit already set for PIL"
_interrupt_actv_bit_not_set:
	.string	"_interrupt(): cpu_intr_actv bit not set for PIL"
_interrupt_timestamp_zero:
	.string "_interrupt(): timestamp zero upon handler return"
_intr_thread_actv_bit_not_set:
	.string	"intr_thread():	cpu_intr_actv bit not set for PIL"
_intr_thread_t_intr_start_zero:
	.string	"intr_thread():	t_intr_start zero upon handler return"
_dosoftint_actv_bit_set:
	.string	"dosoftint(): cpu_intr_actv bit already set for PIL"
_dosoftint_actv_bit_not_set:
	.string	"dosoftint(): cpu_intr_actv bit not set for PIL"

	DGDEF(intr_thread_cnt)
	.4byte	0

#else
#define	ASSERT_NOT_CPU_INTR_ACTV(pilreg, basereg, msg)
#define	ASSERT_CPU_INTR_ACTV(pilreg, basereg, msg)
#define	ASSERT_CPU_PIL_HIGH_START_NZ(basereg)
#define	ASSERT_T_INTR_START_NZ(basereg)
#endif

	ENTRY_NP2(cmnint, _interrupt)

	INTR_PUSH

	/*
	 * At the end of TRACE_PTR %esi points to the current TRAPTRACE entry
	 */
	TRACE_PTR(%esi, %eax, %eax, %edx, $TT_INTERRUPT)
						/* Uses labels 8 and 9 */
	TRACE_REGS(%esi, %esp, %eax, %ebx)	/* Uses label 9 */
	TRACE_STAMP(%esi)		/* Clobbers %eax, %edx, uses 9 */

	movl	%esp, %ebp
	DISABLE_INTR_FLAGS
	LOADCPU(%ebx)		/* get pointer to CPU struct. Avoid gs refs */
	leal    REGOFF_TRAPNO(%ebp), %ecx	/* get address of vector */
	movl	CPU_PRI(%ebx), %edi		/* get ipl */
	movl	CPU_SOFTINFO(%ebx), %edx

	/
	/ Check to see if the trap number is T_SOFTINT; if it is, we'll
	/ jump straight to dosoftint now.
	/
	cmpl	$T_SOFTINT, (%ecx)
	je	dosoftint

	/ raise interrupt priority level
	/ oldipl is in %edi, vectorp is in %ecx
	/ newipl is returned in %eax
	pushl	%ecx
	pushl	%edi
	call    *setlvl
	popl	%edi			/* save oldpil in %edi */
	popl	%ecx

#ifdef TRAPTRACE
	movb	%al, TTR_IPL(%esi)
#endif

	/ check for spurious interrupt
	cmp	$-1, %eax
	je	_sys_rtt

#ifdef TRAPTRACE
	movl	CPU_PRI(%ebx), %edx
	movb	%dl, TTR_PRI(%esi)
	movl	CPU_BASE_SPL(%ebx), %edx
	movb	%dl, TTR_SPL(%esi)
#endif

	movl	%eax, CPU_PRI(%ebx) /* update ipl */
	movl	REGOFF_TRAPNO(%ebp), %ecx /* reload the interrupt vector */

#ifdef TRAPTRACE
	movb	%cl, TTR_VECTOR(%esi)
#endif

	/ At this point we can take one of two paths.  If the new priority
	/ level is less than or equal to LOCK LEVEL then we jump to code that
	/ will run this interrupt as a separate thread.  Otherwise the
	/ interrupt is NOT run as a separate thread.

	/ %edi - old priority level
	/ %ebp - pointer to REGS
	/ %ecx - translated vector
	/ %eax - ipl of isr
	/ %ebx - cpu pointer

	cmpl 	$LOCK_LEVEL, %eax	/* compare to highest thread level */
	jbe	intr_thread		/* process as a separate thread */

	cmpl	$CBE_HIGH_PIL, %eax	/* Is this a CY_HIGH_LEVEL interrupt? */
	jne	2f

	movl	REGOFF_PC(%ebp), %esi
	movl	%edi, CPU_PROFILE_PIL(%ebx)	/* record interrupted PIL */
	testw	$CPL_MASK, REGOFF_CS(%ebp)	/* trap from supervisor mode? */
	jz	1f
	movl	%esi, CPU_PROFILE_UPC(%ebx)	/* record user PC */
	movl	$0, CPU_PROFILE_PC(%ebx)	/* zero kernel PC */
	jmp	2f

1:
	movl	%esi, CPU_PROFILE_PC(%ebx)	/* record kernel PC */
	movl	$0, CPU_PROFILE_UPC(%ebx)	/* zero user PC */

2:
	pushl	%ecx				/* vec */
	pushl	%eax				/* newpil */

	/
	/ See if we are interrupting another high-level interrupt.
	/
	movl	CPU_INTR_ACTV(%ebx), %eax
	andl	$CPU_INTR_ACTV_HIGH_LEVEL_MASK, %eax
	jz	0f
	/
	/ We have interrupted another high-level interrupt.
	/ Load starting timestamp, compute interval, update cumulative counter.
	/
	bsrl	%eax, %ecx		/* find PIL of interrupted handler */
	movl	%ecx, %esi		/* save PIL for later */
	HIGHPILBASE(%ebx, %ecx)
_tsc_patch1:
	nop; nop			/* patched to rdtsc if available */
	TSC_SUB_FROM(%ecx, CPU_PIL_HIGH_START)

	PILBASE_INTRSTAT(%ebx, %esi)
	TSC_ADD_TO(%esi, CPU_INTRSTAT)
	INTRACCTBASE(%ebx, %ecx)
	TSC_ADD_TO(%ecx, CPU_INTRACCT)	/* cpu_intracct[cpu_mstate] += tsc */
	/
	/ Another high-level interrupt is active below this one, so
	/ there is no need to check for an interrupt thread. That will be
	/ done by the lowest priority high-level interrupt active.
	/
	jmp	1f
0:
	/
	/ See if we are interrupting a low-level interrupt thread.
	/
	movl	CPU_THREAD(%ebx), %esi
	testw	$T_INTR_THREAD, T_FLAGS(%esi)
	jz	1f
	/
	/ We have interrupted an interrupt thread. Account for its time slice
	/ only if its time stamp is non-zero.
	/
	cmpl	$0, T_INTR_START+4(%esi)
	jne	0f
	cmpl	$0, T_INTR_START(%esi)
	je	1f
0:
	movzbl	T_PIL(%esi), %ecx /* %ecx has PIL of interrupted handler */
	PILBASE_INTRSTAT(%ebx, %ecx)
_tsc_patch2:
	nop; nop			/* patched to rdtsc if available */
	TSC_SUB_FROM(%esi, T_INTR_START)
	TSC_CLR(%esi, T_INTR_START)
	TSC_ADD_TO(%ecx, CPU_INTRSTAT)
	INTRACCTBASE(%ebx, %ecx)
	TSC_ADD_TO(%ecx, CPU_INTRACCT)	/* cpu_intracct[cpu_mstate] += tsc */
1:
	/ Store starting timestamp in CPU structure for this PIL.
	popl	%ecx			/* restore new PIL */
	pushl	%ecx
	HIGHPILBASE(%ebx, %ecx)
_tsc_patch3:
	nop; nop			/* patched to rdtsc if available */
	TSC_STORE(%ecx, CPU_PIL_HIGH_START)

	popl	%eax			/* restore new pil */
	popl	%ecx			/* vec */
	/
	/ Set bit for this PIL in CPU's interrupt active bitmask.
	/

	ASSERT_NOT_CPU_INTR_ACTV(%eax, %ebx, _interrupt_actv_bit_set)

	/ Save old CPU_INTR_ACTV
	movl	CPU_INTR_ACTV(%ebx), %esi

	cmpl	$15, %eax
	jne	0f
	/ PIL-15 interrupt. Increment nest-count in upper 16 bits of intr_actv
	incw	CPU_INTR_ACTV_REF(%ebx)	/* increment ref count */
0:
	btsl	%eax, CPU_INTR_ACTV(%ebx)
	/
	/ Handle high-level nested interrupt on separate interrupt stack
	/
	testl	$CPU_INTR_ACTV_HIGH_LEVEL_MASK, %esi
	jnz	onstack			/* already on interrupt stack */
	movl	%esp, %eax
	movl	CPU_INTR_STACK(%ebx), %esp	/* get on interrupt stack */
	pushl	%eax			/* save the thread stack pointer */
onstack:
	movl	$autovect, %esi		/* get autovect structure before */
					/* sti to save on AGI later */
	sti				/* enable interrupts */
	pushl	%ecx			/* save interrupt vector */
	/
	/ Get handler address
	/
pre_loop1:
	movl	AVH_LINK(%esi, %ecx, 8), %esi
	xorl	%ebx, %ebx	/* bh is no. of intpts in chain */
				/* bl is DDI_INTR_CLAIMED status of chain */
	testl	%esi, %esi		/* if pointer is null */
	jz	.intr_ret		/* then skip */
loop1:
	incb	%bh
	movl	AV_VECTOR(%esi), %edx	/* get the interrupt routine */
	testl	%edx, %edx		/* if func is null */
	jz	.intr_ret		/* then skip */
	pushl	$0
	pushl	AV_INTARG2(%esi)
	pushl	AV_INTARG1(%esi)
	pushl	AV_VECTOR(%esi)
	pushl	AV_DIP(%esi)
	call	__dtrace_probe_interrupt__start
	pushl	AV_INTARG2(%esi)	/* get 2nd arg to interrupt routine */
	pushl	AV_INTARG1(%esi)	/* get first arg to interrupt routine */
	call	*%edx			/* call interrupt routine with arg */
	addl	$8, %esp
	movl	%eax, 16(%esp)
	call	__dtrace_probe_interrupt__complete
	addl	$20, %esp
	orb	%al, %bl		/* see if anyone claims intpt. */
	movl	AV_LINK(%esi), %esi	/* get next routine on list */
	testl	%esi, %esi		/* if pointer is non-null */
	jnz	loop1			/* then continue */

.intr_ret:
	cmpb	$1, %bh		/* if only 1 intpt in chain, it is OK */
	je	.intr_ret1
	orb	%bl, %bl	/* If no one claims intpt, then it is OK */
	jz	.intr_ret1
	movl	(%esp), %ecx		/* else restore intr vector */
	movl	$autovect, %esi		/* get autovect structure */
	jmp	pre_loop1		/* and try again. */

.intr_ret1:
	LOADCPU(%ebx)			/* get pointer to cpu struct */

	cli
	movl	CPU_PRI(%ebx), %esi

	/ cpu_stats.sys.intr[PIL]++
	INC_CPU_STATS_INTR(%esi, %eax, %eax, %ebx)

	/
	/ Clear bit for this PIL in CPU's interrupt active bitmask.
	/

	ASSERT_CPU_INTR_ACTV(%esi, %ebx, _interrupt_actv_bit_not_set)

	cmpl	$15, %esi
	jne	0f
	/ Only clear bit if reference count is now zero.
	decw	CPU_INTR_ACTV_REF(%ebx)
	jnz	1f
0:
	btrl	%esi, CPU_INTR_ACTV(%ebx)
1:
	/
	/ Take timestamp, compute interval, update cumulative counter.
	/ esi = PIL
_tsc_patch4:
	nop; nop			/* patched to rdtsc if available */
	movl	%esi, %ecx		/* save for later */
	HIGHPILBASE(%ebx, %esi)

	ASSERT_CPU_PIL_HIGH_START_NZ(%esi)

	TSC_SUB_FROM(%esi, CPU_PIL_HIGH_START)
	
	PILBASE_INTRSTAT(%ebx, %ecx)
	TSC_ADD_TO(%ecx, CPU_INTRSTAT)
	INTRACCTBASE(%ebx, %esi)
	TSC_ADD_TO(%esi, CPU_INTRACCT)	/* cpu_intracct[cpu_mstate] += tsc */
	/
	/ Check for lower-PIL nested high-level interrupt beneath current one
	/ If so, place a starting timestamp in its pil_high_start entry.
	/
	movl	CPU_INTR_ACTV(%ebx), %eax
	movl	%eax, %esi
	andl	$CPU_INTR_ACTV_HIGH_LEVEL_MASK, %eax
	jz	0f
	bsrl	%eax, %ecx		/* find PIL of nested interrupt */
	HIGHPILBASE(%ebx, %ecx)
_tsc_patch5:
	nop; nop			/* patched to rdtsc if available */
	TSC_STORE(%ecx, CPU_PIL_HIGH_START)
	/
	/ Another high-level interrupt is active below this one, so
	/ there is no need to check for an interrupt thread. That will be
	/ done by the lowest priority high-level interrupt active.
	/
	jmp	1f
0:
	/ Check to see if there is a low-level interrupt active. If so,
	/ place a starting timestamp in the thread structure.
	movl	CPU_THREAD(%ebx), %esi
	testw	$T_INTR_THREAD, T_FLAGS(%esi)
	jz	1f
_tsc_patch6:
	nop; nop			/* patched to rdtsc if available */
	TSC_STORE(%esi, T_INTR_START)
1:
	movl	%edi, CPU_PRI(%ebx)
				/* interrupt vector already on stack */
	pushl	%edi			/* old ipl */
	call	*setlvlx
	addl	$8, %esp		/* eax contains the current ipl */

	movl	CPU_INTR_ACTV(%ebx), %esi /* reset stack pointer if no more */
	shrl	$LOCK_LEVEL + 1, %esi	/* HI PRI intrs. */
	jnz	.intr_ret2
	popl	%esp			/* restore the thread stack pointer */
.intr_ret2:
	movl	CPU_SOFTINFO(%ebx), %edx /* any pending software interrupts */
	orl	%edx, %edx
	jz	_sys_rtt
	jmp	dosoftint	/* check for softints before we return. */
	SET_SIZE(cmnint)
	SET_SIZE(_interrupt)

#endif	/* __i386 */

/*
 * Declare a uintptr_t which has the size of _interrupt to enable stack
 * traceback code to know when a regs structure is on the stack.
 */
	.globl	_interrupt_size
	.align	CLONGSIZE
_interrupt_size:
	.NWORD	. - _interrupt
	.type	_interrupt_size, @object

#endif	/* __lint */

#if defined(__i386)

/*
 * Handle an interrupt in a new thread.
 *	Entry:  traps disabled.
 *		%edi - old priority level
 *		%ebp - pointer to REGS
 *		%ecx - translated vector
 *		%eax - ipl of isr.
 *		%ebx - pointer to CPU struct
 *	Uses:
 */

#if !defined(__lint)

	ENTRY_NP(intr_thread)
	/
	/ Set bit for this PIL in CPU's interrupt active bitmask.
	/

	ASSERT_NOT_CPU_INTR_ACTV(%eax, %ebx, _interrupt_actv_bit_set)

	btsl	%eax, CPU_INTR_ACTV(%ebx)

	/ Get set to run interrupt thread.
	/ There should always be an interrupt thread since we allocate one
	/ for each level on the CPU.
	/
	/ Note that the code in kcpc_overflow_intr -relies- on the ordering
	/ of events here - in particular that t->t_lwp of the interrupt
	/ thread is set to the pinned thread *before* curthread is changed
	/
	movl	CPU_THREAD(%ebx), %edx		/* cur thread in edx */

	/
	/ Are we interrupting an interrupt thread? If so, account for it.
	/
	testw	$T_INTR_THREAD, T_FLAGS(%edx)
	jz	0f
	/
	/ We have interrupted an interrupt thread. Account for its time slice
	/ only if its time stamp is non-zero. t_intr_start may be zero due to
	/ cpu_intr_swtch_enter.
	/
	cmpl	$0, T_INTR_START+4(%edx)
	jne	1f
	cmpl	$0, T_INTR_START(%edx)
	je	0f
1:	
	pushl	%ecx
	pushl	%eax
	movl	%edx, %esi
_tsc_patch7:
	nop; nop			/* patched to rdtsc if available */
	TSC_SUB_FROM(%esi, T_INTR_START)
	TSC_CLR(%esi, T_INTR_START)
	movzbl	T_PIL(%esi), %ecx
	PILBASE_INTRSTAT(%ebx, %ecx)
	TSC_ADD_TO(%ecx, CPU_INTRSTAT)
	INTRACCTBASE(%ebx, %ecx)
	TSC_ADD_TO(%ecx, CPU_INTRACCT)	/* cpu_intracct[cpu_mstate] += tsc */
	movl	%esi, %edx
	popl	%eax
	popl	%ecx
0:
	movl	%esp, T_SP(%edx)	/* mark stack in curthread for resume */
	pushl	%edi			/* get a temporary register */
	UNLINK_INTR_THREAD(%ebx, %esi, %edi)

	movl	T_LWP(%edx), %edi
	movl	%edx, T_INTR(%esi)		/* push old thread */
	movl	%edi, T_LWP(%esi)
	/
	/ Threads on the interrupt thread free list could have state already
	/ set to TS_ONPROC, but it helps in debugging if they're TS_FREE
	/
	movl	$ONPROC_THREAD, T_STATE(%esi)
	/
	/ chain the interrupted thread onto list from the interrupt thread.
	/ Set the new interrupt thread as the current one.
	/
	popl	%edi			/* Don't need a temp reg anymore */
	movl	T_STACK(%esi), %esp		/* interrupt stack pointer */
	movl	%esp, %ebp
	movl	%esi, CPU_THREAD(%ebx)		/* set new thread */
	pushl	%eax				/* save the ipl */
	/
	/ Initialize thread priority level from intr_pri
	/
	movb	%al, T_PIL(%esi)	/* store pil */
	movzwl	intr_pri, %ebx		/* XXX Can cause probs if new class */
					/* is loaded on some other cpu. */
	addl	%ebx, %eax		/* convert level to dispatch priority */
	movw	%ax, T_PRI(%esi)

	/
	/ Take timestamp and store it in the thread structure.
	/
	movl	%eax, %ebx		/* save priority over rdtsc */
_tsc_patch8:
	nop; nop			/* patched to rdtsc if available */
	TSC_STORE(%esi, T_INTR_START)
	movl	%ebx, %eax		/* restore priority */

	/ The following 3 instructions need not be in cli.
	/ Putting them here only to avoid the AGI penalty on Pentiums.

	pushl	%ecx			/* save interrupt vector. */
	pushl	%esi			/* save interrupt thread */
	movl	$autovect, %esi		/* get autovect structure */
	sti				/* enable interrupts */

	/ Fast event tracing.
	LOADCPU(%ebx)
	movl	CPU_FTRACE_STATE(%ebx), %ebx
	testl	$FTRACE_ENABLED, %ebx
	jz	1f

	movl	8(%esp), %ebx
	pushl	%ebx			/* ipl */
	pushl	%ecx			/* int vector */
	movl	T_SP(%edx), %ebx
	pushl	%ebx			/* &regs */
	pushl	$_ftrace_intr_thread_fmt
	call	ftrace_3_notick
	addl	$8, %esp
	popl	%ecx			/* restore int vector */
	addl	$4, %esp
1:
pre_loop2:
	movl	AVH_LINK(%esi, %ecx, 8), %esi
	xorl	%ebx, %ebx	/* bh is cno. of intpts in chain */
				/* bl is DDI_INTR_CLAIMED status of * chain */
	testl	%esi, %esi	/* if pointer is null */
	jz	loop_done2	/* we're done */
loop2:
	movl	AV_VECTOR(%esi), %edx	/* get the interrupt routine */
	testl	%edx, %edx		/* if pointer is null */
	jz	loop_done2		/* we're done */
	incb	%bh
	pushl	$0
	pushl	AV_INTARG2(%esi)
	pushl	AV_INTARG1(%esi)
	pushl	AV_VECTOR(%esi)
	pushl	AV_DIP(%esi)
	call	__dtrace_probe_interrupt__start
	pushl	AV_INTARG2(%esi)	/* get 2nd arg to interrupt routine */
	pushl	AV_INTARG1(%esi)	/* get first arg to interrupt routine */
	call	*%edx			/* call interrupt routine with arg */
	addl	$8, %esp
	movl	%eax, 16(%esp)
	call	__dtrace_probe_interrupt__complete
	addl	$20, %esp
	orb	%al, %bl		/* see if anyone claims intpt. */
	movl	AV_TICKSP(%esi), %ecx
	testl	%ecx, %ecx
	jz	no_time
	call	intr_get_time
	movl	AV_TICKSP(%esi), %ecx
	TSC_ADD_TO(%ecx, 0)
no_time:
	movl	AV_LINK(%esi), %esi	/* get next routine on list */
	testl	%esi, %esi		/* if pointer is non-null */
	jnz	loop2			/* continue */
loop_done2:
	cmpb	$1, %bh		/* if only 1 intpt in chain, it is OK */
	je	.loop_done2_1
	orb	%bl, %bl	/* If no one claims intpt, then it is OK */
	jz	.loop_done2_1
	movl	$autovect, %esi		/* else get autovect structure */
	movl	4(%esp), %ecx		/* restore intr vector */
	jmp	pre_loop2		/* and try again. */
.loop_done2_1:
	popl	%esi			/* restore intr thread pointer */

	LOADCPU(%ebx)

	cli		/* protect interrupt thread pool and intr_actv */
	movzbl	T_PIL(%esi), %eax

	/ Save value in regs
	pushl	%eax			/* current pil */
	pushl	%edx			/* (huh?) */
	pushl	%edi			/* old pil */

	/ cpu_stats.sys.intr[PIL]++
	INC_CPU_STATS_INTR(%eax, %edx, %edx, %ebx)

	/
	/ Take timestamp, compute interval, and update cumulative counter.
	/ esi = thread pointer, ebx = cpu pointer, eax = PIL
	/
	movl	%eax, %edi

	ASSERT_T_INTR_START_NZ(%esi)

_tsc_patch9:
	nop; nop			/* patched to rdtsc if available */
	TSC_SUB_FROM(%esi, T_INTR_START)
	PILBASE_INTRSTAT(%ebx, %edi)
	TSC_ADD_TO(%edi, CPU_INTRSTAT)
	INTRACCTBASE(%ebx, %edi)
	TSC_ADD_TO(%edi, CPU_INTRACCT)	/* cpu_intracct[cpu_mstate] += tsc */
	popl	%edi
	popl	%edx
	popl	%eax

	/
	/ Clear bit for this PIL in CPU's interrupt active bitmask.
	/

	ASSERT_CPU_INTR_ACTV(%eax, %ebx, _intr_thread_actv_bit_not_set)

	btrl	%eax, CPU_INTR_ACTV(%ebx)

	/ if there is still an interrupted thread underneath this one
	/ then the interrupt was never blocked and the return is fairly
	/ simple.  Otherwise jump to intr_thread_exit
	cmpl	$0, T_INTR(%esi)
	je	intr_thread_exit

	/
	/ link the thread back onto the interrupt thread pool
	LINK_INTR_THREAD(%ebx, %esi, %edx)

	movl	CPU_BASE_SPL(%ebx), %eax	/* used below. */
	/ set the thread state to free so kmdb doesn't see it
	movl	$FREE_THREAD, T_STATE(%esi)

	cmpl	%eax, %edi		/* if (oldipl >= basespl) */
	jae	intr_restore_ipl	/* then use oldipl */
	movl	%eax, %edi		/* else use basespl */
intr_restore_ipl:
	movl	%edi, CPU_PRI(%ebx)
					/* intr vector already on stack */
	pushl	%edi			/* old ipl */
	call	*setlvlx		/* eax contains the current ipl */
	/
	/ Switch back to the interrupted thread
	movl	T_INTR(%esi), %ecx

	/ Place starting timestamp in interrupted thread's thread structure.
_tsc_patch10:
	nop; nop			/* patched to rdtsc if available */
	TSC_STORE(%ecx, T_INTR_START)

	movl	T_SP(%ecx), %esp	/* restore stack pointer */
	movl	%esp, %ebp
	movl	%ecx, CPU_THREAD(%ebx)

	movl	CPU_SOFTINFO(%ebx), %edx /* any pending software interrupts */
	orl	%edx, %edx
	jz	_sys_rtt
	jmp	dosoftint	/* check for softints before we return. */

	/
	/ An interrupt returned on what was once (and still might be)
	/ an interrupt thread stack, but the interrupted process is no longer
	/ there.  This means the interrupt must have blocked.
	/
	/ There is no longer a thread under this one, so put this thread back
	/ on the CPU's free list and resume the idle thread which will dispatch
	/ the next thread to run.
	/
	/ All interrupts are disabled here
	/

intr_thread_exit:
#ifdef DEBUG
	incl	intr_thread_cnt
#endif
	INC64(%ebx, CPU_STATS_SYS_INTRBLK)	/* cpu_stats.sys.intrblk++ */
	/
	/ Put thread back on the interrupt thread list.
	/ As a reminder, the regs at this point are
	/	esi	interrupt thread
	/	edi	old ipl
	/	ebx	ptr to CPU struct

	/ Set CPU's base SPL level based on active interrupts bitmask
	call	set_base_spl

	movl	CPU_BASE_SPL(%ebx), %edi
	movl	%edi, CPU_PRI(%ebx)
					/* interrupt vector already on stack */
	pushl	%edi
	call	*setlvlx
	addl	$8, %esp		/* XXX - don't need to pop since */
					/* we are ready to switch */
	call	splhigh			/* block all intrs below lock level */
	/
	/ Set the thread state to free so kmdb doesn't see it
	/
	movl	$FREE_THREAD, T_STATE(%esi)
	/
	/ Put thread on either the interrupt pool or the free pool and
	/ call swtch() to resume another thread.
	/
	LINK_INTR_THREAD(%ebx, %esi, %edx)
	call 	swtch
	/ swtch() shouldn't return

	SET_SIZE(intr_thread)

#endif	/* __lint */
#endif	/* __i386 */

/*
 * Set Cpu's base SPL level, base on which interrupt levels are active
 *	Called at spl7 or above.
 */

#if defined(__lint)

void
set_base_spl(void)
{}

#else	/* __lint */

	ENTRY_NP(set_base_spl)
	movl	%gs:CPU_INTR_ACTV, %eax	/* load active interrupts mask */
	testl	%eax, %eax		/* is it zero? */
	jz	setbase
	testl	$0xff00, %eax
	jnz	ah_set
	shl	$24, %eax		/* shift 'em over so we can find */
					/* the 1st bit faster */
	bsrl	%eax, %eax
	subl	$24, %eax
setbase:
	movl	%eax, %gs:CPU_BASE_SPL	/* store base priority */
	ret
ah_set:
	shl	$16, %eax
	bsrl	%eax, %eax
	subl	$16, %eax
	jmp	setbase
	SET_SIZE(set_base_spl)

#endif	/* __lint */

#if defined(__i386)

/*
 * int
 * intr_passivate(from, to)
 *      thread_id_t     from;           interrupt thread
 *      thread_id_t     to;             interrupted thread
 *
 *	intr_passivate(t, itp) makes the interrupted thread "t" runnable.
 *
 *	Since t->t_sp has already been saved, t->t_pc is all that needs
 *	set in this function.
 *
 *	Returns interrupt level of the thread.
 */

#if defined(__lint)

/* ARGSUSED */
int
intr_passivate(kthread_id_t from, kthread_id_t to)
{ return (0); }

#else	/* __lint */

	ENTRY(intr_passivate)
	movl	8(%esp), %eax		/* interrupted thread  */
	movl	$_sys_rtt, T_PC(%eax)	/* set T_PC for interrupted thread */

	movl	4(%esp), %eax		/* interrupt thread */
	movl	T_STACK(%eax), %eax	/* get the pointer to the start of */
					/* of the interrupt thread stack */
	movl	-4(%eax), %eax		/* interrupt level was the first */
					/* thing pushed onto the stack */
	ret
	SET_SIZE(intr_passivate)

#endif	/* __lint */
#endif	/* __i386 */

#if defined(__lint)

void
fakesoftint(void)
{}

#else	/* __lint */

	/
	/ If we're here, we're being called from splx() to fake a soft
	/ interrupt (note that interrupts are still disabled from splx()).
	/ We execute this code when a soft interrupt is posted at
	/ level higher than the CPU's current spl; when spl is lowered in
	/ splx(), it will see the softint and jump here.  We'll do exactly
	/ what a trap would do:  push our flags, %cs, %eip, error code
	/ and trap number (T_SOFTINT).  The cmnint() code will see T_SOFTINT
	/ and branch to the dosoftint() code.
	/
#if defined(__amd64)

	/*
	 * In 64-bit mode, iretq -always- pops all five regs
	 * Imitate the 16-byte auto-align of the stack, and the
	 * zero-ed out %ss value.
	 */
	ENTRY_NP(fakesoftint)
	movq	%rsp, %r11
	andq	$-16, %rsp
	pushq	$KDS_SEL	/* %ss */
	pushq	%r11		/* %rsp */
	pushf			/* rflags */
	pushq	$KCS_SEL	/* %cs */
	leaq	fakesoftint_return(%rip), %r11
	pushq	%r11		/* %rip */
	pushq	$0		/* err */
	pushq	$T_SOFTINT	/* trap */
	jmp	cmnint
	SET_SIZE(fakesoftint)

#elif defined(__i386)

	ENTRY_NP(fakesoftint)
	pushf
	push	%cs
	push	$fakesoftint_return
	push	$0
	push	$T_SOFTINT
	jmp	cmnint
	SET_SIZE(fakesoftint)

#endif	/* __i386 */

	.align	CPTRSIZE
	.globl	_fakesoftint_size
	.type	_fakesoftint_size, @object
_fakesoftint_size:
	.NWORD	. - fakesoftint
	SET_SIZE(_fakesoftint_size)

/*
 * dosoftint(old_pil in %edi, softinfo in %edx, CPU pointer in %ebx)
 * Process software interrupts
 * Interrupts are disabled here.
 */
#if defined(__i386)

	ENTRY_NP(dosoftint)

	bsrl	%edx, %edx		/* find highest pending interrupt */
	cmpl 	%edx, %edi		/* if curipl >= pri soft pending intr */
	jae	_sys_rtt		/* skip */

	movl	%gs:CPU_BASE_SPL, %eax	/* check for blocked intr threads */
	cmpl	%edx, %eax		/* if basespl >= pri soft pending */
	jae	_sys_rtt		/* skip */

	lock				/* MP protect */
	btrl	%edx, CPU_SOFTINFO(%ebx) /* clear the selected interrupt bit */
	jnc	dosoftint_again

	movl	%edx, CPU_PRI(%ebx) /* set IPL to sofint level */
	pushl	%edx
	call	*setspl			/* mask levels upto the softint level */
	popl	%eax			/* priority we are at in %eax */

	/ Get set to run interrupt thread.
	/ There should always be an interrupt thread since we allocate one
	/ for each level on the CPU.
	UNLINK_INTR_THREAD(%ebx, %esi, %edx)

	/
	/ Note that the code in kcpc_overflow_intr -relies- on the ordering
	/ of events here - in particular that t->t_lwp of the interrupt
	/ thread is set to the pinned thread *before* curthread is changed
	/
	movl	CPU_THREAD(%ebx), %ecx

	/ If we are interrupting an interrupt thread, account for it.
	testw	$T_INTR_THREAD, T_FLAGS(%ecx)
	jz	0f
	/
	/ We have interrupted an interrupt thread. Account for its time slice
	/ only if its time stamp is non-zero. t_intr_start may be zero due to
	/ cpu_intr_swtch_enter.
	/
	cmpl	$0, T_INTR_START+4(%ecx)
	jne	1f
	cmpl	$0, T_INTR_START(%ecx)
	je	0f
1:
	pushl	%eax
	movl	%eax, %ebp
_tsc_patch11:
	nop; nop			/* patched to rdtsc if available */
	PILBASE_INTRSTAT(%ebx, %ebp)
	TSC_SUB_FROM(%ecx, T_INTR_START)
	TSC_ADD_TO(%ebp, CPU_INTRSTAT)
	INTRACCTBASE(%ebx, %ebp)
	TSC_ADD_TO(%ebp, CPU_INTRACCT)	/* cpu_intracct[cpu_mstate] += tsc */
	popl	%eax
0:
	movl	T_LWP(%ecx), %ebp
	movl	%ebp, T_LWP(%esi)
	/
	/ Threads on the interrupt thread free list could have state already
	/ set to TS_ONPROC, but it helps in debugging if they're TS_FREE
	/ Could eliminate the next two instructions with a little work.
	/
	movl	$ONPROC_THREAD, T_STATE(%esi)
	/
	/ Push interrupted thread onto list from new thread.
	/ Set the new thread as the current one.
	/ Set interrupted thread's T_SP because if it is the idle thread,
	/ Resume() may use that stack between threads.
	/
	movl	%esp, T_SP(%ecx)		/* mark stack for resume */
	movl	%ecx, T_INTR(%esi)		/* push old thread */
	movl	%esi, CPU_THREAD(%ebx)		/* set new thread */
	movl	T_STACK(%esi), %esp		/* interrupt stack pointer */
	movl	%esp, %ebp

	pushl	%eax			/* push ipl as first element in stack */
					/* see intr_passivate() */
	/
	/ Set bit for this PIL in CPU's interrupt active bitmask.
	/

	ASSERT_NOT_CPU_INTR_ACTV(%eax, %ebx, _dosoftint_actv_bit_set)

	btsl	%eax, CPU_INTR_ACTV(%ebx)

	/
	/ Initialize thread priority level from intr_pri
	/
	movb	%al, T_PIL(%esi)	/* store pil */
	movzwl	intr_pri, %ecx
	addl	%eax, %ecx		/* convert level to dispatch priority */
	movw	%cx, T_PRI(%esi)

	/
	/ Store starting timestamp in thread structure.
	/ esi = thread, ebx = cpu pointer, eax = PIL
	/
	movl	%eax, %ecx		/* save PIL from rdtsc clobber */
_tsc_patch12:
	nop; nop			/* patched to rdtsc if available */
	TSC_STORE(%esi, T_INTR_START)

	sti				/* enable interrupts */

	/
	/ Enabling interrupts (above) could raise the current
	/ IPL and base SPL. But, we continue processing the current soft
	/ interrupt and we will check the base SPL next time in the loop
	/ so that blocked interrupt thread would get a chance to run.
	/

	/
	/ dispatch soft interrupts
	/
	pushl	%ecx
	call	av_dispatch_softvect
	addl	$4, %esp

	cli				/* protect interrupt thread pool */
					/* and softinfo & sysinfo */
	movl	CPU_THREAD(%ebx), %esi	/* restore thread pointer */
	movzbl	T_PIL(%esi), %ecx

	/ cpu_stats.sys.intr[PIL]++
	INC_CPU_STATS_INTR(%ecx, %edx, %edx, %ebx)

	/
	/ Clear bit for this PIL in CPU's interrupt active bitmask.
	/

	ASSERT_CPU_INTR_ACTV(%ecx, %ebx, _dosoftint_actv_bit_not_set)

	btrl	%ecx, CPU_INTR_ACTV(%ebx)

	/
	/ Take timestamp, compute interval, update cumulative counter.
	/ esi = thread, ebx = cpu, ecx = PIL
	/
	PILBASE_INTRSTAT(%ebx, %ecx)
_tsc_patch13:
	nop; nop		/* patched to rdtsc if available */
	TSC_SUB_FROM(%esi, T_INTR_START)
	TSC_ADD_TO(%ecx, CPU_INTRSTAT)
	INTRACCTBASE(%ebx, %ecx)
	TSC_ADD_TO(%ecx, CPU_INTRACCT)	/* cpu_intracct[cpu_mstate] += tsc */

	/ if there is still an interrupt thread underneath this one
	/ then the interrupt was never blocked and the return is fairly
	/ simple.  Otherwise jump to softintr_thread_exit.
	/ softintr_thread_exit expect esi to be curthread & ebx to be ipl.
	cmpl	$0, T_INTR(%esi)
	je	softintr_thread_exit

	/
	/ link the thread back onto the interrupt thread pool
	LINK_INTR_THREAD(%ebx, %esi, %edx)

	/ set the thread state to free so kmdb doesn't see it
	movl	$FREE_THREAD, T_STATE(%esi)
	/
	/ Switch back to the interrupted thread
	movl	T_INTR(%esi), %ecx
	movl	%ecx, CPU_THREAD(%ebx)
	movl	T_SP(%ecx), %esp	/* restore stack pointer */
	movl	%esp, %ebp

	/ If we are returning to an interrupt thread, store a starting
	/ timestamp in the thread structure.
	testw	$T_INTR_THREAD, T_FLAGS(%ecx)
	jz	0f
_tsc_patch14:
	nop; nop			/* patched to rdtsc if available */
	TSC_STORE(%ecx, T_INTR_START)
0:
	movl	CPU_BASE_SPL(%ebx), %eax
	cmpl	%eax, %edi		/* if (oldipl >= basespl) */
	jae	softintr_restore_ipl	/* then use oldipl */
	movl	%eax, %edi		/* else use basespl */
softintr_restore_ipl:
	movl	%edi, CPU_PRI(%ebx) /* set IPL to old level */
	pushl	%edi
	call	*setspl
	popl	%eax
dosoftint_again:
	movl	CPU_SOFTINFO(%ebx), %edx /* any pending software interrupts */
	orl	%edx, %edx
	jz	_sys_rtt
	jmp	dosoftint		/* process more software interrupts */

softintr_thread_exit:
	/
	/ Put thread back on the interrupt thread list.
	/ As a reminder, the regs at this point are
	/	%esi	interrupt thread

	/
	/ This was an interrupt thread, so set CPU's base SPL level
	/ set_base_spl only uses %eax.
	/
	call	set_base_spl		/* interrupt vector already on stack */
	/
	/ Set the thread state to free so kmdb doesn't see it
	/
	movl	$FREE_THREAD, T_STATE(%esi)
	/
	/ Put thread on either the interrupt pool or the free pool and
	/ call swtch() to resume another thread.
	/
	LOADCPU(%ebx)
	LINK_INTR_THREAD(%ebx, %esi, %edx)
	call	splhigh			/* block all intrs below lock lvl */
	call	swtch
	/ swtch() shouldn't return
	SET_SIZE(dosoftint)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(lint)

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
 * is returned as ticks. Use tsc_scalehrtime() to convert ticks to nsec.
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
 * to include elapsed running time, and by setting t_intr_start to rdtsc.
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

/*ARGSUSED*/
uint64_t
intr_get_time(void)
{ return 0; }
#else	/* lint */


#if defined(__amd64)
	ENTRY_NP(intr_get_time)
	cli				/* make this easy -- block intrs */
	LOADCPU(%rdi)
	call	intr_thread_get_time
	sti
	ret
	SET_SIZE(intr_get_time)
	
#elif defined(__i386)

#ifdef DEBUG


_intr_get_time_high_pil:
	.string	"intr_get_time(): %pil > LOCK_LEVEL"
_intr_get_time_not_intr:
	.string	"intr_get_time(): not called from an interrupt thread"
_intr_get_time_no_start_time:
	.string	"intr_get_time(): t_intr_start == 0"

/*
 * ASSERT(%pil <= LOCK_LEVEL)
 */
#define	ASSERT_PIL_BELOW_LOCK_LEVEL(cpureg)				\
	testl	$CPU_INTR_ACTV_HIGH_LEVEL_MASK, CPU_INTR_ACTV(cpureg);	\
	jz	0f;							\
	__PANIC(_intr_get_time_high_pil, 0f);				\
0:	

/*
 * ASSERT((t_flags & T_INTR_THREAD) != 0 && t_pil > 0)
 */
#define	ASSERT_NO_PIL_0_INTRS(thrreg)			\
	testw	$T_INTR_THREAD, T_FLAGS(thrreg);	\
	jz	1f;					\
	cmpb	$0, T_PIL(thrreg);			\
	jne	0f;					\
1:							\
	__PANIC(_intr_get_time_not_intr, 0f);		\
0:	
	
/*
 * ASSERT(t_intr_start != 0)
 */
#define	ASSERT_INTR_START_NOT_0(thrreg)			\
	cmpl	$0, T_INTR_START(thrreg);		\
	jnz	0f;					\
	cmpl	$0, T_INTR_START+4(thrreg);		\
	jnz	0f;					\
	__PANIC(_intr_get_time_no_start_time, 0f);	\
0:

#endif /* DEBUG */
	
	ENTRY_NP(intr_get_time)

	cli				/* make this easy -- block intrs */
	pushl	%esi			/* and free up some registers */
	pushl	%ebx

	LOADCPU(%esi)
	movl	CPU_THREAD(%esi), %ecx

#ifdef DEBUG
	ASSERT_PIL_BELOW_LOCK_LEVEL(%esi)
	ASSERT_NO_PIL_0_INTRS(%ecx)
	ASSERT_INTR_START_NOT_0(%ecx)
#endif /* DEBUG */
	
_tsc_patch17:
	nop; nop			/* patched to rdtsc if available */
	TSC_SUB_FROM(%ecx, T_INTR_START)	/* get elapsed time */
	TSC_ADD_TO(%ecx, T_INTR_START)		/* T_INTR_START = rdtsc */

	INTRACCTBASE(%esi, %ebx)			/* %ebx = CPU + cpu_mstate*8 */
	TSC_ADD_TO(%ebx, CPU_INTRACCT);		/* intracct[ms] += elapsed */
	movzbl	T_PIL(%ecx), %ecx			/* %ecx = pil */
	PILBASE_INTRSTAT(%esi, %ecx)		/* %ecx = CPU + pil*16 */
	TSC_ADD_TO(%ecx, CPU_INTRSTAT)		/* intrstat[0] += elapsed */
	TSC_LOAD(%ecx, CPU_INTRSTAT)		/* get new intrstat[0] */
	TSC_SUB_FROM(%ecx, CPU_INTRSTAT+8)	/* diff with intrstat[1] */
	TSC_ADD_TO(%ecx, CPU_INTRSTAT+8)	/* intrstat[1] = intrstat[0] */
	
	/* %edx/%eax contain difference between old and new intrstat[1] */

	popl	%ebx
	popl	%esi
	sti
	ret
	SET_SIZE(intr_get_time)
#endif	/* __i386 */

#endif  /* lint */
