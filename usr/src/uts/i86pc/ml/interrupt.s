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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2019 Joyent, Inc.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved					*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation		*/
/*	  All Rights Reserved					*/

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

#endif	/* lint */

#if defined(__lint)

void
_interrupt(void)
{}

#else	/* __lint */

#if defined(__amd64)

	/*
	 * Common register usage:
	 *
	 * %r12		trap trace pointer
	 */
	ENTRY_NP2(cmnint, _interrupt)

	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS	/* (set kernel rflags values) */

	/*
	 * At the end of TRACE_PTR %r12 points to the current TRAPTRACE entry
	 */
	TRACE_PTR(%r12, %rax, %eax, %rdx, $TT_INTERRUPT)
						/* Uses labels 8 and 9 */
	TRACE_REGS(%r12, %rsp, %rax, %rbx)	/* Uses label 9 */
	TRACE_STAMP(%r12)		/* Clobbers %eax, %edx, uses 9 */

	movq	%rsp, %rbp

	TRACE_STACK(%r12)

#ifdef TRAPTRACE
	LOADCPU(%rbx)				/* &cpu */
	movl	CPU_PRI(%rbx), %r14d		/* old ipl */
	movl	$255, TTR_IPL(%r12)
	movl	%r14d, %edi
	movb	%dil, TTR_PRI(%r12)
	movl	CPU_BASE_SPL(%rbx), %edi
	movb	%dil, TTR_SPL(%r12)
	movb	$255, TTR_VECTOR(%r12)
	movq	%r12, %rsi		/* pass traptrace record pointer */
#endif

	movq	%rsp, %rdi		/* pass struct regs pointer */
	movq	do_interrupt_common, %rax
	INDIRECT_CALL_REG(rax)

	jmp	_sys_rtt_ints_disabled
	/*NOTREACHED*/

	SET_SIZE(cmnint)
	SET_SIZE(_interrupt)

#elif defined(__i386)

	ENTRY_NP2(cmnint, _interrupt)

	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS

	/*
	 * At the end of TRACE_PTR %esi points to the current TRAPTRACE entry
	 */
	TRACE_PTR(%esi, %eax, %eax, %edx, $TT_INTERRUPT)
						/* Uses labels 8 and 9 */
	TRACE_REGS(%esi, %esp, %eax, %ebx)	/* Uses label 9 */
	TRACE_STAMP(%esi)		/* Clobbers %eax, %edx, uses 9 */

	movl	%esp, %ebp

	TRACE_STACK(%esi)

	pushl	%esi			/* pass traptrace record pointer */
	pushl	%ebp			/* pass struct regs pointer */
	call	*do_interrupt_common	/* interrupt service routine */
	addl	$8, %esp		/* pop args off of stack */

	jmp	_sys_rtt_ints_disabled
	/*NOTREACHED*/

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
#if defined(__xpv)
	popq	%r11
	EVENT_MASK_TO_IE(%rdi, %r11)
	pushq	%r11
#endif
	pushq	$KCS_SEL	/* %cs */
	leaq	fakesoftint_return(%rip), %r11
	pushq	%r11		/* %rip */
	pushq	$0		/* err */
	pushq	$T_SOFTINT	/* trap */
	jmp	cmnint
	ALTENTRY(fakesoftint_return)
	ret
	SET_SIZE(fakesoftint_return)
	SET_SIZE(fakesoftint)

#elif defined(__i386)

	ENTRY_NP(fakesoftint)
	pushfl
#if defined(__xpv)
	popl	%eax
	EVENT_MASK_TO_IE(%edx, %eax)
	pushl	%eax
#endif
	pushl	%cs
	pushl	$fakesoftint_return
	pushl	$0
	pushl	$T_SOFTINT
	jmp	cmnint
	ALTENTRY(fakesoftint_return)
	ret
	SET_SIZE(fakesoftint_return)
	SET_SIZE(fakesoftint)

#endif	/* __i386 */
#endif	/* __lint */
