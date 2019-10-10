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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/asm_linkage.h>
#include <sys/hypervisor.h>
#include <sys/privregs.h>
#include <sys/segments.h>
#include <sys/traptrace.h>
#include <sys/trap.h>
#include <sys/psw.h>
#include <sys/x86_archext.h>
#include <sys/asm_misc.h>

#include "assym.h"

	/*
	 * The stack frame for events is exactly that of an x86 hardware
	 * interrupt.
	 *
	 * The stack frame for a failsafe callback is augmented with saved
	 * values for segment registers:
	 *
	 * i386
	 *	%ds, %es, %fs, %gs, %eip, %cs, %eflags [, %oldesp, %oldss ]
	 *
	 * On amd64 the stack frame for events is exactly that of an hardware
	 * interrupt with the addition of rcx and r11.
	 * 
	 * The stack frame for a failsafe callback is augmented with saved
	 * values for segment registers:
	 * 
	 * amd64
	 *	%rcx, %r11, %ds, %es, %fs, %gs, %rip, %cs, %rflags,
	 *      [, %oldrsp, %oldss ]
	 *
	 * The hypervisor  does this to allow the guest OS to handle returns
	 * to processes which have bad segment registers.
	 *
	 * [See comments in xen/arch/x86/[x86_64,x86_32]/entry.S]
	 *
	 * We will construct a fully fledged 'struct regs' and call trap
	 * with a #gp fault.
	 */

#if defined(__amd64)

	ENTRY(xen_failsafe_callback)

	/*
	 * The saved values of rcx and r11 are on the top of the stack.
	 * pop them and let INTR_PUSH save them. We drop ds, es, fs and
	 * gs since the hypervisor will have already loaded these for us.
	 * If any were bad and faulted the hypervisor would have loaded
	 * them with the null selctor.
	 */
	XPV_TRAP_POP	/* rcx, r11 */

	/*
	 * XXPV
	 * If the current segregs are provided for us on the stack by
	 * the hypervisor then we should simply move them into their proper
	 * location in the regs struct?
	 */
	addq    $_CONST(_MUL(4, CLONGSIZE)), %rsp

	/*
	 * XXPV
	 * It would be nice to somehow figure out which selector caused
	 * #gp fault.
	 */

	pushq	$0	/* dummy error */
	pushq	$T_GPFLT

	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS

	/*
	 * We're here because HYPERVISOR_IRET to userland failed due to a
	 * bad %cs value. Rewrite %cs, %ss and %rip on the stack so trap
	 * will know to handle this with kern_gpfault and kill the currently
	 * running process.
	 */
	movq	$KCS_SEL, REGOFF_CS(%rsp)
	movq	$KDS_SEL, REGOFF_SS(%rsp)
	leaq	nopop_sys_rtt_syscall(%rip), %rdi
	movq	%rdi, REGOFF_RIP(%rsp)

	TRACE_PTR(%rdi, %rbx, %ebx, %rcx, $TT_EVENT) /* Uses labels 8 and 9 */
	TRACE_REGS(%rdi, %rsp, %rbx, %rcx)	/* Uses label 9 */
	TRACE_STAMP(%rdi)		/* Clobbers %eax, %edx, uses 9 */

	movq	%rsp, %rbp

	TRACE_STACK(%rdi)

	movq	%rbp, %rdi

	ENABLE_INTR_FLAGS

	movq	%rbp, %rdi
	xorl	%esi, %esi
	movl	%gs:CPU_ID, %edx
	call	trap		/* trap(rp, addr, cpuid) handles all trap */
	jmp	_sys_rtt
	SET_SIZE(xen_failsafe_callback)

#elif defined(__i386)

	ENTRY(xen_failsafe_callback)

	/*
	 * drop ds, es, fs and gs
	 */
	addl    $_CONST(_MUL(4, CLONGSIZE)), %esp /* see comment for 64-bit */

	pushl	$0	/* dummy error (see comment for 64-bit) */
	pushl	$T_GPFLT

	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS	/* (set kernel flag values) */

	/*
	 * The fact were here is because HYPERVISOR_IRET to userland
	 * failed due to a bad %cs value. Rewrite %cs, %ss and %eip
	 * on the stack so trap will know to handle this with
	 * kern_gpfault and kill the currently running process.
	 */
	movl	$KCS_SEL, REGOFF_CS(%esp)
	movl	$KDS_SEL, REGOFF_SS(%esp)
	leal	nopop_sys_rtt_syscall, %edi
	movl	%edi, REGOFF_EIP(%esp)

	TRACE_PTR(%edi, %ebx, %ebx, %ecx, $TT_EVENT) /* Uses labels 8 and 9 */
	TRACE_REGS(%edi, %esp, %ebx, %ecx)	/* Uses label 9 */
	TRACE_STAMP(%edi)		/* Clobbers %eax, %edx, uses 9 */

	movl	%esp, %ebp

	TRACE_STACK(%edi)

	ENABLE_INTR_FLAGS

	pushl	%gs:CPU_ID
	pushl	$0
	pushl	%ebp
	call	trap		/* trap(rp, addr, cpuid) handles all traps */
	addl	$12, %esp
	jmp	_sys_rtt
	SET_SIZE(xen_failsafe_callback)

#endif	/* __i386 */

#if defined(__amd64)

	ENTRY(xen_callback)
	XPV_TRAP_POP

	pushq	$0			/* dummy error */
	pushq	$T_AST

	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS	/* (set kernel flag values) */

	TRACE_PTR(%rdi, %rbx, %ebx, %rcx, $TT_EVENT) /* Uses labels 8 and 9 */
	TRACE_REGS(%rdi, %rsp, %rbx, %rcx)	/* Uses label 9 */
	TRACE_STAMP(%rdi)		/* Clobbers %eax, %edx, uses 9 */

	movq	%rsp, %rbp

	TRACE_STACK(%rdi)

	movq	%rdi, %rsi		/* rsi = trap trace recode pointer */
	movq	%rbp, %rdi		/* rdi = struct regs pointer */
	call	xen_callback_handler

	jmp	_sys_rtt_ints_disabled
	/*NOTREACHED*/

	SET_SIZE(xen_callback)

#elif defined(__i386)

	ENTRY(xen_callback)
	pushl	$0			/* dummy error */
	pushl	$T_AST

	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS	/* (set kernel flag values) */

	TRACE_PTR(%edi, %ebx, %ebx, %ecx, $TT_EVENT) /* Uses labels 8 and 9 */
	TRACE_REGS(%edi, %esp, %ebx, %ecx)	/* Uses label 9 */
	TRACE_STAMP(%edi)		/* Clobbers %eax, %edx, uses 9 */

	movl	%esp, %ebp

	TRACE_STACK(%edi)

	pushl	%edi			/* pass trap trace record pointer */
	pushl	%ebp			/* pass struct regs pointer */
	call	xen_callback_handler
	addl	$8, %esp

	jmp	_sys_rtt_ints_disabled
	/*NOTREACHED*/

	SET_SIZE(xen_callback)

#endif	/* __i386 */
