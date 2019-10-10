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
#include <sys/panic.h>

#include "assym.h"

#if defined(__amd64)
	ENTRY_NP(xpv_panic_getcr3)
	movq	%cr3, %rax
	ret
	SET_SIZE(xpv_panic_getcr3)

	ENTRY_NP(xpv_panic_setcr3)
	movq	%rdi, %cr3
	ret
	SET_SIZE(xpv_panic_setcr3)

	ENTRY(xpv_panic_reload_cr3)
	movq	%cr3, %rdi
	movq	%rdi, %cr3
	ret
	SET_SIZE(xpv_panic_reload_cr3)

	ENTRY_NP(xpv_panic_prep)
	pushq   %rbp
	movq	%rsp, %rbp

	subq	$REGSIZE, %rsp
	movq	%rax, REGOFF_RAX(%rsp)
	movq	%rbx, REGOFF_RBX(%rsp)
	movq	%rsp, %rax
	addq	$REGSIZE, %rax
	movq	(%rax), %rbx
	movq	%rbx, REGOFF_RBP(%rsp)
	movq	8(%rax), %rbx
	movq	%rbx, REGOFF_TRAPNO(%rsp)
	movq	16(%rax), %rbx
	movq	%rbx, REGOFF_ERR(%rsp)
	movq	24(%rax), %rbx
	movq	%rbx, REGOFF_RIP(%rsp)
	movq	32(%rax), %rbx
	movq	%rbx, REGOFF_CS(%rsp)
	movq	40(%rax), %rbx
	movq	%rbx, REGOFF_RFL(%rsp)
	addq	$56, %rax
	movq	%rax, REGOFF_RSP(%rsp)
	xorl	%eax, %eax
	movw	%gs, %ax
	mov	%rax, REGOFF_GS(%rsp)
	movw	%fs, %ax
	mov	%rax, REGOFF_FS(%rsp)
	movw	%es, %ax
	mov	%rax, REGOFF_ES(%rsp)
	movw	%ds, %ax
	mov	%rax, REGOFF_DS(%rsp)
	movw	%ss, %ax
	mov	%rax, REGOFF_SS(%rsp)
	movq	%rcx, REGOFF_RCX(%rsp)
	movq	%rdx, REGOFF_RDX(%rsp)
	movq	%rdi, REGOFF_RDI(%rsp)
	movq	%rsi, REGOFF_RSI(%rsp)
	movq	%r8, REGOFF_R8(%rsp)
	movq	%r9, REGOFF_R9(%rsp)
	movq	%r10, REGOFF_R10(%rsp)
	movq	%r11, REGOFF_R11(%rsp)
	movq	%r12, REGOFF_R12(%rsp)
	movq	%r13, REGOFF_R13(%rsp)
	movq	%r14, REGOFF_R14(%rsp)
	movq	%r15, REGOFF_R15(%rsp)

	movq	%rsp, %rdi
	call	xpv_die
	SET_SIZE(xpv_panic_prep)

	/*
	 * Switch to the Solaris panic stack and jump into the Xen panic
	 * handling code.
	 */
	ENTRY_NP(xpv_panic_hdlr)
	leaq	panic_stack(%rip), %rsp
	addq	$PANICSTKSIZE, %rsp
	call	xpv_do_panic
	SET_SIZE(xpv_panic_hdlr)

	ENTRY_NP(xpv_surprise_intr)
	pushq   %rbp
	movq	%rsp, %rbp
	subq	$REGOFF_TRAPNO, %rsp
	__SAVE_REGS
	movq	%rsp, %rdi
	addq	$REGOFF_TRAPNO, %rdi
	call	xpv_interrupt
	__RESTORE_REGS
	addq	$REGOFF_TRAPNO, %rsp
	popq	%rbp
	iretq
	SET_SIZE(xpv_surprise_intr)

	ENTRY_NP(xpv_timer_trap)
	pushq   %rbp
	movq	%rsp, %rbp
	subq	$REGOFF_TRAPNO, %rsp
	__SAVE_REGS
	movq	%rsp, %rdi
	addq	$REGOFF_TRAPNO, %rdi
	call	xpv_timer_tick
	__RESTORE_REGS
	addq	$REGOFF_TRAPNO, %rsp
	popq	%rbp
	iretq
	SET_SIZE(xpv_timer_trap)

#elif defined(__i386)

	ENTRY_NP(xpv_panic_setcr3)
	movl	4(%esp), %eax
	movl	%eax, %cr3
	ret
	SET_SIZE(xpv_panic_setcr3)

	ENTRY(xpv_panic_reload_cr3)
	movl    %cr3, %eax
	movl    %eax, %cr3
	ret
	SET_SIZE(xpv_panic_reload_cr3)

	/*
	 * Stack on entry:
	 *  +------------+
	 *  |   EFLAGS  |
	 *  |   CS      |
	 *  |   EIP     |
	 *  |   Error   |
	 *  |   Trap    |   <---- %esp
	 *  +------------+
	 */
	ENTRY_NP(xpv_panic_prep)
	pushl   %ebp
	movl	%esp, %ebp

	subl	$REGSIZE, %esp
	movl	%eax, REGOFF_EAX(%esp)
	movl	%ebx, REGOFF_EBX(%esp)
	movl	%esp, %eax
	addl	$REGSIZE, %eax
	movl	(%eax), %ebx
	movl	%ebx, REGOFF_EBP(%esp)
	movl	4(%eax), %ebx
	movl	%ebx, REGOFF_TRAPNO(%esp)
	movl	8(%eax), %ebx
	movl	%ebx, REGOFF_ERR(%esp)
	movl	12(%eax), %ebx
	movl	%ebx, REGOFF_EIP(%esp)
	movl	16(%eax), %ebx
	movl	%ebx, REGOFF_CS(%esp)
	movl	20(%eax), %ebx
	movl	%ebx, REGOFF_EFL(%esp)
	addl	$28, %eax
	movl	%eax, REGOFF_ESP(%esp)
	xorl	%eax, %eax
	movw	%gs, %ax
	mov	%eax, REGOFF_GS(%esp)
	movw	%fs, %ax
	mov	%eax, REGOFF_FS(%esp)
	movw	%es, %ax
	mov	%eax, REGOFF_ES(%esp)
	movw	%ds, %ax
	mov	%eax, REGOFF_DS(%esp)
	movw	%ss, %ax
	mov	%eax, REGOFF_SS(%esp)
	movl	%ecx, REGOFF_ECX(%esp)
	movl	%edx, REGOFF_EDX(%esp)
	movl	%edi, REGOFF_EDI(%esp)
	movl	%esi, REGOFF_ESI(%esp)
	pushl  	%esp
	call	xpv_die
	SET_SIZE(xpv_panic_prep)

	/*
	 * Switch to the Solaris panic stack and jump into the Xen panic
	 * handling code.
	 */
	ENTRY_NP(xpv_panic_hdlr)
	movl	4(%esp), %eax
	lea	panic_stack, %esp
	add	$PANICSTKSIZE, %esp
	pushl	%eax
	call	xpv_do_panic
	SET_SIZE(xpv_panic_hdlr)

	ENTRY_NP(xpv_surprise_intr)
	push	%ebp
	movl	%esp, %ebp
	pusha
	call	xpv_interrupt
	popa
	pop	%ebp
	iret
	SET_SIZE(xpv_surprise_intr)

	ENTRY_NP(xpv_timer_trap)
	push	%ebp
	movl	%esp, %ebp
	pusha
	call	xpv_timer_tick
	popa
	pop	%ebp
	iret
	SET_SIZE(xpv_timer_trap)

#endif	/* __i386 */

	ENTRY_NP(xpv_panic_sti)
	sti
	ret
	SET_SIZE(xpv_panic_sti)

	ENTRY_NP(xpv_panic_halt)
	sti
	hlt
	ret
	SET_SIZE(xpv_panic_halt)

	ENTRY_NP(xpv_panic_resetgs)
	movl	$KGS_SEL, %eax
	movw	%ax, %gs
	ret
	SET_SIZE(xpv_panic_resetgs)

	ENTRY_NP(xpv_invaltrap)
	push	$0xbad0
	push	$0x0bad
	jmp	xpv_panic_prep
	SET_SIZE(xpv_invaltrap) 

	ENTRY_NP(xpv_div0trap)
	push	$0
	push	$T_ZERODIV
	jmp	xpv_panic_prep
	SET_SIZE(xpv_div0trap)

	ENTRY_NP(xpv_dbgtrap)
	push	$0
	push	$T_SGLSTP
	jmp	xpv_panic_prep
	SET_SIZE(xpv_dbgtrap)

	ENTRY_NP(xpv_nmiint)
	push	$0
	push	$T_NMIFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_nmiint)

	ENTRY_NP(xpv_brktrap)
	/* XXX: check for error */
	push	$T_BPTFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_brktrap)

	ENTRY_NP(xpv_ovflotrap)
	push	$0
	push	$T_OVFLW
	jmp	xpv_panic_prep
	SET_SIZE(xpv_ovflotrap)

	ENTRY_NP(xpv_boundstrap)
	push	$0
	push	$T_BOUNDFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_boundstrap)

	ENTRY_NP(xpv_invoptrap)
	push	$T_ILLINST
	jmp	xpv_panic_prep
	SET_SIZE(xpv_invoptrap)

	ENTRY_NP(xpv_ndptrap)
	push	$0
	push	$T_NOEXTFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_ndptrap)

	ENTRY_NP(xpv_syserrtrap)
	/* XXX: check for error */
	push	$T_DBLFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_syserrtrap)

	ENTRY_NP(xpv_invtsstrap)
	push	$T_TSSFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_invtsstrap)

	ENTRY_NP(xpv_segnptrap)
	push	$T_SEGFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_segnptrap)

	ENTRY_NP(xpv_stktrap)
	push	$T_STKFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_stktrap)

	ENTRY_NP(xpv_gptrap)
	push	$T_GPFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_gptrap)

	ENTRY_NP(xpv_pftrap)
	push	$T_PGFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_pftrap)

	ENTRY_NP(xpv_ndperr)
	push	$0
	push	$T_EXTERRFLT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_ndperr)

	ENTRY_NP(xpv_achktrap)
	push	$T_ALIGNMENT
	jmp	xpv_panic_prep
	SET_SIZE(xpv_achktrap)

	ENTRY_NP(xpv_mcetrap)
	push	$0
	push	$T_MCE
	jmp	xpv_panic_prep
	SET_SIZE(xpv_mcetrap)

	ENTRY_NP(xpv_xmtrap)
	push	$0
	push	$T_SIMDFPE
	jmp	xpv_panic_prep
	SET_SIZE(xpv_xmtrap)

