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

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

#if defined(__lint)

#include <sys/link.h>

#include <amd64/amd64.h>

#endif	/* __lint */

#include <sys/asm_linkage.h>
#include <sys/controlregs.h>

#include <amd64/machregs.h>

#include <assym.h>

#if defined(__lint)

/*ARGSUSED*/
void
amd64_exitto(struct amd64_machregs *rp)
{}

#else	/* __lint */

	.data
	.globl	need_init_cr8
need_init_cr8:
	.long	1

	ENTRY_NP(amd64_exitto)
	pushl	%ebp
	movl	%esp, %ebp
	/*
	 * stash current i386 state in i386_machregs
	 */
	lea	exitto_i386_machregs, %eax
	movw	%ss, %dx
	movzx	%dx, %edx
	mov	%edx, i386_REG_SS(%eax)
	pushfl
	pop	%edx
	mov	%edx, i386_REG_EFL(%eax)
	movw	%cs, %dx
	movzx	%dx, %edx
	mov	%edx, i386_REG_CS(%eax)
	mov	%ebx, i386_REG_EBX(%eax)
	mov	%esp, i386_REG_ESP(%eax)
	mov	%ebp, i386_REG_EBP(%eax)
	mov	%esi, i386_REG_ESI(%eax)
	mov	%edi, i386_REG_EDI(%eax)
	movw	%ds, %dx
	movzx	%dx, %edx
	mov	%edx, i386_REG_DS(%eax)
	movw	%es, %dx
	movzx	%dx, %edx
	mov	%edx, i386_REG_ES(%eax)
	movw	%fs, %dx
	movzx	%dx, %edx
	mov	%edx, i386_REG_FS(%eax)
	movw	%gs, %dx
	movzx	%dx, %edx
	mov	%edx, i386_REG_GS(%eax)
	str	i386_REG_TR(%eax)
	sldt	i386_REG_LDT(%eax)
	sidt	i386_REG_IDT(%eax)
	sgdt	i386_REG_GDT(%eax)
	mov	%cr4, %edx
	mov	%edx, i386_REG_CR4(%eax)
	mov	%cr3, %edx
	mov	%edx, i386_REG_CR3(%eax)
	mov	%cr2, %edx
	mov	%edx, i386_REG_CR2(%eax)
	mov	%cr0, %edx
	mov	%edx, i386_REG_CR0(%eax)
	movl	$1, need_init_cr8	/* set flag to cause %cr8 init */
#ifdef DEBUG
	push	%eax
	call	amd64_dump_i386_machregs
	addl	$4, %esp
#endif	/* DEBUG */
	/*
	 * Fetch the argument, and switch to it as a stack;
	 * the new stack contains an amd64_machregs on it,
	 * just sitting there waiting for us to restore it.
	 */
	mov	8(%ebp), %esp
	jmp	__return_to_long_mode
	/*NOTREACHED*/
	SET_SIZE(amd64_exitto)

#endif	/* __lint */

#if defined(__lint)

#define	VTRAP_STUB_BEGIN(opname)	\
	uintptr_t opname;

#define	VTRAP_STUB_END(opname)		\
	uintptr_t opname;

#define	VTRAP_STUB(symname)		\
	uintptr_t symname;

#else

#define	VTRAP_STUB_BEGIN(symname)	\
	.global	symname;		\
symname:				\
	.code64

#define	VTRAP_STUB_END(symname)		\
	.code32;			\
	.global	symname;		\
symname:

/*
 * callbacks from the amd64 kernel to the i386 world are handled
 * as calls into a virtual amd64 boot program as if they were
 * virtual traps i.e. we save the machine state, switch to i386 mode,
 * then decode and interpret the request in C code (amd64_vtrap)
 */

#define	VTRAP_STUB(opname)			\
	ENTRY_NP(opname);			\
	pushq	%rbp;				\
	movq	%rsp, %rbp;			\
	call	1f;				\
1:	pop	%r11;				\
	sub	$_CONST(1b - opname), %r11;	\
	jmp	__vtrap_common;			\
	SET_SIZE(opname)

	ENTRY_NP(__vtrap_common)
	.code64
	/*
	 * put the state of the amd64 machine onto the stack
	 */
	movq	%rsp, %r10
	addq	$0x10, %r10	/* (%rsp immediately before the call) */
	push	$0		/* %ss */
	push	%r10		/* %rsp */
	pushf			/* rflags */
	push	$0		/* %cs */
	push	%r11		/* %rip (the pc we came in on) */
	push	$0		/* err */
	push	$-1		/* trapno (virt trap# larger than idt itself) */
	cli

	ALTENTRY(__amd64_exception)	/* vectored from amd64_idt */
	push	$0		/* %es */
	push	$0		/* %ds */
	push	%fs
	push	%gs
	push	%r15
	push	%r14
	push	%r13
	push	%r12
	push	%r11
	push	%r10
	push	%rbp
	push	%rbx
	push	%rax
	push	%r9
	push	%r8
	push	%rcx
	push	%rdx
	push	%rsi
	push	%rdi

	/*
	 * (that was the 'struct regs' part, now for the somewhat trickier
	 * parts of the machine (with all the implicit state that goes
	 * along with those registers (?)))
	 */

	str	%rax
	push	%rax
	sldt	%rax
	push	%rax

	/* XX64 need to do some compile-time assert here to check this! */

	push	$0
	push	$0
	sidt	(%rsp)

	push	$0
	push	$0
	sgdt	(%rsp)

#define	PUSH_CREG(creg)		\
	mov	creg, %rax;	\
	push	%rax

	PUSH_CREG(%cr8)
	PUSH_CREG(%cr4)
	PUSH_CREG(%cr3)
	PUSH_CREG(%cr2)
	PUSH_CREG(%cr0)

#define	PUSH_SEG_BASE(msr)	\
	mov	$msr, %ecx;	\
	rdmsr;			\
	salq	$32, %rdx;	\
	mov	%eax, %eax;	\
	or	%rdx, %rax;	\
	push	%rax

	PUSH_SEG_BASE(MSR_AMD_FSBASE)
	PUSH_SEG_BASE(MSR_AMD_GSBASE)
	PUSH_SEG_BASE(MSR_AMD_KGSBASE)

	/*
	 * save the sodding segment registers (because push doesn't work!)
	 */
	mov	%cs, %ax
	movzx	%ax, %rax
	mov	%rax, amd64_REG_CS(%rsp)
	
	mov	%ds, %ax
	movzx	%ax, %rax
	mov	%rax, amd64_REG_DS(%rsp)

	mov	%es, %ax
	movzx	%ax, %rax
	mov	%rax, amd64_REG_ES(%rsp)

	mov	%ss, %ax
	movzx	%ax, %rax
	mov	%rax, amd64_REG_SS(%rsp)
	
	/*
	 * Back to i386 mode
	 */

	/*
	 * reload %ds here so we can refer to i386_machregs below
	 */
	mov	$KDS32SEL, %rax
	movw	%ax, %ds

	/*
	 * 1.	Switch to compatibility mode at CPL=0
	 *
	 * We seem forced to do this -- which is a complicated
	 * way to do:
	 *
	 *	ljmp $KCS32SEL, $__amd64_compat_mode
	 * __amd64_compat_mode:
	 *
	 * which unfortunately isn't legal in long mode.
	 *
	 * You'd think this would work, but it doesn't.
	 *
	 *	push	$KCS32SEL
	 *	push	%rax
	 *	lret
	 *
	 * Perhaps there's a better way?
	 */
	call	9f
9:	pop	%rax
	add	$_CONST(__amd64_compat_mode - 9b), %rax
	mov	%rsp, %rdx
	push	$KDS32SEL
	push	%rdx
	pushf	
	push	$KCS32SEL
	push	%rax
	iretq

__amd64_compat_mode:
	.code32
	/*
	 * 2.	Deactivate long mode by clearing CR0.PG
	 */
	mov	%cr0, %eax
	and	$_BITNOT(CR0_PG), %eax
	mov	%eax, %cr0
	/*
	 * 2a.	Disable PAE
	 */
	mov	%cr4, %eax
	and	$_BITNOT(CR4_PAE), %eax
	mov	%eax, %cr4
	/*
	 * 3.	Load CR3 with physical base address of page tables
	 *
	 * (Note we loaded %ds above)
	 */
	lea	exitto_i386_machregs, %eax
	mov	i386_REG_CR3(%eax), %edx
	mov	%edx, %cr3
	/*
	 * 4.	Disable long mode by clearing EFER.LME to 0
	 */
	mov	$MSR_AMD_EFER, %ecx
	rdmsr
	and	$_BITNOT(AMD_EFER_LME), %eax
	wrmsr
	/*
	 * 5.	Enable legacy page-translation
	 */
	mov	%cr0, %eax
	or	$CR0_PG, %eax
	mov	%eax, %cr0
	jmp	__i386_mode
__i386_mode:
	/*
	 * Reconstruct our life as an i386 processor from the
	 * exitto save area.
	 */
	lea	exitto_i386_machregs, %eax
	mov	i386_REG_CR0(%eax), %edx
	mov	%edx, %cr0
	/*
	 * %cr2 is the page fault address; we have no need to restore it
	 */
	mov	i386_REG_CR3(%eax), %edx
	mov	%edx, %cr3
	mov	i386_REG_CR4(%eax), %edx
	mov	%edx, %cr4
	lgdt	i386_REG_GDT(%eax)
	lidt	i386_REG_IDT(%eax)

	/*
	 * Need to clear busy bit in our tss descriptor
	 */
/ clrtss:
/ 	push	%eax
/ 	call	amd64_i386_clrtss
/ 	pop	%eax
/ 
/ 	ltr	i386_REG_TR(%eax)

	mov	i386_REG_GS(%eax), %edx
	movw	%dx, %gs
	mov	i386_REG_FS(%eax), %edx
	movw	%dx, %fs
	mov	i386_REG_ES(%eax), %edx
	movw	%dx, %es
	mov	i386_REG_DS(%eax), %edx
	movw	%dx, %ds
	mov	i386_REG_SS(%eax), %edx
	movw	%dx, %ss

	pushl	i386_REG_EFL(%eax)
	popf

	/*
	 * As long as the transition from long mode to i386 mode
	 * simply truncated %rsp -> %esp, we now have a struct amd64_machregs
	 * sitting on the top of the stack. 
	 */
	pushl	%esp
	call	amd64_vtrap
	addl	$4, %esp

	/*
	 * let's go long ..
	 */
__return_to_long_mode:
	mov	amd64_REG_CR3(%esp), %edx

	/*
	 *	Disable paging
	 */
	mov	%cr0, %eax
	and	$_BITNOT(CR0_PG), %eax
	mov	%eax, %cr0
	/*
	 *	2a.	enable PAE
	 */
	mov	%cr4, %eax
	or	$CR4_PAE, %eax
	mov	%eax, %cr4
	/*
	 *	2b.	load CR3 with PML4 base address
	 */
	mov	%edx, %cr3
	/*
	 *	2c.	enable long mode
	 */
	mov	$MSR_AMD_EFER, %ecx
	rdmsr
	or	$AMD_EFER_LME, %eax
	wrmsr
	/*
	 *	2d.	enable paging
	 */
	mov	%cr0, %eax
	or	$CR0_PG, %eax
	mov	%eax, %cr0
	jmp	__enable_long_mode
__enable_long_mode:

	/*
	 * we are now in compatibility mode
	 * move to the 64 bit descriptor tables so that
	 * we find ourselves in a sane place when we lret
	 * and switch to 64 bit mode ..
	 */
	lgdt	amd64_REG_GDT(%esp)

	/*
	 * switch to 64-bit mode
	 */
	call	1f
1:	pop	%eax
	add	$_CONST(__amd64_64bit_mode - 1b), %eax
	mov	amd64_REG_CS(%esp), %edx
	push	%edx
	push	%eax
	lret
__amd64_64bit_mode:
	.code64

	/*
	 * the following descriptor table loads fetch the full
	 * 64-bit values expected by the client.
	 */
	lgdt	amd64_REG_GDT(%rsp)
	lidt	amd64_REG_IDT(%rsp)
	lldt	amd64_REG_LDT(%rsp)
	ltr	amd64_REG_TR(%rsp)

	/*
	 * fix up the selectors for long mode
	 */
	mov	amd64_REG_DS(%rsp), %rax
	movw	%ax, %ds
	mov	amd64_REG_ES(%rsp), %rax
	movw	%ax, %es
	mov	amd64_REG_FS(%rsp), %rax
	movw	%ax, %fs
	mov	amd64_REG_GS(%rsp), %rax
	movw	%ax, %gs
	mov	amd64_REG_SS(%rsp), %rax
	movw	%ax, %ss

#define	RESTORE_SEG_BASE(seg)			\
	movq	amd64_REG_/**/seg(%rsp), %rax;	\
	movq	%rax, %rdx;			\
	movl	%eax, %eax;			\
	shrq	$32, %rdx;			\
	movl	$MSR_AMD_/**/seg, %ecx;		\
	wrmsr		

	RESTORE_SEG_BASE(KGSBASE)
	RESTORE_SEG_BASE(GSBASE)
	RESTORE_SEG_BASE(FSBASE)

#define	RESTORE_CR(num)					\
	movq	amd64_REG_CR/**/num(%rsp), %rax;	\
	movq	%rax, %cr/**/num

	RESTORE_CR(0)

	/* don't restore %cr2 */

	RESTORE_CR(3)
	RESTORE_CR(4)

	/*
	 * Only restore %cr8 if it's nonzero or if we have not yet initialized
	 * it (if it's zero, that means it's not safe to restore it -- we're
	 * either using the local APIC TPR or no TPR at all).  We only test the
	 * non-reserved bits.  The %cr8 initialization is done only on the first
	 * transfer from the booter to the loaded image.
	 */
	cmpl	$0, need_init_cr8(%rip)		/* Did we initialize cr8 yet? */
	jnz	1f				/* No? Then go and zero it. */

	testq	$0xF, amd64_REG_CR8(%rsp)	/* Is the saved cr8 zero? */
	jz	2f				/* Yes, -- skip the restore */
1:
	movl	$0, need_init_cr8(%rip)		/* Mark cr8 as initialized */
	RESTORE_CR(8)
2:
	/*
	 * gdt/idt/ldt/tr have already been restored, as have %gs, %fs, %ds
	 * and %es.
	 *
	 * Meanwhile %rbp, %r11, err and trapno don't get restored at all.
	 */
	movq	amd64_REG_RDI(%rsp), %rdi
	movq	amd64_REG_RSI(%rsp), %rsi
	movq	amd64_REG_RAX(%rsp), %rax
	movq	amd64_REG_RCX(%rsp), %rcx
	movq	amd64_REG_RDX(%rsp), %rdx
	movq	amd64_REG_R8(%rsp), %r8
	movq	amd64_REG_R9(%rsp), %r9
	movq	amd64_REG_RBX(%rsp), %rbx
	movq	amd64_REG_R10(%rsp), %r10
	movq	amd64_REG_R12(%rsp), %r12
	movq	amd64_REG_R13(%rsp), %r13
	movq	amd64_REG_R14(%rsp), %r14
	movq	amd64_REG_R15(%rsp), %r15

	/*
	 * The bottom five arguments in the struct amd64_machregs on the
	 * stack (starting with r_rip) are positioned such that they can be
	 * used as-is by iretq to return to the caller, switch interrupts
	 * back on if needed, and restore the proper %rsp.
	 *
	 * HOWEVER, we need the %rbp and %rip sitting in the return frame
	 * on the stack, so grab them from beyond the end of the amd64_machregs
	 * structure on the stack so that everything will be restored properly
	 * by the iretq.
	 *
	 * The stack after the addq below will be:
	 *
	 *	0	amd64_machregs %rip
	 *	+8	amd64_machregs %cs
	 *	+0x10	amd64_machflags rflags
	 *	+0x18	amd64_machflags %rsp
	 *	+0x20	amd64_machflags %ss
	 *	+0x28	return %rbp from bootops 'call' insn
	 *	+0x30	return %rip from bootops 'call' insn
	 */
	addq	$amd64_REG_RIP, %rsp
	movq	0x28(%rsp), %rbp	/* load the return %rbp to %rbp */
	movq	0x30(%rsp), %r11	/* copy the return %rip to %r11 */
	movq	%r11, (%rsp)		/* save it as amd64_machregs' r_rip */
	iretq
	SET_SIZE(__vtrap_common)

#endif	/* __lint */

	VTRAP_STUB_BEGIN(bop64_first)

	VTRAP_STUB(bop64_alloc)
	VTRAP_STUB(bop64_free)
	VTRAP_STUB(bop64_getproplen)
	VTRAP_STUB(bop64_getprop)
	VTRAP_STUB(bop64_nextprop)
	VTRAP_STUB(bop64_printf)
	VTRAP_STUB(bop64_doint)
	VTRAP_STUB(bop64_ealloc)

	VTRAP_STUB_END(bop64_last)

	VTRAP_STUB_BEGIN(bsys64_first)

	VTRAP_STUB(bsys64_getchar)
	VTRAP_STUB(bsys64_putchar)
	VTRAP_STUB(bsys64_ischar)

	VTRAP_STUB_END(bsys64_last)
