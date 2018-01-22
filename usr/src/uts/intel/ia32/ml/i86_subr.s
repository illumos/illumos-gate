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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2014 by Delphix. All rights reserved.
 * Copyright 2018 Joyent, Inc.
 */

/*
 *  Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.
 *  Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T
 *    All Rights Reserved
 */

/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

/*
 * General assembly language routines.
 * It is the intent of this file to contain routines that are
 * independent of the specific kernel architecture, and those that are
 * common across kernel architectures.
 * As architectures diverge, and implementations of specific
 * architecture-dependent routines change, the routines should be moved
 * from this file into the respective ../`arch -k`/subr.s file.
 */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/panic.h>
#include <sys/ontrap.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/reboot.h>
#include <sys/psw.h>
#include <sys/x86_archext.h>

#if defined(__lint)
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/archsystm.h>
#include <sys/byteorder.h>
#include <sys/dtrace.h>
#include <sys/ftrace.h>
#else	/* __lint */
#include "assym.h"
#endif	/* __lint */
#include <sys/dditypes.h>

/*
 * on_fault()
 *
 * Catch lofault faults. Like setjmp except it returns one
 * if code following causes uncorrectable fault. Turned off
 * by calling no_fault(). Note that while under on_fault(),
 * SMAP is disabled. For more information see
 * uts/intel/ia32/ml/copy.s.
 */

#if defined(__lint)

/* ARGSUSED */
int
on_fault(label_t *ljb)
{ return (0); }

void
no_fault(void)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(on_fault)
	movq	%gs:CPU_THREAD, %rsi
	leaq	catch_fault(%rip), %rdx
	movq	%rdi, T_ONFAULT(%rsi)		/* jumpbuf in t_onfault */
	movq	%rdx, T_LOFAULT(%rsi)		/* catch_fault in t_lofault */
	call	smap_disable			/* allow user accesses */
	jmp	setjmp				/* let setjmp do the rest */

catch_fault:
	movq	%gs:CPU_THREAD, %rsi
	movq	T_ONFAULT(%rsi), %rdi		/* address of save area */
	xorl	%eax, %eax
	movq	%rax, T_ONFAULT(%rsi)		/* turn off onfault */
	movq	%rax, T_LOFAULT(%rsi)		/* turn off lofault */
	call	smap_enable			/* disallow user accesses */
	jmp	longjmp				/* let longjmp do the rest */
	SET_SIZE(on_fault)

	ENTRY(no_fault)
	movq	%gs:CPU_THREAD, %rsi
	xorl	%eax, %eax
	movq	%rax, T_ONFAULT(%rsi)		/* turn off onfault */
	movq	%rax, T_LOFAULT(%rsi)		/* turn off lofault */
	call	smap_enable			/* disallow user accesses */
	ret
	SET_SIZE(no_fault)

#elif defined(__i386)

	ENTRY(on_fault)
	movl	%gs:CPU_THREAD, %edx
	movl	4(%esp), %eax			/* jumpbuf address */
	leal	catch_fault, %ecx
	movl	%eax, T_ONFAULT(%edx)		/* jumpbuf in t_onfault */
	movl	%ecx, T_LOFAULT(%edx)		/* catch_fault in t_lofault */
	jmp	setjmp				/* let setjmp do the rest */

catch_fault:
	movl	%gs:CPU_THREAD, %edx
	xorl	%eax, %eax
	movl	T_ONFAULT(%edx), %ecx		/* address of save area */
	movl	%eax, T_ONFAULT(%edx)		/* turn off onfault */
	movl	%eax, T_LOFAULT(%edx)		/* turn off lofault */
	pushl	%ecx
	call	longjmp				/* let longjmp do the rest */
	SET_SIZE(on_fault)

	ENTRY(no_fault)
	movl	%gs:CPU_THREAD, %edx
	xorl	%eax, %eax
	movl	%eax, T_ONFAULT(%edx)		/* turn off onfault */
	movl	%eax, T_LOFAULT(%edx)		/* turn off lofault */
	ret
	SET_SIZE(no_fault)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Default trampoline code for on_trap() (see <sys/ontrap.h>).  We just
 * do a longjmp(&curthread->t_ontrap->ot_jmpbuf) if this is ever called.
 */

#if defined(lint)

void
on_trap_trampoline(void)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(on_trap_trampoline)
	movq	%gs:CPU_THREAD, %rsi
	movq	T_ONTRAP(%rsi), %rdi
	addq	$OT_JMPBUF, %rdi
	jmp	longjmp
	SET_SIZE(on_trap_trampoline)

#elif defined(__i386)

	ENTRY(on_trap_trampoline)
	movl	%gs:CPU_THREAD, %eax
	movl	T_ONTRAP(%eax), %eax
	addl	$OT_JMPBUF, %eax
	pushl	%eax
	call	longjmp
	SET_SIZE(on_trap_trampoline)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Push a new element on to the t_ontrap stack.  Refer to <sys/ontrap.h> for
 * more information about the on_trap() mechanism.  If the on_trap_data is the
 * same as the topmost stack element, we just modify that element.
 */
#if defined(lint)

/*ARGSUSED*/
int
on_trap(on_trap_data_t *otp, uint_t prot)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(on_trap)
	movw	%si, OT_PROT(%rdi)		/* ot_prot = prot */
	movw	$0, OT_TRAP(%rdi)		/* ot_trap = 0 */
	leaq	on_trap_trampoline(%rip), %rdx	/* rdx = &on_trap_trampoline */
	movq	%rdx, OT_TRAMPOLINE(%rdi)	/* ot_trampoline = rdx */
	xorl	%ecx, %ecx
	movq	%rcx, OT_HANDLE(%rdi)		/* ot_handle = NULL */
	movq	%rcx, OT_PAD1(%rdi)		/* ot_pad1 = NULL */
	movq	%gs:CPU_THREAD, %rdx		/* rdx = curthread */
	movq	T_ONTRAP(%rdx), %rcx		/* rcx = curthread->t_ontrap */
	cmpq	%rdi, %rcx			/* if (otp == %rcx)	*/
	je	0f				/*	don't modify t_ontrap */

	movq	%rcx, OT_PREV(%rdi)		/* ot_prev = t_ontrap */
	movq	%rdi, T_ONTRAP(%rdx)		/* curthread->t_ontrap = otp */

0:	addq	$OT_JMPBUF, %rdi		/* &ot_jmpbuf */
	jmp	setjmp
	SET_SIZE(on_trap)

#elif defined(__i386)

	ENTRY(on_trap)
	movl	4(%esp), %eax			/* %eax = otp */
	movl	8(%esp), %edx			/* %edx = prot */

	movw	%dx, OT_PROT(%eax)		/* ot_prot = prot */
	movw	$0, OT_TRAP(%eax)		/* ot_trap = 0 */
	leal	on_trap_trampoline, %edx	/* %edx = &on_trap_trampoline */
	movl	%edx, OT_TRAMPOLINE(%eax)	/* ot_trampoline = %edx */
	movl	$0, OT_HANDLE(%eax)		/* ot_handle = NULL */
	movl	$0, OT_PAD1(%eax)		/* ot_pad1 = NULL */
	movl	%gs:CPU_THREAD, %edx		/* %edx = curthread */
	movl	T_ONTRAP(%edx), %ecx		/* %ecx = curthread->t_ontrap */
	cmpl	%eax, %ecx			/* if (otp == %ecx) */
	je	0f				/*    don't modify t_ontrap */

	movl	%ecx, OT_PREV(%eax)		/* ot_prev = t_ontrap */
	movl	%eax, T_ONTRAP(%edx)		/* curthread->t_ontrap = otp */

0:	addl	$OT_JMPBUF, %eax		/* %eax = &ot_jmpbuf */
	movl	%eax, 4(%esp)			/* put %eax back on the stack */
	jmp	setjmp				/* let setjmp do the rest */
	SET_SIZE(on_trap)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Setjmp and longjmp implement non-local gotos using state vectors
 * type label_t.
 */

#if defined(__lint)

/* ARGSUSED */
int
setjmp(label_t *lp)
{ return (0); }

/* ARGSUSED */
void
longjmp(label_t *lp)
{}

#else	/* __lint */

#if LABEL_PC != 0
#error LABEL_PC MUST be defined as 0 for setjmp/longjmp to work as coded
#endif	/* LABEL_PC != 0 */

#if defined(__amd64)

	ENTRY(setjmp)
	movq	%rsp, LABEL_SP(%rdi)
	movq	%rbp, LABEL_RBP(%rdi)
	movq	%rbx, LABEL_RBX(%rdi)
	movq	%r12, LABEL_R12(%rdi)
	movq	%r13, LABEL_R13(%rdi)
	movq	%r14, LABEL_R14(%rdi)
	movq	%r15, LABEL_R15(%rdi)
	movq	(%rsp), %rdx		/* return address */
	movq	%rdx, (%rdi)		/* LABEL_PC is 0 */
	xorl	%eax, %eax		/* return 0 */
	ret
	SET_SIZE(setjmp)

	ENTRY(longjmp)
	movq	LABEL_SP(%rdi), %rsp
	movq	LABEL_RBP(%rdi), %rbp
	movq	LABEL_RBX(%rdi), %rbx
	movq	LABEL_R12(%rdi), %r12
	movq	LABEL_R13(%rdi), %r13
	movq	LABEL_R14(%rdi), %r14
	movq	LABEL_R15(%rdi), %r15
	movq	(%rdi), %rdx		/* return address; LABEL_PC is 0 */
	movq	%rdx, (%rsp)
	xorl	%eax, %eax
	incl	%eax			/* return 1 */
	ret
	SET_SIZE(longjmp)

#elif defined(__i386)

	ENTRY(setjmp)
	movl	4(%esp), %edx		/* address of save area */
	movl	%ebp, LABEL_EBP(%edx)
	movl	%ebx, LABEL_EBX(%edx)
	movl	%esi, LABEL_ESI(%edx)
	movl	%edi, LABEL_EDI(%edx)
	movl	%esp, 4(%edx)
	movl	(%esp), %ecx		/* %eip (return address) */
	movl	%ecx, (%edx)		/* LABEL_PC is 0 */
	subl	%eax, %eax		/* return 0 */
	ret
	SET_SIZE(setjmp)

	ENTRY(longjmp)
	movl	4(%esp), %edx		/* address of save area */
	movl	LABEL_EBP(%edx), %ebp
	movl	LABEL_EBX(%edx), %ebx
	movl	LABEL_ESI(%edx), %esi
	movl	LABEL_EDI(%edx), %edi
	movl	4(%edx), %esp
	movl	(%edx), %ecx		/* %eip (return addr); LABEL_PC is 0 */
	movl	$1, %eax
	addl	$4, %esp		/* pop ret adr */
	jmp	*%ecx			/* indirect */
	SET_SIZE(longjmp)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * if a() calls b() calls caller(),
 * caller() returns return address in a().
 * (Note: We assume a() and b() are C routines which do the normal entry/exit
 *  sequence.)
 */

#if defined(__lint)

caddr_t
caller(void)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(caller)
	movq	8(%rbp), %rax		/* b()'s return pc, in a() */
	ret
	SET_SIZE(caller)

#elif defined(__i386)

	ENTRY(caller)
	movl	4(%ebp), %eax		/* b()'s return pc, in a() */
	ret
	SET_SIZE(caller)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * if a() calls callee(), callee() returns the
 * return address in a();
 */

#if defined(__lint)

caddr_t
callee(void)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(callee)
	movq	(%rsp), %rax		/* callee()'s return pc, in a() */
	ret
	SET_SIZE(callee)

#elif defined(__i386)

	ENTRY(callee)
	movl	(%esp), %eax		/* callee()'s return pc, in a() */
	ret
	SET_SIZE(callee)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * return the current frame pointer
 */

#if defined(__lint)

greg_t
getfp(void)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(getfp)
	movq	%rbp, %rax
	ret
	SET_SIZE(getfp)

#elif defined(__i386)

	ENTRY(getfp)
	movl	%ebp, %eax
	ret
	SET_SIZE(getfp)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Invalidate a single page table entry in the TLB
 */

#if defined(__lint)

/* ARGSUSED */
void
mmu_invlpg(caddr_t m)
{}

#else	/* __lint */

	ENTRY(mmu_invlpg)
	invlpg	(%rdi)
	ret
	SET_SIZE(mmu_invlpg)

#endif	/* __lint */


/*
 * Get/Set the value of various control registers
 */

#if defined(__lint)

ulong_t
getcr0(void)
{ return (0); }

/* ARGSUSED */
void
setcr0(ulong_t value)
{}

ulong_t
getcr2(void)
{ return (0); }

ulong_t
getcr3(void)
{ return (0); }

#if !defined(__xpv)
/* ARGSUSED */
void
setcr3(ulong_t val)
{}

void
reload_cr3(void)
{}
#endif

ulong_t
getcr4(void)
{ return (0); }

/* ARGSUSED */
void
setcr4(ulong_t val)
{}

#if defined(__amd64)

ulong_t
getcr8(void)
{ return (0); }

/* ARGSUSED */
void
setcr8(ulong_t val)
{}

#endif	/* __amd64 */

#else	/* __lint */

#if defined(__amd64)

	ENTRY(getcr0)
	movq	%cr0, %rax
	ret
	SET_SIZE(getcr0)

	ENTRY(setcr0)
	movq	%rdi, %cr0
	ret
	SET_SIZE(setcr0)

        ENTRY(getcr2)
#if defined(__xpv)
	movq	%gs:CPU_VCPU_INFO, %rax
	movq	VCPU_INFO_ARCH_CR2(%rax), %rax
#else
        movq    %cr2, %rax
#endif
        ret
	SET_SIZE(getcr2)

	ENTRY(getcr3)
	movq    %cr3, %rax
	ret
	SET_SIZE(getcr3)

#if !defined(__xpv)

        ENTRY(setcr3)
        movq    %rdi, %cr3
        ret
	SET_SIZE(setcr3)

	ENTRY(reload_cr3)
	movq	%cr3, %rdi
	movq	%rdi, %cr3
	ret
	SET_SIZE(reload_cr3)

#endif	/* __xpv */

	ENTRY(getcr4)
	movq	%cr4, %rax
	ret
	SET_SIZE(getcr4)

	ENTRY(setcr4)
	movq	%rdi, %cr4
	ret
	SET_SIZE(setcr4)

	ENTRY(getcr8)
	movq	%cr8, %rax
	ret
	SET_SIZE(getcr8)

	ENTRY(setcr8)
	movq	%rdi, %cr8
	ret
	SET_SIZE(setcr8)

#elif defined(__i386)

        ENTRY(getcr0)
        movl    %cr0, %eax
        ret
	SET_SIZE(getcr0)

        ENTRY(setcr0)
        movl    4(%esp), %eax
        movl    %eax, %cr0
        ret
	SET_SIZE(setcr0)

	/*
	 * "lock mov %cr0" is used on processors which indicate it is
	 * supported via CPUID. Normally the 32 bit TPR is accessed via
	 * the local APIC.
	 */
	ENTRY(getcr8)
	lock
	movl	%cr0, %eax
	ret
	SET_SIZE(getcr8)

	ENTRY(setcr8)
        movl    4(%esp), %eax
	lock
        movl    %eax, %cr0
	ret
	SET_SIZE(setcr8)

        ENTRY(getcr2)
#if defined(__xpv)
	movl	%gs:CPU_VCPU_INFO, %eax
	movl	VCPU_INFO_ARCH_CR2(%eax), %eax
#else
        movl    %cr2, %eax
#endif
        ret
	SET_SIZE(getcr2)

	ENTRY(getcr3)
	movl    %cr3, %eax
	ret
	SET_SIZE(getcr3)

#if !defined(__xpv)

        ENTRY(setcr3)
        movl    4(%esp), %eax
        movl    %eax, %cr3
        ret
	SET_SIZE(setcr3)

	ENTRY(reload_cr3)
	movl    %cr3, %eax
	movl    %eax, %cr3
	ret
	SET_SIZE(reload_cr3)

#endif	/* __xpv */

	ENTRY(getcr4)
	movl    %cr4, %eax
	ret
	SET_SIZE(getcr4)

        ENTRY(setcr4)
        movl    4(%esp), %eax
        movl    %eax, %cr4
        ret
	SET_SIZE(setcr4)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
uint32_t
__cpuid_insn(struct cpuid_regs *regs)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(__cpuid_insn)
	movq	%rbx, %r8
	movq	%rcx, %r9
	movq	%rdx, %r11
	movl	(%rdi), %eax		/* %eax = regs->cp_eax */
	movl	0x4(%rdi), %ebx		/* %ebx = regs->cp_ebx */
	movl	0x8(%rdi), %ecx		/* %ecx = regs->cp_ecx */
	movl	0xc(%rdi), %edx		/* %edx = regs->cp_edx */
	cpuid
	movl	%eax, (%rdi)		/* regs->cp_eax = %eax */
	movl	%ebx, 0x4(%rdi)		/* regs->cp_ebx = %ebx */
	movl	%ecx, 0x8(%rdi)		/* regs->cp_ecx = %ecx */
	movl	%edx, 0xc(%rdi)		/* regs->cp_edx = %edx */
	movq	%r8, %rbx
	movq	%r9, %rcx
	movq	%r11, %rdx
	ret
	SET_SIZE(__cpuid_insn)

#elif defined(__i386)

        ENTRY(__cpuid_insn)
	pushl	%ebp
	movl	0x8(%esp), %ebp		/* %ebp = regs */
	pushl	%ebx
	pushl	%ecx
	pushl	%edx
	movl	(%ebp), %eax		/* %eax = regs->cp_eax */
	movl	0x4(%ebp), %ebx		/* %ebx = regs->cp_ebx */
	movl	0x8(%ebp), %ecx		/* %ecx = regs->cp_ecx */
	movl	0xc(%ebp), %edx		/* %edx = regs->cp_edx */
	cpuid
	movl	%eax, (%ebp)		/* regs->cp_eax = %eax */
	movl	%ebx, 0x4(%ebp)		/* regs->cp_ebx = %ebx */
	movl	%ecx, 0x8(%ebp)		/* regs->cp_ecx = %ecx */
	movl	%edx, 0xc(%ebp)		/* regs->cp_edx = %edx */
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%ebp
	ret
	SET_SIZE(__cpuid_insn)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void
i86_monitor(volatile uint32_t *addr, uint32_t extensions, uint32_t hints)
{}

#else   /* __lint */

#if defined(__amd64)

	ENTRY_NP(i86_monitor)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rdi, %rax		/* addr */
	movq	%rsi, %rcx		/* extensions */
	/* rdx contains input arg3: hints */
	clflush	(%rax)
	.byte	0x0f, 0x01, 0xc8	/* monitor */
	leave
	ret
	SET_SIZE(i86_monitor)

#elif defined(__i386)

ENTRY_NP(i86_monitor)
	pushl	%ebp
	movl	%esp, %ebp
	movl	0x8(%ebp),%eax		/* addr */
	movl	0xc(%ebp),%ecx		/* extensions */
	movl	0x10(%ebp),%edx		/* hints */
	clflush	(%eax)
	.byte	0x0f, 0x01, 0xc8	/* monitor */
	leave
	ret
	SET_SIZE(i86_monitor)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void
i86_mwait(uint32_t data, uint32_t extensions)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(i86_mwait)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rdi, %rax		/* data */
	movq	%rsi, %rcx		/* extensions */
	.byte	0x0f, 0x01, 0xc9	/* mwait */
	leave
	ret
	SET_SIZE(i86_mwait)

#elif defined(__i386)

	ENTRY_NP(i86_mwait)
	pushl	%ebp
	movl	%esp, %ebp
	movl	0x8(%ebp),%eax		/* data */
	movl	0xc(%ebp),%ecx		/* extensions */
	.byte	0x0f, 0x01, 0xc9	/* mwait */
	leave
	ret
	SET_SIZE(i86_mwait)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__xpv)
	/*
	 * Defined in C
	 */
#else

#if defined(__lint)

hrtime_t
tsc_read(void)
{
	return (0);
}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(tsc_read)
	movq	%rbx, %r11
	movl	$0, %eax
	cpuid
	rdtsc
	movq	%r11, %rbx
	shlq	$32, %rdx
	orq	%rdx, %rax
	ret
	.globl _tsc_mfence_start
_tsc_mfence_start:
	mfence
	rdtsc
	shlq	$32, %rdx
	orq	%rdx, %rax
	ret
	.globl _tsc_mfence_end
_tsc_mfence_end:
	.globl _tscp_start
_tscp_start:
	.byte	0x0f, 0x01, 0xf9	/* rdtscp instruction */
	shlq	$32, %rdx
	orq	%rdx, %rax
	ret
	.globl _tscp_end
_tscp_end:
	.globl _no_rdtsc_start
_no_rdtsc_start:
	xorl	%edx, %edx
	xorl	%eax, %eax
	ret
	.globl _no_rdtsc_end
_no_rdtsc_end:
	.globl _tsc_lfence_start
_tsc_lfence_start:
	lfence
	rdtsc
	shlq	$32, %rdx
	orq	%rdx, %rax
	ret
	.globl _tsc_lfence_end
_tsc_lfence_end:
	SET_SIZE(tsc_read)

#else /* __i386 */

	ENTRY_NP(tsc_read)
	pushl	%ebx
	movl	$0, %eax
	cpuid
	rdtsc
	popl	%ebx
	ret
	.globl _tsc_mfence_start
_tsc_mfence_start:
	mfence
	rdtsc
	ret
	.globl _tsc_mfence_end
_tsc_mfence_end:
	.globl	_tscp_start
_tscp_start:
	.byte	0x0f, 0x01, 0xf9	/* rdtscp instruction */
	ret
	.globl _tscp_end
_tscp_end:
	.globl _no_rdtsc_start
_no_rdtsc_start:
	xorl	%edx, %edx
	xorl	%eax, %eax
	ret
	.globl _no_rdtsc_end
_no_rdtsc_end:
	.globl _tsc_lfence_start
_tsc_lfence_start:
	lfence
	rdtsc
	ret
	.globl _tsc_lfence_end
_tsc_lfence_end:
	SET_SIZE(tsc_read)

#endif	/* __i386 */

#endif	/* __lint */


#endif	/* __xpv */

#ifdef __lint
/*
 * Do not use this function for obtaining clock tick.  This
 * is called by callers who do not need to have a guarenteed
 * correct tick value.  The proper routine to use is tsc_read().
 */
u_longlong_t
randtick(void)
{
	return (0);
}
#else
#if defined(__amd64)
	ENTRY_NP(randtick)
	rdtsc
	shlq    $32, %rdx
	orq     %rdx, %rax
	ret
	SET_SIZE(randtick)
#else
	ENTRY_NP(randtick)
	rdtsc
	ret
	SET_SIZE(randtick)
#endif /* __i386 */
#endif /* __lint */
/*
 * Insert entryp after predp in a doubly linked list.
 */

#if defined(__lint)

/*ARGSUSED*/
void
_insque(caddr_t entryp, caddr_t predp)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(_insque)
	movq	(%rsi), %rax		/* predp->forw			*/
	movq	%rsi, CPTRSIZE(%rdi)	/* entryp->back = predp		*/
	movq	%rax, (%rdi)		/* entryp->forw = predp->forw	*/
	movq	%rdi, (%rsi)		/* predp->forw = entryp		*/
	movq	%rdi, CPTRSIZE(%rax)	/* predp->forw->back = entryp	*/
	ret
	SET_SIZE(_insque)

#elif defined(__i386)

	ENTRY(_insque)
	movl	8(%esp), %edx
	movl	4(%esp), %ecx
	movl	(%edx), %eax		/* predp->forw			*/
	movl	%edx, CPTRSIZE(%ecx)	/* entryp->back = predp		*/
	movl	%eax, (%ecx)		/* entryp->forw = predp->forw	*/
	movl	%ecx, (%edx)		/* predp->forw = entryp		*/
	movl	%ecx, CPTRSIZE(%eax)	/* predp->forw->back = entryp	*/
	ret
	SET_SIZE(_insque)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Remove entryp from a doubly linked list
 */

#if defined(__lint)

/*ARGSUSED*/
void
_remque(caddr_t entryp)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(_remque)
	movq	(%rdi), %rax		/* entry->forw */
	movq	CPTRSIZE(%rdi), %rdx	/* entry->back */
	movq	%rax, (%rdx)		/* entry->back->forw = entry->forw */
	movq	%rdx, CPTRSIZE(%rax)	/* entry->forw->back = entry->back */
	ret
	SET_SIZE(_remque)

#elif defined(__i386)

	ENTRY(_remque)
	movl	4(%esp), %ecx
	movl	(%ecx), %eax		/* entry->forw */
	movl	CPTRSIZE(%ecx), %edx	/* entry->back */
	movl	%eax, (%edx)		/* entry->back->forw = entry->forw */
	movl	%edx, CPTRSIZE(%eax)	/* entry->forw->back = entry->back */
	ret
	SET_SIZE(_remque)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Returns the number of
 * non-NULL bytes in string argument.
 */

#if defined(__lint)

/* ARGSUSED */
size_t
strlen(const char *str)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

/*
 * This is close to a simple transliteration of a C version of this
 * routine.  We should either just -make- this be a C version, or
 * justify having it in assembler by making it significantly faster.
 *
 * size_t
 * strlen(const char *s)
 * {
 *	const char *s0;
 * #if defined(DEBUG)
 *	if ((uintptr_t)s < KERNELBASE)
 *		panic(.str_panic_msg);
 * #endif
 *	for (s0 = s; *s; s++)
 *		;
 *	return (s - s0);
 * }
 */

	ENTRY(strlen)
#ifdef DEBUG
	movq	postbootkernelbase(%rip), %rax
	cmpq	%rax, %rdi
	jae	str_valid
	pushq	%rbp
	movq	%rsp, %rbp
	leaq	.str_panic_msg(%rip), %rdi
	xorl	%eax, %eax
	call	panic
#endif	/* DEBUG */
str_valid:
	cmpb	$0, (%rdi)
	movq	%rdi, %rax
	je	.null_found
	.align	4
.strlen_loop:
	incq	%rdi
	cmpb	$0, (%rdi)
	jne	.strlen_loop
.null_found:
	subq	%rax, %rdi
	movq	%rdi, %rax
	ret
	SET_SIZE(strlen)

#elif defined(__i386)

	ENTRY(strlen)
#ifdef DEBUG
	movl	postbootkernelbase, %eax
	cmpl	%eax, 4(%esp)
	jae	str_valid
	pushl	%ebp
	movl	%esp, %ebp
	pushl	$.str_panic_msg
	call	panic
#endif /* DEBUG */

str_valid:
	movl	4(%esp), %eax		/* %eax = string address */
	testl	$3, %eax		/* if %eax not word aligned */
	jnz	.not_word_aligned	/* goto .not_word_aligned */
	.align	4
.word_aligned:
	movl	(%eax), %edx		/* move 1 word from (%eax) to %edx */
	movl	$0x7f7f7f7f, %ecx
	andl	%edx, %ecx		/* %ecx = %edx & 0x7f7f7f7f */
	addl	$4, %eax		/* next word */
	addl	$0x7f7f7f7f, %ecx	/* %ecx += 0x7f7f7f7f */
	orl	%edx, %ecx		/* %ecx |= %edx */
	andl	$0x80808080, %ecx	/* %ecx &= 0x80808080 */
	cmpl	$0x80808080, %ecx	/* if no null byte in this word */
	je	.word_aligned		/* goto .word_aligned */
	subl	$4, %eax		/* post-incremented */
.not_word_aligned:
	cmpb	$0, (%eax)		/* if a byte in (%eax) is null */
	je	.null_found		/* goto .null_found */
	incl	%eax			/* next byte */
	testl	$3, %eax		/* if %eax not word aligned */
	jnz	.not_word_aligned	/* goto .not_word_aligned */
	jmp	.word_aligned		/* goto .word_aligned */
	.align	4
.null_found:
	subl	4(%esp), %eax		/* %eax -= string address */
	ret
	SET_SIZE(strlen)

#endif	/* __i386 */

#ifdef DEBUG
	.text
.str_panic_msg:
	.string "strlen: argument below kernelbase"
#endif /* DEBUG */

#endif	/* __lint */

	/*
	 * Berkeley 4.3 introduced symbolically named interrupt levels
	 * as a way deal with priority in a machine independent fashion.
	 * Numbered priorities are machine specific, and should be
	 * discouraged where possible.
	 *
	 * Note, for the machine specific priorities there are
	 * examples listed for devices that use a particular priority.
	 * It should not be construed that all devices of that
	 * type should be at that priority.  It is currently were
	 * the current devices fit into the priority scheme based
	 * upon time criticalness.
	 *
	 * The underlying assumption of these assignments is that
	 * IPL 10 is the highest level from which a device
	 * routine can call wakeup.  Devices that interrupt from higher
	 * levels are restricted in what they can do.  If they need
	 * kernels services they should schedule a routine at a lower
	 * level (via software interrupt) to do the required
	 * processing.
	 *
	 * Examples of this higher usage:
	 *	Level	Usage
	 *	14	Profiling clock (and PROM uart polling clock)
	 *	12	Serial ports
	 *
	 * The serial ports request lower level processing on level 6.
	 *
	 * Also, almost all splN routines (where N is a number or a
	 * mnemonic) will do a RAISE(), on the assumption that they are
	 * never used to lower our priority.
	 * The exceptions are:
	 *	spl8()		Because you can't be above 15 to begin with!
	 *	splzs()		Because this is used at boot time to lower our
	 *			priority, to allow the PROM to poll the uart.
	 *	spl0()		Used to lower priority to 0.
	 */

#if defined(__lint)

int spl0(void)		{ return (0); }
int spl6(void)		{ return (0); }
int spl7(void)		{ return (0); }
int spl8(void)		{ return (0); }
int splhigh(void)	{ return (0); }
int splhi(void)		{ return (0); }
int splzs(void)		{ return (0); }

/* ARGSUSED */
void
splx(int level)
{}

#else	/* __lint */

#if defined(__amd64)

#define	SETPRI(level) \
	movl	$/**/level, %edi;	/* new priority */		\
	jmp	do_splx			/* redirect to do_splx */

#define	RAISE(level) \
	movl	$/**/level, %edi;	/* new priority */		\
	jmp	splr			/* redirect to splr */

#elif defined(__i386)

#define	SETPRI(level) \
	pushl	$/**/level;	/* new priority */			\
	call	do_splx;	/* invoke common splx code */		\
	addl	$4, %esp;	/* unstack arg */			\
	ret

#define	RAISE(level) \
	pushl	$/**/level;	/* new priority */			\
	call	splr;		/* invoke common splr code */		\
	addl	$4, %esp;	/* unstack args */			\
	ret

#endif	/* __i386 */

	/* locks out all interrupts, including memory errors */
	ENTRY(spl8)
	SETPRI(15)
	SET_SIZE(spl8)

	/* just below the level that profiling runs */
	ENTRY(spl7)
	RAISE(13)
	SET_SIZE(spl7)

	/* sun specific - highest priority onboard serial i/o asy ports */
	ENTRY(splzs)
	SETPRI(12)	/* Can't be a RAISE, as it's used to lower us */
	SET_SIZE(splzs)

	ENTRY(splhi)
	ALTENTRY(splhigh)
	ALTENTRY(spl6)
	ALTENTRY(i_ddi_splhigh)

	RAISE(DISP_LEVEL)

	SET_SIZE(i_ddi_splhigh)
	SET_SIZE(spl6)
	SET_SIZE(splhigh)
	SET_SIZE(splhi)

	/* allow all interrupts */
	ENTRY(spl0)
	SETPRI(0)
	SET_SIZE(spl0)


	/* splx implementation */
	ENTRY(splx)
	jmp	do_splx		/* redirect to common splx code */
	SET_SIZE(splx)

#endif	/* __lint */

#if defined(__i386)

/*
 * Read and write the %gs register
 */

#if defined(__lint)

/*ARGSUSED*/
uint16_t
getgs(void)
{ return (0); }

/*ARGSUSED*/
void
setgs(uint16_t sel)
{}

#else	/* __lint */

	ENTRY(getgs)
	clr	%eax
	movw	%gs, %ax
	ret
	SET_SIZE(getgs)

	ENTRY(setgs)
	movw	4(%esp), %gs
	ret
	SET_SIZE(setgs)

#endif	/* __lint */
#endif	/* __i386 */

#if defined(__lint)

void
pc_reset(void)
{}

void
efi_reset(void)
{}

#else	/* __lint */

	ENTRY(wait_500ms)
#if defined(__amd64)
	pushq	%rbx
#elif defined(__i386)
	push	%ebx
#endif
	movl	$50000, %ebx
1:
	call	tenmicrosec
	decl	%ebx
	jnz	1b
#if defined(__amd64)
	popq	%rbx
#elif defined(__i386)
	pop	%ebx
#endif
	ret	
	SET_SIZE(wait_500ms)

#define	RESET_METHOD_KBC	1
#define	RESET_METHOD_PORT92	2
#define RESET_METHOD_PCI	4

	DGDEF3(pc_reset_methods, 4, 8)
	.long RESET_METHOD_KBC|RESET_METHOD_PORT92|RESET_METHOD_PCI;

	ENTRY(pc_reset)

#if defined(__i386)
	testl	$RESET_METHOD_KBC, pc_reset_methods
#elif defined(__amd64)
	testl	$RESET_METHOD_KBC, pc_reset_methods(%rip)
#endif
	jz	1f

	/
	/ Try the classic keyboard controller-triggered reset.
	/
	movw	$0x64, %dx
	movb	$0xfe, %al
	outb	(%dx)

	/ Wait up to 500 milliseconds here for the keyboard controller
	/ to pull the reset line.  On some systems where the keyboard
	/ controller is slow to pull the reset line, the next reset method
	/ may be executed (which may be bad if those systems hang when the
	/ next reset method is used, e.g. Ferrari 3400 (doesn't like port 92),
	/ and Ferrari 4000 (doesn't like the cf9 reset method))

	call	wait_500ms

1:
#if defined(__i386)
	testl	$RESET_METHOD_PORT92, pc_reset_methods
#elif defined(__amd64)
	testl	$RESET_METHOD_PORT92, pc_reset_methods(%rip)
#endif
	jz	3f

	/
	/ Try port 0x92 fast reset
	/
	movw	$0x92, %dx
	inb	(%dx)
	cmpb	$0xff, %al	/ If port's not there, we should get back 0xFF
	je	1f
	testb	$1, %al		/ If bit 0
	jz	2f		/ is clear, jump to perform the reset
	andb	$0xfe, %al	/ otherwise,
	outb	(%dx)		/ clear bit 0 first, then
2:
	orb	$1, %al		/ Set bit 0
	outb	(%dx)		/ and reset the system
1:

	call	wait_500ms

3:
#if defined(__i386)
	testl	$RESET_METHOD_PCI, pc_reset_methods
#elif defined(__amd64)
	testl	$RESET_METHOD_PCI, pc_reset_methods(%rip)
#endif
	jz	4f

	/ Try the PCI (soft) reset vector (should work on all modern systems,
	/ but has been shown to cause problems on 450NX systems, and some newer
	/ systems (e.g. ATI IXP400-equipped systems))
	/ When resetting via this method, 2 writes are required.  The first
	/ targets bit 1 (0=hard reset without power cycle, 1=hard reset with
	/ power cycle).
	/ The reset occurs on the second write, during bit 2's transition from
	/ 0->1.
	movw	$0xcf9, %dx
	movb	$0x2, %al	/ Reset mode = hard, no power cycle
	outb	(%dx)
	movb	$0x6, %al
	outb	(%dx)

	call	wait_500ms

4:
	/
	/ port 0xcf9 failed also.  Last-ditch effort is to
	/ triple-fault the CPU.
	/ Also, use triple fault for EFI firmware
	/
	ENTRY(efi_reset)
#if defined(__amd64)
	pushq	$0x0
	pushq	$0x0		/ IDT base of 0, limit of 0 + 2 unused bytes
	lidt	(%rsp)
#elif defined(__i386)
	pushl	$0x0
	pushl	$0x0		/ IDT base of 0, limit of 0 + 2 unused bytes
	lidt	(%esp)
#endif
	int	$0x0		/ Trigger interrupt, generate triple-fault

	cli
	hlt			/ Wait forever
	/*NOTREACHED*/
	SET_SIZE(efi_reset)
	SET_SIZE(pc_reset)

#endif	/* __lint */

/*
 * C callable in and out routines
 */

#if defined(__lint)

/* ARGSUSED */
void
outl(int port_address, uint32_t val)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(outl)
	movw	%di, %dx
	movl	%esi, %eax
	outl	(%dx)
	ret
	SET_SIZE(outl)

#elif defined(__i386)

	.set	PORT, 4
	.set	VAL, 8

	ENTRY(outl)
	movw	PORT(%esp), %dx
	movl	VAL(%esp), %eax
	outl	(%dx)
	ret
	SET_SIZE(outl)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/* ARGSUSED */
void
outw(int port_address, uint16_t val)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(outw)
	movw	%di, %dx
	movw	%si, %ax
	D16 outl (%dx)		/* XX64 why not outw? */
	ret
	SET_SIZE(outw)

#elif defined(__i386)

	ENTRY(outw)
	movw	PORT(%esp), %dx
	movw	VAL(%esp), %ax
	D16 outl (%dx)
	ret
	SET_SIZE(outw)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/* ARGSUSED */
void
outb(int port_address, uint8_t val)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(outb)
	movw	%di, %dx
	movb	%sil, %al
	outb	(%dx)
	ret
	SET_SIZE(outb)

#elif defined(__i386)

	ENTRY(outb)
	movw	PORT(%esp), %dx
	movb	VAL(%esp), %al
	outb	(%dx)
	ret
	SET_SIZE(outb)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/* ARGSUSED */
uint32_t
inl(int port_address)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(inl)
	xorl	%eax, %eax
	movw	%di, %dx
	inl	(%dx)
	ret
	SET_SIZE(inl)

#elif defined(__i386)

	ENTRY(inl)
	movw	PORT(%esp), %dx
	inl	(%dx)
	ret
	SET_SIZE(inl)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/* ARGSUSED */
uint16_t
inw(int port_address)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(inw)
	xorl	%eax, %eax
	movw	%di, %dx
	D16 inl	(%dx)
	ret
	SET_SIZE(inw)

#elif defined(__i386)

	ENTRY(inw)
	subl	%eax, %eax
	movw	PORT(%esp), %dx
	D16 inl	(%dx)
	ret
	SET_SIZE(inw)

#endif	/* __i386 */
#endif	/* __lint */


#if defined(__lint)

/* ARGSUSED */
uint8_t
inb(int port_address)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(inb)
	xorl	%eax, %eax
	movw	%di, %dx
	inb	(%dx)
	ret
	SET_SIZE(inb)

#elif defined(__i386)

	ENTRY(inb)
	subl    %eax, %eax
	movw	PORT(%esp), %dx
	inb	(%dx)
	ret
	SET_SIZE(inb)

#endif	/* __i386 */
#endif	/* __lint */


#if defined(__lint)

/* ARGSUSED */
void
repoutsw(int port, uint16_t *addr, int cnt)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(repoutsw)
	movl	%edx, %ecx
	movw	%di, %dx
	rep
	  D16 outsl
	ret
	SET_SIZE(repoutsw)

#elif defined(__i386)

	/*
	 * The arguments and saved registers are on the stack in the
	 *  following order:
	 *      |  cnt  |  +16
	 *      | *addr |  +12
	 *      | port  |  +8
	 *      |  eip  |  +4
	 *      |  esi  |  <-- %esp
	 * If additional values are pushed onto the stack, make sure
	 * to adjust the following constants accordingly.
	 */
	.set	PORT, 8
	.set	ADDR, 12
	.set	COUNT, 16

	ENTRY(repoutsw)
	pushl	%esi
	movl	PORT(%esp), %edx
	movl	ADDR(%esp), %esi
	movl	COUNT(%esp), %ecx
	rep
	  D16 outsl
	popl	%esi
	ret
	SET_SIZE(repoutsw)

#endif	/* __i386 */
#endif	/* __lint */


#if defined(__lint)

/* ARGSUSED */
void
repinsw(int port_addr, uint16_t *addr, int cnt)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(repinsw)
	movl	%edx, %ecx
	movw	%di, %dx
	rep
	  D16 insl
	ret
	SET_SIZE(repinsw)

#elif defined(__i386)

	ENTRY(repinsw)
	pushl	%edi
	movl	PORT(%esp), %edx
	movl	ADDR(%esp), %edi
	movl	COUNT(%esp), %ecx
	rep
	  D16 insl
	popl	%edi
	ret
	SET_SIZE(repinsw)

#endif	/* __i386 */
#endif	/* __lint */


#if defined(__lint)

/* ARGSUSED */
void
repinsb(int port, uint8_t *addr, int count)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(repinsb)
	movl	%edx, %ecx	
	movw	%di, %dx
	movq	%rsi, %rdi
	rep
	  insb
	ret		
	SET_SIZE(repinsb)

#elif defined(__i386)
	
	/*
	 * The arguments and saved registers are on the stack in the
	 *  following order:
	 *      |  cnt  |  +16
	 *      | *addr |  +12
	 *      | port  |  +8
	 *      |  eip  |  +4
	 *      |  esi  |  <-- %esp
	 * If additional values are pushed onto the stack, make sure
	 * to adjust the following constants accordingly.
	 */
	.set	IO_PORT, 8
	.set	IO_ADDR, 12
	.set	IO_COUNT, 16

	ENTRY(repinsb)
	pushl	%edi
	movl	IO_ADDR(%esp), %edi
	movl	IO_COUNT(%esp), %ecx
	movl	IO_PORT(%esp), %edx
	rep
	  insb
	popl	%edi
	ret
	SET_SIZE(repinsb)

#endif	/* __i386 */
#endif	/* __lint */


/*
 * Input a stream of 32-bit words.
 * NOTE: count is a DWORD count.
 */
#if defined(__lint)

/* ARGSUSED */
void
repinsd(int port, uint32_t *addr, int count)
{}

#else	/* __lint */

#if defined(__amd64)
	
	ENTRY(repinsd)
	movl	%edx, %ecx
	movw	%di, %dx
	movq	%rsi, %rdi
	rep
	  insl
	ret
	SET_SIZE(repinsd)

#elif defined(__i386)

	ENTRY(repinsd)
	pushl	%edi
	movl	IO_ADDR(%esp), %edi
	movl	IO_COUNT(%esp), %ecx
	movl	IO_PORT(%esp), %edx
	rep
	  insl
	popl	%edi
	ret
	SET_SIZE(repinsd)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Output a stream of bytes
 * NOTE: count is a byte count
 */
#if defined(__lint)

/* ARGSUSED */
void
repoutsb(int port, uint8_t *addr, int count)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(repoutsb)
	movl	%edx, %ecx
	movw	%di, %dx
	rep
	  outsb
	ret	
	SET_SIZE(repoutsb)

#elif defined(__i386)

	ENTRY(repoutsb)
	pushl	%esi
	movl	IO_ADDR(%esp), %esi
	movl	IO_COUNT(%esp), %ecx
	movl	IO_PORT(%esp), %edx
	rep
	  outsb
	popl	%esi
	ret
	SET_SIZE(repoutsb)

#endif	/* __i386 */	
#endif	/* __lint */

/*
 * Output a stream of 32-bit words
 * NOTE: count is a DWORD count
 */
#if defined(__lint)

/* ARGSUSED */
void
repoutsd(int port, uint32_t *addr, int count)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(repoutsd)
	movl	%edx, %ecx
	movw	%di, %dx
	rep
	  outsl
	ret	
	SET_SIZE(repoutsd)

#elif defined(__i386)

	ENTRY(repoutsd)
	pushl	%esi
	movl	IO_ADDR(%esp), %esi
	movl	IO_COUNT(%esp), %ecx
	movl	IO_PORT(%esp), %edx
	rep
	  outsl
	popl	%esi
	ret
	SET_SIZE(repoutsd)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * void int3(void)
 * void int18(void)
 * void int20(void)
 * void int_cmci(void)
 */

#if defined(__lint)

void
int3(void)
{}

void
int18(void)
{}

void
int20(void)
{}

void
int_cmci(void)
{}

#else	/* __lint */

	ENTRY(int3)
	int	$T_BPTFLT
	ret
	SET_SIZE(int3)

	ENTRY(int18)
	int	$T_MCE
	ret
	SET_SIZE(int18)

	ENTRY(int20)
	movl	boothowto, %eax
	andl	$RB_DEBUG, %eax
	jz	1f

	int	$T_DBGENTR
1:
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(int20)

	ENTRY(int_cmci)
	int	$T_ENOEXTFLT
	ret
	SET_SIZE(int_cmci)

#endif	/* __lint */

#if defined(__lint)

/* ARGSUSED */
int
scanc(size_t size, uchar_t *cp, uchar_t *table, uchar_t mask)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(scanc)
					/* rdi == size */
					/* rsi == cp */
					/* rdx == table */
					/* rcx == mask */
	addq	%rsi, %rdi		/* end = &cp[size] */
.scanloop:
	cmpq	%rdi, %rsi		/* while (cp < end */
	jnb	.scandone
	movzbq	(%rsi), %r8		/* %r8 = *cp */
	incq	%rsi			/* cp++ */
	testb	%cl, (%r8, %rdx)
	jz	.scanloop		/*  && (table[*cp] & mask) == 0) */
	decq	%rsi			/* (fix post-increment) */
.scandone:
	movl	%edi, %eax
	subl	%esi, %eax		/* return (end - cp) */
	ret
	SET_SIZE(scanc)

#elif defined(__i386)

	ENTRY(scanc)
	pushl	%edi
	pushl	%esi
	movb	24(%esp), %cl		/* mask = %cl */
	movl	16(%esp), %esi		/* cp = %esi */
	movl	20(%esp), %edx		/* table = %edx */
	movl	%esi, %edi
	addl	12(%esp), %edi		/* end = &cp[size]; */
.scanloop:
	cmpl	%edi, %esi		/* while (cp < end */
	jnb	.scandone
	movzbl	(%esi),  %eax		/* %al = *cp */
	incl	%esi			/* cp++ */
	movb	(%edx,  %eax), %al	/* %al = table[*cp] */
	testb	%al, %cl
	jz	.scanloop		/*   && (table[*cp] & mask) == 0) */
	dec	%esi			/* post-incremented */
.scandone:
	movl	%edi, %eax
	subl	%esi, %eax		/* return (end - cp) */
	popl	%esi
	popl	%edi
	ret
	SET_SIZE(scanc)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * Replacement functions for ones that are normally inlined.
 * In addition to the copy in i86.il, they are defined here just in case.
 */

#if defined(__lint)

ulong_t
intr_clear(void)
{ return (0); }

ulong_t
clear_int_flag(void)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(intr_clear)
	ENTRY(clear_int_flag)
	pushfq
	popq	%rax
#if defined(__xpv)
	leaq	xpv_panicking, %rdi
	movl	(%rdi), %edi
	cmpl	$0, %edi
	jne	2f
	CLIRET(%rdi, %dl)	/* returns event mask in %dl */
	/*
	 * Synthesize the PS_IE bit from the event mask bit
	 */
	andq    $_BITNOT(PS_IE), %rax
	testb	$1, %dl
	jnz	1f
	orq	$PS_IE, %rax
1:
	ret
2:
#endif
	CLI(%rdi)
	ret
	SET_SIZE(clear_int_flag)
	SET_SIZE(intr_clear)

#elif defined(__i386)

	ENTRY(intr_clear)
	ENTRY(clear_int_flag)
	pushfl
	popl	%eax
#if defined(__xpv)
	leal	xpv_panicking, %edx
	movl	(%edx), %edx
	cmpl	$0, %edx
	jne	2f
	CLIRET(%edx, %cl)	/* returns event mask in %cl */
	/*
	 * Synthesize the PS_IE bit from the event mask bit
	 */
	andl    $_BITNOT(PS_IE), %eax
	testb	$1, %cl
	jnz	1f
	orl	$PS_IE, %eax
1:
	ret
2:
#endif
	CLI(%edx)
	ret
	SET_SIZE(clear_int_flag)
	SET_SIZE(intr_clear)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

struct cpu *
curcpup(void)
{ return 0; }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(curcpup)
	movq	%gs:CPU_SELF, %rax
	ret
	SET_SIZE(curcpup)

#elif defined(__i386)

	ENTRY(curcpup)
	movl	%gs:CPU_SELF, %eax
	ret
	SET_SIZE(curcpup)

#endif	/* __i386 */
#endif	/* __lint */

/* htonll(), ntohll(), htonl(), ntohl(), htons(), ntohs()
 * These functions reverse the byte order of the input parameter and returns
 * the result.  This is to convert the byte order from host byte order
 * (little endian) to network byte order (big endian), or vice versa.
 */

#if defined(__lint)

uint64_t
htonll(uint64_t i)
{ return (i); }

uint64_t
ntohll(uint64_t i)
{ return (i); }

uint32_t
htonl(uint32_t i)
{ return (i); }

uint32_t
ntohl(uint32_t i)
{ return (i); }

uint16_t
htons(uint16_t i)
{ return (i); }

uint16_t
ntohs(uint16_t i)
{ return (i); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(htonll)
	ALTENTRY(ntohll)
	movq	%rdi, %rax
	bswapq	%rax
	ret
	SET_SIZE(ntohll)
	SET_SIZE(htonll)

	/* XX64 there must be shorter sequences for this */
	ENTRY(htonl)
	ALTENTRY(ntohl)
	movl	%edi, %eax
	bswap	%eax
	ret
	SET_SIZE(ntohl)
	SET_SIZE(htonl)

	/* XX64 there must be better sequences for this */
	ENTRY(htons)
	ALTENTRY(ntohs)
	movl	%edi, %eax
	bswap	%eax
	shrl	$16, %eax
	ret
	SET_SIZE(ntohs)
	SET_SIZE(htons)

#elif defined(__i386)

	ENTRY(htonll)
	ALTENTRY(ntohll)
	movl	4(%esp), %edx
	movl	8(%esp), %eax
	bswap	%edx
	bswap	%eax
	ret
	SET_SIZE(ntohll)
	SET_SIZE(htonll)

	ENTRY(htonl)
	ALTENTRY(ntohl)
	movl	4(%esp), %eax
	bswap	%eax
	ret
	SET_SIZE(ntohl)
	SET_SIZE(htonl)

	ENTRY(htons)
	ALTENTRY(ntohs)
	movl	4(%esp), %eax
	bswap	%eax
	shrl	$16, %eax
	ret
	SET_SIZE(ntohs)
	SET_SIZE(htons)

#endif	/* __i386 */
#endif	/* __lint */


#if defined(__lint)

/* ARGSUSED */
void
intr_restore(ulong_t i)
{ return; }

/* ARGSUSED */
void
restore_int_flag(ulong_t i)
{ return; }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(intr_restore)
	ENTRY(restore_int_flag)
	testq	$PS_IE, %rdi
	jz	1f
#if defined(__xpv)
	leaq	xpv_panicking, %rsi
	movl	(%rsi), %esi
	cmpl	$0, %esi
	jne	1f
	/*
	 * Since we're -really- running unprivileged, our attempt
	 * to change the state of the IF bit will be ignored.
	 * The virtual IF bit is tweaked by CLI and STI.
	 */
	IE_TO_EVENT_MASK(%rsi, %rdi)
#else
	sti
#endif
1:
	ret
	SET_SIZE(restore_int_flag)
	SET_SIZE(intr_restore)

#elif defined(__i386)

	ENTRY(intr_restore)
	ENTRY(restore_int_flag)
	testl	$PS_IE, 4(%esp)
	jz	1f
#if defined(__xpv)
	leal	xpv_panicking, %edx
	movl	(%edx), %edx
	cmpl	$0, %edx
	jne	1f
	/*
	 * Since we're -really- running unprivileged, our attempt
	 * to change the state of the IF bit will be ignored.
	 * The virtual IF bit is tweaked by CLI and STI.
	 */
	IE_TO_EVENT_MASK(%edx, 4(%esp))
#else
	sti
#endif
1:
	ret
	SET_SIZE(restore_int_flag)
	SET_SIZE(intr_restore)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

void
sti(void)
{}

void
cli(void)
{}

#else	/* __lint */

	ENTRY(sti)
	STI
	ret
	SET_SIZE(sti)

	ENTRY(cli)
#if defined(__amd64)
	CLI(%rax)
#elif defined(__i386)
	CLI(%eax)
#endif	/* __i386 */
	ret
	SET_SIZE(cli)

#endif	/* __lint */

#if defined(__lint)

dtrace_icookie_t
dtrace_interrupt_disable(void)
{ return (0); }

#else   /* __lint */

#if defined(__amd64)

	ENTRY(dtrace_interrupt_disable)
	pushfq
	popq	%rax
#if defined(__xpv)
	leaq	xpv_panicking, %rdi
	movl	(%rdi), %edi
	cmpl	$0, %edi
	jne	.dtrace_interrupt_disable_done
	CLIRET(%rdi, %dl)	/* returns event mask in %dl */
	/*
	 * Synthesize the PS_IE bit from the event mask bit
	 */
	andq    $_BITNOT(PS_IE), %rax
	testb	$1, %dl
	jnz	.dtrace_interrupt_disable_done
	orq	$PS_IE, %rax
#else
	CLI(%rdx)
#endif
.dtrace_interrupt_disable_done:
	ret
	SET_SIZE(dtrace_interrupt_disable)

#elif defined(__i386)
		
	ENTRY(dtrace_interrupt_disable)
	pushfl
	popl	%eax
#if defined(__xpv)
	leal	xpv_panicking, %edx
	movl	(%edx), %edx
	cmpl	$0, %edx
	jne	.dtrace_interrupt_disable_done
	CLIRET(%edx, %cl)	/* returns event mask in %cl */
	/*
	 * Synthesize the PS_IE bit from the event mask bit
	 */
	andl    $_BITNOT(PS_IE), %eax
	testb	$1, %cl
	jnz	.dtrace_interrupt_disable_done
	orl	$PS_IE, %eax
#else
	CLI(%edx)
#endif
.dtrace_interrupt_disable_done:
	ret
	SET_SIZE(dtrace_interrupt_disable)

#endif	/* __i386 */	
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void
dtrace_interrupt_enable(dtrace_icookie_t cookie)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(dtrace_interrupt_enable)
	pushq	%rdi
	popfq
#if defined(__xpv)
	leaq	xpv_panicking, %rdx
	movl	(%rdx), %edx
	cmpl	$0, %edx
	jne	.dtrace_interrupt_enable_done
	/*
	 * Since we're -really- running unprivileged, our attempt
	 * to change the state of the IF bit will be ignored. The
	 * virtual IF bit is tweaked by CLI and STI.
	 */
	IE_TO_EVENT_MASK(%rdx, %rdi)
#endif
.dtrace_interrupt_enable_done:
	ret
	SET_SIZE(dtrace_interrupt_enable)

#elif defined(__i386)
		
	ENTRY(dtrace_interrupt_enable)
	movl	4(%esp), %eax
	pushl	%eax
	popfl
#if defined(__xpv)
	leal	xpv_panicking, %edx
	movl	(%edx), %edx
	cmpl	$0, %edx
	jne	.dtrace_interrupt_enable_done
	/*
	 * Since we're -really- running unprivileged, our attempt
	 * to change the state of the IF bit will be ignored. The
	 * virtual IF bit is tweaked by CLI and STI.
	 */
	IE_TO_EVENT_MASK(%edx, %eax)
#endif
.dtrace_interrupt_enable_done:
	ret
	SET_SIZE(dtrace_interrupt_enable)

#endif	/* __i386 */	
#endif	/* __lint */


#if defined(lint)

void
dtrace_membar_producer(void)
{}

void
dtrace_membar_consumer(void)
{}

#else	/* __lint */

	ENTRY(dtrace_membar_producer)
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(dtrace_membar_producer)

	ENTRY(dtrace_membar_consumer)
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(dtrace_membar_consumer)

#endif	/* __lint */

#if defined(__lint)

kthread_id_t
threadp(void)
{ return ((kthread_id_t)0); }

#else	/* __lint */

#if defined(__amd64)
	
	ENTRY(threadp)
	movq	%gs:CPU_THREAD, %rax
	ret
	SET_SIZE(threadp)

#elif defined(__i386)

	ENTRY(threadp)
	movl	%gs:CPU_THREAD, %eax
	ret
	SET_SIZE(threadp)

#endif	/* __i386 */
#endif	/* __lint */

/*
 *   Checksum routine for Internet Protocol Headers
 */

#if defined(__lint)

/* ARGSUSED */
unsigned int
ip_ocsum(
	ushort_t *address,	/* ptr to 1st message buffer */
	int halfword_count,	/* length of data */
	unsigned int sum)	/* partial checksum */
{ 
	int		i;
	unsigned int	psum = 0;	/* partial sum */

	for (i = 0; i < halfword_count; i++, address++) {
		psum += *address;
	}

	while ((psum >> 16) != 0) {
		psum = (psum & 0xffff) + (psum >> 16);
	}

	psum += sum;

	while ((psum >> 16) != 0) {
		psum = (psum & 0xffff) + (psum >> 16);
	}

	return (psum);
}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(ip_ocsum)
	pushq	%rbp
	movq	%rsp, %rbp
#ifdef DEBUG
	movq	postbootkernelbase(%rip), %rax
	cmpq	%rax, %rdi
	jnb	1f
	xorl	%eax, %eax
	movq	%rdi, %rsi
	leaq	.ip_ocsum_panic_msg(%rip), %rdi
	call	panic
	/*NOTREACHED*/
.ip_ocsum_panic_msg:
	.string	"ip_ocsum: address 0x%p below kernelbase\n"
1:
#endif
	movl	%esi, %ecx	/* halfword_count */
	movq	%rdi, %rsi	/* address */
				/* partial sum in %edx */
	xorl	%eax, %eax
	testl	%ecx, %ecx
	jz	.ip_ocsum_done
	testq	$3, %rsi
	jnz	.ip_csum_notaligned
.ip_csum_aligned:	/* XX64 opportunities for 8-byte operations? */
.next_iter:
	/* XX64 opportunities for prefetch? */
	/* XX64 compute csum with 64 bit quantities? */
	subl	$32, %ecx
	jl	.less_than_32

	addl	0(%rsi), %edx
.only60:
	adcl	4(%rsi), %eax
.only56:
	adcl	8(%rsi), %edx
.only52:
	adcl	12(%rsi), %eax
.only48:
	adcl	16(%rsi), %edx
.only44:
	adcl	20(%rsi), %eax
.only40:
	adcl	24(%rsi), %edx
.only36:
	adcl	28(%rsi), %eax
.only32:
	adcl	32(%rsi), %edx
.only28:
	adcl	36(%rsi), %eax
.only24:
	adcl	40(%rsi), %edx
.only20:
	adcl	44(%rsi), %eax
.only16:
	adcl	48(%rsi), %edx
.only12:
	adcl	52(%rsi), %eax
.only8:
	adcl	56(%rsi), %edx
.only4:
	adcl	60(%rsi), %eax	/* could be adding -1 and -1 with a carry */
.only0:
	adcl	$0, %eax	/* could be adding -1 in eax with a carry */
	adcl	$0, %eax

	addq	$64, %rsi
	testl	%ecx, %ecx
	jnz	.next_iter

.ip_ocsum_done:
	addl	%eax, %edx
	adcl	$0, %edx
	movl	%edx, %eax	/* form a 16 bit checksum by */
	shrl	$16, %eax	/* adding two halves of 32 bit checksum */
	addw	%dx, %ax
	adcw	$0, %ax
	andl	$0xffff, %eax
	leave
	ret

.ip_csum_notaligned:
	xorl	%edi, %edi
	movw	(%rsi), %di
	addl	%edi, %edx
	adcl	$0, %edx
	addq	$2, %rsi
	decl	%ecx
	jmp	.ip_csum_aligned

.less_than_32:
	addl	$32, %ecx
	testl	$1, %ecx
	jz	.size_aligned
	andl	$0xfe, %ecx
	movzwl	(%rsi, %rcx, 2), %edi
	addl	%edi, %edx
	adcl	$0, %edx
.size_aligned:
	movl	%ecx, %edi
	shrl	$1, %ecx
	shl	$1, %edi
	subq	$64, %rdi
	addq	%rdi, %rsi
	leaq    .ip_ocsum_jmptbl(%rip), %rdi
	leaq	(%rdi, %rcx, 8), %rdi
	xorl	%ecx, %ecx
	clc
	jmp 	*(%rdi)

	.align	8
.ip_ocsum_jmptbl:
	.quad	.only0, .only4, .only8, .only12, .only16, .only20
	.quad	.only24, .only28, .only32, .only36, .only40, .only44
	.quad	.only48, .only52, .only56, .only60
	SET_SIZE(ip_ocsum)

#elif defined(__i386)

	ENTRY(ip_ocsum)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%ebx
	pushl	%esi
	pushl	%edi
	movl	12(%ebp), %ecx	/* count of half words */
	movl	16(%ebp), %edx	/* partial checksum */
	movl	8(%ebp), %esi
	xorl	%eax, %eax
	testl	%ecx, %ecx
	jz	.ip_ocsum_done

	testl	$3, %esi
	jnz	.ip_csum_notaligned
.ip_csum_aligned:
.next_iter:
	subl	$32, %ecx
	jl	.less_than_32

	addl	0(%esi), %edx
.only60:
	adcl	4(%esi), %eax
.only56:
	adcl	8(%esi), %edx
.only52:
	adcl	12(%esi), %eax
.only48:
	adcl	16(%esi), %edx
.only44:
	adcl	20(%esi), %eax
.only40:
	adcl	24(%esi), %edx
.only36:
	adcl	28(%esi), %eax
.only32:
	adcl	32(%esi), %edx
.only28:
	adcl	36(%esi), %eax
.only24:
	adcl	40(%esi), %edx
.only20:
	adcl	44(%esi), %eax
.only16:
	adcl	48(%esi), %edx
.only12:
	adcl	52(%esi), %eax
.only8:
	adcl	56(%esi), %edx
.only4:
	adcl	60(%esi), %eax	/* We could be adding -1 and -1 with a carry */
.only0:
	adcl	$0, %eax	/* we could be adding -1 in eax with a carry */
	adcl	$0, %eax

	addl	$64, %esi
	andl	%ecx, %ecx
	jnz	.next_iter

.ip_ocsum_done:
	addl	%eax, %edx
	adcl	$0, %edx
	movl	%edx, %eax	/* form a 16 bit checksum by */
	shrl	$16, %eax	/* adding two halves of 32 bit checksum */
	addw	%dx, %ax
	adcw	$0, %ax
	andl	$0xffff, %eax
	popl	%edi		/* restore registers */
	popl	%esi
	popl	%ebx
	leave
	ret

.ip_csum_notaligned:
	xorl	%edi, %edi
	movw	(%esi), %di
	addl	%edi, %edx
	adcl	$0, %edx
	addl	$2, %esi
	decl	%ecx
	jmp	.ip_csum_aligned

.less_than_32:
	addl	$32, %ecx
	testl	$1, %ecx
	jz	.size_aligned
	andl	$0xfe, %ecx
	movzwl	(%esi, %ecx, 2), %edi
	addl	%edi, %edx
	adcl	$0, %edx
.size_aligned:
	movl	%ecx, %edi
	shrl	$1, %ecx
	shl	$1, %edi
	subl	$64, %edi
	addl	%edi, %esi
	movl	$.ip_ocsum_jmptbl, %edi
	lea	(%edi, %ecx, 4), %edi
	xorl	%ecx, %ecx
	clc
	jmp 	*(%edi)
	SET_SIZE(ip_ocsum)

	.data
	.align	4

.ip_ocsum_jmptbl:
	.long	.only0, .only4, .only8, .only12, .only16, .only20
	.long	.only24, .only28, .only32, .only36, .only40, .only44
	.long	.only48, .only52, .only56, .only60

	
#endif	/* __i386 */		
#endif	/* __lint */

/*
 * multiply two long numbers and yield a u_longlong_t result, callable from C.
 * Provided to manipulate hrtime_t values.
 */
#if defined(__lint)

/* result = a * b; */

/* ARGSUSED */
unsigned long long
mul32(uint_t a, uint_t b)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(mul32)
	xorl	%edx, %edx	/* XX64 joe, paranoia? */
	movl	%edi, %eax
	mull	%esi
	shlq	$32, %rdx	
	orq	%rdx, %rax
	ret
	SET_SIZE(mul32)

#elif defined(__i386)

	ENTRY(mul32)
	movl	8(%esp), %eax
	movl	4(%esp), %ecx
	mull	%ecx
	ret
	SET_SIZE(mul32)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(notused)
#if defined(__lint)
/* ARGSUSED */
void
load_pte64(uint64_t *pte, uint64_t pte_value)
{}
#else	/* __lint */
	.globl load_pte64
load_pte64:
	movl	4(%esp), %eax
	movl	8(%esp), %ecx
	movl	12(%esp), %edx
	movl	%edx, 4(%eax)
	movl	%ecx, (%eax)
	ret
#endif	/* __lint */
#endif	/* notused */

#if defined(__lint)

/*ARGSUSED*/
void
scan_memory(caddr_t addr, size_t size)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(scan_memory)
	shrq	$3, %rsi	/* convert %rsi from byte to quadword count */
	jz	.scanm_done
	movq	%rsi, %rcx	/* move count into rep control register */
	movq	%rdi, %rsi	/* move addr into lodsq control reg. */
	rep lodsq		/* scan the memory range */
.scanm_done:
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(scan_memory)

#elif defined(__i386)

	ENTRY(scan_memory)
	pushl	%ecx
	pushl	%esi
	movl	16(%esp), %ecx	/* move 2nd arg into rep control register */
	shrl	$2, %ecx	/* convert from byte count to word count */
	jz	.scanm_done
	movl	12(%esp), %esi	/* move 1st arg into lodsw control register */
	.byte	0xf3		/* rep prefix.  lame assembler.  sigh. */
	lodsl
.scanm_done:
	popl	%esi
	popl	%ecx
	ret
	SET_SIZE(scan_memory)

#endif	/* __i386 */
#endif	/* __lint */


#if defined(__lint)

/*ARGSUSED */
int
lowbit(ulong_t i)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(lowbit)
	movl	$-1, %eax
	bsfq	%rdi, %rdi
	cmovnz	%edi, %eax
	incl	%eax
	ret
	SET_SIZE(lowbit)

#elif defined(__i386)

	ENTRY(lowbit)
	bsfl	4(%esp), %eax
	jz	0f
	incl	%eax
	ret
0:
	xorl	%eax, %eax
	ret
	SET_SIZE(lowbit)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
int
highbit(ulong_t i)
{ return (0); }

/*ARGSUSED*/
int
highbit64(uint64_t i)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY(highbit)
	ALTENTRY(highbit64)
	movl	$-1, %eax
	bsrq	%rdi, %rdi
	cmovnz	%edi, %eax
	incl	%eax
	ret
	SET_SIZE(highbit64)
	SET_SIZE(highbit)

#elif defined(__i386)

	ENTRY(highbit)
	bsrl	4(%esp), %eax
	jz	0f
	incl	%eax
	ret
0:
	xorl	%eax, %eax
	ret    
	SET_SIZE(highbit)

	ENTRY(highbit64)
	bsrl	8(%esp), %eax
	jz	highbit
	addl	$33, %eax
	ret
	SET_SIZE(highbit64)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
uint64_t
rdmsr(uint_t r)
{ return (0); }

/*ARGSUSED*/
void
wrmsr(uint_t r, const uint64_t val)
{}

/*ARGSUSED*/
uint64_t
xrdmsr(uint_t r)
{ return (0); }

/*ARGSUSED*/
void
xwrmsr(uint_t r, const uint64_t val)
{}

void
invalidate_cache(void)
{}

/*ARGSUSED*/
uint64_t
get_xcr(uint_t r)
{ return (0); }

/*ARGSUSED*/
void
set_xcr(uint_t r, const uint64_t val)
{}

#else  /* __lint */

#define	XMSR_ACCESS_VAL		$0x9c5a203a

#if defined(__amd64)
	
	ENTRY(rdmsr)
	movl	%edi, %ecx
	rdmsr
	shlq	$32, %rdx
	orq	%rdx, %rax
	ret
	SET_SIZE(rdmsr)

	ENTRY(wrmsr)
	movq	%rsi, %rdx
	shrq	$32, %rdx
	movl	%esi, %eax
	movl	%edi, %ecx
	wrmsr
	ret
	SET_SIZE(wrmsr)

	ENTRY(xrdmsr)
	pushq	%rbp
	movq	%rsp, %rbp
	movl	%edi, %ecx
	movl	XMSR_ACCESS_VAL, %edi	/* this value is needed to access MSR */
	rdmsr
	shlq	$32, %rdx
	orq	%rdx, %rax
	leave
	ret
	SET_SIZE(xrdmsr)

	ENTRY(xwrmsr)
	pushq	%rbp
	movq	%rsp, %rbp
	movl	%edi, %ecx
	movl	XMSR_ACCESS_VAL, %edi	/* this value is needed to access MSR */
	movq	%rsi, %rdx
	shrq	$32, %rdx
	movl	%esi, %eax
	wrmsr
	leave
	ret
	SET_SIZE(xwrmsr)

	ENTRY(get_xcr)
	movl	%edi, %ecx
	#xgetbv
	.byte	0x0f,0x01,0xd0
	shlq	$32, %rdx
	orq	%rdx, %rax
	ret
	SET_SIZE(get_xcr)

	ENTRY(set_xcr)
	movq	%rsi, %rdx
	shrq	$32, %rdx
	movl	%esi, %eax
	movl	%edi, %ecx
	#xsetbv
	.byte	0x0f,0x01,0xd1
	ret
	SET_SIZE(set_xcr)

#elif defined(__i386)

	ENTRY(rdmsr)
	movl	4(%esp), %ecx
	rdmsr
	ret
	SET_SIZE(rdmsr)

	ENTRY(wrmsr)
	movl	4(%esp), %ecx
	movl	8(%esp), %eax
	movl	12(%esp), %edx 
	wrmsr
	ret
	SET_SIZE(wrmsr)

	ENTRY(xrdmsr)
	pushl	%ebp
	movl	%esp, %ebp
	movl	8(%esp), %ecx
	pushl	%edi
	movl	XMSR_ACCESS_VAL, %edi	/* this value is needed to access MSR */
	rdmsr
	popl	%edi
	leave
	ret
	SET_SIZE(xrdmsr)

	ENTRY(xwrmsr)
	pushl	%ebp
	movl	%esp, %ebp
	movl	8(%esp), %ecx
	movl	12(%esp), %eax
	movl	16(%esp), %edx 
	pushl	%edi
	movl	XMSR_ACCESS_VAL, %edi	/* this value is needed to access MSR */
	wrmsr
	popl	%edi
	leave
	ret
	SET_SIZE(xwrmsr)

	ENTRY(get_xcr)
	movl	4(%esp), %ecx
	#xgetbv
	.byte	0x0f,0x01,0xd0
	ret
	SET_SIZE(get_xcr)

	ENTRY(set_xcr)
	movl	4(%esp), %ecx
	movl	8(%esp), %eax
	movl	12(%esp), %edx
	#xsetbv
	.byte	0x0f,0x01,0xd1
	ret
	SET_SIZE(set_xcr)

#endif	/* __i386 */

	ENTRY(invalidate_cache)
	wbinvd
	ret
	SET_SIZE(invalidate_cache)

#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void
getcregs(struct cregs *crp)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(getcregs)
#if defined(__xpv)
	/*
	 * Only a few of the hardware control registers or descriptor tables
	 * are directly accessible to us, so just zero the structure.
	 *
	 * XXPV	Perhaps it would be helpful for the hypervisor to return
	 *	virtualized versions of these for post-mortem use.
	 *	(Need to reevaluate - perhaps it already does!)
	 */
	pushq	%rdi		/* save *crp */
	movq	$CREGSZ, %rsi
	call	bzero
	popq	%rdi

	/*
	 * Dump what limited information we can
	 */
	movq	%cr0, %rax
	movq	%rax, CREG_CR0(%rdi)	/* cr0 */
	movq	%cr2, %rax
	movq	%rax, CREG_CR2(%rdi)	/* cr2 */
	movq	%cr3, %rax
	movq	%rax, CREG_CR3(%rdi)	/* cr3 */
	movq	%cr4, %rax
	movq	%rax, CREG_CR4(%rdi)	/* cr4 */

#else	/* __xpv */

#define	GETMSR(r, off, d)	\
	movl	$r, %ecx;	\
	rdmsr;			\
	movl	%eax, off(d);	\
	movl	%edx, off+4(d)

	xorl	%eax, %eax
	movq	%rax, CREG_GDT+8(%rdi)
	sgdt	CREG_GDT(%rdi)		/* 10 bytes */
	movq	%rax, CREG_IDT+8(%rdi)
	sidt	CREG_IDT(%rdi)		/* 10 bytes */
	movq	%rax, CREG_LDT(%rdi)
	sldt	CREG_LDT(%rdi)		/* 2 bytes */
	movq	%rax, CREG_TASKR(%rdi)
	str	CREG_TASKR(%rdi)	/* 2 bytes */
	movq	%cr0, %rax
	movq	%rax, CREG_CR0(%rdi)	/* cr0 */
	movq	%cr2, %rax
	movq	%rax, CREG_CR2(%rdi)	/* cr2 */
	movq	%cr3, %rax
	movq	%rax, CREG_CR3(%rdi)	/* cr3 */
	movq	%cr4, %rax
	movq	%rax, CREG_CR4(%rdi)	/* cr4 */
	movq	%cr8, %rax
	movq	%rax, CREG_CR8(%rdi)	/* cr8 */
	GETMSR(MSR_AMD_KGSBASE, CREG_KGSBASE, %rdi)
	GETMSR(MSR_AMD_EFER, CREG_EFER, %rdi)
#endif	/* __xpv */
	ret
	SET_SIZE(getcregs)

#undef GETMSR

#elif defined(__i386)

	ENTRY_NP(getcregs)
#if defined(__xpv)
	/*
	 * Only a few of the hardware control registers or descriptor tables
	 * are directly accessible to us, so just zero the structure.
	 *
	 * XXPV	Perhaps it would be helpful for the hypervisor to return
	 *	virtualized versions of these for post-mortem use.
	 *	(Need to reevaluate - perhaps it already does!)
	 */
	movl	4(%esp), %edx
	pushl	$CREGSZ
	pushl	%edx
	call	bzero
	addl	$8, %esp
	movl	4(%esp), %edx

	/*
	 * Dump what limited information we can
	 */
	movl	%cr0, %eax
	movl	%eax, CREG_CR0(%edx)	/* cr0 */
	movl	%cr2, %eax
	movl	%eax, CREG_CR2(%edx)	/* cr2 */
	movl	%cr3, %eax
	movl	%eax, CREG_CR3(%edx)	/* cr3 */
	movl	%cr4, %eax
	movl	%eax, CREG_CR4(%edx)	/* cr4 */

#else	/* __xpv */

	movl	4(%esp), %edx
	movw	$0, CREG_GDT+6(%edx)
	movw	$0, CREG_IDT+6(%edx)
	sgdt	CREG_GDT(%edx)		/* gdt */
	sidt	CREG_IDT(%edx)		/* idt */
	sldt	CREG_LDT(%edx)		/* ldt */
	str	CREG_TASKR(%edx)	/* task */
	movl	%cr0, %eax
	movl	%eax, CREG_CR0(%edx)	/* cr0 */
	movl	%cr2, %eax
	movl	%eax, CREG_CR2(%edx)	/* cr2 */
	movl	%cr3, %eax
	movl	%eax, CREG_CR3(%edx)	/* cr3 */
	bt	$X86FSET_LARGEPAGE, x86_featureset
	jnc	.nocr4
	movl	%cr4, %eax
	movl	%eax, CREG_CR4(%edx)	/* cr4 */
	jmp	.skip
.nocr4:
	movl	$0, CREG_CR4(%edx)
.skip:
#endif
	ret
	SET_SIZE(getcregs)

#endif	/* __i386 */
#endif	/* __lint */


/*
 * A panic trigger is a word which is updated atomically and can only be set
 * once.  We atomically store 0xDEFACEDD and load the old value.  If the
 * previous value was 0, we succeed and return 1; otherwise return 0.
 * This allows a partially corrupt trigger to still trigger correctly.  DTrace
 * has its own version of this function to allow it to panic correctly from
 * probe context.
 */
#if defined(__lint)

/*ARGSUSED*/
int
panic_trigger(int *tp)
{ return (0); }

/*ARGSUSED*/
int
dtrace_panic_trigger(int *tp)
{ return (0); }

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(panic_trigger)
	xorl	%eax, %eax
	movl	$0xdefacedd, %edx
	lock
	  xchgl	%edx, (%rdi)
	cmpl	$0, %edx
	je	0f 
	movl	$0, %eax
	ret
0:	movl	$1, %eax
	ret
	SET_SIZE(panic_trigger)
	
	ENTRY_NP(dtrace_panic_trigger)
	xorl	%eax, %eax
	movl	$0xdefacedd, %edx
	lock
	  xchgl	%edx, (%rdi)
	cmpl	$0, %edx
	je	0f
	movl	$0, %eax
	ret
0:	movl	$1, %eax
	ret
	SET_SIZE(dtrace_panic_trigger)

#elif defined(__i386)

	ENTRY_NP(panic_trigger)
	movl	4(%esp), %edx		/ %edx = address of trigger
	movl	$0xdefacedd, %eax	/ %eax = 0xdefacedd
	lock				/ assert lock
	xchgl %eax, (%edx)		/ exchange %eax and the trigger
	cmpl	$0, %eax		/ if (%eax == 0x0)
	je	0f			/   return (1);
	movl	$0, %eax		/ else
	ret				/   return (0);
0:	movl	$1, %eax
	ret
	SET_SIZE(panic_trigger)

	ENTRY_NP(dtrace_panic_trigger)
	movl	4(%esp), %edx		/ %edx = address of trigger
	movl	$0xdefacedd, %eax	/ %eax = 0xdefacedd
	lock				/ assert lock
	xchgl %eax, (%edx)		/ exchange %eax and the trigger
	cmpl	$0, %eax		/ if (%eax == 0x0)
	je	0f			/   return (1);
	movl	$0, %eax		/ else
	ret				/   return (0);
0:	movl	$1, %eax
	ret
	SET_SIZE(dtrace_panic_trigger)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * The panic() and cmn_err() functions invoke vpanic() as a common entry point
 * into the panic code implemented in panicsys().  vpanic() is responsible
 * for passing through the format string and arguments, and constructing a
 * regs structure on the stack into which it saves the current register
 * values.  If we are not dying due to a fatal trap, these registers will
 * then be preserved in panicbuf as the current processor state.  Before
 * invoking panicsys(), vpanic() activates the first panic trigger (see
 * common/os/panic.c) and switches to the panic_stack if successful.  Note that
 * DTrace takes a slightly different panic path if it must panic from probe
 * context.  Instead of calling panic, it calls into dtrace_vpanic(), which
 * sets up the initial stack as vpanic does, calls dtrace_panic_trigger(), and
 * branches back into vpanic().
 */
#if defined(__lint)

/*ARGSUSED*/
void
vpanic(const char *format, va_list alist)
{}

/*ARGSUSED*/
void
dtrace_vpanic(const char *format, va_list alist)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(vpanic)			/* Initial stack layout: */
	
	pushq	%rbp				/* | %rip | 	0x60	*/
	movq	%rsp, %rbp			/* | %rbp |	0x58	*/
	pushfq					/* | rfl  |	0x50	*/
	pushq	%r11				/* | %r11 |	0x48	*/
	pushq	%r10				/* | %r10 |	0x40	*/
	pushq	%rbx				/* | %rbx |	0x38	*/
	pushq	%rax				/* | %rax |	0x30	*/
	pushq	%r9				/* | %r9  |	0x28	*/
	pushq	%r8				/* | %r8  |	0x20	*/
	pushq	%rcx				/* | %rcx |	0x18	*/
	pushq	%rdx				/* | %rdx |	0x10	*/
	pushq	%rsi				/* | %rsi |	0x8 alist */
	pushq	%rdi				/* | %rdi |	0x0 format */

	movq	%rsp, %rbx			/* %rbx = current %rsp */

	leaq	panic_quiesce(%rip), %rdi	/* %rdi = &panic_quiesce */
	call	panic_trigger			/* %eax = panic_trigger() */

vpanic_common:
	/*
	 * The panic_trigger result is in %eax from the call above, and
	 * dtrace_panic places it in %eax before branching here.
	 * The rdmsr instructions that follow below will clobber %eax so
	 * we stash the panic_trigger result in %r11d.
	 */
	movl	%eax, %r11d
	cmpl	$0, %r11d
	je	0f

	/*
	 * If panic_trigger() was successful, we are the first to initiate a
	 * panic: we now switch to the reserved panic_stack before continuing.
	 */
	leaq	panic_stack(%rip), %rsp
	addq	$PANICSTKSIZE, %rsp
0:	subq	$REGSIZE, %rsp
	/*
	 * Now that we've got everything set up, store the register values as
	 * they were when we entered vpanic() to the designated location in
	 * the regs structure we allocated on the stack.
	 */
	movq	0x0(%rbx), %rcx
	movq	%rcx, REGOFF_RDI(%rsp)
	movq	0x8(%rbx), %rcx
	movq	%rcx, REGOFF_RSI(%rsp)
	movq	0x10(%rbx), %rcx
	movq	%rcx, REGOFF_RDX(%rsp)
	movq	0x18(%rbx), %rcx
	movq	%rcx, REGOFF_RCX(%rsp)
	movq	0x20(%rbx), %rcx

	movq	%rcx, REGOFF_R8(%rsp)
	movq	0x28(%rbx), %rcx
	movq	%rcx, REGOFF_R9(%rsp)
	movq	0x30(%rbx), %rcx
	movq	%rcx, REGOFF_RAX(%rsp)
	movq	0x38(%rbx), %rcx
	movq	%rcx, REGOFF_RBX(%rsp)
	movq	0x58(%rbx), %rcx

	movq	%rcx, REGOFF_RBP(%rsp)
	movq	0x40(%rbx), %rcx
	movq	%rcx, REGOFF_R10(%rsp)
	movq	0x48(%rbx), %rcx
	movq	%rcx, REGOFF_R11(%rsp)
	movq	%r12, REGOFF_R12(%rsp)

	movq	%r13, REGOFF_R13(%rsp)
	movq	%r14, REGOFF_R14(%rsp)
	movq	%r15, REGOFF_R15(%rsp)

	xorl	%ecx, %ecx
	movw	%ds, %cx
	movq	%rcx, REGOFF_DS(%rsp)
	movw	%es, %cx
	movq	%rcx, REGOFF_ES(%rsp)
	movw	%fs, %cx
	movq	%rcx, REGOFF_FS(%rsp)
	movw	%gs, %cx
	movq	%rcx, REGOFF_GS(%rsp)

	movq	$0, REGOFF_TRAPNO(%rsp)

	movq	$0, REGOFF_ERR(%rsp)
	leaq	vpanic(%rip), %rcx
	movq	%rcx, REGOFF_RIP(%rsp)
	movw	%cs, %cx
	movzwq	%cx, %rcx
	movq	%rcx, REGOFF_CS(%rsp)
	movq	0x50(%rbx), %rcx
	movq	%rcx, REGOFF_RFL(%rsp)
	movq	%rbx, %rcx
	addq	$0x60, %rcx
	movq	%rcx, REGOFF_RSP(%rsp)
	movw	%ss, %cx
	movzwq	%cx, %rcx
	movq	%rcx, REGOFF_SS(%rsp)

	/*
	 * panicsys(format, alist, rp, on_panic_stack) 
	 */	
	movq	REGOFF_RDI(%rsp), %rdi		/* format */
	movq	REGOFF_RSI(%rsp), %rsi		/* alist */
	movq	%rsp, %rdx			/* struct regs */
	movl	%r11d, %ecx			/* on_panic_stack */
	call	panicsys
	addq	$REGSIZE, %rsp
	popq	%rdi
	popq	%rsi
	popq	%rdx
	popq	%rcx
	popq	%r8
	popq	%r9
	popq	%rax
	popq	%rbx
	popq	%r10
	popq	%r11
	popfq
	leave
	ret
	SET_SIZE(vpanic)

	ENTRY_NP(dtrace_vpanic)			/* Initial stack layout: */

	pushq	%rbp				/* | %rip | 	0x60	*/
	movq	%rsp, %rbp			/* | %rbp |	0x58	*/
	pushfq					/* | rfl  |	0x50	*/
	pushq	%r11				/* | %r11 |	0x48	*/
	pushq	%r10				/* | %r10 |	0x40	*/
	pushq	%rbx				/* | %rbx |	0x38	*/
	pushq	%rax				/* | %rax |	0x30	*/
	pushq	%r9				/* | %r9  |	0x28	*/
	pushq	%r8				/* | %r8  |	0x20	*/
	pushq	%rcx				/* | %rcx |	0x18	*/
	pushq	%rdx				/* | %rdx |	0x10	*/
	pushq	%rsi				/* | %rsi |	0x8 alist */
	pushq	%rdi				/* | %rdi |	0x0 format */

	movq	%rsp, %rbx			/* %rbx = current %rsp */

	leaq	panic_quiesce(%rip), %rdi	/* %rdi = &panic_quiesce */
	call	dtrace_panic_trigger	/* %eax = dtrace_panic_trigger() */
	jmp	vpanic_common

	SET_SIZE(dtrace_vpanic)

#elif defined(__i386)

	ENTRY_NP(vpanic)			/ Initial stack layout:

	pushl	%ebp				/ | %eip | 20
	movl	%esp, %ebp			/ | %ebp | 16
	pushl	%eax				/ | %eax | 12
	pushl	%ebx				/ | %ebx |  8
	pushl	%ecx				/ | %ecx |  4
	pushl	%edx				/ | %edx |  0

	movl	%esp, %ebx			/ %ebx = current stack pointer

	lea	panic_quiesce, %eax		/ %eax = &panic_quiesce
	pushl	%eax				/ push &panic_quiesce
	call	panic_trigger			/ %eax = panic_trigger()
	addl	$4, %esp			/ reset stack pointer

vpanic_common:
	cmpl	$0, %eax			/ if (%eax == 0)
	je	0f				/   goto 0f;

	/*
	 * If panic_trigger() was successful, we are the first to initiate a
	 * panic: we now switch to the reserved panic_stack before continuing.
	 */
	lea	panic_stack, %esp		/ %esp  = panic_stack
	addl	$PANICSTKSIZE, %esp		/ %esp += PANICSTKSIZE

0:	subl	$REGSIZE, %esp			/ allocate struct regs

	/*
	 * Now that we've got everything set up, store the register values as
	 * they were when we entered vpanic() to the designated location in
	 * the regs structure we allocated on the stack. 
	 */
#if !defined(__GNUC_AS__)
	movw	%gs, %edx
	movl	%edx, REGOFF_GS(%esp)
	movw	%fs, %edx
	movl	%edx, REGOFF_FS(%esp)
	movw	%es, %edx
	movl	%edx, REGOFF_ES(%esp)
	movw	%ds, %edx
	movl	%edx, REGOFF_DS(%esp)
#else	/* __GNUC_AS__ */
	mov	%gs, %edx
	mov	%edx, REGOFF_GS(%esp)
	mov	%fs, %edx
	mov	%edx, REGOFF_FS(%esp)
	mov	%es, %edx
	mov	%edx, REGOFF_ES(%esp)
	mov	%ds, %edx
	mov	%edx, REGOFF_DS(%esp)
#endif	/* __GNUC_AS__ */
	movl	%edi, REGOFF_EDI(%esp)
	movl	%esi, REGOFF_ESI(%esp)
	movl	16(%ebx), %ecx
	movl	%ecx, REGOFF_EBP(%esp)
	movl	%ebx, %ecx
	addl	$20, %ecx
	movl	%ecx, REGOFF_ESP(%esp)
	movl	8(%ebx), %ecx
	movl	%ecx, REGOFF_EBX(%esp)
	movl	0(%ebx), %ecx
	movl	%ecx, REGOFF_EDX(%esp)
	movl	4(%ebx), %ecx
	movl	%ecx, REGOFF_ECX(%esp)
	movl	12(%ebx), %ecx
	movl	%ecx, REGOFF_EAX(%esp)
	movl	$0, REGOFF_TRAPNO(%esp)
	movl	$0, REGOFF_ERR(%esp)
	lea	vpanic, %ecx
	movl	%ecx, REGOFF_EIP(%esp)
#if !defined(__GNUC_AS__)
	movw	%cs, %edx
#else	/* __GNUC_AS__ */
	mov	%cs, %edx
#endif	/* __GNUC_AS__ */
	movl	%edx, REGOFF_CS(%esp)
	pushfl
	popl	%ecx
#if defined(__xpv)
	/*
	 * Synthesize the PS_IE bit from the event mask bit
	 */
	CURTHREAD(%edx)
	KPREEMPT_DISABLE(%edx)
	EVENT_MASK_TO_IE(%edx, %ecx)
	CURTHREAD(%edx)
	KPREEMPT_ENABLE_NOKP(%edx)
#endif
	movl	%ecx, REGOFF_EFL(%esp)
	movl	$0, REGOFF_UESP(%esp)
#if !defined(__GNUC_AS__)
	movw	%ss, %edx
#else	/* __GNUC_AS__ */
	mov	%ss, %edx
#endif	/* __GNUC_AS__ */
	movl	%edx, REGOFF_SS(%esp)

	movl	%esp, %ecx			/ %ecx = &regs
	pushl	%eax				/ push on_panic_stack
	pushl	%ecx				/ push &regs
	movl	12(%ebp), %ecx			/ %ecx = alist
	pushl	%ecx				/ push alist
	movl	8(%ebp), %ecx			/ %ecx = format
	pushl	%ecx				/ push format
	call	panicsys			/ panicsys();
	addl	$16, %esp			/ pop arguments

	addl	$REGSIZE, %esp
	popl	%edx
	popl	%ecx
	popl	%ebx
	popl	%eax
	leave
	ret
	SET_SIZE(vpanic)

	ENTRY_NP(dtrace_vpanic)			/ Initial stack layout:

	pushl	%ebp				/ | %eip | 20
	movl	%esp, %ebp			/ | %ebp | 16
	pushl	%eax				/ | %eax | 12
	pushl	%ebx				/ | %ebx |  8
	pushl	%ecx				/ | %ecx |  4
	pushl	%edx				/ | %edx |  0

	movl	%esp, %ebx			/ %ebx = current stack pointer

	lea	panic_quiesce, %eax		/ %eax = &panic_quiesce
	pushl	%eax				/ push &panic_quiesce
	call	dtrace_panic_trigger		/ %eax = dtrace_panic_trigger()
	addl	$4, %esp			/ reset stack pointer
	jmp	vpanic_common			/ jump back to common code

	SET_SIZE(dtrace_vpanic)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

void
hres_tick(void)
{}

int64_t timedelta;
hrtime_t hrtime_base;

#else	/* __lint */

	DGDEF3(timedelta, 8, 8)
	.long	0, 0

	/*
	 * initialized to a non zero value to make pc_gethrtime()
	 * work correctly even before clock is initialized
	 */
	DGDEF3(hrtime_base, 8, 8)
	.long	_MUL(NSEC_PER_CLOCK_TICK, 6), 0

	DGDEF3(adj_shift, 4, 4)
	.long	ADJ_SHIFT

#if defined(__amd64)

	ENTRY_NP(hres_tick)
	pushq	%rbp
	movq	%rsp, %rbp

	/*
	 * We need to call *gethrtimef before picking up CLOCK_LOCK (obviously,
	 * hres_last_tick can only be modified while holding CLOCK_LOCK).
	 * At worst, performing this now instead of under CLOCK_LOCK may
	 * introduce some jitter in pc_gethrestime().
	 */
	call	*gethrtimef(%rip)
	movq	%rax, %r8

	leaq	hres_lock(%rip), %rax
	movb	$-1, %dl
.CL1:
	xchgb	%dl, (%rax)
	testb	%dl, %dl
	jz	.CL3			/* got it */
.CL2:
	cmpb	$0, (%rax)		/* possible to get lock? */
	pause
	jne	.CL2
	jmp	.CL1			/* yes, try again */
.CL3:
	/*
	 * compute the interval since last time hres_tick was called
	 * and adjust hrtime_base and hrestime accordingly
	 * hrtime_base is an 8 byte value (in nsec), hrestime is
	 * a timestruc_t (sec, nsec)
	 */
	leaq	hres_last_tick(%rip), %rax
	movq	%r8, %r11
	subq	(%rax), %r8
	addq	%r8, hrtime_base(%rip)	/* add interval to hrtime_base */
	addq	%r8, hrestime+8(%rip)	/* add interval to hrestime.tv_nsec */
	/*
	 * Now that we have CLOCK_LOCK, we can update hres_last_tick
	 */ 	
	movq	%r11, (%rax)	

	call	__adj_hrestime

	/*
	 * release the hres_lock
	 */
	incl	hres_lock(%rip)
	leave
	ret
	SET_SIZE(hres_tick)
	
#elif defined(__i386)

	ENTRY_NP(hres_tick)
	pushl	%ebp
	movl	%esp, %ebp
	pushl	%esi
	pushl	%ebx

	/*
	 * We need to call *gethrtimef before picking up CLOCK_LOCK (obviously,
	 * hres_last_tick can only be modified while holding CLOCK_LOCK).
	 * At worst, performing this now instead of under CLOCK_LOCK may
	 * introduce some jitter in pc_gethrestime().
	 */
	call	*gethrtimef
	movl	%eax, %ebx
	movl	%edx, %esi

	movl	$hres_lock, %eax
	movl	$-1, %edx
.CL1:
	xchgb	%dl, (%eax)
	testb	%dl, %dl
	jz	.CL3			/ got it
.CL2:
	cmpb	$0, (%eax)		/ possible to get lock?
	pause
	jne	.CL2
	jmp	.CL1			/ yes, try again
.CL3:
	/*
	 * compute the interval since last time hres_tick was called
	 * and adjust hrtime_base and hrestime accordingly
	 * hrtime_base is an 8 byte value (in nsec), hrestime is
	 * timestruc_t (sec, nsec)
	 */

	lea	hres_last_tick, %eax

	movl	%ebx, %edx
	movl	%esi, %ecx

	subl 	(%eax), %edx
	sbbl 	4(%eax), %ecx

	addl	%edx, hrtime_base	/ add interval to hrtime_base
	adcl	%ecx, hrtime_base+4

	addl 	%edx, hrestime+4	/ add interval to hrestime.tv_nsec

	/
	/ Now that we have CLOCK_LOCK, we can update hres_last_tick.
	/
	movl	%ebx, (%eax)
	movl	%esi,  4(%eax)

	/ get hrestime at this moment. used as base for pc_gethrestime
	/
	/ Apply adjustment, if any
	/
	/ #define HRES_ADJ	(NSEC_PER_CLOCK_TICK >> ADJ_SHIFT)
	/ (max_hres_adj)
	/
	/ void
	/ adj_hrestime()
	/ {
	/	long long adj;
	/
	/	if (hrestime_adj == 0)
	/		adj = 0;
	/	else if (hrestime_adj > 0) {
	/		if (hrestime_adj < HRES_ADJ)
	/			adj = hrestime_adj;
	/		else
	/			adj = HRES_ADJ;
	/	}
	/	else {
	/		if (hrestime_adj < -(HRES_ADJ))
	/			adj = -(HRES_ADJ);
	/		else
	/			adj = hrestime_adj;
	/	}
	/
	/	timedelta -= adj;
	/	hrestime_adj = timedelta;
	/	hrestime.tv_nsec += adj;
	/
	/	while (hrestime.tv_nsec >= NANOSEC) {
	/		one_sec++;
	/		hrestime.tv_sec++;
	/		hrestime.tv_nsec -= NANOSEC;
	/	}
	/ }
__adj_hrestime:
	movl	hrestime_adj, %esi	/ if (hrestime_adj == 0)
	movl	hrestime_adj+4, %edx
	andl	%esi, %esi
	jne	.CL4			/ no
	andl	%edx, %edx
	jne	.CL4			/ no
	subl	%ecx, %ecx		/ yes, adj = 0;
	subl	%edx, %edx
	jmp	.CL5
.CL4:
	subl	%ecx, %ecx
	subl	%eax, %eax
	subl	%esi, %ecx
	sbbl	%edx, %eax
	andl	%eax, %eax		/ if (hrestime_adj > 0)
	jge	.CL6

	/ In the following comments, HRES_ADJ is used, while in the code
	/ max_hres_adj is used.
	/
	/ The test for "hrestime_adj < HRES_ADJ" is complicated because
	/ hrestime_adj is 64-bits, while HRES_ADJ is 32-bits.  We rely
	/ on the logical equivalence of:
	/
	/	!(hrestime_adj < HRES_ADJ)
	/
	/ and the two step sequence:
	/
	/	(HRES_ADJ - lsw(hrestime_adj)) generates a Borrow/Carry
	/
	/ which computes whether or not the least significant 32-bits
	/ of hrestime_adj is greater than HRES_ADJ, followed by:
	/
	/	Previous Borrow/Carry + -1 + msw(hrestime_adj) generates a Carry
	/
	/ which generates a carry whenever step 1 is true or the most
	/ significant long of the longlong hrestime_adj is non-zero.

	movl	max_hres_adj, %ecx	/ hrestime_adj is positive
	subl	%esi, %ecx
	movl	%edx, %eax
	adcl	$-1, %eax
	jnc	.CL7
	movl	max_hres_adj, %ecx	/ adj = HRES_ADJ;
	subl	%edx, %edx
	jmp	.CL5

	/ The following computation is similar to the one above.
	/
	/ The test for "hrestime_adj < -(HRES_ADJ)" is complicated because
	/ hrestime_adj is 64-bits, while HRES_ADJ is 32-bits.  We rely
	/ on the logical equivalence of:
	/
	/	(hrestime_adj > -HRES_ADJ)
	/
	/ and the two step sequence:
	/
	/	(HRES_ADJ + lsw(hrestime_adj)) generates a Carry
	/
	/ which means the least significant 32-bits of hrestime_adj is
	/ greater than -HRES_ADJ, followed by:
	/
	/	Previous Carry + 0 + msw(hrestime_adj) generates a Carry
	/
	/ which generates a carry only when step 1 is true and the most
	/ significant long of the longlong hrestime_adj is -1.

.CL6:					/ hrestime_adj is negative
	movl	%esi, %ecx
	addl	max_hres_adj, %ecx
	movl	%edx, %eax
	adcl	$0, %eax
	jc	.CL7
	xor	%ecx, %ecx
	subl	max_hres_adj, %ecx	/ adj = -(HRES_ADJ);
	movl	$-1, %edx
	jmp	.CL5
.CL7:
	movl	%esi, %ecx		/ adj = hrestime_adj;
.CL5:
	movl	timedelta, %esi
	subl	%ecx, %esi
	movl	timedelta+4, %eax
	sbbl	%edx, %eax
	movl	%esi, timedelta
	movl	%eax, timedelta+4	/ timedelta -= adj;
	movl	%esi, hrestime_adj
	movl	%eax, hrestime_adj+4	/ hrestime_adj = timedelta;
	addl	hrestime+4, %ecx

	movl	%ecx, %eax		/ eax = tv_nsec
1:
	cmpl	$NANOSEC, %eax		/ if ((unsigned long)tv_nsec >= NANOSEC)
	jb	.CL8			/ no
	incl	one_sec			/ yes,  one_sec++;
	incl	hrestime		/ hrestime.tv_sec++;
	addl	$-NANOSEC, %eax		/ tv_nsec -= NANOSEC
	jmp	1b			/ check for more seconds

.CL8:
	movl	%eax, hrestime+4	/ store final into hrestime.tv_nsec
	incl	hres_lock		/ release the hres_lock

	popl	%ebx
	popl	%esi
	leave
	ret
	SET_SIZE(hres_tick)

#endif	/* __i386 */
#endif	/* __lint */

/*
 * void prefetch_smap_w(void *)
 *
 * Prefetch ahead within a linear list of smap structures.
 * Not implemented for ia32.  Stub for compatibility.
 */

#if defined(__lint)

/*ARGSUSED*/
void prefetch_smap_w(void *smp)
{}

#else	/* __lint */

	ENTRY(prefetch_smap_w)
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(prefetch_smap_w)

#endif	/* __lint */

/*
 * prefetch_page_r(page_t *)
 * issue prefetch instructions for a page_t
 */
#if defined(__lint)

/*ARGSUSED*/
void
prefetch_page_r(void *pp)
{}

#else	/* __lint */

	ENTRY(prefetch_page_r)
	rep;	ret	/* use 2 byte return instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(prefetch_page_r)

#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
int
bcmp(const void *s1, const void *s2, size_t count)
{ return (0); }

#else   /* __lint */

#if defined(__amd64)

	ENTRY(bcmp)
	pushq	%rbp
	movq	%rsp, %rbp
#ifdef DEBUG
	testq	%rdx,%rdx
	je	1f
	movq	postbootkernelbase(%rip), %r11
	cmpq	%r11, %rdi
	jb	0f
	cmpq	%r11, %rsi
	jnb	1f
0:	leaq	.bcmp_panic_msg(%rip), %rdi
	xorl	%eax, %eax
	call	panic
1:
#endif	/* DEBUG */
	call	memcmp
	testl	%eax, %eax
	setne	%dl
	leave
	movzbl	%dl, %eax
	ret
	SET_SIZE(bcmp)
	
#elif defined(__i386)
	
#define	ARG_S1		8
#define	ARG_S2		12
#define	ARG_LENGTH	16

	ENTRY(bcmp)
	pushl	%ebp
	movl	%esp, %ebp	/ create new stack frame
#ifdef DEBUG
	cmpl	$0, ARG_LENGTH(%ebp)
	je	1f
	movl    postbootkernelbase, %eax
	cmpl    %eax, ARG_S1(%ebp)
	jb	0f
	cmpl    %eax, ARG_S2(%ebp)
	jnb	1f
0:	pushl   $.bcmp_panic_msg
	call    panic
1:
#endif	/* DEBUG */

	pushl	%edi		/ save register variable
	movl	ARG_S1(%ebp), %eax	/ %eax = address of string 1
	movl	ARG_S2(%ebp), %ecx	/ %ecx = address of string 2
	cmpl	%eax, %ecx	/ if the same string
	je	.equal		/ goto .equal
	movl	ARG_LENGTH(%ebp), %edi	/ %edi = length in bytes
	cmpl	$4, %edi	/ if %edi < 4
	jb	.byte_check	/ goto .byte_check
	.align	4
.word_loop:
	movl	(%ecx), %edx	/ move 1 word from (%ecx) to %edx
	leal	-4(%edi), %edi	/ %edi -= 4
	cmpl	(%eax), %edx	/ compare 1 word from (%eax) with %edx
	jne	.word_not_equal	/ if not equal, goto .word_not_equal
	leal	4(%ecx), %ecx	/ %ecx += 4 (next word)
	leal	4(%eax), %eax	/ %eax += 4 (next word)
	cmpl	$4, %edi	/ if %edi >= 4
	jae	.word_loop	/ goto .word_loop
.byte_check:
	cmpl	$0, %edi	/ if %edi == 0
	je	.equal		/ goto .equal
	jmp	.byte_loop	/ goto .byte_loop (checks in bytes)
.word_not_equal:
	leal	4(%edi), %edi	/ %edi += 4 (post-decremented)
	.align	4
.byte_loop:
	movb	(%ecx),	%dl	/ move 1 byte from (%ecx) to %dl
	cmpb	%dl, (%eax)	/ compare %dl with 1 byte from (%eax)
	jne	.not_equal	/ if not equal, goto .not_equal
	incl	%ecx		/ %ecx++ (next byte)
	incl	%eax		/ %eax++ (next byte)
	decl	%edi		/ %edi--
	jnz	.byte_loop	/ if not zero, goto .byte_loop
.equal:
	xorl	%eax, %eax	/ %eax = 0
	popl	%edi		/ restore register variable
	leave			/ restore old stack frame
	ret			/ return (NULL)
	.align	4
.not_equal:
	movl	$1, %eax	/ return 1
	popl	%edi		/ restore register variable
	leave			/ restore old stack frame
	ret			/ return (NULL)
	SET_SIZE(bcmp)

#endif	/* __i386 */

#ifdef DEBUG
	.text
.bcmp_panic_msg:
	.string "bcmp: arguments below kernelbase"
#endif	/* DEBUG */

#endif	/* __lint */

#if defined(__lint)

uint_t
bsrw_insn(uint16_t mask)
{
	uint_t index = sizeof (mask) * NBBY - 1;

	while ((mask & (1 << index)) == 0)
		index--;
	return (index);
}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(bsrw_insn)
	xorl	%eax, %eax
	bsrw	%di, %ax
	ret
	SET_SIZE(bsrw_insn)

#elif defined(__i386)

	ENTRY_NP(bsrw_insn)
	movw	4(%esp), %cx
	xorl	%eax, %eax
	bsrw	%cx, %ax
	ret
	SET_SIZE(bsrw_insn)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

uint_t
atomic_btr32(uint32_t *pending, uint_t pil)
{
	return (*pending &= ~(1 << pil));
}

#else	/* __lint */

#if defined(__i386)

	ENTRY_NP(atomic_btr32)
	movl	4(%esp), %ecx
	movl	8(%esp), %edx
	xorl	%eax, %eax
	lock
	btrl	%edx, (%ecx)
	setc	%al
	ret
	SET_SIZE(atomic_btr32)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void
switch_sp_and_call(void *newsp, void (*func)(uint_t, uint_t), uint_t arg1,
	    uint_t arg2)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(switch_sp_and_call)
	pushq	%rbp
	movq	%rsp, %rbp		/* set up stack frame */
	movq	%rdi, %rsp		/* switch stack pointer */
	movq	%rdx, %rdi		/* pass func arg 1 */
	movq	%rsi, %r11		/* save function to call */
	movq	%rcx, %rsi		/* pass func arg 2 */
	call	*%r11			/* call function */
	leave				/* restore stack */
	ret
	SET_SIZE(switch_sp_and_call)

#elif defined(__i386)

	ENTRY_NP(switch_sp_and_call)
	pushl	%ebp
	mov	%esp, %ebp		/* set up stack frame */
	movl	8(%ebp), %esp		/* switch stack pointer */
	pushl	20(%ebp)		/* push func arg 2 */
	pushl	16(%ebp)		/* push func arg 1 */
	call	*12(%ebp)		/* call function */
	addl	$8, %esp		/* pop arguments */
	leave				/* restore stack */
	ret
	SET_SIZE(switch_sp_and_call)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

void
kmdb_enter(void)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY_NP(kmdb_enter)
	pushq	%rbp
	movq	%rsp, %rbp

	/*
	 * Save flags, do a 'cli' then return the saved flags
	 */
	call	intr_clear

	int	$T_DBGENTR

	/*
	 * Restore the saved flags
	 */
	movq	%rax, %rdi
	call	intr_restore

	leave
	ret	
	SET_SIZE(kmdb_enter)

#elif defined(__i386)

	ENTRY_NP(kmdb_enter)
	pushl	%ebp
	movl	%esp, %ebp

	/*
	 * Save flags, do a 'cli' then return the saved flags
	 */
	call	intr_clear

	int	$T_DBGENTR

	/*
	 * Restore the saved flags
	 */
	pushl	%eax
	call	intr_restore
	addl	$4, %esp

	leave
	ret	
	SET_SIZE(kmdb_enter)

#endif	/* __i386 */
#endif	/* __lint */

#if defined(__lint)

void
return_instr(void)
{}

#else	/* __lint */

	ENTRY_NP(return_instr)
	rep;	ret	/* use 2 byte instruction when branch target */
			/* AMD Software Optimization Guide - Section 6.2 */
	SET_SIZE(return_instr)

#endif	/* __lint */

#if defined(__lint)

ulong_t
getflags(void)
{
	return (0);
}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(getflags)
	pushfq
	popq	%rax
#if defined(__xpv)
	CURTHREAD(%rdi)
	KPREEMPT_DISABLE(%rdi)
	/*
	 * Synthesize the PS_IE bit from the event mask bit
	 */
	CURVCPU(%r11)
	andq    $_BITNOT(PS_IE), %rax
	XEN_TEST_UPCALL_MASK(%r11)
	jnz	1f
	orq	$PS_IE, %rax
1:
	KPREEMPT_ENABLE_NOKP(%rdi)
#endif
	ret
	SET_SIZE(getflags)

#elif defined(__i386)

	ENTRY(getflags)
	pushfl
	popl	%eax
#if defined(__xpv)
	CURTHREAD(%ecx)
	KPREEMPT_DISABLE(%ecx)
	/*
	 * Synthesize the PS_IE bit from the event mask bit
	 */
	CURVCPU(%edx)
	andl    $_BITNOT(PS_IE), %eax
	XEN_TEST_UPCALL_MASK(%edx)
	jnz	1f
	orl	$PS_IE, %eax
1:
	KPREEMPT_ENABLE_NOKP(%ecx)
#endif
	ret
	SET_SIZE(getflags)

#endif	/* __i386 */

#endif	/* __lint */

#if defined(__lint)

ftrace_icookie_t
ftrace_interrupt_disable(void)
{ return (0); }

#else   /* __lint */

#if defined(__amd64)

	ENTRY(ftrace_interrupt_disable)
	pushfq
	popq	%rax
	CLI(%rdx)
	ret
	SET_SIZE(ftrace_interrupt_disable)

#elif defined(__i386)
		
	ENTRY(ftrace_interrupt_disable)
	pushfl
	popl	%eax
	CLI(%edx)
	ret
	SET_SIZE(ftrace_interrupt_disable)

#endif	/* __i386 */	
#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void
ftrace_interrupt_enable(ftrace_icookie_t cookie)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(ftrace_interrupt_enable)
	pushq	%rdi
	popfq
	ret
	SET_SIZE(ftrace_interrupt_enable)

#elif defined(__i386)
		
	ENTRY(ftrace_interrupt_enable)
	movl	4(%esp), %eax
	pushl	%eax
	popfl
	ret
	SET_SIZE(ftrace_interrupt_enable)

#endif	/* __i386 */
#endif	/* __lint */

#if defined (__lint)

/*ARGSUSED*/
void
clflush_insn(caddr_t addr)
{}

#else /* __lint */

#if defined (__amd64)
	ENTRY(clflush_insn)
	clflush (%rdi)
	ret
	SET_SIZE(clflush_insn)
#elif defined (__i386)
	ENTRY(clflush_insn)
	movl	4(%esp), %eax
	clflush (%eax)
	ret
	SET_SIZE(clflush_insn)

#endif /* __i386 */
#endif /* __lint */

#if defined (__lint)
/*ARGSUSED*/
void
mfence_insn(void)
{}

#else /* __lint */

#if defined (__amd64)
	ENTRY(mfence_insn)
	mfence
	ret
	SET_SIZE(mfence_insn)
#elif defined (__i386)
	ENTRY(mfence_insn)
	mfence
	ret
	SET_SIZE(mfence_insn)

#endif /* __i386 */
#endif /* __lint */

/*
 * VMware implements an I/O port that programs can query to detect if software
 * is running in a VMware hypervisor. This hypervisor port behaves differently
 * depending on magic values in certain registers and modifies some registers
 * as a side effect.
 *
 * References: http://kb.vmware.com/kb/1009458 
 */

#if defined(__lint)

/* ARGSUSED */
void
vmware_port(int cmd, uint32_t *regs) { return; }

#else

#if defined(__amd64)

	ENTRY(vmware_port)
	pushq	%rbx
	movl	$VMWARE_HVMAGIC, %eax
	movl	$0xffffffff, %ebx
	movl	%edi, %ecx
	movl	$VMWARE_HVPORT, %edx
	inl	(%dx)
	movl	%eax, (%rsi)
	movl	%ebx, 4(%rsi)
	movl	%ecx, 8(%rsi)
	movl	%edx, 12(%rsi)
	popq	%rbx
	ret
	SET_SIZE(vmware_port)

#elif defined(__i386)

	ENTRY(vmware_port)
	pushl	%ebx
	pushl	%esi
	movl	$VMWARE_HVMAGIC, %eax
	movl	$0xffffffff, %ebx
	movl	12(%esp), %ecx
	movl	$VMWARE_HVPORT, %edx
	inl	(%dx)
	movl	16(%esp), %esi
	movl	%eax, (%esi)
	movl	%ebx, 4(%esi)
	movl	%ecx, 8(%esi)
	movl	%edx, 12(%esi)
	popl	%esi
	popl	%ebx
	ret
	SET_SIZE(vmware_port)

#endif /* __i386 */
#endif /* __lint */
