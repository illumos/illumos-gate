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
 * Copyright (c) 1999, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_TRAPTRACE_H
#define	_SYS_TRAPTRACE_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/privregs.h>

/*
 * Trap tracing.  If TRAPTRACE is defined, an entry is recorded every time
 * the CPU jumps through the Interrupt Descriptor Table (IDT).  One exception
 * is the Double Fault handler, which does not record a traptrace entry.
 *
 * There are facilities to (conditionally) interleave tracing of related
 * facilities e.h. x-calls.
 */

/*
 * Note: non-assembler files that include this file must include
 * <sys/systm.h> before it, for the typedef of pc_t to be visible.
 */

#define	TTR_STACK_DEPTH	10

#ifndef	_ASM

#define	TTR_PAD1_SIZE	(sizeof (long) - 1)

typedef struct {
	uintptr_t	ttc_next;
	uintptr_t	ttc_first;
	uintptr_t	ttc_limit;
	uintptr_t	ttc_current;
} trap_trace_ctl_t;

typedef struct {
	struct regs	ttr_regs;
	greg_t		ttr_cr2;
	union _ttr_info {
		struct _idt_entry {
			int	cpuid;
			short	vector;
			uchar_t	ipl;
			uchar_t	spl;
			uchar_t	pri;
		} idt_entry;
		struct _gate_entry {
			int	sysnum;
		} gate_entry;
	} ttr_info;
	uintptr_t	ttr_curthread;
	uchar_t		ttr_pad[TTR_PAD1_SIZE];
	uchar_t		ttr_marker;
	hrtime_t	ttr_stamp;
	int		ttr_sdepth;
	pc_t		ttr_stack[TTR_STACK_DEPTH];
} trap_trace_rec_t;

#define	ttr_cpuid	ttr_info.idt_entry.cpuid
#define	ttr_vector	ttr_info.idt_entry.vector
#define	ttr_ipl		ttr_info.idt_entry.ipl
#define	ttr_spl		ttr_info.idt_entry.spl
#define	ttr_pri		ttr_info.idt_entry.pri
#define	ttr_sysnum	ttr_info.gate_entry.sysnum

#define	TRAPTR_NENT	128

extern trap_trace_ctl_t	trap_trace_ctl[NCPU];	/* Allocated in locore.s */
extern size_t		trap_trace_bufsize;
extern int		trap_trace_freeze;
extern trap_trace_rec_t	trap_trace_postmort;	/* Entry used after death */

#define	TRAPTRACE_FREEZE	trap_trace_freeze = 1;
#define	TRAPTRACE_UNFREEZE	trap_trace_freeze = 0;

#else	/* _ASM */

/*
 * ptr       -- will be set to a TRAPTRACE entry.
 * scr1      -- scratch
 * scr1_32   -- 32-bit version of scr1
 * scr2      -- scratch
 * marker    -- register containing byte to store in marker field of entry
 *
 * Note that this macro defines labels "8" and "9".
 */
#ifdef TRAPTRACE

#if defined(__amd64)

#define	TRACE_PTR(ptr, scr1, scr1_32, scr2, marker)	\
	leaq	trap_trace_postmort(%rip), ptr;	\
	cmpl	$0, trap_trace_freeze(%rip);	\
	jne	9f;				\
	LOADCPU(ptr);				\
	movl	CPU_ID(ptr), scr1_32;		\
	shlq	$TRAPTR_SIZE_SHIFT, scr1;	\
	leaq	trap_trace_ctl(%rip), scr2;	\
	addq	scr2, scr1;			\
	movq	TRAPTR_NEXT(scr1), ptr;		\
	leaq	TRAP_ENT_SIZE(ptr), scr2;	\
	cmpq	TRAPTR_LIMIT(scr1), scr2;	\
	jl	8f;				\
	movq	TRAPTR_FIRST(scr1), scr2;	\
8:	movq	scr2, TRAPTR_NEXT(scr1);	\
9:	movb	marker, TTR_MARKER(ptr);

#elif defined(__i386)

#define	TRACE_PTR(ptr, scr1, scr1_32, scr2, marker)	\
	movl	$trap_trace_postmort, ptr;	\
	cmpl	$0, trap_trace_freeze;		\
	jne	9f;				\
	LOADCPU(ptr);				\
	movl	CPU_ID(ptr), scr1_32;		\
	shll	$TRAPTR_SIZE_SHIFT, scr1;	\
	addl	$trap_trace_ctl, scr1;		\
	movl	TRAPTR_NEXT(scr1), ptr;		\
	leal	TRAP_ENT_SIZE(ptr), scr2;	\
	cmpl	TRAPTR_LIMIT(scr1), scr2;	\
	jl	8f;				\
	movl	TRAPTR_FIRST(scr1), scr2;	\
8:	movl	scr2, TRAPTR_NEXT(scr1);	\
9:	movb	marker, TTR_MARKER(ptr);

#endif	/* __i386 */

/*
 * ptr  -- pointer to the current TRAPTRACE entry.
 * reg  -- pointer to the stored registers; must be on the stack
 * scr1 -- scratch used as array index
 * scr2 -- scratch used as temporary
 *
 * Note that this macro defines label "9".
 * Also captures curthread on exit of loop.
 */
#if defined(__xpv)
#define	__GETCR2(_mov, reg)			\
	_mov	%gs:CPU_VCPU_INFO, reg;		\
	_mov	VCPU_INFO_ARCH_CR2(reg), reg
#else
#define	__GETCR2(_mov, reg)			\
	_mov	%cr2, reg
#endif

#if defined(__amd64)

#define	TRACE_REGS(ptr, reg, scr1, scr2)	\
	xorq	scr1, scr1;			\
	/*CSTYLED*/				\
9:	movq	(reg, scr1, 1), scr2;		\
	movq	scr2, (ptr, scr1, 1);		\
	addq	$CLONGSIZE, scr1;		\
	cmpq	$REGSIZE, scr1;			\
	jl	9b;				\
	movq	%gs:CPU_THREAD, scr2;		\
	movq	scr2, TTR_CURTHREAD(ptr);	\
	__GETCR2(movq, scr2);			\
	movq	scr2, TTR_CR2(ptr)

#elif defined(__i386)

#define	TRACE_REGS(ptr, reg, scr1, scr2)	\
	xorl	scr1, scr1;			\
	/*CSTYLED*/				\
9:	movl	(reg, scr1, 1), scr2;		\
	movl	scr2, (ptr, scr1, 1);		\
	addl	$CLONGSIZE, scr1;		\
	cmpl	$REGSIZE, scr1;			\
	jl	9b;				\
	movl	%gs:CPU_THREAD, scr2;		\
	movl	scr2, TTR_CURTHREAD(ptr);	\
	__GETCR2(movl, scr2);			\
	movl	scr2, TTR_CR2(ptr)

#endif	/* __i386 */

/*
 * The time stamp macro records a high-resolution time stamp for the
 * given TRAPTRACE entry.  Note that %eax and %edx are plowed by this
 * macro;  if they are to be preserved, it's up to the caller of the macro.
 */

#if defined(__amd64)

#define	TRACE_STAMP(reg)			\
	rdtsc;					\
	movl	%eax, TTR_STAMP(reg);		\
	movl	%edx, TTR_STAMP+4(reg)

/*
 * %rbp should be set before invoking this macro.
 */

#define	TRACE_STACK(tt)				\
	pushq	%rdi;				\
	pushq	%rsi;				\
	pushq	%rdx;				\
	pushq	%rcx;				\
	pushq	%r8;				\
	pushq	%r9;				\
	pushq	%rax;				\
	pushq	%r12;				\
	movq	tt, %r12;			\
	leaq	TTR_STACK(%r12), %rdi;		\
	movl	$TTR_STACK_DEPTH, %esi;		\
	call	getpcstack;			\
	movl	%eax, TTR_SDEPTH(%r12);		\
	popq	%r12;				\
	popq	%rax;				\
	popq	%r9;				\
	popq	%r8;				\
	popq	%rcx;				\
	popq	%rdx;				\
	popq	%rsi;				\
	popq	%rdi

#elif defined(__i386)

#define	TRACE_STAMP(reg)			\
	xorl	%eax, %eax;			\
	xorl	%edx, %edx;			\
	btl	$X86FSET_TSC, x86_featureset;	\
	jnc	9f;				\
	rdtsc;					\
9:	movl	%eax, TTR_STAMP(reg);		\
	movl	%edx, TTR_STAMP+4(reg)

#define	TRACE_STACK(tt)				\
	pushl	%eax;				\
	pushl	%ecx;				\
	pushl	%edx;				\
	pushl	%ebx;				\
	pushl	$TTR_STACK_DEPTH;		\
	movl	tt, %ebx;			\
	leal	TTR_STACK(%ebx), %eax;		\
	pushl	%eax;				\
	call	getpcstack;			\
	addl	$8, %esp;			\
	movl	%eax, TTR_SDEPTH(%ebx);		\
	popl	%ebx;				\
	popl	%edx;				\
	popl	%ecx;				\
	popl	%eax

#endif	/* __i386 */

#else

#define	TRACE_PTR(ptr, scr1, scr1_32, scr2, marker)
#define	TRACE_REGS(ptr, reg, scr1, scr2)
#define	TRACE_STAMP(reg)
#define	TRACE_STACK(reg)

#endif	/* TRAPTRACE */

#endif	/* _ASM */

#define	TT_SYSCALL	0xaa	/* system call via lcall */
#define	TT_SYSENTER	0xab	/* system call via sysenter */
#define	TT_SYSC		0xad	/* system call via syscall (32-bit) */
#define	TT_SYSC64	0xae	/* system call via syscall (64-bit) */
#define	TT_INTERRUPT	0xbb
#define	TT_TRAP		0xcc
#define	TT_INTTRAP	0xdd
#define	TT_EVENT	0xee	/* hypervisor event */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_TRAPTRACE_H */
