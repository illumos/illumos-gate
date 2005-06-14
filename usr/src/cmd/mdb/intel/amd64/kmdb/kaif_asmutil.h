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

#ifndef _KAIF_ASMUTIL_H
#define	_KAIF_ASMUTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/segments.h>

#include <kmdb/kaif_regs.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _ASM

/*
 * Multiple CPUs won't be present until cross-call initialization has
 * completed.  Until that time, we just assume we're CPU zero.
 *
 * This macro returns the CPUID in %rax, and doesn't clobber any other
 * registers.
 */
#define	GET_CPUID \
	call	kmdb_kdi_xc_initialized;		\
	cmpq	$0, %rax;				\
	je	1f;					\
	movzbq	%gs:CPU_ID, %rax;			\
	jmp	2f;					\
1:							\
	clrq	%rax;					\
2:

/* clobbers %rdx, %rcx, returns addr in %rax, CPU ID in %rbx */
#define	GET_CPUSAVE_ADDR \
	GET_CPUID;					\
	movq	%rax, %rbx;				\
	movq	$KRS_SIZE, %rcx;			\
	mulq	%rcx;					\
	movq	$kaif_cpusave, %rdx;			\
	/*CSTYLED*/					\
	addq	(%rdx), %rax

/*
 * Save copies of the IDT and GDT descriptors.  Note that we only save the IDT
 * and GDT if the IDT isn't ours, as we may be legitimately re-entering the
 * debugger through the trap handler.  We don't want to clobber the saved IDT
 * in the process, as we'd end up resuming the world on our IDT.
 *
 * assumes cpusave in %rax, clobbers %rcx
 */
#define	SAVE_IDTGDT \
	sidt	KRS_TMPDESC(%rax);			\
	movq	KRS_TMPDESC+2(%rax), %rcx;		\
	cmpq	$kaif_idt, %rcx;			\
	je	1f;					\
	sidt	KRS_IDTR(%rax);				\
	sgdt	KRS_GDTR(%rax);				\
1:

/* %ss, %rsp, %rflags, %cs, %rip, %err, %trapno already on stack */
#define	KAIF_SAVE_REGS(base) \
	movq	%rdi, REG_OFF(KREG_RDI)(base);		\
	movq	%rsi, REG_OFF(KREG_RSI)(base);		\
	movq	%rdx, REG_OFF(KREG_RDX)(base);		\
	movq	%rcx, REG_OFF(KREG_RCX)(base);		\
	movq	%r8, REG_OFF(KREG_R8)(base);		\
	movq	%r9, REG_OFF(KREG_R9)(base);		\
	movq	%rax, REG_OFF(KREG_RAX)(base);		\
	movq	%rbx, REG_OFF(KREG_RBX)(base);		\
	movq	%rbp, REG_OFF(KREG_RBP)(base);		\
	movq	%r10, REG_OFF(KREG_R10)(base);		\
	movq	%r11, REG_OFF(KREG_R11)(base);		\
	movq	%r12, REG_OFF(KREG_R12)(base);		\
	movq	%r13, REG_OFF(KREG_R13)(base);		\
	movq	%r14, REG_OFF(KREG_R14)(base);		\
	movq	%r15, REG_OFF(KREG_R15)(base);		\
	movq	%rbp, REG_OFF(KREG_SAVFP)(base);	\
	movq	REG_OFF(KREG_RIP)(base), %rax;		\
	movq	%rax, REG_OFF(KREG_SAVPC)(base);	\
							\
	movl	$MSR_AMD_FSBASE, %ecx;			\
	rdmsr;						\
	movl	%eax, REG_OFF(KREG_FSBASE)(base);	\
	movl	%edx, _CONST(REG_OFF(KREG_FSBASE)+4)(base); \
							\
	movl	$MSR_AMD_GSBASE, %ecx;			\
	rdmsr;						\
	movl	%eax, REG_OFF(KREG_GSBASE)(base);	\
	movl	%edx, _CONST(REG_OFF(KREG_GSBASE)+4)(base); \
							\
	movl	$MSR_AMD_KGSBASE, %ecx;			\
	rdmsr;						\
	movl	%eax, REG_OFF(KREG_KGSBASE)(base);	\
	movl	%edx, _CONST(REG_OFF(KREG_KGSBASE)+4)(base); \
							\
	clrq	%rax;					\
	movw	%ds, %ax;				\
	movq	%rax, REG_OFF(KREG_DS)(base);		\
	movw	%es, %ax;				\
	movq	%rax, REG_OFF(KREG_ES)(base);		\
	movw	%fs, %ax;				\
	movq	%rax, REG_OFF(KREG_FS)(base);		\
	movw	%gs, %ax;				\
	movq	%rax, REG_OFF(KREG_GS)(base)

#define	KAIF_RESTORE_REGS(base) \
	movq	base, %rdi;				\
	movq	REG_OFF(KREG_GS)(%rdi), %rax;		\
	movw	%ax, %gs;				\
	movq	REG_OFF(KREG_FS)(%rdi), %rax;		\
	movw	%ax, %fs;				\
	movq	REG_OFF(KREG_ES)(%rdi), %rax;		\
	movw	%ax, %es;				\
	movq	REG_OFF(KREG_DS)(%rdi), %rax;		\
	movw	%ax, %ds;				\
							\
	movl	$MSR_AMD_KGSBASE, %ecx;			\
	movl	REG_OFF(KREG_KGSBASE)(%rdi), %eax;	\
	movl	_CONST(REG_OFF(KREG_KGSBASE)+4)(%rdi), %edx; \
	wrmsr;						\
							\
	movl	$MSR_AMD_GSBASE, %ecx;			\
	movl	REG_OFF(KREG_GSBASE)(%rdi), %eax;	\
	movl	_CONST(REG_OFF(KREG_GSBASE)+4)(%rdi), %edx; \
	wrmsr;						\
							\
	movl	$MSR_AMD_FSBASE, %ecx;			\
	movl	REG_OFF(KREG_FSBASE)(%rdi), %eax;	\
	movl	_CONST(REG_OFF(KREG_FSBASE)+4)(%rdi), %edx; \
	wrmsr;						\
							\
	movq	REG_OFF(KREG_R15)(%rdi), %r15;		\
	movq	REG_OFF(KREG_R14)(%rdi), %r14;		\
	movq	REG_OFF(KREG_R13)(%rdi), %r13;		\
	movq	REG_OFF(KREG_R12)(%rdi), %r12;		\
	movq	REG_OFF(KREG_R11)(%rdi), %r11;		\
	movq	REG_OFF(KREG_R10)(%rdi), %r10;		\
	movq	REG_OFF(KREG_RBP)(%rdi), %rbp;		\
	movq	REG_OFF(KREG_RBX)(%rdi), %rbx;		\
	movq	REG_OFF(KREG_RAX)(%rdi), %rax;		\
	movq	REG_OFF(KREG_R9)(%rdi), %r9;		\
	movq	REG_OFF(KREG_R8)(%rdi), %r8;		\
	movq	REG_OFF(KREG_RCX)(%rdi), %rcx;		\
	movq	REG_OFF(KREG_RDX)(%rdi), %rdx;		\
	movq	REG_OFF(KREG_RSI)(%rdi), %rsi;		\
	movq	REG_OFF(KREG_RDI)(%rdi), %rdi

/*
 * Each cpusave buffer has an area set aside for a ring buffer of breadcrumbs.
 * The following macros manage the buffer.
 */

/* Advance the ring buffer */
#define	ADVANCE_CRUMB_POINTER(cpusave, tmp1, tmp2) \
	movq	KRS_CURCRUMBIDX(cpusave), tmp1;	\
	cmpq	$[KAIF_NCRUMBS - 1], tmp1;	\
	jge	1f;				\
	/* Advance the pointer and index */	\
	addq	$1, tmp1;			\
	movq	tmp1, KRS_CURCRUMBIDX(cpusave);	\
	movq	KRS_CURCRUMB(cpusave), tmp1;	\
	addq	$KRM_SIZE, tmp1;		\
	jmp	2f;				\
1:	/* Reset the pointer and index */	\
	movq	$0, KRS_CURCRUMBIDX(cpusave);	\
	leaq	KRS_CRUMBS(cpusave), tmp1;	\
2:	movq	tmp1, KRS_CURCRUMB(cpusave);	\
	/* Clear the new crumb */		\
	movq	$KAIF_NCRUMBS, tmp2;		\
3:	movq	$0, -4(tmp1, tmp2, 4);		\
	decq	tmp2;				\
	jnz	3b

/* Set a value in the current breadcrumb buffer */
#define	ADD_CRUMB(cpusave, offset, value, tmp) \
	movq	KRS_CURCRUMB(cpusave), tmp;	\
	movq	value, offset(tmp)

/* Patch point for MSR clearing. */
#define	KAIF_MSR_PATCH \
	nop; nop; nop; nop; \
	nop; nop; nop; nop; \
	nop; nop; nop; nop; \
	nop; nop; nop; nop; \
	nop

#endif	/* _ASM */

#define	KAIF_MSR_PATCHSZ	17	/* bytes in KAIF_MSR_PATCH, above */
#define	KAIF_MSR_PATCHOFF	8	/* bytes of code before patch point */

#ifdef __cplusplus
}
#endif

#endif /* _KAIF_ASMUTIL_H */
