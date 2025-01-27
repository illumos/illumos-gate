/*-
 * Copyright (c) 2013, Anish Gupta (akgupt3@gmail.com)
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright 2019 Joyent, Inc.
 * Copyright 2024 Oxide Computer Company
 */

#include <sys/asm_linkage.h>

#include "svm_assym.h"

/* Porting note: This is named 'svm_support.S' upstream. */


/*
 * Flush scratch registers to avoid lingering guest state being used for
 * Spectre v1 attacks when returning from guest entry.
 */
#define	SVM_GUEST_FLUSH_SCRATCH						\
	xorl	%edi, %edi;						\
	xorl	%esi, %esi;						\
	xorl	%edx, %edx;						\
	xorl	%ecx, %ecx;						\
	xorl	%r8d, %r8d;						\
	xorl	%r9d, %r9d;						\
	xorl	%r10d, %r10d;						\
	xorl	%r11d, %r11d;

/* Stack layout (offset from %rsp) for svm_launch */
#define	SVMSTK_R15	0x00	/* callee saved %r15			*/
#define	SVMSTK_R14	0x08	/* callee saved %r14			*/
#define	SVMSTK_R13	0x10	/* callee saved %r13			*/
#define	SVMSTK_R12	0x18	/* callee saved %r12			*/
#define	SVMSTK_RBX	0x20	/* callee saved %rbx			*/
#define	SVMSTK_RDX	0x28	/* save-args %rdx (struct cpu *)	*/
#define	SVMSTK_RSI	0x30	/* save-args %rsi (struct svm_regctx *)	*/
#define	SVMSTK_RDI	0x38	/* save-args %rdi (uint64_t vmcb_pa)	*/
#define	SVMSTK_FP	0x40	/* frame pointer %rbp			*/
#define	SVMSTKSIZE	SVMSTK_FP

/*
 * svm_launch(uint64_t vmcb, struct svm_regctx *gctx, struct pcpu *pcpu)
 * %rdi: physical address of VMCB
 * %rsi: pointer to guest context
 * %rdx: pointer to the pcpu data
 */
ENTRY_NP(svm_launch)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$SVMSTKSIZE, %rsp
	movq	%r15, SVMSTK_R15(%rsp)
	movq	%r14, SVMSTK_R14(%rsp)
	movq	%r13, SVMSTK_R13(%rsp)
	movq	%r12, SVMSTK_R12(%rsp)
	movq	%rbx, SVMSTK_RBX(%rsp)
	movq	%rdx, SVMSTK_RDX(%rsp)
	movq	%rsi, SVMSTK_RSI(%rsp)
	movq	%rdi, SVMSTK_RDI(%rsp)

	/* Save the physical address of the VMCB in %rax */
	movq	%rdi, %rax

	/* Restore guest state. */
	movq	SCTX_R8(%rsi), %r8
	movq	SCTX_R9(%rsi), %r9
	movq	SCTX_R10(%rsi), %r10
	movq	SCTX_R11(%rsi), %r11
	movq	SCTX_R12(%rsi), %r12
	movq	SCTX_R13(%rsi), %r13
	movq	SCTX_R14(%rsi), %r14
	movq	SCTX_R15(%rsi), %r15
	movq	SCTX_RBP(%rsi), %rbp
	movq	SCTX_RBX(%rsi), %rbx
	movq	SCTX_RCX(%rsi), %rcx
	movq	SCTX_RDX(%rsi), %rdx
	movq	SCTX_RDI(%rsi), %rdi
	movq	SCTX_RSI(%rsi), %rsi	/* %rsi must be restored last */


	/*
	 * We are under the protection of a cleared GIF here, re-enable the
	 * %rflags interrupt mask so the host CPU is capable of receiving
	 * interrupts while the GIF is re-asserted in guest context.
	 */
	sti

	vmload	%rax
	vmrun	%rax
	vmsave	%rax

	/*
	 * GIF is cleared again here, but the caller expects the interrupts to
	 * still be masked via %rflags.
	 */
	cli

	/* Grab the svm_regctx pointer */
	movq	SVMSTK_RSI(%rsp), %rax

	/* Save guest state. */
	movq	%r8, SCTX_R8(%rax)
	movq	%r9, SCTX_R9(%rax)
	movq	%r10, SCTX_R10(%rax)
	movq	%r11, SCTX_R11(%rax)
	movq	%r12, SCTX_R12(%rax)
	movq	%r13, SCTX_R13(%rax)
	movq	%r14, SCTX_R14(%rax)
	movq	%r15, SCTX_R15(%rax)
	movq	%rbp, SCTX_RBP(%rax)
	movq	%rbx, SCTX_RBX(%rax)
	movq	%rcx, SCTX_RCX(%rax)
	movq	%rdx, SCTX_RDX(%rax)
	movq	%rdi, SCTX_RDI(%rax)
	movq	%rsi, SCTX_RSI(%rax)

	/* Restore callee-saved registers */
	movq	SVMSTK_R15(%rsp), %r15
	movq	SVMSTK_R14(%rsp), %r14
	movq	SVMSTK_R13(%rsp), %r13
	movq	SVMSTK_R12(%rsp), %r12
	movq	SVMSTK_RBX(%rsp), %rbx

	/* Fix %gsbase to point back to the correct 'struct cpu *' */
	movq	SVMSTK_RDX(%rsp), %rdx
	movl	%edx, %eax
	shrq	$32, %rdx
	movl	$MSR_GSBASE, %ecx
	wrmsr

	/*
	 * While SVM will save/restore the GDTR and IDTR, the TR does not enjoy
	 * such treatment.  Reload the KTSS immediately, since it is used by
	 * dtrace and other fault/trap handlers.
	 */
	movq	SVMSTK_RDX(%rsp), %rdi		/* %rdi = CPU */
	movq	CPU_GDT(%rdi), %rdi		/* %rdi = cpu->cpu_gdt */
	leaq	GDT_KTSS_OFF(%rdi), %rdi	/* %rdi = &cpu_gdt[GDT_KTSS] */
	andb	$0xfd, SSD_TYPE(%rdi)		/* ssd_type.busy = 0 */
	movw	$KTSS_SEL, %ax			/* reload kernel TSS */
	ltr	%ax

	SVM_GUEST_FLUSH_SCRATCH

	addq	$SVMSTKSIZE, %rsp
	popq	%rbp
	ret
SET_SIZE(svm_launch)
