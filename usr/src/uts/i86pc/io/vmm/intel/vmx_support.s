/*-
 * Copyright (c) 2011 NetApp, Inc.
 * Copyright (c) 2013 Neel Natu <neel@freebsd.org>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY NETAPP, INC ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL NETAPP, INC OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD$
 */
/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 *
 * Copyright 2013 Pluribus Networks Inc.
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/segments.h>

/* Porting note: This is named 'vmx_support.S' upstream. */



#if defined(lint)

struct vmxctx;
struct vmx;

/*ARGSUSED*/
void
vmx_launch(struct vmxctx *ctx)
{}

void
vmx_exit_guest()
{}

/*ARGSUSED*/
int
vmx_enter_guest(struct vmxctx *ctx, struct vmx *vmx, int launched)
{
	return (0);
}

#else /* lint */

#include "vmx_assym.h"
#include "vmcs.h"

/*
 * Assumes that %rdi holds a pointer to the 'vmxctx'.
 *
 * On "return" all registers are updated to reflect guest state. The two
 * exceptions are %rip and %rsp. These registers are atomically switched
 * by hardware from the guest area of the vmcs.
 *
 * We modify %rsp to point to the 'vmxctx' so we can use it to restore
 * host context in case of an error with 'vmlaunch' or 'vmresume'.
 */
#define	VMX_GUEST_RESTORE						\
	movq	VMXCTX_GUEST_CR2(%rdi),%rsi;				\
	movq	%rsi,%cr2;						\
	movq	VMXCTX_GUEST_RSI(%rdi),%rsi;				\
	movq	VMXCTX_GUEST_RDX(%rdi),%rdx;				\
	movq	VMXCTX_GUEST_RCX(%rdi),%rcx;				\
	movq	VMXCTX_GUEST_R8(%rdi),%r8;				\
	movq	VMXCTX_GUEST_R9(%rdi),%r9;				\
	movq	VMXCTX_GUEST_RAX(%rdi),%rax;				\
	movq	VMXCTX_GUEST_RBX(%rdi),%rbx;				\
	movq	VMXCTX_GUEST_RBP(%rdi),%rbp;				\
	movq	VMXCTX_GUEST_R10(%rdi),%r10;				\
	movq	VMXCTX_GUEST_R11(%rdi),%r11;				\
	movq	VMXCTX_GUEST_R12(%rdi),%r12;				\
	movq	VMXCTX_GUEST_R13(%rdi),%r13;				\
	movq	VMXCTX_GUEST_R14(%rdi),%r14;				\
	movq	VMXCTX_GUEST_R15(%rdi),%r15;				\
	movq	VMXCTX_GUEST_RDI(%rdi),%rdi; /* restore rdi the last */

/*
 * Flush scratch registers to avoid lingering guest state being used for
 * Spectre v1 attacks when returning from guest entry.
 */
#define	VMX_GUEST_FLUSH_SCRATCH						\
	xorl	%edi, %edi;						\
	xorl	%esi, %esi;						\
	xorl	%edx, %edx;						\
	xorl	%ecx, %ecx;						\
	xorl	%r8d, %r8d;						\
	xorl	%r9d, %r9d;						\
	xorl	%r10d, %r10d;						\
	xorl	%r11d, %r11d;


/* Stack layout (offset from %rsp) for vmx_enter_guest */
#define	VMXSTK_TMPRDI	0x00	/* temp store %rdi on vmexit		*/
#define	VMXSTK_R15	0x08	/* callee saved %r15			*/
#define	VMXSTK_R14	0x10	/* callee saved %r14			*/
#define	VMXSTK_R13	0x18	/* callee saved %r13			*/
#define	VMXSTK_R12	0x20	/* callee saved %r12			*/
#define	VMXSTK_RBX	0x28	/* callee saved %rbx			*/
#define	VMXSTK_RDX	0x30	/* save-args %rdx (int launched)	*/
#define	VMXSTK_RSI	0x38	/* save-args %rsi (struct vmx *vmx)	*/
#define	VMXSTK_RDI	0x40	/* save-args %rdi (struct vmxctx *ctx)	*/
#define	VMXSTK_FP	0x48	/* frame pointer %rbp			*/
#define	VMXSTKSIZE	VMXSTK_FP

/*
 * vmx_enter_guest(struct vmxctx *vmxctx, int launched)
 * Interrupts must be disabled on entry.
 */
ENTRY_NP(vmx_enter_guest)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$VMXSTKSIZE, %rsp
	movq	%r15, VMXSTK_R15(%rsp)
	movq	%r14, VMXSTK_R14(%rsp)
	movq	%r13, VMXSTK_R13(%rsp)
	movq	%r12, VMXSTK_R12(%rsp)
	movq	%rbx, VMXSTK_RBX(%rsp)
	movq	%rdx, VMXSTK_RDX(%rsp)
	movq	%rsi, VMXSTK_RSI(%rsp)
	movq	%rdi, VMXSTK_RDI(%rsp)

	movq	%rdi, %r12	/* vmxctx */
	movq	%rsi, %r13	/* vmx */
	movl	%edx, %r14d	/* launch state */
	movq	VMXCTX_PMAP(%rdi), %rbx

	/* Activate guest pmap on this cpu. */
	leaq	PM_ACTIVE(%rbx), %rdi
	movl	%gs:CPU_ID, %esi
	call	cpuset_atomic_add
	movq	%r12, %rdi

	/*
	 * If 'vmx->eptgen[curcpu]' is not identical to 'pmap->pm_eptgen'
	 * then we must invalidate all mappings associated with this EPTP.
	 */
	movq	PM_EPTGEN(%rbx), %r10
	movl	%gs:CPU_ID, %eax
	cmpq	%r10, VMX_EPTGEN(%r13, %rax, 8)
	je	guest_restore

	/* Refresh 'vmx->eptgen[curcpu]' */
	movq	%r10, VMX_EPTGEN(%r13, %rax, 8)

	/* Setup the invept descriptor on the host stack */
	pushq	$0x0
	pushq	VMX_EPTP(%r13)
	movl	$0x1, %eax	/* Single context invalidate */
	invept	(%rsp), %rax
	leaq	0x10(%rsp), %rsp
	jbe	invept_error		/* Check invept instruction error */

guest_restore:
	/* Write the current %rsp into the VMCS to be restored on vmexit */
	movl	$VMCS_HOST_RSP, %eax
	vmwrite	%rsp, %rax
	jbe	vmwrite_error

	/* Check if vmresume is adequate or a full vmlaunch is required */
	cmpl	$0, %r14d
	je	do_launch

	VMX_GUEST_RESTORE
	vmresume
	/*
	 * In the common case, 'vmresume' returns back to the host through
	 * 'vmx_exit_guest'. If there is an error we return VMX_VMRESUME_ERROR
	 * to the caller.
	 */
	leaq	VMXSTK_FP(%rsp), %rbp
	movq	VMXSTK_RDI(%rsp), %rdi
	movl	$VMX_VMRESUME_ERROR, %eax
	jmp	decode_inst_error

do_launch:
	VMX_GUEST_RESTORE
	vmlaunch
	/*
	 * In the common case, 'vmlaunch' returns back to the host through
	 * 'vmx_exit_guest'. If there is an error we return VMX_VMLAUNCH_ERROR
	 * to the caller.
	 */
	leaq	VMXSTK_FP(%rsp), %rbp
	movq	VMXSTK_RDI(%rsp), %rdi
	movl	$VMX_VMLAUNCH_ERROR, %eax
	jmp	decode_inst_error

vmwrite_error:
	movl	$VMX_VMWRITE_ERROR, %eax
	jmp	decode_inst_error
invept_error:
	movl	$VMX_INVEPT_ERROR, %eax
	jmp	decode_inst_error
decode_inst_error:
	movl	$VM_FAIL_VALID, %r11d
	jz	inst_error
	movl	$VM_FAIL_INVALID, %r11d
inst_error:
	movl	%r11d, VMXCTX_INST_FAIL_STATUS(%rdi)

	movq	VMXCTX_PMAP(%rdi), %rdi
	leaq	PM_ACTIVE(%rdi), %rdi
	movl	%gs:CPU_ID, %esi
	movq	%rax, %r12
	call	cpuset_atomic_del
	movq	%r12, %rax

	movq	VMXSTK_RBX(%rsp), %rbx
	movq	VMXSTK_R12(%rsp), %r12
	movq	VMXSTK_R13(%rsp), %r13
	movq	VMXSTK_R14(%rsp), %r14
	movq	VMXSTK_R15(%rsp), %r15

	VMX_GUEST_FLUSH_SCRATCH

	addq	$VMXSTKSIZE, %rsp
	popq	%rbp
	ret

/*
 * Non-error VM-exit from the guest. Make this a label so it can
 * be used by C code when setting up the VMCS.
 * The VMCS-restored %rsp points to the struct vmxctx
 */
.align	ASM_ENTRY_ALIGN;
ALTENTRY(vmx_exit_guest)
	/*
	 * Save guest state that is not automatically saved in the vmcs.
	 */
	movq	%rdi, VMXSTK_TMPRDI(%rsp)
	movq	VMXSTK_RDI(%rsp), %rdi
	movq	%rbp, VMXCTX_GUEST_RBP(%rdi)
	leaq	VMXSTK_FP(%rsp), %rbp

	movq	%rsi, VMXCTX_GUEST_RSI(%rdi)
	movq	%rdx, VMXCTX_GUEST_RDX(%rdi)
	movq	%rcx, VMXCTX_GUEST_RCX(%rdi)
	movq	%r8, VMXCTX_GUEST_R8(%rdi)
	movq	%r9, VMXCTX_GUEST_R9(%rdi)
	movq	%rax, VMXCTX_GUEST_RAX(%rdi)
	movq	%rbx, VMXCTX_GUEST_RBX(%rdi)
	movq	%r10, VMXCTX_GUEST_R10(%rdi)
	movq	%r11, VMXCTX_GUEST_R11(%rdi)
	movq	%r12, VMXCTX_GUEST_R12(%rdi)
	movq	%r13, VMXCTX_GUEST_R13(%rdi)
	movq	%r14, VMXCTX_GUEST_R14(%rdi)
	movq	%r15, VMXCTX_GUEST_R15(%rdi)

	movq	%cr2, %rbx
	movq	%rbx, VMXCTX_GUEST_CR2(%rdi)
	movq	VMXSTK_TMPRDI(%rsp), %rdx
	movq	%rdx, VMXCTX_GUEST_RDI(%rdi)

	/* Deactivate guest pmap on this cpu. */
	movq	VMXCTX_PMAP(%rdi), %rdi
	leaq	PM_ACTIVE(%rdi), %rdi
	movl	%gs:CPU_ID, %esi
	call	cpuset_atomic_del

	/*
	 * This will return to the caller of 'vmx_enter_guest()' with a return
	 * value of VMX_GUEST_VMEXIT.
	 */
	movl	$VMX_GUEST_VMEXIT, %eax
	movq	VMXSTK_RBX(%rsp), %rbx
	movq	VMXSTK_R12(%rsp), %r12
	movq	VMXSTK_R13(%rsp), %r13
	movq	VMXSTK_R14(%rsp), %r14
	movq	VMXSTK_R15(%rsp), %r15

	VMX_GUEST_FLUSH_SCRATCH

	addq	$VMXSTKSIZE, %rsp
	popq	%rbp
	ret
SET_SIZE(vmx_enter_guest)

/*
 * %rdi = trapno
 *
 * We need to do enough to convince cmnint - and its iretting tail - that we're
 * a legit interrupt stack frame.
 */
ENTRY_NP(vmx_call_isr)
	pushq	%rbp
	movq	%rsp, %rbp
	movq	%rsp, %r11
	andq	$~0xf, %rsp	/* align stack */
	pushq	$KDS_SEL	/* %ss */
	pushq	%r11		/* %rsp */
	pushfq			/* %rflags */
	pushq	$KCS_SEL	/* %cs */
	leaq	.iret_dest(%rip), %rcx
	pushq	%rcx		/* %rip */
	pushq	$0		/* err */
	pushq	%rdi		/* trapno */
	cli
	jmp	cmnint		/* %rip (and call) */
.iret_dest:
	popq	%rbp
	ret
SET_SIZE(vmx_call_isr)

#endif /* lint */
