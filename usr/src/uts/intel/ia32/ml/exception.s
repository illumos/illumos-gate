/*
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, 2014 by Delphix. All rights reserved.
 * Copyright (c) 2017 Joyent, Inc.
 */

/*
 * Copyright (c) 1989, 1990 William F. Jolitz.
 * Copyright (c) 1990 The Regents of the University of California.
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * $FreeBSD: src/sys/amd64/amd64/exception.S,v 1.113 2003/10/15 02:04:52 peter Exp $
 */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/trap.h>
#include <sys/psw.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/dtrace.h>
#include <sys/x86_archext.h>
#include <sys/traptrace.h>
#include <sys/machparam.h>

/*
 * only one routine in this file is interesting to lint
 */

#if defined(__lint)

void
ndptrap_frstor(void)
{}

#else

#include "assym.h"

/*
 * push $0 on stack for traps that do not
 * generate an error code. This is so the rest
 * of the kernel can expect a consistent stack
 * from from any exception.
 *
 * Note that for all exceptions for amd64
 * %r11 and %rcx are on the stack. Just pop
 * them back into their appropriate registers and let
 * it get saved as is running native.
 */

#if defined(__xpv) && defined(__amd64)

#define	NPTRAP_NOERR(trapno)	\
	pushq	$0;		\
	pushq	$trapno	

#define	TRAP_NOERR(trapno)	\
	XPV_TRAP_POP;		\
	NPTRAP_NOERR(trapno)

/*
 * error code already pushed by hw
 * onto stack.
 */
#define	TRAP_ERR(trapno)	\
	XPV_TRAP_POP;		\
	pushq	$trapno	

#else /* __xpv && __amd64 */

#define	TRAP_NOERR(trapno)	\
	push	$0;		\
	push	$trapno	

#define	NPTRAP_NOERR(trapno) TRAP_NOERR(trapno)

/*
 * error code already pushed by hw
 * onto stack.
 */
#define	TRAP_ERR(trapno)	\
	push	$trapno	

#endif	/* __xpv && __amd64 */


	/*
	 * #DE
	 */
	ENTRY_NP(div0trap)
	TRAP_NOERR(T_ZERODIV)	/* $0 */
	jmp	cmntrap
	SET_SIZE(div0trap)

	/*
	 * #DB
	 *
	 * Fetch %dr6 and clear it, handing off the value to the
	 * cmntrap code in %r15/%esi
	 */
	ENTRY_NP(dbgtrap)
	TRAP_NOERR(T_SGLSTP)	/* $1 */

#if defined(__amd64)
#if !defined(__xpv)		/* no sysenter support yet */
	/*
	 * If we get here as a result of single-stepping a sysenter
	 * instruction, we suddenly find ourselves taking a #db
	 * in kernel mode -before- we've swapgs'ed.  So before we can
	 * take the trap, we do the swapgs here, and fix the return
	 * %rip in trap() so that we return immediately after the
	 * swapgs in the sysenter handler to avoid doing the swapgs again.
	 *
	 * Nobody said that the design of sysenter was particularly
	 * elegant, did they?
	 */

	pushq	%r11

	/*
	 * At this point the stack looks like this:
	 *
	 * (high address) 	r_ss
	 *			r_rsp
	 *			r_rfl
	 *			r_cs
	 *			r_rip		<-- %rsp + 24
	 *			r_err		<-- %rsp + 16
	 *			r_trapno	<-- %rsp + 8
	 * (low address)	%r11		<-- %rsp
	 */
	leaq	sys_sysenter(%rip), %r11
	cmpq	%r11, 24(%rsp)	/* Compare to saved r_rip on the stack */
	je	1f
	leaq	brand_sys_sysenter(%rip), %r11
	cmpq	%r11, 24(%rsp)	/* Compare to saved r_rip on the stack */
	jne	2f
1:	SWAPGS
2:	popq	%r11
#endif	/* !__xpv */

	INTR_PUSH
#if defined(__xpv)
	movl	$6, %edi
	call	kdi_dreg_get
	movq	%rax, %r15		/* %db6 -> %r15 */
	movl	$6, %edi
	movl	$0, %esi
	call	kdi_dreg_set		/* 0 -> %db6 */
#else
	movq	%db6, %r15
	xorl	%eax, %eax
	movq	%rax, %db6
#endif

#elif defined(__i386)

	INTR_PUSH
#if defined(__xpv)
	pushl	$6
	call	kdi_dreg_get
	addl	$4, %esp
	movl	%eax, %esi		/* %dr6 -> %esi */
	pushl	$0
	pushl	$6
	call	kdi_dreg_set		/* 0 -> %dr6 */
	addl	$8, %esp
#else
	movl	%db6, %esi
	xorl	%eax, %eax
	movl	%eax, %db6
#endif
#endif	/* __i386 */

	jmp	cmntrap_pushed
	SET_SIZE(dbgtrap)

#if defined(__amd64)
#if !defined(__xpv)

/*
 * Macro to set the gsbase or kgsbase to the address of the struct cpu
 * for this processor.  If we came from userland, set kgsbase else
 * set gsbase.  We find the proper cpu struct by looping through
 * the cpu structs for all processors till we find a match for the gdt
 * of the trapping processor.  The stack is expected to be pointing at
 * the standard regs pushed by hardware on a trap (plus error code and trapno).
 */
#define	SET_CPU_GSBASE							\
	subq	$REGOFF_TRAPNO, %rsp;	/* save regs */			\
	movq	%rax, REGOFF_RAX(%rsp);					\
	movq	%rbx, REGOFF_RBX(%rsp);					\
	movq	%rcx, REGOFF_RCX(%rsp);					\
	movq	%rdx, REGOFF_RDX(%rsp);					\
	movq	%rbp, REGOFF_RBP(%rsp);					\
	movq	%rsp, %rbp;						\
	subq	$16, %rsp;		/* space for gdt */		\
	sgdt	6(%rsp);						\
	movq	8(%rsp), %rcx;		/* %rcx has gdt to match */	\
	xorl	%ebx, %ebx;		/* loop index */		\
	leaq	cpu(%rip), %rdx;	/* cpu pointer array */		\
1:									\
	movq	(%rdx, %rbx, CLONGSIZE), %rax;	/* get cpu[i] */	\
	cmpq	$0x0, %rax;		/* cpu[i] == NULL ? */		\
	je	2f;			/* yes, continue */		\
	cmpq	%rcx, CPU_GDT(%rax);	/* gdt == cpu[i]->cpu_gdt ? */	\
	je	3f;			/* yes, go set gsbase */	\
2:									\
	incl	%ebx;			/* i++ */			\
	cmpl	$NCPU, %ebx;		/* i < NCPU ? */		\
	jb	1b;			/* yes, loop */			\
/* XXX BIG trouble if we fall thru here.  We didn't find a gdt match */	\
3:									\
	movl	$MSR_AMD_KGSBASE, %ecx;					\
	cmpw	$KCS_SEL, REGOFF_CS(%rbp); /* trap from kernel? */	\
	jne	4f;			/* no, go set KGSBASE */	\
	movl	$MSR_AMD_GSBASE, %ecx;	/* yes, set GSBASE */		\
        mfence;				/* OPTERON_ERRATUM_88 */	\
4:									\
	movq	%rax, %rdx;		/* write base register */	\
	shrq	$32, %rdx;						\
	wrmsr;								\
	movq	REGOFF_RDX(%rbp), %rdx;	/* restore regs */		\
	movq	REGOFF_RCX(%rbp), %rcx;					\
	movq	REGOFF_RBX(%rbp), %rbx;					\
	movq	REGOFF_RAX(%rbp), %rax;					\
	movq	%rbp, %rsp;						\
	movq	REGOFF_RBP(%rsp), %rbp;					\
	addq	$REGOFF_TRAPNO, %rsp	/* pop stack */

#else	/* __xpv */

#define	SET_CPU_GSBASE	/* noop on the hypervisor */

#endif	/* __xpv */
#endif	/* __amd64 */


#if defined(__amd64)

	/*
	 * #NMI
	 *
	 * XXPV: See 6532669.
	 */
	ENTRY_NP(nmiint)
	TRAP_NOERR(T_NMIFLT)	/* $2 */

	SET_CPU_GSBASE

	/*
	 * Save all registers and setup segment registers
	 * with kernel selectors.
	 */
	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS

	TRACE_PTR(%r12, %rax, %eax, %rdx, $TT_TRAP)
	TRACE_REGS(%r12, %rsp, %rax, %rbx)
	TRACE_STAMP(%r12)

	movq	%rsp, %rbp

	movq	%rbp, %rdi
	call	av_dispatch_nmivect

	INTR_POP
	IRET
	/*NOTREACHED*/
	SET_SIZE(nmiint)

#elif defined(__i386)

	/*
	 * #NMI
	 */
	ENTRY_NP(nmiint)
	TRAP_NOERR(T_NMIFLT)	/* $2 */

	/*
	 * Save all registers and setup segment registers
	 * with kernel selectors.
	 */
	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS

	TRACE_PTR(%edi, %ebx, %ebx, %ecx, $TT_TRAP)
	TRACE_REGS(%edi, %esp, %ebx, %ecx)
	TRACE_STAMP(%edi)

	movl	%esp, %ebp

	pushl	%ebp	
	call	av_dispatch_nmivect	
	addl	$4, %esp

	INTR_POP_USER
	IRET
	SET_SIZE(nmiint)

#endif	/* __i386 */

	/*
	 * #BP
	 */
	ENTRY_NP(brktrap)

#if defined(__amd64)
	XPV_TRAP_POP
	cmpw	$KCS_SEL, 8(%rsp)
	jne	bp_user

	/*
	 * This is a breakpoint in the kernel -- it is very likely that this
	 * is DTrace-induced.  To unify DTrace handling, we spoof this as an
	 * invalid opcode (#UD) fault.  Note that #BP is a trap, not a fault --
	 * we must decrement the trapping %rip to make it appear as a fault.
	 * We then push a non-zero error code to indicate that this is coming
	 * from #BP.
	 */
	decq	(%rsp)
	push	$1			/* error code -- non-zero for #BP */
	jmp	ud_kernel

bp_user:
#endif /* __amd64 */

	NPTRAP_NOERR(T_BPTFLT)	/* $3 */
	jmp	dtrace_trap

	SET_SIZE(brktrap)

	/*
	 * #OF
	 */
	ENTRY_NP(ovflotrap)
	TRAP_NOERR(T_OVFLW)	/* $4 */
	jmp	cmntrap
	SET_SIZE(ovflotrap)

	/*
	 * #BR
	 */
	ENTRY_NP(boundstrap)
	TRAP_NOERR(T_BOUNDFLT)	/* $5 */
	jmp	cmntrap
	SET_SIZE(boundstrap)

#if defined(__amd64)

	ENTRY_NP(invoptrap)

	XPV_TRAP_POP

	cmpw	$KCS_SEL, 8(%rsp)
	jne	ud_user

#if defined(__xpv)
	movb	$0, 12(%rsp)		/* clear saved upcall_mask from %cs */
#endif
	push	$0			/* error code -- zero for #UD */
ud_kernel:
	push	$0xdddd			/* a dummy trap number */
	INTR_PUSH
	movq	REGOFF_RIP(%rsp), %rdi
	movq	REGOFF_RSP(%rsp), %rsi
	movq	REGOFF_RAX(%rsp), %rdx
	pushq	(%rsi)
	movq	%rsp, %rsi
	subq	$8, %rsp
	call	dtrace_invop
	ALTENTRY(dtrace_invop_callsite)
	addq	$16, %rsp
	cmpl	$DTRACE_INVOP_PUSHL_EBP, %eax
	je	ud_push
	cmpl	$DTRACE_INVOP_LEAVE, %eax
	je	ud_leave
	cmpl	$DTRACE_INVOP_NOP, %eax
	je	ud_nop
	cmpl	$DTRACE_INVOP_RET, %eax
	je	ud_ret
	jmp	ud_trap

ud_push:
	/*
	 * We must emulate a "pushq %rbp".  To do this, we pull the stack
	 * down 8 bytes, and then store the base pointer.
	 */
	INTR_POP
	subq	$16, %rsp		/* make room for %rbp */
	pushq	%rax			/* push temp */
	movq	24(%rsp), %rax		/* load calling RIP */
	addq	$1, %rax		/* increment over trapping instr */
	movq	%rax, 8(%rsp)		/* store calling RIP */
	movq	32(%rsp), %rax		/* load calling CS */
	movq	%rax, 16(%rsp)		/* store calling CS */
	movq	40(%rsp), %rax		/* load calling RFLAGS */
	movq	%rax, 24(%rsp)		/* store calling RFLAGS */
	movq	48(%rsp), %rax		/* load calling RSP */
	subq	$8, %rax		/* make room for %rbp */
	movq	%rax, 32(%rsp)		/* store calling RSP */
	movq	56(%rsp), %rax		/* load calling SS */
	movq	%rax, 40(%rsp)		/* store calling SS */
	movq	32(%rsp), %rax		/* reload calling RSP */
	movq	%rbp, (%rax)		/* store %rbp there */
	popq	%rax			/* pop off temp */
	IRET				/* return from interrupt */
	/*NOTREACHED*/

ud_leave:
	/*
	 * We must emulate a "leave", which is the same as a "movq %rbp, %rsp"
	 * followed by a "popq %rbp".  This is quite a bit simpler on amd64
	 * than it is on i386 -- we can exploit the fact that the %rsp is
	 * explicitly saved to effect the pop without having to reshuffle
	 * the other data pushed for the trap.
	 */
	INTR_POP
	pushq	%rax			/* push temp */
	movq	8(%rsp), %rax		/* load calling RIP */
	addq	$1, %rax		/* increment over trapping instr */
	movq	%rax, 8(%rsp)		/* store calling RIP */
	movq	(%rbp), %rax		/* get new %rbp */
	addq	$8, %rbp		/* adjust new %rsp */
	movq	%rbp, 32(%rsp)		/* store new %rsp */
	movq	%rax, %rbp		/* set new %rbp */
	popq	%rax			/* pop off temp */
	IRET				/* return from interrupt */
	/*NOTREACHED*/

ud_nop:
	/*
	 * We must emulate a "nop".  This is obviously not hard:  we need only
	 * advance the %rip by one.
	 */
	INTR_POP
	incq	(%rsp)
	IRET
	/*NOTREACHED*/

ud_ret:
	INTR_POP
	pushq	%rax			/* push temp */
	movq	32(%rsp), %rax		/* load %rsp */
	movq	(%rax), %rax		/* load calling RIP */
	movq	%rax, 8(%rsp)		/* store calling RIP */
	addq	$8, 32(%rsp)		/* adjust new %rsp */
	popq	%rax			/* pop off temp */
	IRET				/* return from interrupt */
	/*NOTREACHED*/

ud_trap:
	/*
	 * We're going to let the kernel handle this as a normal #UD.  If,
	 * however, we came through #BP and are spoofing #UD (in this case,
	 * the stored error value will be non-zero), we need to de-spoof
	 * the trap by incrementing %rip and pushing T_BPTFLT.
	 */
	cmpq	$0, REGOFF_ERR(%rsp)
	je	ud_ud
	incq	REGOFF_RIP(%rsp)
	addq	$REGOFF_RIP, %rsp
	NPTRAP_NOERR(T_BPTFLT)	/* $3 */
	jmp	cmntrap

ud_ud:
	addq	$REGOFF_RIP, %rsp
ud_user:
	NPTRAP_NOERR(T_ILLINST)
	jmp	cmntrap
	SET_SIZE(invoptrap)

#elif defined(__i386)

	/*
	 * #UD
	 */
	ENTRY_NP(invoptrap)
	/*
	 * If we are taking an invalid opcode trap while in the kernel, this
	 * is likely an FBT probe point.
	 */
	pushl   %gs
	cmpw	$KGS_SEL, (%esp)
	jne	8f

	addl	$4, %esp
#if defined(__xpv)
	movb	$0, 6(%esp)		/* clear saved upcall_mask from %cs */
#endif	/* __xpv */
	pusha
	pushl	%eax			/* push %eax -- may be return value */
	pushl	%esp			/* push stack pointer */
	addl	$48, (%esp)		/* adjust to incoming args */
	pushl	40(%esp)		/* push calling EIP */
	call	dtrace_invop
	ALTENTRY(dtrace_invop_callsite)
	addl	$12, %esp
	cmpl	$DTRACE_INVOP_PUSHL_EBP, %eax
	je	1f
	cmpl	$DTRACE_INVOP_POPL_EBP, %eax
	je	2f
	cmpl	$DTRACE_INVOP_LEAVE, %eax
	je	3f
	cmpl	$DTRACE_INVOP_NOP, %eax
	je	4f
	jmp	7f
1:
	/*
	 * We must emulate a "pushl %ebp".  To do this, we pull the stack
	 * down 4 bytes, and then store the base pointer.
	 */
	popa
	subl	$4, %esp		/* make room for %ebp */
	pushl	%eax			/* push temp */
	movl	8(%esp), %eax		/* load calling EIP */
	incl	%eax			/* increment over LOCK prefix */
	movl	%eax, 4(%esp)		/* store calling EIP */
	movl	12(%esp), %eax		/* load calling CS */
	movl	%eax, 8(%esp)		/* store calling CS */
	movl	16(%esp), %eax		/* load calling EFLAGS */
	movl	%eax, 12(%esp)		/* store calling EFLAGS */
	movl	%ebp, 16(%esp)		/* push %ebp */
	popl	%eax			/* pop off temp */
	jmp	_emul_done
2:
	/*
	 * We must emulate a "popl %ebp".  To do this, we do the opposite of
	 * the above:  we remove the %ebp from the stack, and squeeze up the
	 * saved state from the trap.
	 */
	popa
	pushl	%eax			/* push temp */
	movl	16(%esp), %ebp		/* pop %ebp */
	movl	12(%esp), %eax		/* load calling EFLAGS */
	movl	%eax, 16(%esp)		/* store calling EFLAGS */
	movl	8(%esp), %eax		/* load calling CS */
	movl	%eax, 12(%esp)		/* store calling CS */
	movl	4(%esp), %eax		/* load calling EIP */
	incl	%eax			/* increment over LOCK prefix */
	movl	%eax, 8(%esp)		/* store calling EIP */
	popl	%eax			/* pop off temp */
	addl	$4, %esp		/* adjust stack pointer */
	jmp	_emul_done
3:
	/*
	 * We must emulate a "leave", which is the same as a "movl %ebp, %esp"
	 * followed by a "popl %ebp".  This looks similar to the above, but
	 * requires two temporaries:  one for the new base pointer, and one
	 * for the staging register.
	 */
	popa
	pushl	%eax			/* push temp */
	pushl	%ebx			/* push temp */
	movl	%ebp, %ebx		/* set temp to old %ebp */
	movl	(%ebx), %ebp		/* pop %ebp */
	movl	16(%esp), %eax		/* load calling EFLAGS */
	movl	%eax, (%ebx)		/* store calling EFLAGS */
	movl	12(%esp), %eax		/* load calling CS */
	movl	%eax, -4(%ebx)		/* store calling CS */
	movl	8(%esp), %eax		/* load calling EIP */
	incl	%eax			/* increment over LOCK prefix */
	movl	%eax, -8(%ebx)		/* store calling EIP */
	movl	%ebx, -4(%esp)		/* temporarily store new %esp */
	popl	%ebx			/* pop off temp */
	popl	%eax			/* pop off temp */
	movl	-12(%esp), %esp		/* set stack pointer */
	subl	$8, %esp		/* adjust for three pushes, one pop */
	jmp	_emul_done
4:
	/*
	 * We must emulate a "nop".  This is obviously not hard:  we need only
	 * advance the %eip by one.
	 */
	popa
	incl	(%esp)
_emul_done:
	IRET				/* return from interrupt */
7:
	popa
	pushl	$0
	pushl	$T_ILLINST	/* $6 */
	jmp	cmntrap
8:
	addl	$4, %esp
	pushl	$0
	pushl	$T_ILLINST	/* $6 */
	jmp	cmntrap
	SET_SIZE(invoptrap)

#endif	/* __i386 */

#if defined(__amd64)

	/*
	 * #NM
	 */
#if defined(__xpv)

	ENTRY_NP(ndptrap)
	/*
	 * (On the hypervisor we must make a hypercall so we might as well
	 * save everything and handle as in a normal trap.)
	 */
	TRAP_NOERR(T_NOEXTFLT)	/* $7 */
	INTR_PUSH
	
	/*
	 * We want to do this quickly as every lwp using fp will take this
	 * after a context switch -- we do the frequent path in ndptrap_frstor
	 * below; for all other cases, we let the trap code handle it
	 */
	LOADCPU(%rax)			/* swapgs handled in hypervisor */
	cmpl	$0, fpu_exists(%rip)
	je	.handle_in_trap		/* let trap handle no fp case */
	movq	CPU_THREAD(%rax), %rbx	/* %rbx = curthread */
	movl	$FPU_EN, %eax
	movq	T_LWP(%rbx), %rbx	/* %rbx = lwp */
	testq	%rbx, %rbx
	jz	.handle_in_trap		/* should not happen? */
#if LWP_PCB_FPU	!= 0
	addq	$LWP_PCB_FPU, %rbx	/* &lwp->lwp_pcb.pcb_fpu */
#endif
	testl	%eax, PCB_FPU_FLAGS(%rbx)
	jz	.handle_in_trap		/* must be the first fault */
	CLTS
	andl	$_BITNOT(FPU_VALID), PCB_FPU_FLAGS(%rbx)
#if FPU_CTX_FPU_REGS != 0
	addq	$FPU_CTX_FPU_REGS, %rbx
#endif

	movl	FPU_CTX_FPU_XSAVE_MASK(%rbx), %eax	/* for xrstor */
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%rbx), %edx	/* for xrstor */

	/*
	 * the label below is used in trap.c to detect FP faults in
	 * kernel due to user fault.
	 */
	ALTENTRY(ndptrap_frstor)
	movq (%rbx), %rbx		/* fpu_regs.kfpu_u.kfpu_XX pointer */
	.globl  _patch_xrstorq_rbx
_patch_xrstorq_rbx:
	fxrstorq (%rbx)
	cmpw	$KCS_SEL, REGOFF_CS(%rsp)
	je	.return_to_kernel

	ASSERT_UPCALL_MASK_IS_SET
	USER_POP
	IRET				/* return to user mode */
	/*NOTREACHED*/

.return_to_kernel:
	INTR_POP
	IRET
	/*NOTREACHED*/

.handle_in_trap:
	INTR_POP
	pushq	$0			/* can not use TRAP_NOERR */
	pushq	$T_NOEXTFLT
	jmp	cmninttrap
	SET_SIZE(ndptrap_frstor)
	SET_SIZE(ndptrap)

#else	/* __xpv */

	ENTRY_NP(ndptrap)
	/*
	 * We want to do this quickly as every lwp using fp will take this
	 * after a context switch -- we do the frequent path in ndptrap_frstor
	 * below; for all other cases, we let the trap code handle it
	 */
	pushq	%rax
	pushq	%rbx
	cmpw    $KCS_SEL, 24(%rsp)	/* did we come from kernel mode? */
	jne     1f
	LOADCPU(%rax)			/* if yes, don't swapgs */
	jmp	2f
1:
	SWAPGS				/* if from user, need swapgs */
	LOADCPU(%rax)
	SWAPGS
2:	
	/*
	 * Xrstor needs to use edx as part of its flag.
	 * NOTE: have to push rdx after "cmpw ...24(%rsp)", otherwise rsp+$24
	 * will not point to CS.
	 */
	pushq	%rdx
	cmpl	$0, fpu_exists(%rip)
	je	.handle_in_trap		/* let trap handle no fp case */
	movq	CPU_THREAD(%rax), %rbx	/* %rbx = curthread */
	movl	$FPU_EN, %eax
	movq	T_LWP(%rbx), %rbx	/* %rbx = lwp */
	testq	%rbx, %rbx
	jz	.handle_in_trap		/* should not happen? */
#if LWP_PCB_FPU	!= 0
	addq	$LWP_PCB_FPU, %rbx	/* &lwp->lwp_pcb.pcb_fpu */
#endif
	testl	%eax, PCB_FPU_FLAGS(%rbx)
	jz	.handle_in_trap		/* must be the first fault */
	clts
	andl	$_BITNOT(FPU_VALID), PCB_FPU_FLAGS(%rbx)
#if FPU_CTX_FPU_REGS != 0
	addq	$FPU_CTX_FPU_REGS, %rbx
#endif

	movl	FPU_CTX_FPU_XSAVE_MASK(%rbx), %eax	/* for xrstor */
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%rbx), %edx	/* for xrstor */

	/*
	 * the label below is used in trap.c to detect FP faults in
	 * kernel due to user fault.
	 */
	ALTENTRY(ndptrap_frstor)
	movq (%rbx), %rbx		/* fpu_regs.kfpu_u.kfpu_XX pointer */
	.globl  _patch_xrstorq_rbx
_patch_xrstorq_rbx:
	fxrstorq (%rbx)
	popq	%rdx
	popq	%rbx
	popq	%rax
	IRET
	/*NOTREACHED*/

.handle_in_trap:
	popq	%rdx
	popq	%rbx
	popq	%rax
	TRAP_NOERR(T_NOEXTFLT)	/* $7 */
	jmp	cmninttrap
	SET_SIZE(ndptrap_frstor)
	SET_SIZE(ndptrap)

#endif	/* __xpv */

#elif defined(__i386)

	ENTRY_NP(ndptrap)
	/*
	 * We want to do this quickly as every lwp using fp will take this
	 * after a context switch -- we do the frequent path in fpnoextflt
	 * below; for all other cases, we let the trap code handle it
	 */
	pushl	%eax
	pushl	%ebx
	pushl	%edx			/* for xrstor */
	pushl	%ds
	pushl	%gs
	movl	$KDS_SEL, %ebx
	movw	%bx, %ds
	movl	$KGS_SEL, %eax
	movw	%ax, %gs
	LOADCPU(%eax)
	cmpl	$0, fpu_exists
	je	.handle_in_trap		/* let trap handle no fp case */
	movl	CPU_THREAD(%eax), %ebx	/* %ebx = curthread */
	movl	$FPU_EN, %eax
	movl	T_LWP(%ebx), %ebx	/* %ebx = lwp */
	testl	%ebx, %ebx
	jz	.handle_in_trap		/* should not happen? */
#if LWP_PCB_FPU != 0
	addl	$LWP_PCB_FPU, %ebx 	/* &lwp->lwp_pcb.pcb_fpu */
#endif
	testl	%eax, PCB_FPU_FLAGS(%ebx)
	jz	.handle_in_trap		/* must be the first fault */
	CLTS
	andl	$_BITNOT(FPU_VALID), PCB_FPU_FLAGS(%ebx)
#if FPU_CTX_FPU_REGS != 0
	addl	$FPU_CTX_FPU_REGS, %ebx
#endif

	movl	FPU_CTX_FPU_XSAVE_MASK(%ebx), %eax	/* for xrstor */
	movl	FPU_CTX_FPU_XSAVE_MASK+4(%ebx), %edx	/* for xrstor */

	/*
	 * the label below is used in trap.c to detect FP faults in kernel
	 * due to user fault.
	 */
	ALTENTRY(ndptrap_frstor)
	movl	(%ebx), %ebx		/* fpu_regs.kfpu_u.kfpu_XX pointer */
	.globl  _patch_fxrstor_ebx
_patch_fxrstor_ebx:
	.globl  _patch_xrstor_ebx
_patch_xrstor_ebx:
	frstor	(%ebx)		/* may be patched to fxrstor or xrstor */
	popl	%gs
	popl	%ds
	popl	%edx
	popl	%ebx
	popl	%eax
	IRET

.handle_in_trap:
	popl	%gs
	popl	%ds
	popl	%edx
	popl	%ebx
	popl	%eax
	TRAP_NOERR(T_NOEXTFLT)	/* $7 */
	jmp	cmninttrap
	SET_SIZE(ndptrap_frstor)
	SET_SIZE(ndptrap)

#endif	/* __i386 */

#if !defined(__xpv)
#if defined(__amd64)

	/*
	 * #DF
	 */
	ENTRY_NP(syserrtrap)
	pushq	$T_DBLFLT
	SET_CPU_GSBASE

	/*
	 * We share this handler with kmdb (if kmdb is loaded).  As such, we
	 * may have reached this point after encountering a #df in kmdb.  If
	 * that happens, we'll still be on kmdb's IDT.  We need to switch back
	 * to this CPU's IDT before proceeding.  Furthermore, if we did arrive
	 * here from kmdb, kmdb is probably in a very sickly state, and
	 * shouldn't be entered from the panic flow.  We'll suppress that
	 * entry by setting nopanicdebug.
	 */
	pushq	%rax
	subq	$DESCTBR_SIZE, %rsp
	sidt	(%rsp)
	movq	%gs:CPU_IDT, %rax
	cmpq	%rax, DTR_BASE(%rsp)
	je	1f

	movq	%rax, DTR_BASE(%rsp)
	movw	$_MUL(NIDT, GATE_DESC_SIZE), DTR_LIMIT(%rsp)
	lidt	(%rsp)

	movl	$1, nopanicdebug

1:	addq	$DESCTBR_SIZE, %rsp
	popq	%rax
	
	DFTRAP_PUSH

	/*
	 * freeze trap trace.
	 */
#ifdef TRAPTRACE
	leaq	trap_trace_freeze(%rip), %r11
	incl	(%r11)
#endif

	ENABLE_INTR_FLAGS

	movq	%rsp, %rdi	/* &regs */
	xorl	%esi, %esi	/* clear address */
	xorl	%edx, %edx	/* cpuid = 0 */
	call	trap

	SET_SIZE(syserrtrap)

#elif defined(__i386)

	/*
	 * #DF
	 */
	ENTRY_NP(syserrtrap)
	cli				/* disable interrupts */

	/*
	 * We share this handler with kmdb (if kmdb is loaded).  As such, we
	 * may have reached this point after encountering a #df in kmdb.  If
	 * that happens, we'll still be on kmdb's IDT.  We need to switch back
	 * to this CPU's IDT before proceeding.  Furthermore, if we did arrive
	 * here from kmdb, kmdb is probably in a very sickly state, and
	 * shouldn't be entered from the panic flow.  We'll suppress that
	 * entry by setting nopanicdebug.
	 */

	subl	$DESCTBR_SIZE, %esp
	movl	%gs:CPU_IDT, %eax
	sidt	(%esp)
	cmpl	DTR_BASE(%esp), %eax
	je	1f

	movl	%eax, DTR_BASE(%esp)
	movw	$_MUL(NIDT, GATE_DESC_SIZE), DTR_LIMIT(%esp)
	lidt	(%esp)

	movl	$1, nopanicdebug

1:	addl	$DESCTBR_SIZE, %esp

	/*
	 * Check the CPL in the TSS to see what mode
	 * (user or kernel) we took the fault in.  At this
	 * point we are running in the context of the double
	 * fault task (dftss) but the CPU's task points to
	 * the previous task (ktss) where the process context
	 * has been saved as the result of the task switch.
	 */
	movl	%gs:CPU_TSS, %eax	/* get the TSS */
	movl	TSS_SS(%eax), %ebx	/* save the fault SS */
	movl	TSS_ESP(%eax), %edx	/* save the fault ESP */
	testw	$CPL_MASK, TSS_CS(%eax)	/* user mode ? */
	jz	make_frame
	movw	TSS_SS0(%eax), %ss	/* get on the kernel stack */
	movl	TSS_ESP0(%eax), %esp

	/*
	 * Clear the NT flag to avoid a task switch when the process
	 * finally pops the EFL off the stack via an iret.  Clear
	 * the TF flag since that is what the processor does for
	 * a normal exception. Clear the IE flag so that interrupts
	 * remain disabled.
	 */
	movl	TSS_EFL(%eax), %ecx
	andl	$_BITNOT(PS_NT|PS_T|PS_IE), %ecx
	pushl	%ecx
	popfl				/* restore the EFL */
	movw	TSS_LDT(%eax), %cx	/* restore the LDT */
	lldt	%cx

	/*
	 * Restore process segment selectors.
	 */
	movw	TSS_DS(%eax), %ds
	movw	TSS_ES(%eax), %es
	movw	TSS_FS(%eax), %fs
	movw	TSS_GS(%eax), %gs

	/*
	 * Restore task segment selectors.
	 */
	movl	$KDS_SEL, TSS_DS(%eax)
	movl	$KDS_SEL, TSS_ES(%eax)
	movl	$KDS_SEL, TSS_SS(%eax)
	movl	$KFS_SEL, TSS_FS(%eax)
	movl	$KGS_SEL, TSS_GS(%eax)

	/*
	 * Clear the TS bit, the busy bits in both task
	 * descriptors, and switch tasks.
	 */
	clts
	leal	gdt0, %ecx
	movl	DFTSS_SEL+4(%ecx), %esi
	andl	$_BITNOT(0x200), %esi
	movl	%esi, DFTSS_SEL+4(%ecx)
	movl	KTSS_SEL+4(%ecx), %esi
	andl	$_BITNOT(0x200), %esi
	movl	%esi, KTSS_SEL+4(%ecx)
	movw	$KTSS_SEL, %cx
	ltr	%cx

	/*
	 * Restore part of the process registers.
	 */
	movl	TSS_EBP(%eax), %ebp
	movl	TSS_ECX(%eax), %ecx
	movl	TSS_ESI(%eax), %esi
	movl	TSS_EDI(%eax), %edi

make_frame:
	/*
	 * Make a trap frame.  Leave the error code (0) on
	 * the stack since the first word on a trap stack is
	 * unused anyway.
	 */
	pushl	%ebx			/ fault SS
	pushl	%edx			/ fault ESP
	pushl	TSS_EFL(%eax)		/ fault EFL
	pushl	TSS_CS(%eax)		/ fault CS
	pushl	TSS_EIP(%eax)		/ fault EIP
	pushl	$0			/ error code
	pushl	$T_DBLFLT		/ trap number 8
	movl	TSS_EBX(%eax), %ebx	/ restore EBX
	movl	TSS_EDX(%eax), %edx	/ restore EDX
	movl	TSS_EAX(%eax), %eax	/ restore EAX
	sti				/ enable interrupts
	jmp	cmntrap
	SET_SIZE(syserrtrap)

#endif	/* __i386 */
#endif	/* !__xpv */

	ENTRY_NP(overrun)
	push	$0
	TRAP_NOERR(T_EXTOVRFLT)	/* $9 i386 only - not generated */
	jmp	cmninttrap
	SET_SIZE(overrun)

	/*
	 * #TS
	 */
	ENTRY_NP(invtsstrap)
	TRAP_ERR(T_TSSFLT)	/* $10 already have error code on stack */
	jmp	cmntrap
	SET_SIZE(invtsstrap)

	/*
	 * #NP
	 */
	ENTRY_NP(segnptrap)
	TRAP_ERR(T_SEGFLT)	/* $11 already have error code on stack */
#if defined(__amd64)
	SET_CPU_GSBASE
#endif
	jmp	cmntrap
	SET_SIZE(segnptrap)

	/*
	 * #SS
	 */
	ENTRY_NP(stktrap)
	TRAP_ERR(T_STKFLT)	/* $12 already have error code on stack */
#if defined(__amd64)
	SET_CPU_GSBASE
#endif
	jmp	cmntrap
	SET_SIZE(stktrap)

	/*
	 * #GP
	 */
	ENTRY_NP(gptrap)
	TRAP_ERR(T_GPFLT)	/* $13 already have error code on stack */
#if defined(__amd64)
	SET_CPU_GSBASE
#endif
	jmp	cmntrap
	SET_SIZE(gptrap)

	/*
	 * #PF
	 */
	ENTRY_NP(pftrap)
	TRAP_ERR(T_PGFLT)	/* $14 already have error code on stack */
	INTR_PUSH
#if defined(__xpv)

#if defined(__amd64)
	movq	%gs:CPU_VCPU_INFO, %r15
	movq	VCPU_INFO_ARCH_CR2(%r15), %r15	/* vcpu[].arch.cr2 */
#elif defined(__i386)
	movl	%gs:CPU_VCPU_INFO, %esi
	movl	VCPU_INFO_ARCH_CR2(%esi), %esi	/* vcpu[].arch.cr2 */
#endif	/* __i386 */

#else	/* __xpv */

#if defined(__amd64)
	movq	%cr2, %r15
#elif defined(__i386)
	movl	%cr2, %esi
#endif	/* __i386 */

#endif	/* __xpv */
	jmp	cmntrap_pushed
	SET_SIZE(pftrap)

#if !defined(__amd64)

	.globl	idt0_default_r

	/*
	 * #PF pentium bug workaround
	 */
	ENTRY_NP(pentium_pftrap)
	pushl	%eax
	movl	%cr2, %eax
	andl	$MMU_STD_PAGEMASK, %eax

	cmpl	%eax, %cs:idt0_default_r+2	/* fixme */

	je	check_for_user_address
user_mode:
	popl	%eax
	pushl	$T_PGFLT	/* $14 */
	jmp	cmntrap
check_for_user_address:
	/*
	 * Before we assume that we have an unmapped trap on our hands,
	 * check to see if this is a fault from user mode.  If it is,
	 * we'll kick back into the page fault handler.
	 */
	movl	4(%esp), %eax	/* error code */
	andl	$PF_ERR_USER, %eax
	jnz	user_mode

	/*
	 * We now know that this is the invalid opcode trap.
	 */
	popl	%eax
	addl	$4, %esp	/* pop error code */
	jmp	invoptrap
	SET_SIZE(pentium_pftrap)

#endif	/* !__amd64 */

	ENTRY_NP(resvtrap)
	TRAP_NOERR(15)		/* (reserved)  */
	jmp	cmntrap
	SET_SIZE(resvtrap)

	/*
	 * #MF
	 */
	ENTRY_NP(ndperr)
	TRAP_NOERR(T_EXTERRFLT)	/* $16 */
	jmp	cmninttrap
	SET_SIZE(ndperr)

	/*
	 * #AC
	 */
	ENTRY_NP(achktrap)
	TRAP_ERR(T_ALIGNMENT)	/* $17 */
	jmp	cmntrap
	SET_SIZE(achktrap)

	/*
	 * #MC
	 */
	.globl	cmi_mca_trap	/* see uts/i86pc/os/cmi.c */

#if defined(__amd64)

	ENTRY_NP(mcetrap)
	TRAP_NOERR(T_MCE)	/* $18 */

	SET_CPU_GSBASE

	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS

	TRACE_PTR(%rdi, %rbx, %ebx, %rcx, $TT_TRAP)
	TRACE_REGS(%rdi, %rsp, %rbx, %rcx)
	TRACE_STAMP(%rdi)

	movq	%rsp, %rbp

	movq	%rsp, %rdi	/* arg0 = struct regs *rp */
	call	cmi_mca_trap	/* cmi_mca_trap(rp); */

	jmp	_sys_rtt
	SET_SIZE(mcetrap)

#else

	ENTRY_NP(mcetrap)
	TRAP_NOERR(T_MCE)	/* $18 */

	INTR_PUSH
	INTGATE_INIT_KERNEL_FLAGS

	TRACE_PTR(%edi, %ebx, %ebx, %ecx, $TT_TRAP)
	TRACE_REGS(%edi, %esp, %ebx, %ecx)
	TRACE_STAMP(%edi)

	movl	%esp, %ebp

	movl	%esp, %ecx
	pushl	%ecx		/* arg0 = struct regs *rp */
	call	cmi_mca_trap	/* cmi_mca_trap(rp) */
	addl	$4, %esp	/* pop arg0 */

	jmp	_sys_rtt
	SET_SIZE(mcetrap)

#endif

	/*
	 * #XF
	 */
	ENTRY_NP(xmtrap)
	TRAP_NOERR(T_SIMDFPE)	/* $19 */
	jmp	cmninttrap
	SET_SIZE(xmtrap)

	ENTRY_NP(invaltrap)
	TRAP_NOERR(30)		/* very invalid */
	jmp	cmntrap
	SET_SIZE(invaltrap)

	ENTRY_NP(invalint)
	TRAP_NOERR(31)		/* even more so */
	jmp	cmnint
	SET_SIZE(invalint)

	.globl	fasttable

#if defined(__amd64)

	ENTRY_NP(fasttrap)
	cmpl	$T_LASTFAST, %eax
	ja	1f
	orl	%eax, %eax	/* (zero extend top 32-bits) */
	leaq	fasttable(%rip), %r11
	leaq	(%r11, %rax, CLONGSIZE), %r11
	jmp	*(%r11)
1:
	/*
	 * Fast syscall number was illegal.  Make it look
	 * as if the INT failed.  Modify %rip to point before the
	 * INT, push the expected error code and fake a GP fault.
	 *
	 * XXX Why make the error code be offset into idt + 1?
	 * Instead we should push a real (soft?) error code
	 * on the stack and #gp handler could know about fasttraps?
	 */
	XPV_TRAP_POP

	subq	$2, (%rsp)	/* XXX int insn 2-bytes */
	pushq	$_CONST(_MUL(T_FASTTRAP, GATE_DESC_SIZE) + 2)

#if defined(__xpv)
	pushq	%r11
	pushq	%rcx
#endif
	jmp	gptrap
	SET_SIZE(fasttrap)

#elif defined(__i386)

	ENTRY_NP(fasttrap)
	cmpl	$T_LASTFAST, %eax
	ja	1f
	jmp	*%cs:fasttable(, %eax, CLONGSIZE)
1:
	/*
	 * Fast syscall number was illegal.  Make it look
	 * as if the INT failed.  Modify %eip to point before the
	 * INT, push the expected error code and fake a GP fault.
	 *
	 * XXX Why make the error code be offset into idt + 1?
	 * Instead we should push a real (soft?) error code
	 * on the stack and #gp handler could know about fasttraps?
	 */
	subl	$2, (%esp)	/* XXX int insn 2-bytes */
	pushl	$_CONST(_MUL(T_FASTTRAP, GATE_DESC_SIZE) + 2)
	jmp	gptrap
	SET_SIZE(fasttrap)

#endif	/* __i386 */

	ENTRY_NP(dtrace_ret)
	TRAP_NOERR(T_DTRACE_RET)
	jmp	dtrace_trap
	SET_SIZE(dtrace_ret)

#if defined(__amd64)

	/*
	 * RFLAGS 24 bytes up the stack from %rsp.
	 * XXX a constant would be nicer.
	 */
	ENTRY_NP(fast_null)
	XPV_TRAP_POP
	orq	$PS_C, 24(%rsp)	/* set carry bit in user flags */
	IRET
	/*NOTREACHED*/
	SET_SIZE(fast_null)

#elif defined(__i386)

	ENTRY_NP(fast_null)
	orw	$PS_C, 8(%esp)	/* set carry bit in user flags */
	IRET
	SET_SIZE(fast_null)

#endif	/* __i386 */

	/*
	 * Interrupts start at 32
	 */
#define MKIVCT(n)			\
	ENTRY_NP(ivct/**/n)		\
	push	$0;			\
	push	$n - 0x20;		\
	jmp	cmnint;			\
	SET_SIZE(ivct/**/n)

	MKIVCT(32)
	MKIVCT(33)
	MKIVCT(34)
	MKIVCT(35)
	MKIVCT(36)
	MKIVCT(37)
	MKIVCT(38)
	MKIVCT(39)
	MKIVCT(40)
	MKIVCT(41)
	MKIVCT(42)
	MKIVCT(43)
	MKIVCT(44)
	MKIVCT(45)
	MKIVCT(46)
	MKIVCT(47)
	MKIVCT(48)
	MKIVCT(49)
	MKIVCT(50)
	MKIVCT(51)
	MKIVCT(52)
	MKIVCT(53)
	MKIVCT(54)
	MKIVCT(55)
	MKIVCT(56)
	MKIVCT(57)
	MKIVCT(58)
	MKIVCT(59)
	MKIVCT(60)
	MKIVCT(61)
	MKIVCT(62)
	MKIVCT(63)
	MKIVCT(64)
	MKIVCT(65)
	MKIVCT(66)
	MKIVCT(67)
	MKIVCT(68)
	MKIVCT(69)
	MKIVCT(70)
	MKIVCT(71)
	MKIVCT(72)
	MKIVCT(73)
	MKIVCT(74)
	MKIVCT(75)
	MKIVCT(76)
	MKIVCT(77)
	MKIVCT(78)
	MKIVCT(79)
	MKIVCT(80)
	MKIVCT(81)
	MKIVCT(82)
	MKIVCT(83)
	MKIVCT(84)
	MKIVCT(85)
	MKIVCT(86)
	MKIVCT(87)
	MKIVCT(88)
	MKIVCT(89)
	MKIVCT(90)
	MKIVCT(91)
	MKIVCT(92)
	MKIVCT(93)
	MKIVCT(94)
	MKIVCT(95)
	MKIVCT(96)
	MKIVCT(97)
	MKIVCT(98)
	MKIVCT(99)
	MKIVCT(100)
	MKIVCT(101)
	MKIVCT(102)
	MKIVCT(103)
	MKIVCT(104)
	MKIVCT(105)
	MKIVCT(106)
	MKIVCT(107)
	MKIVCT(108)
	MKIVCT(109)
	MKIVCT(110)
	MKIVCT(111)
	MKIVCT(112)
	MKIVCT(113)
	MKIVCT(114)
	MKIVCT(115)
	MKIVCT(116)
	MKIVCT(117)
	MKIVCT(118)
	MKIVCT(119)
	MKIVCT(120)
	MKIVCT(121)
	MKIVCT(122)
	MKIVCT(123)
	MKIVCT(124)
	MKIVCT(125)
	MKIVCT(126)
	MKIVCT(127)
	MKIVCT(128)
	MKIVCT(129)
	MKIVCT(130)
	MKIVCT(131)
	MKIVCT(132)
	MKIVCT(133)
	MKIVCT(134)
	MKIVCT(135)
	MKIVCT(136)
	MKIVCT(137)
	MKIVCT(138)
	MKIVCT(139)
	MKIVCT(140)
	MKIVCT(141)
	MKIVCT(142)
	MKIVCT(143)
	MKIVCT(144)
	MKIVCT(145)
	MKIVCT(146)
	MKIVCT(147)
	MKIVCT(148)
	MKIVCT(149)
	MKIVCT(150)
	MKIVCT(151)
	MKIVCT(152)
	MKIVCT(153)
	MKIVCT(154)
	MKIVCT(155)
	MKIVCT(156)
	MKIVCT(157)
	MKIVCT(158)
	MKIVCT(159)
	MKIVCT(160)
	MKIVCT(161)
	MKIVCT(162)
	MKIVCT(163)
	MKIVCT(164)
	MKIVCT(165)
	MKIVCT(166)
	MKIVCT(167)
	MKIVCT(168)
	MKIVCT(169)
	MKIVCT(170)
	MKIVCT(171)
	MKIVCT(172)
	MKIVCT(173)
	MKIVCT(174)
	MKIVCT(175)
	MKIVCT(176)
	MKIVCT(177)
	MKIVCT(178)
	MKIVCT(179)
	MKIVCT(180)
	MKIVCT(181)
	MKIVCT(182)
	MKIVCT(183)
	MKIVCT(184)
	MKIVCT(185)
	MKIVCT(186)
	MKIVCT(187)
	MKIVCT(188)
	MKIVCT(189)
	MKIVCT(190)
	MKIVCT(191)
	MKIVCT(192)
	MKIVCT(193)
	MKIVCT(194)
	MKIVCT(195)
	MKIVCT(196)
	MKIVCT(197)
	MKIVCT(198)
	MKIVCT(199)
	MKIVCT(200)
	MKIVCT(201)
	MKIVCT(202)
	MKIVCT(203)
	MKIVCT(204)
	MKIVCT(205)
	MKIVCT(206)
	MKIVCT(207)
	MKIVCT(208)
	MKIVCT(209)
	MKIVCT(210)
	MKIVCT(211)
	MKIVCT(212)
	MKIVCT(213)
	MKIVCT(214)
	MKIVCT(215)
	MKIVCT(216)
	MKIVCT(217)
	MKIVCT(218)
	MKIVCT(219)
	MKIVCT(220)
	MKIVCT(221)
	MKIVCT(222)
	MKIVCT(223)
	MKIVCT(224)
	MKIVCT(225)
	MKIVCT(226)
	MKIVCT(227)
	MKIVCT(228)
	MKIVCT(229)
	MKIVCT(230)
	MKIVCT(231)
	MKIVCT(232)
	MKIVCT(233)
	MKIVCT(234)
	MKIVCT(235)
	MKIVCT(236)
	MKIVCT(237)
	MKIVCT(238)
	MKIVCT(239)
	MKIVCT(240)
	MKIVCT(241)
	MKIVCT(242)
	MKIVCT(243)
	MKIVCT(244)
	MKIVCT(245)
	MKIVCT(246)
	MKIVCT(247)
	MKIVCT(248)
	MKIVCT(249)
	MKIVCT(250)
	MKIVCT(251)
	MKIVCT(252)
	MKIVCT(253)
	MKIVCT(254)
	MKIVCT(255)

#endif	/* __lint */
