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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#include <sys/asm_linkage.h>
#include <sys/regset.h>
#include <sys/segments.h>
#include <sys/syscall.h>
#include <sys/lx_brand.h>

#if defined(_ASM)
#include <sys/lx_signal.h>
#include <sys/lx_syscall.h>
#endif	/* _ASM */

#include "assym.h"

/* 32-bit syscall numbers */
#define	LX_SYS_sigreturn	119
#define	LX_SYS_rt_sigreturn	173

#define	PIC_SETUP(r)					\
	call	9f;					\
9:	popl	r;					\
	addl	$_GLOBAL_OFFSET_TABLE_ + [. - 9b], r

/*
 * Each JMP must occupy 16 bytes
 */
#define	JMP	\
	pushl	$_CONST(. - lx_handler_table); \
	jmp	lx_handler;	\
	.align	16;	

#define	JMP4	JMP; JMP; JMP; JMP
#define JMP16	JMP4; JMP4; JMP4; JMP4
#define JMP64	JMP16; JMP16; JMP16; JMP16
#define JMP256	JMP64; JMP64; JMP64; JMP64

/*
 * Alternate jump table that turns on lx_traceflag before proceeding with
 * the normal emulation routine.
 */
#define	TJMP	\
	pushl	$_CONST(. - lx_handler_trace_table); \
	jmp	lx_handler_trace;	\
	.align	16;	

#define	TJMP4	TJMP; TJMP; TJMP; TJMP
#define TJMP16	TJMP4; TJMP4; TJMP4; TJMP4
#define TJMP64	TJMP16; TJMP16; TJMP16; TJMP16
#define TJMP256	TJMP64; TJMP64; TJMP64; TJMP64

	
#if defined(lint)

#include <sys/types.h>
#include <sys/regset.h>
#include <sys/signal.h>

void
lx_handler_table(void)
{}

void
lx_handler(void)
{}

/* ARGSUSED */
void
lx_setup_clone(uintptr_t gs, void *retaddr, void *stk)
{}

/* ARGSUSED */
void
lx_sigdeliver(int sig, siginfo_t *sip, void *p, size_t stacksz,
    void (*stack_frame_builder)(void), void (*lx_sighandler)(void),
    uintptr_t gs)
{}

/* ARGSUSED */
void
lx_sigacthandler(int sig, siginfo_t *s, void *p)
{}

void
lx_sigreturn_tramp(void)
{}

void
lx_rt_sigreturn_tramp(void)
{}

/* ARGSUSED */
void
lx_sigreturn_tolibc(uintptr_t sp)
{}

#else	/* lint */

	/*
	 * On entry to this table, %eax will hold the return address. The
	 * location where we enter the table is a function of the system
	 * call number. The table needs the same alignment as the individual
	 * entries.
	 */
	.align	16
	ENTRY_NP(lx_handler_trace_table)
	TJMP256
	TJMP64
	TJMP64
	SET_SIZE(lx_handler_trace_table)

	.align	16
	ENTRY_NP(lx_handler_table)
	JMP256
	JMP64
	JMP64
	SET_SIZE(lx_handler_table)

	ENTRY_NP(lx_handler_trace)
	pushl	%esi
	PIC_SETUP(%esi)
	movl	lx_traceflag@GOT(%esi), %esi
	movl	$1, (%esi)
	popl	%esi
	/*
	 * While we could just fall through to lx_handler(), we "tail-call" it
	 * instead to make ourselves a little more comprehensible to trace
	 * tools.
	 */
	jmp	lx_handler
	SET_SIZE(lx_handler_trace)
	
	ALTENTRY(lx_handler)
	/*
	 * %ebp isn't always going to be a frame pointer on Linux, but when
	 * it is, saving it here lets us have a coherent stack backtrace.
	 */
	pushl	%ebp

	/*
	 * Fill in a lx_regs_t structure on the stack.
	 */
	subl	$SIZEOF_LX_REGS_T, %esp

	/*
	 * Save %ebp and then fill it with what would be its usual value as
	 * the frame pointer. The value we save for %esp needs to be the
	 * stack pointer at the time of the interrupt so we need to skip the
	 * saved %ebp and (what will be) the return address.
	 */
	movl	%ebp, LXR_EBP(%esp)
	movl	%esp, %ebp
	addl	$_CONST(SIZEOF_LX_REGS_T), %ebp
	movl	%ebp, LXR_ESP(%esp)
	addl	$_CONST(_MUL(CPTRSIZE, 2)), LXR_ESP(%esp)

	movl	$0, LXR_GS(%esp)
	movw	%gs, LXR_GS(%esp)
	movl	%edi, LXR_EDI(%esp)
	movl	%esi, LXR_ESI(%esp)
	movl	%ebx, LXR_EBX(%esp)
	movl	%edx, LXR_EDX(%esp)
	movl	%ecx, LXR_ECX(%esp)
	movl	%eax, LXR_EIP(%esp)

	/*
	 * The kernel drops us into the middle of one of the tables above
	 * that then pushes that table offset onto the stack, and calls into
	 * lx_handler. That offset indicates the system call number while
	 * %eax holds the return address for the system call. We replace the
	 * value on the stack with the return address, and use the value to
	 * compute the system call number by dividing by the table entry size.
	 */
	xchgl	CPTRSIZE(%ebp), %eax
	shrl	$4, %eax
	movl	%eax, LXR_EAX(%esp)

	/*
	 * Switch to the Solaris libc's %gs.
	 */
	movl	$LWPGS_SEL, %ebx
	movw	%bx, %gs

	/*
	 * Call lx_emulate() whose only argument is a pointer to the
	 * lx_regs_t structure we've placed on the stack.
	 */
	pushl	%esp
	call	lx_emulate

	/*
	 * We use this global symbol to identify this return site when
	 * walking the stack backtrace. It needs to remain immediately
	 * after the call to lx_emulate().
	 */
	ALTENTRY(lx_emulate_done)

	/*
	 * Clean up the argument to lx_emulate().
	 */
	addl	$4, %esp

	/*
	 * Restore the saved register state; we get %ebp, %esp and %esp from
	 * the ordinary locations rather than the saved state.
	 */
	movl	LXR_EDI(%esp), %edi
	movl	LXR_ESI(%esp), %esi
	movl	LXR_EBX(%esp), %ebx
	movl	LXR_EDX(%esp), %edx
	movl	LXR_ECX(%esp), %ecx
	movl	LXR_EAX(%esp), %eax
	movw	LXR_GS(%esp), %gs

	addl	$SIZEOF_LX_REGS_T, %esp

	movl	%ebp, %esp
	popl	%ebp
	ret
	SET_SIZE(lx_handler)

	ENTRY_NP(lx_swap_gs)
	push	%eax		/* save the current eax value */
	movl	0xc(%esp),%eax	/* 2nd param is a pointer */
	movw	%gs,(%eax)	/* use the pointer to save current gs */
	movl	0x8(%esp),%eax	/* first parameter is the new gs value */
	movw	%ax, %gs	/* switch to the new gs value */
	pop	%eax		/* restore eax */
	ret
	SET_SIZE(lx_swap_gs)

	ENTRY_NP(lx_setup_clone)
	xorl	%ebp, %ebp	/* terminating stack */
	popl	%edx		/* eat the clone_start() return address */
	popl	%gs		/* Switch back to the Linux libc's %gs */
	popl	%edx		/* Linux clone() return address */
	popl	%esp		/* New stack pointer */
	xorl	%eax, %eax	/* child returns 0 to SYS_clone() */
	jmp	*%edx		/* return to Linux app. */
	SET_SIZE(lx_setup_clone)

	/*
	 * lx_sigdeliver(sig, siginfo_t *, ucontext_t *, stack_size,
	 *     stack_build_routine, signal_handler, glibc_gs)
	 *
	 * This routine allocates stack space for the Linux signal stack,
	 * calls a routine to build the signal stack and then calls the Linux
	 * signal handler.  This is written in assembly because of the way
	 * we need to directly manipulate the stack and pass the resulting
	 * stack to the signal handler with the Linux signal stack on top.
	 *
	 * When the Linux signal handler is called, the stack will look
	 * like this:
	 *
	 * 	=================================================
	 * |	| %ebp						|
	 * | 	=================================================
	 * |	| LX_SIGRT_MAGIC				|
	 * | 	=================================================
	 * V	| Linux signal frame built by lx_stackbuilder() |
	 * 	=================================================
	 *
	 * The stack frame (%ebp) will be reset to its original value (i.e. the
	 * previous frame) on entry to the Linux signal handler.
	 */
	ENTRY_NP(lx_sigdeliver)
	pushl   %ebp
	movl    %esp, %ebp
	movl	16(%ebp), %edx		/* pointer to Solaris ucontext_t */
	pushl	%edx			/* save ucontext_t ptr for later */
	pushl	$LX_SIGRT_MAGIC		/* marker value for lx_(rt)_sigreturn */

	subl    20(%ebp), %esp		/* create stack_size stack buffer */
	pushl   %esp			/* push stack pointer */
	pushl   %edx			/* push pointer to ucontext_t */
	pushl   12(%ebp)		/* push pointer to siginfo_t */
	pushl   8(%ebp)			/* push signal number */
	call    *24(%ebp)		/* lx_stackbuilder(sig, sip, ucp, sp) */
	add     $16, %esp		/* remove args from stack */
	movw	32(%ebp), %gs		/* only low 16 bits are used */

	mov	4(%ebp),%eax		/* fetch old %ebp from stack */
	mov	28(%ebp), %edx		/* get address of Linux handler */
	mov	%eax, %ebp		/* restore old %ebp */
	jmp	*%edx			/* jmp to the Linux signal handler */
	SET_SIZE(lx_sigdeliver)

	/*
	 * Due to the nature of signals, we need to be able to force the %gs
	 * value to that used by Solaris by running any Solaris code.
	 *
	 * This routine does that, then calls a C routine that will save the
	 * %gs value at the time of the signal off into a thread-specific data
	 * structure.  Finally, we trampoline to the libc code that would
	 * normally interpose itself before calling a signal handler.
	 *
	 * The libc routine that calls user signal handlers ends with a
	 * setcontext, so we would never return here even if we used a call
	 * rather than a jmp.
	 *
	 * %esi is used for the PIC as it is guaranteed by the 386 ABI to
	 * survive the call to lx_sigsavegs.  The downside is we must also
	 * preserve its value for our caller.
	 *
	 * Note that because lx_sigsavegs and libc_sigacthandler are externs,
	 * they need to be dereferenced via the GOT.
	 *
	 * IMPORTANT:  Because libc apparently gets upset if extra data is
	 *	       left on its stack, this routine needs to be crafted
	 *	       in assembly so that the jmp to the libc interposer
	 *	       doesn't leave any cruft lying around.
	 */
	ENTRY_NP(lx_sigacthandler)
	pushl	%esi				/* save %esi */
	pushl	%gs				/* push the Linux %gs */
	pushl	$LWPGS_SEL
	popl	%gs				/* install the Solaris %gs */

	PIC_SETUP(%esi)
	movl	lx_sigsavegs@GOT(%esi), %eax
	call	*%eax				/* save the Linux %gs */
	movl    libc_sigacthandler@GOT(%esi), %eax 
	add	$4, %esp			/* clear Linux %gs from stack */
	popl	%esi				/* restore %esi */
	jmp     *(%eax)				/* jmp to libc's interposer */
	SET_SIZE(lx_sigacthandler)

	/*
	 * Trampoline code is called by the return at the end of a Linux
	 * signal handler to return control to the interrupted application
	 * via the lx_sigreturn() or lx_rt_sigreturn() syscalls.
	 *
	 * (lx_sigreturn() is called for legacy signal handling, and
	 * lx_rt_sigreturn() is called for "new"-style signals.)
	 *
	 * These two routines must consist of the EXACT code sequences below
	 * as gdb looks at the sequence of instructions a routine will return
	 * to determine whether it is in a signal handler or not.
	 * See the Linux code setup_signal_stack_sc() in arch/x86/um/signal.c.
	 */
	ENTRY_NP(lx_sigreturn_tramp)
	popl	%eax
	movl	$LX_SYS_sigreturn, %eax
	int	$0x80
	SET_SIZE(lx_sigreturn_tramp)

	ENTRY_NP(lx_rt_sigreturn_tramp)
	movl	$LX_SYS_rt_sigreturn, %eax
	int	$0x80
	SET_SIZE(lx_rt_sigreturn_tramp)

	/*
	 * Manipulate the stack in the way necessary for it to appear to libc
	 * that the signal handler it invoked via call_user_handler() is
	 * returning.
	 */
	ENTRY_NP(lx_sigreturn_tolibc)
	movl	4(%esp), %esp		/* set %esp to passed value */
	popl	%ebp			/* restore proper %ebp */
	ret				/* return to lx_call_user_handler */
	SET_SIZE(lx_sigreturn_tolibc)
#endif	/* lint */
