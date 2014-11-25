/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
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

/* 64-bit signal syscall numbers */
#define	LX_SYS_sigreturn	513
#define	LX_SYS_rt_sigreturn	15

/*
 * Each JMP must occupy 16 bytes.
 * The syscall offset is stored immediately above the red zone to avoid
 * clobbering data there.  Once lx_handler is reached, the stack will be
 * advanced to account for both the red zone and the stored syscall offset.
 */
#define	JMP	\
	movl	$_CONST(. - lx_handler_table), -136(%rsp); \
	jmp	lx_handler;	\
	.align	16;

#define	JMP4	JMP; JMP; JMP; JMP
#define	JMP16	JMP4; JMP4; JMP4; JMP4
#define	JMP64	JMP16; JMP16; JMP16; JMP16
#define	JMP256	JMP64; JMP64; JMP64; JMP64

/*
 * Alternate jump table that turns on lx_traceflag before proceeding with
 * the normal emulation routine.
 */
#define	TJMP	\
	movl	$_CONST(. - lx_handler_trace_table), -136(%rsp); \
	jmp	lx_handler_trace;	\
	.align	16;

#define	TJMP4	TJMP; TJMP; TJMP; TJMP
#define	TJMP16	TJMP4; TJMP4; TJMP4; TJMP4
#define	TJMP64	TJMP16; TJMP16; TJMP16; TJMP16
#define	TJMP256	TJMP64; TJMP64; TJMP64; TJMP64


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
	 * On entry to this table, %rax will hold the return address. The
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
	subq	$136, %rsp		/* skip red zone + syscall offset */
	pushq	%rsi
	movq    lx_traceflag@GOTPCREL(%rip), %rsi
	movq	$1, (%rsi)
	popq	%rsi
	addq	$136, %rsp
	/*
	 * While we could just fall through to lx_handler(), we "tail-call" it
	 * instead to make ourselves a little more comprehensible to trace
	 * tools.
	 */
	jmp	lx_handler
	SET_SIZE(lx_handler_trace)

	ALTENTRY(lx_handler)
	/*
	 * We are running on the Linux process's stack here so we have to
	 * account for the AMD64 ABI red zone of 128 bytes past the %rsp which
	 * the process can use as scratch space.  In addition to the red zone,
	 * the syscall offset stored by the handler tables above must be
	 * accounted for.  To that end, rsp is advanced by a further 8 bytes to
	 * include the syscall offset.
	 */
	subq	$136, %rsp /* red zone + syscall offset */

	/*
	 * In order to keep the hander_table entries within 16 bytes, only 4
	 * bytes of the syscall offset are stored during dispatch.
	 * The upper 4 bytes are zeroed here to account for that.
	 */
	movl	$0, 4(%rsp)

	/*
	 * %rbp isn't always going to be a frame pointer on Linux, but when
	 * it is, saving it here lets us have a coherent stack backtrace.
	 */
	pushq	%rbp

	/*
	 * Fill in a lx_regs_t structure on the stack.
	 */
	subq	$SIZEOF_LX_REGS_T, %rsp

	/*
	 * Save %rbp and then fill it with what would be its usual value as
	 * the frame pointer. The value we save for %rsp needs to be the
	 * stack pointer at the time of the syscall so we need to skip the
	 * red zone, saved %rbp and (what will be) the return address.
	 */
	movq	%rbp, LXR_RBP(%rsp)
	movq	%rsp, %rbp
	addq	$SIZEOF_LX_REGS_T, %rbp
	movq	%rbp, LXR_RSP(%rsp)
	addq	$144, LXR_RSP(%rsp)	/* 128 byte red zone + 2 pointers */

	movq	$0, LXR_FS(%rsp)
	movw	%fs, LXR_FS(%rsp)
	movq	%rdi, LXR_RDI(%rsp)
	movq	%rsi, LXR_RSI(%rsp)
	movq	%rbx, LXR_RBX(%rsp)
	movq	%rdx, LXR_RDX(%rsp)
	movq	%rcx, LXR_RCX(%rsp)
	movq	%rax, LXR_RIP(%rsp)	/* %rax holds the return addr. */
	movq	%r8, LXR_R8(%rsp)
	movq	%r9, LXR_R9(%rsp)
	movq	%r10, LXR_R10(%rsp)
	movq	%r11, LXR_R11(%rsp)
	movq	%r12, LXR_R12(%rsp)
	movq	%r13, LXR_R13(%rsp)
	movq	%r14, LXR_R14(%rsp)
	movq	%r15, LXR_R15(%rsp)

	/*
	 * The kernel drops us into the middle of one of the tables above
	 * that then stores the table offset immediately above the 128 byte
	 * red zone and calls into lx_handler.  That offset indicates the
	 * syscall number while %rax holds the return address for the syscall.
	 * We replace the value on the stack with the return address, and use
	 * the value to compute the system call number by dividing by the table
	 * entry size.
	 */
	xchgq	8(%rbp), %rax		/* just after the rbp we pushed */
	shrq	$4, %rax
	movq	%rax, LXR_RAX(%rsp)

	/*
	 * Call lx_emulate() whose only argument is a pointer to the
	 * lx_regs_t structure we've placed on the stack.
	 */
	movq	%rsp, %rdi
	call	lx_emulate

	/*
	 * We use this global symbol to identify this return site when
	 * walking the stack backtrace. It needs to remain immediately
	 * after the call to lx_emulate().
	 */
	ALTENTRY(lx_emulate_done)

	/*
	 * Restore the saved register state; we get %rbp and %rsp from
	 * the ordinary locations rather than the saved state.
	 */
	movq	LXR_RDI(%rsp), %rdi
	movq	LXR_RSI(%rsp), %rsi
	movq	LXR_RBX(%rsp), %rbx
	movq	LXR_RDX(%rsp), %rdx
	movq	LXR_RCX(%rsp), %rcx
	movq	LXR_RAX(%rsp), %rax
	movq	LXR_R8(%rsp), %r8
	movq	LXR_R9(%rsp), %r9
	movq	LXR_R10(%rsp), %r10
	movq	LXR_R11(%rsp), %r11
	movq	LXR_R12(%rsp), %r12
	movq	LXR_R13(%rsp), %r13
	movq	LXR_R14(%rsp), %r14
	movq	LXR_R15(%rsp), %r15
	/* XXX movw	LXR_FS(%rsp), %fs */

	movq	%rbp, %rsp
	popq	%rbp

	/*
	 * Returning from lx_handler is complicated by our preservation of the
	 * red zone on the stack.  The return address resides just above the
	 * red zone making it impossible to use 'retq' and return rsp to the
	 * correct value.  Instead, rsp is manually moved to its original
	 * position and we jmp using the return address at the known stack
	 * offset above the red zone.
	 */
	addq	$136, %rsp		/* red zone + return address */
	jmpq	*-136(%rsp)
	SET_SIZE(lx_handler)

	/*
	 * lx_setup_clone(lx_regs_t *regp, void *retaddr, void *stack)
	 * Restore the register state using arg0 (%rdi).
	 * Return to Linux app using arg1 (%rsi) with the Linux stack we got
	 * in arg2 (%rdx).
	 */
	ENTRY_NP(lx_setup_clone)
	/*
	 * arg0 is a ptr to an lx_regs_t struct. The AMD64 ABI says that the
	 * kernel clobbers %rcx and %r11 so we use those for working registers.
	 */
	movq	%rdi, %rcx	/* arg0, use rcx as ptr */
	movq	%rsi, %r11	/* arg1, the return addr */
	movq	LXR_RDI(%rcx), %rdi
	movq	LXR_RSI(%rcx), %rsi
	movq	LXR_RBX(%rcx), %rbx
	movq	LXR_R8(%rcx), %r8
	movq	LXR_R9(%rcx), %r9
	movq	LXR_R10(%rcx), %r10
	movq	LXR_R12(%rcx), %r12
	movq	LXR_R13(%rcx), %r13
	movq	LXR_R14(%rcx), %r14
	movq	LXR_R15(%rcx), %r15

	xorq	%rbp, %rbp	/* terminating stack */
	popq	%rax		/* pop the clone_start() return address */
	movq	%rdx, %rsp	/* arg2 is new stack pointer */
	movq	LXR_RDX(%rcx), %rdx
	xorq	%rax, %rax	/* child returns 0 to SYS_clone() */
	jmp	*%r11		/* return to Linux app. using arg1 addr. */
	SET_SIZE(lx_setup_clone)

	/*
	 * lx_sigdeliver(int sig, siginfo_t *, ucontext_t *, int stack_size,
	 *     void *stack_build_routine, void *signal_handler, void *glibc_gs)
	 *
	 * The final parameter (%gs) is ignored in the 64-bit code.
	 *
	 * we're called by:
	 *     lx_call_user_handler(int sig, siginfo_t *sip, void *p)
	 *
	 * This routine allocates stack space for the lx_sigstack local
	 * variable structure, calls a routine to populate that structure, and
	 * then calls the Linux signal handler.  This is written in assembly
	 * because of the way we directly jmp to the Linux signal handler
	 * with everything setup as if this function wasn't really here. We
	 * rely on the code in lx_rt_sigreturn() to cleanup the things we've
	 * pushed on the stack here.
	 *
	 * See lx_build_signal_frame() for the code which populates lx_sigstack.
	 *
	 * When we jump to the Linux signal handler, the stack will look
	 * like this:
	 *
	 * 	=================================================
	 * 	| %rbp						|
	 * | 	=================================================
	 * |	| stuff we saved in our prologue		|
	 * |	=================================================
	 * |	| LX_SIGRT_MAGIC				|
	 * |	=================================================
	 * |	| {unused word to maintain ABI stack alignment} |
	 * V	=================================================
	 *	| Linux local data built by lx stk_builder()	|
	 * 	=================================================
	 *
	 * Unlike the 32-bit case, we don't reset %rbp before jumping into the
	 * Linux handler, since that would mean the handler would clobber our
	 * data in the stack frame it builds.
	 *
	 */
	ENTRY_NP(lx_sigdeliver)
	pushq   %rbp
	movq    %rsp, %rbp
	subq	$0x40, %rsp		/* an extra word to maintain alignmnt */
	movq	%rdi,  -8(%rbp)		/* sig */
	movq	%rsi, -16(%rbp)		/* siginfo* */
	movq	%rdx, -24(%rbp)		/* ucontext* */
	movq	%rcx, -32(%rbp)		/* stack size */
	movq	%r8,  -40(%rbp)		/* stack builder */
	movq	%r9,  -48(%rbp)		/* Linux signal handler */

	subq    %rcx, %rsp		/* create stack_size stack buffer */

	movq	$LX_SIGRT_MAGIC, %rcx	/* load and place marker value onto */
	movq	%rcx, -56(%rbp)		/*        stack for lx_rt_sigreturn */

	movq	%rsp, %rcx		/* arg3 - %rcx is stack pointer */
					/* arg2 - %rdx is ucontext ptr */
					/* arg1 - %rsi is siginfo ptr */
					/* arg0 - %rdi is sig num */
	call    *%r8			/* stk_builder(sig, sip, ucp, sp) */

	/* setup for jump to Linux signal hander */
	movq	-8(%rbp), %rdi		/* arg0 %rdi is sig num */

	/*
	 * If we had a NULL siginfo pointer as input then we never converted
	 * anything in the stack builder function and we need to pass along
	 * a null siginfo pointer to the Linux handler.
	 *
	 * arg1 %rsi is ptr to converted siginfo on stack or NULL
	 */
	movq	-16(%rbp), %rsi
	cmp	$0, %rsi
	je	1f
	movq	%rsp, %rsi
	addq	$SI, %rsi
1:
	/*
	 * arg2 %rdx is ptr to converted ucontext on stk (uc member of
	 * lx_sigstack).
	 */
	movq	%rsp, %rdx
	addq	$UC, %rdx

	movq	-48(%rbp), %r9		/* fetch signal handler ptr */
	jmp	*%r9			/* jmp to the Linux signal handler */
	SET_SIZE(lx_sigdeliver)

	/*
	 * The libc routine that calls user signal handlers ends with a
	 * setcontext, so we would never return here even if we used a call
	 * rather than a jmp. However, we'll let the emulation unwind the stack
	 * with a brand call that combines the setcontext with the management
	 * of the syscall mode flag.
	 *
	 * Note that because libc_sigacthandler is an extern, it needs to be
	 * dereferenced via the GOT.
	 *
	 * IMPORTANT:  Because libc apparently gets upset if extra data is
	 *	       left on its stack, this routine needs to be crafted
	 *	       in assembly so that the jmp to the libc interposer
	 *	       doesn't leave any cruft lying around.
	 *
	 * lx_sigacthandler(int sig, siginfo_t *s, void *p)
	 */
	ENTRY_NP(lx_sigacthandler)
	movq    libc_sigacthandler@GOTPCREL(%rip), %rax
	jmp     *(%rax)				/* jmp to libc's interposer */
	SET_SIZE(lx_sigacthandler)

	/*
	 * Trampoline code is called by the return at the end of a Linux
	 * signal handler to return control to the interrupted application
	 * via the lx_rt_sigreturn() syscall.
	 */
	ENTRY_NP(lx_rt_sigreturn_tramp)
	movq	$LX_SYS_rt_sigreturn, %rax
	syscall
	SET_SIZE(lx_rt_sigreturn_tramp)

	/*
	 * Manipulate the stack in the way necessary for it to appear to libc
	 * that the signal handler it invoked via call_user_handler() is
	 * returning.
	 */
	ENTRY_NP(lx_sigreturn_tolibc)
	movq	%rdi, %rsp		/* set %rsp to passed value */
	popq	%rbp			/* restore proper %rbp */
	ret				/* return to lx_call_user_handler */
	SET_SIZE(lx_sigreturn_tolibc)
#endif	/* lint */
