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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/privregs.h>
#include <sys/psw.h>
#include <sys/machbrand.h>

#if defined(__lint)

#include <sys/types.h>
#include <sys/thread.h>
#include <sys/systm.h>

#else	/* __lint */

#include <sys/segments.h>
#include <sys/pcb.h>
#include <sys/trap.h>
#include <sys/ftrace.h>
#include <sys/traptrace.h>
#include <sys/clock.h>
#include <sys/model.h>
#include <sys/panic.h>

#if defined(__xpv)
#include <sys/hypervisor.h>
#endif

#include "assym.h"

#endif	/* __lint */

/*
 * We implement five flavours of system call entry points
 *
 * -	syscall/sysretq		(amd64 generic)
 * -	syscall/sysretl		(i386 plus SYSC bit)
 * -	sysenter/sysexit	(i386 plus SEP bit)
 * -	int/iret		(i386 generic)
 * -	lcall/iret		(i386 generic)
 *
 * The current libc included in Solaris uses int/iret as the base unoptimized
 * kernel entry method. Older libc implementations and legacy binaries may use
 * the lcall call gate, so it must continue to be supported.
 *
 * System calls that use an lcall call gate are processed in trap() via a
 * segment-not-present trap, i.e. lcalls are extremely slow(!).
 *
 * The basic pattern used in the 32-bit SYSC handler at this point in time is
 * to have the bare minimum of assembler, and get to the C handlers as
 * quickly as possible.
 *
 * The 64-bit handler is much closer to the sparcv9 handler; that's
 * because of passing arguments in registers.  The 32-bit world still
 * passes arguments on the stack -- that makes that handler substantially
 * more complex.
 *
 * The two handlers share a few code fragments which are broken
 * out into preprocessor macros below.
 *
 * XX64	come back and speed all this up later.  The 32-bit stuff looks
 * especially easy to speed up the argument copying part ..
 *
 *
 * Notes about segment register usage (c.f. the 32-bit kernel)
 *
 * In the 32-bit kernel, segment registers are dutifully saved and
 * restored on all mode transitions because the kernel uses them directly.
 * When the processor is running in 64-bit mode, segment registers are
 * largely ignored.
 *
 * %cs and %ss
 *	controlled by the hardware mechanisms that make mode transitions
 *
 * The remaining segment registers have to either be pointing at a valid
 * descriptor i.e. with the 'present' bit set, or they can NULL descriptors
 *
 * %ds and %es
 *	always ignored
 *
 * %fs and %gs
 *	fsbase and gsbase are used to control the place they really point at.
 *	The kernel only depends on %gs, and controls its own gsbase via swapgs
 *
 * Note that loading segment registers is still costly because the GDT
 * lookup still happens (this is because the hardware can't know that we're
 * not setting up these segment registers for a 32-bit program).  Thus we
 * avoid doing this in the syscall path, and defer them to lwp context switch
 * handlers, so the register values remain virtualized to the lwp.
 */

#if defined(SYSCALLTRACE)
#define	ORL_SYSCALLTRACE(r32)		\
	orl	syscalltrace(%rip), r32
#else
#define	ORL_SYSCALLTRACE(r32)
#endif

/*
 * In the 32-bit kernel, we do absolutely nothing before getting into the
 * brand callback checks.  In 64-bit land, we do swapgs and then come here.
 * We assume that the %rsp- and %r15-stashing fields in the CPU structure
 * are still unused.
 *
 * Check if a brand_mach_ops callback is defined for the specified callback_id
 * type.  If so invoke it with the kernel's %gs value loaded and the following
 * data on the stack:
 *
 * stack:  --------------------------------------
 *      32 | callback pointer			|
 *    | 24 | user (or interrupt) stack pointer	|
 *    | 16 | lwp pointer			|
 *    v  8 | userland return address		|
 *       0 | callback wrapper return addr	|
 *         --------------------------------------
 *
 * Since we're pushing the userland return address onto the kernel stack
 * we need to get that address without accessing the user's stack (since we
 * can't trust that data).  There are different ways to get the userland
 * return address depending on how the syscall trap was made:
 *
 * a) For sys_syscall and sys_syscall32 the return address is in %rcx.
 * b) For sys_sysenter the return address is in %rdx.
 * c) For sys_int80 and sys_syscall_int (int91), upon entry into the macro,
 *    the stack pointer points at the state saved when we took the interrupt:
 *	 ------------------------
 *    |  | user's %ss		|
 *    |  | user's %esp		|
 *    |  | EFLAGS register	|
 *    v  | user's %cs		|
 *       | user's %eip		|
 *	 ------------------------
 *
 * The 2nd parameter to the BRAND_CALLBACK macro is either the
 * BRAND_URET_FROM_REG or BRAND_URET_FROM_INTR_STACK macro.  These macros are
 * used to generate the proper code to get the userland return address for
 * each syscall entry point.
 *
 * The interface to the brand callbacks on the 64-bit kernel assumes %r15
 * is available as a scratch register within the callback.  If the callback
 * returns within the kernel then this macro will restore %r15.  If the
 * callback is going to return directly to userland then it should restore
 * %r15 before returning to userland.
 */
#define BRAND_URET_FROM_REG(rip_reg)					\
	pushq	rip_reg			/* push the return address	*/

/*
 * The interrupt stack pointer we saved on entry to the BRAND_CALLBACK macro
 * is currently pointing at the user return address (%eip).
 */
#define BRAND_URET_FROM_INTR_STACK()					\
	movq	%gs:CPU_RTMP_RSP, %r15	/* grab the intr. stack pointer	*/ ;\
	pushq	(%r15)			/* push the return address	*/

#define	BRAND_CALLBACK(callback_id, push_userland_ret)			    \
	movq	%rsp, %gs:CPU_RTMP_RSP	/* save the stack pointer	*/ ;\
	movq	%r15, %gs:CPU_RTMP_R15	/* save %r15			*/ ;\
	movq	%gs:CPU_THREAD, %r15	/* load the thread pointer	*/ ;\
	movq	T_STACK(%r15), %rsp	/* switch to the kernel stack	*/ ;\
	subq	$16, %rsp		/* save space for 2 pointers	*/ ;\
	pushq	%r14			/* save %r14			*/ ;\
	movq	%gs:CPU_RTMP_RSP, %r14					   ;\
	movq	%r14, 8(%rsp)		/* stash the user stack pointer	*/ ;\
	popq	%r14			/* restore %r14			*/ ;\
	movq	T_LWP(%r15), %r15	/* load the lwp pointer		*/ ;\
	pushq	%r15			/* push the lwp pointer		*/ ;\
	movq	LWP_PROCP(%r15), %r15	/* load the proc pointer	*/ ;\
	movq	P_BRAND(%r15), %r15	/* load the brand pointer	*/ ;\
	movq	B_MACHOPS(%r15), %r15	/* load the machops pointer	*/ ;\
	movq	_CONST(_MUL(callback_id, CPTRSIZE))(%r15), %r15		   ;\
	cmpq	$0, %r15						   ;\
	je	1f							   ;\
	movq	%r15, 16(%rsp)		/* save the callback pointer	*/ ;\
	push_userland_ret		/* push the return address	*/ ;\
	call	*24(%rsp)		/* call callback		*/ ;\
1:	movq	%gs:CPU_RTMP_R15, %r15	/* restore %r15			*/ ;\
	movq	%gs:CPU_RTMP_RSP, %rsp	/* restore the stack pointer	*/

#define	MSTATE_TRANSITION(from, to)		\
	movl	$from, %edi;			\
	movl	$to, %esi;			\
	call	syscall_mstate

/*
 * Check to see if a simple (direct) return is possible i.e.
 *
 *	if (t->t_post_sys_ast | syscalltrace |
 *	    lwp->lwp_pcb.pcb_rupdate == 1)
 *		do full version	;
 *
 * Preconditions:
 * -	t is curthread
 * Postconditions:
 * -	condition code NE is set if post-sys is too complex
 * -	rtmp is zeroed if it isn't (we rely on this!)
 * -	ltmp is smashed
 */
#define	CHECK_POSTSYS_NE(t, ltmp, rtmp)			\
	movq	T_LWP(t), ltmp;				\
	movzbl	PCB_RUPDATE(ltmp), rtmp;		\
	ORL_SYSCALLTRACE(rtmp);				\
	orl	T_POST_SYS_AST(t), rtmp;		\
	cmpl	$0, rtmp
	
/*
 * Fix up the lwp, thread, and eflags for a successful return
 *
 * Preconditions:
 * -	zwreg contains zero
 */
#define	SIMPLE_SYSCALL_POSTSYS(t, lwp, zwreg)		\
	movb	$LWP_USER, LWP_STATE(lwp);		\
	movw	zwreg, T_SYSNUM(t);			\
	andb	$_CONST(0xffff - PS_C), REGOFF_RFL(%rsp)

/*
 * ASSERT(lwptoregs(lwp) == rp);
 *
 * This may seem obvious, but very odd things happen if this
 * assertion is false
 *
 * Preconditions:
 *	(%rsp is ready for normal call sequence)
 * Postconditions (if assertion is true):
 *	%r11 is smashed
 *
 * ASSERT(rp->r_cs == descnum)
 *
 * The code selector is written into the regs structure when the
 * lwp stack is created.  We use this ASSERT to validate that
 * the regs structure really matches how we came in.
 *
 * Preconditions:
 *	(%rsp is ready for normal call sequence)
 * Postconditions (if assertion is true):
 *	-none-
 *
 * ASSERT(lwp->lwp_pcb.pcb_rupdate == 0);
 *
 * If this is false, it meant that we returned to userland without
 * updating the segment registers as we were supposed to.
 *
 * Note that we must ensure no interrupts or other traps intervene
 * between entering privileged mode and performing the assertion,
 * otherwise we may perform a context switch on the thread, which
 * will end up setting pcb_rupdate to 1 again.
 */
#if defined(DEBUG)

#if !defined(__lint)

__lwptoregs_msg:
	.string	"syscall_asm_amd64.s:%d lwptoregs(%p) [%p] != rp [%p]"

__codesel_msg:
	.string	"syscall_asm_amd64.s:%d rp->r_cs [%ld] != %ld"

__no_rupdate_msg:
	.string	"syscall_asm_amd64.s:%d lwp %p, pcb_rupdate != 0"

#endif	/* !__lint */

#define	ASSERT_LWPTOREGS(lwp, rp)			\
	movq	LWP_REGS(lwp), %r11;			\
	cmpq	rp, %r11;				\
	je	7f;					\
	leaq	__lwptoregs_msg(%rip), %rdi;		\
	movl	$__LINE__, %esi;			\
	movq	lwp, %rdx;				\
	movq	%r11, %rcx;				\
	movq	rp, %r8;				\
	xorl	%eax, %eax;				\
	call	panic;					\
7:

#define	ASSERT_NO_RUPDATE_PENDING(lwp)			\
	testb	$0x1, PCB_RUPDATE(lwp);			\
	je	8f;					\
	movq	lwp, %rdx;				\
	leaq	__no_rupdate_msg(%rip), %rdi;		\
	movl	$__LINE__, %esi;			\
	xorl	%eax, %eax;				\
	call	panic;					\
8:

#else
#define	ASSERT_LWPTOREGS(lwp, rp)
#define	ASSERT_NO_RUPDATE_PENDING(lwp)
#endif

/*
 * Do the traptrace thing and restore any registers we used
 * in situ.  Assumes that %rsp is pointing at the base of
 * the struct regs, obviously ..
 */	
#ifdef TRAPTRACE	
#define	SYSCALL_TRAPTRACE(ttype)				\
	TRACE_PTR(%rdi, %rbx, %ebx, %rcx, ttype);		\
	TRACE_REGS(%rdi, %rsp, %rbx, %rcx);			\
	TRACE_STAMP(%rdi);	/* rdtsc clobbers %eax, %edx */	\
	movq	REGOFF_RAX(%rsp), %rax;				\
	movq	REGOFF_RBX(%rsp), %rbx;				\
	movq	REGOFF_RCX(%rsp), %rcx;				\
	movq	REGOFF_RDX(%rsp), %rdx;				\
	movl	%eax, TTR_SYSNUM(%rdi);				\
	movq	REGOFF_RDI(%rsp), %rdi

#define	SYSCALL_TRAPTRACE32(ttype)				\
	SYSCALL_TRAPTRACE(ttype);				\
	/* paranoia: clean the top 32-bits of the registers */	\
	orl	%eax, %eax;					\
	orl	%ebx, %ebx;					\
	orl	%ecx, %ecx;					\
	orl	%edx, %edx;					\
	orl	%edi, %edi	
#else	/* TRAPTRACE */
#define	SYSCALL_TRAPTRACE(ttype)
#define	SYSCALL_TRAPTRACE32(ttype)	
#endif	/* TRAPTRACE */

/*
 * The 64-bit libc syscall wrapper does this:
 *
 * fn(<args>)
 * {
 *	movq	%rcx, %r10	-- because syscall smashes %rcx
 *	movl	$CODE, %eax
 *	syscall
 *	<error processing>
 * }
 *
 * Thus when we come into the kernel:
 *
 *	%rdi, %rsi, %rdx, %r10, %r8, %r9 contain first six args
 *	%rax is the syscall number
 *	%r12-%r15 contain caller state
 *
 * The syscall instruction arranges that:
 *	
 *	%rcx contains the return %rip
 *	%r11d contains bottom 32-bits of %rflags
 *	%rflags is masked (as determined by the SFMASK msr)
 *	%cs is set to UCS_SEL (as determined by the STAR msr)
 *	%ss is set to UDS_SEL (as determined by the STAR msr)
 *	%rip is set to sys_syscall (as determined by the LSTAR msr)
 *
 * Or in other words, we have no registers available at all.
 * Only swapgs can save us!
 *
 * Under the hypervisor, the swapgs has happened already.  However, the
 * state of the world is very different from that we're familiar with.
 *
 * In particular, we have a stack structure like that for interrupt
 * gates, except that the %cs and %ss registers are modified for reasons
 * that are not entirely clear.  Critically, the %rcx/%r11 values do
 * *not* reflect the usage of those registers under a 'real' syscall[1];
 * the stack, therefore, looks like this:
 *
 *	0x0(rsp)	potentially junk %rcx
 *	0x8(rsp)	potentially junk %r11
 *	0x10(rsp)	user %rip
 *	0x18(rsp)	modified %cs
 *	0x20(rsp)	user %rflags
 *	0x28(rsp)	user %rsp
 *	0x30(rsp)	modified %ss
 *
 *
 * and before continuing on, we must load the %rip into %rcx and the
 * %rflags into %r11.
 *
 * [1] They used to, and we relied on it, but this was broken in 3.1.1.
 * Sigh.
 */
#if defined(__xpv)
#define	XPV_SYSCALL_PROD						\
	movq	0x10(%rsp), %rcx;					\
	movq	0x20(%rsp), %r11;					\
	movq	0x28(%rsp), %rsp
#else
#define	XPV_SYSCALL_PROD /* nothing */
#endif

#if defined(__lint)

/*ARGSUSED*/
void
sys_syscall()
{}

void
_allsyscalls()
{}

size_t _allsyscalls_size;

#else	/* __lint */

	ENTRY_NP2(brand_sys_syscall,_allsyscalls)
	SWAPGS				/* kernel gsbase */
	XPV_SYSCALL_PROD
	BRAND_CALLBACK(BRAND_CB_SYSCALL, BRAND_URET_FROM_REG(%rcx))
	jmp	noprod_sys_syscall

	ALTENTRY(sys_syscall)
	SWAPGS				/* kernel gsbase */
	XPV_SYSCALL_PROD

noprod_sys_syscall:
	movq	%r15, %gs:CPU_RTMP_R15
	movq	%rsp, %gs:CPU_RTMP_RSP

	movq	%gs:CPU_THREAD, %r15
	movq	T_STACK(%r15), %rsp	/* switch from user to kernel stack */

	ASSERT_UPCALL_MASK_IS_SET

	movl	$UCS_SEL, REGOFF_CS(%rsp)
	movq	%rcx, REGOFF_RIP(%rsp)		/* syscall: %rip -> %rcx */
	movq	%r11, REGOFF_RFL(%rsp)		/* syscall: %rfl -> %r11d */
	movl	$UDS_SEL, REGOFF_SS(%rsp)

	movl	%eax, %eax			/* wrapper: sysc# -> %eax */
	movq	%rdi, REGOFF_RDI(%rsp)
	movq	%rsi, REGOFF_RSI(%rsp)
	movq	%rdx, REGOFF_RDX(%rsp)
	movq	%r10, REGOFF_RCX(%rsp)		/* wrapper: %rcx -> %r10 */
	movq	%r10, %rcx			/* arg[3] for direct calls */

	movq	%r8, REGOFF_R8(%rsp)
	movq	%r9, REGOFF_R9(%rsp)
	movq	%rax, REGOFF_RAX(%rsp)
	movq	%rbx, REGOFF_RBX(%rsp)

	movq	%rbp, REGOFF_RBP(%rsp)
	movq	%r10, REGOFF_R10(%rsp)
	movq	%gs:CPU_RTMP_RSP, %r11
	movq	%r11, REGOFF_RSP(%rsp)
	movq	%r12, REGOFF_R12(%rsp)

	movq	%r13, REGOFF_R13(%rsp)
	movq	%r14, REGOFF_R14(%rsp)
	movq	%gs:CPU_RTMP_R15, %r10
	movq	%r10, REGOFF_R15(%rsp)
	movq	$0, REGOFF_SAVFP(%rsp)
	movq	$0, REGOFF_SAVPC(%rsp)

	/*
	 * Copy these registers here in case we end up stopped with
	 * someone (like, say, /proc) messing with our register state.
	 * We don't -restore- them unless we have to in update_sregs.
	 *
	 * Since userland -can't- change fsbase or gsbase directly,
	 * and capturing them involves two serializing instructions,
	 * we don't bother to capture them here.
	 */
	xorl	%ebx, %ebx
	movw	%ds, %bx
	movq	%rbx, REGOFF_DS(%rsp)
	movw	%es, %bx
	movq	%rbx, REGOFF_ES(%rsp)
	movw	%fs, %bx
	movq	%rbx, REGOFF_FS(%rsp)
	movw	%gs, %bx
	movq	%rbx, REGOFF_GS(%rsp)

	/*
	 * Machine state saved in the regs structure on the stack
	 * First six args in %rdi, %rsi, %rdx, %rcx, %r8, %r9
	 * %eax is the syscall number
	 * %rsp is the thread's stack, %r15 is curthread
	 * REG_RSP(%rsp) is the user's stack
	 */

	SYSCALL_TRAPTRACE($TT_SYSC64)

	movq	%rsp, %rbp
	
	movq	T_LWP(%r15), %r14
	ASSERT_NO_RUPDATE_PENDING(%r14)
	ENABLE_INTR_FLAGS

	MSTATE_TRANSITION(LMS_USER, LMS_SYSTEM)
	movl	REGOFF_RAX(%rsp), %eax	/* (%rax damaged by mstate call) */

	ASSERT_LWPTOREGS(%r14, %rsp)

	movb	$LWP_SYS, LWP_STATE(%r14)
	incq	LWP_RU_SYSC(%r14)
	movb	$NORMALRETURN, LWP_EOSYS(%r14)

	incq	%gs:CPU_STATS_SYS_SYSCALL

	movw	%ax, T_SYSNUM(%r15)
	movzbl	T_PRE_SYS(%r15), %ebx
	ORL_SYSCALLTRACE(%ebx)
	testl	%ebx, %ebx
	jne	_syscall_pre

_syscall_invoke:
	movq	REGOFF_RDI(%rbp), %rdi
	movq	REGOFF_RSI(%rbp), %rsi
	movq	REGOFF_RDX(%rbp), %rdx
	movq	REGOFF_RCX(%rbp), %rcx
	movq	REGOFF_R8(%rbp), %r8
	movq	REGOFF_R9(%rbp), %r9

	cmpl	$NSYSCALL, %eax
	jae	_syscall_ill	
	shll	$SYSENT_SIZE_SHIFT, %eax
	leaq	sysent(%rax), %rbx

	call	*SY_CALLC(%rbx)

	movq	%rax, %r12
	movq	%rdx, %r13

	/*
	 * If the handler returns two ints, then we need to split the
	 * 64-bit return value into two 32-bit values.
	 */
	testw	$SE_32RVAL2, SY_FLAGS(%rbx)
	je	5f
	movq	%r12, %r13
	shrq	$32, %r13	/* upper 32-bits into %edx */
	movl	%r12d, %r12d	/* lower 32-bits into %eax */
5:
	/*
	 * Optimistically assume that there's no post-syscall
	 * work to do.  (This is to avoid having to call syscall_mstate()
	 * with interrupts disabled)
	 */
	MSTATE_TRANSITION(LMS_SYSTEM, LMS_USER)

	/*
	 * We must protect ourselves from being descheduled here;
	 * If we were, and we ended up on another cpu, or another
	 * lwp got in ahead of us, it could change the segment
	 * registers without us noticing before we return to userland.
	 */
	CLI(%r14)
	CHECK_POSTSYS_NE(%r15, %r14, %ebx)
	jne	_syscall_post

	/*
	 * We need to protect ourselves against non-canonical return values
	 * because Intel doesn't check for them on sysret (AMD does).  Canonical
	 * addresses on current amd64 processors only use 48-bits for VAs; an
	 * address is canonical if all upper bits (47-63) are identical. If we
	 * find a non-canonical %rip, we opt to go through the full
	 * _syscall_post path which takes us into an iretq which is not
	 * susceptible to the same problems sysret is.
	 * 
	 * We're checking for a canonical address by first doing an arithmetic
	 * shift. This will fill in the remaining bits with the value of bit 63.
	 * If the address were canonical, the register would now have either all
	 * zeroes or all ones in it. Therefore we add one (inducing overflow)
	 * and compare against 1. A canonical address will either be zero or one
	 * at this point, hence the use of ja.
	 *
	 * At this point, r12 and r13 have the return value so we can't use
	 * those registers.
	 */
	movq	REGOFF_RIP(%rsp), %rcx
	sarq	$47, %rcx
	incq	%rcx
	cmpq	$1, %rcx
	ja	_syscall_post


	SIMPLE_SYSCALL_POSTSYS(%r15, %r14, %bx)

	movq	%r12, REGOFF_RAX(%rsp)
	movq	%r13, REGOFF_RDX(%rsp)

	/*
	 * To get back to userland, we need the return %rip in %rcx and
	 * the return %rfl in %r11d.  The sysretq instruction also arranges
	 * to fix up %cs and %ss; everything else is our responsibility.
	 */
	movq	REGOFF_RDI(%rsp), %rdi
	movq	REGOFF_RSI(%rsp), %rsi
	movq	REGOFF_RDX(%rsp), %rdx
	/* %rcx used to restore %rip value */

	movq	REGOFF_R8(%rsp), %r8
	movq	REGOFF_R9(%rsp), %r9
	movq	REGOFF_RAX(%rsp), %rax
	movq	REGOFF_RBX(%rsp), %rbx

	movq	REGOFF_RBP(%rsp), %rbp	
	movq	REGOFF_R10(%rsp), %r10
	/* %r11 used to restore %rfl value */
	movq	REGOFF_R12(%rsp), %r12

	movq	REGOFF_R13(%rsp), %r13
	movq	REGOFF_R14(%rsp), %r14
	movq	REGOFF_R15(%rsp), %r15

	movq	REGOFF_RIP(%rsp), %rcx	
	movl	REGOFF_RFL(%rsp), %r11d

#if defined(__xpv)
	addq	$REGOFF_RIP, %rsp
#else
	movq	REGOFF_RSP(%rsp), %rsp
#endif

        /*
         * There can be no instructions between the ALTENTRY below and
	 * SYSRET or we could end up breaking brand support. See label usage
         * in sn1_brand_syscall_callback for an example.
         */
	ASSERT_UPCALL_MASK_IS_SET
#if defined(__xpv)
	SYSRETQ
        ALTENTRY(nopop_sys_syscall_swapgs_sysretq)

	/*
	 * We can only get here after executing a brand syscall
	 * interposition callback handler and simply need to
	 * "sysretq" back to userland. On the hypervisor this
	 * involves the iret hypercall which requires us to construct
	 * just enough of the stack needed for the hypercall.
	 * (rip, cs, rflags, rsp, ss).
	 */
	movq    %rsp, %gs:CPU_RTMP_RSP		/* save user's rsp */
	movq	%gs:CPU_THREAD, %r11
	movq	T_STACK(%r11), %rsp

	movq	%rcx, REGOFF_RIP(%rsp)
	movl	$UCS_SEL, REGOFF_CS(%rsp)
	movq	%gs:CPU_RTMP_RSP, %r11
	movq	%r11, REGOFF_RSP(%rsp)
	pushfq
	popq	%r11				/* hypercall enables ints */
	movq	%r11, REGOFF_RFL(%rsp)
	movl	$UDS_SEL, REGOFF_SS(%rsp)
	addq	$REGOFF_RIP, %rsp
	/*
	 * XXPV: see comment in SYSRETQ definition for future optimization
	 *       we could take.
	 */
	ASSERT_UPCALL_MASK_IS_SET
	SYSRETQ
#else
        ALTENTRY(nopop_sys_syscall_swapgs_sysretq)
	SWAPGS				/* user gsbase */
	SYSRETQ
#endif
        /*NOTREACHED*/
        SET_SIZE(nopop_sys_syscall_swapgs_sysretq)

_syscall_pre:
	call	pre_syscall
	movl	%eax, %r12d
	testl	%eax, %eax
	jne	_syscall_post_call
	/*
	 * Didn't abort, so reload the syscall args and invoke the handler.
	 */
	movzwl	T_SYSNUM(%r15), %eax	
	jmp	_syscall_invoke

_syscall_ill:
	call	nosys
	movq	%rax, %r12
	movq	%rdx, %r13
	jmp	_syscall_post_call

_syscall_post:
	STI
	/*
	 * Sigh, our optimism wasn't justified, put it back to LMS_SYSTEM
	 * so that we can account for the extra work it takes us to finish.
	 */
	MSTATE_TRANSITION(LMS_USER, LMS_SYSTEM)
_syscall_post_call:
	movq	%r12, %rdi
	movq	%r13, %rsi
	call	post_syscall
	MSTATE_TRANSITION(LMS_SYSTEM, LMS_USER)
	jmp	_sys_rtt
	SET_SIZE(sys_syscall)
	SET_SIZE(brand_sys_syscall)

#endif	/* __lint */

#if defined(__lint)

/*ARGSUSED*/
void
sys_syscall32()
{}

#else	/* __lint */

	ENTRY_NP(brand_sys_syscall32)
	SWAPGS				/* kernel gsbase */
	XPV_TRAP_POP
	BRAND_CALLBACK(BRAND_CB_SYSCALL32, BRAND_URET_FROM_REG(%rcx))
	jmp	nopop_sys_syscall32

	ALTENTRY(sys_syscall32)
	SWAPGS				/* kernel gsbase */
	XPV_TRAP_POP

nopop_sys_syscall32:
	movl	%esp, %r10d
	movq	%gs:CPU_THREAD, %r15
	movq	T_STACK(%r15), %rsp
	movl	%eax, %eax

	movl	$U32CS_SEL, REGOFF_CS(%rsp)
	movl	%ecx, REGOFF_RIP(%rsp)		/* syscall: %rip -> %rcx */
	movq	%r11, REGOFF_RFL(%rsp)		/* syscall: %rfl -> %r11d */
	movq	%r10, REGOFF_RSP(%rsp)
	movl	$UDS_SEL, REGOFF_SS(%rsp)

_syscall32_save:
	movl	%edi, REGOFF_RDI(%rsp)
	movl	%esi, REGOFF_RSI(%rsp)
	movl	%ebp, REGOFF_RBP(%rsp)
	movl	%ebx, REGOFF_RBX(%rsp)
	movl	%edx, REGOFF_RDX(%rsp)
	movl	%ecx, REGOFF_RCX(%rsp)
	movl	%eax, REGOFF_RAX(%rsp)		/* wrapper: sysc# -> %eax */
	movq	$0, REGOFF_SAVFP(%rsp)
	movq	$0, REGOFF_SAVPC(%rsp)

	/*
	 * Copy these registers here in case we end up stopped with
	 * someone (like, say, /proc) messing with our register state.
	 * We don't -restore- them unless we have to in update_sregs.
	 *
	 * Since userland -can't- change fsbase or gsbase directly,
	 * we don't bother to capture them here.
	 */
	xorl	%ebx, %ebx
	movw	%ds, %bx
	movq	%rbx, REGOFF_DS(%rsp)
	movw	%es, %bx
	movq	%rbx, REGOFF_ES(%rsp)
	movw	%fs, %bx
	movq	%rbx, REGOFF_FS(%rsp)
	movw	%gs, %bx
	movq	%rbx, REGOFF_GS(%rsp)

	/*
	 * Application state saved in the regs structure on the stack
	 * %eax is the syscall number
	 * %rsp is the thread's stack, %r15 is curthread
	 * REG_RSP(%rsp) is the user's stack
	 */

	SYSCALL_TRAPTRACE32($TT_SYSC)

	movq	%rsp, %rbp

	movq	T_LWP(%r15), %r14
	ASSERT_NO_RUPDATE_PENDING(%r14)

	ENABLE_INTR_FLAGS

	MSTATE_TRANSITION(LMS_USER, LMS_SYSTEM)
	movl	REGOFF_RAX(%rsp), %eax	/* (%rax damaged by mstate call) */

	ASSERT_LWPTOREGS(%r14, %rsp)

	incq	 %gs:CPU_STATS_SYS_SYSCALL

	/*
	 * Make some space for MAXSYSARGS (currently 8) 32-bit args placed
	 * into 64-bit (long) arg slots, maintaining 16 byte alignment.  Or
	 * more succinctly:
	 *
	 *	SA(MAXSYSARGS * sizeof (long)) == 64
	 */
#define	SYS_DROP	64			/* drop for args */
	subq	$SYS_DROP, %rsp
	movb	$LWP_SYS, LWP_STATE(%r14)
	movq	%r15, %rdi
	movq	%rsp, %rsi
	call	syscall_entry

	/*
	 * Fetch the arguments copied onto the kernel stack and put
	 * them in the right registers to invoke a C-style syscall handler.
	 * %rax contains the handler address.
	 *
	 * Ideas for making all this go faster of course include simply
	 * forcibly fetching 6 arguments from the user stack under lofault
	 * protection, reverting to copyin_args only when watchpoints
	 * are in effect.
	 *
	 * (If we do this, make sure that exec and libthread leave
	 * enough space at the top of the stack to ensure that we'll
	 * never do a fetch from an invalid page.)
	 *
	 * Lots of ideas here, but they won't really help with bringup B-)
	 * Correctness can't wait, performance can wait a little longer ..
	 */

	movq	%rax, %rbx
	movl	0(%rsp), %edi
	movl	8(%rsp), %esi
	movl	0x10(%rsp), %edx
	movl	0x18(%rsp), %ecx
	movl	0x20(%rsp), %r8d
	movl	0x28(%rsp), %r9d

	call	*SY_CALLC(%rbx)

	movq	%rbp, %rsp	/* pop the args */

	/*
	 * amd64 syscall handlers -always- return a 64-bit value in %rax.
	 * On the 32-bit kernel, they always return that value in %eax:%edx
	 * as required by the 32-bit ABI.
	 *
	 * Simulate the same behaviour by unconditionally splitting the
	 * return value in the same way.
	 */
	movq	%rax, %r13
	shrq	$32, %r13	/* upper 32-bits into %edx */
	movl	%eax, %r12d	/* lower 32-bits into %eax */

	/*
	 * Optimistically assume that there's no post-syscall
	 * work to do.  (This is to avoid having to call syscall_mstate()
	 * with interrupts disabled)
	 */
	MSTATE_TRANSITION(LMS_SYSTEM, LMS_USER)

	/*
	 * We must protect ourselves from being descheduled here;
	 * If we were, and we ended up on another cpu, or another
	 * lwp got in ahead of us, it could change the segment
	 * registers without us noticing before we return to userland.
	 */
	CLI(%r14)
	CHECK_POSTSYS_NE(%r15, %r14, %ebx)
	jne	_full_syscall_postsys32
	SIMPLE_SYSCALL_POSTSYS(%r15, %r14, %bx)

	/*
	 * To get back to userland, we need to put the return %rip in %rcx and
	 * the return %rfl in %r11d.  The sysret instruction also arranges
	 * to fix up %cs and %ss; everything else is our responsibility.
	 */

	movl	%r12d, %eax			/* %eax: rval1 */
	movl	REGOFF_RBX(%rsp), %ebx
	/* %ecx used for return pointer */
	movl	%r13d, %edx			/* %edx: rval2 */
	movl	REGOFF_RBP(%rsp), %ebp
	movl	REGOFF_RSI(%rsp), %esi
	movl	REGOFF_RDI(%rsp), %edi

	movl	REGOFF_RFL(%rsp), %r11d		/* %r11 -> eflags */
	movl	REGOFF_RIP(%rsp), %ecx		/* %ecx -> %eip */
	movl	REGOFF_RSP(%rsp), %esp

	ASSERT_UPCALL_MASK_IS_SET
        ALTENTRY(nopop_sys_syscall32_swapgs_sysretl)
	SWAPGS				/* user gsbase */
	SYSRETL
        SET_SIZE(nopop_sys_syscall32_swapgs_sysretl)
	/*NOTREACHED*/

_full_syscall_postsys32:
	STI
	/*
	 * Sigh, our optimism wasn't justified, put it back to LMS_SYSTEM
	 * so that we can account for the extra work it takes us to finish.
	 */
	MSTATE_TRANSITION(LMS_USER, LMS_SYSTEM)
	movq	%r15, %rdi
	movq	%r12, %rsi			/* rval1 - %eax */
	movq	%r13, %rdx			/* rval2 - %edx */
	call	syscall_exit
	MSTATE_TRANSITION(LMS_SYSTEM, LMS_USER)
	jmp	_sys_rtt
	SET_SIZE(sys_syscall32)
	SET_SIZE(brand_sys_syscall32)

#endif	/* __lint */

/*
 * System call handler via the sysenter instruction
 * Used only for 32-bit system calls on the 64-bit kernel.
 *
 * The caller in userland has arranged that:
 *
 * -	%eax contains the syscall number
 * -	%ecx contains the user %esp
 * -	%edx contains the return %eip
 * -	the user stack contains the args to the syscall
 *
 * Hardware and (privileged) initialization code have arranged that by
 * the time the sysenter instructions completes:
 *
 * - %rip is pointing to sys_sysenter (below).
 * - %cs and %ss are set to kernel text and stack (data) selectors.
 * - %rsp is pointing at the lwp's stack
 * - interrupts have been disabled.
 *
 * Note that we are unable to return both "rvals" to userland with
 * this call, as %edx is used by the sysexit instruction.
 *
 * One final complication in this routine is its interaction with
 * single-stepping in a debugger.  For most of the system call mechanisms,
 * the CPU automatically clears the single-step flag before we enter the
 * kernel.  The sysenter mechanism does not clear the flag, so a user
 * single-stepping through a libc routine may suddenly find him/herself
 * single-stepping through the kernel.  To detect this, kmdb compares the
 * trap %pc to the [brand_]sys_enter addresses on each single-step trap.
 * If it finds that we have single-stepped to a sysenter entry point, it
 * explicitly clears the flag and executes the sys_sysenter routine.
 *
 * One final complication in this final complication is the fact that we
 * have two different entry points for sysenter: brand_sys_sysenter and
 * sys_sysenter.  If we enter at brand_sys_sysenter and start single-stepping
 * through the kernel with kmdb, we will eventually hit the instruction at
 * sys_sysenter.  kmdb cannot distinguish between that valid single-step
 * and the undesirable one mentioned above.  To avoid this situation, we
 * simply add a jump over the instruction at sys_sysenter to make it
 * impossible to single-step to it.
 */
#if defined(__lint)

void
sys_sysenter()
{}

#else	/* __lint */

	ENTRY_NP(brand_sys_sysenter)
	SWAPGS				/* kernel gsbase */
	ALTENTRY(_brand_sys_sysenter_post_swapgs)
	BRAND_CALLBACK(BRAND_CB_SYSENTER, BRAND_URET_FROM_REG(%rdx))
	/*
	 * Jump over sys_sysenter to allow single-stepping as described
	 * above.
	 */
	jmp	_sys_sysenter_post_swapgs

	ALTENTRY(sys_sysenter)
	SWAPGS				/* kernel gsbase */

	ALTENTRY(_sys_sysenter_post_swapgs)
	movq	%gs:CPU_THREAD, %r15

	movl	$U32CS_SEL, REGOFF_CS(%rsp)
	movl	%ecx, REGOFF_RSP(%rsp)		/* wrapper: %esp -> %ecx */
	movl	%edx, REGOFF_RIP(%rsp)		/* wrapper: %eip -> %edx */
	pushfq
	popq	%r10
	movl	$UDS_SEL, REGOFF_SS(%rsp)

	/*
	 * Set the interrupt flag before storing the flags to the
	 * flags image on the stack so we can return to user with
	 * interrupts enabled if we return via sys_rtt_syscall32
	 */
	orq	$PS_IE, %r10
	movq	%r10, REGOFF_RFL(%rsp)

	movl	%edi, REGOFF_RDI(%rsp)
	movl	%esi, REGOFF_RSI(%rsp)
	movl	%ebp, REGOFF_RBP(%rsp)
	movl	%ebx, REGOFF_RBX(%rsp)
	movl	%edx, REGOFF_RDX(%rsp)
	movl	%ecx, REGOFF_RCX(%rsp)
	movl	%eax, REGOFF_RAX(%rsp)		/* wrapper: sysc# -> %eax */
	movq	$0, REGOFF_SAVFP(%rsp)
	movq	$0, REGOFF_SAVPC(%rsp)

	/*
	 * Copy these registers here in case we end up stopped with
	 * someone (like, say, /proc) messing with our register state.
	 * We don't -restore- them unless we have to in update_sregs.
	 *
	 * Since userland -can't- change fsbase or gsbase directly,
	 * we don't bother to capture them here.
	 */
	xorl	%ebx, %ebx
	movw	%ds, %bx
	movq	%rbx, REGOFF_DS(%rsp)
	movw	%es, %bx
	movq	%rbx, REGOFF_ES(%rsp)
	movw	%fs, %bx
	movq	%rbx, REGOFF_FS(%rsp)
	movw	%gs, %bx
	movq	%rbx, REGOFF_GS(%rsp)

	/*
	 * Application state saved in the regs structure on the stack
	 * %eax is the syscall number
	 * %rsp is the thread's stack, %r15 is curthread
	 * REG_RSP(%rsp) is the user's stack
	 */

	SYSCALL_TRAPTRACE($TT_SYSENTER)

	movq	%rsp, %rbp

	movq	T_LWP(%r15), %r14
	ASSERT_NO_RUPDATE_PENDING(%r14)

	ENABLE_INTR_FLAGS

	/*
	 * Catch 64-bit process trying to issue sysenter instruction
	 * on Nocona based systems.
	 */
	movq	LWP_PROCP(%r14), %rax
	cmpq	$DATAMODEL_ILP32, P_MODEL(%rax)
	je	7f

	/*
	 * For a non-32-bit process, simulate a #ud, since that's what
	 * native hardware does.  The traptrace entry (above) will
	 * let you know what really happened.
	 */
	movq	$T_ILLINST, REGOFF_TRAPNO(%rsp)
	movq	REGOFF_CS(%rsp), %rdi
	movq	%rdi, REGOFF_ERR(%rsp)
	movq	%rsp, %rdi
	movq	REGOFF_RIP(%rsp), %rsi
	movl	%gs:CPU_ID, %edx
	call	trap
	jmp	_sys_rtt
7:

	MSTATE_TRANSITION(LMS_USER, LMS_SYSTEM)
	movl	REGOFF_RAX(%rsp), %eax	/* (%rax damaged by mstate calls) */

	ASSERT_LWPTOREGS(%r14, %rsp)

	incq	%gs:CPU_STATS_SYS_SYSCALL

	/*
	 * Make some space for MAXSYSARGS (currently 8) 32-bit args
	 * placed into 64-bit (long) arg slots, plus one 64-bit
	 * (long) arg count, maintaining 16 byte alignment.
	 */
	subq	$SYS_DROP, %rsp
	movb	$LWP_SYS, LWP_STATE(%r14)
	movq	%r15, %rdi
	movq	%rsp, %rsi
	call	syscall_entry

	/*
	 * Fetch the arguments copied onto the kernel stack and put
	 * them in the right registers to invoke a C-style syscall handler.
	 * %rax contains the handler address.
	 */
	movq	%rax, %rbx
	movl	0(%rsp), %edi
	movl	8(%rsp), %esi
	movl	0x10(%rsp), %edx
	movl	0x18(%rsp), %ecx
	movl	0x20(%rsp), %r8d
	movl	0x28(%rsp), %r9d

	call	*SY_CALLC(%rbx)

	movq	%rbp, %rsp	/* pop the args */

	/*
	 * amd64 syscall handlers -always- return a 64-bit value in %rax.
	 * On the 32-bit kernel, the always return that value in %eax:%edx
	 * as required by the 32-bit ABI.
	 *
	 * Simulate the same behaviour by unconditionally splitting the
	 * return value in the same way.
	 */
	movq	%rax, %r13
	shrq	$32, %r13	/* upper 32-bits into %edx */
	movl	%eax, %r12d	/* lower 32-bits into %eax */

	/*
	 * Optimistically assume that there's no post-syscall
	 * work to do.  (This is to avoid having to call syscall_mstate()
	 * with interrupts disabled)
	 */
	MSTATE_TRANSITION(LMS_SYSTEM, LMS_USER)

	/*
	 * We must protect ourselves from being descheduled here;
	 * If we were, and we ended up on another cpu, or another
	 * lwp got int ahead of us, it could change the segment
	 * registers without us noticing before we return to userland.
	 */
	cli
	CHECK_POSTSYS_NE(%r15, %r14, %ebx)
	jne	_full_syscall_postsys32
	SIMPLE_SYSCALL_POSTSYS(%r15, %r14, %bx)

	/*
	 * To get back to userland, load up the 32-bit registers and
	 * sysexit back where we came from.
	 */

	/*
	 * Interrupts will be turned on by the 'sti' executed just before
	 * sysexit.  The following ensures that restoring the user's rflags
	 * doesn't enable interrupts too soon.
	 */
	andq	$_BITNOT(PS_IE), REGOFF_RFL(%rsp)

	/*
	 * (There's no point in loading up %edx because the sysexit
	 * mechanism smashes it.)
	 */
	movl	%r12d, %eax
	movl	REGOFF_RBX(%rsp), %ebx
	movl	REGOFF_RBP(%rsp), %ebp
	movl	REGOFF_RSI(%rsp), %esi
	movl	REGOFF_RDI(%rsp), %edi

	movl	REGOFF_RIP(%rsp), %edx	/* sysexit: %edx -> %eip */
	pushq	REGOFF_RFL(%rsp)
	popfq
	movl	REGOFF_RSP(%rsp), %ecx	/* sysexit: %ecx -> %esp */
        ALTENTRY(sys_sysenter_swapgs_sysexit)
	swapgs
	sti
	sysexit
	SET_SIZE(sys_sysenter_swapgs_sysexit)
	SET_SIZE(sys_sysenter)
	SET_SIZE(_sys_sysenter_post_swapgs)
	SET_SIZE(brand_sys_sysenter)

#endif	/* __lint */

/*
 * This is the destination of the "int $T_SYSCALLINT" interrupt gate, used by
 * the generic i386 libc to do system calls. We do a small amount of setup
 * before jumping into the existing sys_syscall32 path.
 */
#if defined(__lint)

/*ARGSUSED*/
void
sys_syscall_int()
{}

#else	/* __lint */

	ENTRY_NP(brand_sys_syscall_int)
	SWAPGS				/* kernel gsbase */
	XPV_TRAP_POP
	call	smap_enable
	BRAND_CALLBACK(BRAND_CB_INT91, BRAND_URET_FROM_INTR_STACK())
	jmp	nopop_syscall_int

	ALTENTRY(sys_syscall_int)
	SWAPGS				/* kernel gsbase */
	XPV_TRAP_POP
	call	smap_enable

nopop_syscall_int:
	movq	%gs:CPU_THREAD, %r15
	movq	T_STACK(%r15), %rsp
	movl	%eax, %eax
	/*
	 * Set t_post_sys on this thread to force ourselves out via the slow
	 * path. It might be possible at some later date to optimize this out
	 * and use a faster return mechanism.
	 */
	movb	$1, T_POST_SYS(%r15)
	CLEAN_CS
	jmp	_syscall32_save
	/*
	 * There should be no instructions between this label and SWAPGS/IRET
	 * or we could end up breaking branded zone support. See the usage of
	 * this label in lx_brand_int80_callback and sn1_brand_int91_callback
	 * for examples.
	 */
        ALTENTRY(sys_sysint_swapgs_iret)
	SWAPGS				/* user gsbase */
	IRET
	/*NOTREACHED*/
	SET_SIZE(sys_sysint_swapgs_iret)
	SET_SIZE(sys_syscall_int)
	SET_SIZE(brand_sys_syscall_int)

#endif	/* __lint */
	
/*
 * Legacy 32-bit applications and old libc implementations do lcalls;
 * we should never get here because the LDT entry containing the syscall
 * segment descriptor has the "segment present" bit cleared, which means
 * we end up processing those system calls in trap() via a not-present trap.
 *
 * We do it this way because a call gate unhelpfully does -nothing- to the
 * interrupt flag bit, so an interrupt can run us just after the lcall
 * completes, but just before the swapgs takes effect.   Thus the INTR_PUSH and
 * INTR_POP paths would have to be slightly more complex to dance around
 * this problem, and end up depending explicitly on the first
 * instruction of this handler being either swapgs or cli.
 */

#if defined(__lint)

/*ARGSUSED*/
void
sys_lcall32()
{}

#else	/* __lint */

	ENTRY_NP(sys_lcall32)
	SWAPGS				/* kernel gsbase */
	pushq	$0
	pushq	%rbp
	movq	%rsp, %rbp
	leaq	__lcall_panic_str(%rip), %rdi
	xorl	%eax, %eax
	call	panic
	SET_SIZE(sys_lcall32)

__lcall_panic_str:	
	.string	"sys_lcall32: shouldn't be here!"

/*
 * Declare a uintptr_t which covers the entire pc range of syscall
 * handlers for the stack walkers that need this.
 */
	.align	CPTRSIZE
	.globl	_allsyscalls_size
	.type	_allsyscalls_size, @object
_allsyscalls_size:
	.NWORD	. - _allsyscalls
	SET_SIZE(_allsyscalls_size)

#endif	/* __lint */

/*
 * These are the thread context handlers for lwps using sysenter/sysexit.
 */

#if defined(__lint)

/*ARGSUSED*/
void
sep_save(void *ksp)
{}

/*ARGSUSED*/
void
sep_restore(void *ksp)
{}

#else	/* __lint */

	/*
	 * setting this value to zero as we switch away causes the
	 * stack-pointer-on-sysenter to be NULL, ensuring that we
	 * don't silently corrupt another (preempted) thread stack
	 * when running an lwp that (somehow) didn't get sep_restore'd
	 */
	ENTRY_NP(sep_save)
	xorl	%edx, %edx
	xorl	%eax, %eax
	movl	$MSR_INTC_SEP_ESP, %ecx
	wrmsr
	ret
	SET_SIZE(sep_save)

	/*
	 * Update the kernel stack pointer as we resume onto this cpu.
	 */
	ENTRY_NP(sep_restore)
	movq	%rdi, %rdx
	shrq	$32, %rdx
	movl	%edi, %eax
	movl	$MSR_INTC_SEP_ESP, %ecx
	wrmsr
	ret
	SET_SIZE(sep_restore)

#endif	/* __lint */
