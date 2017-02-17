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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved					*/

/*	Copyright (c) 1987, 1988 Microsoft Corporation		*/
/*	  All Rights Reserved					*/

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/psw.h>
#include <sys/x86_archext.h>
#include <sys/machbrand.h>
#include <sys/privregs.h>

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
#include <sys/panic.h>
#include "assym.h"

#endif	/* __lint */

/*
 * We implement two flavours of system call entry points
 *
 * -	{int,lcall}/iret	(i386)
 * -	sysenter/sysexit	(Pentium II and beyond)
 *
 * The basic pattern used in the handlers is to check to see if we can
 * do fast (simple) version of the system call; if we can't we use various
 * C routines that handle corner cases and debugging.
 *
 * To reduce the amount of assembler replication, yet keep the system call
 * implementations vaguely comprehensible, the common code in the body
 * of the handlers is broken up into a set of preprocessor definitions
 * below.
 */

/*
 * When we have SYSCALLTRACE defined, we sneak an extra
 * predicate into a couple of tests.
 */
#if defined(SYSCALLTRACE)
#define	ORL_SYSCALLTRACE(r32)	\
	orl	syscalltrace, r32
#else
#define	ORL_SYSCALLTRACE(r32)
#endif

/*
 * This check is false whenever we want to go fast i.e.
 *
 *	if (code >= NSYSCALL ||
 *	    t->t_pre_sys || (t->t_proc_flag & TP_WATCHPT) != 0)
 *		do full version
 * #ifdef SYSCALLTRACE
 *	if (syscalltrace)
 *		do full version
 * #endif
 *
 * Preconditions:
 * -	t	curthread
 * -	code	contains the syscall number
 * Postconditions:
 * -	%ecx and %edi are smashed
 * -	condition code flag ZF is cleared if pre-sys is too complex
 */
#define	CHECK_PRESYS_NE(t, code)		\
	movzbl	T_PRE_SYS(t), %edi;		\
	movzwl	T_PROC_FLAG(t), %ecx;		\
	andl	$TP_WATCHPT, %ecx;		\
	orl	%ecx, %edi;			\
	cmpl	$NSYSCALL, code;		\
	setae	%cl;				\
	movzbl	%cl, %ecx;			\
	orl	%ecx, %edi;			\
	ORL_SYSCALLTRACE(%edi)

/*
 * Check if a brand_mach_ops callback is defined for the specified callback_id
 * type.  If so invoke it with the user's %gs value loaded and the following
 * data on the stack:
 *	   --------------------------------------
 *         | user's %ss                         |
 *    |    | user's %esp                        |
 *    |    | EFLAGS register                    |
 *    |    | user's %cs                         |
 *    |    | user's %eip (user return address)  |
 *    |    | 'scratch space'			|
 *    |    | user's %ebx			|
 *    |    | user's %gs selector		|
 *    v    | lwp pointer			|
 *         | callback wrapper return addr 	|
 *         --------------------------------------
 *
 * If the brand code returns, we assume that we are meant to execute the
 * normal system call path.
 *
 * The interface to the brand callbacks on the 32-bit kernel assumes %ebx
 * is available as a scratch register within the callback.  If the callback
 * returns within the kernel then this macro will restore %ebx.  If the
 * callback is going to return directly to userland then it should restore
 * %ebx before returning to userland.
 */
#define	BRAND_CALLBACK(callback_id)					    \
	subl	$4, %esp		/* save some scratch space	*/ ;\
	pushl	%ebx			/* save %ebx to use for scratch	*/ ;\
	pushl	%gs			/* save the user %gs		*/ ;\
	movl	$KGS_SEL, %ebx						   ;\
	movw	%bx, %gs		/* switch to the kernel's %gs	*/ ;\
	movl	%gs:CPU_THREAD, %ebx	/* load the thread pointer	*/ ;\
	movl	T_LWP(%ebx), %ebx	/* load the lwp pointer		*/ ;\
	pushl	%ebx			/* push the lwp pointer		*/ ;\
	movl	LWP_PROCP(%ebx), %ebx	/* load the proc pointer	*/ ;\
	movl	P_BRAND(%ebx), %ebx	/* load the brand pointer	*/ ;\
	movl	B_MACHOPS(%ebx), %ebx	/* load the machops pointer	*/ ;\
	movl	_CONST(_MUL(callback_id, CPTRSIZE))(%ebx), %ebx		   ;\
	cmpl	$0, %ebx						   ;\
	je	1f							   ;\
	movl	%ebx, 12(%esp)		/* save callback to scratch	*/ ;\
	movl	4(%esp), %ebx		/* grab the user %gs		*/ ;\
	movw	%bx, %gs		/* restore the user %gs		*/ ;\
	call	*12(%esp)		/* call callback in scratch	*/ ;\
1:	movl	4(%esp), %ebx		/* restore user %gs (re-do if	*/ ;\
	movw	%bx, %gs		/* branch due to no callback)	*/ ;\
	movl	8(%esp), %ebx		/* restore user's %ebx		*/ ;\
	addl	$16, %esp		/* restore stack ptr		*/

#define	MSTATE_TRANSITION(from, to)		\
	pushl	$to;				\
	pushl	$from;				\
	call	syscall_mstate;			\
	addl	$0x8, %esp

/*
 * aka CPU_STATS_ADDQ(CPU, sys.syscall, 1)
 * This must be called with interrupts or preemption disabled.
 */
#define	CPU_STATS_SYS_SYSCALL_INC			\
	addl	$1, %gs:CPU_STATS_SYS_SYSCALL;		\
	adcl	$0, %gs:CPU_STATS_SYS_SYSCALL+4;

#if !defined(__lint)

/*
 * ASSERT(lwptoregs(lwp) == rp);
 *
 * this may seem obvious, but very odd things happen if this
 * assertion is false
 *
 * Preconditions:
 *	-none-
 * Postconditions (if assertion is true):
 *	%esi and %edi are smashed
 */
#if defined(DEBUG)

__lwptoregs_msg:
	.string	"syscall_asm.s:%d lwptoregs(%p) [%p] != rp [%p]"

#define	ASSERT_LWPTOREGS(t, rp)				\
	movl	T_LWP(t), %esi;				\
	movl	LWP_REGS(%esi), %edi;			\
	cmpl	rp, %edi;				\
	je	7f;					\
	pushl	rp;					\
	pushl	%edi;					\
	pushl	%esi;					\
	pushl	$__LINE__;				\
	pushl	$__lwptoregs_msg;			\
	call	panic;					\
7:
#else
#define	ASSERT_LWPTOREGS(t, rp)
#endif

#endif	/* __lint */

/*
 * This is an assembler version of this fragment:
 *
 * lwp->lwp_state = LWP_SYS;
 * lwp->lwp_ru.sysc++;
 * lwp->lwp_eosys = NORMALRETURN;
 * lwp->lwp_ap = argp;
 *
 * Preconditions:
 *	-none-
 * Postconditions:
 *	-none-
 */
#define	SET_LWP(lwp, argp)				\
	movb	$LWP_SYS, LWP_STATE(lwp);		\
	addl	$1, LWP_RU_SYSC(lwp);			\
	adcl	$0, LWP_RU_SYSC+4(lwp);			\
	movb	$NORMALRETURN, LWP_EOSYS(lwp);		\
	movl	argp, LWP_AP(lwp)

/*
 * Set up the thread, lwp, find the handler, and copy
 * in the arguments from userland to the kernel stack.
 *
 * Preconditions:
 * -	%eax contains the syscall number
 * Postconditions:
 * -	%eax contains a pointer to the sysent structure
 * -	%ecx is zeroed
 * -	%esi, %edi are smashed
 * -	%esp is SYS_DROPped ready for the syscall
 */
#define	SIMPLE_SYSCALL_PRESYS(t, faultlabel)		\
	movl	T_LWP(t), %esi;				\
	movw	%ax, T_SYSNUM(t);			\
	subl	$SYS_DROP, %esp;			\
	shll	$SYSENT_SIZE_SHIFT, %eax;			\
	SET_LWP(%esi, %esp);				\
	leal	sysent(%eax), %eax;			\
	movzbl	SY_NARG(%eax), %ecx;			\
	testl	%ecx, %ecx;				\
	jz	4f;					\
	movl	%esp, %edi;				\
	movl	SYS_DROP + REGOFF_UESP(%esp), %esi;	\
	movl	$faultlabel, T_LOFAULT(t);		\
	addl	$4, %esi;				\
	rep;						\
	  smovl;					\
	movl	%ecx, T_LOFAULT(t);			\
4:

/*
 * Check to see if a simple return is possible i.e.
 *
 *	if ((t->t_post_sys_ast | syscalltrace) != 0)
 *		do full version;
 *
 * Preconditions:
 * -	t is curthread
 * Postconditions:
 * -	condition code NE is set if post-sys is too complex
 * -	rtmp is zeroed if it isn't (we rely on this!)
 */
#define	CHECK_POSTSYS_NE(t, rtmp)			\
	xorl	rtmp, rtmp;				\
	ORL_SYSCALLTRACE(rtmp);				\
	orl	T_POST_SYS_AST(t), rtmp;		\
	cmpl	$0, rtmp

/*
 * Fix up the lwp, thread, and eflags for a successful return
 *
 * Preconditions:
 * -	zwreg contains zero
 * Postconditions:
 * -	%esp has been unSYS_DROPped
 * -	%esi is smashed (points to lwp)
 */
#define	SIMPLE_SYSCALL_POSTSYS(t, zwreg)		\
	movl	T_LWP(t), %esi;				\
	addl	$SYS_DROP, %esp;			\
	movw	zwreg, T_SYSNUM(t);			\
	movb	$LWP_USER, LWP_STATE(%esi);		\
	andb	$_CONST(0xffff - PS_C), REGOFF_EFL(%esp)

/*
 * System call handler.  This is the destination of both the call
 * gate (lcall 0x27) _and_ the interrupt gate (int 0x91). For our purposes,
 * there are two significant differences between an interrupt gate and a call
 * gate:
 *
 * 1) An interrupt gate runs the handler with interrupts disabled, whereas a
 * call gate runs the handler with whatever EFLAGS settings were in effect at
 * the time of the call.
 *
 * 2) An interrupt gate pushes the contents of the EFLAGS register at the time
 * of the interrupt onto the stack, whereas a call gate does not.
 *
 * Because we use the following code sequence to handle system calls made from
 * _both_ a call gate _and_ an interrupt gate, these two differences must be
 * respected. In regards to number 1) above, the handler must ensure that a sane
 * EFLAGS snapshot is stored on the stack so that when the kernel returns back
 * to the user via iret (which returns to user with the EFLAGS value saved on
 * the stack), interrupts are re-enabled.
 *
 * In regards to number 2) above, the handler must always put a current snapshot
 * of EFLAGS onto the stack in the appropriate place. If we came in via an
 * interrupt gate, we will be clobbering the EFLAGS value that was pushed by
 * the interrupt gate. This is OK, as the only bit that was changed by the
 * hardware was the IE (interrupt enable) bit, which for an interrupt gate is
 * now off. If we were to do nothing, the stack would contain an EFLAGS with
 * IE off, resulting in us eventually returning back to the user with interrupts
 * disabled. The solution is to turn on the IE bit in the EFLAGS value saved on
 * the stack.
 *
 * Another subtlety which deserves mention is the difference between the two
 * descriptors. The call gate descriptor is set to instruct the hardware to copy
 * one parameter from the user stack to the kernel stack, whereas the interrupt
 * gate descriptor doesn't use the parameter passing mechanism at all. The
 * kernel doesn't actually use the parameter that is copied by the hardware; the
 * only reason it does this is so that there is a space on the stack large
 * enough to hold an EFLAGS register value, which happens to be in the correct
 * place for use by iret when we go back to userland. How convenient.
 *
 * Stack frame description in syscall() and callees.
 *
 * |------------|
 * | regs	| +(8*4)+4	registers
 * |------------|
 * | 8 args	| <- %esp	MAXSYSARGS (currently 8) arguments
 * |------------|
 *
 */
#define	SYS_DROP	_CONST(_MUL(MAXSYSARGS, 4))

#if defined(__lint)

/*ARGSUSED*/
void
sys_call()
{}

void
_allsyscalls()
{}

size_t _allsyscalls_size;

#else	/* __lint */

	ENTRY_NP2(brand_sys_call, _allsyscalls)
	BRAND_CALLBACK(BRAND_CB_SYSCALL)

	ALTENTRY(sys_call)
	/ on entry	eax = system call number

	/ set up the stack to look as in reg.h
	subl    $8, %esp        / pad the stack with ERRCODE and TRAPNO

	SYSCALL_PUSH

#ifdef TRAPTRACE
	TRACE_PTR(%edi, %ebx, %ebx, %ecx, $TT_SYSCALL) / Uses labels "8" and "9"
	TRACE_REGS(%edi, %esp, %ebx, %ecx)	/ Uses label "9"
	pushl	%eax
	TRACE_STAMP(%edi)		/ Clobbers %eax, %edx, uses "9"
	popl	%eax
	movl	%eax, TTR_SYSNUM(%edi)
#endif

_watch_do_syscall:
	movl	%esp, %ebp

	/ Interrupts may be enabled here, so we must make sure this thread
	/ doesn't migrate off the CPU while it updates the CPU stats.
	/
	/ XXX This is only true if we got here via call gate thru the LDT for
	/ old style syscalls. Perhaps this preempt++-- will go away soon?
	movl	%gs:CPU_THREAD, %ebx
	addb	$1, T_PREEMPT(%ebx)
	CPU_STATS_SYS_SYSCALL_INC
	subb	$1, T_PREEMPT(%ebx)

	ENABLE_INTR_FLAGS

	pushl	%eax				/ preserve across mstate call
	MSTATE_TRANSITION(LMS_USER, LMS_SYSTEM)
	popl	%eax

	movl	%gs:CPU_THREAD, %ebx

	ASSERT_LWPTOREGS(%ebx, %esp)

	CHECK_PRESYS_NE(%ebx, %eax)
	jne	_full_syscall_presys
	SIMPLE_SYSCALL_PRESYS(%ebx, _syscall_fault)

_syslcall_call:
	call	*SY_CALLC(%eax)

_syslcall_done:
	CHECK_POSTSYS_NE(%ebx, %ecx)
	jne	_full_syscall_postsys
	SIMPLE_SYSCALL_POSTSYS(%ebx, %cx)
	movl	%eax, REGOFF_EAX(%esp)
	movl	%edx, REGOFF_EDX(%esp)

	MSTATE_TRANSITION(LMS_SYSTEM, LMS_USER)

	/
	/ get back via iret
	/
	CLI(%edx)
	jmp	sys_rtt_syscall

_full_syscall_presys:
	movl	T_LWP(%ebx), %esi
	subl	$SYS_DROP, %esp
	movb	$LWP_SYS, LWP_STATE(%esi)
	pushl	%esp
	pushl	%ebx
	call	syscall_entry
	addl	$8, %esp
	jmp	_syslcall_call

_full_syscall_postsys:
	addl	$SYS_DROP, %esp
	pushl	%edx
	pushl	%eax
	pushl	%ebx
	call	syscall_exit
	addl	$12, %esp
	MSTATE_TRANSITION(LMS_SYSTEM, LMS_USER)
	jmp	_sys_rtt

_syscall_fault:
	push	$0xe			/ EFAULT
	call	set_errno
	addl	$4, %esp
	xorl	%eax, %eax		/ fake syscall_err()
	xorl	%edx, %edx
	jmp	_syslcall_done
	SET_SIZE(sys_call)
	SET_SIZE(brand_sys_call)

#endif	/* __lint */

/*
 * System call handler via the sysenter instruction
 *
 * Here's how syscall entry usually works (see sys_call for details).
 *
 * There, the caller (lcall or int) in userland has arranged that:
 *
 * -	%eax contains the syscall number
 * -	the user stack contains the args to the syscall
 *
 * Normally the lcall instruction into the call gate causes the processor
 * to push %ss, %esp, <top-of-stack>, %cs, %eip onto the kernel stack.
 * The sys_call handler then leaves space for r_trapno and r_err, and
 * pusha's {%eax, %ecx, %edx, %ebx, %esp, %ebp, %esi, %edi}, followed
 * by %ds, %es, %fs and %gs to capture a 'struct regs' on the stack.
 * Then the kernel sets %ds, %es and %gs to kernel selectors, and finally
 * extracts %efl and puts it into r_efl (which happens to live at the offset
 * that <top-of-stack> was copied into). Note that the value in r_efl has
 * the IF (interrupt enable) flag turned on. (The int instruction into the
 * interrupt gate does essentially the same thing, only instead of
 * <top-of-stack> we get eflags - see comment above.)
 *
 * In the sysenter case, things are a lot more primitive.
 *
 * The caller in userland has arranged that:
 *
 * -	%eax contains the syscall number
 * -	%ecx contains the user %esp
 * -	%edx contains the return %eip
 * -	the user stack contains the args to the syscall
 *
 * e.g.
 *	<args on the stack>
 *	mov	$SYS_callnum, %eax
 *	mov	$1f, %edx	/ return %eip
 *	mov	%esp, %ecx	/ return %esp
 *	sysenter
 * 1:
 *
 * Hardware and (privileged) initialization code have arranged that by
 * the time the sysenter instructions completes:
 *
 * - %eip is pointing to sys_sysenter (below).
 * - %cs and %ss are set to kernel text and stack (data) selectors.
 * - %esp is pointing at the lwp's stack
 * - Interrupts have been disabled.
 *
 * The task for the sysenter handler is:
 *
 * -	recreate the same regs structure on the stack and the same
 *	kernel state as if we'd come in on an lcall
 * -	do the normal work of a syscall
 * -	execute the system call epilogue, use sysexit to return to userland.
 *
 * Note that we are unable to return both "rvals" to userland with this
 * call, as %edx is used by the sysexit instruction.
 *
 * One final complication in this routine is its interaction with
 * single-stepping in a debugger.  For most of the system call mechanisms,
 * the CPU automatically clears the single-step flag before we enter the
 * kernel.  The sysenter mechanism does not clear the flag, so a user
 * single-stepping through a libc routine may suddenly find themself
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
	pushl	%edx
	BRAND_CALLBACK(BRAND_CB_SYSENTER)
	popl	%edx
	/*
	 * Jump over sys_sysenter to allow single-stepping as described
	 * above.
	 */
	ja	1f

	ALTENTRY(sys_sysenter)
	nop
1:
	/
	/ do what the call gate would've done to the stack ..
	/
	pushl	$UDS_SEL	/ (really %ss, but it's the same ..)
	pushl	%ecx		/ userland makes this a copy of %esp
	pushfl
	orl	$PS_IE, (%esp)	/ turn interrupts on when we return to user
	pushl	$UCS_SEL
	pushl	%edx		/ userland makes this a copy of %eip
	/
	/ done.  finish building the stack frame
	/
	subl	$8, %esp	/ leave space for ERR and TRAPNO

	SYSENTER_PUSH

#ifdef TRAPTRACE
	TRACE_PTR(%edi, %ebx, %ebx, %ecx, $TT_SYSENTER)	/ uses labels 8 and 9
	TRACE_REGS(%edi, %esp, %ebx, %ecx)		/ uses label 9
	pushl	%eax
	TRACE_STAMP(%edi)		/ clobbers %eax, %edx, uses label 9
	popl	%eax
	movl	%eax, TTR_SYSNUM(%edi)
#endif
	movl	%esp, %ebp

	CPU_STATS_SYS_SYSCALL_INC

	ENABLE_INTR_FLAGS

	pushl	%eax				/ preserve across mstate call
	MSTATE_TRANSITION(LMS_USER, LMS_SYSTEM)
	popl	%eax

	movl	%gs:CPU_THREAD, %ebx

	ASSERT_LWPTOREGS(%ebx, %esp)

	CHECK_PRESYS_NE(%ebx, %eax)
	jne	_full_syscall_presys
	SIMPLE_SYSCALL_PRESYS(%ebx, _syscall_fault)

_sysenter_call:
	call	*SY_CALLC(%eax)

_sysenter_done:
	CHECK_POSTSYS_NE(%ebx, %ecx)
	jne	_full_syscall_postsys
	SIMPLE_SYSCALL_POSTSYS(%ebx, %cx)
	/
	/ sysexit uses %edx to restore %eip, so we can't use it
	/ to return a value, sigh.
	/
	movl	%eax, REGOFF_EAX(%esp)
	/ movl	%edx, REGOFF_EDX(%esp)

	/ Interrupts will be turned on by the 'sti' executed just before
	/ sysexit. The following ensures that restoring the user's EFLAGS
	/ doesn't enable interrupts too soon.
	andl	$_BITNOT(PS_IE), REGOFF_EFL(%esp)

	MSTATE_TRANSITION(LMS_SYSTEM, LMS_USER)

	cli

	SYSCALL_POP

	popl	%edx			/ sysexit: %edx -> %eip
	addl	$4, %esp		/ get CS off the stack
	popfl				/ EFL
	popl	%ecx			/ sysexit: %ecx -> %esp
	sti
	sysexit
	SET_SIZE(sys_sysenter)
	SET_SIZE(brand_sys_sysenter)

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
	movl	4(%esp), %eax			/* per-lwp kernel sp */
	xorl	%edx, %edx
	movl	$MSR_INTC_SEP_ESP, %ecx
	wrmsr
	ret
	SET_SIZE(sep_restore)

#endif	/* __lint */

/*
 * Call syscall().  Called from trap() on watchpoint at lcall 0,7
 */

#if defined(__lint)

void
watch_syscall(void)
{}

#else	/* __lint */

	ENTRY_NP(watch_syscall)
	CLI(%eax)
	movl	%gs:CPU_THREAD, %ebx
	movl	T_STACK(%ebx), %esp		/ switch to the thread stack
	movl	REGOFF_EAX(%esp), %eax		/ recover original syscall#
	jmp	_watch_do_syscall
	SET_SIZE(watch_syscall)

#endif	/* __lint */
