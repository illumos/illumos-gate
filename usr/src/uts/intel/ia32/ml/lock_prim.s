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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(lint) || defined(__lint)
#include <sys/types.h>
#include <sys/thread.h>
#include <sys/cpuvar.h>
#include <vm/page.h>
#include <sys/mutex_impl.h>
#else	/* __lint */
#include "assym.h"
#endif	/* __lint */

#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/rwlock_impl.h>
#include <sys/lockstat.h>

/*
 * lock_try(lp), ulock_try(lp)
 *	- returns non-zero on success.
 *	- doesn't block interrupts so don't use this to spin on a lock.
 *
 * ulock_try() is for a lock in the user address space.
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
int
lock_try(lock_t *lp)
{ return (0); }

/* ARGSUSED */
int
lock_spin_try(lock_t *lp)
{ return (0); }

/* ARGSUSED */
int
ulock_try(lock_t *lp)
{ return (0); }

#else	/* __lint */
	.globl	kernelbase

#if defined(__amd64)

	ENTRY(lock_try)
	movb	$-1, %dl
	movzbq	%dl, %rax
	xchgb	%dl, (%rdi)
	xorb	%dl, %al
.lock_try_lockstat_patch_point:
	ret
	testb	%al, %al
	jnz	0f
	ret
0:
	movq	%gs:CPU_THREAD, %rdx	/* rdx = thread addr */
	movq	%rdi, %rsi		/* rsi = lock addr */
	movl	$LS_LOCK_TRY_ACQUIRE, %edi /* edi = event */
	jmp	lockstat_wrapper
	SET_SIZE(lock_try)

	ENTRY(lock_spin_try)
	movb	$-1, %dl
	movzbq	%dl, %rax
	xchgb	%dl, (%rdi)
	xorb	%dl, %al
	ret
	SET_SIZE(lock_spin_try)

	ENTRY(ulock_try)
#ifdef DEBUG
	movq	kernelbase(%rip), %rax
	cmpq	%rax, %rdi		/* test uaddr < kernelbase */
	jb	ulock_pass		/*	uaddr < kernelbase, proceed */

	movq	%rdi, %r12		/* preserve lock ptr for debugging */
	leaq	.ulock_panic_msg(%rip), %rdi
	pushq	%rbp			/* align stack properly */
	movq	%rsp, %rbp
	xorl	%eax, %eax		/* clear for varargs */
	call	panic

#endif /* DEBUG */

ulock_pass:
	movl	$1, %eax
	xchgb	%al, (%rdi)
	xorb	$1, %al
	ret
	SET_SIZE(ulock_try)

#else

	ENTRY(lock_try)
	movl	$1,%edx
	movl	4(%esp),%ecx		/* ecx = lock addr */
	xorl	%eax,%eax
	xchgb	%dl, (%ecx)		/* using dl will avoid partial */
	testb	%dl,%dl			/* stalls on P6 ? */
	setz	%al
.lock_try_lockstat_patch_point:
	ret
	movl	%gs:CPU_THREAD, %edx	/* edx = thread addr */
	testl	%eax, %eax
	jz	0f
	movl	$LS_LOCK_TRY_ACQUIRE, %eax
	jmp	lockstat_wrapper
0:
	ret
	SET_SIZE(lock_try)

	ENTRY(lock_spin_try)
	movl	$-1,%edx
	movl	4(%esp),%ecx		/* ecx = lock addr */
	xorl	%eax,%eax
	xchgb	%dl, (%ecx)		/* using dl will avoid partial */
	testb	%dl,%dl			/* stalls on P6 ? */
	setz	%al
	ret
	SET_SIZE(lock_spin_try)

	ENTRY(ulock_try)
#ifdef DEBUG
	movl	kernelbase, %eax
	cmpl	%eax, 4(%esp)		/* test uaddr < kernelbase */
	jb	ulock_pass		/* uaddr < kernelbase, proceed */

	pushl	$.ulock_panic_msg
	call	panic

#endif /* DEBUG */

ulock_pass:
	movl	$1,%eax
	movl	4(%esp),%ecx
	xchgb	%al, (%ecx)
	xorb	$1, %al
	ret
	SET_SIZE(ulock_try)

#endif	/* !__amd64 */

#ifdef DEBUG
	.data
.ulock_panic_msg:
	.string "ulock_try: Argument is above kernelbase"
	.text
#endif	/* DEBUG */

#endif	/* __lint */

/*
 * lock_clear(lp)
 *	- unlock lock without changing interrupt priority level.
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
lock_clear(lock_t *lp)
{}

/* ARGSUSED */
void
ulock_clear(lock_t *lp)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(lock_clear)
	movb	$0, (%rdi)
.lock_clear_lockstat_patch_point:
	ret
	movq	%rdi, %rsi			/* rsi = lock addr */
	movq	%gs:CPU_THREAD, %rdx		/* rdx = thread addr */
	movl	$LS_LOCK_CLEAR_RELEASE, %edi	/* edi = event */
	jmp	lockstat_wrapper
	SET_SIZE(lock_clear)

	ENTRY(ulock_clear)
#ifdef DEBUG
	movq	kernelbase(%rip), %rcx
	cmpq	%rcx, %rdi		/* test uaddr < kernelbase */
	jb	ulock_clr		/*	 uaddr < kernelbase, proceed */

	leaq	.ulock_clear_msg(%rip), %rdi
	pushq	%rbp			/* align stack properly */
	movq	%rsp, %rbp
	xorl	%eax, %eax		/* clear for varargs */
	call	panic
#endif

ulock_clr:
	movb	$0, (%rdi)
	ret
	SET_SIZE(ulock_clear)

#else

	ENTRY(lock_clear)
	movl	4(%esp), %eax
	movb	$0, (%eax)
.lock_clear_lockstat_patch_point:
	ret
	movl	%gs:CPU_THREAD, %edx		/* edx = thread addr */
	movl	%eax, %ecx			/* ecx = lock pointer */
	movl	$LS_LOCK_CLEAR_RELEASE, %eax
	jmp	lockstat_wrapper
	SET_SIZE(lock_clear)

	ENTRY(ulock_clear)
#ifdef DEBUG
	movl	kernelbase, %ecx
	cmpl	%ecx, 4(%esp)		/* test uaddr < kernelbase */
	jb	ulock_clr		/* uaddr < kernelbase, proceed */

	pushl	$.ulock_clear_msg
	call	panic
#endif

ulock_clr:
	movl	4(%esp),%eax
	xorl	%ecx,%ecx
	movb	%cl, (%eax)
	ret
	SET_SIZE(ulock_clear)

#endif	/* !__amd64 */

#ifdef DEBUG
	.data
.ulock_clear_msg:
	.string "ulock_clear: Argument is above kernelbase"
	.text
#endif	/* DEBUG */


#endif	/* __lint */

/*
 * lock_set_spl(lock_t *lp, int new_pil, u_short *old_pil)
 * Drops lp, sets pil to new_pil, stores old pil in *old_pil.
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
lock_set_spl(lock_t *lp, int new_pil, u_short *old_pil)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(lock_set_spl)
	pushq	%rbp
	movq	%rsp, %rbp
	subq	$32, %rsp
	movl	%esi, 8(%rsp)		/* save priority level */
	movq	%rdx, 16(%rsp)		/* save old pil ptr */
	movq	%rdi, 24(%rsp)		/* save lock pointer */
	movl	%esi, %edi		/* pass priority level */
	call	splr			/* raise priority level */
	movq	24(%rsp), %rdi		/* rdi = lock addr */
	movb	$-1, %dl
	xchgb	%dl, (%rdi)		/* try to set lock */
	testb	%dl, %dl		/* did we get the lock? ... */
	jnz	.lss_miss		/* ... no, go to C for the hard case */
	movq	16(%rsp), %rdx		/* rdx = old pil addr */
	movw	%ax, (%rdx)		/* store old pil */
	leave
.lock_set_spl_lockstat_patch_point:
	ret
	movq	%rdi, %rsi		/* rsi = lock addr */
	movq	%gs:CPU_THREAD, %rdx	/* rdx = thread addr */
	movl	$LS_LOCK_SET_SPL_ACQUIRE, %edi
	jmp	lockstat_wrapper
.lss_miss:
	movl	8(%rsp), %esi		/* new_pil */
	movq	16(%rsp), %rdx		/* old_pil_addr */
	movl	%eax, %ecx		/* original pil */
	leave				/* unwind stack */
	jmp	lock_set_spl_spin
	SET_SIZE(lock_set_spl)

#else

	ENTRY(lock_set_spl)
	movl	8(%esp), %eax		/* get priority level */
	pushl	%eax
	call	splr			/* raise priority level */
	movl 	8(%esp), %ecx		/* ecx = lock addr */
	movl	$-1, %edx
	addl	$4, %esp
	xchgb	%dl, (%ecx)		/* try to set lock */
	testb	%dl, %dl		/* did we get the lock? ... */
	movl	12(%esp), %edx		/* edx = olp pil addr (ZF unaffected) */
	jnz	.lss_miss		/* ... no, go to C for the hard case */
	movw	%ax, (%edx)		/* store old pil */
.lock_set_spl_lockstat_patch_point:
	ret
	movl	%gs:CPU_THREAD, %edx	/* edx = thread addr*/
	movl	$LS_LOCK_SET_SPL_ACQUIRE, %eax
	jmp	lockstat_wrapper
.lss_miss:
	pushl	%eax			/* original pil */
	pushl	%edx			/* old_pil addr */
	pushl	16(%esp)		/* new_pil */
	pushl	%ecx			/* lock addr */
	call	lock_set_spl_spin
	addl	$16, %esp
	ret
	SET_SIZE(lock_set_spl)

#endif	/* !__amd64 */

#endif	/* __lint */

/*
 * void
 * lock_init(lp)
 */

#if defined(__lint)

/* ARGSUSED */
void
lock_init(lock_t *lp)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(lock_init)
	movb	$0, (%rdi)
	ret
	SET_SIZE(lock_init)

#else

	ENTRY(lock_init)
	movl	4(%esp), %eax
	movb	$0, (%eax)
	ret
	SET_SIZE(lock_init)

#endif	/* !__amd64 */

#endif	/* __lint */

/*
 * void
 * lock_set(lp)
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
lock_set(lock_t *lp)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(lock_set)
	movb	$-1, %dl
	xchgb	%dl, (%rdi)		/* try to set lock */
	testb	%dl, %dl		/* did we get it? */
	jnz	lock_set_spin		/* no, go to C for the hard case */
.lock_set_lockstat_patch_point:
	ret
	movq	%rdi, %rsi		/* rsi = lock addr */
	movq	%gs:CPU_THREAD, %rdx	/* rdx = thread addr */
	movl	$LS_LOCK_SET_ACQUIRE, %edi
	jmp	lockstat_wrapper
	SET_SIZE(lock_set)

#else

	ENTRY(lock_set)
	movl	4(%esp), %ecx		/* ecx = lock addr */
	movl	$-1, %edx
	xchgb	%dl, (%ecx)		/* try to set lock */
	testb	%dl, %dl		/* did we get it? */
	jnz	lock_set_spin		/* no, go to C for the hard case */
.lock_set_lockstat_patch_point:
	ret
	movl	%gs:CPU_THREAD, %edx	/* edx = thread addr */
	movl	$LS_LOCK_SET_ACQUIRE, %eax
	jmp	lockstat_wrapper
	SET_SIZE(lock_set)

#endif	/* !__amd64 */

#endif	/* __lint */

/*
 * lock_clear_splx(lp, s)
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
lock_clear_splx(lock_t *lp, int s)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(lock_clear_splx)
	movb	$0, (%rdi)		/* clear lock */
.lock_clear_splx_lockstat_patch_point:
	jmp	0f
0:
	movl	%esi, %edi		/* arg for splx */
	jmp	splx			/* let splx do its thing */
.lock_clear_splx_lockstat:
	pushq	%rbp			/* align stack properly */
	movq	%rsp, %rbp
	subq	$16, %rsp		/* space to save args across splx */
	movq	%rdi, 8(%rsp)		/* save lock ptr across splx call */
	movl	%esi, %edi		/* arg for splx */
	call	splx			/* lower the priority */
	movq	8(%rsp), %rsi		/* rsi = lock ptr */
	leave				/* unwind stack */
	movq	%gs:CPU_THREAD, %rdx	/* rdx = thread addr */
	movl	$LS_LOCK_CLEAR_SPLX_RELEASE, %edi
	jmp	lockstat_wrapper
	SET_SIZE(lock_clear_splx)

#if defined(__GNUC_AS__)
#define	LOCK_CLEAR_SPLX_LOCKSTAT_PATCH_VAL	\
	(.lock_clear_splx_lockstat - .lock_clear_splx_lockstat_patch_point - 2)

#define LOCK_CLEAR_SPLX_LOCKSTAT_PATCH_POINT	\
	(.lock_clear_splx_lockstat_patch_point + 1)
#else
#define	LOCK_CLEAR_SPLX_LOCKSTAT_PATCH_VAL	\
	[.lock_clear_splx_lockstat - .lock_clear_splx_lockstat_patch_point - 2]

#define LOCK_CLEAR_SPLX_LOCKSTAT_PATCH_POINT	\
	[.lock_clear_splx_lockstat_patch_point + 1]
#endif

#else

	ENTRY(lock_clear_splx)
	LOADCPU(%ecx)			/* ecx = cpu pointer */
	movl	4(%esp), %eax		/* eax = lock addr */
	movl	8(%esp), %edx		/* edx = desired pil */
	movb	$0, (%eax)		/* clear lock */
	cli				/* disable interrupts */
	call	spl			/* magic calling sequence */
.lock_clear_splx_lockstat_patch_point:
	ret
	movl	4(%esp), %ecx		/* ecx = lock pointer */
	movl	%gs:CPU_THREAD, %edx	/* edx = thread addr */
	movl	$LS_LOCK_CLEAR_SPLX_RELEASE, %eax
	jmp	lockstat_wrapper
	SET_SIZE(lock_clear_splx)

#endif	/* !__amd64 */

#endif	/* __lint */

/*
 * mutex_enter() and mutex_exit().
 *
 * These routines handle the simple cases of mutex_enter() (adaptive
 * lock, not held) and mutex_exit() (adaptive lock, held, no waiters).
 * If anything complicated is going on we punt to mutex_vector_enter().
 *
 * mutex_tryenter() is similar to mutex_enter() but returns zero if
 * the lock cannot be acquired, nonzero on success.
 *
 * If mutex_exit() gets preempted in the window between checking waiters
 * and clearing the lock, we can miss wakeups.  Disabling preemption
 * in the mutex code is prohibitively expensive, so instead we detect
 * mutex preemption by examining the trapped PC in the interrupt path.
 * If we interrupt a thread in mutex_exit() that has not yet cleared
 * the lock, cmnint() resets its PC back to the beginning of
 * mutex_exit() so it will check again for waiters when it resumes.
 *
 * The lockstat code below is activated when the lockstat driver
 * calls lockstat_hot_patch() to hot-patch the kernel mutex code.
 * Note that we don't need to test lockstat_event_mask here -- we won't
 * patch this code in unless we're gathering ADAPTIVE_HOLD lockstats.
 */
#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
mutex_enter(kmutex_t *lp)
{}

/* ARGSUSED */
int
mutex_tryenter(kmutex_t *lp)
{ return (0); }

/* ARGSUSED */
int
mutex_adaptive_tryenter(mutex_impl_t *lp)
{ return (0); }

/* ARGSUSED */
void
mutex_exit(kmutex_t *lp)
{}

#else

#if defined(__amd64)

	ENTRY_NP(mutex_enter)
	movq	%gs:CPU_THREAD, %rdx		/* rdx = thread ptr */
	xorl	%eax, %eax			/* rax = 0 (unheld adaptive) */
	lock
	cmpxchgq %rdx, (%rdi)
	jnz	mutex_vector_enter
.mutex_enter_lockstat_patch_point:
	ret
	movq	%rdi, %rsi
	movl	$LS_MUTEX_ENTER_ACQUIRE, %edi
/*
 * expects %rdx=thread, %rsi=lock, %edi=lockstat event
 */
	ALTENTRY(lockstat_wrapper)
	incb	T_LOCKSTAT(%rdx)		/* curthread->t_lockstat++ */
	leaq	lockstat_probemap(%rip), %rax
	movl	(%rax, %rdi, DTRACE_IDSIZE), %eax
	testl	%eax, %eax			/* check for non-zero probe */
	jz	1f
	pushq	%rbp				/* align stack properly */
	movq	%rsp, %rbp
	movl	%eax, %edi
	call	*lockstat_probe
	leave					/* unwind stack */
1:
	movq	%gs:CPU_THREAD, %rdx		/* reload thread ptr */
	decb	T_LOCKSTAT(%rdx)		/* curthread->t_lockstat-- */
	movl	$1, %eax			/* return success if tryenter */
	ret
	SET_SIZE(lockstat_wrapper)
	SET_SIZE(mutex_enter)

/*
 * expects %rcx=thread, %rdx=arg, %rsi=lock, %edi=lockstat event
 */
	ENTRY(lockstat_wrapper_arg)
	incb	T_LOCKSTAT(%rcx)		/* curthread->t_lockstat++ */
	leaq	lockstat_probemap(%rip), %rax
	movl	(%rax, %rdi, DTRACE_IDSIZE), %eax
	testl	%eax, %eax			/* check for non-zero probe */
	jz	1f
	pushq	%rbp				/* align stack properly */
	movq	%rsp, %rbp
	movl	%eax, %edi
	call	*lockstat_probe
	leave					/* unwind stack */
1:
	movq	%gs:CPU_THREAD, %rdx		/* reload thread ptr */
	decb	T_LOCKSTAT(%rdx)		/* curthread->t_lockstat-- */
	movl	$1, %eax			/* return success if tryenter */
	ret
	SET_SIZE(lockstat_wrapper_arg)


	ENTRY(mutex_tryenter)
	movq	%gs:CPU_THREAD, %rdx		/* rdx = thread ptr */
	xorl	%eax, %eax			/* rax = 0 (unheld adaptive) */
	lock
	cmpxchgq %rdx, (%rdi)
	jnz	mutex_vector_tryenter
	not	%eax				/* return success (nonzero) */
.mutex_tryenter_lockstat_patch_point:
	ret
	movq	%rdi, %rsi
	movl	$LS_MUTEX_ENTER_ACQUIRE, %edi
	jmp	lockstat_wrapper
	SET_SIZE(mutex_tryenter)

	ENTRY(mutex_adaptive_tryenter)
	movq	%gs:CPU_THREAD, %rdx		/* rdx = thread ptr */
	xorl	%eax, %eax			/* rax = 0 (unheld adaptive) */
	lock
	cmpxchgq %rdx, (%rdi)
	jnz	0f
	not	%eax				/* return success (nonzero) */
	ret
0:
	xorl	%eax, %eax			/* return failure */
	ret
	SET_SIZE(mutex_adaptive_tryenter)

	.globl mutex_exit_critical_start

	ENTRY(mutex_exit)
mutex_exit_critical_start:		/* If interrupted, restart here */
	movq	%gs:CPU_THREAD, %rdx
	cmpq	%rdx, (%rdi)
	jne	mutex_vector_exit		/* wrong type or wrong owner */
	movq	$0, (%rdi)			/* clear owner AND lock */
.mutex_exit_critical_end:
.mutex_exit_lockstat_patch_point:
	ret
	movq	%rdi, %rsi
	movl	$LS_MUTEX_EXIT_RELEASE, %edi
	jmp	lockstat_wrapper
	SET_SIZE(mutex_exit)

	.globl	mutex_exit_critical_size
	.type	mutex_exit_critical_size, @object
	.align	CPTRSIZE
mutex_exit_critical_size:
	.quad	.mutex_exit_critical_end - mutex_exit_critical_start
	SET_SIZE(mutex_exit_critical_size)

#else

	ENTRY_NP(mutex_enter)
	movl	%gs:CPU_THREAD, %edx		/* edx = thread ptr */
	movl	4(%esp), %ecx			/* ecx = lock ptr */
	xorl	%eax, %eax			/* eax = 0 (unheld adaptive) */
	lock
	cmpxchgl %edx, (%ecx)
	jnz	mutex_vector_enter
.mutex_enter_lockstat_patch_point:
	ret
	movl	$LS_MUTEX_ENTER_ACQUIRE, %eax
	ALTENTRY(lockstat_wrapper)	/* expects edx=thread, ecx=lock, */
					/*   eax=lockstat event */
	pushl	%ebp				/* buy a frame */
	movl	%esp, %ebp
	incb	T_LOCKSTAT(%edx)		/* curthread->t_lockstat++ */
	pushl	%edx				/* save thread pointer	 */
	movl	$lockstat_probemap, %edx
	movl	(%edx, %eax, DTRACE_IDSIZE), %eax
	testl	%eax, %eax			/* check for non-zero probe */
	jz	1f
	pushl	%ecx				/* push lock */
	pushl	%eax				/* push probe ID */
	call	*lockstat_probe
	addl	$8, %esp
1:
	popl	%edx				/* restore thread pointer */
	decb	T_LOCKSTAT(%edx)		/* curthread->t_lockstat-- */
	movl	$1, %eax			/* return success if tryenter */
	popl	%ebp				/* pop off frame */
	ret
	SET_SIZE(lockstat_wrapper)
	SET_SIZE(mutex_enter)

	ENTRY(lockstat_wrapper_arg)	/* expects edx=thread, ecx=lock, */
					/* eax=lockstat event, pushed arg */
	incb	T_LOCKSTAT(%edx)		/* curthread->t_lockstat++ */
	pushl	%edx				/* save thread pointer	 */
	movl	$lockstat_probemap, %edx
	movl	(%edx, %eax, DTRACE_IDSIZE), %eax
	testl	%eax, %eax			/* check for non-zero probe */
	jz	1f
	pushl	%ebp				/* save %ebp */
	pushl	8(%esp)				/* push arg1 */
	movl	%ebp, 12(%esp)			/* fake up the stack frame */
	movl	%esp, %ebp			/* fake up base pointer */
	addl	$12, %ebp			/* adjust faked base pointer */
	pushl	%ecx				/* push lock */
	pushl	%eax				/* push probe ID */
	call	*lockstat_probe
	addl	$12, %esp			/* adjust for arguments */
	popl	%ebp				/* pop frame */
1:
	popl	%edx				/* restore thread pointer */
	decb	T_LOCKSTAT(%edx)		/* curthread->t_lockstat-- */
	movl	$1, %eax			/* return success if tryenter */
	addl	$4, %esp			/* pop argument */
	ret
	SET_SIZE(lockstat_wrapper_arg)


	ENTRY(mutex_tryenter)
	movl	%gs:CPU_THREAD, %edx		/* edx = thread ptr */
	movl	4(%esp), %ecx			/* ecx = lock ptr */
	xorl	%eax, %eax			/* eax = 0 (unheld adaptive) */
	lock
	cmpxchgl %edx, (%ecx)
	jnz	mutex_vector_tryenter
	movl	%ecx, %eax
.mutex_tryenter_lockstat_patch_point:
	ret
	movl	$LS_MUTEX_ENTER_ACQUIRE, %eax
	jmp	lockstat_wrapper
	SET_SIZE(mutex_tryenter)

	ENTRY(mutex_adaptive_tryenter)
	movl	%gs:CPU_THREAD, %edx		/* edx = thread ptr */
	movl	4(%esp), %ecx			/* ecx = lock ptr */
	xorl	%eax, %eax			/* eax = 0 (unheld adaptive) */
	lock
	cmpxchgl %edx, (%ecx)
	jnz	0f
	movl	%ecx, %eax
	ret
0:
	xorl	%eax, %eax
	ret
	SET_SIZE(mutex_adaptive_tryenter)

	.globl mutex_exit_critical_size
	.globl mutex_exit_critical_start

	ENTRY(mutex_exit)
mutex_exit_critical_start:		/* If interrupted, restart here */
	movl	%gs:CPU_THREAD, %edx
	movl	4(%esp), %ecx
	cmpl	%edx, (%ecx)
	jne	mutex_vector_exit		/* wrong type or wrong owner */
	movl	$0, (%ecx)			/* clear owner AND lock */
.mutex_exit_critical_end:
.mutex_exit_lockstat_patch_point:
	ret
	movl	$LS_MUTEX_EXIT_RELEASE, %eax
	jmp	lockstat_wrapper
	SET_SIZE(mutex_exit)

	.globl	mutex_exit_critical_size
	.type	mutex_exit_critical_size, @object
	.align	CPTRSIZE
mutex_exit_critical_size:
	.long	.mutex_exit_critical_end - mutex_exit_critical_start
	SET_SIZE(mutex_exit_critical_size)

#endif	/* !__amd64 */

#endif	/* __lint */

/*
 * rw_enter() and rw_exit().
 *
 * These routines handle the simple cases of rw_enter (write-locking an unheld
 * lock or read-locking a lock that's neither write-locked nor write-wanted)
 * and rw_exit (no waiters or not the last reader).  If anything complicated
 * is going on we punt to rw_enter_sleep() and rw_exit_wakeup(), respectively.
 */
#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
rw_enter(krwlock_t *lp, krw_t rw)
{}

/* ARGSUSED */
void
rw_exit(krwlock_t *lp)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(rw_enter)
	movq	%gs:CPU_THREAD, %rdx		/* rdx = thread ptr */
	cmpl	$RW_WRITER, %esi
	je	.rw_write_enter
	incl	T_KPRI_REQ(%rdx)		/* THREAD_KPRI_REQUEST() */
	movq	(%rdi), %rax			/* rax = old rw_wwwh value */
	testl	$RW_WRITE_LOCKED|RW_WRITE_WANTED, %eax
	jnz	rw_enter_sleep
	leaq	RW_READ_LOCK(%rax), %rdx	/* rdx = new rw_wwwh value */
	lock
	cmpxchgq %rdx, (%rdi)			/* try to grab read lock */
	jnz	rw_enter_sleep
.rw_read_enter_lockstat_patch_point:
	ret
	movq	%gs:CPU_THREAD, %rcx		/* rcx = thread ptr */
	movq	%rdi, %rsi			/* rsi = lock ptr */
	movl	$LS_RW_ENTER_ACQUIRE, %edi
	movl	$RW_READER, %edx
	jmp	lockstat_wrapper_arg
.rw_write_enter:
	orq	$RW_WRITE_LOCKED, %rdx		/* rdx = write-locked value */
	xorl	%eax, %eax			/* rax = unheld value */
	lock
	cmpxchgq %rdx, (%rdi)			/* try to grab write lock */
	jnz	rw_enter_sleep
.rw_write_enter_lockstat_patch_point:
	ret
	movq	%gs:CPU_THREAD, %rcx		/* rcx = thread ptr */
	movq	%rdi, %rsi			/* rsi = lock ptr */
	movl	$LS_RW_ENTER_ACQUIRE, %edi
	movl	$RW_WRITER, %edx
	jmp	lockstat_wrapper_arg
	SET_SIZE(rw_enter)

	ENTRY(rw_exit)
	movq	(%rdi), %rax			/* rax = old rw_wwwh value */
	cmpl	$RW_READ_LOCK, %eax		/* single-reader, no waiters? */
	jne	.rw_not_single_reader
	xorl	%edx, %edx			/* rdx = new value (unheld) */
.rw_read_exit:
	lock
	cmpxchgq %rdx, (%rdi)			/* try to drop read lock */
	jnz	rw_exit_wakeup
	movq	%gs:CPU_THREAD, %rcx		/* rcx = thread ptr */
	decl	T_KPRI_REQ(%rcx)		/* THREAD_KPRI_RELEASE() */
.rw_read_exit_lockstat_patch_point:
	ret
	movq	%rdi, %rsi			/* rsi = lock ptr */
	movl	$LS_RW_EXIT_RELEASE, %edi
	movl	$RW_READER, %edx
	jmp	lockstat_wrapper_arg
.rw_not_single_reader:
	testl	$RW_WRITE_LOCKED, %eax	/* write-locked or write-wanted? */
	jnz	.rw_write_exit
	leaq	-RW_READ_LOCK(%rax), %rdx	/* rdx = new value */
	cmpl	$RW_READ_LOCK, %edx
	jge	.rw_read_exit		/* not last reader, safe to drop */
	jmp	rw_exit_wakeup			/* last reader with waiters */
.rw_write_exit:
	movq	%gs:CPU_THREAD, %rax		/* rax = thread ptr */
	xorl	%edx, %edx			/* rdx = new value (unheld) */
	orq	$RW_WRITE_LOCKED, %rax		/* eax = write-locked value */
	lock
	cmpxchgq %rdx, (%rdi)			/* try to drop read lock */
	jnz	rw_exit_wakeup
.rw_write_exit_lockstat_patch_point:
	ret
	movq	%gs:CPU_THREAD, %rcx		/* rcx = thread ptr */
	movq	%rdi, %rsi			/* rsi - lock ptr */
	movl	$LS_RW_EXIT_RELEASE, %edi
	movl	$RW_WRITER, %edx
	jmp	lockstat_wrapper_arg
	SET_SIZE(rw_exit)

#else

	ENTRY(rw_enter)
	movl	%gs:CPU_THREAD, %edx		/* edx = thread ptr */
	movl	4(%esp), %ecx			/* ecx = lock ptr */
	cmpl	$RW_WRITER, 8(%esp)
	je	.rw_write_enter
	incl	T_KPRI_REQ(%edx)		/* THREAD_KPRI_REQUEST() */
	movl	(%ecx), %eax			/* eax = old rw_wwwh value */
	testl	$RW_WRITE_LOCKED|RW_WRITE_WANTED, %eax
	jnz	rw_enter_sleep
	leal	RW_READ_LOCK(%eax), %edx	/* edx = new rw_wwwh value */
	lock
	cmpxchgl %edx, (%ecx)			/* try to grab read lock */
	jnz	rw_enter_sleep
.rw_read_enter_lockstat_patch_point:
	ret
	movl	%gs:CPU_THREAD, %edx		/* edx = thread ptr */
	movl	$LS_RW_ENTER_ACQUIRE, %eax
	pushl	$RW_READER
	jmp	lockstat_wrapper_arg
.rw_write_enter:
	orl	$RW_WRITE_LOCKED, %edx		/* edx = write-locked value */
	xorl	%eax, %eax			/* eax = unheld value */
	lock
	cmpxchgl %edx, (%ecx)			/* try to grab write lock */
	jnz	rw_enter_sleep
.rw_write_enter_lockstat_patch_point:
	ret
	movl	%gs:CPU_THREAD, %edx		/* edx = thread ptr */
	movl	$LS_RW_ENTER_ACQUIRE, %eax
	pushl	$RW_WRITER
	jmp	lockstat_wrapper_arg
	SET_SIZE(rw_enter)

	ENTRY(rw_exit)
	movl	4(%esp), %ecx			/* ecx = lock ptr */
	movl	(%ecx), %eax			/* eax = old rw_wwwh value */
	cmpl	$RW_READ_LOCK, %eax		/* single-reader, no waiters? */
	jne	.rw_not_single_reader
	xorl	%edx, %edx			/* edx = new value (unheld) */
.rw_read_exit:
	lock
	cmpxchgl %edx, (%ecx)			/* try to drop read lock */
	jnz	rw_exit_wakeup
	movl	%gs:CPU_THREAD, %edx		/* edx = thread ptr */
	decl	T_KPRI_REQ(%edx)		/* THREAD_KPRI_RELEASE() */
.rw_read_exit_lockstat_patch_point:
	ret
	movl	$LS_RW_EXIT_RELEASE, %eax
	pushl	$RW_READER
	jmp	lockstat_wrapper_arg
.rw_not_single_reader:
	testl	$RW_WRITE_LOCKED, %eax	/* write-locked or write-wanted? */
	jnz	.rw_write_exit
	leal	-RW_READ_LOCK(%eax), %edx	/* edx = new value */
	cmpl	$RW_READ_LOCK, %edx
	jge	.rw_read_exit		/* not last reader, safe to drop */
	jmp	rw_exit_wakeup			/* last reader with waiters */
.rw_write_exit:
	movl	%gs:CPU_THREAD, %eax		/* eax = thread ptr */
	xorl	%edx, %edx			/* edx = new value (unheld) */
	orl	$RW_WRITE_LOCKED, %eax		/* eax = write-locked value */
	lock
	cmpxchgl %edx, (%ecx)			/* try to drop read lock */
	jnz	rw_exit_wakeup
.rw_write_exit_lockstat_patch_point:
	ret
	movl	%gs:CPU_THREAD, %edx		/* edx = thread ptr */
	movl	$LS_RW_EXIT_RELEASE, %eax
	pushl	$RW_WRITER
	jmp	lockstat_wrapper_arg
	SET_SIZE(rw_exit)

#endif	/* !__amd64 */

#endif	/* __lint */

#if defined(lint) || defined(__lint)

void
lockstat_hot_patch(void)
{}

#else

#if defined(__amd64)

#define	HOT_PATCH(addr, event, active_instr, normal_instr, len)	\
	movq	$normal_instr, %rsi;		\
	movq	$active_instr, %rdi;		\
	leaq	lockstat_probemap(%rip), %rax;	\
	movl 	_MUL(event, DTRACE_IDSIZE)(%rax), %eax;	\
	testl	%eax, %eax;			\
	jz	9f;				\
	movq	%rdi, %rsi;			\
9:						\
	movq	$len, %rdx;			\
	movq	$addr, %rdi;			\
	call	hot_patch_kernel_text

#else

#define	HOT_PATCH(addr, event, active_instr, normal_instr, len)	\
	movl	$normal_instr, %ecx;		\
	movl	$active_instr, %edx;		\
	movl	$lockstat_probemap, %eax;	\
	movl	_MUL(event, DTRACE_IDSIZE)(%eax), %eax;	\
	testl	%eax, %eax;			\
	jz	. + 4;				\
	movl	%edx, %ecx;			\
	pushl	$len;				\
	pushl	%ecx;				\
	pushl	$addr;				\
	call	hot_patch_kernel_text;		\
	addl	$12, %esp;

#endif	/* !__amd64 */

	ENTRY(lockstat_hot_patch)
#if defined(__amd64)
	pushq	%rbp			/* align stack properly */
	movq	%rsp, %rbp
#endif	/* __amd64 */
	HOT_PATCH(.mutex_enter_lockstat_patch_point,
		LS_MUTEX_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.mutex_tryenter_lockstat_patch_point,
		LS_MUTEX_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.mutex_exit_lockstat_patch_point,
		LS_MUTEX_EXIT_RELEASE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.rw_write_enter_lockstat_patch_point,
		LS_RW_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.rw_read_enter_lockstat_patch_point,
		LS_RW_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.rw_write_exit_lockstat_patch_point,
		LS_RW_EXIT_RELEASE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.rw_read_exit_lockstat_patch_point,
		LS_RW_EXIT_RELEASE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.lock_set_lockstat_patch_point,
		LS_LOCK_SET_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.lock_try_lockstat_patch_point,
		LS_LOCK_TRY_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.lock_clear_lockstat_patch_point,
		LS_LOCK_CLEAR_RELEASE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.lock_set_spl_lockstat_patch_point,
		LS_LOCK_SET_SPL_ACQUIRE, NOP_INSTR, RET_INSTR, 1)

#if defined(__amd64)
	HOT_PATCH(LOCK_CLEAR_SPLX_LOCKSTAT_PATCH_POINT,
		LS_LOCK_CLEAR_SPLX_RELEASE,
		LOCK_CLEAR_SPLX_LOCKSTAT_PATCH_VAL, 0, 1);
#else
	HOT_PATCH(.lock_clear_splx_lockstat_patch_point,
		LS_LOCK_CLEAR_SPLX_RELEASE, NOP_INSTR, RET_INSTR, 1)
#endif	/* !__amd64 */

#if defined(__amd64)
	leave			/* unwind stack */
#endif	/* __amd64 */
	ret
	SET_SIZE(lockstat_hot_patch)

#endif	/* __lint */

#if defined(lint) || defined(__lint)

/* XX64 membar_*() should be inlines */

void
membar_enter(void)
{}

void
membar_exit(void)
{}

void
membar_producer(void)
{}

void
membar_consumer(void)
{}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(membar_enter)
	ALTENTRY(membar_exit)
	mfence			/* lighter weight than lock; xorq $0,(%rsp) */
	ret
	SET_SIZE(membar_exit)
	SET_SIZE(membar_enter)

	ENTRY(membar_producer)
	sfence
	ret
	SET_SIZE(membar_producer)

	ENTRY(membar_consumer)
	lfence
	ret
	SET_SIZE(membar_consumer)

#else

	ENTRY(membar_enter)
	ALTENTRY(membar_exit)
	lock
	xorl	$0, (%esp)
	ret
	SET_SIZE(membar_exit)
	SET_SIZE(membar_enter)

/*
 * On machines that support sfence and lfence, these
 * memory barriers can be more precisely implemented
 * without causing the whole world to stop
 */
	ENTRY(membar_producer)
	.globl	_patch_sfence_ret
_patch_sfence_ret:			/* c.f. membar #StoreStore */
	lock
	xorl	$0, (%esp)
	ret
	SET_SIZE(membar_producer)

	ENTRY(membar_consumer)
	.globl	_patch_lfence_ret
_patch_lfence_ret:			/* c.f. membar #LoadLoad */
	lock
	xorl	$0, (%esp)
	ret
	SET_SIZE(membar_consumer)

#endif	/* !__amd64 */

#endif	/* __lint */

/*
 * thread_onproc()
 * Set thread in onproc state for the specified CPU.
 * Also set the thread lock pointer to the CPU's onproc lock.
 * Since the new lock isn't held, the store ordering is important.
 * If not done in assembler, the compiler could reorder the stores.
 */
#if defined(lint) || defined(__lint)

void
thread_onproc(kthread_id_t t, cpu_t *cp)
{
	t->t_state = TS_ONPROC;
	t->t_lockp = &cp->cpu_thread_lock;
}

#else	/* __lint */

#if defined(__amd64)

	ENTRY(thread_onproc)
	addq	$CPU_THREAD_LOCK, %rsi	/* pointer to disp_lock while running */
	movl	$ONPROC_THREAD, T_STATE(%rdi)	/* set state to TS_ONPROC */
	movq	%rsi, T_LOCKP(%rdi)	/* store new lock pointer */
	ret
	SET_SIZE(thread_onproc)

#else

	ENTRY(thread_onproc)
	movl	4(%esp), %eax
	movl	8(%esp), %ecx
	addl	$CPU_THREAD_LOCK, %ecx	/* pointer to disp_lock while running */
	movl	$ONPROC_THREAD, T_STATE(%eax)	/* set state to TS_ONPROC */
	movl	%ecx, T_LOCKP(%eax)	/* store new lock pointer */
	ret
	SET_SIZE(thread_onproc)

#endif	/* !__amd64 */

#endif	/* __lint */
