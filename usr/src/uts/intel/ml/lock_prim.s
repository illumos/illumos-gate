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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright 2019 Joyent, Inc.
 */

#include "assym.h"

#include <sys/mutex_impl.h>
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

	.globl	kernelbase

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

#ifdef DEBUG
	.data
.ulock_panic_msg:
	.string "ulock_try: Argument is above kernelbase"
	.text
#endif	/* DEBUG */

/*
 * lock_clear(lp)
 *	- unlock lock without changing interrupt priority level.
 */

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

#ifdef DEBUG
	.data
.ulock_clear_msg:
	.string "ulock_clear: Argument is above kernelbase"
	.text
#endif	/* DEBUG */


/*
 * lock_set_spl(lock_t *lp, int new_pil, u_short *old_pil)
 * Drops lp, sets pil to new_pil, stores old pil in *old_pil.
 */

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

/*
 * void
 * lock_init(lp)
 */

	ENTRY(lock_init)
	movb	$0, (%rdi)
	ret
	SET_SIZE(lock_init)

/*
 * void
 * lock_set(lp)
 */

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

/*
 * lock_clear_splx(lp, s)
 */

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

	ENTRY_NP(mutex_enter)
	movq	%gs:CPU_THREAD, %rdx		/* rdx = thread ptr */
	xorl	%eax, %eax			/* rax = 0 (unheld adaptive) */
	lock
	cmpxchgq %rdx, (%rdi)
	jnz	mutex_vector_enter
.mutex_enter_lockstat_patch_point:
#if defined(OPTERON_WORKAROUND_6323525)
.mutex_enter_6323525_patch_point:
	ret					/* nop space for lfence */
	nop
	nop
.mutex_enter_lockstat_6323525_patch_point:	/* new patch point if lfence */
	nop
#else	/* OPTERON_WORKAROUND_6323525 */
	ret
#endif	/* OPTERON_WORKAROUND_6323525 */
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
	movq	lockstat_probe, %rax
	INDIRECT_CALL_REG(rax)
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
	movq	lockstat_probe, %rax
	INDIRECT_CALL_REG(rax)
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
#if defined(OPTERON_WORKAROUND_6323525)
.mutex_tryenter_lockstat_patch_point:
.mutex_tryenter_6323525_patch_point:
	ret					/* nop space for lfence */
	nop
	nop
.mutex_tryenter_lockstat_6323525_patch_point:	/* new patch point if lfence */
	nop
#else	/* OPTERON_WORKAROUND_6323525 */
.mutex_tryenter_lockstat_patch_point:
	ret
#endif	/* OPTERON_WORKAROUND_6323525 */
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
#if defined(OPTERON_WORKAROUND_6323525)
.mutex_atryenter_6323525_patch_point:
	ret					/* nop space for lfence */
	nop
	nop
	nop
#else	/* OPTERON_WORKAROUND_6323525 */
	ret
#endif	/* OPTERON_WORKAROUND_6323525 */
0:
	xorl	%eax, %eax			/* return failure */
	ret
	SET_SIZE(mutex_adaptive_tryenter)

	.globl	mutex_owner_running_critical_start

	ENTRY(mutex_owner_running)
mutex_owner_running_critical_start:
	movq	(%rdi), %r11		/* get owner field */
	andq	$MUTEX_THREAD, %r11	/* remove waiters bit */
	cmpq	$0, %r11		/* if free, skip */
	je	1f			/* go return 0 */
	movq	T_CPU(%r11), %r8	/* get owner->t_cpu */
	movq	CPU_THREAD(%r8), %r9	/* get t_cpu->cpu_thread */
.mutex_owner_running_critical_end:
	cmpq	%r11, %r9	/* owner == running thread? */
	je	2f		/* yes, go return cpu */
1:
	xorq	%rax, %rax	/* return 0 */
	ret
2:
	movq	%r8, %rax		/* return cpu */
	ret
	SET_SIZE(mutex_owner_running)

	.globl	mutex_owner_running_critical_size
	.type	mutex_owner_running_critical_size, @object
	.align	CPTRSIZE
mutex_owner_running_critical_size:
	.quad	.mutex_owner_running_critical_end - mutex_owner_running_critical_start
	SET_SIZE(mutex_owner_running_critical_size)

	.globl	mutex_exit_critical_start

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

/*
 * rw_enter() and rw_exit().
 *
 * These routines handle the simple cases of rw_enter (write-locking an unheld
 * lock or read-locking a lock that's neither write-locked nor write-wanted)
 * and rw_exit (no waiters or not the last reader).  If anything complicated
 * is going on we punt to rw_enter_sleep() and rw_exit_wakeup(), respectively.
 */

	ENTRY(rw_enter)
	cmpl	$RW_WRITER, %esi
	je	.rw_write_enter
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
	movq	%gs:CPU_THREAD, %rdx
	orq	$RW_WRITE_LOCKED, %rdx		/* rdx = write-locked value */
	xorl	%eax, %eax			/* rax = unheld value */
	lock
	cmpxchgq %rdx, (%rdi)			/* try to grab write lock */
	jnz	rw_enter_sleep

#if defined(OPTERON_WORKAROUND_6323525)
.rw_write_enter_lockstat_patch_point:
.rw_write_enter_6323525_patch_point:
	ret
	nop
	nop
.rw_write_enter_lockstat_6323525_patch_point:
	nop
#else	/* OPTERON_WORKAROUND_6323525 */
.rw_write_enter_lockstat_patch_point:
	ret
#endif	/* OPTERON_WORKAROUND_6323525 */

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
.rw_read_exit_lockstat_patch_point:
	ret
	movq	%gs:CPU_THREAD, %rcx		/* rcx = thread ptr */
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

#if defined(OPTERON_WORKAROUND_6323525)

/*
 * If it is necessary to patch the lock enter routines with the lfence
 * workaround, workaround_6323525_patched is set to a non-zero value so that
 * the lockstat_hat_patch routine can patch to the new location of the 'ret'
 * instruction.
 */
	DGDEF3(workaround_6323525_patched, 4, 4)
	.long	0

#define HOT_MUTEX_PATCH(srcaddr, dstaddr, size)	\
	movq	$size, %rbx;			\
	movq	$dstaddr, %r13;			\
	addq	%rbx, %r13;			\
	movq	$srcaddr, %r12;			\
	addq	%rbx, %r12;			\
0:						\
	decq	%r13;				\
	decq	%r12;				\
	movzbl	(%r12), %esi;			\
	movq	$1, %rdx;			\
	movq	%r13, %rdi;			\
	call	hot_patch_kernel_text;		\
	decq	%rbx;				\
	testq	%rbx, %rbx;			\
	jg	0b;

/*
 * patch_workaround_6323525: provide workaround for 6323525
 *
 * The workaround is to place a fencing instruction (lfence) between the
 * mutex operation and the subsequent read-modify-write instruction.
 *
 * This routine hot patches the lfence instruction on top of the space
 * reserved by nops in the lock enter routines.
 */
	ENTRY_NP(patch_workaround_6323525)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12
	pushq	%r13
	pushq	%rbx

	/*
	 * lockstat_hot_patch() to use the alternate lockstat workaround
	 * 6323525 patch points (points past the lfence instruction to the
	 * new ret) when workaround_6323525_patched is set.
	 */
	movl	$1, workaround_6323525_patched

	/*
	 * patch ret/nop/nop/nop to lfence/ret at the end of the lock enter
	 * routines. The 4 bytes are patched in reverse order so that the
	 * the existing ret is overwritten last. This provides lock enter
	 * sanity during the intermediate patching stages.
	 */
	HOT_MUTEX_PATCH(_lfence_insn, .mutex_enter_6323525_patch_point, 4)
	HOT_MUTEX_PATCH(_lfence_insn, .mutex_tryenter_6323525_patch_point, 4)
	HOT_MUTEX_PATCH(_lfence_insn, .mutex_atryenter_6323525_patch_point, 4)
	HOT_MUTEX_PATCH(_lfence_insn, .rw_write_enter_6323525_patch_point, 4)

	popq	%rbx
	popq	%r13
	popq	%r12
	movq	%rbp, %rsp
	popq	%rbp
	ret
_lfence_insn:
	lfence
	ret
	SET_SIZE(patch_workaround_6323525)


#endif	/* OPTERON_WORKAROUND_6323525 */


#define	HOT_PATCH(addr, event, active_instr, normal_instr, len)	\
	movq	$normal_instr, %rsi;		\
	movq	$active_instr, %rdi;		\
	leaq	lockstat_probemap(%rip), %rax;	\
	movl	_MUL(event, DTRACE_IDSIZE)(%rax), %eax;	\
	testl	%eax, %eax;			\
	jz	9f;				\
	movq	%rdi, %rsi;			\
9:						\
	movq	$len, %rdx;			\
	movq	$addr, %rdi;			\
	call	hot_patch_kernel_text

	ENTRY(lockstat_hot_patch)
	pushq	%rbp			/* align stack properly */
	movq	%rsp, %rbp

#if defined(OPTERON_WORKAROUND_6323525)
	cmpl	$0, workaround_6323525_patched
	je	1f
	HOT_PATCH(.mutex_enter_lockstat_6323525_patch_point,
		LS_MUTEX_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.mutex_tryenter_lockstat_6323525_patch_point,
		LS_MUTEX_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.rw_write_enter_lockstat_6323525_patch_point,
		LS_RW_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	jmp	2f
1:
	HOT_PATCH(.mutex_enter_lockstat_patch_point,
		LS_MUTEX_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.mutex_tryenter_lockstat_patch_point,
		LS_MUTEX_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.rw_write_enter_lockstat_patch_point,
		LS_RW_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
2:
#else	/* OPTERON_WORKAROUND_6323525 */
	HOT_PATCH(.mutex_enter_lockstat_patch_point,
		LS_MUTEX_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.mutex_tryenter_lockstat_patch_point,
		LS_MUTEX_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
	HOT_PATCH(.rw_write_enter_lockstat_patch_point,
		LS_RW_ENTER_ACQUIRE, NOP_INSTR, RET_INSTR, 1)
#endif	/* !OPTERON_WORKAROUND_6323525 */
	HOT_PATCH(.mutex_exit_lockstat_patch_point,
		LS_MUTEX_EXIT_RELEASE, NOP_INSTR, RET_INSTR, 1)
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

	HOT_PATCH(LOCK_CLEAR_SPLX_LOCKSTAT_PATCH_POINT,
		LS_LOCK_CLEAR_SPLX_RELEASE,
		LOCK_CLEAR_SPLX_LOCKSTAT_PATCH_VAL, 0, 1);
	leave			/* unwind stack */
	ret
	SET_SIZE(lockstat_hot_patch)

	ENTRY(membar_enter)
	ALTENTRY(membar_exit)
	ALTENTRY(membar_sync)
	mfence			/* lighter weight than lock; xorq $0,(%rsp) */
	ret
	SET_SIZE(membar_sync)
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

/*
 * thread_onproc()
 * Set thread in onproc state for the specified CPU.
 * Also set the thread lock pointer to the CPU's onproc lock.
 * Since the new lock isn't held, the store ordering is important.
 * If not done in assembler, the compiler could reorder the stores.
 */

	ENTRY(thread_onproc)
	addq	$CPU_THREAD_LOCK, %rsi	/* pointer to disp_lock while running */
	movl	$ONPROC_THREAD, T_STATE(%rdi)	/* set state to TS_ONPROC */
	movq	%rsi, T_LOCKP(%rdi)	/* store new lock pointer */
	ret
	SET_SIZE(thread_onproc)

/*
 * mutex_delay_default(void)
 * Spins for approx a few hundred processor cycles and returns to caller.
 */

	ENTRY(mutex_delay_default)
	movq	$92,%r11
0:	decq	%r11
	jg	0b
	ret
	SET_SIZE(mutex_delay_default)

