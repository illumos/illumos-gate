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
 * Copyright 2022 Oxide Computer Company
 */

#include "assym.h"

#include <sys/mutex_impl.h>
#include <sys/asm_linkage.h>
#include <sys/asm_misc.h>
#include <sys/regset.h>
#include <sys/rwlock_impl.h>
#include <sys/lockstat.h>


#if defined(OPTERON_ERRATUM_147)

/*
 * Leave space for an lfence to be inserted if required by a CPU which suffers
 * from this erratum.  Pad (with nops) the location for the lfence so that it
 * is adequately aligned for atomic hotpatching.
 */
#define	ERRATUM147_PATCH_POINT(name)	\
	.align	4, NOP_INSTR;		\
./**/name/**/_147_patch_point:		\
	nop;				\
	nop;				\
	nop;				\
	nop;

#else /* defined(OPTERON_ERRATUM_147) */

/* Empty macro so ifdefs are not required for all of the erratum sites. */
#define	ERRATUM147_PATCH_POINT(name)

#endif /* defined(OPTERON_ERRATUM_147) */

/*
 * Patch point for lockstat probes.  When the associated probe is disabled, it
 * will 'ret' from the function.  It is hotpatched to allow execution to fall
 * through when the probe is enabled.
 */
#define	LOCKSTAT_RET(name)		\
./**/name/**/_lockstat_patch_point:	\
	ret;

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
	LOCKSTAT_RET(lock_try)

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
	pushq	%rbp
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
	LOCKSTAT_RET(lock_clear)

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
	pushq	%rbp
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
	LOCKSTAT_RET(lock_set_spl)

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
	LOCKSTAT_RET(lock_set)

	movq	%rdi, %rsi		/* rsi = lock addr */
	movq	%gs:CPU_THREAD, %rdx	/* rdx = thread addr */
	movl	$LS_LOCK_SET_ACQUIRE, %edi
	jmp	lockstat_wrapper
	SET_SIZE(lock_set)

/*
 * lock_clear_splx(lp, s)
 */

	ENTRY(lock_clear_splx)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%rdi		/* save lp across call for lockstat */
	movb	$0, (%rdi)	/* clear lock */
	movl	%esi, %edi	/* arg for splx */
	call	splx		/* let splx do its thing */
	popq	%rsi		/* retreive lp for lockstat */
	leave
	LOCKSTAT_RET(lock_clear_splx)

	movq	%gs:CPU_THREAD, %rdx	/* rdx = thread addr */
	movl	$LS_LOCK_CLEAR_SPLX_RELEASE, %edi
	jmp	lockstat_wrapper
	SET_SIZE(lock_clear_splx)

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
 */

	ENTRY_NP(mutex_enter)
	movq	%gs:CPU_THREAD, %rdx		/* rdx = thread ptr */
	xorl	%eax, %eax			/* rax = 0 (unheld adaptive) */
	lock
	cmpxchgq %rdx, (%rdi)
	jnz	mutex_vector_enter

	ERRATUM147_PATCH_POINT(mutex_enter)

	LOCKSTAT_RET(mutex_enter)

	movq	%rdi, %rsi
	movl	$LS_MUTEX_ENTER_ACQUIRE, %edi
	jmp	lockstat_wrapper
	SET_SIZE(mutex_enter)


/*
 * expects %rdx=thread, %rsi=lock, %edi=lockstat event
 */
	ENTRY_NP(lockstat_wrapper)
	incb	T_LOCKSTAT(%rdx)		/* curthread->t_lockstat++ */
	leaq	lockstat_probemap(%rip), %rax
	movl	(%rax, %rdi, DTRACE_IDSIZE), %eax
	testl	%eax, %eax			/* check for non-zero probe */
	jz	1f
	pushq	%rbp
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

/*
 * expects %rcx=thread, %rdx=arg, %rsi=lock, %edi=lockstat event
 */
	ENTRY(lockstat_wrapper_arg)
	incb	T_LOCKSTAT(%rcx)		/* curthread->t_lockstat++ */
	leaq	lockstat_probemap(%rip), %rax
	movl	(%rax, %rdi, DTRACE_IDSIZE), %eax
	testl	%eax, %eax			/* check for non-zero probe */
	jz	1f
	pushq	%rbp
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

	ERRATUM147_PATCH_POINT(mutex_tryenter)

	LOCKSTAT_RET(mutex_tryenter)

	movq	%rdi, %rsi
	movl	$LS_MUTEX_TRYENTER_ACQUIRE, %edi
	jmp	lockstat_wrapper
	SET_SIZE(mutex_tryenter)

	ENTRY(mutex_adaptive_tryenter)
	movq	%gs:CPU_THREAD, %rdx		/* rdx = thread ptr */
	xorl	%eax, %eax			/* rax = 0 (unheld adaptive) */
	lock
	cmpxchgq %rdx, (%rdi)
	jnz	0f
	not	%eax				/* return success (nonzero) */

	ERRATUM147_PATCH_POINT(mutex_atryenter)

	ret
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
	LOCKSTAT_RET(mutex_exit)

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
	LOCKSTAT_RET(rw_read_enter)

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

	ERRATUM147_PATCH_POINT(rw_write_enter)

	LOCKSTAT_RET(rw_write_enter)

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
	LOCKSTAT_RET(rw_read_exit)

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
	LOCKSTAT_RET(rw_write_exit)

	movq	%gs:CPU_THREAD, %rcx		/* rcx = thread ptr */
	movq	%rdi, %rsi			/* rsi - lock ptr */
	movl	$LS_RW_EXIT_RELEASE, %edi
	movl	$RW_WRITER, %edx
	jmp	lockstat_wrapper_arg
	SET_SIZE(rw_exit)

#if defined(OPTERON_ERRATUM_147)

/*
 * Track if erratum 147 workaround has been hotpatched into place.
 */
	DGDEF3(erratum_147_patched, 4, 4)
	.long	0

#define HOT_MUTEX_PATCH(iaddr, insn_reg)	\
	movq	$iaddr, %rdi;		\
	movl	%insn_reg, %esi;	\
	movl	$4, %edx;		\
	call	hot_patch_kernel_text;


/*
 * void
 * patch_erratum_147(void)
 *
 * Patch lock operations to work around erratum 147.
 *
 * The workaround is to place a fencing instruction (lfence) between the
 * mutex operation and the subsequent read-modify-write instruction.
 */

	ENTRY_NP(patch_erratum_147)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12

	/*
	 * Patch `nop; nop; nop; nop` sequence to `lfence; nop`.  Since those
	 * patch points have been aligned to a 4-byte boundary, we can be
	 * confident that hot_patch_kernel_text() will be able to proceed
	 * safely and successfully.
	 */
	movl	$0x90e8ae0f, %r12d
	HOT_MUTEX_PATCH(.mutex_enter_147_patch_point, r12d)
	HOT_MUTEX_PATCH(.mutex_tryenter_147_patch_point, r12d)
	HOT_MUTEX_PATCH(.mutex_atryenter_147_patch_point, r12d)
	HOT_MUTEX_PATCH(.rw_write_enter_147_patch_point, r12d)

	/* Record that erratum 147 points have been hotpatched */
	movl	$1, erratum_147_patched

	popq	%r12
	movq	%rbp, %rsp
	popq	%rbp
	ret
	SET_SIZE(patch_erratum_147)

#endif	/* OPTERON_ERRATUM_147 */

	/*
	 * void
	 * lockstat_hotpatch_site(caddr_t instr_addr, int do_enable)
	 */
	ENTRY(lockstat_hotpatch_site)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%rdi
	pushq	%rsi

	testl	%esi, %esi
	jz	.do_disable

	/* enable the probe (replace ret with nop) */
	movl	$NOP_INSTR, %esi
	movl	$1, %edx
	call	hot_patch_kernel_text
	leave
	ret

.do_disable:
	/* disable the probe (replace nop with ret) */
	movl	$RET_INSTR, %esi
	movl	$1, %edx
	call	hot_patch_kernel_text
	leave
	ret
	SET_SIZE(lockstat_hotpatch_site)

#define	HOT_PATCH_MATCH(name, probe, reg)			\
	cmpl	$probe, %reg;					\
	jne	1f;						\
	leaq	lockstat_probemap(%rip), %rax;			\
	movl	_MUL(probe, DTRACE_IDSIZE)(%rax), %esi;		\
	movq	$./**/name/**/_lockstat_patch_point, %rdi;	\
	call	lockstat_hotpatch_site;				\
	1:

/*
 * void
 * lockstat_hotpatch_probe(int ls_probe)
 *
 * Given a lockstat probe identifier, hotpatch any associated lockstat
 * primitive routine(s) so they fall through into the lockstat_probe() call (if
 * the probe is enabled) or return normally (when the probe is disabled).
 */

	ENTRY(lockstat_hotpatch_probe)
	pushq	%rbp
	movq	%rsp, %rbp
	pushq	%r12
	movl	%edi, %r12d

	HOT_PATCH_MATCH(mutex_enter, LS_MUTEX_ENTER_ACQUIRE, r12d)
	HOT_PATCH_MATCH(mutex_tryenter, LS_MUTEX_TRYENTER_ACQUIRE, r12d)
	HOT_PATCH_MATCH(mutex_exit, LS_MUTEX_EXIT_RELEASE, r12d)

	HOT_PATCH_MATCH(rw_write_enter, LS_RW_ENTER_ACQUIRE, r12d)
	HOT_PATCH_MATCH(rw_read_enter, LS_RW_ENTER_ACQUIRE, r12d)
	HOT_PATCH_MATCH(rw_write_exit, LS_RW_EXIT_RELEASE, r12d)
	HOT_PATCH_MATCH(rw_read_exit, LS_RW_EXIT_RELEASE, r12d)

	HOT_PATCH_MATCH(lock_set, LS_LOCK_SET_ACQUIRE, r12d)
	HOT_PATCH_MATCH(lock_try, LS_LOCK_TRY_ACQUIRE, r12d)
	HOT_PATCH_MATCH(lock_clear, LS_LOCK_CLEAR_RELEASE, r12d)
	HOT_PATCH_MATCH(lock_set_spl, LS_LOCK_SET_SPL_ACQUIRE, r12d)
	HOT_PATCH_MATCH(lock_clear_splx, LS_LOCK_CLEAR_SPLX_RELEASE, r12d)

	popq	%r12
	leave
	ret
	SET_SIZE(lockstat_hotpatch_probe)

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

