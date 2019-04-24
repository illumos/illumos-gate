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
 *
 * Copyright 2020 Joyent, Inc.
 */

#include "assym.h"

#include <sys/t_lock.h>
#include <sys/mutex.h>
#include <sys/mutex_impl.h>
#include <sys/rwlock_impl.h>
#include <sys/asm_linkage.h>
#include <sys/machlock.h>
#include <sys/machthread.h>
#include <sys/lockstat.h>

/* #define DEBUG */

#ifdef DEBUG
#include <sys/machparam.h>
#endif /* DEBUG */

/************************************************************************
 *		ATOMIC OPERATIONS
 */

/*
 * uint8_t	ldstub(uint8_t *cp)
 *
 * Store 0xFF at the specified location, and return its previous content.
 */

	ENTRY(ldstub)
	retl
	ldstub	[%o0], %o0
	SET_SIZE(ldstub)

/************************************************************************
 *		MEMORY BARRIERS -- see atomic.h for full descriptions.
 */

#ifdef SF_ERRATA_51
	.align 32
	ENTRY(membar_return)
	retl
	nop
	SET_SIZE(membar_return)
#define	MEMBAR_RETURN	ba,pt %icc, membar_return
#else
#define	MEMBAR_RETURN	retl
#endif

	ENTRY(membar_enter)
	MEMBAR_RETURN
	membar	#StoreLoad|#StoreStore
	SET_SIZE(membar_enter)

	ENTRY(membar_exit)
	MEMBAR_RETURN
	membar	#LoadStore|#StoreStore
	SET_SIZE(membar_exit)

	ENTRY(membar_producer)
	MEMBAR_RETURN
	membar	#StoreStore
	SET_SIZE(membar_producer)

	ENTRY(membar_consumer)
	MEMBAR_RETURN
	membar	#LoadLoad
	SET_SIZE(membar_consumer)

/************************************************************************
 *		MINIMUM LOCKS
 */

/*
 * lock_try(lp), ulock_try(lp)
 * - returns non-zero on success.
 * - doesn't block interrupts so don't use this to spin on a lock.
 * - uses "0xFF is busy, anything else is free" model.
 *
 * ulock_try() is for a lock in the user address space.
 */

	.align	32
	ENTRY(lock_try)
	ldstub	[%o0], %o1		! try to set lock, get value in %o1
	brnz,pn	%o1, 1f
	membar	#LoadLoad
.lock_try_lockstat_patch_point:
	retl
	or	%o0, 1, %o0		! ensure lo32 != 0
1:
	retl
	clr	%o0
	SET_SIZE(lock_try)

	.align	32
	ENTRY(lock_spin_try)
	ldstub	[%o0], %o1		! try to set lock, get value in %o1
	brnz,pn	%o1, 1f
	membar	#LoadLoad
	retl
	or	%o0, 1, %o0		! ensure lo32 != 0
1:
	retl
	clr	%o0
	SET_SIZE(lock_spin_try)

	.align	32
	ENTRY(lock_set)
	ldstub	[%o0], %o1
	brnz,pn	%o1, 1f			! go to C for the hard case
	membar	#LoadLoad
.lock_set_lockstat_patch_point:
	retl
	nop
1:
	sethi	%hi(lock_set_spin), %o2	! load up for jump to C
	jmp	%o2 + %lo(lock_set_spin)
	nop				! delay: do nothing
	SET_SIZE(lock_set)

	ENTRY(lock_clear)
	membar	#LoadStore|#StoreStore
.lock_clear_lockstat_patch_point:
	retl
	clrb	[%o0]
	SET_SIZE(lock_clear)

	.align	32
	ENTRY(ulock_try)
	ldstuba	[%o0]ASI_USER, %o1	! try to set lock, get value in %o1
	xor	%o1, 0xff, %o0		! delay - return non-zero if success
	retl
	  membar	#LoadLoad
	SET_SIZE(ulock_try)

	ENTRY(ulock_clear)
	membar  #LoadStore|#StoreStore
	retl
	  stba	%g0, [%o0]ASI_USER	! clear lock
	SET_SIZE(ulock_clear)


/*
 * lock_set_spl(lp, new_pil, *old_pil_addr)
 *	Sets pil to new_pil, grabs lp, stores old pil in *old_pil_addr.
 */

	ENTRY(lock_set_spl)
	rdpr	%pil, %o3			! %o3 = current pil
	cmp	%o3, %o1			! is current pil high enough?
	bl,a,pt %icc, 1f			! if not, write %pil in delay
	wrpr	%g0, %o1, %pil
1:
	ldstub	[%o0], %o4			! try the lock
	brnz,pn	%o4, 2f				! go to C for the miss case
	membar	#LoadLoad
.lock_set_spl_lockstat_patch_point:
	retl
	sth	%o3, [%o2]			! delay - save original pil
2:
	sethi	%hi(lock_set_spl_spin), %o5	! load up jmp to C
	jmp	%o5 + %lo(lock_set_spl_spin)	! jmp to lock_set_spl_spin
	nop					! delay: do nothing
	SET_SIZE(lock_set_spl)

/*
 * lock_clear_splx(lp, s)
 */

	ENTRY(lock_clear_splx)
	ldn	[THREAD_REG + T_CPU], %o2	! get CPU pointer
	membar	#LoadStore|#StoreStore
	ld	[%o2 + CPU_BASE_SPL], %o2
	clrb	[%o0]				! clear lock
	cmp	%o2, %o1			! compare new to base
	movl	%xcc, %o1, %o2			! use new pri if base is less
.lock_clear_splx_lockstat_patch_point:
	retl
	wrpr	%g0, %o2, %pil
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
 * the lock, pil_interrupt() resets its PC back to the beginning of
 * mutex_exit() so it will check again for waiters when it resumes.
 *
 * The lockstat code below is activated when the lockstat driver
 * calls lockstat_hot_patch() to hot-patch the kernel mutex code.
 * Note that we don't need to test lockstat_event_mask here -- we won't
 * patch this code in unless we're gathering ADAPTIVE_HOLD lockstats.
 */

	.align	32
	ENTRY(mutex_enter)
	mov	THREAD_REG, %o1
	casx	[%o0], %g0, %o1			! try to acquire as adaptive
	brnz,pn	%o1, 1f				! locked or wrong type
	membar	#LoadLoad
.mutex_enter_lockstat_patch_point:
	retl
	nop
1:
	sethi	%hi(mutex_vector_enter), %o2	! load up for jump to C
	jmp	%o2 + %lo(mutex_vector_enter)
	nop
	SET_SIZE(mutex_enter)

	ENTRY(mutex_tryenter)
	mov	THREAD_REG, %o1
	casx	[%o0], %g0, %o1			! try to acquire as adaptive
	brnz,pn	%o1, 1f				! locked or wrong type continue
	membar	#LoadLoad
.mutex_tryenter_lockstat_patch_point:
	retl
	or	%o0, 1, %o0			! ensure lo32 != 0
1:
	sethi	%hi(mutex_vector_tryenter), %o2		! hi bits
	jmp	%o2 + %lo(mutex_vector_tryenter)	! go to C
	nop
	SET_SIZE(mutex_tryenter)

	ENTRY(mutex_adaptive_tryenter)
	mov	THREAD_REG, %o1
	casx	[%o0], %g0, %o1			! try to acquire as adaptive
	brnz,pn	%o1, 0f				! locked or wrong type
	membar	#LoadLoad
	retl
	or	%o0, 1, %o0			! ensure lo32 != 0
0:
	retl
	mov	%g0, %o0
	SET_SIZE(mutex_adaptive_tryenter)

	! these need to be together and cache aligned for performance.
	.align 64
	.global	mutex_exit_critical_size
	.global	mutex_exit_critical_start
	.global mutex_owner_running_critical_size
	.global mutex_owner_running_critical_start

mutex_exit_critical_size = .mutex_exit_critical_end - mutex_exit_critical_start

	.align	32

	ENTRY(mutex_exit)
mutex_exit_critical_start:		! If we are interrupted, restart here
	ldn	[%o0], %o1		! get the owner field
	membar	#LoadStore|#StoreStore
	cmp	THREAD_REG, %o1		! do we own lock with no waiters?
	be,a,pt	%ncc, 1f		! if so, drive on ...
	stn	%g0, [%o0]		! delay: clear lock if we owned it
.mutex_exit_critical_end:		! for pil_interrupt() hook
	ba,a,pt	%xcc, mutex_vector_exit	! go to C for the hard cases
1:
.mutex_exit_lockstat_patch_point:
	retl
	nop
	SET_SIZE(mutex_exit)

mutex_owner_running_critical_size = .mutex_owner_running_critical_end - mutex_owner_running_critical_start

	.align  32

	ENTRY(mutex_owner_running)
mutex_owner_running_critical_start:	! If interrupted restart here
	ldn	[%o0], %o1		! get the owner field
	and	%o1, MUTEX_THREAD, %o1	! remove the waiters bit if any
	brz,pn	%o1, 1f			! if so, drive on ...
	nop
	ldn	[%o1+T_CPU], %o2	! get owner->t_cpu
	ldn	[%o2+CPU_THREAD], %o3	! get owner->t_cpu->cpu_thread
.mutex_owner_running_critical_end:	! for pil_interrupt() hook
	cmp	%o1, %o3		! owner == running thread?
	be,a,pt	%xcc, 2f		! yes, go return cpu
	nop
1:
	retl
	mov	%g0, %o0		! return 0 (owner not running)
2:
	retl
	mov	%o2, %o0		! owner running, return cpu
	SET_SIZE(mutex_owner_running)

/*
 * rw_enter() and rw_exit().
 *
 * These routines handle the simple cases of rw_enter (write-locking an unheld
 * lock or read-locking a lock that's neither write-locked nor write-wanted)
 * and rw_exit (no waiters or not the last reader).  If anything complicated
 * is going on we punt to rw_enter_sleep() and rw_exit_wakeup(), respectively.
 */

	.align	16
	ENTRY(rw_enter)
	cmp	%o1, RW_WRITER			! entering as writer?
	be,a,pn	%icc, 2f			! if so, go do it ...
	or	THREAD_REG, RW_WRITE_LOCKED, %o5 ! delay: %o5 = owner
	ldn	[%o0], %o4			! %o4 = old lock value
1:
	andcc	%o4, RW_WRITE_CLAIMED, %g0	! write-locked or write-wanted?
	bz,pt	%xcc, 3f			! if so, prepare to block
	add	%o4, RW_READ_LOCK, %o5		! delay: increment hold count
	sethi	%hi(rw_enter_sleep), %o2	! load up jump
	jmp	%o2 + %lo(rw_enter_sleep)	! jmp to rw_enter_sleep
	nop					! delay: do nothing
3:
	casx	[%o0], %o4, %o5			! try to grab read lock
	cmp	%o4, %o5			! did we get it?
#ifdef sun4v
	be,a,pt %xcc, 0f
	membar  #LoadLoad
	sethi	%hi(rw_enter_sleep), %o2	! load up jump
	jmp	%o2 + %lo(rw_enter_sleep)	! jmp to rw_enter_sleep
	nop					! delay: do nothing
0:
#else /* sun4v */
	bne,pn	%xcc, 1b			! if not, try again
	mov	%o5, %o4			! delay: %o4 = old lock value
	membar	#LoadLoad
#endif /* sun4v */
.rw_read_enter_lockstat_patch_point:
	retl
	nop
2:
	casx	[%o0], %g0, %o5			! try to grab write lock
	brz,pt %o5, 4f				! branch around if we got it
	membar	#LoadLoad			! done regardless of where we go
	sethi	%hi(rw_enter_sleep), %o2
	jmp	%o2 + %lo(rw_enter_sleep)	! jump to rw_enter_sleep if not
	nop					! delay: do nothing
4:
.rw_write_enter_lockstat_patch_point:
	retl
	nop
	SET_SIZE(rw_enter)

	.align	16
	ENTRY(rw_exit)
	ldn	[%o0], %o4			! %o4 = old lock value
	membar	#LoadStore|#StoreStore		! membar_exit()
	subcc	%o4, RW_READ_LOCK, %o5		! %o5 = new lock value if reader
	bnz,pn	%xcc, 2f			! single reader, no waiters?
	clr	%o1
1:
	srl	%o4, RW_HOLD_COUNT_SHIFT, %o3	! %o3 = hold count (lockstat)
	casx	[%o0], %o4, %o5			! try to drop lock
	cmp	%o4, %o5			! did we succeed?
	bne,pn	%xcc, rw_exit_wakeup		! if not, go to C
	nop					! delay: do nothing
.rw_read_exit_lockstat_patch_point:
	retl
	nop					! delay: do nothing
2:
	andcc	%o4, RW_WRITE_LOCKED, %g0	! are we a writer?
	bnz,a,pt %xcc, 3f
	or	THREAD_REG, RW_WRITE_LOCKED, %o4 ! delay: %o4 = owner
	cmp	%o5, RW_READ_LOCK		! would lock still be held?
	bge,pt	%xcc, 1b			! if so, go ahead and drop it
	nop
	ba,pt	%xcc, rw_exit_wakeup		! otherwise, wake waiters
	nop
3:
	casx	[%o0], %o4, %o1			! try to drop write lock
	cmp	%o4, %o1			! did we succeed?
	bne,pn	%xcc, rw_exit_wakeup		! if not, go to C
	nop
.rw_write_exit_lockstat_patch_point:
	retl
	nop
	SET_SIZE(rw_exit)

#define	RETL			0x81c3e008
#define	NOP			0x01000000
#define BA			0x10800000

#define	DISP22			((1 << 22) - 1)
#define	ANNUL			0x20000000

#define	HOT_PATCH_COMMON(addr, event, normal_instr, annul, rs)		\
	ba	1f;							\
	rd	%pc, %o0;						\
	save	%sp, -SA(MINFRAME), %sp;				\
	set	lockstat_probemap, %l1;					\
	ld	[%l1 + (event * DTRACE_IDSIZE)], %o0;			\
	brz,pn	%o0, 0f;						\
	ldub	[THREAD_REG + T_LOCKSTAT], %l0;				\
	add	%l0, 1, %l2;						\
	stub	%l2, [THREAD_REG + T_LOCKSTAT];				\
	set	lockstat_probe, %g1;					\
	ld	[%l1 + (event * DTRACE_IDSIZE)], %o0;			\
	brz,a,pn %o0, 0f;						\
	stub	%l0, [THREAD_REG + T_LOCKSTAT];				\
	ldn	[%g1], %g2;						\
	mov	rs, %o2;						\
	jmpl	%g2, %o7;						\
	mov	%i0, %o1;						\
	stub	%l0, [THREAD_REG + T_LOCKSTAT];				\
0:	ret;								\
	restore	%g0, 1, %o0;	/* for mutex_tryenter / lock_try */	\
1:	set	addr, %o1;						\
	sub	%o0, %o1, %o0;						\
	srl	%o0, 2, %o0;						\
	inc	%o0;							\
	set	DISP22, %o1;						\
	and	%o1, %o0, %o0;						\
	set	BA, %o1;						\
	or	%o1, %o0, %o0;						\
	sethi	%hi(annul), %o2;					\
	add	%o0, %o2, %o2;						\
	set	addr, %o0;						\
	set	normal_instr, %o1;					\
	ld	[%i0 + (event * DTRACE_IDSIZE)], %o3;			\
	tst	%o3;							\
	movnz	%icc, %o2, %o1;						\
	call	hot_patch_kernel_text;					\
	mov	4, %o2;							\
	membar	#Sync

#define	HOT_PATCH(addr, event, normal_instr)	\
	HOT_PATCH_COMMON(addr, event, normal_instr, 0, %i1)

#define	HOT_PATCH_ARG(addr, event, normal_instr, arg)	\
	HOT_PATCH_COMMON(addr, event, normal_instr, 0, arg)

#define HOT_PATCH_ANNULLED(addr, event, normal_instr)	\
	HOT_PATCH_COMMON(addr, event, normal_instr, ANNUL, %i1)

	ENTRY(lockstat_hot_patch)
	save	%sp, -SA(MINFRAME), %sp
	set	lockstat_probemap, %i0
	HOT_PATCH(.mutex_enter_lockstat_patch_point,
		LS_MUTEX_ENTER_ACQUIRE, RETL)
	HOT_PATCH_ANNULLED(.mutex_tryenter_lockstat_patch_point,
		LS_MUTEX_TRYENTER_ACQUIRE, RETL)
	HOT_PATCH(.mutex_exit_lockstat_patch_point,
		LS_MUTEX_EXIT_RELEASE, RETL)
	HOT_PATCH(.rw_write_enter_lockstat_patch_point,
		LS_RW_ENTER_ACQUIRE, RETL)
	HOT_PATCH(.rw_read_enter_lockstat_patch_point,
		LS_RW_ENTER_ACQUIRE, RETL)
	HOT_PATCH_ARG(.rw_write_exit_lockstat_patch_point,
		LS_RW_EXIT_RELEASE, RETL, RW_WRITER)
	HOT_PATCH_ARG(.rw_read_exit_lockstat_patch_point,
		LS_RW_EXIT_RELEASE, RETL, RW_READER)
	HOT_PATCH(.lock_set_lockstat_patch_point,
		LS_LOCK_SET_ACQUIRE, RETL)
	HOT_PATCH_ANNULLED(.lock_try_lockstat_patch_point,
		LS_LOCK_TRY_ACQUIRE, RETL)
	HOT_PATCH(.lock_clear_lockstat_patch_point,
		LS_LOCK_CLEAR_RELEASE, RETL)
	HOT_PATCH(.lock_set_spl_lockstat_patch_point,
		LS_LOCK_SET_SPL_ACQUIRE, RETL)
	HOT_PATCH(.lock_clear_splx_lockstat_patch_point,
		LS_LOCK_CLEAR_SPLX_RELEASE, RETL)
	ret
	restore
	SET_SIZE(lockstat_hot_patch)

/*
 * asm_mutex_spin_enter(mutex_t *)
 *
 * For use by assembly interrupt handler only.
 * Does not change spl, since the interrupt handler is assumed to be
 * running at high level already.
 * Traps may be off, so cannot panic.
 * Does not keep statistics on the lock.
 *
 * Entry:	%l6 - points to mutex
 *		%l7 - address of call (returns to %l7+8)
 * Uses:	%l6, %l5
 */
	.align 16
	ENTRY_NP(asm_mutex_spin_enter)
	ldstub	[%l6 + M_SPINLOCK], %l5	! try to set lock, get value in %l5
1:
	tst	%l5
	bnz	3f			! lock already held - go spin
	nop
2:
	jmp	%l7 + 8			! return
	membar	#LoadLoad
	!
	! Spin on lock without using an atomic operation to prevent the caches
	! from unnecessarily moving ownership of the line around.
	!
3:
	ldub	[%l6 + M_SPINLOCK], %l5
4:
	tst	%l5
	bz,a	1b			! lock appears to be free, try again
	ldstub	[%l6 + M_SPINLOCK], %l5	! delay slot - try to set lock

	sethi	%hi(panicstr) , %l5
	ldn	[%l5 + %lo(panicstr)], %l5
	tst	%l5
	bnz	2b			! after panic, feign success
	nop
	b	4b
	ldub	[%l6 + M_SPINLOCK], %l5	! delay - reload lock
	SET_SIZE(asm_mutex_spin_enter)

/*
 * asm_mutex_spin_exit(mutex_t *)
 *
 * For use by assembly interrupt handler only.
 * Does not change spl, since the interrupt handler is assumed to be
 * running at high level already.
 *
 * Entry:	%l6 - points to mutex
 *		%l7 - address of call (returns to %l7+8)
 * Uses:	none
 */
	ENTRY_NP(asm_mutex_spin_exit)
	membar	#LoadStore|#StoreStore
	jmp	%l7 + 8			! return
	clrb	[%l6 + M_SPINLOCK]	! delay - clear lock
	SET_SIZE(asm_mutex_spin_exit)

/*
 * thread_onproc()
 * Set thread in onproc state for the specified CPU.
 * Also set the thread lock pointer to the CPU's onproc lock.
 * Since the new lock isn't held, the store ordering is important.
 * If not done in assembler, the compiler could reorder the stores.
 */

	ENTRY(thread_onproc)
	set	TS_ONPROC, %o2		! TS_ONPROC state
	st	%o2, [%o0 + T_STATE]	! store state
	add	%o1, CPU_THREAD_LOCK, %o3 ! pointer to disp_lock while running
	retl				! return
	stn	%o3, [%o0 + T_LOCKP]	! delay - store new lock pointer
	SET_SIZE(thread_onproc)

/* delay function used in some mutex code - just do 3 nop cas ops */
	ENTRY(cas_delay)
	casx [%o0], %g0, %g0
	casx [%o0], %g0, %g0
	retl
	casx [%o0], %g0, %g0
	SET_SIZE(cas_delay)

/*
 * alternative delay function for some niagara processors.   The rd
 * instruction uses less resources than casx on those cpus.
 */
	ENTRY(rdccr_delay)
	rd	%ccr, %g0
	rd	%ccr, %g0
	retl
	rd	%ccr, %g0
	SET_SIZE(rdccr_delay)

/*
 * mutex_delay_default(void)
 * Spins for approx a few hundred processor cycles and returns to caller.
 */

	ENTRY(mutex_delay_default)
	mov	72,%o0
1:	brgz	%o0, 1b
	dec	%o0
	retl
	nop
	SET_SIZE(mutex_delay_default)

