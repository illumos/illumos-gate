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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2014, Joyent, Inc.  All rights reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/seg_vn.h>
#include <vm/page.h>
#include <sys/mman.h>
#include <sys/timer.h>
#include <sys/condvar.h>
#include <sys/inttypes.h>
#include <sys/cmn_err.h>
#include <sys/lx_futex.h>
#include <sys/lx_impl.h>

/*
 * Futexes are a Linux-specific implementation of inter-process mutexes.
 * They are designed to use shared memory for simple, uncontested
 * operations, and rely on the kernel to resolve any contention issues.
 *
 * Most of the information in this section comes from the paper "Futexes
 * Are Tricky", by Ulrich Drepper.  This paper is currently available at:
 * http://people.redhat.com/~drepper/futex.pdf.
 *
 * A futex itself a 4-byte integer, which must be 4-byte aligned.  The
 * value of this integer is expected to be modified using user-level atomic
 * operations.  The futex(4) design itself does not impose any semantic
 * constraints on the value stored in the futex; it is up to the
 * application to define its own protocol.
 *
 * When the application decides that kernel intervention is required, it
 * will use the futex(2) system call.  There are 5 different operations
 * that can be performed on a futex, using this system call.  Since this
 * interface has evolved over time, there are several different prototypes
 * available to the user.  Fortunately, there is only a single kernel-level
 * interface:
 *
 * long sys_futex(void *futex1, int cmd, int val1,
 * 	struct timespec	*timeout, void *futex2, int val2)
 *
 * The kernel-level operations that may be performed on a futex are:
 *
 * FUTEX_WAIT
 *
 *	Atomically verify that futex1 contains the value val1.  If it
 *	doesn't, return EWOULDBLOCK.  If it does contain the expected
 *	value, the thread will sleep until somebody performs a FUTEX_WAKE
 *	on the futex.  The caller may also specify a timeout, indicating
 *	the maximum time the thread should sleep.  If the timer expires,
 *	the call returns ETIMEDOUT.  If the thread is awoken with a signal,
 *	the call returns EINTR.  Otherwise, the call returns 0.
 *
 * FUTEX_WAKE
 *
 *	Wake up val1 processes that are waiting on futex1.  The call
 *	returns the number of blocked threads that were woken up.
 *
 * FUTEX_WAKE_OP
 *
 *	The implementation of a conditional variable in terms of futexes
 *	actually uses two futexes:  one to assure sequential access and one to
 *	represent the condition variable.  This implementation gives rise to a
 *	particular performance problem whereby a thread is awoken on the futex
 *	that represents the condition variable only to have to (potentially)
 *	immediately wait on the futex that protects the condition variable.
 *	(Do not confuse the futex that serves to protect the condition variable
 *	with the pthread_mutex_t associated with pthread_cond_t -- which
 *	represents a third futex.)  To (over)solve this problem, FUTEX_WAKE_OP
 *	was invented, which performs an atomic compare-and-exchange on a
 *	second address in a specified fashion (that is, with a specified
 *	operation).  Here are the possible operations (OPARG is defined
 *	to be 12 bit value embedded in the operation):
 *
 *	- FUTEX_OP_SET: Sets the value at the second address to OPARG
 *	- FUTEX_OP_ADD: Adds the value to OPARG
 *	- FUTEX_OP_OR: OR's the value with OPARG
 *	- FUTEX_OP_ANDN: Performs a negated AND of the value with OPARG
 *	- FUTEX_OP_XOR: XOR's the value with OPARG
 *
 *	After this compare-and-exchange on the second address, a FUTEX_WAKE is
 *	performed on the first address and -- if the compare-and-exchange
 *	matches a specified result based on a specified comparison operation --
 *	a FUTEX_WAKE is performed on the second address.  Here are the possible
 *	comparison operations:
 *
 *	- FUTEX_OP_CMP_EQ: If old value is CMPARG, wake
 *	- FUTEX_OP_CMP_NE: If old value is not equal to CMPARG, wake
 *	- FUTEX_OP_CMP_LT: If old value is less than CMPARG, wake
 *	- FUTEX_OP_CMP_LE: If old value is less than or equal to CMPARG, wake
 *	- FUTEX_OP_CMP_GT: If old value is greater than CMPARG, wake
 *	- FUTEX_OP_CMP_GE: If old value is greater than or equal to CMPARG, wake
 *
 *	As a practical matter, the only way that this is used (or, some might
 *	argue, is usable) is by the implementation of pthread_cond_signal(),
 *	which uses FUTEX_WAKE_OP to -- in a single system call -- unlock the
 *	futex that protects the condition variable and wake the futex that
 *	represents the condition variable.  The second wake-up is conditional
 *	because the futex that protects the condition variable (rather than the
 *	one that represents it) may or may not have waiters.  Given that this
 *	is the use case, FUTEX_WAKE_OP is falsely generic: despite allowing for
 *	five different kinds of operations and six different kinds of
 *	comparision operations, in practice only one is used.  (Namely, setting
 *	to 0 and waking if the old value is greater than 1 -- which denotes
 *	that waiters are present and the wakeup should be performed.) Moreover,
 *	because FUTEX_WAKE_OP does not (and cannot) optimize anything in the
 *	case that the pthread_mutex_t associated with the pthread_cond_t is
 *	held at the time of a pthread_cond_signal(), this entire mechanism is
 *	essentially for naught in this case.  As one can imagine (and can
 *	verify on just about any source base that uses pthread_cond_signal()),
 *	it is overwhelmingly the common case that the lock associated with the
 *	pthread_cond_t is held at the time of pthread_cond_signal(), assuring
 *	that the problem that all of this complexity was designed to solve
 *	isn't, in fact, solved because the signalled thread simply wakes up
 *	only to block again on the held mutex.  Cue a slow clap!
 *
 * FUTEX_CMP_REQUEUE
 *
 *	If the value stored in futex1 matches that passed in in val2, wake
 *	up val1 processes that are waiting on futex1.  Otherwise, return
 *	EAGAIN.
 *
 *	If there are more than val1 threads waiting on the futex, remove
 *	the remaining threads from this futex, and requeue them on futex2.
 *	The caller can limit the number of threads being requeued by
 *	encoding an integral numerical value in the position usually used
 *	for the timeout pointer.
 *
 *	The call returns the number of blocked threads that were woken up
 *	or requeued.
 *
 * FUTEX_REQUEUE
 *
 *	 Identical to FUTEX_CMP_REQUEUE except that it does not use val2.
 *	 This command has been declared broken and obsolete, but we still
 *	 need to support it.
 *
 * FUTEX_FD
 *
 *	Return a file descriptor, which can be used to refer to the futex.
 *	This operation was broken by design, and was blessedly removed in
 *	Linux 2.6.26 ("because it was inherently racy"); it should go without
 *	saying that we don't support this operation.
 */

/*
 * This structure is used to track all the threads currently waiting on a
 * futex.  There is one fwaiter_t for each blocked thread.  We store all
 * fwaiter_t's in a hash structure, indexed by the memid_t of the integer
 * containing the futex's value.
 *
 * At the moment, all fwaiter_t's for a single futex are simply dumped into
 * the hash bucket.  If futex contention ever becomes a hot path, we can
 * chain a single futex's waiters together.
 */
typedef struct fwaiter {
	memid_t		fw_memid;	/* memid of the user-space futex */
	kcondvar_t	fw_cv;		/* cond var */
	struct fwaiter	*fw_next;	/* hash queue */
	struct fwaiter	*fw_prev;	/* hash queue */
	volatile int	fw_woken;
} fwaiter_t;

#define	MEMID_COPY(s, d) \
	{ (d)->val[0] = (s)->val[0]; (d)->val[1] = (s)->val[1]; }
#define	MEMID_EQUAL(s, d) \
	((d)->val[0] == (s)->val[0] && (d)->val[1] == (s)->val[1])

/* Borrowed from the page freelist hash code.  */
#define	HASH_SHIFT_SZ	7
#define	HASH_SIZE	(1 << HASH_SHIFT_SZ)
#define	HASH_FUNC(id)						\
	((((uintptr_t)((id)->val[1]) >> PAGESHIFT) +			\
	((uintptr_t)((id)->val[1]) >> (PAGESHIFT + HASH_SHIFT_SZ)) +	\
	((uintptr_t)((id)->val[0]) >> 3) +				\
	((uintptr_t)((id)->val[0]) >> (3 + HASH_SHIFT_SZ)) +		\
	((uintptr_t)((id)->val[0]) >> (3 + 2 * HASH_SHIFT_SZ))) &	\
	(HASH_SIZE - 1))

static fwaiter_t *futex_hash[HASH_SIZE];
static kmutex_t futex_hash_lock[HASH_SIZE];

static void
futex_hashin(fwaiter_t *fwp)
{
	int index;

	index = HASH_FUNC(&fwp->fw_memid);
	ASSERT(MUTEX_HELD(&futex_hash_lock[index]));

	fwp->fw_prev = NULL;
	fwp->fw_next = futex_hash[index];
	if (fwp->fw_next)
		fwp->fw_next->fw_prev = fwp;
	futex_hash[index] = fwp;
}

static void
futex_hashout(fwaiter_t *fwp)
{
	int index;

	index = HASH_FUNC(&fwp->fw_memid);
	ASSERT(MUTEX_HELD(&futex_hash_lock[index]));

	if (fwp->fw_prev)
		fwp->fw_prev->fw_next = fwp->fw_next;
	if (fwp->fw_next)
		fwp->fw_next->fw_prev = fwp->fw_prev;
	if (futex_hash[index] == fwp)
		futex_hash[index] = fwp->fw_next;

	fwp->fw_prev = NULL;
	fwp->fw_next = NULL;
}

/*
 * Go to sleep until somebody does a WAKE operation on this futex, we get a
 * signal, or the timeout expires.
 */
static int
futex_wait(memid_t *memid, caddr_t addr, int val, timespec_t *timeout)
{
	int err, ret;
	int32_t curval;
	fwaiter_t fw;
	int index;

	fw.fw_woken = 0;
	MEMID_COPY(memid, &fw.fw_memid);
	cv_init(&fw.fw_cv, NULL, CV_DEFAULT, NULL);

	index = HASH_FUNC(&fw.fw_memid);
	mutex_enter(&futex_hash_lock[index]);

	if (fuword32(addr, (uint32_t *)&curval)) {
		err = set_errno(EFAULT);
		goto out;
	}
	if (curval != val) {
		err = set_errno(EWOULDBLOCK);
		goto out;
	}

	futex_hashin(&fw);

	err = 0;
	while ((fw.fw_woken == 0) && (err == 0)) {
		ret = cv_waituntil_sig(&fw.fw_cv, &futex_hash_lock[index],
		    timeout, timechanged);
		if (ret < 0)
			err = set_errno(ETIMEDOUT);
		else if (ret == 0)
			err = set_errno(EINTR);
	}

	/*
	 * The futex is normally hashed out in wakeup.  If we timed out or
	 * got a signal, we need to hash it out here instead.
	 */
	if (fw.fw_woken == 0)
		futex_hashout(&fw);

out:
	mutex_exit(&futex_hash_lock[index]);

	return (err);
}

/*
 * Wake up to wake_threads threads that are blocked on the futex at memid.
 */
static int
futex_wake(memid_t *memid, int wake_threads)
{
	fwaiter_t *fwp, *next;
	int index;
	int ret = 0;

	index = HASH_FUNC(memid);

	mutex_enter(&futex_hash_lock[index]);

	for (fwp = futex_hash[index]; fwp && ret < wake_threads; fwp = next) {
		next = fwp->fw_next;
		if (MEMID_EQUAL(&fwp->fw_memid, memid)) {
			futex_hashout(fwp);
			fwp->fw_woken = 1;
			cv_signal(&fwp->fw_cv);
			ret++;
		}
	}

	mutex_exit(&futex_hash_lock[index]);

	return (ret);
}

static int
futex_wake_op_execute(int32_t *addr, int32_t val3)
{
	int32_t op = FUTEX_OP_OP(val3);
	int32_t cmp = FUTEX_OP_CMP(val3);
	int32_t cmparg = FUTEX_OP_CMPARG(val3);
	int32_t oparg, oldval, newval;
	label_t ljb;
	int rval;

	if ((uintptr_t)addr >= KERNELBASE)
		return (set_errno(EFAULT));

	if (on_fault(&ljb))
		return (set_errno(EFAULT));

	oparg = FUTEX_OP_OPARG(val3);

	do {
		oldval = *addr;
		newval = oparg;

		switch (op) {
		case FUTEX_OP_SET:
			break;

		case FUTEX_OP_ADD:
			newval += oparg;
			break;

		case FUTEX_OP_OR:
			newval |= oparg;
			break;

		case FUTEX_OP_ANDN:
			newval &= ~oparg;
			break;

		case FUTEX_OP_XOR:
			newval ^= oparg;
			break;

		default:
			no_fault();
			return (set_errno(EINVAL));
		}
	} while (atomic_cas_32((uint32_t *)addr, oldval, newval) != oldval);

	no_fault();

	switch (cmp) {
	case FUTEX_OP_CMP_EQ:
		rval = (oldval == cmparg);
		break;

	case FUTEX_OP_CMP_NE:
		rval = (oldval != cmparg);
		break;

	case FUTEX_OP_CMP_LT:
		rval = (oldval < cmparg);
		break;

	case FUTEX_OP_CMP_LE:
		rval = (oldval <= cmparg);
		break;

	case FUTEX_OP_CMP_GT:
		rval = (oldval > cmparg);
		break;

	case FUTEX_OP_CMP_GE:
		rval = (oldval >= cmparg);
		break;

	default:
		return (set_errno(EINVAL));
	}

	return (rval);
}

static int
futex_wake_op(memid_t *memid, caddr_t addr2, memid_t *memid2,
    int wake_threads, int wake_threads2, int val3)
{
	kmutex_t *l1, *l2;
	int ret = 0, ret2 = 0, wake;
	fwaiter_t *fwp, *next;
	int index1, index2;

	index1 = HASH_FUNC(memid);
	index2 = HASH_FUNC(memid2);

	if (index1 == index2) {
		l1 = &futex_hash_lock[index1];
		l2 = NULL;
	} else if (index1 < index2) {
		l1 = &futex_hash_lock[index1];
		l2 = &futex_hash_lock[index2];
	} else {
		l1 = &futex_hash_lock[index2];
		l2 = &futex_hash_lock[index1];
	}

	mutex_enter(l1);
	if (l2 != NULL)
		mutex_enter(l2);

	/* LINTED: alignment */
	if ((wake = futex_wake_op_execute((int32_t *)addr2, val3)) < 0)
		goto out;

	for (fwp = futex_hash[index1]; fwp; fwp = next) {
		next = fwp->fw_next;
		if (!MEMID_EQUAL(&fwp->fw_memid, memid))
			continue;

		futex_hashout(fwp);
		fwp->fw_woken = 1;
		cv_signal(&fwp->fw_cv);
		if (++ret >= wake_threads) {
			break;
		}
	}

	if (!wake)
		goto out;

	for (fwp = futex_hash[index2]; fwp; fwp = next) {
		next = fwp->fw_next;
		if (!MEMID_EQUAL(&fwp->fw_memid, memid2))
			continue;

		futex_hashout(fwp);
		fwp->fw_woken = 1;
		cv_signal(&fwp->fw_cv);
		if (++ret2 >= wake_threads2) {
			break;
		}
	}

	ret += ret2;
out:
	if (l2 != NULL)
		mutex_exit(l2);
	mutex_exit(l1);

	return (ret);
}

/*
 * Wake up to wake_threads waiting on the futex at memid.  If there are
 * more than that many threads waiting, requeue the remaining threads on
 * the futex at requeue_memid.
 */
static int
futex_requeue(memid_t *memid, memid_t *requeue_memid, int wake_threads,
	ulong_t requeue_threads, caddr_t addr, int *cmpval)
{
	fwaiter_t *fwp, *next;
	int index1, index2;
	int ret = 0;
	int32_t curval;
	kmutex_t *l1, *l2;

	/*
	 * To ensure that we don't miss a wakeup if the value of cmpval
	 * changes, we need to grab locks on both the original and new hash
	 * buckets.  To avoid deadlock, we always grab the lower-indexed
	 * lock first.
	 */
	index1 = HASH_FUNC(memid);
	index2 = HASH_FUNC(requeue_memid);

	if (index1 == index2) {
		l1 = &futex_hash_lock[index1];
		l2 = NULL;
	} else if (index1 < index2) {
		l1 = &futex_hash_lock[index1];
		l2 = &futex_hash_lock[index2];
	} else {
		l1 = &futex_hash_lock[index2];
		l2 = &futex_hash_lock[index1];
	}

	mutex_enter(l1);
	if (l2 != NULL)
		mutex_enter(l2);

	if (cmpval != NULL) {
		if (fuword32(addr, (uint32_t *)&curval)) {
			ret = -EFAULT;
			goto out;
		}
		if (curval != *cmpval) {
			ret = -EAGAIN;
			goto out;
		}
	}

	for (fwp = futex_hash[index1]; fwp; fwp = next) {
		next = fwp->fw_next;
		if (!MEMID_EQUAL(&fwp->fw_memid, memid))
			continue;

		futex_hashout(fwp);
		if (ret++ < wake_threads) {
			fwp->fw_woken = 1;
			cv_signal(&fwp->fw_cv);
		} else {
			MEMID_COPY(requeue_memid, &fwp->fw_memid);
			futex_hashin(fwp);

			if ((ret - wake_threads) >= requeue_threads)
				break;
		}
	}

out:
	if (l2 != NULL)
		mutex_exit(l2);
	mutex_exit(l1);

	if (ret < 0)
		return (set_errno(-ret));
	return (ret);
}

/*
 * Copy in the relative timeout provided by the application and convert it
 * to an absolute timeout.
 */
static int
get_timeout(void *lx_timeout, timestruc_t *timeout)
{
	timestruc_t now;

	if (get_udatamodel() == DATAMODEL_NATIVE) {
		if (copyin(lx_timeout, timeout, sizeof (timestruc_t)))
			return (EFAULT);
	}
#ifdef _SYSCALL32_IMPL
	else {
		timestruc32_t timeout32;
		if (copyin(lx_timeout, &timeout32, sizeof (timestruc32_t)))
			return (EFAULT);
		timeout->tv_sec = (time_t)timeout32.tv_sec;
		timeout->tv_nsec = timeout32.tv_nsec;
	}
#endif
	gethrestime(&now);

	if (itimerspecfix(timeout))
		return (EINVAL);

	timespecadd(timeout, &now);
	return (0);
}

long
lx_futex(uintptr_t addr, int op, int val, uintptr_t lx_timeout,
	uintptr_t addr2, int val3)
{
	struct as *as = curproc->p_as;
	memid_t memid, memid2;
	timestruc_t timeout;
	timestruc_t *tptr = NULL;
	int val2 = NULL;
	int rval = 0;
	int cmd = op & FUTEX_CMD_MASK;
	int private = op & FUTEX_PRIVATE_FLAG;
	char dmsg[32];

	/* must be aligned on int boundary */
	if (addr & 0x3)
		return (set_errno(EINVAL));

	/* Sanity check the futex command */
	if (cmd < 0 || cmd > FUTEX_MAX_CMD)
		return (set_errno(EINVAL));

	if (cmd == FUTEX_FD) {
		/*
		 * FUTEX_FD was sentenced to death for grievous crimes of
		 * semantics against humanity; it has been ripped out of Linux
		 * and will never be supported by us.
		 */
		(void) snprintf(dmsg, sizeof (dmsg), "futex 0x%x", cmd);
		lx_unsupported(dmsg);
		return (set_errno(ENOSYS));
	}

	switch (cmd) {
	case FUTEX_LOCK_PI:
	case FUTEX_UNLOCK_PI:
	case FUTEX_TRYLOCK_PI:
	case FUTEX_WAIT_BITSET:
	case FUTEX_WAKE_BITSET:
	case FUTEX_WAIT_REQUEUE_PI:
	case FUTEX_CMP_REQUEUE_PI:
		/*
		 * These are operations that we don't currently support, but
		 * may well need to in the future.  For now, callers need to
		 * deal with these being missing -- but if and as that changes,
		 * they may well need to be implemented.
		 */
		(void) snprintf(dmsg, sizeof (dmsg), "futex 0x%x", cmd);
		lx_unsupported(dmsg);
		return (set_errno(ENOSYS));
	}

	/* Copy in the timeout structure from userspace. */
	if (cmd == FUTEX_WAIT && lx_timeout != NULL) {
		rval = get_timeout((timespec_t *)lx_timeout, &timeout);
		if (rval != 0)
			return (set_errno(rval));
		tptr = &timeout;
	}

	switch (cmd) {
	case FUTEX_REQUEUE:
	case FUTEX_CMP_REQUEUE:
	case FUTEX_WAKE_OP:
		/*
		 * lx_timeout is nominally a pointer to a userspace address.
		 * For several commands, however, it actually contains
		 * an additional interage parameter.  This is horrible, and
		 * the people who did this to us should be sorry.
		 */
		val2 = (int)lx_timeout;
	}

	/*
	 * Translate the process-specific, user-space futex virtual
	 * address(es) to a universal memid.  If the private bit is set, we
	 * can just use our as plus the virtual address, saving quite a bit
	 * of effort.
	 */
	if (private) {
		memid.val[0] = (uintptr_t)as;
		memid.val[1] = (uintptr_t)addr;
	} else {
		rval = as_getmemid(as, (void *)addr, &memid);
		if (rval != 0)
			return (set_errno(rval));
	}

	if (cmd == FUTEX_REQUEUE || cmd == FUTEX_CMP_REQUEUE ||
	    cmd == FUTEX_WAKE_OP) {
		if (addr2 & 0x3)
			return (set_errno(EINVAL));

		if (private) {
			memid2.val[0] = (uintptr_t)as;
			memid2.val[1] = (uintptr_t)addr2;
		} else {
			rval = as_getmemid(as, (void *)addr2, &memid2);
			if (rval)
				return (set_errno(rval));
		}
	}

	switch (cmd) {
	case FUTEX_WAIT:
		rval = futex_wait(&memid, (void *)addr, val, tptr);
		break;

	case FUTEX_WAKE:
		rval = futex_wake(&memid, val);
		break;

	case FUTEX_WAKE_OP:
		rval = futex_wake_op(&memid, (void *)addr2, &memid2,
		    val, val2, val3);
		break;

	case FUTEX_CMP_REQUEUE:
	case FUTEX_REQUEUE:
		rval = futex_requeue(&memid, &memid2, val,
		    val2, (void *)addr2, &val3);

		break;
	}

	return (rval);
}

void
lx_futex_init(void)
{
	int i;

	for (i = 0; i < HASH_SIZE; i++)
		mutex_init(&futex_hash_lock[i], NULL, MUTEX_DEFAULT, NULL);
	bzero(futex_hash, sizeof (futex_hash));
}

int
lx_futex_fini(void)
{
	int i, err;

	err = 0;
	for (i = 0; (err == 0) && (i < HASH_SIZE); i++) {
		mutex_enter(&futex_hash_lock[i]);
		if (futex_hash[i] != NULL)
			err = EBUSY;
		mutex_exit(&futex_hash_lock[i]);
	}
	return (err);
}
