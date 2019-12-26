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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/class.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/waitq.h>
#include <sys/cmn_err.h>
#include <sys/time.h>
#include <sys/dtrace.h>
#include <sys/sdt.h>
#include <sys/zone.h>

/*
 * Wait queue implementation.
 */

void
waitq_init(waitq_t *wq)
{
	DISP_LOCK_INIT(&wq->wq_lock);
	wq->wq_first = NULL;
	wq->wq_count = 0;
	wq->wq_blocked = B_TRUE;
}

void
waitq_fini(waitq_t *wq)
{
	ASSERT(wq->wq_count == 0);
	ASSERT(wq->wq_first == NULL);
	ASSERT(wq->wq_blocked == B_TRUE);
	ASSERT(!DISP_LOCK_HELD(&wq->wq_lock));

	DISP_LOCK_DESTROY(&wq->wq_lock);
}

/*
 * Operations on waitq_t structures.
 *
 * A wait queue is a singly linked NULL-terminated list with doubly
 * linked circular sublists.  The singly linked list is in descending
 * priority order and FIFO for threads of the same priority.  It links
 * through the t_link field of the thread structure.  The doubly linked
 * sublists link threads of the same priority.  They use the t_priforw
 * and t_priback fields of the thread structure.
 *
 * Graphically (with priorities in parens):
 *
 *         ________________           _______                   _______
 *        /                \         /       \                 /       \
 *        |                |         |       |                 |       |
 *        v                v         v       v                 v       v
 *     t1(60)-->t2(60)-->t3(60)-->t4(50)-->t5(50)-->t6(30)-->t7(0)-->t8(0)
 *        ^      ^  ^      ^         ^       ^       ^  ^      ^       ^
 *        |      |  |      |         |       |       |  |      |       |
 *        \______/  \______/         \_______/       \__/      \_______/
 *
 * There are three interesting operations on a waitq list: inserting
 * a thread into the proper position according to priority; removing a
 * thread given a pointer to it; and walking the list, possibly
 * removing threads along the way.  This design allows all three
 * operations to be performed efficiently and easily.
 *
 * To insert a thread, traverse the list looking for the sublist of
 * the same priority as the thread (or one of a lower priority,
 * meaning there are no other threads in the list of the same
 * priority).  This can be done without touching all threads in the
 * list by following the links between the first threads in each
 * sublist.  Given a thread t that is the head of a sublist (the first
 * thread of that priority found when following the t_link pointers),
 * t->t_priback->t_link points to the head of the next sublist.  It's
 * important to do this since a waitq may contain thousands of
 * threads.
 *
 * Removing a thread from the list is also efficient.  First, the
 * t_waitq field contains a pointer to the waitq on which a thread
 * is waiting (or NULL if it's not on a waitq).  This is used to
 * determine if the given thread is on the given waitq without
 * searching the list.  Assuming it is, if it's not the head of a
 * sublist, just remove it from the sublist and use the t_priback
 * pointer to find the thread that points to it with t_link.  If it is
 * the head of a sublist, search for it by walking the sublist heads,
 * similar to searching for a given priority level when inserting a
 * thread.
 *
 * To walk the list, simply follow the t_link pointers.  Removing
 * threads along the way can be done easily if the code maintains a
 * pointer to the t_link field that pointed to the thread being
 * removed.
 */

static void
waitq_link(waitq_t *wq, kthread_t *t)
{
	kthread_t *next_tp;
	kthread_t *last_tp = NULL;
	kthread_t **tpp;
	pri_t tpri, next_pri, last_pri = -1;

	ASSERT(DISP_LOCK_HELD(&wq->wq_lock));

	tpri = DISP_PRIO(t);
	tpp = &wq->wq_first;
	while ((next_tp = *tpp) != NULL) {
		next_pri = DISP_PRIO(next_tp);
		if (tpri > next_pri)
			break;
		last_tp = next_tp->t_priback;
		last_pri = next_pri;
		tpp = &last_tp->t_link;
	}
	*tpp = t;
	t->t_link = next_tp;
	if (last_tp != NULL && last_pri == tpri) {
		/* last_tp points to the last thread of this priority */
		t->t_priback = last_tp;
		t->t_priforw = last_tp->t_priforw;
		last_tp->t_priforw->t_priback = t;
		last_tp->t_priforw = t;
	} else {
		t->t_priback = t->t_priforw = t;
	}
	wq->wq_count++;
	t->t_waitq = wq;
}

static void
waitq_unlink(waitq_t *wq, kthread_t *t)
{
	kthread_t *nt;
	kthread_t **ptl;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(DISP_LOCK_HELD(&wq->wq_lock));
	ASSERT(t->t_waitq == wq);

	ptl = &t->t_priback->t_link;
	/*
	 * Is it the head of a priority sublist?  If so, need to walk
	 * the priorities to find the t_link pointer that points to it.
	 */
	if (*ptl != t) {
		/*
		 * Find the right priority level.
		 */
		ptl = &t->t_waitq->wq_first;
		while ((nt = *ptl) != t)
			ptl = &nt->t_priback->t_link;
	}
	/*
	 * Remove thread from the t_link list.
	 */
	*ptl = t->t_link;

	/*
	 * Take it off the priority sublist if there's more than one
	 * thread there.
	 */
	if (t->t_priforw != t) {
		t->t_priback->t_priforw = t->t_priforw;
		t->t_priforw->t_priback = t->t_priback;
	}
	t->t_link = NULL;

	wq->wq_count--;
	t->t_waitq = NULL;
	t->t_priforw = NULL;
	t->t_priback = NULL;
}

/*
 * Put specified thread to specified wait queue without dropping thread's lock.
 * Returns 1 if thread was successfully placed on project's wait queue, or
 * 0 if wait queue is blocked.
 */
int
waitq_enqueue(waitq_t *wq, kthread_t *t)
{
	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t->t_sleepq == NULL);
	ASSERT(t->t_waitq == NULL);
	ASSERT(t->t_link == NULL);

	disp_lock_enter_high(&wq->wq_lock);

	/*
	 * Can't enqueue anything on a blocked wait queue
	 */
	if (wq->wq_blocked) {
		disp_lock_exit_high(&wq->wq_lock);
		return (0);
	}

	/*
	 * Mark the time when thread is placed on wait queue. The microstate
	 * accounting code uses this timestamp to determine wait times.
	 */
	t->t_waitrq = gethrtime_unscaled();

	/*
	 * Mark thread as not swappable.  If necessary, it will get
	 * swapped out when it returns to the userland.
	 */
	t->t_schedflag |= TS_DONT_SWAP;
	DTRACE_SCHED1(cpucaps__sleep, kthread_t *, t);
	waitq_link(wq, t);

	THREAD_WAIT(t, &wq->wq_lock);
	return (1);
}

/*
 * Change thread's priority while on the wait queue.
 * Dequeue and equeue it again so that it gets placed in the right place.
 */
void
waitq_change_pri(kthread_t *t, pri_t new_pri)
{
	waitq_t *wq = t->t_waitq;

	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(ISWAITING(t));
	ASSERT(wq != NULL);

	waitq_unlink(wq, t);
	t->t_pri = new_pri;
	waitq_link(wq, t);
}

static void
waitq_dequeue(waitq_t *wq, kthread_t *t)
{
	ASSERT(THREAD_LOCK_HELD(t));
	ASSERT(t->t_waitq == wq);
	ASSERT(ISWAITING(t));

	waitq_unlink(wq, t);
	DTRACE_SCHED1(cpucaps__wakeup, kthread_t *, t);

	/*
	 * Change thread to transition state and drop the wait queue lock. The
	 * thread will remain locked since its t_lockp points to the
	 * transition_lock.
	 */
	THREAD_TRANSITION(t);
}

/*
 * Return True iff there are any threads on the specified wait queue.
 * The check is done **without holding any locks**.
 */
boolean_t
waitq_isempty(waitq_t *wq)
{
	return (wq->wq_count == 0);
}

/*
 * Take thread off its wait queue and make it runnable.
 * Returns with thread lock held.
 */
void
waitq_setrun(kthread_t *t)
{
	waitq_t *wq = t->t_waitq;

	ASSERT(THREAD_LOCK_HELD(t));

	ASSERT(ISWAITING(t));
	if (wq == NULL)
		panic("waitq_setrun: thread %p is not on waitq", (void *)t);
	waitq_dequeue(wq, t);
	CL_SETRUN(t);
}

/*
 * Take the first thread off the wait queue and return pointer to it.
 */
static kthread_t *
waitq_takeone(waitq_t *wq)
{
	kthread_t *t;

	disp_lock_enter(&wq->wq_lock);
	/*
	 * waitq_dequeue drops wait queue lock but leaves the CPU at high PIL.
	 */
	if ((t = wq->wq_first) != NULL)
		waitq_dequeue(wq, wq->wq_first);
	else
		disp_lock_exit(&wq->wq_lock);
	return (t);
}

/*
 * Take the first thread off the wait queue and make it runnable.
 * Return the pointer to the thread or NULL if waitq is empty
 */
static kthread_t *
waitq_runfirst(waitq_t *wq)
{
	kthread_t *t;

	t = waitq_takeone(wq);
	if (t != NULL) {
		/*
		 * t should have transition lock held.
		 * CL_SETRUN() will replace it with dispq lock and keep it held.
		 * thread_unlock() will drop dispq lock and restore PIL.
		 */
		ASSERT(THREAD_LOCK_HELD(t));
		CL_SETRUN(t);
		thread_unlock(t);
	}
	return (t);
}

/*
 * Take the first thread off the wait queue and make it runnable.
 */
void
waitq_runone(waitq_t *wq)
{
	(void) waitq_runfirst(wq);
}

/*
 * Take all threads off the wait queue and make them runnable.
 */
static void
waitq_runall(waitq_t *wq)
{
	while (waitq_runfirst(wq) != NULL)
		;
}

/*
 * Prevent any new threads from entering wait queue and make all threads
 * currently on the wait queue runnable. After waitq_block() completion, no
 * threads should ever appear on the wait queue untill it is unblocked.
 */
void
waitq_block(waitq_t *wq)
{
	ASSERT(!wq->wq_blocked);
	disp_lock_enter(&wq->wq_lock);
	wq->wq_blocked = B_TRUE;
	disp_lock_exit(&wq->wq_lock);
	waitq_runall(wq);
	ASSERT(waitq_isempty(wq));
}

/*
 * Allow threads to be placed on the wait queue.
 */
void
waitq_unblock(waitq_t *wq)
{
	disp_lock_enter(&wq->wq_lock);

	ASSERT(waitq_isempty(wq));
	ASSERT(wq->wq_blocked);

	wq->wq_blocked = B_FALSE;

	disp_lock_exit(&wq->wq_lock);
}
