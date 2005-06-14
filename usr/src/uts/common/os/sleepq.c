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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/debug.h>
#include <sys/cpuvar.h>
#include <sys/sleepq.h>
#include <sys/sdt.h>

/*
 * Operations on sleepq_t structures.
 *
 * A sleep queue is a singly linked NULL-terminated list with doubly
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
 * There are three interesting operations on a sleepq list: inserting
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
 * important to do this since a sleepq may contain thousands of
 * threads.
 *
 * Removing a thread from the list is also efficient.  First, the
 * t_sleepq field contains a pointer to the sleepq on which a thread
 * is waiting (or NULL if it's not on a sleepq).  This is used to
 * determine if the given thread is on the given sleepq without
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

sleepq_head_t sleepq_head[NSLEEPQ];

/*
 * Common code to unlink a thread from the queue.  tpp is a pointer to
 * the t_link pointer that points to tp.
 */
void
sleepq_unlink(kthread_t **tpp, kthread_t *tp)
{
	ASSERT(*tpp == tp);
	ASSERT(tp->t_sleepq != NULL);

	/* remove it from the t_link list */
	*tpp = tp->t_link;

	/*
	 * Take it off the priority sublist if there's more than one
	 * thread there.
	 */
	if (tp->t_priforw != tp) {
		tp->t_priback->t_priforw = tp->t_priforw;
		tp->t_priforw->t_priback = tp->t_priback;
	}

	/* Clear out the link junk */
	tp->t_link = NULL;
	tp->t_sleepq = NULL;
	tp->t_priforw = NULL;
	tp->t_priback = NULL;
}

/*
 * Insert thread t into sleep queue spq in dispatch priority order.
 * For lwp_rwlock_t queueing, we must queue writers ahead of readers
 * of the same priority.  We do this by making writers appear to have
 * a half point higher priority for purposes of priority comparisions.
 */
#define	CMP_PRIO(t)	((DISP_PRIO(t) << 1) + (t)->t_writer)
void
sleepq_insert(sleepq_t *spq, kthread_t *t)
{
	kthread_t	*next_tp;
	kthread_t	*last_tp;
	kthread_t	**tpp;
	pri_t		tpri, next_pri, last_pri = -1;

	ASSERT(THREAD_LOCK_HELD(t));	/* holding the lock on the sleepq */
	ASSERT(t->t_sleepq == NULL);	/* not already on a sleep queue */

	tpri = CMP_PRIO(t);
	tpp = &spq->sq_first;
	while ((next_tp = *tpp) != NULL) {
		next_pri = CMP_PRIO(next_tp);
		if (tpri > next_pri)
			break;
		last_tp = next_tp->t_priback;
		last_pri = next_pri;
		tpp = &last_tp->t_link;
	}
	*tpp = t;
	t->t_link = next_tp;
	if (last_pri == tpri) {
		/* last_tp points to the last thread of this priority */
		t->t_priback = last_tp;
		t->t_priforw = last_tp->t_priforw;
		last_tp->t_priforw->t_priback = t;
		last_tp->t_priforw = t;
	} else {
		t->t_priback = t->t_priforw = t;
	}
	t->t_sleepq = spq;
}


/*
 * Yank a particular thread out of sleep queue and wake it up.
 */
void
sleepq_unsleep(kthread_t *t)
{
	ASSERT(THREAD_LOCK_HELD(t));	/* thread locked via sleepq */

	/* remove it from queue */
	sleepq_dequeue(t);

	/* wake it up */
	t->t_sobj_ops = NULL;
	t->t_wchan = NULL;
	t->t_wchan0 = NULL;
	ASSERT(t->t_state == TS_SLEEP);
	/*
	 * Change thread to transition state without
	 * dropping the sleep queue lock.
	 */
	THREAD_TRANSITION_NOLOCK(t);
}

/*
 * Yank a particular thread out of sleep queue but don't wake it up.
 */
void
sleepq_dequeue(kthread_t *t)
{
	kthread_t	*nt;
	kthread_t	**ptl;

	ASSERT(THREAD_LOCK_HELD(t));	/* thread locked via sleepq */
	ASSERT(t->t_sleepq != NULL);

	ptl = &t->t_priback->t_link;
	/*
	 * Is it the head of a priority sublist?  If so, need to walk
	 * the priorities to find the t_link pointer that points to it.
	 */
	if (*ptl != t) {
		/*
		 * Find the right priority level.
		 */
		ptl = &t->t_sleepq->sq_first;
		while ((nt = *ptl) != t)
			ptl = &nt->t_priback->t_link;
	}
	sleepq_unlink(ptl, t);
}

kthread_t *
sleepq_wakeone_chan(sleepq_t *spq, void *chan)
{
	kthread_t 	*tp;
	kthread_t	**tpp;

	tpp = &spq->sq_first;
	while ((tp = *tpp) != NULL) {
		if (tp->t_wchan == chan) {
			ASSERT(tp->t_wchan0 == NULL);
			sleepq_unlink(tpp, tp);
			DTRACE_SCHED1(wakeup, kthread_t *, tp);
			tp->t_wchan = NULL;
			tp->t_sobj_ops = NULL;
			/*
			 * Let the target thread know it was cv_signal()ed.
			 * This assumes that cv_signal() is the only
			 * caller of sleepq_wakeone_chan().  If this
			 * becomes false, this code must be revised.
			 */
			tp->t_schedflag |= TS_SIGNALLED;
			ASSERT(tp->t_state == TS_SLEEP);
			CL_WAKEUP(tp);
			thread_unlock_high(tp);		/* drop runq lock */
			return (tp);
		}
		tpp = &tp->t_link;
	}
	return (NULL);
}

void
sleepq_wakeall_chan(sleepq_t *spq, void *chan)
{
	kthread_t 	*tp;
	kthread_t	**tpp;

	tpp = &spq->sq_first;
	while ((tp = *tpp) != NULL) {
		if (tp->t_wchan == chan) {
			ASSERT(tp->t_wchan0 == NULL);
			sleepq_unlink(tpp, tp);
			DTRACE_SCHED1(wakeup, kthread_t *, tp);
			tp->t_wchan = NULL;
			tp->t_sobj_ops = NULL;
			ASSERT(tp->t_state == TS_SLEEP);
			CL_WAKEUP(tp);
			thread_unlock_high(tp);		/* drop runq lock */
			continue;
		}
		tpp = &tp->t_link;
	}
}
