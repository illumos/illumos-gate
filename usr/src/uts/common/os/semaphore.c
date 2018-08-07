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
 * Copyright 2018 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * This file contains the semaphore operations.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/schedctl.h>
#include <sys/semaphore.h>
#include <sys/sema_impl.h>
#include <sys/t_lock.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/disp.h>
#include <sys/sobject.h>
#include <sys/cpuvar.h>
#include <sys/sleepq.h>
#include <sys/sdt.h>

static void sema_unsleep(kthread_t *t);
static void sema_change_pri(kthread_t *t, pri_t pri, pri_t *t_prip);
static kthread_t *sema_owner(ksema_t *);

/*
 * The sobj_ops vector exports a set of functions needed when a thread
 * is asleep on a synchronization object of this type.
 */
static sobj_ops_t sema_sobj_ops = {
	SOBJ_SEMA, sema_owner, sema_unsleep, sema_change_pri
};

/*
 * SEMA_BLOCK(sema_impl_t *s, disp_lock_t *lockp)
 */
#define	SEMA_BLOCK(s, lockp)						\
	{								\
		kthread_t	*tp;					\
		kthread_t	**tpp;					\
		pri_t		cpri;					\
		klwp_t	*lwp = ttolwp(curthread);			\
		ASSERT(THREAD_LOCK_HELD(curthread));			\
		ASSERT(curthread != CPU->cpu_idle_thread);		\
		ASSERT(CPU_ON_INTR(CPU) == 0);				\
		ASSERT(curthread->t_wchan0 == NULL);			\
		ASSERT(curthread->t_wchan == NULL);			\
		ASSERT(curthread->t_state == TS_ONPROC);		\
		CL_SLEEP(curthread);					\
		THREAD_SLEEP(curthread, lockp);				\
		curthread->t_wchan = (caddr_t)s;			\
		curthread->t_sobj_ops = &sema_sobj_ops;			\
		DTRACE_SCHED(sleep);					\
		if (lwp != NULL) {					\
			lwp->lwp_ru.nvcsw++;				\
			(void) new_mstate(curthread, LMS_SLEEP);	\
		}							\
		cpri = DISP_PRIO(curthread);				\
		tpp = &s->s_slpq;					\
		while ((tp = *tpp) != NULL) {				\
			if (cpri > DISP_PRIO(tp))			\
				break;					\
			tpp = &tp->t_link;				\
		}							\
		*tpp = curthread;					\
		curthread->t_link = tp;					\
		ASSERT(s->s_slpq != NULL);				\
	}

/* ARGSUSED */
void
sema_init(ksema_t *sp, unsigned count, char *name, ksema_type_t type, void *arg)
{
	((sema_impl_t *)sp)->s_count = count;
	((sema_impl_t *)sp)->s_slpq = NULL;
}

void
sema_destroy(ksema_t *sp)
{
	ASSERT(((sema_impl_t *)sp)->s_slpq == NULL);
}

/*
 * Put a thread on the sleep queue for this semaphore.
 */
static void
sema_queue(ksema_t *sp, kthread_t *t)
{
	kthread_t	**tpp;
	kthread_t	*tp;
	pri_t		cpri;
	sema_impl_t	*s;

	ASSERT(THREAD_LOCK_HELD(t));
	s = (sema_impl_t *)sp;
	tpp = &s->s_slpq;
	cpri = DISP_PRIO(t);
	while ((tp = *tpp) != NULL) {
		if (cpri > DISP_PRIO(tp))
			break;
		tpp = &tp->t_link;
	}
	*tpp = t;
	t->t_link = tp;
}

/*
 * Remove a thread from the sleep queue for this
 * semaphore.
 */
static void
sema_dequeue(ksema_t *sp, kthread_t *t)
{
	kthread_t	**tpp;
	kthread_t	*tp;
	sema_impl_t	*s;

	ASSERT(THREAD_LOCK_HELD(t));
	s = (sema_impl_t *)sp;
	tpp = &s->s_slpq;
	while ((tp = *tpp) != NULL) {
		if (tp == t) {
			*tpp = t->t_link;
			t->t_link = NULL;
			return;
		}
		tpp = &tp->t_link;
	}
}

/* ARGSUSED */
static kthread_t *
sema_owner(ksema_t *sp)
{
	return ((kthread_t *)NULL);
}

/*
 * Wakeup a thread sleeping on a semaphore, and put it
 * on the dispatch queue.
 * Called via SOBJ_UNSLEEP().
 */
static void
sema_unsleep(kthread_t *t)
{
	kthread_t	**tpp;
	kthread_t	*tp;
	sema_impl_t	*s;

	ASSERT(THREAD_LOCK_HELD(t));
	s = (sema_impl_t *)t->t_wchan;
	tpp = &s->s_slpq;
	while ((tp = *tpp) != NULL) {
		if (tp == t) {
			*tpp = t->t_link;
			t->t_link = NULL;
			t->t_sobj_ops = NULL;
			t->t_wchan = NULL;
			t->t_wchan0 = NULL;
			/*
			 * Change thread to transition state and
			 * drop the semaphore sleep queue lock.
			 */
			THREAD_TRANSITION(t);
			CL_SETRUN(t);
			return;
		}
		tpp = &tp->t_link;
	}
}

/*
 * operations to perform when changing the priority
 * of a thread asleep on a semaphore.
 * Called via SOBJ_CHANGE_PRI() and SOBJ_CHANGE_EPRI().
 */
static void
sema_change_pri(kthread_t *t, pri_t pri, pri_t *t_prip)
{
	ksema_t *sp;

	if ((sp = (ksema_t *)t->t_wchan) != NULL) {
		sema_dequeue(sp, t);
		*t_prip = pri;
		sema_queue(sp, t);
	} else
		panic("sema_change_pri: %p not on sleep queue", (void *)t);
}

/*
 * the semaphore is granted when the semaphore's
 * count is greater than zero and blocks when equal
 * to zero.
 */
void
sema_p(ksema_t *sp)
{
	sema_impl_t	*s;
	disp_lock_t	*sqlp;

	/* no-op during panic */
	if (panicstr)
		return;

	s = (sema_impl_t *)sp;
	sqlp = &SQHASH(s)->sq_lock;
	disp_lock_enter(sqlp);
	ASSERT(s->s_count >= 0);
	while (s->s_count == 0) {
		thread_lock_high(curthread);
		SEMA_BLOCK(s, sqlp);
		thread_unlock_nopreempt(curthread);
		swtch();
		disp_lock_enter(sqlp);
	}
	s->s_count--;
	disp_lock_exit(sqlp);
}

/*
 * similiar to sema_p except that it blocks at an interruptible
 * priority. if a signal is present then return 1 otherwise 0.
 */
int
sema_p_sig(ksema_t *sp)
{
	kthread_t	*t = curthread;
	klwp_t		*lwp = ttolwp(t);
	int		cancel_pending;
	int		cancelled = 0;
	sema_impl_t	*s;
	disp_lock_t	*sqlp;

	if (lwp == NULL) {
		sema_p(sp);
		return (0);
	}

	cancel_pending = schedctl_cancel_pending();
	s = (sema_impl_t *)sp;
	sqlp = &SQHASH(s)->sq_lock;
	disp_lock_enter(sqlp);
	ASSERT(s->s_count >= 0);
	while (s->s_count == 0) {
		proc_t *p = ttoproc(t);
		thread_lock_high(t);
		t->t_flag |= T_WAKEABLE;
		SEMA_BLOCK(s, sqlp);
		lwp->lwp_asleep = 1;
		lwp->lwp_sysabort = 0;
		thread_unlock_nopreempt(t);
		if (ISSIG(t, JUSTLOOKING) || MUSTRETURN(p, t) || cancel_pending)
			setrun(t);
		swtch();
		t->t_flag &= ~T_WAKEABLE;
		if (ISSIG(t, FORREAL) || lwp->lwp_sysabort ||
		    MUSTRETURN(p, t) || (cancelled = cancel_pending) != 0) {
			kthread_t *sq, *tp;
			lwp->lwp_asleep = 0;
			lwp->lwp_sysabort = 0;
			disp_lock_enter(sqlp);
			sq = s->s_slpq;
			/*
			 * in case sema_v and interrupt happen
			 * at the same time, we need to pass the
			 * sema_v to the next thread.
			 */
			if ((sq != NULL) && (s->s_count > 0)) {
				tp = sq;
				ASSERT(THREAD_LOCK_HELD(tp));
				sq = sq->t_link;
				tp->t_link = NULL;
				DTRACE_SCHED1(wakeup, kthread_t *, tp);
				tp->t_sobj_ops = NULL;
				tp->t_wchan = NULL;
				ASSERT(tp->t_state == TS_SLEEP);
				CL_WAKEUP(tp);
				s->s_slpq = sq;
				disp_lock_exit_high(sqlp);
				thread_unlock(tp);
			} else {
				disp_lock_exit(sqlp);
			}
			if (cancelled)
				schedctl_cancel_eintr();
			return (1);
		}
		lwp->lwp_asleep = 0;
		disp_lock_enter(sqlp);
	}
	s->s_count--;
	disp_lock_exit(sqlp);
	return (0);
}

/*
 * the semaphore's count is incremented by one. a blocked thread
 * is awakened and re-tries to acquire the semaphore.
 */
void
sema_v(ksema_t *sp)
{
	sema_impl_t	*s;
	kthread_t	*sq, *tp;
	disp_lock_t	*sqlp;

	/* no-op during panic */
	if (panicstr)
		return;

	s = (sema_impl_t *)sp;
	sqlp = &SQHASH(s)->sq_lock;
	disp_lock_enter(sqlp);
	s->s_count++;
	sq = s->s_slpq;
	if (sq != NULL) {
		tp = sq;
		ASSERT(THREAD_LOCK_HELD(tp));
		sq = sq->t_link;
		tp->t_link = NULL;
		DTRACE_SCHED1(wakeup, kthread_t *, tp);
		tp->t_sobj_ops = NULL;
		tp->t_wchan = NULL;
		ASSERT(tp->t_state == TS_SLEEP);
		CL_WAKEUP(tp);
		s->s_slpq = sq;
		disp_lock_exit_high(sqlp);
		thread_unlock(tp);
	} else {
		disp_lock_exit(sqlp);
	}
}

/*
 * try to acquire the semaphore. if the semaphore is greater than
 * zero, then the semaphore is granted and returns 1. otherwise
 * return 0.
 */
int
sema_tryp(ksema_t *sp)
{
	sema_impl_t	*s;
	sleepq_head_t	*sqh;

	int	gotit = 0;

	/* no-op during panic */
	if (panicstr)
		return (1);

	s = (sema_impl_t *)sp;
	sqh = SQHASH(s);
	disp_lock_enter(&sqh->sq_lock);
	if (s->s_count > 0) {
		s->s_count--;
		gotit = 1;
	}
	disp_lock_exit(&sqh->sq_lock);
	return (gotit);
}

int
sema_held(ksema_t *sp)
{
	sema_impl_t	*s;

	/* no-op during panic */
	if (panicstr)
		return (1);

	s = (sema_impl_t *)sp;
	return (s->s_count <= 0);
}
