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

/*
 * Kernel protection serializers: general purpose synchronization mechanism.
 *
 * Serializers provide a simple way to serialize access to some resource. They
 * can be used as an alternative to locks or STREAMS perimeters. They scale
 * much better than STREAMS outer serializers.
 *
 * Serializer is an abstraction that guarantees that all functions executed
 * within the serializer are serialized: they are executed in the order they
 * entered serializer one at a time.
 *
 * INTERFACES:
 *
 * serializer_t *serializer_create(flags);
 *
 *	Create a serializer. The flags may be either SER_SLEEP or SER_NOSLEEP
 *	which are the same as KM_SLEEP and KM_NOSLEEP respectively.
 *
 * serializer_enter(serializer, proc, mblk, arg);
 *
 *	Execute 'proc(mblk, arg)' within the serializer.
 *
 * serializer_wait(serializer);
 *
 *	Wait for pending serializer jobs to complete. This function should never
 *	be called within the serializer or it will deadlock.
 *
 * serializer_destroy(serializer);
 *
 *	Destroy serializer.
 *
 * Serializers export three DTrace SDT probes:
 *
 *	serializer-enqueue(serializer, mblk, arg, proc)
 *
 *		The probe triggers when serializer is busy and the request is
 *		queued.
 *
 *	serializer-exec-start(serializer, mblk, arg, proc)
 *
 *		The probe triggers before the request is executed
 *
 *	serializer-exec-end(serializer, mblk, arg, proc)
 *
 *		The probe triggers after the request is executed
 *
 *
 * IMPLEMENTATION.
 *
 * Serializer consists of a "owner" and a list of queued jobs. The first thread
 * entering serializer sets the owner and executes its job directly without
 * context switch. Then it processes jobs which may have been enqueued while it
 * was executing a job and drops the owner, leaving the serializer empty.  Any
 * thread entering an owned serializer enqueues its job and returns immediately.
 *
 * Serializer data structure holds several fields used for debugging only. They
 * are not relevant for the proper serializer functioning.
 *
 * When new requests arrive faster then they are processed it is possible that a
 * thread that started processing serializer will continue doing so for a long
 * time. To avoid such pathological behavior the amount of requests drained by
 * serializer_enter() is limited by `serializer_credit' value. After the credit
 * is expired serializer_enter() schedules a taskq request to continue draining.
 * The taskq thread draining is not limited by serializer_credit. Note that it
 * is possible that another serializer_enter() will drain the serializer before
 * a taskq thread will get to it.
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/thread.h>
#include <sys/mutex.h>
#include <sys/systm.h>
#include <sys/debug.h>
#include <sys/taskq.h>
#include <sys/sdt.h>
#include <sys/serializer.h>

#define	SERIALIZER_NAMELEN 31

/*
 * Serializer abstraction.
 * Fields marked (D) are used for debugging purposes only.
 */
struct serializer_s {
	kmutex_t	ser_lock;	/* Protects state and the list */
	kthread_t	*ser_owner;	/* Thread executing serializer */
	ushort_t	ser_taskq;	/* Serializer scheduled for taskq */
	kcondvar_t	ser_cv;		/* For serializer-wait */
	uint_t		ser_count;	/* # of queued requests (D) */
	mblk_t		*ser_first;	/* First message in the queue */
	mblk_t		*ser_last;	/* Last message in the queue */
	srproc_t	*ser_proc;	/* Currently executing proc (D) */
	mblk_t		*ser_curr;	/* Currently executing msg (D) */
	void		*ser_arg;	/* Currently executing arg (D) */
};

static kmem_cache_t *serializer_cache;

/*
 * How many drains are allowed before we switch to taskq processing.
 */
#define	SERIALIZER_CREDIT 10
static int serializer_credit = SERIALIZER_CREDIT;

/* Statistics for debugging */
static int perim_context_swtch = 0;

static int serializer_constructor(void *, void *, int);
static void serializer_destructor(void *, void *);
static void serializer_exec(serializer_t *, srproc_t, mblk_t *, void *);
static void serializer_enqueue(serializer_t *, srproc_t, mblk_t *, void *);
static void serializer_drain(serializer_t *, int);
static void serializer_drain_completely(serializer_t *);

/*
 * SERIALIZER Implementation.
 */

/*
 * Record debugging information and execute single request.
 */
static void
serializer_exec(serializer_t *s, srproc_t proc, mblk_t *mp, void *arg)
{
	ASSERT(MUTEX_NOT_HELD(&s->ser_lock));
	ASSERT(s->ser_owner == curthread);

	ASSERT(proc != NULL);
	ASSERT(mp != NULL);

	s->ser_curr = mp;
	s->ser_arg = arg;
	s->ser_proc = proc;
	proc(mp, arg);
}

/*
 * Enqueue a single request on serializer.
 */
static void
serializer_enqueue(serializer_t *s, srproc_t proc, mblk_t *mp, void *arg)
{
	ASSERT(MUTEX_HELD(&s->ser_lock));

	DTRACE_PROBE4(serializer__enqueue, serializer_t *, s,
	    mblk_t *, mp, void *, arg, srproc_t, proc);
	s->ser_count++;
	mp->b_queue = (queue_t *)proc;
	mp->b_prev = (mblk_t *)arg;
	if (s->ser_last != NULL)
		s->ser_last->b_next = mp;
	else
		s->ser_first = mp;
	s->ser_last = mp;
}

/*
 * Drain serializer, limiting drain to `credit' requests at most.
 */
static void
serializer_drain(serializer_t *s, int credit)
{
	mblk_t *mp = s->ser_first;

	ASSERT(MUTEX_HELD(&s->ser_lock));
	ASSERT(s->ser_owner == curthread);

	for (; mp != NULL && credit-- != 0; mp = s->ser_first) {
		srproc_t *proc = (srproc_t *)mp->b_queue;
		void *arg = mp->b_prev;

		if ((s->ser_first = s->ser_first->b_next) == NULL) {
			s->ser_last = NULL;
		} else {
			mp->b_next = NULL;
		}
		ASSERT(s->ser_count != 0);
		s->ser_count--;
		mp->b_queue = NULL;
		mp->b_prev = NULL;
		mutex_exit(&s->ser_lock);

		DTRACE_PROBE4(serializer__exec__start, serializer_t *, s,
		    mblk_t *, mp, void *, arg, srproc_t, proc);
		serializer_exec(s, proc, mp, arg);
		DTRACE_PROBE4(serializer__exec__end, serializer_t *, s,
		    mblk_t *, mp, void *, arg, srproc_t, proc);

		mutex_enter(&s->ser_lock);
	}
}

/*
 * Drain serializer completely if serializer is free.
 */
static void
serializer_drain_completely(serializer_t *s)
{
	mutex_enter(&s->ser_lock);
	ASSERT(s->ser_taskq);
	if (s->ser_owner == NULL) {
		s->ser_owner = curthread;
		while (s->ser_first != NULL)
			serializer_drain(s, INT_MAX);
		s->ser_owner = NULL;
		s->ser_curr = NULL;
		s->ser_proc = NULL;
		s->ser_arg = NULL;
	}
	s->ser_taskq = B_FALSE;
	/*
	 * Wake up serializer_wait().
	 */
	cv_signal(&s->ser_cv);
	mutex_exit(&s->ser_lock);
}

/*
 * Call proc(mp, arg) within serializer.
 *
 * If serializer is empty and not owned, proc(mp, arg) is called right
 * away. Otherwise the request is queued.
 */
void
serializer_enter(serializer_t *s, srproc_t proc, mblk_t *mp, void *arg)
{
	ASSERT(proc != NULL);
	ASSERT(mp != NULL);
	ASSERT(mp->b_next == NULL);
	ASSERT(mp->b_prev == NULL);

	ASSERT(MUTEX_NOT_HELD(&s->ser_lock));

	mutex_enter(&s->ser_lock);
	if (s->ser_owner != NULL) {
		/*
		 * Serializer is owned. Enqueue and return.
		 */
		serializer_enqueue(s, proc, mp, arg);
	} else {
		taskqid_t tid = 0;

		/*
		 * If the request list is empty, can process right away,
		 * otherwise enqueue and process.
		 */
		s->ser_owner = curthread;

		if (s->ser_first != NULL) {
			ASSERT(s->ser_count != 0);
			serializer_enqueue(s, proc, mp, arg);
		} else {
			ASSERT(s->ser_count == 0);
			mutex_exit(&s->ser_lock);
			/*
			 * Execute request
			 */
			DTRACE_PROBE4(serializer__exec__start,
			    serializer_t *, s, mblk_t *, mp,
			    void *, arg, srproc_t, proc);
			serializer_exec(s, proc, mp, arg);
			DTRACE_PROBE4(serializer__exec__end,
			    serializer_t *, s, mblk_t *, mp,
			    void *, arg, srproc_t, proc);
			mutex_enter(&s->ser_lock);
		}

		/*
		 * Drain whatever has arrived in the meantime.
		 * If we spend too much time draining, continue draining by the
		 * taskq thread.
		 */
		while ((s->ser_first != NULL) && (tid == 0)) {
			serializer_drain(s, serializer_credit);
			if (s->ser_first != NULL) {
				perim_context_swtch++;
				/*
				 * If there is a taskq pending for this
				 * serializer, no need to schedule a new one.
				 */
				if (s->ser_taskq) {
					break;
				} else {
					tid = taskq_dispatch(system_taskq,
					    (task_func_t *)
					    serializer_drain_completely,
					    s, TQ_NOSLEEP | TQ_NOQUEUE);
					if (tid != 0)
						s->ser_taskq = B_TRUE;
				}
			}
		}
		s->ser_owner = NULL;
		s->ser_curr = NULL;
		s->ser_proc = NULL;
		s->ser_arg = NULL;
	}
	/*
	 * Wakeup serializer_wait().
	 */
	cv_signal(&s->ser_cv);
	mutex_exit(&s->ser_lock);
}

/*
 * Wait for pending serializer jobs to complete. This function should never be
 * called within the serializer or it will deadlock.
 */
void
serializer_wait(serializer_t *s)
{
	mutex_enter(&s->ser_lock);

	ASSERT(s->ser_owner != curthread);

	while ((s->ser_owner != NULL) || s->ser_taskq || (s->ser_first != NULL))
		cv_wait(&s->ser_cv, &s->ser_lock);
	ASSERT((s->ser_first == NULL) && (s->ser_last == NULL));
	/*
	 * Wakeup other potential waiters.
	 */
	cv_signal(&s->ser_cv);
	mutex_exit(&s->ser_lock);
}

/*
 * Create a new serializer.
 */
serializer_t *
serializer_create(int flags)
{
	return (kmem_cache_alloc(serializer_cache, flags));
}

/*
 * Wait for all pending entries to drain and then destroy serializer.
 */
void
serializer_destroy(serializer_t *s)
{
	serializer_wait(s);

	ASSERT(s->ser_owner == NULL);
	ASSERT(s->ser_taskq == 0);
	ASSERT(s->ser_count == 0);
	ASSERT(s->ser_first == NULL);
	ASSERT(s->ser_last == NULL);

	kmem_cache_free(serializer_cache, s);
}

/*ARGSUSED*/
static int
serializer_constructor(void *buf, void *cdrarg, int kmflags)
{
	serializer_t *s = buf;

	mutex_init(&s->ser_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&s->ser_cv, NULL, CV_DEFAULT, NULL);

	s->ser_taskq = 0;
	s->ser_count = 0;
	s->ser_first = s->ser_last = s->ser_curr = NULL;
	s->ser_proc = NULL;
	s->ser_arg = NULL;
	s->ser_owner = NULL;
	return (0);
}

/*ARGSUSED*/
static void
serializer_destructor(void *buf, void *cdrarg)
{
	serializer_t *s = buf;

	mutex_destroy(&s->ser_lock);
	cv_destroy(&s->ser_cv);
}

void
serializer_init(void)
{
	serializer_cache = kmem_cache_create("serializer_cache",
	    sizeof (serializer_t), 0, serializer_constructor,
	    serializer_destructor, NULL, NULL, NULL, 0);
}
