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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/callo.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/callb.h>
#include <sys/debug.h>
#include <sys/vtrace.h>
#include <sys/sysmacros.h>
#include <sys/sdt.h>

/*
 * Callout tables.  See timeout(9F) for details.
 */
static int cpr_stop_callout;
static int callout_fanout;
static int ncallout;
static callout_table_t *callout_table[CALLOUT_TABLES];

#define	CALLOUT_HASH_INSERT(cthead, cp, cnext, cprev)	\
{							\
	callout_t **headpp = &cthead;			\
	callout_t *headp = *headpp;			\
	cp->cnext = headp;				\
	cp->cprev = NULL;				\
	if (headp != NULL)				\
		headp->cprev = cp;			\
	*headpp = cp;					\
}

#define	CALLOUT_HASH_DELETE(cthead, cp, cnext, cprev)	\
{							\
	callout_t *nextp = cp->cnext;			\
	callout_t *prevp = cp->cprev;			\
	if (nextp != NULL)				\
		nextp->cprev = prevp;			\
	if (prevp != NULL)				\
		prevp->cnext = nextp;			\
	else						\
		cthead = nextp;				\
}

#define	CALLOUT_HASH_UPDATE(INSDEL, ct, cp, id, runtime)		\
	ASSERT(MUTEX_HELD(&ct->ct_lock));				\
	ASSERT(cp->c_xid == id && cp->c_runtime == runtime);		\
	CALLOUT_HASH_##INSDEL(ct->ct_idhash[CALLOUT_IDHASH(id)],	\
	cp, c_idnext, c_idprev)						\
	CALLOUT_HASH_##INSDEL(ct->ct_lbhash[CALLOUT_LBHASH(runtime)],	\
	cp, c_lbnext, c_lbprev)

#define	CALLOUT_HRES_INSERT(ct, cp, cnext, cprev, hresms)		\
{									\
	callout_t *nextp = ct->ct_hresq;				\
	callout_t *prevp;						\
									\
	if (nextp == NULL || hresms <= nextp->c_hresms) {		\
		cp->cnext = ct->ct_hresq;				\
		ct->ct_hresq = cp;					\
		cp->cprev = NULL;					\
		if (cp->cnext != NULL)					\
			cp->cnext->cprev = cp;				\
	} else {							\
		do {							\
			prevp = nextp;					\
			nextp = nextp->cnext;				\
		} while (nextp != NULL && hresms > nextp->c_hresms);	\
		prevp->cnext = cp;					\
		cp->cprev = prevp;					\
		cp->cnext = nextp;					\
		if (nextp != NULL) 					\
			nextp->cprev = cp;				\
	}								\
}

#define	CALLOUT_HRES_DELETE(ct, cp, cnext, cprev, hresms)	\
{								\
	if (cp == ct->ct_hresq) {				\
		ct->ct_hresq = cp->cnext;			\
		if (cp->cnext != NULL)				\
			cp->cnext->cprev = NULL;		\
	} else {						\
		cp->cprev->cnext = cp->cnext;			\
		if (cp->cnext != NULL)				\
			cp->cnext->cprev = cp->cprev;		\
	}							\
}

#define	CALLOUT_HRES_UPDATE(INSDEL, ct, cp, id, hresms)		\
	ASSERT(MUTEX_HELD(&ct->ct_lock));			\
	ASSERT(cp->c_xid == id);				\
	CALLOUT_HRES_##INSDEL(ct, cp, c_hrnext,			\
	c_hrprev, hresms)

/*
 * Allocate a callout structure.  We try quite hard because we
 * can't sleep, and if we can't do the allocation, we're toast.
 * Failing all, we try a KM_PANIC allocation.
 */
static callout_t *
callout_alloc(callout_table_t *ct)
{
	size_t size = 0;
	callout_t *cp = NULL;

	mutex_exit(&ct->ct_lock);
	cp = kmem_alloc_tryhard(sizeof (callout_t), &size,
	    KM_NOSLEEP | KM_PANIC);
	bzero(cp, sizeof (callout_t));
	ncallout++;
	mutex_enter(&ct->ct_lock);
	return (cp);
}

/*
 * Arrange that func(arg) be called after delta clock ticks.
 */
static timeout_id_t
timeout_common(void (*func)(void *), void *arg, clock_t delta,
    callout_table_t *ct)
{
	callout_t	*cp;
	callout_id_t	id;
	clock_t		runtime;
	timestruc_t	now;
	int64_t		hresms;

	gethrestime(&now);

	mutex_enter(&ct->ct_lock);

	if ((cp = ct->ct_freelist) == NULL)
		cp = callout_alloc(ct);
	else
		ct->ct_freelist = cp->c_idnext;

	cp->c_func = func;
	cp->c_arg = arg;

	/*
	 * Make sure the callout runs at least 1 tick in the future.
	 */
	if (delta <= 0)
		delta = 1;
	cp->c_runtime = runtime = lbolt + delta;

	/* Calculate the future time in milli-second */
	hresms = now.tv_sec * MILLISEC + now.tv_nsec / MICROSEC +
	    TICK_TO_MSEC(delta);
	cp->c_hresms = hresms;

	/*
	 * Assign an ID to this callout
	 */
	if (delta > CALLOUT_LONGTERM_TICKS)
		ct->ct_long_id = id = (ct->ct_long_id - CALLOUT_COUNTER_LOW) |
		    CALLOUT_COUNTER_HIGH;
	else
		ct->ct_short_id = id = (ct->ct_short_id - CALLOUT_COUNTER_LOW) |
		    CALLOUT_COUNTER_HIGH;

	cp->c_xid = id;

	CALLOUT_HASH_UPDATE(INSERT, ct, cp, id, runtime);
	CALLOUT_HRES_UPDATE(INSERT, ct, cp, id, hresms);

	mutex_exit(&ct->ct_lock);

	TRACE_4(TR_FAC_CALLOUT, TR_TIMEOUT,
		"timeout:%K(%p) in %ld ticks, cp %p",
		func, arg, delta, cp);

	return ((timeout_id_t)id);
}

timeout_id_t
timeout(void (*func)(void *), void *arg, clock_t delta)
{
	return (timeout_common(func, arg, delta,
	    callout_table[CALLOUT_TABLE(CALLOUT_NORMAL, CPU->cpu_seqid)]));

}

timeout_id_t
realtime_timeout(void (*func)(void *), void *arg, clock_t delta)
{
	return (timeout_common(func, arg, delta,
	    callout_table[CALLOUT_TABLE(CALLOUT_REALTIME, CPU->cpu_seqid)]));
}

clock_t
untimeout(timeout_id_t id_arg)
{
	callout_id_t id = (callout_id_t)id_arg;
	callout_table_t *ct;
	callout_t *cp;
	callout_id_t xid;

	ct = callout_table[id & CALLOUT_TABLE_MASK];

	mutex_enter(&ct->ct_lock);

	for (cp = ct->ct_idhash[CALLOUT_IDHASH(id)]; cp; cp = cp->c_idnext) {

		if ((xid = cp->c_xid) == id) {
			clock_t runtime = cp->c_runtime;
			clock_t time_left = runtime - lbolt;

			CALLOUT_HASH_UPDATE(DELETE, ct, cp, id, runtime);
			CALLOUT_HRES_UPDATE(DELETE, ct, cp, id, 0);
			cp->c_idnext = ct->ct_freelist;
			ct->ct_freelist = cp;
			mutex_exit(&ct->ct_lock);
			TRACE_2(TR_FAC_CALLOUT, TR_UNTIMEOUT,
			    "untimeout:ID %lx ticks_left %ld", id, time_left);
			return (time_left < 0 ? 0 : time_left);
		}

		if (xid != (id | CALLOUT_EXECUTING))
			continue;

		/*
		 * The callout we want to delete is currently executing.
		 * The DDI states that we must wait until the callout
		 * completes before returning, so we block on c_done until
		 * the callout ID changes (to zero if it's on the freelist,
		 * or to a new callout ID if it's in use).  This implicitly
		 * assumes that callout structures are persistent (they are).
		 */
		if (cp->c_executor == curthread) {
			/*
			 * The timeout handler called untimeout() on itself.
			 * Stupid, but legal.  We can't wait for the timeout
			 * to complete without deadlocking, so we just return.
			 */
			mutex_exit(&ct->ct_lock);
			TRACE_1(TR_FAC_CALLOUT, TR_UNTIMEOUT_SELF,
			    "untimeout_self:ID %x", id);
			return (-1);
		}
		while (cp->c_xid == xid)
			cv_wait(&cp->c_done, &ct->ct_lock);
		mutex_exit(&ct->ct_lock);
		TRACE_1(TR_FAC_CALLOUT, TR_UNTIMEOUT_EXECUTING,
		    "untimeout_executing:ID %lx", id);
		return (-1);
	}

	mutex_exit(&ct->ct_lock);
	TRACE_1(TR_FAC_CALLOUT, TR_UNTIMEOUT_BOGUS_ID,
	    "untimeout_bogus_id:ID %lx", id);

	/*
	 * We didn't find the specified callout ID.  This means either
	 * (1) the callout already fired, or (2) the caller passed us
	 * a bogus value.  Perform a sanity check to detect case (2).
	 */
	if (id != 0 && (id & (CALLOUT_COUNTER_HIGH | CALLOUT_EXECUTING)) !=
	    CALLOUT_COUNTER_HIGH)
		panic("untimeout: impossible timeout id %lx", id);

	return (-1);
}

/*
 * Do the actual work of executing callouts.  This routine is called either
 * by a taskq_thread (normal case), or by softcall (realtime case).
 */
static void
callout_execute(callout_table_t *ct)
{
	callout_t	*cp;
	callout_id_t	xid;
	clock_t		runtime;
	timestruc_t	now;
	int64_t		hresms;

	mutex_enter(&ct->ct_lock);

	while (((runtime = ct->ct_runtime) - ct->ct_curtime) <= 0) {
		for (cp = ct->ct_lbhash[CALLOUT_LBHASH(runtime)];
		    cp != NULL; cp = cp->c_lbnext) {
			xid = cp->c_xid;
			if (cp->c_runtime != runtime ||
			    (xid & CALLOUT_EXECUTING))
				continue;
			cp->c_executor = curthread;
			cp->c_xid = xid |= CALLOUT_EXECUTING;
			mutex_exit(&ct->ct_lock);
			DTRACE_PROBE1(callout__start, callout_t *, cp);
			(*cp->c_func)(cp->c_arg);
			DTRACE_PROBE1(callout__end, callout_t *, cp);
			mutex_enter(&ct->ct_lock);

			/*
			 * Delete callout from both the hash tables and the
			 * hres queue, return it to freelist, and tell anyone
			 * who cares that we're done.
			 * Even though we dropped and reacquired ct->ct_lock,
			 * it's OK to pick up where we left off because only
			 * newly-created timeouts can precede cp on ct_lbhash,
			 * and those timeouts cannot be due on this tick.
			 */
			CALLOUT_HASH_UPDATE(DELETE, ct, cp, xid, runtime);
			CALLOUT_HRES_UPDATE(DELETE, ct, cp, xid, hresms);
			cp->c_idnext = ct->ct_freelist;
			ct->ct_freelist = cp;
			cp->c_xid = 0;	/* Indicate completion for c_done */
			cv_broadcast(&cp->c_done);
		}
		/*
		 * We have completed all callouts that were scheduled to
		 * run at "runtime".  If the global run time still matches
		 * our local copy, then we advance the global run time;
		 * otherwise, another callout thread must have already done so.
		 */
		if (ct->ct_runtime == runtime)
			ct->ct_runtime = runtime + 1;
	}

	gethrestime(&now);

	/* Calculate the current time in milli-second */
	hresms = now.tv_sec * MILLISEC + now.tv_nsec / MICROSEC;

	cp = ct->ct_hresq;
	while (cp != NULL && hresms >= cp->c_hresms) {
		xid = cp->c_xid;
		if (xid & CALLOUT_EXECUTING) {
			cp = cp->c_hrnext;
			continue;
		}
		cp->c_executor = curthread;
		cp->c_xid = xid |= CALLOUT_EXECUTING;
		runtime = cp->c_runtime;
		mutex_exit(&ct->ct_lock);
		DTRACE_PROBE1(callout__start, callout_t *, cp);
		(*cp->c_func)(cp->c_arg);
		DTRACE_PROBE1(callout__end, callout_t *, cp);
		mutex_enter(&ct->ct_lock);

		/*
		 * See comments above.
		 */
		CALLOUT_HASH_UPDATE(DELETE, ct, cp, xid, runtime);
		CALLOUT_HRES_UPDATE(DELETE, ct, cp, xid, hresms);
		cp->c_idnext = ct->ct_freelist;
		ct->ct_freelist = cp;
		cp->c_xid = 0;	/* Indicate completion for c_done */
		cv_broadcast(&cp->c_done);

		/*
		 * Start over from the head of the list, see if
		 * any timeout bearing an earlier hres time.
		 */
		cp = ct->ct_hresq;
	}
	mutex_exit(&ct->ct_lock);
}

/*
 * Schedule any callouts that are due on or before this tick.
 */
static void
callout_schedule_1(callout_table_t *ct)
{
	callout_t	*cp;
	clock_t		curtime, runtime;
	timestruc_t	now;
	int64_t		hresms;

	mutex_enter(&ct->ct_lock);
	ct->ct_curtime = curtime = lbolt;
	while (((runtime = ct->ct_runtime) - curtime) <= 0) {
		for (cp = ct->ct_lbhash[CALLOUT_LBHASH(runtime)];
		    cp != NULL; cp = cp->c_lbnext) {
			if (cp->c_runtime != runtime ||
			    (cp->c_xid & CALLOUT_EXECUTING))
				continue;
			mutex_exit(&ct->ct_lock);
			if (ct->ct_taskq == NULL)
				softcall((void (*)(void *))callout_execute, ct);
			else
				(void) taskq_dispatch(ct->ct_taskq,
				    (task_func_t *)callout_execute, ct,
				    KM_NOSLEEP);
			return;
		}
		ct->ct_runtime++;
	}

	gethrestime(&now);

	/* Calculate the current time in milli-second */
	hresms = now.tv_sec * MILLISEC + now.tv_nsec / MICROSEC;

	cp = ct->ct_hresq;
	while (cp != NULL && hresms >= cp->c_hresms) {
		if (cp->c_xid & CALLOUT_EXECUTING) {
			cp = cp->c_hrnext;
			continue;
		}
		mutex_exit(&ct->ct_lock);
		if (ct->ct_taskq == NULL)
			softcall((void (*)(void *))callout_execute, ct);
		else
			(void) taskq_dispatch(ct->ct_taskq,
			    (task_func_t *)callout_execute, ct, KM_NOSLEEP);
		return;
	}
	mutex_exit(&ct->ct_lock);
}

/*
 * Schedule callouts for all callout tables.  Called by clock() on each tick.
 */
void
callout_schedule(void)
{
	int f, t;

	if (cpr_stop_callout)
		return;

	for (t = 0; t < CALLOUT_NTYPES; t++)
		for (f = 0; f < callout_fanout; f++)
			callout_schedule_1(callout_table[CALLOUT_TABLE(t, f)]);
}

/*
 * Callback handler used by CPR to stop and resume callouts.
 */
/*ARGSUSED*/
static boolean_t
callout_cpr_callb(void *arg, int code)
{
	cpr_stop_callout = (code == CB_CODE_CPR_CHKPT);
	return (B_TRUE);
}

/*
 * Initialize all callout tables.  Called at boot time just before clkstart().
 */
void
callout_init(void)
{
	int f, t;
	int table_id;
	callout_table_t *ct;

	callout_fanout = MIN(CALLOUT_FANOUT, max_ncpus);

	for (t = 0; t < CALLOUT_NTYPES; t++) {
		for (f = 0; f < CALLOUT_FANOUT; f++) {
			table_id = CALLOUT_TABLE(t, f);
			if (f >= callout_fanout) {
				callout_table[table_id] =
				    callout_table[table_id - callout_fanout];
				continue;
			}
			ct = kmem_zalloc(sizeof (callout_table_t), KM_SLEEP);
			callout_table[table_id] = ct;
			ct->ct_short_id = (callout_id_t)table_id |
			    CALLOUT_COUNTER_HIGH;
			ct->ct_long_id = ct->ct_short_id | CALLOUT_LONGTERM;
			ct->ct_curtime = ct->ct_runtime = lbolt;
			if (t == CALLOUT_NORMAL) {
				/*
				 * Each callout thread consumes exactly one
				 * task structure while active.  Therefore,
				 * prepopulating with 2 * CALLOUT_THREADS tasks
				 * ensures that there's at least one task per
				 * thread that's either scheduled or on the
				 * freelist.  In turn, this guarantees that
				 * taskq_dispatch() will always either succeed
				 * (because there's a free task structure) or
				 * be unnecessary (because "callout_excute(ct)"
				 * has already scheduled).
				 */
				ct->ct_taskq =
				    taskq_create_instance("callout_taskq", f,
				    CALLOUT_THREADS, maxclsyspri,
				    2 * CALLOUT_THREADS, 2 * CALLOUT_THREADS,
				    TASKQ_PREPOPULATE | TASKQ_CPR_SAFE);
			}
		}
	}
	(void) callb_add(callout_cpr_callb, 0, CB_CL_CPR_CALLOUT, "callout");
}
