/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/cmn_err.h>
#include <sys/thread.h>
#include <sys/zone.h>

#define	_SYNCH_H	/* keep out <synch.h> */
#include <thread.h>

/*
 * Get the current kthread_t pointer.
 */
kthread_t *
_curthread(void)
{
	thread_t tid;

	tid = thr_self();
	return ((kthread_t *)(uintptr_t)tid);
}

/*
 * Create a thread.
 *
 * thread_create() blocks for memory if necessary.  It never fails.
 */
/* ARGSUSED */
kthread_t *
thread_create(
	caddr_t	stk,
	size_t	stksize,
	void	(*func)(),
	void	*arg,
	size_t	len,
	struct proc *pp,
	int	state,
	pri_t	pri)
{
	void * (*thr_func)(void *);
	thread_t newtid;
	int thr_flags = 0;
	int rc;

	thr_flags = THR_BOUND;

	switch (state) {
	case TS_RUN:
	case TS_ONPROC:
		break;
	case TS_STOPPED:
		thr_flags |= THR_SUSPENDED;
		break;
	default:
		cmn_err(CE_PANIC, "thread_create: invalid state");
		break;
	}

	thr_func = (void *(*)(void *))func;
	rc = thr_create(NULL, 0, thr_func, arg, thr_flags, &newtid);
	if (rc != 0)
		cmn_err(CE_PANIC, "thread_create failed, rc=%d", rc);

	return ((void *)(uintptr_t)newtid);
}

void
thread_exit(void)
{
	thr_exit(NULL);
}

void
thread_join(kt_did_t id)
{
	thread_t thr_id;

	thr_id = (thread_t)id;
	(void) thr_join(thr_id, NULL, NULL);
}

void
tsignal(kthread_t *kt, int sig)
{
	thread_t tid = (thread_t)(uintptr_t)kt;

	(void) thr_kill(tid, sig);
}


/*ARGSUSED*/
kthread_t *
zthread_create(
    caddr_t stk,
    size_t stksize,
    void (*func)(),
    void *arg,
    size_t len,
    pri_t pri)
{
	kthread_t *t;

	t = thread_create(stk, stksize, func, arg, len, NULL, TS_RUN, pri);

	return (t);
}

void
zthread_exit(void)
{
	thread_exit();
	/* NOTREACHED */
}
