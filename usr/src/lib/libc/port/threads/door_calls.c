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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "thr_uberdata.h"
#include "libc.h"

#include <alloca.h>
#include <unistd.h>
#include <thread.h>
#include <pthread.h>
#include <stdio.h>
#include <errno.h>
#include <door.h>
#include <signal.h>
#include <ucred.h>
#include <sys/ucred.h>

static door_server_func_t door_create_server;

/*
 * Global state -- the non-statics are accessed from the __door_return()
 * syscall wrapper.
 */
static mutex_t		door_state_lock = DEFAULTMUTEX;
door_server_func_t	*door_server_func = door_create_server;
pid_t			door_create_pid = 0;
static pid_t		door_create_first_pid = 0;
static pid_t		door_create_unref_pid = 0;

/*
 * The raw system call interfaces
 */
extern int __door_create(void (*)(void *, char *, size_t, door_desc_t *,
    uint_t), void *, uint_t);
extern int __door_return(caddr_t, size_t, door_return_desc_t *, caddr_t,
    size_t);
extern int __door_ucred(ucred_t *);
extern int __door_unref(void);

/*
 * We park the ourselves in the kernel to serve as the "caller" for
 * unreferenced upcalls for this process.  If the call returns with
 * EINTR (e.g., someone did a forkall), we repeat as long as we're still
 * in the parent.  If the child creates an unref door it will create
 * a new thread.
 */
static void *
door_unref_func(void *arg)
{
	pid_t mypid = (pid_t)(uintptr_t)arg;

	sigset_t fillset;

	/* mask signals before diving into the kernel */
	(void) sigfillset(&fillset);
	(void) thr_sigsetmask(SIG_SETMASK, &fillset, NULL);

	while (getpid() == mypid && __door_unref() && errno == EINTR)
		continue;

	return (NULL);
}

int
door_create(void (*f)(void *, char *, size_t, door_desc_t *, uint_t),
    void *cookie, uint_t flags)
{
	int d;

	int is_private = (flags & DOOR_PRIVATE);
	int is_unref = (flags & (DOOR_UNREF | DOOR_UNREF_MULTI));
	int do_create_first = 0;
	int do_create_unref = 0;

	ulwp_t *self = curthread;

	pid_t mypid;

	if (self->ul_vfork) {
		errno = ENOTSUP;
		return (-1);
	}

	/*
	 * Doors are associated with the processes which created them.  In
	 * the face of forkall(), this gets quite complicated.  To simplify
	 * it somewhat, we include the call to __door_create() in a critical
	 * section, and figure out what additional actions to take while
	 * still in the critical section.
	 */
	enter_critical(self);
	if ((d = __door_create(f, cookie, flags)) < 0) {
		exit_critical(self);
		return (-1);
	}
	mypid = getpid();
	if (mypid != door_create_pid ||
	    (!is_private && mypid != door_create_first_pid) ||
	    (is_unref && mypid != door_create_unref_pid)) {

		lmutex_lock(&door_state_lock);
		door_create_pid = mypid;

		if (!is_private && mypid != door_create_first_pid) {
			do_create_first = 1;
			door_create_first_pid = mypid;
		}
		if (is_unref && mypid != door_create_unref_pid) {
			do_create_unref = 1;
			door_create_unref_pid = mypid;
		}
		lmutex_unlock(&door_state_lock);
	}
	exit_critical(self);

	if (do_create_unref) {
		/*
		 * Create an unref thread the first time we create an
		 * unref door for this process.  Create it as a daemon
		 * thread, so that it doesn't interfere with normal exit
		 * processing.
		 */
		(void) thr_create(NULL, 0, door_unref_func,
		    (void *)(uintptr_t)mypid, THR_DAEMON, NULL);
	}

	/*
	 * If this is the first door created in the process, or the door
	 * has a private pool, we need to kick off the thread pool now.
	 */
	if (do_create_first)
		(*door_server_func)(NULL);

	if (is_private) {
		door_info_t di;

		if (__door_info(d, &di) < 0)
			return (-1);
		(*door_server_func)(&di);
	}

	return (d);
}

int
door_ucred(ucred_t **uc)
{
	ucred_t *ucp = *uc;

	if (ucp == NULL) {
		ucp = _ucred_alloc();
		if (ucp == NULL)
			return (-1);
	}

	if (__door_ucred(ucp) != 0) {
		if (*uc == NULL)
			ucred_free(ucp);
		return (-1);
	}

	*uc = ucp;

	return (0);
}

int
door_cred(door_cred_t *dc)
{
	/*
	 * Ucred size is small and alloca is fast
	 * and cannot fail.
	 */
	ucred_t *ucp = alloca(ucred_size());
	int ret;

	if ((ret = __door_ucred(ucp)) == 0) {
		dc->dc_euid = ucred_geteuid(ucp);
		dc->dc_ruid = ucred_getruid(ucp);
		dc->dc_egid = ucred_getegid(ucp);
		dc->dc_rgid = ucred_getrgid(ucp);
		dc->dc_pid = ucred_getpid(ucp);
	}
	return (ret);
}

int
door_return(char *data_ptr, size_t data_size,
    door_desc_t *desc_ptr, uint_t num_desc)
{
	caddr_t sp;
	size_t ssize;
	size_t reserve;
	ulwp_t *self = curthread;

	{
		stack_t s;
		if (thr_stksegment(&s) != 0) {
			errno = EINVAL;
			return (-1);
		}
		sp = s.ss_sp;
		ssize = s.ss_size;
	}

	if (!self->ul_door_noreserve) {
		/*
		 * When we return from the kernel, we must have enough stack
		 * available to handle the request.  Since the creator of
		 * the thread has control over its stack size, and larger
		 * stacks generally indicate bigger request queues, we
		 * use the heuristic of reserving 1/32nd of the stack size
		 * (up to the default stack size), with a minimum of 1/8th
		 * of MINSTACK.  Currently, this translates to:
		 *
		 *			_ILP32		_LP64
		 *	min resv	 512 bytes	1024 bytes
		 *	max resv	 32k bytes	 64k bytes
		 *
		 * This reservation can be disabled by setting
		 *	_THREAD_DOOR_NORESERVE=1
		 * in the environment, but shouldn't be.
		 */

#define	STACK_FRACTION		32
#define	MINSTACK_FRACTION	8

		if (ssize < (MINSTACK * (STACK_FRACTION/MINSTACK_FRACTION)))
			reserve = MINSTACK / MINSTACK_FRACTION;
		else if (ssize < DEFAULTSTACK)
			reserve = ssize / STACK_FRACTION;
		else
			reserve = DEFAULTSTACK / STACK_FRACTION;

#undef STACK_FRACTION
#undef MINSTACK_FRACTION

		if (ssize > reserve)
			ssize -= reserve;
		else
			ssize = 0;
	}

	/*
	 * Historically, the __door_return() syscall wrapper subtracted
	 * some "slop" from the stack pointer before trapping into the
	 * kernel.  We now do this here, so that ssize can be adjusted
	 * correctly.  Eventually, this should be removed, since it is
	 * unnecessary.  (note that TNF on x86 currently relies upon this
	 * idiocy)
	 */
#if defined(__sparc)
	reserve = SA(MINFRAME);
#elif defined(__x86)
	reserve = SA(512);
#else
#error need to define stack base reserve
#endif

#ifdef _STACK_GROWS_DOWNWARD
	sp -= reserve;
#else
#error stack does not grow downwards, routine needs update
#endif

	if (ssize > reserve)
		ssize -= reserve;
	else
		ssize = 0;

	/*
	 * Normally, the above will leave plenty of space in sp for a
	 * request.  Just in case some bozo overrides thr_stksegment() to
	 * return an uncommonly small stack size, we turn off stack size
	 * checking if there is less than 1k remaining.
	 */
#define	MIN_DOOR_STACK	1024
	if (ssize < MIN_DOOR_STACK)
		ssize = 0;

#undef MIN_DOOR_STACK

	/*
	 * We have to wrap the desc_* arguments for the syscall.  If there are
	 * no descriptors being returned, we can skip the wrapping.
	 */
	if (num_desc != 0) {
		door_return_desc_t d;

		d.desc_ptr = desc_ptr;
		d.desc_num = num_desc;
		return (__door_return(data_ptr, data_size, &d, sp, ssize));
	}
	return (__door_return(data_ptr, data_size, NULL, sp, ssize));
}

/*
 * Install a new server creation function.
 */
door_server_func_t *
door_server_create(door_server_func_t *create_func)
{
	door_server_func_t *prev;

	lmutex_lock(&door_state_lock);
	prev = door_server_func;
	door_server_func = create_func;
	lmutex_unlock(&door_state_lock);

	return (prev);
}

/*
 * Create door server threads with cancellation(5) disabled.
 */
static void *
door_create_func(void *arg)
{
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	(void) door_return(NULL, 0, NULL, 0);

	return (arg);
}

/*
 * The default server thread creation routine.
 */
/* ARGSUSED */
static void
door_create_server(door_info_t *dip)
{
	(void) thr_create(NULL, 0, door_create_func, NULL, THR_DETACHED, NULL);
	yield();	/* Gives server thread a chance to run */
}
