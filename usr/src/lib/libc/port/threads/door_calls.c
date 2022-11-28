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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

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
#include <strings.h>
#include <ucontext.h>
#include <sys/ucred.h>
#include <atomic.h>

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
extern int __door_unbind(void);

/*
 * Key for per-door data for doors created with door_xcreate.
 */
static pthread_key_t privdoor_key = PTHREAD_ONCE_KEY_NP;

/*
 * Each door_xcreate'd door has a struct privdoor_data allocated for it,
 * and each of the initial pool of service threads for the door
 * has TSD for the privdoor_key set to point to this structure.
 * When a thread in door_return decides it is time to perform a
 * thread depletion callback we can retrieve this door information
 * via a TSD lookup on the privdoor key.
 */
struct privdoor_data {
	int pd_dfd;
	door_id_t pd_uniqid;
	volatile uint32_t pd_refcnt;
	door_xcreate_server_func_t *pd_crf;
	void *pd_crcookie;
	door_xcreate_thrsetup_func_t *pd_setupf;
};

static int door_xcreate_n(door_info_t *, struct privdoor_data *, int);

/*
 * door_create_cmn holds the privdoor data before kicking off server
 * thread creation, all of which must succeed; if they don't then
 * they return leaving the refcnt unchanged overall, and door_create_cmn
 * releases its hold after revoking the door and we're done.  Otherwise
 * all n threads created add one each to the refcnt, and door_create_cmn
 * drops its hold.  If and when a server thread exits the key destructor
 * function will be called, and we use that to decrement the reference
 * count.  We also decrement the reference count on door_unbind().
 * If ever we get the reference count to 0 then we will free that data.
 */
static void
privdoor_data_hold(struct privdoor_data *pdd)
{
	atomic_inc_32(&pdd->pd_refcnt);
}

static void
privdoor_data_rele(struct privdoor_data *pdd)
{
	if (atomic_dec_32_nv(&pdd->pd_refcnt) == 0)
		free(pdd);
}

void
privdoor_destructor(void *data)
{
	privdoor_data_rele((struct privdoor_data *)data);
}

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

static int
door_create_cmn(door_server_procedure_t *f, void *cookie, uint_t flags,
    door_xcreate_server_func_t *crf, door_xcreate_thrsetup_func_t *setupf,
    void *crcookie, int nthread)
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

	if (crf)
		flags |= DOOR_PRIVCREATE;

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
		return (-1);	/* errno is set */
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

	if (is_private) {
		door_info_t di;

		/*
		 * Create the first thread(s) for this private door.
		 */
		if (__door_info(d, &di) < 0)
			return (-1);	/* errno is set */

		/*
		 * This key must be available for lookup for all private
		 * door threads, whether associated with a door created via
		 * door_create or door_xcreate.
		 */
		(void) pthread_key_create_once_np(&privdoor_key,
		    privdoor_destructor);

		if (crf == NULL) {
			(*door_server_func)(&di);
		} else {
			struct privdoor_data *pdd = malloc(sizeof (*pdd));

			if (pdd == NULL) {
				(void) door_revoke(d);
				errno = ENOMEM;
				return (-1);
			}

			pdd->pd_dfd = d;
			pdd->pd_uniqid = di.di_uniquifier;
			pdd->pd_refcnt = 1; /* prevent free during xcreate_n */
			pdd->pd_crf = crf;
			pdd->pd_crcookie = crcookie;
			pdd->pd_setupf = setupf;

			if (!door_xcreate_n(&di, pdd, nthread)) {
				int errnocp = errno;

				(void) door_revoke(d);
				privdoor_data_rele(pdd);
				errno = errnocp;
				return (-1);
			} else {
				privdoor_data_rele(pdd);
			}
		}
	} else if (do_create_first) {
		/* First non-private door created in the process */
		(*door_server_func)(NULL);
	}

	return (d);
}

int
door_create(door_server_procedure_t *f, void *cookie, uint_t flags)
{
	if (flags & (DOOR_NO_DEPLETION_CB | DOOR_PRIVCREATE)) {
		errno = EINVAL;
		return (-1);
	}

	return (door_create_cmn(f, cookie, flags, NULL, NULL, NULL, 1));
}

int
door_xcreate(door_server_procedure_t *f, void *cookie, uint_t flags,
    door_xcreate_server_func_t *crf, door_xcreate_thrsetup_func_t *setupf,
    void *crcookie, int nthread)
{
	if (flags & DOOR_PRIVCREATE || nthread < 1 || crf == NULL) {
		errno = EINVAL;
		return (-1);
	}

	return (door_create_cmn(f, cookie, flags | DOOR_PRIVATE,
	    crf, setupf, crcookie, nthread));
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
door_unbind(void)
{
	struct privdoor_data *pdd;
	int rv = __door_unbind();

	/*
	 * If we were indeed bound to the door then check to see whether
	 * we are part of a door_xcreate'd door by checking for our TSD.
	 * If so, then clear the TSD for this key to avoid destructor
	 * callback on future thread exit, and release the private door data.
	 */
	if (rv == 0 && (pdd = pthread_getspecific(privdoor_key)) != NULL) {
		(void) pthread_setspecific(privdoor_key, NULL);
		privdoor_data_rele(pdd);
	}

	return (rv);
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
 * To start and synchronize a number of door service threads at once
 * we use a struct door_xsync_shared shared by all threads, and
 * a struct door_xsync for each thread.  While each thread
 * has its own startup state, all such state are protected by the same
 * shared lock.  This could cause a little contention but it is a one-off
 * cost at door creation.
 */
enum door_xsync_state {
	DOOR_XSYNC_CREATEWAIT = 0x1c8c8c80,	/* awaits creation handshake */
	DOOR_XSYNC_ABORT,		/* aborting door_xcreate */
	DOOR_XSYNC_ABORTED,		/* thread heeded abort request */
	DOOR_XSYNC_MAXCONCUR,		/* create func decided no more */
	DOOR_XSYNC_CREATEFAIL,		/* thr_create/pthread_create failure */
	DOOR_XSYNC_SETSPEC_FAIL,	/* setspecific failed */
	DOOR_XSYNC_BINDFAIL,		/* door_bind failed */
	DOOR_XSYNC_BOUND,		/* door_bind succeeded */
	DOOR_XSYNC_ENTER_SERVICE	/* Go on to door_return */
};

/* These stats are incremented non-atomically - indicative only */
uint64_t door_xcreate_n_stats[DOOR_XSYNC_ENTER_SERVICE -
    DOOR_XSYNC_CREATEWAIT + 1];

struct door_xsync_shared {
	pthread_mutex_t lock;
	pthread_cond_t cv_m2s;
	pthread_cond_t cv_s2m;
	struct privdoor_data *pdd;
	volatile uint32_t waiting;
};

struct door_xsync {
	volatile enum door_xsync_state state;
	struct door_xsync_shared *sharedp;
};

/*
 * Thread start function that xcreated private doors must use in
 * thr_create or pthread_create.  They must also use the argument we
 * provide.  We:
 *
 *	o call a thread setup function if supplied, or apply sensible defaults
 *	o bind the newly-created thread to the door it will service
 *	o synchronize with door_xcreate to indicate that we have successfully
 *	  bound to the door;  door_xcreate will not return until all
 *	  requested threads have at least bound
 *	o enter service with door_return quoting magic sentinel args
 */
void *
door_xcreate_startf(void *arg)
{
	struct door_xsync *xsp = (struct door_xsync *)arg;
	struct door_xsync_shared *xssp = xsp->sharedp;
	struct privdoor_data *pdd = xssp->pdd;
	enum door_xsync_state next_state;

	privdoor_data_hold(pdd);
	if (pthread_setspecific(privdoor_key, (const void *)pdd) != 0) {
		next_state = DOOR_XSYNC_SETSPEC_FAIL;
		privdoor_data_rele(pdd);
		goto handshake;
	}

	if (pdd->pd_setupf != NULL) {
		(pdd->pd_setupf)(pdd->pd_crcookie);
	} else {
		(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
		(void) pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, NULL);
	}

	if (door_bind(pdd->pd_dfd) == 0)
		next_state = DOOR_XSYNC_BOUND;
	else
		next_state = DOOR_XSYNC_BINDFAIL;

handshake:
	(void) pthread_mutex_lock(&xssp->lock);

	ASSERT(xsp->state == DOOR_XSYNC_CREATEWAIT ||
	    xsp->state == DOOR_XSYNC_ABORT);

	if (xsp->state == DOOR_XSYNC_ABORT)
		next_state = DOOR_XSYNC_ABORTED;

	xsp->state = next_state;

	if (--xssp->waiting == 0)
		(void) pthread_cond_signal(&xssp->cv_s2m);

	if (next_state != DOOR_XSYNC_BOUND) {
		(void) pthread_mutex_unlock(&xssp->lock);
		return (NULL);	/* thread exits, key destructor called */
	}

	while (xsp->state == DOOR_XSYNC_BOUND)
		(void) pthread_cond_wait(&xssp->cv_m2s, &xssp->lock);

	next_state = xsp->state;
	ASSERT(next_state == DOOR_XSYNC_ENTER_SERVICE ||
	    next_state == DOOR_XSYNC_ABORT);

	if (--xssp->waiting == 0)
		(void) pthread_cond_signal(&xssp->cv_s2m);

	(void) pthread_mutex_unlock(&xssp->lock); /* xssp/xsp can be freed */

	if (next_state == DOOR_XSYNC_ABORT)
		return (NULL);	/* thread exits, key destructor called */

	(void) door_return(NULL, 0, NULL, 0);
	return (NULL);
}

static int
door_xcreate_n(door_info_t *dip, struct privdoor_data *pdd, int n)
{
	struct door_xsync_shared *xssp;
	struct door_xsync *xsp;
	int i, failidx = -1;
	int isdepcb = 0;
	int failerrno;
	int bound = 0;
#ifdef _STACK_GROWS_DOWNWARD
	int stkdir = -1;
#else
	int stkdir = 1;
#endif
	int rv = 0;

	/*
	 * If we're called during door creation then we have the
	 * privdoor_data.  If we're called as part of a depletion callback
	 * then the current thread has the privdoor_data as TSD.
	 */
	if (pdd == NULL) {
		isdepcb = 1;
		if ((pdd = pthread_getspecific(privdoor_key)) == NULL)
			thr_panic("door_xcreate_n - no privdoor_data "
			    "on existing server thread");
	}

	/*
	 * Allocate on our stack.  We'll pass pointers to this to the
	 * newly-created threads, therefore this function must not return until
	 * we have synced with server threads that are created.
	 * We do not limit the number of threads so begin by checking
	 * that we have space on the stack for this.
	 */
	{
		size_t sz = sizeof (*xssp) + n * sizeof (*xsp) + 32;
		char dummy;

		if (!stack_inbounds(&dummy + stkdir * sz)) {
			errno = E2BIG;
			return (0);
		}
	}

	if ((xssp = alloca(sizeof (*xssp))) == NULL ||
	    (xsp = alloca(n * sizeof (*xsp))) == NULL) {
		errno = E2BIG;
		return (0);
	}

	(void) pthread_mutex_init(&xssp->lock, NULL);
	(void) pthread_cond_init(&xssp->cv_m2s, NULL);
	(void) pthread_cond_init(&xssp->cv_s2m, NULL);
	xssp->pdd = pdd;
	xssp->waiting = 0;

	(void) pthread_mutex_lock(&xssp->lock);

	for (i = 0; failidx == -1 && i < n; i++) {
		xsp[i].sharedp = xssp;
		membar_producer();	/* xssp and xsp[i] for new thread */

		switch ((pdd->pd_crf)(dip, door_xcreate_startf,
		    (void *)&xsp[i], pdd->pd_crcookie)) {
		case 1:
			/*
			 * Thread successfully created.  Set mailbox
			 * state and increment the number we have to
			 * sync with.
			 */
			xsp[i].state = DOOR_XSYNC_CREATEWAIT;
			xssp->waiting++;
			break;
		case 0:
			/*
			 * Elected to create no further threads.  OK for
			 * a depletion callback, but not during door_xcreate.
			 */
			xsp[i].state = DOOR_XSYNC_MAXCONCUR;
			if (!isdepcb) {
				failidx = i;
				failerrno = EINVAL;
			}
			break;
		case -1:
			/*
			 * Thread creation was attempted but failed.
			 */
			xsp[i].state = DOOR_XSYNC_CREATEFAIL;
			failidx = i;
			failerrno = EPIPE;
			break;
		default:
			/*
			 * The application-supplied function did not return
			 * -1/0/1 - best we can do is panic because anything
			 * else is harder to debug.
			 */
			thr_panic("door server create function illegal return");
			/*NOTREACHED*/
		}
	}

	/*
	 * On initial creation all must succeed; if not then abort
	 */
	if (!isdepcb && failidx != -1) {
		for (i = 0; i < failidx; i++)
			if (xsp[i].state == DOOR_XSYNC_CREATEWAIT)
				xsp[i].state = DOOR_XSYNC_ABORT;
	}

	/*
	 * Wait for thread startup handshake to complete for all threads
	 */
	while (xssp->waiting)
		(void) pthread_cond_wait(&xssp->cv_s2m, &xssp->lock);

	/*
	 * If we are aborting for a failed thread create in door_xcreate
	 * then we're done.
	 */
	if (!isdepcb && failidx != -1) {
		rv = 0;
		goto out;	/* lock held, failerrno is set */
	}

	/*
	 * Did we all succeed in binding?
	 */
	for (i = 0; i < n; i++) {
		int statidx = xsp[i].state - DOOR_XSYNC_CREATEWAIT;

		door_xcreate_n_stats[statidx]++;
		if (xsp[i].state == DOOR_XSYNC_BOUND)
			bound++;
	}

	if (bound == n) {
		rv = 1;
	} else {
		failerrno = EBADF;
		rv = 0;
	}

	/*
	 * During door_xcreate all must succeed in binding - if not then
	 * we command even those that did bind to abort.  Threads that
	 * did not get as far as binding have already exited.
	 */
	for (i = 0; i < n; i++) {
		if (xsp[i].state == DOOR_XSYNC_BOUND) {
			xsp[i].state = (rv == 1 || isdepcb) ?
			    DOOR_XSYNC_ENTER_SERVICE : DOOR_XSYNC_ABORT;
			xssp->waiting++;
		}
	}

	(void) pthread_cond_broadcast(&xssp->cv_m2s);

	while (xssp->waiting)
		(void) pthread_cond_wait(&xssp->cv_s2m, &xssp->lock);

out:
	(void) pthread_mutex_unlock(&xssp->lock);
	(void) pthread_mutex_destroy(&xssp->lock);
	(void) pthread_cond_destroy(&xssp->cv_m2s);
	(void) pthread_cond_destroy(&xssp->cv_s2m);

	if (rv == 0)
		errno = failerrno;

	return (rv);
}

/*
 * Call the server creation function to give it the opportunity to
 * create more threads.  Called during a door invocation when we
 * return from door_return(NULL,0, NULL, 0) and notice that we're
 * running on the last available thread.
 */
void
door_depletion_cb(door_info_t *dip)
{
	if (dip == NULL) {
		/*
		 * Non-private doors always use door_server_func.
		 */
		(*door_server_func)(NULL);
		return;
	}

	if (dip->di_attributes & DOOR_NO_DEPLETION_CB) {
		/*
		 * Private, door_xcreate'd door specified no callbacks.
		 */
		return;
	} else if (!(dip->di_attributes & DOOR_PRIVCREATE)) {
		/*
		 * Private door with standard/legacy creation semantics.
		 */
		dip->di_attributes |= DOOR_DEPLETION_CB;
		(*door_server_func)(dip);
		return;
	} else {
		/*
		 * Private, door_xcreate'd door.
		 */
		dip->di_attributes |= DOOR_DEPLETION_CB;
		(void) door_xcreate_n(dip, NULL, 1);
	}
}

/*
 * Install a new server creation function.  The appointed function
 * will receieve depletion callbacks for non-private doors and private
 * doors created with door_create(..., DOOR_PRIVATE).
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
 * Thread start function for door_create_server() below.
 * Create door server threads with cancellation(7) disabled.
 */
static void *
door_create_func(void *arg)
{
	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
	(void) door_return(NULL, 0, NULL, 0);

	return (arg);
}

/*
 * The default door_server_func_t.
 */
static void
door_create_server(door_info_t *dip __unused)
{
	(void) thr_create(NULL, 0, door_create_func, NULL, THR_DETACHED, NULL);
	yield();	/* Gives server thread a chance to run */
}
