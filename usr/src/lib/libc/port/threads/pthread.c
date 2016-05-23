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
 * Copyright 2016 Joyent, Inc.
 */

#include "lint.h"
#include "thr_uberdata.h"

/*
 * pthread_once related data
 * This structure is exported as pthread_once_t in pthread.h.
 * We export only the size of this structure. so check
 * pthread_once_t in pthread.h before making a change here.
 */
typedef struct  __once {
	mutex_t	mlock;
	union {
		uint32_t	pad32_flag[2];
		uint64_t	pad64_flag;
	} oflag;
} __once_t;

#define	once_flag	oflag.pad32_flag[1]

static int
_thr_setinherit(pthread_t tid, int inherit)
{
	ulwp_t *ulwp;
	int error = 0;

	if ((ulwp = find_lwp(tid)) == NULL) {
		error = ESRCH;
	} else {
		ulwp->ul_ptinherit = inherit;
		ulwp_unlock(ulwp, curthread->ul_uberdata);
	}

	return (error);
}

static int
_thr_setparam(pthread_t tid, int policy, int prio)
{
	ulwp_t *ulwp;
	id_t cid;
	int error = 0;

	if ((ulwp = find_lwp(tid)) == NULL) {
		error = ESRCH;
	} else {
		if (policy == ulwp->ul_policy &&
		    (policy == SCHED_FIFO || policy == SCHED_RR) &&
		    ulwp->ul_epri != 0) {
			/*
			 * Don't change the ceiling priority,
			 * just the base priority.
			 */
			if (prio > ulwp->ul_epri)
				error = EPERM;
			else
				ulwp->ul_pri = prio;
		} else if ((cid = setparam(P_LWPID, tid, policy, prio)) == -1) {
			error = errno;
		} else {
			if (policy == SCHED_FIFO || policy == SCHED_RR)
				ulwp->ul_rtclassid = cid;
			ulwp->ul_cid = cid;
			ulwp->ul_pri = prio;
			membar_producer();
			ulwp->ul_policy = policy;
		}
		ulwp_unlock(ulwp, curthread->ul_uberdata);
	}
	return (error);
}

/*
 * pthread_create: creates a thread in the current process.
 * calls common _thrp_create() after copying the attributes.
 */
#pragma weak _pthread_create = pthread_create
int
pthread_create(pthread_t *thread, const pthread_attr_t *attr,
    void * (*start_routine)(void *), void *arg)
{
	ulwp_t		*self = curthread;
	const thrattr_t	*ap = attr? attr->__pthread_attrp : def_thrattr();
	const pcclass_t	*pccp;
	long		flag;
	pthread_t	tid;
	int		error;

	update_sched(self);

	if (ap == NULL)
		return (EINVAL);

	/* validate explicit scheduling attributes */
	if (ap->inherit == PTHREAD_EXPLICIT_SCHED &&
	    (ap->policy == SCHED_SYS ||
	    (pccp = get_info_by_policy(ap->policy)) == NULL ||
	    ap->prio < pccp->pcc_primin || ap->prio > pccp->pcc_primax))
		return (EINVAL);

	flag = ap->scope | ap->detachstate | ap->daemonstate | THR_SUSPENDED;
	error = _thrp_create(ap->stkaddr, ap->stksize, start_routine, arg,
	    flag, &tid, ap->guardsize);
	if (error == 0) {
		/*
		 * Record the original inheritence value for
		 * pthread_getattr_np(). We should always be able to find the
		 * thread.
		 */
		(void) _thr_setinherit(tid, ap->inherit);

		if (ap->inherit == PTHREAD_EXPLICIT_SCHED &&
		    (ap->policy != self->ul_policy ||
		    ap->prio != (self->ul_epri ? self->ul_epri :
		    self->ul_pri))) {
			/*
			 * The SUSv3 specification requires pthread_create()
			 * to fail with EPERM if it cannot set the scheduling
			 * policy and parameters on the new thread.
			 */
			error = _thr_setparam(tid, ap->policy, ap->prio);
		}

		if (error) {
			/*
			 * We couldn't determine this error before
			 * actually creating the thread.  To recover,
			 * mark the thread detached and cancel it.
			 * It is as though it was never created.
			 */
			ulwp_t *ulwp = find_lwp(tid);
			if (ulwp->ul_detached == 0) {
				ulwp->ul_detached = 1;
				ulwp->ul_usropts |= THR_DETACHED;
				(void) __lwp_detach(tid);
			}
			ulwp->ul_cancel_pending = 2; /* cancelled on creation */
			ulwp->ul_cancel_disabled = 0;
			ulwp_unlock(ulwp, self->ul_uberdata);
		} else if (thread) {
			*thread = tid;
		}
		(void) thr_continue(tid);
	}

	/* posix version expects EAGAIN for lack of memory */
	if (error == ENOMEM)
		error = EAGAIN;
	return (error);
}

/*
 * pthread_once: calls given function only once.
 * it synchronizes via mutex in pthread_once_t structure
 */
int
pthread_once(pthread_once_t *once_control, void (*init_routine)(void))
{
	__once_t *once = (__once_t *)once_control;

	if (once == NULL || init_routine == NULL)
		return (EINVAL);

	if (once->once_flag == PTHREAD_ONCE_NOTDONE) {
		(void) mutex_lock(&once->mlock);
		if (once->once_flag == PTHREAD_ONCE_NOTDONE) {
			pthread_cleanup_push(mutex_unlock, &once->mlock);
			(*init_routine)();
			pthread_cleanup_pop(0);
			membar_producer();
			once->once_flag = PTHREAD_ONCE_DONE;
		}
		(void) mutex_unlock(&once->mlock);
	}
	membar_consumer();

	return (0);
}

/*
 * pthread_equal: equates two thread ids.
 */
int
pthread_equal(pthread_t t1, pthread_t t2)
{
	return (t1 == t2);
}

/*
 * pthread_getschedparam: get the thread's sched parameters.
 */
#pragma weak _pthread_getschedparam = pthread_getschedparam
int
pthread_getschedparam(pthread_t tid, int *policy, struct sched_param *param)
{
	ulwp_t *ulwp;
	id_t cid;
	int error = 0;

	if ((ulwp = find_lwp(tid)) == NULL) {
		error = ESRCH;
	} else {
		cid = getparam(P_LWPID, ulwp->ul_lwpid, policy, param);
		if (cid == -1) {
			error = errno;
		} else if (*policy == ulwp->ul_policy && cid == ulwp->ul_cid &&
		    (*policy == SCHED_FIFO || *policy == SCHED_RR)) {
			/*
			 * Return the defined priority, not the effective
			 * priority from priority ceiling mutexes.
			 */
			param->sched_priority = ulwp->ul_pri;
		} else {
			if (*policy == SCHED_FIFO || *policy == SCHED_RR)
				ulwp->ul_rtclassid = cid;
			ulwp->ul_cid = cid;
			ulwp->ul_pri = param->sched_priority;
			membar_producer();
			ulwp->ul_policy = *policy;
		}
		ulwp_unlock(ulwp, curthread->ul_uberdata);
	}

	return (error);
}

#pragma weak _thr_getprio = thr_getprio
int
thr_getprio(thread_t tid, int *priority)
{
	struct sched_param param;
	int policy;
	int error;

	if ((error = pthread_getschedparam(tid, &policy, &param)) == 0)
		*priority = param.sched_priority;
	return (error);
}

/*
 * pthread_setschedparam: sets the sched parameters for a thread.
 */
int
pthread_setschedparam(pthread_t tid,
    int policy, const struct sched_param *param)
{
	return (_thr_setparam(tid, policy, param->sched_priority));
}

#pragma weak pthread_setschedprio = thr_setprio
int
thr_setprio(thread_t tid, int prio)
{
	struct sched_param param;
	int policy;
	int error;

	/*
	 * pthread_getschedparam() has the side-effect of setting
	 * the target thread's ul_policy, ul_pri and ul_cid correctly.
	 */
	if ((error = pthread_getschedparam(tid, &policy, &param)) != 0)
		return (error);
	if (param.sched_priority == prio)	/* no change */
		return (0);
	return (_thr_setparam(tid, policy, prio));
}
