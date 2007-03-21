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

/*
 * pthread_create: creates a thread in the current process.
 * calls common _thrp_create() after copying the attributes.
 */
#pragma weak	pthread_create			= _pthread_create
int
_pthread_create(pthread_t *thread, const pthread_attr_t *attr,
	void * (*start_routine)(void *), void *arg)
{
	ulwp_t		*self = curthread;
	uberdata_t	*udp = self->ul_uberdata;
	const thrattr_t	*ap = attr? attr->__pthread_attrp : def_thrattr();
	long		flag;
	pthread_t	tid;
	int		policy;
	pri_t		priority;
	int		error;
	int		mapped = 0;
	int		mappedpri;
	int		rt = 0;

	if (ap == NULL)
		return (EINVAL);

	if (ap->inherit == PTHREAD_INHERIT_SCHED) {
		policy = self->ul_policy;
		priority = self->ul_pri;
		mapped = self->ul_pri_mapped;
		mappedpri = self->ul_mappedpri;
	} else {
		policy = ap->policy;
		priority = ap->prio;
		if (policy == SCHED_OTHER) {
			if (priority < THREAD_MIN_PRIORITY ||
			    priority > THREAD_MAX_PRIORITY) {
				if (_validate_rt_prio(policy, priority))
					return (EINVAL);
				mapped = 1;
				mappedpri = priority;
				priority = map_rtpri_to_gp(priority);
				ASSERT(priority >= THREAD_MIN_PRIORITY &&
				    priority <= THREAD_MAX_PRIORITY);
			}
		} else if (policy == SCHED_FIFO || policy == SCHED_RR) {
			if (_validate_rt_prio(policy, priority))
				return (EINVAL);
			if (_private_geteuid() == 0)
				rt = 1;
		} else {
			return (EINVAL);
		}
	}

	flag = ap->scope | ap->detachstate | ap->daemonstate | THR_SUSPENDED;
	error = _thrp_create(ap->stkaddr, ap->stksize, start_routine, arg,
		flag, &tid, priority, policy, ap->guardsize);
	if (error == 0) {
		int prio_err;

		if (mapped) {
			ulwp_t *ulwp = find_lwp(tid);
			ulwp->ul_pri_mapped = 1;
			ulwp->ul_mappedpri = mappedpri;
			ulwp_unlock(ulwp, udp);
		}

		if (rt && (prio_err = _thrp_setlwpprio(tid, policy, priority)))
			return (prio_err);

		if (thread)
			*thread = tid;
		(void) _thr_continue(tid);
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
#pragma weak	pthread_once			= _pthread_once
int
_pthread_once(pthread_once_t *once_control, void (*init_routine)(void))
{
	__once_t *once = (__once_t *)once_control;

	if (once == NULL || init_routine == NULL)
		return (EINVAL);

	if (once->once_flag == PTHREAD_ONCE_NOTDONE) {
		(void) _private_mutex_lock(&once->mlock);
		if (once->once_flag == PTHREAD_ONCE_NOTDONE) {
			pthread_cleanup_push(_private_mutex_unlock,
			    &once->mlock);
			(*init_routine)();
			pthread_cleanup_pop(0);
			_membar_producer();
			once->once_flag = PTHREAD_ONCE_DONE;
		}
		(void) _private_mutex_unlock(&once->mlock);
	}
	_membar_consumer();

	return (0);
}

/*
 * pthread_equal: equates two thread ids.
 */
#pragma weak	pthread_equal			= _pthread_equal
int
_pthread_equal(pthread_t t1, pthread_t t2)
{
	return (t1 == t2);
}

/*
 * pthread_getschedparam: gets the sched parameters in a struct.
 */
#pragma weak	pthread_getschedparam		= _pthread_getschedparam
int
_pthread_getschedparam(pthread_t tid, int *policy, struct sched_param *param)
{
	uberdata_t *udp = curthread->ul_uberdata;
	ulwp_t *ulwp;
	int error = 0;

	if (param == NULL || policy == NULL)
		error = EINVAL;
	else if ((ulwp = find_lwp(tid)) == NULL)
		error = ESRCH;
	else {
		if (ulwp->ul_pri_mapped)
			param->sched_priority = ulwp->ul_mappedpri;
		else
			param->sched_priority = ulwp->ul_pri;
		*policy = ulwp->ul_policy;
		ulwp_unlock(ulwp, udp);
	}

	return (error);
}

/*
 * Besides the obvious arguments, the inheritflag needs to be explained:
 * If set to PRIO_SET or PRIO_SET_PRIO, it does the normal, expected work
 * of setting thread's assigned scheduling parameters and policy.
 * If set to PRIO_INHERIT, it sets the thread's effective priority values
 * (t_epri, t_empappedpri), and does not update the assigned priority values
 * (t_pri, t_mappedpri).  If set to PRIO_DISINHERIT, it clears the thread's
 * effective priority values, and reverts the thread, if necessary, back
 * to the assigned priority values.
 */
int
_thread_setschedparam_main(pthread_t tid, int policy,
    const struct sched_param *param, int inheritflag)
{
	uberdata_t *udp = curthread->ul_uberdata;
	ulwp_t	*ulwp;
	int	error = 0;
	int	prio;
	int	opolicy;
	int	mappedprio;
	int	mapped = 0;
	pri_t	*mappedprip;

	if (param == NULL)
		return (EINVAL);
	if ((ulwp = find_lwp(tid)) == NULL)
		return (ESRCH);
	prio = param->sched_priority;
	opolicy = ulwp->ul_policy;
	if (inheritflag == PRIO_SET_PRIO) {	/* don't change policy */
		policy = opolicy;
		inheritflag = PRIO_SET;
	}
	ASSERT(inheritflag == PRIO_SET || opolicy == policy);
	if (inheritflag == PRIO_DISINHERIT) {
		ulwp->ul_emappedpri = 0;
		ulwp->ul_epri = 0;
		prio = ulwp->ul_pri;	/* ignore prio in sched_param */
	}
	if (policy == SCHED_OTHER) {
		/*
		 * Set thread's policy to OTHER
		 */
		if (prio < THREAD_MIN_PRIORITY || prio > THREAD_MAX_PRIORITY) {
			if (_validate_rt_prio(policy, prio)) {
				error = EINVAL;
				goto out;
			}
			mapped = 1;
			mappedprio = prio;
			prio = map_rtpri_to_gp(prio);
			ASSERT(prio >= THREAD_MIN_PRIORITY &&
			    prio <= THREAD_MAX_PRIORITY);
		}
		/*
		 * Thread changing from FIFO/RR to OTHER
		 */
		if (opolicy == SCHED_FIFO || opolicy == SCHED_RR) {
			if ((error = _thrp_setlwpprio(tid, policy, prio)) != 0)
				goto out;
		}
		if (inheritflag != PRIO_DISINHERIT) {
			if (inheritflag == PRIO_INHERIT)
				mappedprip = &ulwp->ul_emappedpri;
			else
				mappedprip = &ulwp->ul_mappedpri;
			if (mapped) {
				ulwp->ul_pri_mapped = 1;
				*mappedprip = mappedprio;
			} else {
				ulwp->ul_pri_mapped = 0;
				*mappedprip = 0;
			}
		}
		ulwp->ul_policy = policy;
		if (inheritflag == PRIO_INHERIT)
			ulwp->ul_epri = prio;
		else
			ulwp->ul_pri = prio;
	} else if (policy == SCHED_FIFO || policy == SCHED_RR) {
		if (_validate_rt_prio(policy, prio))
			error = EINVAL;
		else {
			int prio_err;

			if (_private_geteuid() == 0 &&
			    (prio_err = _thrp_setlwpprio(tid, policy, prio))) {
				error = prio_err;
				goto out;
			}

			ulwp->ul_policy = policy;
			if (inheritflag == PRIO_INHERIT)
				ulwp->ul_epri = prio;
			else
				ulwp->ul_pri = prio;
		}
	} else {
		error = EINVAL;
	}

out:
	ulwp_unlock(ulwp, udp);
	return (error);
}

/*
 * pthread_setschedparam: sets the sched parameters for a thread.
 */
#pragma weak	pthread_setschedparam		= _pthread_setschedparam
int
_pthread_setschedparam(pthread_t tid,
	int policy, const struct sched_param *param)
{
	return (_thread_setschedparam_main(tid, policy, param, PRIO_SET));
}
