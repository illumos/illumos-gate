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

#include "lint.h"
#include "thr_uberdata.h"
#include <pthread.h>

/*
 * Implementation-private attribute structure (for extensibility).
 */
typedef struct {
	int	pshared;
} barrierattr_t;

int
pthread_barrierattr_init(pthread_barrierattr_t *attr)
{
	barrierattr_t *ap;

	if ((ap = lmalloc(sizeof (barrierattr_t))) == NULL)
		return (ENOMEM);
	ap->pshared = PTHREAD_PROCESS_PRIVATE;
	attr->__pthread_barrierattrp = ap;
	return (0);
}

int
pthread_barrierattr_destroy(pthread_barrierattr_t *attr)
{
	if (attr == NULL || attr->__pthread_barrierattrp == NULL)
		return (EINVAL);
	lfree(attr->__pthread_barrierattrp, sizeof (barrierattr_t));
	attr->__pthread_barrierattrp = NULL;
	return (0);
}

int
pthread_barrierattr_setpshared(pthread_barrierattr_t *attr, int pshared)
{
	barrierattr_t *ap;

	if (attr == NULL || (ap = attr->__pthread_barrierattrp) == NULL ||
	    (pshared != PTHREAD_PROCESS_PRIVATE &&
	    pshared != PTHREAD_PROCESS_SHARED))
		return (EINVAL);
	ap->pshared = pshared;
	return (0);
}

int
pthread_barrierattr_getpshared(const pthread_barrierattr_t *attr, int *pshared)
{
	barrierattr_t *ap;

	if (attr == NULL || (ap = attr->__pthread_barrierattrp) == NULL ||
	    pshared == NULL)
		return (EINVAL);
	*pshared = ap->pshared;
	return (0);
}

int
pthread_barrier_init(pthread_barrier_t *barrier,
    const pthread_barrierattr_t *attr, uint_t count)
{
	mutex_t *mp = (mutex_t *)&barrier->__pthread_barrier_lock;
	cond_t *cvp = (cond_t *)&barrier->__pthread_barrier_cond;
	barrierattr_t *ap;
	int type;

	if (attr == NULL)
		type = PTHREAD_PROCESS_PRIVATE;
	else if ((ap = attr->__pthread_barrierattrp) != NULL)
		type = ap->pshared;
	else
		type = -1;

	if (count == 0 ||
	    (type != PTHREAD_PROCESS_PRIVATE && type != PTHREAD_PROCESS_SHARED))
		return (EINVAL);

	barrier->__pthread_barrier_count = count;
	barrier->__pthread_barrier_current = count;
	barrier->__pthread_barrier_cycle = 0;
	barrier->__pthread_barrier_reserved = 0;
	(void) mutex_init(mp, type, NULL);
	(void) cond_init(cvp, type, NULL);

	/*
	 * This should be at the beginning of the function,
	 * but for the sake of old broken applications that
	 * do not have proper alignment for their barriers
	 * (and don't check the return code from pthread_barrier_init),
	 * we put it here, after initializing the barrier regardless.
	 */
	if (((uintptr_t)barrier & (_LONG_LONG_ALIGNMENT - 1)) &&
	    curthread->ul_misaligned == 0)
		return (EINVAL);

	return (0);
}

int
pthread_barrier_destroy(pthread_barrier_t *barrier)
{
	mutex_t *mp = (mutex_t *)&barrier->__pthread_barrier_lock;
	cond_t *cvp = (cond_t *)&barrier->__pthread_barrier_cond;

	(void) mutex_destroy(mp);
	(void) cond_destroy(cvp);
	(void) memset(barrier, -1, sizeof (*barrier));
	return (0);
}

/*
 * pthread_barrier_wait() is not a cancellation point;
 */
int
pthread_barrier_wait(pthread_barrier_t *barrier)
{
	mutex_t *mp = (mutex_t *)&barrier->__pthread_barrier_lock;
	cond_t *cvp = (cond_t *)&barrier->__pthread_barrier_cond;
	uint64_t cycle;
	int cancel_state;

	(void) mutex_lock(mp);

	if (--barrier->__pthread_barrier_current == 0) {
		barrier->__pthread_barrier_cycle++;
		barrier->__pthread_barrier_current =
		    barrier->__pthread_barrier_count;
		(void) mutex_unlock(mp);
		(void) cond_broadcast(cvp);
		return (PTHREAD_BARRIER_SERIAL_THREAD);
	}

	(void) pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	cycle = barrier->__pthread_barrier_cycle;
	do {
		(void) cond_wait(cvp, mp);
	} while (cycle == barrier->__pthread_barrier_cycle);
	(void) pthread_setcancelstate(cancel_state, NULL);

	(void) mutex_unlock(mp);
	return (0);
}
