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
#include <pthread.h>

/*
 * Implementation-private attribute structure (for extensibility).
 */
typedef struct {
	int	pshared;
} barrierattr_t;

#pragma weak pthread_barrierattr_init = _pthread_barrierattr_init
int
_pthread_barrierattr_init(pthread_barrierattr_t *attr)
{
	barrierattr_t *ap;

	if ((ap = lmalloc(sizeof (barrierattr_t))) == NULL)
		return (ENOMEM);
	ap->pshared = PTHREAD_PROCESS_PRIVATE;
	attr->__pthread_barrierattrp = ap;
	return (0);
}

#pragma weak pthread_barrierattr_destroy = _pthread_barrierattr_destroy
int
_pthread_barrierattr_destroy(pthread_barrierattr_t *attr)
{
	if (attr == NULL || attr->__pthread_barrierattrp == NULL)
		return (EINVAL);
	lfree(attr->__pthread_barrierattrp, sizeof (barrierattr_t));
	attr->__pthread_barrierattrp = NULL;
	return (0);
}

#pragma weak pthread_barrierattr_setpshared =  _pthread_barrierattr_setpshared
int
_pthread_barrierattr_setpshared(pthread_barrierattr_t *attr, int pshared)
{
	barrierattr_t *ap;

	if (attr == NULL || (ap = attr->__pthread_barrierattrp) == NULL ||
	    (pshared != PTHREAD_PROCESS_PRIVATE &&
	    pshared != PTHREAD_PROCESS_SHARED))
		return (EINVAL);
	ap->pshared = pshared;
	return (0);
}

#pragma weak pthread_barrierattr_getpshared =  _pthread_barrierattr_getpshared
int
_pthread_barrierattr_getpshared(const pthread_barrierattr_t *attr, int *pshared)
{
	barrierattr_t *ap;

	if (attr == NULL || (ap = attr->__pthread_barrierattrp) == NULL ||
	    pshared == NULL)
		return (EINVAL);
	*pshared = ap->pshared;
	return (0);
}

#pragma weak pthread_barrier_init = _pthread_barrier_init
int
_pthread_barrier_init(pthread_barrier_t *barrier,
	const pthread_barrierattr_t *attr, uint_t count)
{
	mutex_t *mp = (mutex_t *)&barrier->__pthread_barrier_lock;
	cond_t *cvp = (cond_t *)&barrier->__pthread_barrier_cond;
	barrierattr_t *ap;
	int type;

	if (attr == NULL)
		type = DEFAULT_TYPE;
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
	(void) __mutex_init(mp, type, NULL);
	(void) _cond_init(cvp, type, NULL);
	return (0);
}

#pragma weak pthread_barrier_destroy = _pthread_barrier_destroy
int
_pthread_barrier_destroy(pthread_barrier_t *barrier)
{
	mutex_t *mp = (mutex_t *)&barrier->__pthread_barrier_lock;
	cond_t *cvp = (cond_t *)&barrier->__pthread_barrier_cond;

	(void) __mutex_destroy(mp);
	(void) _cond_destroy(cvp);
	(void) memset(barrier, -1, sizeof (*barrier));
	return (0);
}

/*
 * pthread_barrier_wait() is not a cancellation point;
 */
#pragma weak pthread_barrier_wait = _pthread_barrier_wait
int
_pthread_barrier_wait(pthread_barrier_t *barrier)
{
	mutex_t *mp = (mutex_t *)&barrier->__pthread_barrier_lock;
	cond_t *cvp = (cond_t *)&barrier->__pthread_barrier_cond;
	uint64_t cycle;
	int cancel_state;

	(void) __mutex_lock(mp);

	if (--barrier->__pthread_barrier_current == 0) {
		barrier->__pthread_barrier_cycle++;
		barrier->__pthread_barrier_current =
		    barrier->__pthread_barrier_count;
		(void) __mutex_unlock(mp);
		(void) _cond_broadcast(cvp);
		return (PTHREAD_BARRIER_SERIAL_THREAD);
	}

	(void) _pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancel_state);
	cycle = barrier->__pthread_barrier_cycle;
	do {
		(void) _cond_wait(cvp, mp);
	} while (cycle == barrier->__pthread_barrier_cycle);
	(void) _pthread_setcancelstate(cancel_state, NULL);

	(void) __mutex_unlock(mp);
	return (0);
}
