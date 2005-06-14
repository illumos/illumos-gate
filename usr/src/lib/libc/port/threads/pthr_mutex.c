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
 * Copyright 1999-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "lint.h"
#include "thr_uberdata.h"
#include <pthread.h>

/*
 * pthread_mutexattr_init: allocates the mutex attribute object and
 * initializes it with the default values.
 */
#pragma weak pthread_mutexattr_init = _pthread_mutexattr_init
int
_pthread_mutexattr_init(pthread_mutexattr_t *attr)
{
	mattr_t	*ap;

	if ((ap = lmalloc(sizeof (mattr_t))) == NULL)
		return (ENOMEM);
	ap->pshared = DEFAULT_TYPE;
	ap->type = PTHREAD_MUTEX_DEFAULT;
	ap->protocol = PTHREAD_PRIO_NONE;
	ap->robustness = PTHREAD_MUTEX_STALL_NP;
	attr->__pthread_mutexattrp = ap;
	return (0);
}

/*
 * pthread_mutexattr_destroy: frees the mutex attribute object and
 * invalidates it with NULL value.
 */
#pragma weak pthread_mutexattr_destroy =  _pthread_mutexattr_destroy
int
_pthread_mutexattr_destroy(pthread_mutexattr_t *attr)
{
	if (attr == NULL || attr->__pthread_mutexattrp == NULL)
		return (EINVAL);
	lfree(attr->__pthread_mutexattrp, sizeof (mattr_t));
	attr->__pthread_mutexattrp = NULL;
	return (0);
}

/*
 * pthread_mutexattr_setpshared: sets the shared attr to PRIVATE or SHARED.
 * This is equivalent to setting USYNC_PROCESS/USYNC_THREAD flag in
 * mutex_init().
 */
#pragma weak pthread_mutexattr_setpshared =  _pthread_mutexattr_setpshared
int
_pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    (pshared != PTHREAD_PROCESS_PRIVATE &&
	    pshared != PTHREAD_PROCESS_SHARED))
		return (EINVAL);
	ap->pshared = pshared;
	return (0);
}

/*
 * pthread_mutexattr_getpshared: gets the shared attr.
 */
#pragma weak pthread_mutexattr_getpshared =  _pthread_mutexattr_getpshared
int
_pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr, int *pshared)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    pshared == NULL)
		return (EINVAL);
	*pshared = ap->pshared;
	return (0);
}

/*
 * pthread_mutexattr_setprioceiling: sets the prioceiling attr.
 */
#pragma weak pthread_mutexattr_setprioceiling = \
					_pthread_mutexattr_setprioceiling
int
_pthread_mutexattr_setprioceiling(pthread_mutexattr_t *attr, int prioceiling)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    _validate_rt_prio(SCHED_FIFO, prioceiling))
		return (EINVAL);
	ap->prioceiling = prioceiling;
	return (0);
}

/*
 * pthread_mutexattr_getprioceiling: gets the prioceiling attr.
 * Currently unsupported.
 */
#pragma weak pthread_mutexattr_getprioceiling = \
					_pthread_mutexattr_getprioceiling
int
_pthread_mutexattr_getprioceiling(const pthread_mutexattr_t *attr, int *ceiling)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    ceiling == NULL)
		return (EINVAL);
	*ceiling = ap->prioceiling;
	return (0);
}

/*
 * pthread_mutexattr_setprotocol: sets the protocol attribute.
 * Currently unsupported.
 */
#pragma weak pthread_mutexattr_setprotocol =  _pthread_mutexattr_setprotocol
int
_pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr, int protocol)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL)
		return (EINVAL);
	if (protocol != PTHREAD_PRIO_NONE &&
	    protocol != PTHREAD_PRIO_INHERIT &&
	    protocol != PTHREAD_PRIO_PROTECT)
		return (ENOTSUP);
	ap->protocol = protocol;
	return (0);
}

/*
 * pthread_mutexattr_getprotocol: gets the protocol attribute.
 * Currently unsupported.
 */
#pragma weak pthread_mutexattr_getprotocol =  _pthread_mutexattr_getprotocol
int
_pthread_mutexattr_getprotocol(const pthread_mutexattr_t *attr, int *protocol)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    protocol == NULL)
		return (EINVAL);
	*protocol = ap->protocol;
	return (0);
}

/*
 * pthread_mutexattr_setrobust_np: sets the robustness attr to ROBUST or STALL.
 */
#pragma weak pthread_mutexattr_setrobust_np = \
					_pthread_mutexattr_setrobust_np
int
_pthread_mutexattr_setrobust_np(pthread_mutexattr_t *attr, int robust)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    (robust != PTHREAD_MUTEX_ROBUST_NP &&
	    robust != PTHREAD_MUTEX_STALL_NP))
		return (EINVAL);
	ap->robustness = robust;
	return (0);
}

/*
 * pthread_mutexattr_getrobust_np: gets the robustness attr.
 */
#pragma weak pthread_mutexattr_getrobust_np = \
					_pthread_mutexattr_getrobust_np
int
_pthread_mutexattr_getrobust_np(const pthread_mutexattr_t *attr, int *robust)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    robust == NULL)
		return (EINVAL);
	*robust = ap->robustness;
	return (0);
}

/*
 * pthread_mutex_consistent_np: make an inconsistent mutex consistent.
 * The mutex must have been made inconsistent due to the last owner of it
 * having died. Currently, no validation is done to check if:
 *      - the caller owns the mutex
 * Since this function is supported only for PI/robust locks, to check
 * if the caller owns the mutex, one needs to call the kernel. For now,
 * such extra validation does not seem necessary.
 */
#pragma weak pthread_mutex_consistent_np = _pthread_mutex_consistent_np
int
_pthread_mutex_consistent_np(pthread_mutex_t *pmp)
{
	mutex_t *mp = (mutex_t *)pmp;

	/*
	 * Do this only for an inconsistent, initialized, PI, Robust lock.
	 * For all other cases, return EINVAL.
	 */
	if ((mp->mutex_type & PTHREAD_PRIO_INHERIT) &&
	    (mp->mutex_type & PTHREAD_MUTEX_ROBUST_NP) &&
	    (mp->mutex_flag & LOCK_INITED) &&
	    (mp->mutex_flag & LOCK_OWNERDEAD)) {
		mp->mutex_flag &= ~LOCK_OWNERDEAD;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_mutex_init: Initializes the mutex object. It copies the
 * pshared attr into type argument and calls mutex_init().
 */
#pragma weak pthread_mutex_init = _pthread_mutex_init
int
_pthread_mutex_init(pthread_mutex_t *mutex, pthread_mutexattr_t *attr)
{
	mutex_t *mp = (mutex_t *)mutex;
	int	type;
	int	pshared;
	int	protocol;
	int	prioceiling = 0;
	int	robust;
	int	error;
	mattr_t *ap;

	if (attr != NULL) {
		if ((ap = attr->__pthread_mutexattrp) == NULL)
			return (EINVAL);
		pshared = ap->pshared;
		type = ap->type;
		protocol = ap->protocol;
		if (protocol == PTHREAD_PRIO_PROTECT)
			prioceiling = ap->prioceiling;
		robust = ap->robustness;
		/*
		 * Support robust mutexes only for PI locks.
		 */
		if (robust == PTHREAD_MUTEX_ROBUST_NP &&
		    protocol != PTHREAD_PRIO_INHERIT)
			return (EINVAL);
	} else {
		pshared = DEFAULT_TYPE;
		type = PTHREAD_MUTEX_DEFAULT;
		protocol = PTHREAD_PRIO_NONE;
		robust = PTHREAD_MUTEX_STALL_NP;
	}

	error = _private_mutex_init(mp, pshared, NULL);
	if (error == 0) {
		/*
		 * Use the same routine to set the protocol, and robustness
		 * attributes, as that used to set the type attribute, since
		 * all of these attributes translate to bits in the mutex_type
		 * field.
		 *
		 * Note that robustness is a new bit, not the Solaris robust
		 * bit - the latter implies USYNC_PROCESS_ROBUST, or
		 * SHARED,ROBUST together. For POSIX, since robustness is an
		 * orthogonal attribute, both SHARED,ROBUST and PRIVATE,ROBUST
		 * should be valid combinations for the future. Hence,
		 * introduce a new bit in the mutex type field. See
		 * sys/synch.h or pthread.h. In the future, if we ever
		 * introduce a USYNC_THREAD_ROBUST, the latter could use this
		 * new bit...
		 */
		_mutex_set_typeattr(mp, type|protocol|robust);
		mp->mutex_ceiling = (uint8_t)prioceiling;
	}
	return (error);
}

/*
 * pthread_mutex_setprioceiling: sets the prioceiling.
 */
#pragma weak pthread_mutex_setprioceiling =  _pthread_mutex_setprioceiling
int
_pthread_mutex_setprioceiling(pthread_mutex_t *mutex, int ceil, int *oceil)
{
	mutex_t *mp = (mutex_t *)mutex;
	int error;

	if (!(mp->mutex_type & PTHREAD_PRIO_PROTECT) ||
	    _validate_rt_prio(SCHED_FIFO, ceil) != 0)
		return (EINVAL);
	error = _private_mutex_lock(mp);
	if (error == 0) {
		if (oceil)
			*oceil = mp->mutex_ceiling;
		mp->mutex_ceiling = (uint8_t)ceil;
		error = _private_mutex_unlock(mp);
	}
	return (error);
}

/*
 * pthread_mutex_getprioceiling: gets the prioceiling.
 */
#pragma weak pthread_mutex_getprioceiling =  _pthread_mutex_getprioceiling
int
_pthread_mutex_getprioceiling(const pthread_mutex_t *mp, int *ceiling)
{
	*ceiling = ((mutex_t *)mp)->mutex_ceiling;
	return (0);
}

/*
 * UNIX98
 * pthread_mutexattr_settype: sets the type attribute
 */
#pragma weak pthread_mutexattr_settype =  _pthread_mutexattr_settype
int
_pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL)
		return (EINVAL);
	switch (type) {
	case PTHREAD_MUTEX_NORMAL:
		type = LOCK_NORMAL;
		break;
	case PTHREAD_MUTEX_ERRORCHECK:
		type = LOCK_ERRORCHECK;
		break;
	case PTHREAD_MUTEX_RECURSIVE:
		type = LOCK_RECURSIVE|LOCK_ERRORCHECK;
		break;
	default:
		return (EINVAL);
	}
	ap->type = type;
	return (0);
}

/*
 * UNIX98
 * pthread_mutexattr_gettype: gets the type attr.
 */
#pragma weak pthread_mutexattr_gettype =  _pthread_mutexattr_gettype
int
_pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *typep)
{
	mattr_t	*ap;
	int type;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    typep == NULL)
		return (EINVAL);
	switch (ap->type) {
	case LOCK_NORMAL:
		type = PTHREAD_MUTEX_NORMAL;
		break;
	case LOCK_ERRORCHECK:
		type = PTHREAD_MUTEX_ERRORCHECK;
		break;
	case LOCK_RECURSIVE|LOCK_ERRORCHECK:
		type = PTHREAD_MUTEX_RECURSIVE;
		break;
	default:
		return (EINVAL);
	}
	*typep = type;
	return (0);
}
