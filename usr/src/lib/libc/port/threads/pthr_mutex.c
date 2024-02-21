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
 * pthread_mutexattr_init: allocates the mutex attribute object and
 * initializes it with the default values.
 */
#pragma weak _pthread_mutexattr_init = pthread_mutexattr_init
int
pthread_mutexattr_init(pthread_mutexattr_t *attr)
{
	mattr_t	*ap;

	if ((ap = lmalloc(sizeof (mattr_t))) == NULL)
		return (ENOMEM);
	ap->pshared = PTHREAD_PROCESS_PRIVATE;
	ap->type = PTHREAD_MUTEX_DEFAULT;
	ap->protocol = PTHREAD_PRIO_NONE;
	ap->robustness = PTHREAD_MUTEX_STALLED;
	attr->__pthread_mutexattrp = ap;
	return (0);
}

/*
 * pthread_mutexattr_destroy: frees the mutex attribute object and
 * invalidates it with NULL value.
 */
int
pthread_mutexattr_destroy(pthread_mutexattr_t *attr)
{
	if (attr == NULL || attr->__pthread_mutexattrp == NULL)
		return (EINVAL);
	lfree(attr->__pthread_mutexattrp, sizeof (mattr_t));
	attr->__pthread_mutexattrp = NULL;
	return (0);
}

/*
 * pthread_mutexattr_setpshared: sets the shared attribute
 * to PTHREAD_PROCESS_PRIVATE or PTHREAD_PROCESS_SHARED.
 * This is equivalent to setting the USYNC_THREAD/USYNC_PROCESS
 * flag in mutex_init().
 */
int
pthread_mutexattr_setpshared(pthread_mutexattr_t *attr, int pshared)
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
 * pthread_mutexattr_getpshared: gets the shared attribute.
 */
#pragma weak _pthread_mutexattr_getpshared = pthread_mutexattr_getpshared
int
pthread_mutexattr_getpshared(const pthread_mutexattr_t *attr, int *pshared)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    pshared == NULL)
		return (EINVAL);
	*pshared = ap->pshared;
	return (0);
}

/*
 * pthread_mutexattr_setprioceiling: sets the prioceiling attribute.
 */
int
pthread_mutexattr_setprioceiling(pthread_mutexattr_t *attr, int prioceiling)
{
	const pcclass_t *pccp = get_info_by_policy(SCHED_FIFO);
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    prioceiling < pccp->pcc_primin || prioceiling > pccp->pcc_primax)
		return (EINVAL);
	ap->prioceiling = prioceiling;
	return (0);
}

/*
 * pthread_mutexattr_getprioceiling: gets the prioceiling attribute.
 */
#pragma weak _pthread_mutexattr_getprioceiling = \
			pthread_mutexattr_getprioceiling
int
pthread_mutexattr_getprioceiling(const pthread_mutexattr_t *attr, int *ceiling)
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
 */
int
pthread_mutexattr_setprotocol(pthread_mutexattr_t *attr, int protocol)
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
 */
#pragma weak _pthread_mutexattr_getprotocol = pthread_mutexattr_getprotocol
int
pthread_mutexattr_getprotocol(const pthread_mutexattr_t *attr, int *protocol)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    protocol == NULL)
		return (EINVAL);
	*protocol = ap->protocol;
	return (0);
}

/*
 * pthread_mutexattr_setrobust: set the mutex robust attribute.
 * pthread_mutexattr_setrobust_np: the historical name.
 */
#pragma weak pthread_mutexattr_setrobust_np = pthread_mutexattr_setrobust
int
pthread_mutexattr_setrobust(pthread_mutexattr_t *attr, int robust)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    (robust != PTHREAD_MUTEX_ROBUST && robust != PTHREAD_MUTEX_STALLED))
		return (EINVAL);
	ap->robustness = robust;
	return (0);
}

/*
 * pthread_mutexattr_getrobust: get the mutex robust attribute.
 * pthread_mutexattr_getrobust_np: the historical name.
 */
#pragma weak pthread_mutexattr_getrobust_np = pthread_mutexattr_getrobust
int
pthread_mutexattr_getrobust(const pthread_mutexattr_t *attr, int *robust)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    robust == NULL)
		return (EINVAL);
	*robust = ap->robustness;
	return (0);
}

/*
 * pthread_mutex_init: Initializes the mutex object.  It copies the various
 * attributes into one type argument and calls mutex_init().  Unlike other
 * values, the types that are used in the mutex attributes are not 1:1 mapped to
 * our underlying lock types at this time so we can properly honor the semantics
 * of someone asking for a PTHREAD_MUTEX_NORMAL lock that must deadlock. The
 * underlying threads implementation does not do this by default for
 * USYNC_THREAD and so we don't do this unless explicitly asked for it.
 */
#pragma weak _pthread_mutex_init = pthread_mutex_init
int
pthread_mutex_init(pthread_mutex_t *_RESTRICT_KYWD mutex,
    const pthread_mutexattr_t *_RESTRICT_KYWD attr)
{
	mattr_t		*ap;
	int		type, ret;
	int		prioceiling = 0;
	uint16_t	flags = 0;

	/*
	 * All of the pshared, type, protocol, robust attributes
	 * translate to bits in the mutex_type field.
	 */
	if (attr != NULL) {
		if ((ap = attr->__pthread_mutexattrp) == NULL)
			return (EINVAL);
		switch (ap->type) {
		case PTHREAD_MUTEX_NORMAL:
			type = LOCK_NORMAL;
			flags = LOCK_DEADLOCK;
			break;
		case PTHREAD_MUTEX_ERRORCHECK:
			type = LOCK_ERRORCHECK;
			break;
		case PTHREAD_MUTEX_RECURSIVE:
			type = LOCK_RECURSIVE;
			break;
		default:
			/*
			 * This covers PTHREAD_MUTEX_DEFAULT, which should be
			 * the only remaining valid value.
			 */
			type = LOCK_NORMAL;
			break;
		}

		type |= ap->pshared | ap->protocol | ap->robustness;
		if (ap->protocol == PTHREAD_PRIO_PROTECT)
			prioceiling = ap->prioceiling;
	} else {
		type = PTHREAD_PROCESS_PRIVATE | LOCK_NORMAL |
		    PTHREAD_PRIO_NONE | PTHREAD_MUTEX_STALLED;
	}

	/*
	 * POSIX mutexes (this interface) make no guarantee about the state of
	 * the mutex before pthread_mutex_init(3C) is called.  Sun mutexes, upon
	 * which these are built and which mutex_init(3C) below represents
	 * require that a robust mutex be initialized to all 0s _prior_ to
	 * mutex_init() being called, and that mutex_init() of an initialized
	 * mutex return EBUSY.
	 *
	 * We respect both these behaviors by zeroing the mutex here in the
	 * POSIX implementation if and only if the mutex magic is incorrect,
	 * and the mutex is robust.
	 */
	if (((type & PTHREAD_MUTEX_ROBUST) != 0) &&
	    (((mutex_t *)mutex)->mutex_magic != MUTEX_MAGIC)) {
		(void) memset(mutex, 0, sizeof (*mutex));
	}

	ret = mutex_init((mutex_t *)mutex, type, &prioceiling);

	/*
	 * If we have a normal mutex, we need to set that deadlock behavior is
	 * required.
	 */
	if (ret == 0 && flags != 0) {
		mutex_t *mp = (mutex_t *)mutex;
		mp->mutex_flag |= flags;
	}

	return (ret);
}

/*
 * pthread_mutex_setprioceiling: sets the prioceiling.
 * From the SUSv3 (POSIX) specification for pthread_mutex_setprioceiling():
 *	The process of locking the mutex need not
 *	adhere to the priority protect protocol.
 * We pass the MUTEX_NOCEIL flag to mutex_lock_internal() so that
 * a non-realtime thread can successfully execute this operation.
 */
int
pthread_mutex_setprioceiling(pthread_mutex_t *mutex, int ceil, int *oceil)
{
	mutex_t *mp = (mutex_t *)mutex;
	const pcclass_t *pccp = get_info_by_policy(SCHED_FIFO);
	int error;

	if (!(mp->mutex_type & PTHREAD_PRIO_PROTECT) ||
	    ceil < pccp->pcc_primin || ceil > pccp->pcc_primax)
		return (EINVAL);
	error = mutex_lock_internal(mp, NULL, MUTEX_LOCK | MUTEX_NOCEIL);
	if (error == 0 || error == EOWNERDEAD || error == ELOCKUNMAPPED) {
		if (oceil)
			*oceil = mp->mutex_ceiling;
		mp->mutex_ceiling = ceil;
		error = mutex_unlock_internal(mp, 1);
	}
	return (error);
}

/*
 * pthread_mutex_getprioceiling: gets the prioceiling.
 */
#pragma weak _pthread_mutex_getprioceiling = pthread_mutex_getprioceiling
int
pthread_mutex_getprioceiling(const pthread_mutex_t *mp, int *ceiling)
{
	*ceiling = ((mutex_t *)mp)->mutex_ceiling;
	return (0);
}

/*
 * UNIX98
 * pthread_mutexattr_settype: sets the type attribute
 *
 * Type attributes are kept in terms of POSIX mutex types until the mutex is
 * initialized, after which it is translated into the corresponding underlying
 * lock type.
 */
int
pthread_mutexattr_settype(pthread_mutexattr_t *attr, int type)
{
	mattr_t	*ap;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL)
		return (EINVAL);
	switch (type) {
	case PTHREAD_MUTEX_NORMAL:
	case PTHREAD_MUTEX_ERRORCHECK:
	case PTHREAD_MUTEX_RECURSIVE:
	case PTHREAD_MUTEX_DEFAULT:
		break;
	default:
		return (EINVAL);
	}
	ap->type = type;
	return (0);
}

/*
 * UNIX98
 * pthread_mutexattr_gettype: gets the type attribute.
 */
int
pthread_mutexattr_gettype(const pthread_mutexattr_t *attr, int *typep)
{
	mattr_t	*ap;
	int type;

	if (attr == NULL || (ap = attr->__pthread_mutexattrp) == NULL ||
	    typep == NULL)
		return (EINVAL);
	*typep = type;
	return (0);
}
