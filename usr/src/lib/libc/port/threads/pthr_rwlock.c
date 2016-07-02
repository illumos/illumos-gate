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

/*
 * UNIX98
 * pthread_rwlockattr_init: allocates the mutex attribute object and
 * initializes it with the default values.
 */
int
pthread_rwlockattr_init(pthread_rwlockattr_t *attr)
{
	rwlattr_t *ap;

	if ((ap = lmalloc(sizeof (rwlattr_t))) == NULL)
		return (ENOMEM);
	ap->pshared = PTHREAD_PROCESS_PRIVATE;
	attr->__pthread_rwlockattrp = ap;
	return (0);
}

/*
 * UNIX98
 * pthread_rwlockattr_destroy: frees the rwlock attribute object and
 * invalidates it with NULL value.
 */
int
pthread_rwlockattr_destroy(pthread_rwlockattr_t *attr)
{
	if (attr == NULL || attr->__pthread_rwlockattrp == NULL)
		return (EINVAL);
	lfree(attr->__pthread_rwlockattrp, sizeof (rwlattr_t));
	attr->__pthread_rwlockattrp = NULL;
	return (0);
}

/*
 * UNIX98
 * pthread_rwlockattr_setpshared: sets the shared attr to PRIVATE or SHARED.
 */
int
pthread_rwlockattr_setpshared(pthread_rwlockattr_t *attr, int pshared)
{
	rwlattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_rwlockattrp) != NULL &&
	    (pshared == PTHREAD_PROCESS_PRIVATE ||
	    pshared == PTHREAD_PROCESS_SHARED)) {
		ap->pshared = pshared;
		return (0);
	}
	return (EINVAL);
}

/*
 * UNIX98
 * pthread_rwlockattr_getpshared: gets the shared attr.
 */
int
pthread_rwlockattr_getpshared(const pthread_rwlockattr_t *attr, int *pshared)
{
	rwlattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_rwlockattrp) != NULL &&
	    pshared != NULL) {
		*pshared = ap->pshared;
		return (0);
	}
	return (EINVAL);
}

/*
 * UNIX98
 * pthread_rwlock_init: Initializes the rwlock object. It copies the
 * pshared attr into type argument and calls rwlock_init().
 */
int
pthread_rwlock_init(pthread_rwlock_t *_RESTRICT_KYWD rwlock,
    const pthread_rwlockattr_t *_RESTRICT_KYWD attr)
{
	rwlattr_t *ap;
	int type;

	if (attr == NULL)
		type = PTHREAD_PROCESS_PRIVATE;
	else if ((ap = attr->__pthread_rwlockattrp) != NULL)
		type = ap->pshared;
	else
		return (EINVAL);

	return (rwlock_init((rwlock_t *)rwlock, type, NULL));
}
