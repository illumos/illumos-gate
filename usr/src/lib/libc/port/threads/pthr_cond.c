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
 * pthread_condattr_init: allocates the cond attribute object and
 * initializes it with the default values.
 */
#pragma weak _pthread_condattr_init = pthread_condattr_init
int
pthread_condattr_init(pthread_condattr_t *attr)
{
	cvattr_t *ap;

	if ((ap = lmalloc(sizeof (cvattr_t))) == NULL)
		return (ENOMEM);
	ap->pshared = PTHREAD_PROCESS_PRIVATE;
	ap->clockid = CLOCK_REALTIME;
	attr->__pthread_condattrp = ap;
	return (0);
}

/*
 * pthread_condattr_destroy: frees the cond attribute object and
 * invalidates it with NULL value.
 */
int
pthread_condattr_destroy(pthread_condattr_t *attr)
{
	if (attr == NULL || attr->__pthread_condattrp == NULL)
		return (EINVAL);
	lfree(attr->__pthread_condattrp, sizeof (cvattr_t));
	attr->__pthread_condattrp = NULL;
	return (0);
}

/*
 * pthread_condattr_setclock: sets the clockid attribute.
 */
int
pthread_condattr_setclock(pthread_condattr_t *attr, clockid_t clock_id)
{
	cvattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_condattrp) != NULL &&
	    (clock_id == CLOCK_REALTIME || clock_id == CLOCK_HIGHRES)) {
		ap->clockid = clock_id;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_condattr_getclock: gets the shared attr.
 */
int
pthread_condattr_getclock(const pthread_condattr_t *attr, clockid_t *clock_id)
{
	cvattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_condattrp) != NULL &&
	    clock_id != NULL) {
		*clock_id = ap->clockid;
		return (0);
	}
	return (EINVAL);
}


/*
 * pthread_condattr_setpshared: sets the shared attr to PRIVATE or SHARED.
 * This is equivalent to setting USYNC_PROCESS/USYNC_THREAD flag in cond_init().
 */
int
pthread_condattr_setpshared(pthread_condattr_t *attr, int pshared)
{
	cvattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_condattrp) != NULL &&
	    (pshared == PTHREAD_PROCESS_PRIVATE ||
	    pshared == PTHREAD_PROCESS_SHARED)) {
		ap->pshared = pshared;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_condattr_getpshared: gets the shared attr.
 */
#pragma weak _pthread_condattr_getpshared = pthread_condattr_getpshared
int
pthread_condattr_getpshared(const pthread_condattr_t *attr, int *pshared)
{
	cvattr_t *ap;

	if (attr != NULL && (ap = attr->__pthread_condattrp) != NULL &&
	    pshared != NULL) {
		*pshared = ap->pshared;
		return (0);
	}
	return (EINVAL);
}

/*
 * pthread_cond_init: Initializes the cond object. It copies the
 * pshared attr into type argument and calls cond_init().
 */
#pragma weak _pthread_cond_init = pthread_cond_init
int
pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr)
{
	cvattr_t *ap;
	int type;
	clockid_t clock_id;
	int error;

	if (attr == NULL) {
		type = PTHREAD_PROCESS_PRIVATE;
		clock_id = CLOCK_REALTIME;
	} else if ((ap = attr->__pthread_condattrp) != NULL) {
		type = ap->pshared;
		clock_id = ap->clockid;
	} else {
		return (EINVAL);
	}

	if (clock_id != CLOCK_REALTIME && clock_id != CLOCK_HIGHRES)
		error = EINVAL;
	else if ((error = cond_init((cond_t *)cond, type, NULL)) == 0)
		((cond_t *)cond)->cond_clockid = (uint8_t)clock_id;

	return (error);
}
