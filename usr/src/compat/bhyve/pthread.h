/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

#ifndef _COMPAT_FREEBSD_PTHREAD_H_
#define	_COMPAT_FREEBSD_PTHREAD_H_

#include <sys/debug.h>
#include_next <pthread.h>

/*
 * Mutexes on FreeBSD are error-checking by default. Wrap pthread_mutex_*()
 * to deliver the same, and check for errors.
 */

#undef PTHREAD_MUTEX_INITIALIZER
#define	PTHREAD_MUTEX_INITIALIZER PTHREAD_ERRORCHECK_MUTEX_INITIALIZER_NP

static __inline int
checked_pthread_mutex_init(pthread_mutex_t *restrict mutex,
    const pthread_mutexattr_t *restrict cattr)
{
	if (cattr != NULL) {
		VERIFY0(pthread_mutex_init(mutex, cattr));
	} else {
		pthread_mutexattr_t attr = { 0 };

		VERIFY0(pthread_mutexattr_init(&attr));
		VERIFY0(pthread_mutexattr_settype(&attr,
		    PTHREAD_MUTEX_ERRORCHECK));
		VERIFY0(pthread_mutex_init(mutex, &attr));
		VERIFY0(pthread_mutexattr_destroy(&attr));
	}

	return (0);
}

static __inline int
checked_pthread_mutex_destroy(pthread_mutex_t *mutex)
{
	VERIFY0(pthread_mutex_destroy(mutex));
	return (0);
}

#define	pthread_mutex_init(m, a)	checked_pthread_mutex_init(m, a)
#define	pthread_mutex_destroy(m)	checked_pthread_mutex_destroy(m)
#define	pthread_mutex_lock(m)		pthread_mutex_enter_np(m)
#define	pthread_mutex_unlock(m)		pthread_mutex_exit_np(m)

#endif	/* _COMPAT_FREEBSD_PTHREAD_H_ */
