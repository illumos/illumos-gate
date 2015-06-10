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
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * semaphore(9f)
 */

/* This is the API we're emulating */
#include <sys/semaphore.h>

#include <sys/errno.h>
#include <sys/debug.h>

/* <synch.h> */
int	_lwp_sema_init(lwp_sema_t *, int);
int	_lwp_sema_wait(lwp_sema_t *);
int	_lwp_sema_trywait(lwp_sema_t *);
int	_lwp_sema_post(lwp_sema_t *);


/* ARGSUSED */
void
ksema_init(ksema_t *sem, uint32_t val,
	char *name, ksema_type_t st, void *arg)
{
	(void) _lwp_sema_init(sem, val);
}

/* ARGSUSED */
void
ksema_destroy(ksema_t *sem)
{
}

void
sema_p(ksema_t *sem)
{
	int rv;
	do {
		rv = _lwp_sema_wait(sem);
	} while (rv == EINTR);
}

void
sema_v(ksema_t *sem)
{
	(void) _lwp_sema_post(sem);
}

/*
 * Return values:
 * 1: interrupted
 * 0: success
 */
int
sema_p_sig(ksema_t *sem)
{
	int rv;
	rv = _lwp_sema_wait(sem);
	switch (rv) {
	case 0:
		/* rv = 0 ; success */
		break;
	case EINTR:
	default:
		rv = 1; /* interrrupted */
		break;
	}

	return (rv);
}

/*
 * Return values:
 * 0: could not get semaphore
 * 1: successful (backwards from sema_p_sig!)
 */
int
sema_tryp(ksema_t *sem)
{
	int rv;
	rv = _lwp_sema_trywait(sem);

	switch (rv) {
	case 0:
		rv = 1; /* success */
		break;
	case EBUSY:
	default:
		rv = 0; /* failed */
		break;
	}

	return (rv);
}
