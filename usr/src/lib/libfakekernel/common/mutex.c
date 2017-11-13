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
 * Copyright 2017 RackTop Systems.
 */

/*
 * mutex(9f)
 */

/* This is the API we're emulating */
#include <sys/mutex.h>

#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/thread.h>

int	_lwp_mutex_lock(lwp_mutex_t *);
int	_lwp_mutex_unlock(lwp_mutex_t *);
int	_lwp_mutex_trylock(lwp_mutex_t *);

extern clock_t ddi_get_lbolt(void);

static const lwp_mutex_t default_mutex =
	{{0, 0, 0, {USYNC_THREAD}, _MUTEX_MAGIC},
	{{{0, 0, 0, 0, 0, 0, 0, 0}}}, 0};

/* ARGSUSED */
void
kmutex_init(kmutex_t *mp, char *name, kmutex_type_t typ, void *arg)
{
	mp->m_lock = default_mutex;
	mp->m_owner = _KTHREAD_INVALID;
}

/* ARGSUSED */
void
kmutex_destroy(kmutex_t *mp)
{
	mp->m_owner = _KTHREAD_INVALID;
}

void
kmutex_enter(kmutex_t *mp)
{
	VERIFY(0 == _lwp_mutex_lock(&mp->m_lock));
	mp->m_owner = _curthread();
}

int
mutex_tryenter(kmutex_t *mp)
{
	int rc;

	rc = _lwp_mutex_trylock(&mp->m_lock);
	if (rc == 0) {
		mp->m_owner = _curthread();
		return (1);
	}
	return (0);
}

void
kmutex_exit(kmutex_t *mp)
{
	ASSERT(mp->m_owner == _curthread());
	mp->m_owner = _KTHREAD_INVALID;
	(void) _lwp_mutex_unlock(&mp->m_lock);
}

/*
 * Returns the kthread_t * of the owner.
 */
void *
mutex_owner(const kmutex_t *mp)
{
	return (mp->m_owner);
}

int
mutex_owned(const kmutex_t *mp)
{
	void *t = _curthread();
	return (t == mp->m_owner);
}
