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
 * condvar(9f)
 */

/* This is the API we're emulating */
#include <sys/condvar.h>

#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/thread.h>
#include <sys/systm.h>

/* avoiding synch.h */
int	_lwp_cond_wait(lwp_cond_t *, lwp_mutex_t *);
int	_lwp_cond_timedwait(lwp_cond_t *, lwp_mutex_t *, timespec_t *);
int	_lwp_cond_reltimedwait(lwp_cond_t *, lwp_mutex_t *, timespec_t *);
int	_lwp_cond_signal(lwp_cond_t *);
int	_lwp_cond_broadcast(lwp_cond_t *);


extern clock_t ddi_get_lbolt(void);

static int cv__wait(kcondvar_t *, kmutex_t *, int);
static clock_t cv__twait(kcondvar_t *, kmutex_t *, clock_t, int, int);

static const lwp_cond_t  default_cv =
	{{{0, 0, 0, 0}, USYNC_THREAD, _COND_MAGIC}, 0};


/* ARGSUSED */
void
cv_init(kcondvar_t *cv, char *name, kcv_type_t typ, void *arg)
{
	*cv = default_cv;
}

/* ARGSUSED */
void
cv_destroy(kcondvar_t *cv)
{
}

void
cv_signal(kcondvar_t *cv)
{
	(void) _lwp_cond_signal(cv);
}

void
cv_broadcast(kcondvar_t *cv)
{
	(void) _lwp_cond_broadcast(cv);
}

void
cv_wait(kcondvar_t *cv, kmutex_t *mp)
{
	(void) cv__wait(cv, mp, 0);
}

int
cv_wait_sig(kcondvar_t *cv, kmutex_t *mp)
{
	return (cv__wait(cv, mp, 1));
}

int
cv__wait(kcondvar_t *cv, kmutex_t *mp, int sigok)
{
	int err;

top:
	ASSERT(mp->m_owner == _curthread());
	mp->m_owner = _KTHREAD_INVALID;
	err = _lwp_cond_wait(cv, &mp->m_lock);
	mp->m_owner = _curthread();

	if (err == 0)
		return (1);
	if (err == EINTR) {
		if (sigok)
			return (0);
		goto top;
	}
	return (-1);
}

clock_t
cv_timedwait(kcondvar_t *cv, kmutex_t *mp, clock_t abstime)
{
	clock_t delta;

	delta = abstime - ddi_get_lbolt();
	return (cv__twait(cv, mp, delta, 0, 0));
}

clock_t
cv_timedwait_sig(kcondvar_t *cv, kmutex_t *mp, clock_t abstime)
{
	clock_t delta;

	delta = abstime - ddi_get_lbolt();
	return (cv__twait(cv, mp, delta, 1, 0));
}

/*ARGSUSED*/
clock_t
cv_timedwait_hires(kcondvar_t *cv, kmutex_t *mp, hrtime_t tim, hrtime_t res,
    int flag)
{
	clock_t delta;

	delta = tim;
	if (flag & CALLOUT_FLAG_ABSOLUTE)
		delta -= gethrtime();
	return (cv__twait(cv, mp, delta, 0, 1));
}

clock_t
cv_reltimedwait(kcondvar_t *cv, kmutex_t *mp, clock_t delta, time_res_t res)
{
	_NOTE(ARGUNUSED(res))

	return (cv__twait(cv, mp, delta, 0, 0));
}

clock_t
cv_reltimedwait_sig(kcondvar_t *cv, kmutex_t *mp, clock_t delta,
    time_res_t res)
{
	_NOTE(ARGUNUSED(res))

	return (cv__twait(cv, mp, delta, 1, 0));
}

/*
 * Factored out implementation of all the cv_*timedwait* functions.
 * Note that the delta passed in is relative to the (simulated)
 * current time reported by ddi_get_lbolt().  Convert that to
 * timespec format and keep calling _lwp_cond_reltimedwait,
 * which (NB!) decrements that delta in-place!
 */
static clock_t
cv__twait(kcondvar_t *cv, kmutex_t *mp, clock_t delta, int sigok, int hires)
{
	timestruc_t ts;
	int err;

	if (delta <= 0)
		return (-1);

	if (hires) {
		ts.tv_sec = delta / NANOSEC;
		ts.tv_nsec = delta % NANOSEC;
	} else {
		ts.tv_sec = delta / hz;
		ts.tv_nsec = (delta % hz) * (NANOSEC / hz);
	}

top:
	if (ts.tv_sec == 0 && ts.tv_nsec == 0)
		return (-1);

	ASSERT(mp->m_owner == _curthread());
	mp->m_owner = _KTHREAD_INVALID;
	err = _lwp_cond_reltimedwait(cv, &mp->m_lock, &ts);
	mp->m_owner = _curthread();

	switch (err) {
	case 0:
		return (1);
	case EINTR:
		if (sigok)
			return (0);
		goto top;
	default:
		ASSERT(0);
		/* FALLTHROUGH */
	case ETIME:
		break;
	}

	return (-1);
}
