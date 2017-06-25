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
 * Copyright 2017 Joyent, Inc.
 */

#include <pthread.h>
#include <thread.h>
#include <synch.h>
#include <threads.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>

/*
 * ISO/IEC C11 thread support.
 *
 * In illumos, the underlying implementation of lock related routines is the
 * same between pthreads and traditional SunOS routines. The same is true with
 * the C11 routines. Their types are actually just typedef's to other things.
 * Thus in the implementation here, we treat this as a wrapper around existing
 * thread related routines and don't sweet the extra indirection.
 *
 * Note that in many places the C standard doesn't allow for errors to be
 * returned. In those cases, if we have an instance of programmer error
 * (something resulting in EINVAL), we opt to abort the program as we don't have
 * much other recourse available.
 */

void
call_once(once_flag *flag, void (*func)(void))
{
	if (pthread_once(flag, func) != 0)
		abort();
}

int
cnd_broadcast(cnd_t *cnd)
{
	int ret;

	ret = pthread_cond_broadcast(cnd);
	if (ret == 0)
		return (thrd_success);
	else
		return (thrd_error);
}

void
cnd_destroy(cnd_t *cnd)
{
	if (pthread_cond_destroy(cnd) != 0)
		abort();
}

int
cnd_init(cnd_t *cnd)
{
	int ret;

	ret = pthread_cond_init(cnd, NULL);
	if (ret == 0)
		return (thrd_success);
	return (thrd_error);
}

int
cnd_signal(cnd_t *cnd)
{
	int ret;

	ret = pthread_cond_signal(cnd);
	if (ret == 0)
		return (thrd_success);
	else
		return (thrd_error);
}

/* ARGSUSED */
int
cnd_timedwait(cnd_t *_RESTRICT_KYWD cnd, mtx_t *_RESTRICT_KYWD mtx,
    const struct timespec *_RESTRICT_KYWD ts)
{
	int ret;

	ret = pthread_cond_timedwait(cnd, mtx, ts);
	if (ret == 0)
		return (thrd_success);
	if (ret == ETIMEDOUT)
		return (thrd_timedout);
	return (thrd_error);
}

/* ARGSUSED */
int
cnd_wait(cnd_t *cnd, mtx_t *mtx)
{
	int ret;

	ret = pthread_cond_wait(cnd, mtx);
	if (ret == 0)
		return (thrd_success);
	return (thrd_error);
}

void
mtx_destroy(mtx_t *mtx)
{
	if (pthread_mutex_destroy(mtx) != 0)
		abort();
}

int
mtx_init(mtx_t *mtx, int type)
{
	int mtype;

	switch (type) {
	case mtx_plain:
	case mtx_timed:
		mtype = USYNC_THREAD;
		break;
	case mtx_plain | mtx_recursive:
	case mtx_timed | mtx_recursive:
		mtype = USYNC_THREAD | LOCK_RECURSIVE;
		break;
	default:
		return (thrd_error);
	}

	/*
	 * Here, we buck the trend and use the traditional SunOS routine. It's
	 * much simpler than fighting with pthread attributes.
	 */
	if (mutex_init((mutex_t *)mtx, mtype, NULL) == 0)
		return (thrd_success);
	return (thrd_error);
}

int
mtx_lock(mtx_t *mtx)
{
	if (pthread_mutex_lock(mtx) == 0)
		return (thrd_success);
	return (thrd_error);
}

int
mtx_timedlock(mtx_t *_RESTRICT_KYWD mtx,
    const struct timespec *_RESTRICT_KYWD abstime)
{
	int ret;

	ret = pthread_mutex_timedlock(mtx, abstime);
	if (ret == ETIMEDOUT)
		return (thrd_timedout);
	else if (ret != 0)
		return (thrd_error);
	return (thrd_success);
}

int
mtx_trylock(mtx_t *mtx)
{
	int ret;

	ret = pthread_mutex_trylock(mtx);
	if (ret == 0)
		return (thrd_success);
	else if (ret == EBUSY)
		return (thrd_busy);
	else
		return (thrd_error);
}

int
mtx_unlock(mtx_t *mtx)
{
	if (pthread_mutex_unlock(mtx) == 0)
		return (thrd_success);
	return (thrd_error);
}

int
thrd_create(thrd_t *thr, thrd_start_t func, void *arg)
{
	int ret;

	ret = pthread_create(thr, NULL, (void *(*)(void *))func, arg);
	if (ret == 0)
		return (thrd_success);
	else if (ret == -1 && errno == EAGAIN)
		return (thrd_nomem);
	else
		return (thrd_error);
}

thrd_t
thrd_current(void)
{
	return (pthread_self());
}

int
thrd_detach(thrd_t thr)
{
	if (pthread_detach(thr) == 0)
		return (thrd_success);
	return (thrd_error);
}

int
thrd_equal(thrd_t t1, thrd_t t2)
{
	return (pthread_equal(t1, t2));
}

_NORETURN_KYWD void
thrd_exit(int res)
{
	pthread_exit((void *)(uintptr_t)res);
}

int
thrd_join(thrd_t thrd, int *res)
{
	void *es;

	if (pthread_join(thrd, &es) != 0)
		return (thrd_error);
	if (res != NULL)
		*res = (uintptr_t)es;
	return (thrd_success);
}

/*
 * thrd_sleep has somewhat odd standardized return values. It doesn't use the
 * same returns values as the thrd_* family of functions at all.
 */
int
thrd_sleep(const struct timespec *rqtp, struct timespec *rmtp)
{
	int ret;
	if ((ret = nanosleep(rqtp, rmtp)) == 0)
		return (0);
	if (ret == -1 && errno == EINTR)
		return (-1);
	return (-2);
}

void
thrd_yield(void)
{
	thr_yield();
}

int
tss_create(tss_t *key, tss_dtor_t dtor)
{
	if (pthread_key_create(key, dtor) == 0)
		return (thrd_success);
	return (thrd_error);
}

void
tss_delete(tss_t key)
{
	if (pthread_key_delete(key) != 0)
		abort();
}

void *
tss_get(tss_t key)
{
	return (pthread_getspecific(key));
}

int
tss_set(tss_t key, void *val)
{
	if (pthread_setspecific(key, val) == 0)
		return (thrd_success);
	return (thrd_error);
}
