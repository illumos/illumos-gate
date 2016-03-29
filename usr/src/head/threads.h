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
 * Copyright 2016 Joyent, Inc.
 */

#ifndef _THREADS_H
#define	_THREADS_H

/*
 * ISO/IEC C11 threads.h support
 */

#include <sys/feature_tests.h>

#include <sys/types.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_STRICT_SYMBOLS) || defined(_STDC_C11)

#if !defined(_NORETURN_KYWD)
#if __STDC_VERSION__ - 0 >= 201112L
#define	_NORETURN_KYWD	_Noreturn
#else
#define	_NORETURN_KYWD
#endif	/* __STDC_VERSION__ - 0 >= 201112L */
#endif	/* !defined(_NORETURN_KYWD) */

#define	thread_local	_Thread_local
#define	ONCE_FLAG_INIT	PTHREAD_ONCE_INIT
#define	TSS_DTOR_ITERATIONS	PTHREAD_DESTRUCTOR_ITERATIONS

typedef	pthread_cond_t cnd_t;
typedef	pthread_t thrd_t;
typedef	pthread_key_t tss_t;
typedef	pthread_mutex_t mtx_t;
typedef	void (*tss_dtor_t)(void *);
typedef int (*thrd_start_t)(void *);
typedef	pthread_once_t once_flag;

enum {
	mtx_plain = 0x1,
	mtx_recursive = 0x2,
	mtx_timed = 0x4
};

enum {
	thrd_success = 0,
	thrd_error = 1,
	thrd_busy = 2,
	thrd_timedout = 3,
	thrd_nomem = 4
};

extern void call_once(once_flag *, void (*)(void));
extern int cnd_broadcast(cnd_t *);
extern void cnd_destroy(cnd_t *);
extern int cnd_init(cnd_t *);
extern int cnd_signal(cnd_t *);
extern int cnd_timedwait(cnd_t *_RESTRICT_KYWD, mtx_t *_RESTRICT_KYWD,
    const struct timespec *_RESTRICT_KYWD);
extern int cnd_wait(cnd_t *, mtx_t *);
extern void mtx_destroy(mtx_t *);
extern int mtx_init(mtx_t *, int);
extern int mtx_lock(mtx_t *);
extern int mtx_timedlock(mtx_t *_RESTRICT_KYWD,
    const struct timespec *_RESTRICT_KYWD);
extern int mtx_trylock(mtx_t *);
extern int mtx_unlock(mtx_t *);
extern int thrd_create(thrd_t *, thrd_start_t, void *);
extern thrd_t thrd_current(void);
extern int thrd_detach(thrd_t);
extern int thrd_equal(thrd_t, thrd_t);
extern _NORETURN_KYWD void thrd_exit(int) __NORETURN;
extern int thrd_join(thrd_t, int *);
extern int thrd_sleep(const struct timespec *, struct timespec *);
extern void thrd_yield(void);
extern int tss_create(tss_t *, tss_dtor_t);
extern void tss_delete(tss_t);
extern void *tss_get(tss_t);
extern int tss_set(tss_t, void *);

#endif /* !_STRICT_SYMBOLS | _STDC_C11 */

#ifdef __cplusplus
}
#endif

#endif /* _THREADS_H */
