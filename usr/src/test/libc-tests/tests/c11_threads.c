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

/*
 * Validate various C11 threads routines. Specifically we want to cover:
 *
 *    o threads
 *    o mutexes
 *    o condition variables
 */

#include <threads.h>
#include <sys/debug.h>
#include <stdlib.h>
#include <unistd.h>

#define	STRESS_NTHREADS	128
#define	STRESS_COUNT	1000

static mtx_t stress_mtx;
static int stress_count;

#define	BROADCAST_NTHREADS 128

static mtx_t broadcast_mtx;
static cnd_t broadcast_cnd;
static boolean_t broadcast_done;

#define	SIGNAL_NTHREADS 128

static mtx_t signal_mtx;
static cnd_t signal_cnd;
static boolean_t signal_done;

/*
 * This thread should only ever be used for detach.
 */
static int
cthr_test_sleep_thr(void *arg)
{
	for (;;) {
		sleep(1000);
	}

	abort();
}

static void
cthr_test_mtx_init(void)
{
	mtx_t mtx;

	VERIFY3S(mtx_init(&mtx, mtx_plain), ==, thrd_success);
	mtx_destroy(&mtx);
	VERIFY3S(mtx_init(&mtx, mtx_timed), ==, thrd_success);
	mtx_destroy(&mtx);
	VERIFY3S(mtx_init(&mtx, mtx_plain | mtx_recursive), ==, thrd_success);
	mtx_destroy(&mtx);
	VERIFY3S(mtx_init(&mtx, mtx_timed | mtx_recursive), ==, thrd_success);
	mtx_destroy(&mtx);

	VERIFY3S(mtx_init(&mtx, UINT32_MAX), ==, thrd_error);
	VERIFY3S(mtx_init(&mtx, 42), ==, thrd_error);
}

static void
cthr_test_mtx_lockrec(void)
{
	mtx_t mtx;

	VERIFY3S(mtx_init(&mtx, mtx_plain | mtx_recursive), ==, thrd_success);
	VERIFY3S(mtx_lock(&mtx), ==, thrd_success);
	VERIFY3S(mtx_lock(&mtx), ==, thrd_success);
	VERIFY3S(mtx_trylock(&mtx), ==, thrd_success);
	VERIFY3S(mtx_unlock(&mtx), ==, thrd_success);
	VERIFY3S(mtx_unlock(&mtx), ==, thrd_success);
	VERIFY3S(mtx_unlock(&mtx), ==, thrd_success);
	mtx_destroy(&mtx);
}

static void
cthr_test_mtx_trylock(void)
{
	mtx_t mtx;

	VERIFY3S(mtx_init(&mtx, mtx_plain), ==, thrd_success);
	VERIFY3S(mtx_trylock(&mtx), ==, thrd_success);
	VERIFY3S(mtx_trylock(&mtx), ==, thrd_busy);
	VERIFY3S(mtx_unlock(&mtx), ==, thrd_success);
	mtx_destroy(&mtx);
}

static int
cthr_test_stress_thr(void *arg)
{
	int i;
	int *ip = arg;

	for (i = 0; i < STRESS_COUNT; i++) {
		VERIFY3S(mtx_lock(&stress_mtx), ==, thrd_success);
		*ip = *ip + 1;
		VERIFY3S(mtx_unlock(&stress_mtx), ==, thrd_success);
	}

	return (0);
}

static void
cthr_test_stress(void)
{
	int i;
	thrd_t threads[STRESS_NTHREADS];

	VERIFY3S(mtx_init(&stress_mtx, mtx_plain), ==, thrd_success);
	for (i = 0; i < STRESS_NTHREADS; i++) {
		VERIFY3S(thrd_create(&threads[i], cthr_test_stress_thr,
		    &stress_count),  ==, thrd_success);
	}

	for (i = 0; i < STRESS_NTHREADS; i++) {
		VERIFY3S(thrd_join(threads[i], NULL), ==, thrd_success);
	}
	mtx_destroy(&stress_mtx);

	VERIFY3S(stress_count, ==, STRESS_NTHREADS * STRESS_COUNT);
}

static void
cthr_test_equal(void)
{
	thrd_t self, other;

	self = thrd_current();

	VERIFY3S(thrd_equal(self, self), !=, 0);
	VERIFY3S(thrd_create(&other, cthr_test_sleep_thr, NULL), ==,
	    thrd_success);
	VERIFY3S(thrd_equal(self, other), ==, 0);
	VERIFY3S(thrd_equal(other, other), !=, 0);
	VERIFY3S(thrd_detach(other), ==, thrd_success);
}

static void
cthr_test_detach_err(void)
{
	thrd_t self, other;

	self = thrd_current();

	VERIFY3S(thrd_equal(self, self), !=, 0);
	VERIFY3S(thrd_create(&other, cthr_test_sleep_thr, NULL), ==,
	    thrd_success);
	VERIFY3S(thrd_detach(other), ==, thrd_success);

	VERIFY3S(thrd_join(self, NULL), ==, thrd_error);
	VERIFY3S(thrd_join(other, NULL), ==, thrd_error);
}

static int
cthr_test_detach_thr0(void *arg)
{
	thrd_exit(23);
	abort();
}

static int
cthr_test_detach_thr1(void *arg)
{
	return (42);
}

static void
cthr_test_detach(void)
{
	int status;
	thrd_t thrd;

	VERIFY3S(thrd_create(&thrd, cthr_test_detach_thr0, NULL), ==,
	    thrd_success);
	VERIFY3S(thrd_join(thrd, &status), ==, thrd_success);
	VERIFY3S(status, ==, 23);

	VERIFY3S(thrd_create(&thrd, cthr_test_detach_thr1, NULL), ==,
	    thrd_success);
	VERIFY3S(thrd_join(thrd, &status), ==, thrd_success);
	VERIFY3S(status, ==, 42);
}

static void
cthr_test_sleep(void)
{
	struct timespec ts;
	hrtime_t start, end;
	long stime = 10 * NANOSEC / MILLISEC;

	ts.tv_sec = 1;
	ts.tv_nsec = -1;

	VERIFY3S(thrd_sleep(&ts, NULL), <, -1);

	ts.tv_sec = 0;
	ts.tv_nsec = stime;
	start = gethrtime();
	VERIFY3S(thrd_sleep(&ts, NULL), ==, 0);
	end = gethrtime();

	VERIFY3S(end - start, >, stime);
}

static int
cthr_test_broadcast_thr(void *arg)
{
	VERIFY3S(mtx_lock(&broadcast_mtx), ==, thrd_success);
	while (broadcast_done == B_FALSE)
		VERIFY3S(cnd_wait(&broadcast_cnd, &broadcast_mtx), ==,
		    thrd_success);
	VERIFY3S(mtx_unlock(&broadcast_mtx), ==, thrd_success);

	return (0);
}

static void
cthr_test_broadcast(void)
{
	int i;
	thrd_t threads[BROADCAST_NTHREADS];

	VERIFY3S(mtx_init(&broadcast_mtx, mtx_plain), ==, thrd_success);
	VERIFY3S(cnd_init(&broadcast_cnd), ==, thrd_success);
	for (i = 0; i < BROADCAST_NTHREADS; i++) {
		VERIFY3S(thrd_create(&threads[i], cthr_test_broadcast_thr,
		    NULL),  ==, thrd_success);
	}

	VERIFY3S(mtx_lock(&broadcast_mtx), ==, thrd_success);
	broadcast_done = B_TRUE;
	VERIFY3S(mtx_unlock(&broadcast_mtx), ==, thrd_success);
	VERIFY3S(cnd_broadcast(&broadcast_cnd), ==, thrd_success);

	for (i = 0; i < STRESS_NTHREADS; i++) {
		VERIFY3S(thrd_join(threads[i], NULL), ==, thrd_success);
	}

	mtx_destroy(&broadcast_mtx);
	cnd_destroy(&broadcast_cnd);
}


static int
cthr_test_signal_thr(void *arg)
{
	VERIFY3S(mtx_lock(&signal_mtx), ==, thrd_success);
	while (signal_done == B_FALSE)
		VERIFY3S(cnd_wait(&signal_cnd, &signal_mtx), ==,
		    thrd_success);
	VERIFY3S(mtx_unlock(&signal_mtx), ==, thrd_success);
	VERIFY3S(cnd_signal(&signal_cnd), ==, thrd_success);

	return (0);
}

static void
cthr_test_signal(void)
{
	int i;
	thrd_t threads[SIGNAL_NTHREADS];

	VERIFY3S(mtx_init(&signal_mtx, mtx_plain), ==, thrd_success);
	VERIFY3S(cnd_init(&signal_cnd), ==, thrd_success);
	for (i = 0; i < SIGNAL_NTHREADS; i++) {
		VERIFY3S(thrd_create(&threads[i], cthr_test_signal_thr, NULL),
		    ==, thrd_success);
	}

	VERIFY3S(mtx_lock(&signal_mtx), ==, thrd_success);
	signal_done = B_TRUE;
	VERIFY3S(mtx_unlock(&signal_mtx), ==, thrd_success);
	VERIFY3S(cnd_signal(&signal_cnd), ==, thrd_success);

	for (i = 0; i < STRESS_NTHREADS; i++) {
		VERIFY3S(thrd_join(threads[i], NULL), ==, thrd_success);
	}

	mtx_destroy(&signal_mtx);
	cnd_destroy(&signal_cnd);
}

static void
cthr_test_cndtime(void)
{
	mtx_t mtx;
	cnd_t cnd;
	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec = 1 * NANOSEC / MILLISEC;
	VERIFY3S(mtx_init(&mtx, mtx_plain), ==, thrd_success);
	VERIFY3S(cnd_init(&cnd), ==, thrd_success);

	VERIFY3S(mtx_lock(&mtx), ==, thrd_success);
	VERIFY3S(cnd_timedwait(&cnd, &mtx, &ts), ==, thrd_timedout);
	VERIFY3S(mtx_unlock(&mtx), ==, thrd_success);

	mtx_destroy(&mtx);
	cnd_destroy(&cnd);
}

static void
cthr_test_mtx_selftime(void)
{
	mtx_t mtx;
	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec = 1 * NANOSEC / MILLISEC;
	VERIFY3S(mtx_init(&mtx, mtx_timed), ==, thrd_success);
	VERIFY3S(mtx_lock(&mtx), ==, thrd_success);
	VERIFY3S(mtx_timedlock(&mtx, &ts), ==, thrd_timedout);
	VERIFY3S(mtx_unlock(&mtx), ==, thrd_success);
	mtx_destroy(&mtx);
}

static int
cthr_test_mtx_busy_thr(void *arg)
{
	mtx_t *mtx = arg;
	struct timespec ts;

	ts.tv_sec = 0;
	ts.tv_nsec = 1 * NANOSEC / MILLISEC;

	VERIFY3S(mtx_trylock(mtx), ==, thrd_busy);
	VERIFY3S(mtx_timedlock(mtx, &ts), ==, thrd_timedout);

	return (0);
}

static void
cthr_test_mtx_busy(void)
{
	mtx_t mtx;
	thrd_t thrd;

	VERIFY3S(mtx_init(&mtx, mtx_timed), ==, thrd_success);
	VERIFY3S(mtx_lock(&mtx), ==, thrd_success);

	VERIFY3S(thrd_create(&thrd, cthr_test_mtx_busy_thr, &mtx), ==,
	    thrd_success);
	VERIFY3S(thrd_join(thrd, NULL), ==, thrd_success);

	VERIFY3S(mtx_unlock(&mtx), ==, thrd_success);
	mtx_destroy(&mtx);
}

int
main(void)
{
	cthr_test_mtx_init();
	cthr_test_mtx_lockrec();
	cthr_test_mtx_trylock();
	cthr_test_stress();
	cthr_test_equal();
	cthr_test_detach_err();
	cthr_test_detach();
	cthr_test_sleep();
	cthr_test_broadcast();
	cthr_test_signal();
	cthr_test_cndtime();
	cthr_test_mtx_selftime();
	cthr_test_mtx_busy();

	return (0);
}
