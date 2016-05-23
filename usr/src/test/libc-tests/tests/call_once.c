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

/*
 * Test call_once(3C)
 */

#include <threads.h>
#include <sys/debug.h>

#define	CO_NTHREADS	32

static int co_val = 41;
static mtx_t co_once_mtx;
static mtx_t co_mtx;
static boolean_t co_go = B_FALSE;
static once_flag co_once = ONCE_FLAG_INIT;
static cnd_t co_cnd;

static void
co_once_func(void)
{
	VERIFY3S(mtx_lock(&co_once_mtx), ==, thrd_success);
	co_val++;
	VERIFY3S(mtx_unlock(&co_once_mtx), ==, thrd_success);
}

/*ARGSUSED*/
static int
co_thr(void *arg)
{
	VERIFY3S(mtx_lock(&co_mtx), ==, thrd_success);
	while (co_go == B_FALSE)
		cnd_wait(&co_cnd, &co_mtx);
	VERIFY3S(mtx_unlock(&co_mtx), ==, thrd_success);
	call_once(&co_once, co_once_func);
	return (0);
}

int
main(void)
{
	int i;
	thrd_t threads[CO_NTHREADS];

	VERIFY3S(mtx_init(&co_once_mtx, mtx_plain), ==, thrd_success);
	VERIFY3S(mtx_init(&co_mtx, mtx_plain), ==, thrd_success);
	VERIFY3S(cnd_init(&co_cnd), ==, thrd_success);

	for (i = 0; i < CO_NTHREADS; i++) {
		VERIFY3S(thrd_create(&threads[i], co_thr, NULL), ==,
		    thrd_success);
	}

	VERIFY3S(mtx_lock(&co_mtx), ==, thrd_success);
	co_go = B_TRUE;
	VERIFY3S(mtx_unlock(&co_mtx), ==, thrd_success);
	VERIFY3S(cnd_broadcast(&co_cnd), ==, thrd_success);

	for (i = 0; i < CO_NTHREADS; i++) {
		VERIFY3S(thrd_join(threads[i], NULL), ==, thrd_success);
	}
	VERIFY3S(co_val, ==, 42);

	return (0);
}
