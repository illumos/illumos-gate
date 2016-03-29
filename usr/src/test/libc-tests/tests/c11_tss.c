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
 * Test various C11 thread-specific storage (tss(3C)) interfaces.
 */

#include <threads.h>
#include <sys/debug.h>

#define	TSS_NTHREADS	128

static tss_t ct_key;
static int ct_count;
static int ct_ready;
static mtx_t ct_mtx;
static cnd_t ct_cnd;

static void
ct_tss_dtor(void *arg)
{
	VERIFY3S(mtx_lock(&ct_mtx), ==, thrd_success);
	ct_count++;
	VERIFY3S(mtx_unlock(&ct_mtx), ==, thrd_success);
}

static int
ct_tss_thr(void *arg)
{
	VERIFY3P(tss_get(ct_key), ==, NULL);
	VERIFY3S(tss_set(ct_key, arg), ==, thrd_success);

	VERIFY3S(mtx_lock(&ct_mtx), ==, thrd_success);
	ct_ready++;
	if (ct_ready == TSS_NTHREADS) {
		VERIFY3S(cnd_broadcast(&ct_cnd), ==, thrd_success);
	} else {
		while (ct_ready != TSS_NTHREADS) {
			VERIFY3S(cnd_wait(&ct_cnd, &ct_mtx), ==, thrd_success);
		}
	}
	VERIFY3S(mtx_unlock(&ct_mtx), ==, thrd_success);

	VERIFY3P(tss_get(ct_key), ==, arg);

	return (0);
}

int
main(void)
{
	int i;
	thrd_t threads[TSS_NTHREADS];

	VERIFY3S(tss_create(&ct_key, ct_tss_dtor), ==, thrd_success);
	VERIFY3S(mtx_init(&ct_mtx, mtx_plain), ==, thrd_success);
	VERIFY3S(cnd_init(&ct_cnd), ==, thrd_success);

	for (i = 0; i < TSS_NTHREADS; i++) {
		VERIFY3S(thrd_create(&threads[i], ct_tss_thr,
		    (void *)(uintptr_t)(i + 100)), ==, thrd_success);
	}

	for (i = 0; i < TSS_NTHREADS; i++) {
		VERIFY3S(thrd_join(threads[i], NULL), ==, thrd_success);
	}

	VERIFY3S(ct_count, ==, TSS_NTHREADS);

	mtx_destroy(&ct_mtx);
	cnd_destroy(&ct_cnd);
	tss_delete(ct_key);

	return (0);
}
