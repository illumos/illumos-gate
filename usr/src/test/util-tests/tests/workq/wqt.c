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
 * Copyright 2015 Joyent, Inc.
 */

/*
 * workq testing routines
 *
 * What we want to guarantee is that every function is executed exactly once. To
 * that end we have the callback function basically increment a global in the
 * test around a mutex.
 */

#include <workq.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <thread.h>
#include <synch.h>

mutex_t wqt_lock = ERRORCHECKMUTEX;
uintptr_t wqt_count;

const char *
_umem_debug_init()
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}

void *
workq_alloc(size_t size)
{
	return (malloc(size));
}

/*ARGSUSED*/
void
workq_free(void *buf, size_t size)
{
	free(buf);
}

/*ARGSUSED*/
int
wqt_fatal(void *item, void *arg)
{
	return (-1);
}

int
wqt_add(void *item, void *arg)
{
	uintptr_t a = (uintptr_t)item;

	mutex_enter(&wqt_lock);
	wqt_count += a;
	mutex_exit(&wqt_lock);

	return (0);
}

typedef struct wq_test {
	const char	*wq_desc;	/* test description/name */
	workq_proc_f	*wq_proc;	/* processing function */
	int		wq_rval;	/* workq_work return value */
	int		wq_uerr;	/* user error, if any */
	uintptr_t	wq_sum;		/* expected sum */
	void		**wq_args;	/* argument array */
} wq_test_t;

static void *wqt_empty_args[] = { NULL };
static void *wqt_single_args[] = { (void *)42, NULL };
static void *wqt_double_args[] = { (void *)42, (void *)27, NULL };
static void *wqt_wrap_args[] = {
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, NULL
};
static void *wqt_grow_args[] = {
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, (void *)1, (void *)1, (void *)1, (void *)1,
	(void *)1, (void *)1, NULL
};

static wq_test_t wq_tests[] = {
	{ "empty", wqt_add, 0, 0, NULL, wqt_empty_args },
	{ "single", wqt_add, 0, 0, 42, wqt_single_args },
	{ "double", wqt_add, 0, 0, 69, wqt_double_args },
	{ "wrap", wqt_add, 0, 0, 64, wqt_wrap_args },
	{ "grow", wqt_add, 0, 0, 92, wqt_grow_args },
	{ "fatal", wqt_fatal, WORKQ_UERROR, -1, -1, wqt_double_args }
};

#define	NWQ_TESTS (sizeof (wq_tests) / sizeof (wq_test_t))

static void
wq_test_run(workq_t *wqp, wq_test_t *wqt)
{
	int ret, err;
	void **itemp = wqt->wq_args;

	while (*itemp != NULL) {
		if ((ret = workq_add(wqp, *itemp)) != 0) {
			(void) fprintf(stderr, "test %s: failed to add item: "
			    "%s\n", wqt->wq_desc, strerror(errno));
			exit(1);
		}
		itemp++;
	}

	wqt_count = 0;
	ret = workq_work(wqp, wqt->wq_proc, NULL, &err);
	if (ret != wqt->wq_rval) {
		(void) fprintf(stderr, "test %s: got incorrect rval. "
		    "Expected %d, got %d (%d)\n", wqt->wq_desc, wqt->wq_rval,
		    ret, errno);
		exit(1);
	}

	if (ret == WORKQ_UERROR && err != wqt->wq_uerr) {
		(void) fprintf(stderr, "test %s: got incorrect user error. "
		    "Expected %d, got %d\n", wqt->wq_desc, wqt->wq_uerr, err);
		exit(1);
	}

	if (ret == 0 && wqt_count != wqt->wq_sum) {
		(void) fprintf(stderr, "test %s: got unexpected "
		    "result: %d, expected %d\n", wqt->wq_desc, wqt_count,
		    wqt->wq_sum);
		exit(1);
	}
}

int
main(void)
{
	int ret, i, t;
	workq_t *wqp;
	int nthreads[] = { 1, 2, 4, 8, 16, 32, 64, 128, 256, -1 };

	for (t = 0; nthreads[t] != -1; t++) {
		printf("Beginning tests with %d threads\n", nthreads[t]);
		if ((ret = workq_init(&wqp, nthreads[t])) != 0) {
			fprintf(stderr, "failed to init workq: %s\n",
			    strerror(errno));
			return (1);
		}

		for (i = 0; i < NWQ_TESTS; i++) {
			wq_test_run(wqp, &wq_tests[i]);
		}

		workq_fini(wqp);
	}


	return (0);
}
