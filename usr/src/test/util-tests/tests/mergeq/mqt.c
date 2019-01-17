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
 * mergeq testing routines
 */

#include <mergeq.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>

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
mergeq_alloc(size_t size)
{
	return (malloc(size));
}

/*ARGSUSED*/
void
mergeq_free(void *buf, size_t size)
{
	free(buf);
}

static int
mqt_int(void *first, void *second, void **outp, void *arg)
{
	uintptr_t a, b, c;
	a = (uintptr_t)first;
	b = (uintptr_t)second;
	c = a + b;
	*outp = (void *)c;

	return (0);
}

static int
mqt_append(void *first, void *second, void **outp, void *arg)
{
	char *out;

	/* Yes, this leaks, don't worry about it for the test */
	if (asprintf(&out, "%s%s", first, second) != -1) {
		*outp = out;
		return (0);
	}
	return (-1);
}

static int
mqt_fatal(void *first, void *second, void **outp, void *arg)
{
	return (-1);
}

/*
 * Test structures and cases. We really want mq_args to be a flexible array
 * member, but then we cant initialize it. Thus we set a fixed size number of
 * entries.
 */
typedef struct mq_test {
	const char	*mq_desc;	/* test description/name */
	mergeq_proc_f	*mq_proc;	/* processing function */
	int		mq_rval;	/* mergeq_merge return value */
	int		mq_uerr;	/* user error, if any */
	boolean_t	mq_strcmp;	/* use strcmp rather than == */
	void		*mq_result;	/* expected result */
	void		**mq_args;	/* argument array */
} mq_test_t;

static void *mqt_empty_args[] = { NULL };
static void *mqt_single_args[] = { (void *)42, NULL };
static void *mqt_double_args[] = { (void *)42, (void *)27, NULL };
static void *mqt_wrap_args[] = {
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
static void *mqt_grow_args[] = {
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
static void *mqt_order_args[] = { "l", "e", "g", "e", "n", "d", " ", "o", "f",
	" ", "z", "e", "l", "d", "a", NULL };


static mq_test_t mq_tests[] = {
	{ "empty", mqt_int, 0, 0, B_FALSE, NULL, mqt_empty_args },
	{ "single", mqt_int, 0, 0, B_FALSE, (void *)42, mqt_single_args },
	{ "double", mqt_int, 0, 0, B_FALSE, (void *)69, mqt_double_args },
	{ "wrap", mqt_int, 0, 0, B_FALSE, (void *)64, mqt_wrap_args },
	{ "grow", mqt_int, 0, 0, B_FALSE, (void *)92, mqt_grow_args },
	{ "fatal", mqt_fatal, MERGEQ_UERROR, -1, B_FALSE, NULL,
	    mqt_double_args },
	{ "order", mqt_append, 0, 0, B_TRUE, "alegend of zeld", mqt_order_args }
};

#define	NMQ_TESTS (sizeof (mq_tests) / sizeof (mq_test_t))

static void
mq_test_run(mergeq_t *mqp, mq_test_t *mqt)
{
	int ret, err;
	void **itemp = mqt->mq_args;
	void *out;

	while (*itemp != NULL) {
		if ((ret = mergeq_add(mqp, *itemp)) != 0) {
			(void) fprintf(stderr,
			    "test %s: failed to add item: %s\n",
			    mqt->mq_desc, strerror(errno));
			exit(1);
		}
		itemp++;
	}

	ret = mergeq_merge(mqp, mqt->mq_proc, NULL, &out, &err);
	if (ret != mqt->mq_rval) {
		(void) fprintf(stderr, "test %s: got incorrect rval. "
		    "Expected %d, got %d\n", mqt->mq_desc, mqt->mq_rval, ret);
		exit(1);
	}

	if (ret == MERGEQ_UERROR && err != mqt->mq_uerr) {
		(void) fprintf(stderr, "test %s: got incorrect user error. "
		    "Expected %d, got %d\n", mqt->mq_desc, mqt->mq_uerr, err);
		exit(1);
	}

	if (ret == 0) {
		if (mqt->mq_strcmp == B_TRUE &&
		    strcmp(out, mqt->mq_result) != 0) {
			(void) fprintf(stderr, "test %s: got unexpected "
			    "result: %s, expected %s\n", mqt->mq_desc, out,
			    mqt->mq_result);
			exit(1);
		} else if (mqt->mq_strcmp == B_FALSE && out != mqt->mq_result) {
			(void) fprintf(stderr, "test %s: got unexpected "
			    "result: %p, expected %p\n", mqt->mq_desc, out,
			    mqt->mq_result);
			exit(1);
		}
	}
}

int
main(void)
{
	int ret, i, t;
	mergeq_t *mqp;
	int nthreads[] = { 1, 2, 4, 8, 16, 32, 64, 128, 256, -1 };

	for (t = 0; nthreads[t] != -1; t++) {
		printf("Beginning tests with %d threads\n", nthreads[t]);
		if ((ret = mergeq_init(&mqp, nthreads[t])) != 0) {
			fprintf(stderr, "failed to init mergeq: %s\n",
			    strerror(errno));
			return (1);
		}

		for (i = 0; i < NMQ_TESTS; i++) {
			mq_test_run(mqp, &mq_tests[i]);
		}

		mergeq_fini(mqp);
	}

	return (0);
}
