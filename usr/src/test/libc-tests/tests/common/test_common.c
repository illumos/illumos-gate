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
 * Copyright 2014 Garrett D'Amore <garrett@damore.org>
 */

/*
 * Common handling for test programs.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <pthread.h>
#include "test_common.h"

static int debug = 0;
static int force = 0;
static pthread_mutex_t lk;

struct test {
	char		*name;
	int		ntids;
	pthread_t	*tids;
	int		fails;
	void		*arg;
	void		(*func)(test_t t, void *);
};

void
test_set_debug(void)
{
	debug++;
}

void
test_set_force(void)
{
	force++;
}

test_t
test_start(const char *format, ...)
{
	va_list args;
	test_t t;
	char *s;

	t = calloc(1, sizeof (*t));
	va_start(args, format);
	(void) vasprintf(&s, format, args);
	va_end(args);

	(void) asprintf(&t->name, "%s (%s)", s, ARCH);
	free(s);

	(void) pthread_mutex_lock(&lk);
	(void) printf("TEST STARTING %s:\n", t->name);
	(void) fflush(stdout);
	(void) pthread_mutex_unlock(&lk);

#ifdef	LINT
	/* We inject references to make avoid name unused warnings */
	test_run(0, NULL, NULL, NULL);
	test_debugf(t, NULL);
	test_failed(t, NULL);
	test_passed(t);
	test_set_debug();
	test_set_force();
#endif

	return (t);

}

void
test_failed(test_t t, const char *format, ...)
{
	va_list args;

	(void) pthread_mutex_lock(&lk);
	if (force || (t->ntids > 0)) {
		(void) printf("TEST FAILING %s: ", t->name);
	} else {
		(void) printf("TEST FAILED %s: ", t->name);
	}

	va_start(args, format);
	(void) vprintf(format, args);
	va_end(args);
	(void) printf("\n");
	(void) fflush(stdout);
	(void) pthread_mutex_unlock(&lk);

	t->fails++;
	if (!force) {
		if (t->ntids > 0) {
			pthread_exit(NULL);
		} else {
			(void) exit(EXIT_FAILURE);
		}
	}
}

void
test_passed(test_t t)
{
	if (t->ntids > 0) {
		if (debug) {
			(void) pthread_mutex_lock(&lk);
			(void) printf("TEST PASSING: %s\n", t->name);
			(void) pthread_mutex_unlock(&lk);
		}
		return;
	}
	(void) pthread_mutex_lock(&lk);
	if (t->fails == 0) {
		(void) printf("TEST PASS: %s\n", t->name);
	} else {
		(void) printf("TEST FAILED: %d failures\n", t->fails);
	}
	(void) fflush(stdout);
	(void) pthread_mutex_unlock(&lk);
	free(t->name);
	if (t->tids) {
		free(t->tids);
	}
	free(t);
}

void
test_debugf(test_t t, const char *format, ...)
{
	va_list args;

	if (!debug)
		return;

	(void) pthread_mutex_lock(&lk);
	(void) printf("TEST DEBUG %s: ", t->name);

	va_start(args, format);
	(void) vprintf(format, args);
	va_end(args);
	(void) printf("\n");
	(void) fflush(stdout);
	(void) pthread_mutex_unlock(&lk);
}

static void *
test_thr_one(void *arg)
{
	test_t t = arg;
	t->func(t, t->arg);
	return (NULL);
}

void
test_run(int nthr, void (*func)(test_t, void *), void *arg,
    const char *tname, ...)
{
	test_t		t;
	char		*s;
	va_list		args;

	t = calloc(1, sizeof (*t));
	t->ntids = nthr;
	t->tids = calloc(nthr, sizeof (pthread_t));
	t->func = func;
	t->arg = arg;

	va_start(args, tname);
	(void) vasprintf(&s, tname, args);
	va_end(args);

	(void) asprintf(&t->name, "%s (%s)", s, ARCH);
	free(s);

	(void) pthread_mutex_lock(&lk);
	(void) printf("TEST STARTING %s:\n", t->name);
	(void) fflush(stdout);
	(void) pthread_mutex_unlock(&lk);

	test_debugf(t, "running %d threads", nthr);

	for (int i = 0; i < nthr; i++) {
		test_debugf(t, "started thread %d", i);
		(void) pthread_create(&t->tids[i], NULL, test_thr_one, t);
	}

	for (int i = 0; i < nthr; i++) {
		(void) pthread_join(t->tids[i], NULL);
		test_debugf(t, "thread %d joined", i);
		t->ntids--;
	}
	test_passed(t);
}
