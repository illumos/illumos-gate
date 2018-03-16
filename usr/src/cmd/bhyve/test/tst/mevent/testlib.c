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
 * Copyright 2018 Joyent, Inc.
 */

#include <pthread.h>
#include <signal.h>
#include <strings.h>
#include <unistd.h>

#include "testlib.h"
#include "mevent.h"

const char *testlib_prog;
boolean_t testlib_verbose;

static void
timed_out(int signo) {
	ASSERT_INT_EQ(("timeout signal"), signo, SIGALRM);

	FAIL(("Timed out"));
}

void
start_test(const char *argv0, uint32_t timeout)
{
	char *val;

	testlib_prog = strrchr(argv0, '/');
	if (testlib_prog == NULL) {
		testlib_prog = argv0;
	} else {
		testlib_prog++;
	}

	testlib_verbose = ((val = getenv("TEST_VERBOSE")) != NULL) &&
	    val[0] != '\0';

	signal(SIGALRM, timed_out);
	alarm(timeout);
}

/* ARGSUSED */
static void *
event_thread(void *arg)
{
	mevent_dispatch();
	return (NULL);
}

void
start_event_thread(void)
{
	pthread_t tid;

	if (pthread_create(&tid, NULL, event_thread, NULL) != 0) {
		FAIL_ERRNO("pthread_create");
	}
}
