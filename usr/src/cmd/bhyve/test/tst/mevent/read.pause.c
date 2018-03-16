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

/*
 *        Test:	read.pause
 *   Assertion: mevent_disable() can be used to pause reads.
 *
 *    Strategy: 1. Create a pipe
 *		2. Call mevent_add() to be notified of writes to the pipe.  The
 *		   callback will signal a cv.
 *		3. In a loop, write to the pipe then wait on the cv.
 */

#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>

#include "testlib.h"
#include "mevent.h"

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

static char cookie[] = "Chocolate chip with fudge stripes";

/*
 * After this many bytes are sent, writes will get batched up, progress will be
 * made on the write side via an interval timer
 */
const int pauseat = 8;

static void
munch(int fd, enum ev_type ev, void *arg)
{
	static int i = 0;
	char buf[sizeof (cookie)] = { 0 };
	ssize_t nbytes;
	ssize_t expected;

	ASSERT_INT_EQ(("bad event"), ev, EVF_READ);
	ASSERT_PTR_EQ(("bad cookie"), arg, cookie);

	/*
	 * For the first while, expect data to come a byte at a time.  After the
	 * pause, we should get a burst with the rest of the data.
	 */
	if (i > pauseat) {
		expected = strlen(cookie) - pauseat - 1;
	} else {
		expected = 1;
	}

	if ((nbytes = read(fd, buf, sizeof (buf))) < 0) {
		FAIL_ERRNO("bad read");
	}
	VERBOSE(("read %ld bytes '%s'", nbytes, buf));

	ASSERT_INT64_EQ(("wanted a byte of cookie"), nbytes, expected);

	if (expected == 1) {
		ASSERT_CHAR_EQ(("bad byte %d of cookie", i), buf[0], cookie[i]);
	} else {
		ASSERT_STR_EQ(("bad last half of cookie"), buf, &cookie[i]);
	}

	pthread_mutex_lock(&mtx);
	pthread_cond_signal(&cv);
	VERBOSE(("wakeup"));
	pthread_mutex_unlock(&mtx);

	i++;
}

static void
tick(int ms, enum ev_type ev, void *arg)
{
	pthread_mutex_lock(&mtx);
	pthread_cond_signal(&cv);
	VERBOSE(("wakeup"));
	pthread_mutex_unlock(&mtx);
}

int
main(int argc, const char *argv[])
{
	int pipefds[2];
	struct mevent *evp, *timer;
	ssize_t written;

	start_test(argv[0], 5);
	start_event_thread();

	if (pipe(pipefds) != 0) {
		FAIL_ERRNO("pipe");
	}
	if (fcntl(pipefds[0], F_SETFL, O_NONBLOCK) != 0) {
		FAIL_ERRNO("set pipe nonblocking");
	}

	evp = mevent_add(pipefds[0], EVF_READ, munch, cookie);
	ASSERT_PTR_NEQ(("mevent_add pipefd"), evp, NULL);

	for (int i = 0; cookie[i] != 0; i++) {
		pthread_mutex_lock(&mtx);
		written = write(pipefds[1], cookie + i, 1);
		if (written < 0) {
			FAIL_ERRNO("bad write");
		}
		ASSERT_INT64_EQ(("write byte %d of cookie", i), written, 1);

		/* Wait for it to be read */
		pthread_cond_wait(&cv, &mtx);
		pthread_mutex_unlock(&mtx);

		if (i == pauseat) {
			timer = mevent_add(10, EVF_TIMER, tick,
			    &cookie[pauseat]);
			ASSERT_PTR_NEQ(("mevent_add timer"), timer, NULL);
			VERBOSE(("disable munch"));
			mevent_disable(evp);
		}
	}

	pthread_mutex_lock(&mtx);

	mevent_enable(evp);

	pthread_cond_wait(&cv, &mtx);
	pthread_mutex_unlock(&mtx);

	PASS();
}
