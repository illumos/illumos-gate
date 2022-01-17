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
 *        Test:	read.requeue
 *   Assertion: A sequence of writes turns into a sequence of events.
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

static char *cookie = "Chocolate chip with fudge stripes";

static void
munch(int fd, enum ev_type ev, void *arg)
{
	static int i = 0;
	char buf[8] = { 0 };
	ssize_t nbytes;

	ASSERT_INT_EQ(("bad event"), ev, EVF_READ);
	ASSERT_PTR_EQ(("bad cookie"), arg, cookie);

	if ((nbytes = read(fd, buf, sizeof (buf))) < 0) {
		ASSERT_INT64_EQ(("bad read: %s", strerror(errno)), nbytes, 1);
	}
	VERBOSE(("read %ld bytes '%s'", nbytes, buf));

	ASSERT_INT64_EQ(("wanted a byte of cookie"), nbytes, 1);

	ASSERT_CHAR_EQ(("bad byte %d of cookie", i), buf[0], cookie[i]);

	pthread_mutex_lock(&mtx);
	pthread_cond_signal(&cv);
	VERBOSE(("wakeup"));
	pthread_mutex_unlock(&mtx);

	i++;
}

int
main(int argc, const char *argv[])
{
	int pipefds[2];
	struct mevent *evp;

	start_test(argv[0], 5);
	start_event_thread();

	if (pipe(pipefds) != 0) {
		FAIL_ERRNO("pipe");
	}
	if (fcntl(pipefds[0], F_SETFL, O_NONBLOCK) != 0) {
		FAIL_ERRNO("set pipe nonblocking");
	}

	evp = mevent_add(pipefds[0], EVF_READ, munch, cookie);
	ASSERT_PTR_NEQ(("mevent_add"), evp, NULL);

	for (int i = 0; cookie[i] != '\0'; i++) {
		ssize_t written;

		pthread_mutex_lock(&mtx);
		written = write(pipefds[1], cookie + i, 1);
		if (written < 0) {
			FAIL_ERRNO("bad write");
		}
		ASSERT_INT64_EQ(("write byte %d of cookie", i), written, 1);

		/* Wait for it to be read */
		pthread_cond_wait(&cv, &mtx);
		pthread_mutex_unlock(&mtx);
	}

	PASS();
}
