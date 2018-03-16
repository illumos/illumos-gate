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
 *        Test:	read.cancel
 *   Assertion: A read is not requeued if mevent_disable() is called while it is
 *		being handled.
 *
 *    Strategy: 1. Create a pipe
 *		2. Call mevent_add() to be notified of writes to the pipe.  The
 *		   callback will signal a cv.
 *		3. Write to the pipe then wait for a wakeup.
 *		4. From the read event callback, disable the event then awaken
 *		   the main thread.
 *		5. In the main thread, add a timer event that will awaken the
 *		   main thread after a short delay.
 *		5. Write to the pipe and wait to be awoken.  The wakeup should
 *		   come from the timer event, not the read event.
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

typedef enum {
	CB_NONE,
	CB_READ,
	CB_TIMER,
} lastwake_t;

static lastwake_t lastwake = CB_NONE;

static pthread_mutex_t mtx = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t cv = PTHREAD_COND_INITIALIZER;

static struct mevent *read_event;

static void
munch(int fd, enum ev_type ev, void *arg)
{
	ssize_t nbytes;
	char buf[32] = { 0 };
	int err;

	if ((nbytes = read(fd, buf, sizeof (buf))) < 0) {
		FAIL_ERRNO("bad read");
	}
	VERBOSE(("read %ld bytes '%s'", nbytes, buf));

	err = mevent_disable(read_event);
	ASSERT_INT_EQ(("mevent_disable: ", strerror(err)), err, 0);

	pthread_mutex_lock(&mtx);

	ASSERT_INT_EQ(("wrong lastwake"), lastwake, CB_NONE);
	lastwake = CB_READ;

	pthread_cond_signal(&cv);
	VERBOSE(("wakeup"));

	pthread_mutex_unlock(&mtx);
}

static void
tick(int ms, enum ev_type ev, void *arg)
{
	pthread_mutex_lock(&mtx);

	ASSERT_INT_EQ(("wrong lastwake"), lastwake, CB_READ);
	lastwake = CB_TIMER;

	pthread_cond_signal(&cv);
	VERBOSE(("wakeup"));

	pthread_mutex_unlock(&mtx);
}

int
main(int argc, const char *argv[])
{
	int pipefds[2];
	struct mevent *timer;
	ssize_t written;
	char *msgs[] = { "first", "second" };
	char *msg;

	start_test(argv[0], 5);
	start_event_thread();

	if (pipe(pipefds) != 0) {
		FAIL_ERRNO("pipe");
	}
	if (fcntl(pipefds[0], F_SETFL, O_NONBLOCK) != 0) {
		FAIL_ERRNO("set pipe nonblocking");
	}

	/*
	 * First write
	 */
	msg = msgs[0];
	read_event = mevent_add(pipefds[0], EVF_READ, munch, msg);
	ASSERT_PTR_NEQ(("mevent_add pipefd"), read_event, NULL);

	pthread_mutex_lock(&mtx);
	written = write(pipefds[1], msg, strlen(msg));
	if (written < 0) {
		FAIL_ERRNO("bad write");
	}
	ASSERT_INT64_EQ(("write '%s' failed", msg), written, strlen(msg));

	/*
	 * Wait for it to be read
	 */
	pthread_cond_wait(&cv, &mtx);
	ASSERT_INT_EQ(("wrong lastwake"), lastwake, CB_READ);
	pthread_mutex_unlock(&mtx);

	/*
	 * Add timer, second write.
	 */
	msg = msgs[1];
	timer = mevent_add(50, EVF_TIMER, tick, msg);
	ASSERT_PTR_NEQ(("mevent_add timer"), timer, NULL);

	pthread_mutex_lock(&mtx);
	written = write(pipefds[1], msg, strlen(msg));
	if (written < 0) {
		FAIL_ERRNO("bad write");
	}
	ASSERT_INT64_EQ(("write '%s' failed", msg), written, strlen(msg));

	/*
	 * Wait for timer to expire
	 */
	pthread_cond_wait(&cv, &mtx);
	ASSERT_INT_EQ(("wrong lastwake"), lastwake, CB_TIMER);
	pthread_mutex_unlock(&mtx);

	PASS();
}
