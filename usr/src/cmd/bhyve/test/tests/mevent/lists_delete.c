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
 *        Test:	lists.delete
 *   Assertion: mevent_delete() causes the total number of events to decrease
 *
 *    Strategy: 1. Create a pipe.
 *		2. Call mevent_add() to be notified of writes to the pipe.  The
 *		   callback will do nothing other than generate an error if it
 *		   is called.
 *		3. Create another pipe and add a read event watcher to it.  The
 *		   callback will signal a cv when called.  A write to the pipe
 *		   followed by a wait on the cv will ensure that async
 *		   operations in mevent.c are complete.  See flush_and_wait().
 *		4. Call flush_and_wait(), then get event count.
 *		5. Delete the event created in step 2.
 *		6. Call flush_and_wait(), then get event count.
 *		7. Verify result in step 6 is one less than result in step 4.
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

static int
get_count(void)
{
	int global = -1, change = -1, del_pending = -1;
	int total;

	test_mevent_count_lists(&global, &change, &del_pending);
	ASSERT_INT_NEQ(("count not set"), global, -1);
	ASSERT_INT_NEQ(("count not set"), change, -1);
	ASSERT_INT_NEQ(("count not set"), change, -1);
	ASSERT_INT_EQ(("pending delete not processed"), del_pending, 0);

	total = global + change + del_pending;

	VERBOSE(("count = %d (%d + %d + %d)", total, global, change,
	    del_pending));

	return (total);
}

static void
not_called_cb(int fd, enum ev_type ev, void *arg)
{
	FAIL(("this callback should never be called"));
}

static void
flush_cb(int fd, enum ev_type ev, void *arg)
{
	char buf[32];

	/* Drain the pipe */
	while (read(fd, buf, sizeof (buf)) > 0)
		;

	pthread_mutex_lock(&mtx);
	pthread_cond_signal(&cv);
	pthread_mutex_unlock(&mtx);
}

void
flush_and_wait(int fd)
{
	uint8_t msg = 42;

	/*
	 * Lock taken ahead of waking flush_cb so this thread doesn't race
	 * with the event thread.
	 */
	pthread_mutex_lock(&mtx);
	if (write(fd, &msg, sizeof (msg)) != sizeof (msg)) {
		FAIL(("bad write"));
	}

	/* Wait for it to be read */
	pthread_cond_wait(&cv, &mtx);
	pthread_mutex_unlock(&mtx);
}

int
main(int argc, const char *argv[])
{
	int unused_pipe[2];
	int flush_pipe[2];
	struct mevent *unused_evp, *flush_evp;
	int count1, count2;

	start_test(argv[0], 5);
	start_event_thread();

	/*
	 * Create first pipe and related event
	 */
	if (pipe(unused_pipe) != 0) {
		FAIL_ERRNO("pipe");
	}
	VERBOSE(("unused_pipe[] = { %d, %d }", unused_pipe[0], unused_pipe[1]));
	if (fcntl(unused_pipe[0], F_SETFL, O_NONBLOCK) != 0) {
		FAIL_ERRNO("set pipe nonblocking");
	}
	unused_evp = mevent_add(unused_pipe[0], EVF_READ, not_called_cb, NULL);
	ASSERT_PTR_NEQ(("mevent_add"), unused_evp, NULL);

	/*
	 * Create flush pipe and related event
	 */
	if (pipe(flush_pipe) != 0) {
		FAIL_ERRNO("pipe");
	}
	VERBOSE(("flush_pipe[] = { %d, %d }", flush_pipe[0],
	    flush_pipe[1]));
	if (fcntl(flush_pipe[0], F_SETFL, O_NONBLOCK) != 0) {
		FAIL_ERRNO("set pipe nonblocking");
	}
	flush_evp = mevent_add(flush_pipe[0], EVF_READ, flush_cb, NULL);
	ASSERT_PTR_NEQ(("mevent_add"), flush_evp, NULL);

	/* Get count before delete. */
	flush_and_wait(flush_pipe[1]);
	count1 = get_count();

	/*
	 * Delete the first event and flush a read after the delete is
	 * complete.
	 */
	if (mevent_delete(unused_evp) != 0) {
		FAIL_ERRNO("mevent_delete");
	}

	/*
	 * Verify count decreased.
	 */
	flush_and_wait(flush_pipe[1]);
	count2 = get_count();
	if (count1 - 1 != count2) {
		FAIL(("mevent_delete() did not decrease count by 1: "
		    "was %d, now %d", count1, count2));
	}

	PASS();
}
