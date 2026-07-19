/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version 1.0
 * (the "License").
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Verify that closing one of two descriptors for the same STREAMS vnode does
 * not confuse poll cache state belonging to the other descriptor.  On DEBUG
 * kernels, checkwfdlist() used to assert that every same-process entry on the
 * vnode's pollhead appears on the closing descriptor's per-fd fpollinfo list,
 * panicking on this pattern. Non-DEBUG builds compile the check out.  Keeping
 * both polling threads alive while one descriptor is closed exercises the
 * necessary check.
 */

#include <poll.h>
#include <pthread.h>
#include <stdlib.h>
#include <sys/debug.h>
#include <unistd.h>

typedef struct poll_arg {
	int		pa_fd;
	pthread_barrier_t *pa_ready;
	pthread_barrier_t *pa_done;
} poll_arg_t;

static void
barrier_wait(pthread_barrier_t *barrier)
{
	int ret = pthread_barrier_wait(barrier);

	VERIFY(ret == 0 || ret == PTHREAD_BARRIER_SERIAL_THREAD);
}

static void *
poller(void *arg)
{
	poll_arg_t *pa = arg;
	struct pollfd pfd = {
		.fd = pa->pa_fd,
		.events = POLLIN
	};

	VERIFY0(poll(&pfd, 1, 0));
	VERIFY0(pfd.revents);

	barrier_wait(pa->pa_ready);
	barrier_wait(pa->pa_done);

	return (NULL);
}

int
main(void)
{
	pthread_barrier_t ready, done;
	pthread_t threads[2];
	poll_arg_t args[2];
	int pipefds[2];

	VERIFY0(pipe(pipefds));
	args[0].pa_fd = pipefds[0];
	args[1].pa_fd = dup(pipefds[0]);
	VERIFY3S(args[1].pa_fd, >=, 0);

	VERIFY0(pthread_barrier_init(&ready, NULL, 3));
	VERIFY0(pthread_barrier_init(&done, NULL, 3));

	for (uint_t i = 0; i < 2; i++) {
		args[i].pa_ready = &ready;
		args[i].pa_done = &done;
		VERIFY0(pthread_create(&threads[i], NULL, poller, &args[i]));
	}

	barrier_wait(&ready);
	VERIFY0(close(args[0].pa_fd));
	barrier_wait(&done);

	for (uint_t i = 0; i < 2; i++)
		VERIFY0(pthread_join(threads[i], NULL));

	VERIFY0(pthread_barrier_destroy(&ready));
	VERIFY0(pthread_barrier_destroy(&done));
	VERIFY0(close(args[1].pa_fd));
	VERIFY0(close(pipefds[1]));

	return (EXIT_SUCCESS);
}
