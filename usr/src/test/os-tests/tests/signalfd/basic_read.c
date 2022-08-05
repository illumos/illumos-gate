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
 * Copyright 2023 Oxide Computer Company
 */


#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "common.h"

int
main(void)
{
	int err;
	ssize_t sz;
	signalfd_siginfo_t info[3];

	const int fd = test_basic_prep(0);

	/* A too-small read should yield EINVAL */
	sz = read(fd, info, sizeof (signalfd_siginfo_t) - 1);
	err = errno;
	if (sz != -1 || errno != EINVAL) {
		test_fail("expected EINVAL for too-small read, "
		    "found res=%ld errno=%d", sz, err);
	}

	const int pid = getpid();

	/* simple single read */
	assert(kill(pid, SIGUSR1) == 0);
	sz = read(fd, info, sizeof (signalfd_siginfo_t));
	err = errno;
	if (sz != sizeof (signalfd_siginfo_t)) {
		test_fail("bad read result, found sz=%ld errno=%d", sz, err);
	}
	if (info[0].ssi_signo != SIGUSR1) {
		test_fail("bad ssi_signo %d != %d", info[0].ssi_signo, SIGUSR1);
	}

	struct sigevent sigev = {
		.sigev_notify = SIGEV_SIGNAL,
		.sigev_signo = SIGALRM,
	};
	timer_t tid;
	struct itimerspec its_1ms = {
		.it_value = {
			.tv_sec = 0,
			.tv_nsec = MSEC2NSEC(1),
		}
	};

	/* block for a single read: a SIGALRM 1ms in the future */
	assert(timer_create(CLOCK_HIGHRES, &sigev, &tid) == 0);
	assert(timer_settime(tid, 0, &its_1ms, NULL) == 0);
	sz = read(fd, info, sizeof (signalfd_siginfo_t));
	err = errno;
	if (sz != sizeof (signalfd_siginfo_t)) {
		test_fail("bad read result, found sz=%ld errno=%d", sz, err);
	}
	if (info[0].ssi_signo != SIGALRM) {
		test_fail("bad ssi_signo %d != %d", info[0].ssi_signo, SIGALRM);
	}

	/*
	 * If we get a result during a read, we should not block until the
	 * entire buffer is full, but rather return what we have.
	 */
	assert(kill(pid, SIGUSR1) == 0);
	assert(kill(pid, SIGUSR2) == 0);
	sz = read(fd, info, sizeof (info));
	err = errno;
	if (sz != (2 * sizeof (signalfd_siginfo_t))) {
		test_fail("bad read result, found sz=%ld errno=%d", sz, err);
	}
	if (info[0].ssi_signo != SIGUSR1) {
		test_fail("bad ssi_signo %d != %d", info[0].ssi_signo, SIGUSR1);
	}
	if (info[1].ssi_signo != SIGUSR2) {
		test_fail("bad ssi_signo %d != %d", info[1].ssi_signo, SIGUSR2);
	}

	test_pass();
}
