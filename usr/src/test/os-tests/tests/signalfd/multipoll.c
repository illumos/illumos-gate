
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
#include <sys/devpoll.h>

#include "common.h"

int
main(void)
{
	sigset_t mask;

	assert(sigemptyset(&mask) == 0);
	int sigfd1 = signalfd(-1, &mask, 0);
	int sigfd2 = signalfd(-1, &mask, 0);

	if (sigfd1 == -1 || sigfd2 == -1) {
		test_fail("unable to initialize signalfd resources");
	}

	int pfd = open("/dev/poll", O_RDWR);
	if (pfd == -1) {
		test_fail("unable to initialize devpoll resource");
	}

	struct pollfd buf[2] = {
		{
			.fd = sigfd1,
			.events = POLLIN,
		},
		{
			.fd = sigfd2,
			.events = POLLIN,
		}
	};
	ssize_t wrote = write(pfd, buf, sizeof (buf));
	if (wrote != sizeof (buf)) {
		test_fail("unable to establish polling");
	}

	(void) close(sigfd1);
	(void) close(sigfd2);
	test_pass();
}
