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
	int res, err, fd;

	/* Open with a bad signal mask pointer */
	res = signalfd(-1, NULL, 0);
	err = errno;
	if (res != -1 || err != EFAULT) {
		test_fail("expected EFAULT for NULL signal mask"
		    ", found res=%d errno=%d", res, err);
	}

	sigset_t mask;
	assert(sigemptyset(&mask) == 0);

	/* Open with bad flags */
	res = signalfd(-1, &mask, ~0);
	err = errno;
	if (res != -1 || err != EINVAL) {
		test_fail("expected EINVAL bad flags"
		    ", found res=%d errno=%d", res, err);
	}

	/* Open basic instance and confirm empty flags */
	res = signalfd(-1, &mask, 0);
	err = errno;
	if (res < 0) {
		test_fail("failed to open signalfd, found res=%d errno=%d",
		    res, err);
	}
	fd = res;
	res = fcntl(fd, F_GETFL, 0);
	assert(res >= 0);
	if ((res & O_NONBLOCK) != 0) {
		test_fail("expected no O_NONBLOCK, found flags=0x%x", res);
	}
	res = fcntl(fd, F_GETFD, 0);
	assert(res >= 0);
	if ((res & FD_CLOEXEC) != 0) {
		test_fail("expected no FD_CLOEXEC, found fdflags=0x%x", res);
	}
	(void) close(fd);

	/* Open with NONBLOCK and CLOEXEC, and confirm flags */
	res = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
	err = errno;
	if (res < 0) {
		test_fail("failed to open signalfd, found res=%d errno=%d",
		    res, err);
	}
	fd = res;
	res = fcntl(fd, F_GETFL, 0);
	assert(res >= 0);
	if ((res & O_NONBLOCK) == 0) {
		test_fail("missing O_NONBLOCK, found flags=0x%x", res);
	}
	res = fcntl(fd, F_GETFD, 0);
	assert(res >= 0);
	if ((res & FD_CLOEXEC) == 0) {
		test_fail("missing FD_CLOEXEC, found fdflags=0x%x", res);
	}
	(void) close(fd);

	test_pass();
}
