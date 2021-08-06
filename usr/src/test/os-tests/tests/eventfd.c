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
 * Copyright 2021 OmniOS Community Edition (OmniOSce) Association.
 */

#include <err.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/debug.h>
#include <sys/eventfd.h>
#include <unistd.h>

static int
readn(int fd, uint_t n)
{
	uint_t i;
	int failures = 0;

	for (i = 0; i < n; i++) {
		eventfd_t v = 0xdeadbeef;
		int ret;

		ret = eventfd_read(fd, &v);
		if (ret != 0) {
			warn("Reading %u/%u got ret %d (expected 0)",
			    i + 1, n, ret);
			failures++;
		} else if (v != 1) {
			warnx("Reading %u/%u got value %"PRIu64" (expected 1)",
			    i + 1, n, v);
			failures++;
		}
	}

	return (failures);
}

static int
check_nosem(int fd)
{
	eventfd_t v = 0xdeadbeef;
	int failures = 0;
	int ret;

	ret = eventfd_read(fd, &v);

	if (ret != -1) {
		warnx("no semaphores read got ret %d (expected -1)", ret);
		failures++;
	}

	if (errno != EAGAIN) {
		warn("no semaphores read expected EAGAIN but got");
		failures++;
	}

	if (v != 0xdeadbeef) {
		warnx("no semaphores read modified value to %"PRIx64, v);
		failures++;
	}

	return (failures);
}

static int
check_badwrite(int fd)
{
	int failures = 0;
	int ret;

	ret = eventfd_write(fd, ULLONG_MAX);

	if (ret != -1) {
		warnx("bad write got ret %d (expected -1)", ret);
		failures++;
	}

	if (errno != EINVAL) {
		warn("bad write expected EINVAL but got");
		failures++;
	}

	return (failures);
}

int
main(void)
{
	int fd, failures = 0;

	/* Test eventfd semaphore semantics */
	fd = eventfd(2, EFD_NONBLOCK | EFD_CLOEXEC | EFD_SEMAPHORE);
	if (fd == -1)
		err(EXIT_FAILURE, "Could not create eventfd semaphore");

	/* Consume the available semaphores */
	failures += readn(fd, 2);

	/* The next read should return -1/EAGAIN */
	failures += check_nosem(fd);

	/* Return two + three semaphores */
	if (eventfd_write(fd, 2) != 0) {
		warn("Error while returning two semaphores");
		failures++;
	}
	if (eventfd_write(fd, 3) != 0) {
		warn("Error while returning three semaphores");
		failures++;
	}

	/* Consume the available semaphores */
	failures += readn(fd, 5);

	/* The next read should return -1/EAGAIN */
	failures += check_nosem(fd);

	/*
	 * Check that a writing too large a value results in an error from
	 * eventfd_write() - testing that an error from the underlying write()
	 * is passed back.
	 */
	failures += check_badwrite(fd);

	VERIFY0(close(fd));

	return (failures == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
