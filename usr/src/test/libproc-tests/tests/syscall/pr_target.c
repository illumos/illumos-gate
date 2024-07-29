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
 * Copyright 2024 Oxide Computer Company
 */

/*
 * This program serves as a target for the pr_inject program to run.
 * pr_target_hook() is used as a place to set a breakpoint and the before and
 * after point for the test. pr_inject will modify a bunch of our state
 * (currently file descriptors) and then we will validate it after we run again.
 */

#include <stdlib.h>
#include <err.h>
#include <libproc.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <sys/debug.h>

#include "pr_target.h"

/*
 * This is used as a place to set a breakpoint for the target to find us. It is
 * a weak symbol to help avoid compiler optimization.
 */
#pragma weak pr_target_hook
void
pr_target_hook(void)
{
}

static bool
pr_target_check_fd(const char *desc, int fd, int fflag, int fdflags,
    const struct stat *st)
{
	int val;
	bool ret = true;
	struct stat targ;

	val = fcntl(fd, F_GETFL, NULL);
	if (val < 0) {
		warn("TEST FAILED: %s F_GETFL failed", desc);
		ret = false;
	} else if ((val & O_ACCMODE) != fflag) {
		warnx("TEST FAILED: %s: open flags mismatch: found 0x%x, "
		    "expected 0x%x", desc, val & O_ACCMODE, fflag);
		ret = false;
	} else {
		(void) printf("TEST PASSED: %s: injected open flags match "
		    "expected value\n", desc);
	}

	val = fcntl(fd, F_GETFD, NULL);
	if (val < 0) {
		warn("TEST FAILED: %s F_GETFD failed", desc);
		ret = false;
	} else if (val != fdflags) {
		warnx("TEST FAILED: %s: fd flags mismatch: found 0x%x, "
		    "expected 0x%x", desc, val, fdflags);
		ret = false;
	} else {
		(void) printf("TEST PASSED: %s: injected fd flags match "
		    "expected value\n", desc);
	}

	if (fstat(fd, &targ) != 0) {
		warn("TEST FAILED: %s: failed to stat fd", desc);
		ret = false;
	} else if (st->st_ino != targ.st_ino || st->st_dev != targ.st_dev ||
	    st->st_rdev != targ.st_rdev) {
		warnx("TEST FAILED: %s: fstat data does not match "
		    "expectations", desc);
		ret = false;
	} else {
		(void) printf("TEST PASSED: %s: fstat information matched\n",
		    desc);
	}

	return (ret);
}

int
main(void)
{
	int ret = EXIT_SUCCESS;
	struct stat nstat, zstat;
	int fd;

	(void) closefrom(STDERR_FILENO + 1);

	fd = open("/dev/null", PRT_NULL_OFLAG);
	if (fd < 0) {
		errx(EXIT_FAILURE, "TEST FAILED: failed to open /dev/null");
	}
	VERIFY3S(fd, ==, PRT_NULL_FD);

	if (fstat(fd, &nstat) != 0) {
		err(EXIT_FAILURE, "failed to fstat /dev/null");
	}

	fd = open("/dev/zero", O_RDONLY);
	if (fd < 0) {
		errx(EXIT_FAILURE, "TEST FAILED: failed to open /dev/zero");
	}
	VERIFY3S(fd, ==, PRT_CLOSE_FD);

	if (fstat(fd, &zstat) != 0) {
		err(EXIT_FAILURE, "failed to fstat /dev/zero");
	}

	pr_target_hook();

	if (!pr_target_check_fd("normal open", PRT_NULL_FD, PRT_NULL_OFLAG,
	    PRT_NULL_GETFD, &nstat)) {
		ret = EXIT_FAILURE;
	}

	if (!pr_target_check_fd("injected open", PRT_ZERO_FD, PRT_ZERO_OFLAG,
	    PRT_ZERO_GETFD, &zstat)) {
		ret = EXIT_FAILURE;
	}

	if (!pr_target_check_fd("injected F_DUPFD", PRT_DUP_FD, PRT_DUP_OFLAG,
	    PRT_DUP_GETFD, &nstat)) {
		ret = EXIT_FAILURE;
	}

	if (!pr_target_check_fd("injected F_DUP2FD_CLOFORK", PRT_CLOFORK_FD,
	    PRT_CLOFORK_OFLAG, PRT_CLOFORK_GETFD, &nstat)) {
		ret = EXIT_FAILURE;
	}

	if (!pr_target_check_fd("injected F_DUP3FD", PRT_DUP3_FD,
	    PRT_DUP3_OFLAG, PRT_DUP3_GETFD, &zstat)) {
		ret = EXIT_FAILURE;
	}

	/*
	 * The close fd we expect to have been closed already.
	 */
	if (fcntl(PRT_CLOSE_FD, F_GETFD, NULL) != -1) {
		warnx("TEST FAILED: fstat on supposedly closed fd worked");
		ret = false;
	} else if (errno != EBADF) {
		warnx("TEST FAILED: expected EBADF on closed fd, but found %s",
		    strerrorname_np(errno));
		ret = false;
	} else {
		(void) printf("TEST PASSED: injected close successfully closed "
		    "fd\n");
	}

	return (ret);
}
