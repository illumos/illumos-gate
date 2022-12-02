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
 * Copyright 2022 Oxide Computer Company
 */

/*
 * This program verifies that isatty(3C) correctly handles and sets errno for
 * different cases.
 */

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <err.h>
#include <stdbool.h>
#include <sys/stropts.h>
#include <sys/sysmacros.h>

/*
 * This is named this way with the hope that it'll be replaced someday by
 * openpty.
 */
bool
openpty(int *mfdp, int *sfdp)
{
	int sfd;
	int mfd = posix_openpt(O_RDWR | O_NOCTTY);
	const char *name;

	if (mfd < 0) {
		warn("failed to open a pseudo-terminal");
		return (false);
	}

	if (grantpt(mfd) != 0 || unlockpt(mfd) != 0) {
		warn("failed to grant and unlock the manager fd");
		(void) close(mfd);
		return (false);
	}

	name = ptsname(mfd);
	if (name == NULL) {
		warnx("failed to get ptsname for fd %d", mfd);
		(void) close(mfd);
		return (false);
	}

	sfd = open(name, O_RDWR | O_NOCTTY);
	if (sfd < 0) {
		warn("failed to open pty %s", name);
		(void) close(mfd);
		return (false);
	}

	if (ioctl(sfd, __I_PUSH_NOCTTY, "ptem") < 0 ||
	    ioctl(sfd, __I_PUSH_NOCTTY, "ldterm") < 0) {
		warn("failed to push streams modules");
		(void) close(mfd);
		(void) close(sfd);
	}

	*sfdp = sfd;
	*mfdp = mfd;
	return (true);
}

int
main(void)
{
	int sfd, mfd;
	int ret = EXIT_SUCCESS;
	const int badfds[] = { 3, -1, INT_MAX, INT_MIN, 7777 };
	const char *notttys[] = { "/proc/self/status", "/usr/lib/64/libc.so.1",
	    "/dev/zero", "/dev/tcp", "/dev/poll", "/etc/default/init" };

	/*
	 * We start off by using closefrom() to verify that we don't have
	 * anything open other than the standard file descriptors, allowing us
	 * to pick FDs that make sense.
	 */
	closefrom(STDERR_FILENO + 1);

	for (size_t i = 0; i < ARRAY_SIZE(badfds); i++) {
		/*
		 * We explicitly clear errno to prove that we are setting it.
		 * The closefrom() will hit EBADF and we want to clear that out
		 * from the test (as well as any side effects below.
		 */
		errno = 0;
		if (isatty(badfds[i]) != 0) {
			warnx("TEST FAILED: isatty(%d) returned success on bad "
			    "fd", badfds[i]);
			ret = EXIT_FAILURE;
			continue;
		}

		if (errno != EBADF) {
			int e = errno;
			warnx("TEST FAILED: isatty(%d) didn't set EBADF, "
			    "found: %d", badfds[i], e);
			ret = EXIT_FAILURE;
			continue;
		}

		(void) printf("TEST PASSED: isatty(%d) failed with EBADF\n",
		    badfds[i]);
	}

	for (size_t i = 0; i < ARRAY_SIZE(notttys); i++) {
		int fd = open(notttys[i], O_RDONLY);
		int ttyret, ttyerr;

		if (fd < 0) {
			warn("TEST FAILED: failed to open %s", notttys[i]);
			ret = EXIT_FAILURE;
			continue;
		}

		errno = 0;
		ttyret = isatty(fd);
		ttyerr = errno;
		(void) close(fd);

		if (ttyret != 0) {
			warnx("TEST FAILED: %s is somehow a tty!", notttys[i]);
			ret = EXIT_FAILURE;
			continue;
		}

		if (ttyerr != ENOTTY) {
			warnx("TEST FAILED: got wrong errno for %s, expected "
			    "ENOTTY, found %d", notttys[i], ttyerr);
			ret = EXIT_FAILURE;
			continue;
		}

		(void) printf("TEST PASSED: %s is not a tty, errno was "
		    "ENOTTY\n", notttys[i]);
	}

	if (!openpty(&mfd, &sfd)) {
		errx(EXIT_FAILURE, "TEST FAILED: failed to open a pty");
	}

	if (isatty(sfd) != 1) {
		warnx("subsidiary PTY fd somehow isn't a TTY!");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: subsidiary PTY is a TTY\n");
	}

	if (isatty(mfd) != 0) {
		warnx("manager PTY fd somehow is a TTY!");
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: manager PTY is not a TTY\n");
	}

	(void) close(mfd);
	(void) close(sfd);

	return (ret);
}
