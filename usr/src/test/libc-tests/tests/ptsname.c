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
 * Verify basic behavior of ptsname() and ptsname_r().
 */

#include <stdlib.h>
#include <fcntl.h>
#include <err.h>
#include <unistd.h>
#include <sys/debug.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <sys/socket.h>

static const char *pts_base = "/dev/pts";

static bool
ptsname_err(const char *desc, int fd, int error)
{
	if (ptsname(fd) != NULL) {
		warnx("TEST FAILED: %s: ptsname incorrectly succeeded!", desc);
		return (false);
	}

	if (errno != error) {
		int e = errno;
		warnx("TEST FAILED: %s: ptsname returned %s, but we expected "
		    "%s", desc, strerrorname_np(e), strerrorname_np(error));
		return (false);
	}

	(void) printf("TEST PASSED: %s correctly returned %s\n", desc,
	    strerrorname_np(error));
	return (true);
}

static bool
ptsname_r_err(const char *desc, int fd, char *buf, size_t len, int error)
{
	int ret;

	if ((ret = ptsname_r(fd, buf, len)) == 0) {
		warnx("TEST FAILED: %s: ptsname incorrectly succeeded!", desc);
		return (false);
	}

	if (ret != error) {
		warnx("TEST FAILED: %s: ptsname returned %s, but we expected "
		    "%s", desc, strerrorname_np(ret), strerrorname_np(error));
		return (false);
	}

	(void) printf("TEST PASSED: %s correctly returned %s\n", desc,
	    strerrorname_np(error));
	return (true);
}

int
main(void)
{
	char *buf, *alt_buf, *pts;
	size_t len;
	long l;
	int ret = EXIT_SUCCESS;
	int mngr, alt_mngr, zero, stream, pts_ret;

	if ((mngr = posix_openpt(O_RDWR | O_NOCTTY)) < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create manager "
		    "pseudo-terminal device");
	}

	if ((alt_mngr = posix_openpt(O_RDWR | O_NOCTTY)) < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to create second "
		    "manager pseudo-terminal device");
	}

	if ((l = sysconf(_SC_TTY_NAME_MAX)) < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to obtain TTY_NAME_MAX");
	}
	len = (size_t)l;

	if ((buf = malloc(len)) == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: failed to allocate %zu bytes "
		    "for tty name buffer", len);
	}

	if ((alt_buf = malloc(len)) == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: failed to allocate %zu bytes "
		    "for second tty name buffer", len);
	}

	if ((stream = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to open a UDS socket");
	}

	if ((zero = open("/dev/zero", O_RDWR)) < 0) {
		err(EXIT_FAILURE, "TEST FAILED: failed to open /dev/zero");
	}

	closefrom(zero + 1);

	/*
	 * The errors that are returned here are kind of all over the place.
	 * This is because we have historically just returned the results of an
	 * ioctl and haven't tried to consolidate anything in the past. So for
	 * now the following are kind of a check to both ensure that things have
	 * failed and see what changes. The EBADF is what we expect. EINVAL is
	 * okay. ENXIO is really not great, but it is what it is.
	 */
	if (!ptsname_err("ptsname: non-existent fd", zero + 1, EBADF)) {
		ret = EXIT_FAILURE;
	}

	if (!ptsname_err("ptsname: non-terminal fd", zero, ENXIO)) {
		ret = EXIT_FAILURE;
	}

	if (!ptsname_err("ptsname: non-terminal fd", stream, EINVAL)) {
		ret = EXIT_FAILURE;
	}

	if (!ptsname_r_err("ptsname: non-existent fd", zero + 1, buf, len,
	    EBADF)) {
		ret = EXIT_FAILURE;
	}

	if (!ptsname_r_err("ptsname: non-terminal fd", zero, buf, len,
	    ENXIO)) {
		ret = EXIT_FAILURE;
	}

	if (!ptsname_r_err("ptsname: non-terminal fd", stream, buf, len,
	    EINVAL)) {
		ret = EXIT_FAILURE;
	}

	/*
	 * Next, verify that ptsname and ptsname_r() give the same results.
	 */
	if ((pts = ptsname(mngr)) == NULL) {
		err(EXIT_FAILURE, "TEST FAILED: ptsname on a manager "
		    "unexpected failed");
	}

	if (strncmp(pts, pts_base, strlen(pts_base)) != 0) {
		warnx("TEST FAILED: ptsname() path '%s' does not have base "
		    "of %s", pts, pts_base);
	} else {
		(void) printf("TEST PASSED: ptsname() path has correct base\n");
	}

	if ((pts_ret = ptsname_r(mngr, buf, len)) != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: ptsname_r unexpected failed "
		    "with %s", strerrorname_np(pts_ret));
	}

	if (strncmp(buf, pts_base, strlen(pts_base)) != 0) {
		warnx("TEST FAILED: ptsname_r() path '%s' does not have base "
		    "of %s", buf, pts_base);
	} else {
		(void) printf("TEST PASSED: ptsname_r() path has correct "
		    "base\n");
	}

	if (strcmp(pts, buf) == 0) {
		(void) printf("TEST PASSED: ptsname() and ptsname_r() "
		    "agreed\n");
	} else {
		warnx("TEST FAILED: ptsname() and ptsname_r() returned "
		    "different strings: found '%s' and '%s' respectively", pts,
		    buf);
		ret = EXIT_FAILURE;
	}

	/*
	 * Confirm that ptsname_r() and ptsname() on a second device doesn't
	 * impact the other.
	 */
	if ((pts_ret = ptsname_r(alt_mngr, alt_buf, len)) != 0) {
		errx(EXIT_FAILURE, "TEST FAILED: ptsname_r unexpected failed "
		    "with %s", strerrorname_np(pts_ret));
	}

	if (strncmp(alt_buf, pts_base, strlen(pts_base)) != 0) {
		warnx("TEST FAILED: ptsname_r() path '%s' does not have base "
		    "of %s", buf, pts_base);
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: ptsname_r() path has correct "
		    "base\n");
	}

	if (strcmp(buf, alt_buf) == 0) {
		warnx("TEST FAILED: ptsname_r() on two separate devices "
		    "returned the same value: '%s'", buf);
		ret = EXIT_FAILURE;
	} else {
		(void) printf("TEST PASSED: ptsname_r() on two separate "
		    "devices have different paths\n");
	}

	if (strcmp(pts, buf) == 0) {
		(void) printf("TEST PASSED: ptsname() buffer not impacted by "
		    "ptsname_r() call\n");
	} else {
		warnx("TEST FAILED: ptsname() value changed after ptsname_r() "
		    "call: found '%s', but expected '%s'", pts, buf);
		ret = EXIT_FAILURE;
	}

	if (ptsname(alt_mngr) == NULL) {
		warn("TEST FAILED: ptsname() failed on second manager fd");
		ret = EXIT_FAILURE;
	}

	if (strcmp(pts, alt_buf) == 0) {
		(void) printf("TEST PASSED: ptsname() matches ptsname_r() on "
		    "second manager\n");
	} else {
		warnx("TEST FAILED: ptsname() and ptsname_r() returned "
		    "different strings for second manager: found '%s' and "
		    "'%s' respectively", pts, buf);
		ret = EXIT_FAILURE;
	}

	if (!ptsname_r_err("ptsname: length 0", mngr, buf, 0, ERANGE)) {
		ret = EXIT_FAILURE;
	}

	if (!ptsname_r_err("ptsname: length 8 (/dev/pts)", mngr, buf,
	    strlen(pts_base), ERANGE)) {
		ret = EXIT_FAILURE;
	}

	if (!ptsname_r_err("ptsname: length no-NUL", mngr, buf, strlen(buf),
	    ERANGE)) {
		ret = EXIT_FAILURE;
	}

	free(buf);
	free(alt_buf);
	VERIFY0(close(mngr));

	if (ret == EXIT_SUCCESS) {
		(void) printf("All tests passed successfully\n");
	}

	return (ret);
}
