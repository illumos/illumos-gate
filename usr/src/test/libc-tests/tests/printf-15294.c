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
 * Copyright 2022 OmniOS Community Edition (OmniOSce) Association.
 */

/*
 * Regression test for illumos #15294. A change in isatty(3C) caused printf(3C)
 * to start setting errno on a successful call if the output is not a TTY.
 */

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/debug.h>
#include <sys/types.h>

#include "common/openpty.c"

static int failures;

static void
fail(const char *fmt, ...)
{
	va_list va;

	va_start(va, fmt);
	(void) vfprintf(stderr, fmt, va);
	va_end(va);

	failures++;
}

static void
test_file(FILE *fp, char *tag, int e_n, int e_err)
{
	int n, err;

	errno = 0;
	n = fprintf(fp, "%s", tag);
	err = errno;

	if (n != e_n)
		fail("%s return value was %d, expected %d\n", tag, n, e_n);
	if (err != e_err)
		fail("%s errno value was %d, expected %d\n", tag, errno, e_err);
}

int
main(void)
{
	int mfd, sfd;
	FILE *fp, *sfp;

	if (!openpty(&mfd, &sfd))
		errx(EXIT_FAILURE, "failed to open a pty");
	if (isatty(sfd) != 1)
		errx(EXIT_FAILURE, "subsidiary PTY fd somehow isn't a TTY!");

	fp = tmpfile();
	if (fp == NULL)
		errx(EXIT_FAILURE, "could not create temporary file");

	if ((sfp = fdopen(sfd, "w")) == NULL)
		errx(EXIT_FAILURE, "could not fdopen subsidiary PTY fd");

	test_file(fp, "test non-PTY", sizeof ("test non-PTY") - 1, 0);
	test_file(sfp, "test PTY", sizeof ("test PTY") - 1, 0);

	VERIFY0(fclose(fp));
	VERIFY0(fclose(sfp));
	VERIFY0(close(mfd));

	return (failures);
}
