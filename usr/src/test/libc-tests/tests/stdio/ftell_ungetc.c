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
 * Copyright 2020 Robert Mustacchi
 */

/*
 * Regression test for illumos#12392. Here, ftello64 didn't correctly handle an
 * ungetc() in the write path when it was unbuffered.
 */

#include <stdio.h>
#include <err.h>
#include <stdlib.h>

static void
check_pos(FILE *f, long pos)
{
	long l;
	off_t off;
	off64_t off64;

	l = ftell(f);
	off = ftello(f);
	off64 = ftello64(f);

	if (l != pos) {
		errx(EXIT_FAILURE, "ftell position mismatched: found %ld, "
		    "expected %ld", l, pos);
	}

	if (off != pos) {
		errx(EXIT_FAILURE, "ftello position mismatched: found %ld, "
		    "expected %ld", off, pos);
	}

	if (off64 != pos) {
		errx(EXIT_FAILURE, "ftello64 position mismatched: found %ld, "
		    "expected %ld", off64, pos);
	}
}

static void
check_one(FILE *f)
{
	if (fputc('a', f) != 'a') {
		err(EXIT_FAILURE, "failed to write character");
	}
	check_pos(f, 1);

	if (ungetc('b', f) != 'b') {
		err(EXIT_FAILURE, "failed to unget character");
	}
	check_pos(f, 0);
}

int
main(void)
{
	FILE *f;

	f = tmpfile();
	if (f == NULL) {
		err(EXIT_FAILURE, "failed to create temproary "
		    "file");
	}

	if (setvbuf(f, NULL, _IONBF, 0) != 0) {
		err(EXIT_FAILURE, "failed to set non-buffering mode");
	}
	check_one(f);
	if (fclose(f) != 0) {
		err(EXIT_FAILURE, "failed to close temporary file");
	}

	return (0);
}
