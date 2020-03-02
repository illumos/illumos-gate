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
 * In a c99/xpg6 environment freopen(3C) allows you to specify a NULL path to
 * try and change the fopen() flags. Verify that the memstream functions do not
 * allow this. Note, freopen(3C) is defined to try and close the stream, hence
 * you won't see anything here.
 */

#include <stdio.h>
#include <stdio.h>
#include <wchar.h>
#include <err.h>
#include <stdlib.h>
#include <errno.h>

const char *
_umem_debug_init(void)
{
	return ("default,verbose");
}

const char *
_umem_logging_init(void)
{
	return ("fail,contents");
}

static void
check_reopen(FILE *f, const char *variant)
{
	FILE *new = freopen(NULL, "r", f);
	if (new != NULL) {
		errx(EXIT_FAILURE, "TEST FAILED: was able to freopen %s",
		    variant);
	}

	if (errno != EBADF) {
		errx(EXIT_FAILURE, "TEST FAILED: found wrong errno for %s: "
		    "expected %d, found %d", EBADF, errno);
	}

	(void) printf("TEST PASSED: %s\n", variant);
}

int
main(void)
{
	FILE *f;
	char *c;
	wchar_t *wc;
	size_t sz;

	f = fmemopen(NULL, 16, "a+");
	if (f == NULL) {
		err(EXIT_FAILURE, "failed to create fmemopen() stream");
	}
	check_reopen(f, "fmemopen()");

	f = open_memstream(&c, &sz);
	if (f == NULL) {
		err(EXIT_FAILURE, "failed to create open_memstream() stream");
	}
	check_reopen(f, "open_memstream()");
	free(c);

	f = open_wmemstream(&wc, &sz);
	if (f == NULL) {
		err(EXIT_FAILURE, "failed to create open_wmemstream() stream");
	}
	check_reopen(f, "open_wmemstream()");
	free(wc);

	return (0);
}
