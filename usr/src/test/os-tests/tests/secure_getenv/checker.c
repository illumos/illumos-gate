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
 * Copyright 2025 Oxide Computer Company
 */

/*
 * This goes through and attempts to verify whether or not the "SECRET"
 * environment variable is readable or not with getenv(3C) and
 * secure_getenv(3C). It should always work with the former. It will only work
 * with the latter depending on how we've been invoked. We know whether or not
 * our caller expects this to pass depending on whether or not we have the -s
 * argument.
 */

#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <err.h>

int
main(int argc, char *argv[])
{
	bool sec;
	const char *desc;
	int ret = EXIT_SUCCESS;

	if (argc != 2 && argc != 3) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: found %d args, but "
		    "expected 2 or 3", argc);
	}

	desc = argv[1];

	if (argc == 2) {
		sec = false;
	} else if (strcmp(argv[2], "secure") != 0) {
		errx(EXIT_FAILURE, "INTERNAL TEST FAILURE: argv[2] should "
		    "either be missing or 'secure', found %s", argv[2]);
	} else {
		sec = true;
	}

	if (getenv("SECRET") == NULL) {
		warnx("TEST FAILED: %s: getenv(\"SECRET\") failed "
		    "unexpectedly", desc);
		ret = EXIT_FAILURE;
	}

	if (sec) {
		if (secure_getenv("SECRET") != NULL) {
			warnx("TEST FAILED: %s: secure_getenv() returned a "
			    "value unexpectedly", desc);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: %s: secure_getenv() "
			    "correctly failed to return 'SECRET'\n", desc);
		}
	} else {
		if (secure_getenv("SECRET") == NULL) {
			warnx("TEST FAILED: %s: secure_getenv() failed to "
			    "return a value unexpectedly", desc);
			ret = EXIT_FAILURE;
		} else {
			(void) printf("TEST PASSED: %s: secure_getenv() "
			    "correctly returned 'SECRET'\n", desc);
		}
	}

	return (ret);
}
