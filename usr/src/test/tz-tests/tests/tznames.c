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
 * This file tests that the parsed tzname is equal to what was passed in as
 * args. We use the arguments as TZ=arg0, name0=arg1, name1=arg2.
 */

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <err.h>

int
main(int argc, char *argv[])
{
	int ret = EXIT_SUCCESS;

	if (argc != 4) {
		(void) fprintf(stderr, "Usage:  tznames <TZ> <tzname0> "
		    "<tzname1>\n");
		exit(EXIT_FAILURE);
	}

	if (setenv("TZ", argv[1], 1) != 0) {
		err(EXIT_FAILURE, "failed to set TZ to %s", argv[1]);
	}

	tzset();

	if (strcmp(tzname[0], argv[2]) != 0) {
		warnx("TEST FAILED: TZ %s: found tzname[0] %s, expected %s",
		    argv[1], tzname[0], argv[2]);
		ret = EXIT_FAILURE;
	}

	if (strcmp(tzname[1], argv[3]) != 0) {
		warnx("TEST FAILED: TZ %s: found tzname[1] %s, expected %s",
		    argv[1], tzname[1], argv[3]);
		ret = EXIT_FAILURE;
	}

	return (ret);
}
