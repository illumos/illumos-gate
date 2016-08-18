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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * Regression test for 7076 where doing a putenv() call without an '=' sign
 * may lead to a segmentation fault when doing a getenv() depending on the
 * circumstances of the environment's layout. Verify putenv() mimics
 * unsetenv().
 */

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/debug.h>

int
main(void)
{
	if (putenv("FOO=bar") != 0) {
		fprintf(stderr, "failed to put FOO into the environment: %s\n",
		    strerror(errno));
		return (1);
	}

	if (getenv("FOO") == NULL) {
		fprintf(stderr, "failed to retrieve FOO from the "
		    "environment!\n");
		return (1);
	}

	VERIFY0(unsetenv("FOO"));

	if (getenv("FOO") != NULL) {
		fprintf(stderr, "Somehow retrieved FOO from the "
		    "environment after unsetenv()!\n");
		return (1);
	}

	if (putenv("FOO=bar") != 0) {
		fprintf(stderr, "failed to put FOO into the environment: %s\n",
		    strerror(errno));
		return (1);
	}

	if (getenv("FOO") == NULL) {
		fprintf(stderr, "failed to retrieve FOO from the "
		    "environment!\n");
		return (1);
	}

	VERIFY0(putenv("FOO"));

	if (getenv("FOO") != NULL) {
		fprintf(stderr, "Somehow retrieved FOO from the "
		    "environment after putenv()!\n");
		return (1);
	}

	return (0);
}
