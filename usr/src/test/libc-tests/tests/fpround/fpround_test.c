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
 * Copyright 2014 PALO, Richard. All rights reserved.
 * Copyright 2014 OmniTI Computer Consulting, Inc. All rights reserved.
 */

/*
 * Test rounding of floating point numbers in libc's *printf() routines.
 *
 * C99 must be enabled to get DECIMAL_DIG defined, but it looks like all
 * of usr/src/test/libc is compiled that way.
 */

#include <float.h>
#include <fenv.h>
#include <stdio.h>
#include <strings.h>
#include "test_common.h"

/*
 * Returns negative if snprintf() fails.  Returns 0 upon
 * successful execution of the test, return 1 upon a failure.
 * Spews output if verbose is TRUE.
 */
int
run_one(test_t t, int i, int j, int precision, boolean_t verbose)
{
	const int size = 100;
	char buffer[size], check[size];
	double val;
	int status;

	val = (double)(0.0 + j) / i;
	/* first get max precision for control check */
	status = snprintf(check, size, "%+-.*f", DECIMAL_DIG, val);
	if (status < 0) {
		test_failed(t, "Max precision snprintf() "
		    "(i = %d, j = %d) returned %d\n", i, j, status);
		return (status);
	}
	/* then get specific precision */
	status = snprintf(buffer, size, "%+-#.*f", precision, val);
	if (status < 0) {
		test_failed(t, "Specific precision snprintf() "
		    "(i = %d, j = %d, precision = %d) returned %d\n", i, j,
		    precision, status);
		return (status);
	}

	if (strlen(check) > strlen(buffer) &&
	    strncmp(buffer, check, strlen(buffer))) {
		/* last check if correctly rounded up */
		if (check[strlen(buffer)] < '5' &&
		    buffer[strlen(buffer) - 1] > check[strlen(buffer) - 1]) {
			if (verbose)
				(void) printf("failure:f precision %d "
				    "for %02d/%02d => %s (%s)\n",
				    precision, j, i, buffer, check);
			return (1);
		}
	}

	return (0);
}

int
main(int argc, char *argv[])
{
	int status, i, j, precision;
	int failures = 0;
	int runs = 0;
	test_t t;
	/* NOTE:  Any argument after the command enables "VERBOSE" mode. */
	boolean_t verbose = (argc > 1);

	t = test_start("*printf() floating-point rounding tests.");

	(void) fesetround(FE_TONEAREST);

	for (j = 1; j < 100; j++) {
		for (i = 2; i < 100; i++) {
			for (precision = DBL_DIG - 1; precision <= DECIMAL_DIG;
			    precision++) {
				runs++;
				status = run_one(t, i, j, precision, verbose);
				if (status < 0)
					return (status);
				failures += status;
			}
		}
	}

	if (failures > 0) {
		test_failed(t, "Tests failed %d times out of %d attempts.\n"
		    "Run '%s full' to see the %d failures individually.\n",
		    failures, runs, argv[0], failures);
	} else
		test_passed(t);

	return (0);
}
